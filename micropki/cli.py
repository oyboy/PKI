import argparse
import os
import sys
import json

from .logger import setup_logger
from .ca import init_ca, issue_intermediate, issue_cert, verify_chain, issue_ocsp_cert
from .database import Database
from .repository import run_server
from .audit import read_records, filter_records, print_records, verify_log, log_event
from .transparency import verify_inclusion
from .compromise import public_key_hash

from .crypto_utils import load_certificate, load_private_key
from .revocation import REASON_CODES
from .crl import generate_crl
from .ocsp_responder import run_ocsp_server
from .client import (
    client_gen_csr, client_request_cert, client_validate, client_check_status
)

def validate_key_params(args):
    if not hasattr(args, "key_type"):
        return
    if args.key_type == "rsa":
        args.key_size = args.key_size or 4096
        if args.key_size < 2048:
            raise ValueError("--key-size must be at least 2048 for RSA")
    elif args.key_type == "ecc":
        args.key_size = args.key_size or 384
        if args.key_size not in (256, 384):
            raise ValueError("--key-size must be 256 or 384 for ECC")
    else:
        raise ValueError(f"Unsupported key type: {args.key_type}")


def validate_file_readable(path, name):
    if not os.path.isfile(path) or not os.access(path, os.R_OK):
        raise ValueError(f"Cannot read {name}: {path}")


def validate_common(args):
    if hasattr(args, "validity_days") and args.validity_days <= 0:
        raise ValueError("--validity-days must be positive")
    if hasattr(args, "subject") and (not args.subject or not args.subject.strip()):
        raise ValueError("--subject cannot be empty")


def validate_init(args):
    validate_key_params(args)
    if args.key_type == "rsa" and args.key_size < 4096:
        raise ValueError("Root CA RSA key must be at least 4096 bits")
    if args.key_type == "ecc" and args.key_size < 384:
        raise ValueError("Root CA ECC key must be at least P-384")
    validate_file_readable(args.passphrase_file, "passphrase file")


def validate_intermediate(args):
    validate_key_params(args)
    if args.key_type == "ecc" and args.key_size < 384:
        raise ValueError("Intermediate CA ECC key must be at least P-384")
    validate_file_readable(args.root_cert, "root cert")
    validate_file_readable(args.root_key, "root key")
    validate_file_readable(args.root_pass_file, "root passphrase file")
    validate_file_readable(args.passphrase_file, "intermediate passphrase file")


def validate_issue_cert(args):
    validate_file_readable(args.ca_cert, "CA cert")
    validate_file_readable(args.ca_key, "CA key")
    validate_file_readable(args.ca_pass_file, "CA passphrase file")


def handle_init(args, logger):
    validate_common(args)
    validate_init(args)
    init_ca(args, logger)


def handle_issue_intermediate(args, logger):
    validate_common(args)
    validate_intermediate(args)
    issue_intermediate(args, logger)


def handle_issue_cert(args, logger):
    validate_common(args)
    validate_issue_cert(args)
    os.makedirs(args.out_dir, exist_ok=True)
    issue_cert(args, logger)


def handle_verify_chain(args, logger):
    verify_chain(args, logger)


def handle_list_certs(args, logger):
    db = Database(args.db_path, logger)
    certs = db.list_certs(args.status)
    if args.format == "table":
        print(f"{'Serial':<40} {'Subject':<50} {'Status':<10} {'Expires'}")
        print("-" * 120)
        for cert in certs:
            print(f"{cert['serial_hex']:<40} {cert['subject']:<50} {cert['status']:<10} {cert['not_after']}")
    elif args.format == "json":
        print(json.dumps([dict(row) for row in certs], indent=2))
    elif args.format == "csv":
        print("serial,subject,status,expires")
        for cert in certs:
            print(f"{cert['serial_hex']},{cert['subject']},{cert['status']},{cert['not_after']}")


def handle_show_cert(args, logger):
    db = Database(args.db_path, logger)
    pem = db.get_cert_pem_by_serial(args.serial)
    if pem:
        print(pem)
    else:
        raise ValueError(f"Certificate with serial {args.serial} not found")


def handle_db_init(args, logger):
    db = Database(args.db_path, logger)
    db.init_db()
    logger.info("Database initialized")


def handle_repo_serve(args, logger):
    run_server(args.host, args.port, args.db_path, args.cert_dir, args.rate_limit, args.rate_burst)

def handle_revoke(args, logger):
    logger.info(f"Revoking certificate {args.serial}...")
    if args.reason not in REASON_CODES:
        logger.error(f"Invalid reason: {args.reason}")
        sys.exit(1)
        
    db = Database(args.db_path, logger)
    result = db.revoke_certificate(args.serial, args.reason)
    
    if result == "not_found":
        logger.error("Certificate not found.")
        sys.exit(1)
    elif result == "already_revoked":
        logger.warning("Certificate is already revoked.")
    else:
        log_event("revoke_certificate", "success", "Certificate revoked", {"serial": args.serial.upper(), "reason": args.reason}, out_dir="./pki")
        logger.info(f"SUCCESS: Certificate {args.serial} revoked.")

def handle_gen_crl(args, logger):
    db = Database(args.db_path, logger)
    
    if args.ca == 'root':
        cert_path = os.path.join(args.out_dir, "certs/ca.cert.pem")
        key_path = os.path.join(args.out_dir, "private/ca.key.pem")
        pass_path = args.root_pass_file
    else:
        cert_path = os.path.join(args.out_dir, "certs/intermediate.cert.pem")
        key_path = os.path.join(args.out_dir, "private/intermediate.key.pem")
        pass_path = args.ca_pass_file
        
    ca_cert = load_certificate(cert_path)
    with open(pass_path, 'rb') as f:
        passphrase = f.read().strip()
    ca_key = load_private_key(key_path, passphrase)
    
    revoked = db.get_revoked_for_issuer(ca_cert.subject.rfc4514_string())
    
    crl_num = db.get_next_crl_number(ca_cert.subject.rfc4514_string())
    
    logger.info(f"Generating CRL #{crl_num} for {args.ca} with {len(revoked)} entries...")
    crl_pem = generate_crl(ca_cert, ca_key, revoked, crl_num, args.next_update)
    
    crl_dir = os.path.join(args.out_dir, "crl")
    os.makedirs(crl_dir, exist_ok=True)
    out_path = args.out_file or os.path.join(crl_dir, f"{args.ca}.crl.pem")
    
    with open(out_path, 'wb') as f:
        f.write(crl_pem)
    
    log_event("generate_crl", "success", "CRL generated", {"ca": args.ca, "path": out_path, "revoked_count": len(revoked)}, out_dir=args.out_dir)
    logger.info(f"SUCCESS: CRL saved to {out_path}")

def handle_issue_ocsp_cert(args, logger):
    issue_ocsp_cert(args, logger)

def handle_ocsp_serve(args, logger):
    log_event("ocsp_serve", "started", "OCSP responder started", {"host": args.host, "port": args.port}, out_dir="./pki")
    run_ocsp_server(
        args.host, 
        args.port, 
        args.db_path, 
        args.responder_cert, 
        args.responder_key, 
        args.ca_cert,
        args.cache_ttl,
        args.rate_limit,
        args.rate_burst
    )


def handle_audit_query(args, logger):
    records = read_records(args.log_file)
    records = filter_records(records, args.from_ts, args.to_ts, args.level, args.operation, args.serial)
    if args.verify:
        ok, line, msg = verify_log(args.log_file, args.chain_file, subset=records)
        if not ok:
            logger.error(f"Audit integrity verification failed at record {line}: {msg}")
            sys.exit(1)
    print_records(records, args.format)

def handle_audit_verify(args, logger):
    ok, line, msg = verify_log(args.log_file, args.chain_file)
    if ok:
        print(f"OK: audit log integrity verified. Last hash: {msg}")
    else:
        print(f"BROKEN: audit log integrity failed at record {line}: {msg}")
        sys.exit(1)

def handle_ct_verify(args, logger):
    cert = load_certificate(args.cert) if args.cert else None
    ok = verify_inclusion(serial=args.serial, cert=cert, ct_file=args.ct_log)
    if ok:
        print("OK: certificate is present in simulated CT log")
    else:
        print("MISSING: certificate is not present in simulated CT log")
        sys.exit(1)

def handle_detect_anomalies(args, logger):
    records = read_records(args.log_file)
    counts = {}
    for r in records:
        hour = str(r.get("timestamp", ""))[:13]
        op = r.get("operation")
        key = (hour, op)
        counts[key] = counts.get(key, 0) + 1
    bad = [(h, op, c) for (h, op), c in counts.items() if c >= args.threshold]
    if not bad:
        print("OK: anomalies were not detected")
    else:
        for h, op, c in bad:
            print(f"WARNING: {c} events for {op} during {h}:00")

def handle_compromise(args, logger):
    cert = load_certificate(args.cert)
    serial = hex(cert.serial_number)[2:].upper()
    if not args.force:
        answer = input(f"Compromise and revoke certificate {serial}? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Cancelled")
            return
    db = Database(args.db_path, logger)
    db.init_db()
    db.revoke_certificate(serial, args.reason)
    pk_hash = public_key_hash(cert.public_key())
    db.mark_key_compromised(pk_hash, serial, args.reason)
    log_event("key_compromise", "success", "Certificate key marked as compromised and revoked", {"serial": serial, "reason": args.reason, "public_key_hash": pk_hash}, out_dir="./pki")
    print(f"SUCCESS: certificate {serial} revoked with reason {args.reason}; public key marked compromised")

def build_parser():
    parent = argparse.ArgumentParser(add_help=False, conflict_handler="resolve")
    parent.add_argument("--log-file", default=None)
    parent.add_argument("--config", default=None, help="Optional MicroPKI config file placeholder")

    parser = argparse.ArgumentParser(description="MicroPKI CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    db_path_arg = {"default": "./pki/micropki.db", "help": "Path to the SQLite database file"}
    cert_dir_arg = {"default": "./pki/certs", "help": "Directory with CA certificates"}

    ca_parser = subparsers.add_parser("ca", parents=[parent])
    ca_subparsers = ca_parser.add_subparsers(dest="action", required=True)

    init_p = ca_subparsers.add_parser("init", parents=[parent])
    init_p.add_argument("--subject", required=True)
    init_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_p.add_argument("--key-size", type=int)
    init_p.add_argument("--passphrase-file", required=True)
    init_p.add_argument("--out-dir", default="./pki")
    init_p.add_argument("--validity-days", type=int, default=3650)
    init_p.add_argument("--force", action="store_true")
    init_p.add_argument("--db-path", **db_path_arg)
    init_p.set_defaults(func=handle_init)

    inter_p = ca_subparsers.add_parser("issue-intermediate", parents=[parent])
    inter_p.add_argument("--root-cert", required=True)
    inter_p.add_argument("--root-key", required=True)
    inter_p.add_argument("--root-pass-file", required=True)
    inter_p.add_argument("--subject", required=True)
    inter_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    inter_p.add_argument("--key-size", type=int)
    inter_p.add_argument("--passphrase-file", required=True)
    inter_p.add_argument("--out-dir", default="./pki")
    inter_p.add_argument("--validity-days", type=int, default=1825)
    inter_p.add_argument("--pathlen", type=int, default=0)
    inter_p.add_argument("--db-path", **db_path_arg)
    inter_p.set_defaults(func=handle_issue_intermediate)

    issue_p = ca_subparsers.add_parser("issue-cert", parents=[parent])
    issue_p.add_argument("--ca-cert", required=True)
    issue_p.add_argument("--ca-key", required=True)
    issue_p.add_argument("--ca-pass-file", required=True)
    issue_p.add_argument("--template", choices=["server", "client", "code_signing"], required=True)
    issue_p.add_argument("--subject", required=True)
    issue_p.add_argument("--san", action="append")
    issue_p.add_argument("--out-dir", default="./pki/certs")
    issue_p.add_argument("--validity-days", type=int, default=365)
    issue_p.add_argument("--db-path", **db_path_arg)
    issue_p.set_defaults(func=handle_issue_cert)

    verify_p = ca_subparsers.add_parser("verify-chain", parents=[parent])
    verify_p.add_argument("--leaf-cert", required=True)
    verify_p.add_argument("--untrusted", action="append")
    verify_p.add_argument("--ca-file", required=True)
    verify_p.set_defaults(func=handle_verify_chain)

    list_p = ca_subparsers.add_parser("list-certs", parents=[parent])
    list_p.add_argument("--status", choices=["valid", "revoked", "expired"])
    list_p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    list_p.add_argument("--db-path", **db_path_arg)
    list_p.set_defaults(func=handle_list_certs)

    comp_p = ca_subparsers.add_parser("compromise", parents=[parent], help="Simulate private key compromise and revoke certificate")
    comp_p.add_argument("--cert", required=True)
    comp_p.add_argument("--reason", default="keyCompromise", choices=list(REASON_CODES.keys()))
    comp_p.add_argument("--force", action="store_true")
    comp_p.add_argument("--db-path", **db_path_arg)
    comp_p.set_defaults(func=handle_compromise)

    show_p = ca_subparsers.add_parser("show-cert", parents=[parent])
    show_p.add_argument("serial")
    show_p.add_argument("--db-path", **db_path_arg)
    show_p.set_defaults(func=handle_show_cert)

    audit_parser = subparsers.add_parser("audit", parents=[parent])
    audit_sub = audit_parser.add_subparsers(dest="action", required=True)

    aq = audit_sub.add_parser("query")
    aq.add_argument("--from", dest="from_ts")
    aq.add_argument("--to", dest="to_ts")
    aq.add_argument("--level", choices=["INFO", "WARNING", "ERROR", "AUDIT"])
    aq.add_argument("--operation")
    aq.add_argument("--serial")
    aq.add_argument("--format", choices=["table", "json", "csv"], default="table")
    aq.add_argument("--verify", action="store_true")
    aq.add_argument("--log-file", default="./pki/audit/audit.log")
    aq.add_argument("--chain-file", default="./pki/audit/chain.dat")
    aq.set_defaults(func=handle_audit_query)

    av = audit_sub.add_parser("verify")
    av.add_argument("--log-file", default="./pki/audit/audit.log")
    av.add_argument("--chain-file", default="./pki/audit/chain.dat")
    av.set_defaults(func=handle_audit_verify)

    ctv = audit_sub.add_parser("ct-verify")
    ctv.add_argument("--serial")
    ctv.add_argument("--cert")
    ctv.add_argument("--ct-log", default="./pki/audit/ct.log")
    ctv.set_defaults(func=handle_ct_verify)

    det = audit_sub.add_parser("detect-anomalies")
    det.add_argument("--log-file", default="./pki/audit/audit.log")
    det.add_argument("--threshold", type=int, default=10)
    det.set_defaults(func=handle_detect_anomalies)

    db_parser = subparsers.add_parser("db", parents=[parent])
    db_subparsers = db_parser.add_subparsers(dest="action", required=True)

    db_init_p = db_subparsers.add_parser("init", parents=[parent])
    db_init_p.add_argument("--db-path", **db_path_arg)
    db_init_p.set_defaults(func=handle_db_init)

    repo_parser = subparsers.add_parser("repo", parents=[parent])
    repo_subparsers = repo_parser.add_subparsers(dest="action", required=True)

    serve_p = repo_subparsers.add_parser("serve", parents=[parent])
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8080)
    serve_p.add_argument("--db-path", **db_path_arg)
    serve_p.add_argument("--cert-dir", **cert_dir_arg)
    serve_p.add_argument("--rate-limit", type=float, default=0)
    serve_p.add_argument("--rate-burst", type=int, default=10)
    serve_p.set_defaults(func=handle_repo_serve)

    revoke_p = ca_subparsers.add_parser("revoke", help="Revoke a certificate")
    revoke_p.add_argument("serial", help="Serial number in hex")
    revoke_p.add_argument("--reason", default="unspecified", choices=list(REASON_CODES.keys()))
    revoke_p.add_argument("--db-path", **db_path_arg)
    revoke_p.add_argument("--force", action="store_true", help="Skip confirmation")
    revoke_p.set_defaults(func=handle_revoke)

    gen_crl_p = ca_subparsers.add_parser("gen-crl", help="Generate CRL")
    gen_crl_p.add_argument("--ca", choices=["root", "intermediate"], required=True)
    gen_crl_p.add_argument("--next-update", type=int, default=7)
    gen_crl_p.add_argument("--out-dir", default="./pki")
    gen_crl_p.add_argument("--out-file", help="Custom output path")
    gen_crl_p.add_argument("--db-path", **db_path_arg)

    gen_crl_p.add_argument("--root-pass-file", default="./secrets/root.pass")
    gen_crl_p.add_argument("--ca-pass-file", default="./secrets/intermediate.pass")
    gen_crl_p.set_defaults(func=handle_gen_crl)

    ocsp_cert_p = ca_subparsers.add_parser("issue-ocsp-cert", help="Issue an OCSP signing certificate")
    ocsp_cert_p.add_argument("--ca-cert", required=True)
    ocsp_cert_p.add_argument("--ca-key", required=True)
    ocsp_cert_p.add_argument("--ca-pass-file", required=True)
    ocsp_cert_p.add_argument("--subject", required=True)
    ocsp_cert_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ocsp_cert_p.add_argument("--key-size", type=int, default=2048)
    ocsp_cert_p.add_argument("--san", action="append")
    ocsp_cert_p.add_argument("--out-dir", default="./pki/certs")
    ocsp_cert_p.add_argument("--validity-days", type=int, default=365)
    ocsp_cert_p.add_argument("--db-path", **db_path_arg)
    ocsp_cert_p.set_defaults(func=handle_issue_ocsp_cert)

    ocsp_parser = subparsers.add_parser("ocsp", help="OCSP Responder commands")
    ocsp_subparsers = ocsp_parser.add_subparsers(dest="action", required=True)
    ocsp_serve_p = ocsp_subparsers.add_parser("serve", help="Run the OCSP responder")
    ocsp_serve_p.add_argument("--host", default="127.0.0.1")
    ocsp_serve_p.add_argument("--port", type=int, default=8081)
    ocsp_serve_p.add_argument("--db-path", **db_path_arg)
    ocsp_serve_p.add_argument("--responder-cert", required=True)
    ocsp_serve_p.add_argument("--responder-key", required=True)
    ocsp_serve_p.add_argument("--ca-cert", required=True)
    ocsp_serve_p.add_argument("--cache-ttl", type=int, default=60, help="Cache TTL in seconds")
    ocsp_serve_p.add_argument("--rate-limit", type=float, default=0)
    ocsp_serve_p.add_argument("--rate-burst", type=int, default=10)
    ocsp_serve_p.add_argument("--log-file", default=None, help="Path to log file")

    ocsp_serve_p.set_defaults(func=handle_ocsp_serve)

    client_parser = subparsers.add_parser("client", help="Client side tools", parents=[parent])
    client_sub = client_parser.add_subparsers(dest="action", required=True)

    csr_p = client_sub.add_parser("gen-csr", help="Generate Private Key and CSR", parents=[parent])
    csr_p.add_argument("--subject", required=True)
    csr_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    csr_p.add_argument("--key-size", type=int)
    csr_p.add_argument("--san", action="append")
    csr_p.add_argument("--out-key", default="./key.pem")
    csr_p.add_argument("--out-csr", default="./request.csr.pem")
    csr_p.set_defaults(func=client_gen_csr)
    
    req_p = client_sub.add_parser("request-cert", help="Send CSR to CA", parents=[parent])
    req_p.add_argument("--csr", required=True)
    req_p.add_argument("--template", choices=["server", "client", "code_signing"], required=True)
    req_p.add_argument("--ca-url", default="http://localhost:8080")
    req_p.add_argument("--out-cert", default="./cert.pem")
    req_p.set_defaults(func=client_request_cert)

    val_p = client_sub.add_parser("validate", parents=[parent])
    val_p.add_argument("--cert", required=True)
    val_p.add_argument("--untrusted", action="append")
    val_p.add_argument("--trusted", default="./pki/certs/ca.cert.pem")
    val_p.add_argument("--crl")
    val_p.add_argument("--ocsp", action="store_true")
    val_p.add_argument("--ocsp-url")
    val_p.add_argument("--mode", choices=["chain", "full"], default="full")
    val_p.add_argument("--validation-time")
    val_p.set_defaults(func=client_validate)

    status_p = client_sub.add_parser("check-status", help="Check revocation status", parents=[parent])
    status_p.add_argument("--cert", required=True)
    status_p.add_argument("--ca-cert", required=True)
    status_p.add_argument("--crl")
    status_p.add_argument("--ocsp-url")
    status_p.set_defaults(func=client_check_status)

    return parser


def main():
    parser = build_parser()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    log_file = getattr(args, "log_file", None)
    if hasattr(args, 'command'):
        logger = setup_logger(args.log_file)
    else:
        logger = setup_logger(log_file, name="MicroPKI_CLI")

    try:
        if not hasattr(args, "func"):
            raise ValueError("No command handler defined")
        args.func(args, logger)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception:
        logger.exception("Unexpected failure")
        sys.exit(1)


if __name__ == "__main__":
    main()