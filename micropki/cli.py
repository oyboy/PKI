import argparse
import os
import sys
import json

from .logger import setup_logger
from .ca import init_ca, issue_intermediate, issue_cert, verify_chain, issue_ocsp_cert
from .database import Database
from .repository import run_server

from .crypto_utils import load_certificate, load_private_key
from .revocation import REASON_CODES
from .crl import generate_crl
from .ocsp_responder import run_ocsp_server

def validate_key_params(args):
    if not hasattr(args, "key_type"):
        return
    if args.key_type == "rsa":
        args.key_size = args.key_size or 4096
        if args.key_size != 4096:
            raise ValueError("--key-size must be 4096 for RSA")
    elif args.key_type == "ecc":
        args.key_size = args.key_size or 384
        if args.key_size != 384:
            raise ValueError("--key-size must be 384 for ECC")
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
    validate_file_readable(args.passphrase_file, "passphrase file")


def validate_intermediate(args):
    validate_key_params(args)
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
    run_server(args.host, args.port, args.db_path, args.cert_dir)

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
    
    logger.info(f"SUCCESS: CRL saved to {out_path}")

def handle_issue_ocsp_cert(args, logger):
    issue_ocsp_cert(args, logger)

def handle_ocsp_serve(args, logger):
    run_ocsp_server(
        args.host, 
        args.port, 
        args.db_path, 
        args.responder_cert, 
        args.responder_key, 
        args.ca_cert,
        args.cache_ttl
    )

def build_parser():
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--log-file", default=None)

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

    show_p = ca_subparsers.add_parser("show-cert", parents=[parent])
    show_p.add_argument("serial")
    show_p.add_argument("--db-path", **db_path_arg)
    show_p.set_defaults(func=handle_show_cert)

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
    ocsp_serve_p.add_argument("--log-file", default=None, help="Path to log file")

    ocsp_serve_p.set_defaults(func=handle_ocsp_serve)

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
        sys.exit(2)
    except Exception:
        logger.exception("Unexpected failure")
        sys.exit(1)


if __name__ == "__main__":
    main()