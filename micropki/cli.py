import argparse
import os
import sys

from .logger import setup_logger
from .ca import init_ca, issue_intermediate, issue_cert, verify_chain

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

def build_parser():
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--log-file", default=None)

    parser = argparse.ArgumentParser(description="MicroPKI CLI")

    subparsers = parser.add_subparsers(dest="command", required=True)

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
    issue_p.set_defaults(func=handle_issue_cert)

    verify_p = ca_subparsers.add_parser("verify-chain", help="Verify a certificate chain", parents=[parent])
    verify_p.add_argument("--leaf-cert", required=True, help="The certificate to verify")
    verify_p.add_argument("--untrusted", action="append", help="Intermediate certificate(s) forming the chain")
    verify_p.add_argument("--ca-file", required=True, help="The trusted root CA certificate")
    verify_p.set_defaults(func=handle_verify_chain)

    return parser

def main():
    parser = build_parser()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    logger = setup_logger(args.log_file)

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