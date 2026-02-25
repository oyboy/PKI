import argparse
import os
import sys

from .logger import setup_logger
from .ca import init_ca

def main():
    parser = argparse.ArgumentParser(description="MicroPKI CLI")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    ca_parser = subparsers.add_parser("ca", help="Certificate Authority commands")
    ca_subparsers = ca_parser.add_subparsers(dest="action", required=True, help="CA actions")

    init_p = ca_subparsers.add_parser("init", help="Initialize self-signed Root CA")

    init_p.add_argument("--subject", required=True, help="DN string, e.g. /CN=MyCA or CN=MyCA,O=Demo")
    init_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa", help="Key type (rsa/ecc)")
    init_p.add_argument("--key-size", type=int, default=None, help="Key size (4096 for RSA, 384 for ECC)")
    init_p.add_argument("--passphrase-file", required=True, help="Path to passphrase file")
    init_p.add_argument("--out-dir", default="./pki", help="Output directory")
    init_p.add_argument("--validity-days", type=int, default=3650, help="Validity in days")
    init_p.add_argument("--log-file", default=None, help="Log file path")
    init_p.add_argument("--force", action="store_true", help="Overwrite existing files")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    logger = setup_logger(args.log_file)

    try:
        if args.key_type == "rsa":
            args.key_size = args.key_size or 4096
            if args.key_size != 4096:
                raise ValueError("--key-size must be 4096 for RSA")
        else:  # ecc
            args.key_size = args.key_size or 384
            if args.key_size != 384:
                raise ValueError("--key-size must be 384 for ECC")

        if not os.path.isfile(args.passphrase_file) or not os.access(args.passphrase_file, os.R_OK):
            raise ValueError(f"Cannot read passphrase file: {args.passphrase_file}")

        if args.validity_days <= 0:
            raise ValueError("--validity-days must be positive")
        if not args.subject.strip():
            raise ValueError("--subject cannot be empty")

    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during validation: {e}")
        sys.exit(1)

    if args.command == "ca" and args.action == "init":
        try:
            init_ca(args, logger)
        except Exception as e:
            logger.error(f"CRITICAL FAILURE: {e}")
            import traceback
            logger.error(traceback.format_exc())
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()