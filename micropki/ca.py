import os
import sys
from datetime import datetime, timezone

from .crypto_utils import (
    generate_key,
    create_self_signed_cert,
    save_encrypted_key,
    save_cert,
    ensure_pki_dirs,
)

def create_policy_file(out_dir, args, cert):
    policy_path = os.path.join(out_dir, "policy.txt")
    
    not_before = cert.not_valid_before_utc.isoformat()
    not_after = cert.not_valid_after_utc.isoformat()
    serial_hex = hex(cert.serial_number)
    
    content = (
        f"MicroPKI Root CA Policy\n"
        f"-----------------------\n"
        f"Version: 1.0\n"
        f"Created: {datetime.now(timezone.utc).isoformat()}\n\n"
        f"CA Subject: {args.subject}\n"
        f"Serial Number: {serial_hex}\n"
        f"Algorithm: {args.key_type.upper()} ({args.key_size} bits)\n"
        f"Validity: {not_before} to {not_after}\n"
        f"Purpose: Root CA for MicroPKI demonstration (Sprint 1)\n"
    )
    
    with open(policy_path, "w", encoding="utf-8") as f:
        f.write(content)
    
    return policy_path

def init_ca(args, logger):
    logger.info("=== Starting Root CA initialization ===")

    try:
        with open(args.passphrase_file, "rb") as f:
            passphrase = f.read().strip()
    except FileNotFoundError:
        logger.error(f"Passphrase file not found: {args.passphrase_file}")
        sys.exit(1)
        
    if not passphrase:
        logger.error("Passphrase file is empty")
        sys.exit(1)

    private_dir, certs_dir = ensure_pki_dirs(args.out_dir, logger)

    key_path = os.path.join(private_dir, "ca.key.pem")
    cert_path = os.path.join(certs_dir, "ca.cert.pem")

    if (os.path.exists(key_path) or os.path.exists(cert_path)) and not args.force:
        logger.error(f"Files already exist in {args.out_dir}. Use --force to overwrite.")
        sys.exit(1)

    logger.info(f"Generating {args.key_type.upper()} key ({args.key_size} bits)")
    private_key = generate_key(args.key_type, args.key_size)

    logger.info("Creating self-signed X.509v3 certificate")
    try:
        cert = create_self_signed_cert(private_key, args.subject, args.validity_days)
    except ValueError as e:
        logger.error(f"Certificate creation failed: {e}")
        sys.exit(1)

    logger.info("Saving encrypted private key (PKCS#8)")
    save_encrypted_key(private_key, passphrase, key_path)
    try:
        os.chmod(key_path, 0o600) # KEY-3
    except OSError:
        logger.warning("Cannot set 0o600 on ca.key.pem")

    logger.info("Saving certificate (PEM)")
    save_cert(cert, cert_path)

    logger.info("Generating policy.txt")
    policy_path = create_policy_file(args.out_dir, args, cert)

    logger.info(f"SUCCESS: Root CA successfully created in {args.out_dir}")
    logger.info(f"   Private key: {key_path}")
    logger.info(f"   Certificate: {cert_path}")
    logger.info(f"   Policy File: {policy_path}")