import os
import sys
from datetime import datetime, timezone, timedelta
import secrets

from .crypto_utils import (
    generate_key, create_self_signed_cert, save_encrypted_key, save_cert,
    ensure_pki_dirs, load_private_key, load_certificate, save_unencrypted_key,
    parse_dn, verify_chain, generate_unique_serial
)
from .templates import TEMPLATES, parse_san
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from .database import Database

def create_policy_file(out_dir, args, cert):
    policy_path = os.path.join(out_dir, "policy.txt")
    
    not_before = cert.not_valid_before.isoformat()
    not_after = cert.not_valid_after.isoformat()
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
        os.chmod(key_path, 0o600)
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

def issue_intermediate(args, logger):
    logger.info("=== Starting Intermediate CA issuance ===")
    
    logger.info(f"Loading Root CA from {args.root_cert} and {args.root_key}")
    with open(args.root_pass_file, "rb") as f:
        root_pass = f.read().strip()
    root_key = load_private_key(args.root_key, root_pass)
    root_cert = load_certificate(args.root_cert)

    logger.info(f"Generating new {args.key_type.upper()} key ({args.key_size} bits) for Intermediate CA")
    intermediate_key = generate_key(args.key_type, args.key_size)

    subject = parse_dn(args.subject)
    issuer = root_cert.subject

    hash_alg = hashes.SHA256() if isinstance(root_key, rsa.RSAPrivateKey) else hashes.SHA384()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(intermediate_key.public_key())
    builder = builder.serial_number(generate_unique_serial())
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=args.validity_days))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=args.pathlen), critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=False, content_commitment=False, 
                       key_encipherment=False, data_encipherment=False, key_agreement=False, 
                       encipher_only=False, decipher_only=False), critical=True
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()), critical=False
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False
    )
    
    intermediate_cert = builder.sign(root_key, hash_alg)

    private_dir, certs_dir = ensure_pki_dirs(args.out_dir, logger)
    key_path = os.path.join(private_dir, "intermediate.key.pem")
    cert_path = os.path.join(certs_dir, "intermediate.cert.pem")

    with open(args.passphrase_file, "rb") as f:
        intermediate_pass = f.read().strip()
    
    save_encrypted_key(intermediate_key, intermediate_pass, key_path)
    os.chmod(key_path, 0o600)
    save_cert(intermediate_cert, cert_path)

    try:
        db = Database(args.db_path, logger)
        db.insert_cert(intermediate_cert)
    except Exception as e:
        logger.error(f"FATAL: Could not write cert to database. Aborting. Error: {e}")
        sys.exit(1)

    logger.info("SUCCESS: Intermediate CA created and recorded in the database.")
    logger.info(f"  Key: {key_path}")
    logger.info(f"  Cert: {cert_path}")

def issue_cert(args, logger):
    logger.info(f"=== Starting certificate issuance with template '{args.template}' ===")

    if args.template == "server" and not args.san:
        logger.error("Server certificate requires SAN")
        sys.exit(1)
        
    logger.info(f"Loading signing CA from {args.ca_cert} and {args.ca_key}")
    with open(args.ca_pass_file, "rb") as f:
        ca_pass = f.read().strip()
    ca_key = load_private_key(args.ca_key, ca_pass)
    ca_cert = load_certificate(args.ca_cert)

    template = TEMPLATES[args.template]
    try:
        san_list = args.san or []
        for san_str in san_list:
            if ":" not in san_str:
                logger.error(f"Invalid SAN format: {san_str}")
                sys.exit(1)
            san_type = san_str.split(":", 1)[0].lower().strip()
            if san_type not in template["valid_san_types"]:
                logger.error(f"SAN type '{san_type}' is not allowed for template '{args.template}'")
                sys.exit(1)
        san_ext = parse_san(san_list)
    except ValueError as e:
        logger.error(f"Invalid SAN: {e}")
        sys.exit(1)

    key_type = "rsa"
    key_size = 2048
    logger.info(f"Generating new {key_type.upper()} key ({key_size} bits) for end-entity")
    entity_key = generate_key(key_type, key_size)

    subject = parse_dn(args.subject)
    hash_alg = hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(entity_key.public_key())
    builder = builder.serial_number(generate_unique_serial())
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=args.validity_days))

    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(x509.KeyUsage(**template["key_usage"]), critical=True)
    builder = builder.add_extension(x509.ExtendedKeyUsage(template["extended_key_usage"]), critical=False)
    if san_ext:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_ext), critical=False)
    
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(entity_key.public_key()), critical=False
    )
    
    entity_cert = builder.sign(ca_key, hash_alg)
    
    cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    base_name = cn.replace(" ", "_").lower()
    cert_path = os.path.join(args.out_dir, f"{base_name}.cert.pem")
    key_path = os.path.join(args.out_dir, f"{base_name}.key.pem")

    enforce_leaf_constraints(entity_cert)

    save_cert(entity_cert, cert_path)

    try:
        db = Database(args.db_path, logger)
        db.insert_cert(entity_cert)
    except Exception as e:
        logger.error(f"FATAL: Could not write cert to database. Aborting. Error: {e}")
        sys.exit(1)

    logger.info(f"SUCCESS: Certificate for '{cn}' issued and recorded in the database.")
    
    logger.warning(f"Saving unencrypted private key to {key_path}")
    save_unencrypted_key(entity_key, key_path)
    os.chmod(key_path, 0o600)
    
    logger.info(f"SUCCESS: Certificate for '{cn}' issued.")

def enforce_leaf_constraints(cert):
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    if bc.ca:
        raise ValueError("Leaf certificate must not have CA=true")