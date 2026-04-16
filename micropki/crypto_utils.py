import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
import sys

OID_MAP = {
    'CN': NameOID.COMMON_NAME,
    'O': NameOID.ORGANIZATION_NAME,
    'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
    'C': NameOID.COUNTRY_NAME,
    'ST': NameOID.STATE_OR_PROVINCE_NAME,
    'L': NameOID.LOCALITY_NAME,
    'E': NameOID.EMAIL_ADDRESS,
}

def parse_dn(dn_string: str) -> x509.Name:
    if not dn_string or not dn_string.strip():
        raise ValueError("DN string cannot be empty")
    
    dn_string = dn_string.strip()
    rdns = []
    
    if dn_string.startswith('/'):
        parts = [p for p in dn_string[1:].split('/') if p.strip()]
    else:
        parts = [p for p in dn_string.split(',') if p.strip()]
        
    for part in parts:
        if '=' not in part:
            continue
        key, value = part.split('=', 1)
        key = key.strip().upper()
        value = value.strip()
        
        if key in OID_MAP:
            rdns.append(x509.NameAttribute(OID_MAP[key], value))
        else:
            pass
            
    if not rdns:
        raise ValueError(f"No valid DN attributes found in: {dn_string}")
        
    return x509.Name(rdns)

def generate_key(key_type: str, key_size: int):
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "ecc":
        return ec.generate_private_key(ec.SECP384R1())
    raise ValueError("Unsupported key-type")

def create_self_signed_cert(private_key, subject_str: str, validity_days: int) -> x509.Certificate:
    subject = parse_dn(subject_str)
    serial = secrets.randbits(20) 
    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=validity_days)

    if isinstance(private_key, rsa.RSAPrivateKey):
        hash_alg = hashes.SHA256()
    else:
        hash_alg = hashes.SHA384()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject) # Self-signed: Issuer = Subject
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False,
    )

    cert = builder.sign(private_key, hash_alg)
    return cert

def save_encrypted_key(private_key, passphrase: bytes, path: str):
    encryption = serialization.BestAvailableEncryption(passphrase)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    with open(path, "wb") as f:
        f.write(pem)

def save_cert(cert, path: str):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(path, "wb") as f:
        f.write(pem)

def ensure_pki_dirs(out_dir: str, logger):
    private_dir = os.path.join(out_dir, "private")
    certs_dir = os.path.join(out_dir, "certs")
    
    os.makedirs(private_dir, exist_ok=True)
    os.makedirs(certs_dir, exist_ok=True)
    
    try:
        os.chmod(private_dir, 0o700)
    except OSError:
        logger.warning("Cannot set 0o700 on private/ (Windows implementation may vary)")
        
    return private_dir, certs_dir

def load_private_key(path: str, passphrase: bytes | None) -> serialization.load_pem_private_key:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase)

def load_certificate(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def save_unencrypted_key(private_key, path: str):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)

def verify_chain(args, logger):
    logger.info("=== Verifying certificate chain ===")
    
    leaf_cert = load_certificate(args.leaf_cert)
    logger.info(f"Loaded leaf certificate: {leaf_cert.subject.rfc4514_string()}")

    chain = []
    if args.untrusted:
        for untrusted_path in args.untrusted:
            cert = load_certificate(untrusted_path)
            chain.append(cert)
            logger.info(f"Loaded untrusted certificate: {cert.subject.rfc4514_string()}")
    
    ca_cert = load_certificate(args.ca_file)
    logger.info(f"Loaded trusted root: {ca_cert.subject.rfc4514_string()}")
    
    all_certs = [leaf_cert] + chain
    issuers = chain + [ca_cert]

    for i, cert in enumerate(all_certs):
        issuer = issuers[i]
        
        logger.info(f"Verifying signature of '{cert.subject.rfc4514_string()}' against '{issuer.subject.rfc4514_string()}'")
        
        try:
            issuer.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_parameters,
                cert.signature_hash_algorithm
            )
            logger.info("  [OK] Signature is valid.")
        except InvalidSignature:
            logger.error("  [FAIL] Signature is INVALID!")
            sys.exit(1)

        now = datetime.utcnow()
        if not (cert.not_valid_before <= now <= cert.not_valid_after):
            logger.error(f"  [FAIL] Certificate for '{cert.subject.rfc4514_string()}' has expired or is not yet valid.")
            sys.exit(1)
        logger.info("  [OK] Validity period is fine.")
        
        bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc.ca:
            logger.error(f"  [FAIL] Issuer '{issuer.subject.rfc4514_string()}' is not a CA.")
            sys.exit(1)
        logger.info("  [OK] Issuer is a CA.")

    logger.info("\nSUCCESS: Certificate chain appears to be valid.")