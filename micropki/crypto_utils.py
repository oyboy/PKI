import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

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