import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_crl(ca_cert, ca_key, revoked_certs, crl_number, next_update_days):
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.last_update(now)
    builder = builder.next_update(now + datetime.timedelta(days=next_update_days))
    
    for cert_info in revoked_certs:
        revocation_date = datetime.datetime.fromisoformat(cert_info['revocation_date'])
        
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            int(cert_info['serial_hex'], 16)
        ).revocation_date(
            revocation_date
        )
        
        reason = cert_info['revocation_reason']
        if reason and reason != 'unspecified':
            from .revocation import REASON_CODES
            revoked_cert = revoked_cert.add_extension(
                x509.CRLReason(REASON_CODES[reason]), critical=False
            )
            
        builder = builder.add_revoked_certificate(revoked_cert.build())

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.CRLNumber(crl_number),
        critical=False
    )

    hash_alg = hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()
    crl = builder.sign(ca_key, hash_alg)
    
    return crl.public_bytes(serialization.Encoding.PEM)