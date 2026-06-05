import hashlib
from cryptography.hazmat.primitives import serialization


def public_key_hash(public_key):
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()
