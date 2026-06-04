import pytest
from micropki.validation import validate_path
from micropki.crypto_utils import generate_key, create_self_signed_cert
from micropki.templates import parse_san
from cryptography import x509
import datetime

class TestSprint6:
    def test_path_length_constraint(self):
        root_key = generate_key("rsa", 2048)
        root_cert = create_self_signed_cert(root_key, "/CN=Root", 365)
        
        int_key = generate_key("rsa", 2048)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Int")]))
        builder = builder.issuer_name(root_cert.subject)
        builder = builder.public_key(int_key.public_key())
        builder = builder.serial_number(12345)
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))

        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        int_cert = builder.sign(root_key, x509.hashes.SHA256())
        
        leaf_key = generate_key("rsa", 2048)
        builder2 = x509.CertificateBuilder()
        builder2 = builder2.subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Leaf")]))
        builder2 = builder2.issuer_name(int_cert.subject)
        builder2 = builder2.public_key(leaf_key.public_key())
        builder2 = builder2.serial_number(6789)
        builder2 = builder2.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder2 = builder2.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))

        builder2 = builder2.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        leaf_cert = builder2.sign(int_key, x509.hashes.SHA256())
        
        success, chain, msg = validate_path(leaf_cert, [int_cert], [root_cert])
        assert success is False
        assert "PathLen exceeded" in msg

    def test_invalid_signature_logic(self):
        root_key = generate_key("rsa", 2048)
        root_cert = create_self_signed_cert(root_key, "/CN=Root", 365)
        
        fake_key = generate_key("rsa", 2048)
        
        leaf_key = generate_key("rsa", 2048)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Leaf")]))
        builder = builder.issuer_name(root_cert.subject)
        builder = builder.public_key(leaf_key.public_key())
        builder = builder.serial_number(1)
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        
        leaf_cert = builder.sign(fake_key, x509.hashes.SHA256())
        
        success, chain, msg = validate_path(leaf_cert, [], [root_cert])
        assert success is False
        assert "Signature fail" in msg