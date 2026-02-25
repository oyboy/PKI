import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from micropki import crypto_utils

class TestCryptoUtils:
    
    def test_generate_rsa_key(self):
        key = crypto_utils.generate_key("rsa", 4096)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_generate_ecc_key(self):
        key = crypto_utils.generate_key("ecc", 384)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == 'secp384r1'

    def test_parse_dn_slash(self):
        dn_obj = crypto_utils.parse_dn("/CN=Test/O=MicroPKI/C=US")
        assert isinstance(dn_obj, x509.Name)
        assert len(dn_obj) == 3

    def test_parse_dn_comma(self):
        dn_obj = crypto_utils.parse_dn("CN=Test,O=MicroPKI,C=US")
        assert len(dn_obj) == 3

    def test_create_self_signed_cert(self):
        key = crypto_utils.generate_key("rsa", 4096)
        subject = "/CN=Test Root CA/O=MicroPKI"
        validity_days = 365
        
        cert = crypto_utils.create_self_signed_cert(
            private_key=key,
            subject_str=subject,
            validity_days=validity_days
        )
        
        assert isinstance(cert, x509.Certificate)
        assert cert.subject == cert.issuer 
        
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.critical is True

    def test_encrypt_save_and_load_key(self, tmp_path):
        key = crypto_utils.generate_key("rsa", 4096)
        passphrase = b"secret123"
        key_file = tmp_path / "test.key"

        crypto_utils.save_encrypted_key(key, passphrase, str(key_file))
        assert key_file.exists()

        with open(key_file, "rb") as f:
            loaded_key = serialization.load_pem_private_key(
                f.read(),
                password=passphrase
            )
        assert isinstance(loaded_key, rsa.RSAPrivateKey)