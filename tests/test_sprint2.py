import pytest
from micropki.templates import parse_san
from micropki.ca import issue_cert
from micropki.crypto_utils import generate_key, save_encrypted_key, save_cert, create_self_signed_cert
from cryptography import x509
import ipaddress
from types import SimpleNamespace
from unittest.mock import MagicMock

def test_parse_san_success():
    sans = ["dns:example.com", "ip:192.168.1.1", "email:test@test.com"]
    result = parse_san(sans)
    assert len(result) == 3
    assert isinstance(result[0], x509.DNSName)
    assert result[0].value == "example.com"
    assert isinstance(result[1], x509.IPAddress)
    assert result[1].value == ipaddress.ip_address("192.168.1.1")
    assert isinstance(result[2], x509.RFC822Name)

def test_parse_san_invalid_format():
    with pytest.raises(ValueError, match="Invalid SAN format"):
        parse_san(["dns-example.com"])

def test_parse_san_unsupported_type():
    with pytest.raises(ValueError, match="Unsupported SAN type"):
        parse_san(["ftp:example.com"])

def test_issue_cert_invalid_san_for_template(tmp_path):
    mock_logger = MagicMock()
    
    passphrase = b"test-pass"
    
    ca_key = generate_key("rsa", 2048)
    ca_key_path = tmp_path / "ca.key"
    ca_pass_path = tmp_path / "ca.pass"
    ca_pass_path.write_bytes(passphrase)
    save_encrypted_key(ca_key, passphrase, str(ca_key_path))

    ca_cert_obj = create_self_signed_cert(ca_key, "/CN=Test CA", 365)
    ca_cert_path = tmp_path / "ca.cert.pem"
    save_cert(ca_cert_obj, str(ca_cert_path))

    args = SimpleNamespace(
        template="server",
        san=["email:hacker@evil.com"],
        ca_cert=str(ca_cert_path),
        ca_key=str(ca_key_path),
        ca_pass_file=str(ca_pass_path),
        subject="/CN=test",
        out_dir=str(tmp_path),
        validity_days=365
    )
    
    with pytest.raises(SystemExit) as e:
        issue_cert(args, mock_logger)
    
    assert e.value.code == 1
    mock_logger.error.assert_called_with(
        "Invalid SAN: SAN type 'rfc822' is not allowed for template 'server'"
    )

def test_no_san_server_cert(tmp_path):
    logger = MagicMock()

    ca_key = generate_key("rsa", 2048)
    passphrase = b"test"
    ca_key_path = tmp_path / "ca.key"
    ca_pass = tmp_path / "ca.pass"
    ca_pass.write_bytes(passphrase)

    save_encrypted_key(ca_key, passphrase, str(ca_key_path))
    ca_cert = create_self_signed_cert(ca_key, "/CN=CA", 365)
    ca_cert_path = tmp_path / "ca.pem"
    save_cert(ca_cert, str(ca_cert_path))

    args = SimpleNamespace(
        template="server",
        san=None,
        ca_cert=str(ca_cert_path),
        ca_key=str(ca_key_path),
        ca_pass_file=str(ca_pass),
        subject="/CN=test",
        out_dir=str(tmp_path),
        validity_days=365
    )

    with pytest.raises(SystemExit):
        issue_cert(args, logger)


def test_invalid_san_template(tmp_path):
    logger = MagicMock()

    ca_key = generate_key("rsa", 2048)
    passphrase = b"test"
    ca_key_path = tmp_path / "ca.key"
    ca_pass = tmp_path / "ca.pass"
    ca_pass.write_bytes(passphrase)

    save_encrypted_key(ca_key, passphrase, str(ca_key_path))
    ca_cert = create_self_signed_cert(ca_key, "/CN=CA", 365)
    ca_cert_path = tmp_path / "ca.pem"
    save_cert(ca_cert, str(ca_cert_path))

    args = SimpleNamespace(
        template="server",
        san=["email:test@test.com"],
        ca_cert=str(ca_cert_path),
        ca_key=str(ca_key_path),
        ca_pass_file=str(ca_pass),
        subject="/CN=test",
        out_dir=str(tmp_path),
        validity_days=365
    )

    with pytest.raises(SystemExit):
        issue_cert(args, logger)


def test_leaf_ca_true_rejected(tmp_path):
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    key = generate_key("rsa", 2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bad")])

    cert = create_self_signed_cert(key, "/CN=bad", 365)

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True