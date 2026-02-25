import os
import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock

from micropki.ca import init_ca

class TestIntegration:
    @pytest.fixture
    def mock_logger(self):
        return MagicMock()

    @pytest.fixture
    def passphrase_file(self, tmp_path):
        p_file = tmp_path / "pass.txt"
        p_file.write_text("test-passphrase-123")
        return str(p_file)

    def test_init_ca_success(self, tmp_path, passphrase_file, mock_logger):
        out_dir = tmp_path / "pki"
        
        args = SimpleNamespace(
            subject="/CN=Test CA/O=IntegrationTest",
            key_type="rsa",
            key_size=4096,
            passphrase_file=passphrase_file,
            out_dir=str(out_dir),
            validity_days=365,
            force=True
        )

        init_ca(args, mock_logger)

        assert (out_dir / "private" / "ca.key.pem").exists()
        assert (out_dir / "certs" / "ca.cert.pem").exists()
        assert (out_dir / "policy.txt").exists()

        policy_content = (out_dir / "policy.txt").read_text()
        assert "MicroPKI Root CA Policy" in policy_content
        assert "/CN=Test CA/O=IntegrationTest" in policy_content