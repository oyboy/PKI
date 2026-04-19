import pytest
import re
from fastapi.testclient import TestClient

from micropki.database import Database
from micropki.repository import app 
from micropki.crypto_utils import generate_key, create_self_signed_cert
from unittest.mock import MagicMock

@pytest.fixture
def mock_logger():
    return MagicMock()

@pytest.fixture
def db(mock_logger):
    database = Database(db_path=":memory:", logger=mock_logger)
    database.init_db()
    return database

class TestDatabase:
    def test_db_init(self, db):
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='certificates';")
            assert cursor.fetchone() is not None

    def test_insert_and_get_cert(self, db):
        key = generate_key("rsa", 2048)
        cert = create_self_signed_cert(key, "/CN=DB Test", 30)
        serial_hex = f"{cert.serial_number:X}"

        db.insert_cert(cert)

        pem = db.get_cert_pem_by_serial(serial_hex)
        assert pem is not None
        assert pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_list_certs(self, db):
        key1 = generate_key("rsa", 2048)
        cert1 = create_self_signed_cert(key1, "/CN=List Test 1", 30)
        db.insert_cert(cert1)

        key2 = generate_key("rsa", 2048)
        cert2 = create_self_signed_cert(key2, "/CN=List Test 2", 30)
        db.insert_cert(cert2)

        all_certs = db.list_certs()
        assert len(all_certs) == 2

class TestRepositoryAPI:
    @pytest.fixture
    def client(self, db):
        app.state.db_path = ":memory:" 
        def get_test_db():
            return db
                app.state.db_path = db.db_path
        app.state.cert_dir = "./pki/certs"

        return TestClient(app)

    def test_get_cert_invalid_serial_format(self, client):
        response = client.get("/certificate/XYZ123-INVALID")
        assert response.status_code == 400
    
    def test_get_cert_not_found(self, client):
        response = client.get("/certificate/112233445566778899AABBCCDDEEFF")
        assert response.status_code == 404

    def test_get_ca_invalid_level(self, client):
        response = client.get("/ca/ceo")
        assert response.status_code == 400

    def test_crl_endpoint_is_stub(self, client):
        response = client.get("/crl")
        assert response.status_code == 501
        assert "not implemented" in response.text.lower()