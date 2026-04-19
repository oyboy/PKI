import sqlite3
import os
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization

class Database:
    def __init__(self, db_path, logger):
        self.db_path = db_path
        self.logger = logger
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        self.logger.info(f"Initializing database at {self.db_path}")
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_hex TEXT UNIQUE NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    cert_pem TEXT NOT NULL,
                    status TEXT NOT NULL,
                    revocation_reason TEXT,
                    revocation_date TEXT,
                    created_at TEXT NOT NULL
                );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON certificates (status);")
                conn.commit()
            self.logger.info("Database schema initialized successfully.")
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            raise

    def insert_cert(self, cert):
        self.logger.info(f"Inserting certificate with serial {hex(cert.serial_number)} into database.")
        pem_data = cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')
        
        record = {
            "serial_hex": hex(cert.serial_number)[2:].upper(),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "cert_pem": pem_data,
            "status": "valid",
            "revocation_reason": None,
            "revocation_date": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO certificates (
                        serial_hex, subject, issuer, not_before, not_after,
                        cert_pem, status, revocation_reason, revocation_date, created_at
                    ) VALUES (
                        :serial_hex, :subject, :issuer, :not_before, :not_after,
                        :cert_pem, :status, :revocation_reason, :revocation_date, :created_at
                    )
                """, record)
                conn.commit()
            self.logger.info("Certificate successfully inserted.")
        except sqlite3.IntegrityError as e:
            self.logger.error(f"Failed to insert certificate: {e}. Serial number might already exist.")
            raise
        except Exception as e:
            self.logger.error(f"An unexpected database error occurred: {e}")
            raise

    def get_cert_pem_by_serial(self, serial_hex: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT cert_pem FROM certificates WHERE serial_hex = ?", (serial_hex.upper(),))
            result = cursor.fetchone()
            return result[0] if result else None

    def list_certs(self, status=None):
        query = "SELECT serial_hex, subject, not_after, status FROM certificates"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()