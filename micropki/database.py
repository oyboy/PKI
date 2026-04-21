import sqlite3
import os
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization

class Database:
    def __init__(self, db_path, logger):
        self.db_path = db_path
        self.logger = logger

        dirpath = os.path.dirname(db_path)
        if db_path != ":memory:" and dirpath:
            os.makedirs(dirpath, exist_ok=True)

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
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS crl_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ca_subject TEXT UNIQUE NOT NULL,
                    crl_number INTEGER NOT NULL,
                    last_generated TEXT NOT NULL
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

    def revoke_certificate(self, serial_hex, reason):
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status, issuer FROM certificates WHERE serial_hex = ?", (serial_hex.upper(),))
            row = cursor.fetchone()
            if not row:
                return "not_found"
            if row[0] == 'revoked':
                return "already_revoked"
            
            cursor.execute("""
                UPDATE certificates 
                SET status = 'revoked', revocation_date = ?, revocation_reason = ? 
                WHERE serial_hex = ?
            """, (now, reason, serial_hex.upper()))
            conn.commit()
            return row[1]

    def get_revoked_for_issuer(self, issuer_dn):
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT serial_hex, revocation_date, revocation_reason 
                FROM certificates 
                WHERE status = 'revoked' AND issuer = ?
            """, (issuer_dn,))
            return cursor.fetchall()

    def get_next_crl_number(self, ca_subject):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT crl_number FROM crl_metadata WHERE ca_subject = ?", (ca_subject,))
            row = cursor.fetchone()
            if row:
                new_num = row[0] + 1
                cursor.execute("UPDATE crl_metadata SET crl_number = ?, last_generated = ? WHERE ca_subject = ?",
                               (new_num, datetime.now(timezone.utc).isoformat(), ca_subject))
            else:
                new_num = 1
                cursor.execute("INSERT INTO crl_metadata (ca_subject, crl_number, last_generated) VALUES (?, ?, ?)",
                               (ca_subject, new_num, datetime.now(timezone.utc).isoformat()))
            conn.commit()
            return new_num

    def get_cert_record_by_serial(self, serial_hex: str):
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM certificates WHERE serial_hex = ?", (serial_hex.upper(),))
            return cursor.fetchone()