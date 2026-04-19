import time
import sqlite3
import concurrent.futures
from unittest.mock import MagicMock
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from micropki.database import Database
from micropki.crypto_utils import generate_key, create_self_signed_cert, generate_unique_serial

TOTAL_CERTS = 100
CONCURRENT_THREADS = 20
DB_PATH = "./pki/stress_test.db"

def worker(worker_id, db_path, key, cert_template):
    local_db = Database(db_path, MagicMock())
    try:
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, f"User-{worker_id}-{time.time_ns()}")
        ]))
        builder = builder.issuer_name(cert_template.issuer)
        builder = builder.not_valid_before(cert_template.not_valid_before_utc)
        builder = builder.not_valid_after(cert_template.not_valid_after_utc)
        builder = builder.public_key(cert_template.public_key())
        
        builder = builder.serial_number(generate_unique_serial())
        
        new_cert = builder.sign(key, hashes.SHA256())
        
        local_db.insert_cert(new_cert)
        return True
    except Exception as e:
        print(f"Error in worker {worker_id}: {e}")
        return False

def run_test():
    if os.path.exists(DB_PATH): os.remove(DB_PATH)
    logger = MagicMock()
    db = Database(DB_PATH, logger)
    db.init_db()

    print("Generating base crypto materials...")
    key = generate_key("rsa", 2048)
    cert_template = create_self_signed_cert(key, "/CN=Stress Test CA", 365)

    print(f"Starting highload test: {TOTAL_CERTS} certs, {CONCURRENT_THREADS} threads...")
    start_time = time.perf_counter()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_THREADS) as executor:
        futures = [executor.submit(worker, i, DB_PATH, key, cert_template) for i in range(TOTAL_CERTS)]
        concurrent.futures.wait(futures)

    duration = time.perf_counter() - start_time

    print("\nVerifying data integrity in SQLite...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM certificates")
    actual_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(DISTINCT serial_hex) FROM certificates")
    unique_count = cursor.fetchone()[0]
    
    conn.close()

    print(f"Total time: {duration:.2f}s ({TOTAL_CERTS / duration:.2f} certs/s)")
    print(f"Database records: {actual_count}")
    print(f"Unique serials:   {unique_count}")

    if actual_count != TOTAL_CERTS:
        print(f"Fail: expected {TOTAL_CERTS} records, but found {actual_count}. Some inserts failed.")
    elif actual_count != unique_count:
        print(f"Fail: detected collision {actual_count - unique_count} duplicate serial numbers found.")
    else:
        print("Success: all records are unique")

if __name__ == "__main__":
    import os
    run_test()