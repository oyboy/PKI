import hashlib, os
from .audit import utc_now
from cryptography.hazmat.primitives import serialization


def ct_path_from_out_dir(out_dir=None):
    base = out_dir or "./pki"
    if os.path.basename(os.path.normpath(base)) == "certs":
        base = os.path.dirname(os.path.normpath(base)) or "."
    return os.path.join(base, "audit", "ct.log")


def cert_fingerprint(cert):
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def append_ct(cert, out_dir=None, ct_file=None):
    path = ct_file or ct_path_from_out_dir(out_dir)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    serial = hex(cert.serial_number)[2:].upper()
    line = " | ".join([utc_now(), serial, cert.subject.rfc4514_string(), cert_fingerprint(cert), cert.issuer.rfc4514_string()])
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    try: os.chmod(path, 0o644)
    except OSError: pass
    return path


def verify_inclusion(serial=None, cert=None, ct_file="./pki/audit/ct.log"):
    needle = serial.upper() if serial else None
    if cert:
        needle = cert_fingerprint(cert)
    if not needle or not os.path.exists(ct_file):
        return False
    with open(ct_file, encoding="utf-8") as f:
        return any(needle in line.upper() or needle in line for line in f)
