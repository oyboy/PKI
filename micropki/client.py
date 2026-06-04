import os
import sys
import requests
import datetime
from .crypto_utils import (
    generate_key, generate_csr, save_unencrypted_key, 
    load_certificate, load_csr
)
from .revocation_check import check_revocation
from .validation import validate_path

def client_gen_csr(args, logger):
    k_type = args.key_type.lower()
    k_size = args.key_size or (2048 if k_type == "rsa" else 256)
    key = generate_key(k_type, k_size)
    csr_pem = generate_csr(key, args.subject, args.san)
    old_umask = os.umask(0o177)
    try:
        save_unencrypted_key(key, args.out_key)
    finally:
        os.umask(old_umask)
    with open(args.out_csr, "wb") as f:
        f.write(csr_pem)
    logger.info(f"CSR and Key saved")

def client_request_cert(args, logger):
    with open(args.csr, "rb") as f:
        csr_data = f.read()
    url = f"{args.ca_url}/request-cert?template={args.template}"
    headers = {"X-API-Key": "changeme", "Content-Type": "application/x-pem-file"}
    res = requests.post(url, data=csr_data, headers=headers)
    if res.status_code in [200, 201]:
        with open(args.out_cert, "wb") as f:
            f.write(res.content)
        logger.info(f"Cert saved to {args.out_cert}")
    else:
        logger.error(f"Error {res.status_code}: {res.text}")
        sys.exit(1)

def client_validate(args, logger):
    leaf = load_certificate(args.cert)
    trusted = [load_certificate(args.trusted)]
    untrusted = [load_certificate(p) for p in (args.untrusted or [])]
    v_time = None
    if args.validation_time:
        v_time = datetime.datetime.fromisoformat(args.validation_time).replace(tzinfo=datetime.timezone.utc)

    success, chain, msg = validate_path(leaf, untrusted, trusted, validation_time=v_time)
    if not success:
        logger.error(f"Chain invalid: {msg}")
        sys.exit(1)
    
    logger.info(f"Chain valid: {' -> '.join([c.subject.rfc4514_string() for c in chain])}")

    if args.mode == "full":
        for i in range(len(chain) - 1):
            subject = chain[i]
            issuer = chain[i+1]
            status, rev_msg = check_revocation(subject, issuer, logger, crl_url=args.crl, ocsp_url=args.ocsp_url)
            
            if status == "good":
                logger.info(f"Revocation OK [{status}]: {subject.subject.rfc4514_string()}")
            elif status == "revoked":
                logger.error(f"CERTIFICATE REVOKED: {subject.subject.rfc4514_string()} ({rev_msg})")
                sys.exit(1)
            else:
                if i == 0:
                    logger.error(f"Could not verify leaf revocation: {rev_msg}")
                    sys.exit(1)
                else:
                    logger.warning(f"Revocation info missing for CA (skipping): {subject.subject.rfc4514_string()}")

    logger.info("VERIFICATION SUCCESSFUL")

def client_check_status(args, logger):
    cert = load_certificate(args.cert)
    ca_cert = load_certificate(args.ca_cert)
    status, reason = check_revocation(cert, ca_cert, logger, crl_url=args.crl, ocsp_url=args.ocsp_url)
    logger.info(f"RESULT: {status} ({reason})")
    if status != "good": sys.exit(1)