from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
import datetime
from cryptography.x509.oid import ObjectIdentifier

OCSP_NONCE_OID = ObjectIdentifier("1.3.6.1.5.5.7.48.1.2")

def process_ocsp_request(request_data, db, ca_cert, responder_cert, responder_key, logger):
    try:
        ocsp_req = ocsp.load_der_ocsp_request(request_data)
    except Exception as e:
        logger.error(f"Malformed OCSP request: {e}")
        return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

    serial_hex = f"{ocsp_req.serial_number:X}"
    cert_record = db.get_cert_record_by_serial(serial_hex)
    if not cert_record:
        logger.warning(f"OCSP request for unknown serial: {serial_hex}. Returning UNAUTHORIZED.")
        return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED)

    builder = ocsp.OCSPResponseBuilder()
    now = datetime.datetime.now(datetime.timezone.utc)
    subject_cert = x509.load_pem_x509_certificate(cert_record['cert_pem'].encode())
    
    if cert_record['status'] == 'revoked':
        from .revocation import REASON_CODES
        revocation_time = datetime.datetime.fromisoformat(cert_record['revocation_date'])
        reason_str = cert_record['revocation_reason']
        reason = REASON_CODES.get(reason_str, x509.ReasonFlags.unspecified)
        
        builder = builder.add_response(
            cert=subject_cert, issuer=ca_cert, algorithm=ocsp_req.hash_algorithm,
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            this_update=now, next_update=now + datetime.timedelta(minutes=5),
            revocation_time=revocation_time, 
            revocation_reason=reason
        )
    else:
        builder = builder.add_response(
            cert=subject_cert,
            issuer=ca_cert,
            algorithm=ocsp_req.hash_algorithm,
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=now,
            next_update=now + datetime.timedelta(minutes=5),
            revocation_time=None,
            revocation_reason=None
        )

    for ext in ocsp_req.extensions:
        if ext.oid == OCSP_NONCE_OID:
            builder = builder.add_extension(ext.value, critical=False)

    builder = builder.responder_id(
        ocsp.OCSPResponderEncoding.HASH,
        responder_cert
    )

    return builder.sign(responder_key, hashes.SHA256())