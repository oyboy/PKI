import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

def check_revocation(cert, issuer_cert, logger, crl_url=None, ocsp_url=None):
    actual_ocsp_url = ocsp_url
    if not actual_ocsp_url:
        try:
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            for desc in aia:
                if desc.access_method == x509.OID_OCSP:
                    actual_ocsp_url = desc.access_location.value
        except x509.ExtensionNotFound:
            pass

    if actual_ocsp_url:
        try:
            logger.info(f"Checking OCSP at {actual_ocsp_url}...")
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
            req_der = builder.build().public_bytes(serialization.Encoding.DER)
            res = requests.post(actual_ocsp_url, data=req_der, headers={'Content-Type': 'application/ocsp-request'}, timeout=5)
            if res.status_code == 200:
                ocsp_res = ocsp.load_der_ocsp_response(res.content)
                if ocsp_res.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                    if ocsp_res.certificate_status == ocsp.OCSPCertStatus.GOOD:
                        return "good", "OCSP"
                    elif ocsp_res.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                        return "revoked", f"OCSP: {ocsp_res.revocation_time}"
        except Exception as e:
            logger.warning(f"OCSP failed: {e}")

    actual_crl_url = crl_url
    if not actual_crl_url:
        try:
            cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
            for point in cdp:
                for full_name in point.full_name:
                    actual_crl_url = full_name.value
        except x509.ExtensionNotFound:
            pass

    if actual_crl_url:
        try:
            if actual_crl_url.startswith("http"):
                crl_data = requests.get(actual_crl_url, timeout=5).content
            else:
                with open(actual_crl_url, "rb") as f:
                    crl_data = f.read()
            
            crl = x509.load_pem_x509_crl(crl_data)
            
            try:
                issuer_cert.public_key().verify(
                    crl.signature, 
                    crl.tbs_certlist_bytes, 
                    crl.signature_algorithm_parameters, 
                    crl.signature_hash_algorithm
                )
            except Exception:
                return "unknown", "CRL signature mismatch (likely wrong CRL for this issuer)"

            if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
                return "revoked", "CRL"
            return "good", "CRL"
        except Exception as e:
            logger.warning(f"CRL check skipped: {e}")

    return "unknown", "No revocation source found"