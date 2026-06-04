import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.exceptions import InvalidSignature

def verify_signature(cert, issuer_cert):
    public_key = issuer_cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            return False, "Unsupported public key type"
        return True, None
    except InvalidSignature:
        return False, "Invalid signature"
    except Exception as e:
        return False, str(e)

def validate_path(leaf_cert, untrusted_certs, trusted_certs, validation_time=None):
    if not validation_time:
        validation_time = datetime.datetime.now(datetime.timezone.utc)
    elif validation_time.tzinfo is None:
        validation_time = validation_time.replace(tzinfo=datetime.timezone.utc)

    chain = [leaf_cert]
    current = leaf_cert
    max_chain_depth = 10
    steps_log = []

    while len(chain) < max_chain_depth:
        is_trusted = False
        for root in trusted_certs:
            if root.subject == current.subject and root.public_key() == current.public_key():
                is_trusted = True
                steps_log.append(f"Reached trusted root: {current.subject.rfc4514_string()}")
                break
        if is_trusted:
            break

        issuer = next((c for c in untrusted_certs if c.subject == current.issuer), None)
        if not issuer:
            issuer = next((c for c in trusted_certs if c.subject == current.issuer), None)

        if issuer:
            if issuer in chain:
                return False, chain, "Circular dependency detected"
            chain.append(issuer)
            current = issuer
            steps_log.append(f"Added: {current.subject.rfc4514_string()}")
        else:
            return False, chain, f"Issuer not found: {current.issuer.rfc4514_string()}"
    else:
        return False, chain, "Chain too long"

    root_idx = len(chain) - 1
    for i in range(root_idx, -1, -1):
        cert = chain[i]
        subject_name = cert.subject.rfc4514_string()
        
        if not (cert.not_valid_before_utc <= validation_time <= cert.not_valid_after_utc):
            return False, chain, f"Expired: {subject_name}"
        
        if i < root_idx:
            issuer = chain[i+1]
            sig_ok, sig_err = verify_signature(cert, issuer)
            if not sig_ok:
                return False, chain, f"Signature fail: {subject_name} ({sig_err})"

        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if i > 0:
                if not bc.ca:
                    return False, chain, f"Not a CA: {subject_name}"
                if bc.path_length is not None:
                    cas_below = i - 1
                    if cas_below > bc.path_length:
                        return False, chain, f"PathLen exceeded: {subject_name}"
            else:
                if bc.ca:
                    return False, chain, f"Leaf is CA: {subject_name}"
        except x509.ExtensionNotFound:
            if i > 0:
                return False, chain, f"No BasicConstraints: {subject_name}"

        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if i > 0 and not ku.key_cert_sign:
                return False, chain, f"No keyCertSign: {subject_name}"
        except x509.ExtensionNotFound:
            pass

    return True, chain, "\n".join(steps_log)