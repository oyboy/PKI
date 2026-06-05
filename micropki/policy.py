from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes

MAX_VALIDITY = {"root": 3650, "intermediate": 1825, "leaf": 365}


def key_type_and_size(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ecc", getattr(public_key.curve, "key_size", 0)
    return "unknown", 0


def validate_ca_key(public_key, role):
    kt, size = key_type_and_size(public_key)
    if kt == "rsa":
        min_size = 4096 if role == "root" else 2048
        if size < min_size:
            raise ValueError(f"Policy violation: {role} CA RSA key must be at least {min_size} bits")
    elif kt == "ecc":
        if size < 384:
            raise ValueError(f"Policy violation: {role} CA ECC key must be at least P-384")
    else:
        raise ValueError("Policy violation: unsupported CA key type")


def validate_validity(role, days):
    max_days = MAX_VALIDITY[role]
    if days > max_days:
        raise ValueError(f"Policy violation: {role} certificate validity must not exceed {max_days} days")


def san_type(name):
    if isinstance(name, x509.DNSName): return "dns"
    if isinstance(name, x509.IPAddress): return "ip"
    if isinstance(name, x509.RFC822Name): return "email"
    if isinstance(name, x509.UniformResourceIdentifier): return "uri"
    return "unknown"


def validate_leaf_policy(template, public_key, sans, validity_days, csr=None, allow_wildcard=False):
    validate_validity("leaf", validity_days)
    kt, size = key_type_and_size(public_key)
    if kt == "rsa" and size < 2048:
        raise ValueError("Policy violation: leaf RSA key must be at least 2048 bits")
    if kt == "ecc" and size < 256:
        raise ValueError("Policy violation: leaf ECC key must be at least P-256")
    if kt not in ("rsa", "ecc"):
        raise ValueError("Policy violation: unsupported public key type")

    allowed = {
        "server": {"dns", "ip"},
        "client": {"email", "dns", "ip", "uri"},
        "code_signing": {"dns", "uri"},
        "ocsp": {"dns", "uri"},
    }.get(template, set())
    got = [san_type(x) for x in (sans or [])]
    for typ in got:
        if typ not in allowed:
            raise ValueError(f"SAN type '{typ}' is not allowed for template '{template}'")
    if template == "server":
        if not sans:
            raise ValueError("Server certificate requires SAN")
        for n in sans:
            if isinstance(n, x509.DNSName) and n.value.startswith("*.") and not allow_wildcard:
                raise ValueError("Policy violation: wildcard SAN is not allowed by default")
    if template == "client" and "email" not in got:
        raise ValueError("Policy violation: client certificate requires at least one email SAN")
    if csr:
        h = csr.signature_hash_algorithm
        if h and h.name.lower() in ("sha1", "md5"):
            raise ValueError("Policy violation: weak CSR signature hash is not allowed")
        if kt == "ecc" and size >= 384 and h and not isinstance(h, (hashes.SHA384, hashes.SHA512)):
            raise ValueError("Policy violation: P-384 CSR must use SHA-384 or stronger")


def validate_intermediate_policy(public_key, validity_days, pathlen):
    validate_validity("intermediate", validity_days)
    validate_ca_key(public_key, "intermediate")
    if pathlen != 0:
        raise ValueError("Policy violation: intermediate pathLen must be 0")
