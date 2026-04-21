from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import ipaddress

TEMPLATES = {
    "server": {
        "key_usage": {
            "digital_signature": True,
            "key_encipherment": True,
            "content_commitment": False, "data_encipherment": False, "key_agreement": False,
            "key_cert_sign": False, "crl_sign": False, "encipher_only": False, "decipher_only": False,
        },
        "extended_key_usage": [ExtendedKeyUsageOID.SERVER_AUTH],
        "valid_san_types": ["dns", "ip"],
        "min_key_size": {"rsa": 2048, "ecc": 256}
    },
    "client": {
        "key_usage": {
            "digital_signature": True,
            "content_commitment": False, "key_encipherment": False, "data_encipherment": False,
            "key_agreement": True, "key_cert_sign": False, "crl_sign": False, "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usage": [ExtendedKeyUsageOID.CLIENT_AUTH],
        "valid_san_types": ["email", "dns", "uri"],
        "min_key_size": {"rsa": 2048, "ecc": 256}
    },
    "code_signing": {
        "key_usage": {
            "digital_signature": True,
            "content_commitment": False, "key_encipherment": False, "data_encipherment": False,
            "key_agreement": False, "key_cert_sign": False, "crl_sign": False, "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usage": [ExtendedKeyUsageOID.CODE_SIGNING],
        "valid_san_types": ["dns", "uri"],
        "min_key_size": {"rsa": 2048, "ecc": 256}
    },
    "ocsp": {
        "key_usage": {
            "digital_signature": True,
            "content_commitment": False, "key_encipherment": False, "data_encipherment": False,
            "key_agreement": False, "key_cert_sign": False, "crl_sign": False, "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usage": [ExtendedKeyUsageOID.OCSP_SIGNING],
        "valid_san_types": ["dns", "uri"],
        "min_key_size": {"rsa": 2048, "ecc": 256}
    },
}

def parse_san(san_list: list[str]) -> list[x509.GeneralName]:
    if not san_list:
        return []

    general_names = []
    for san_str in san_list:
        if ":" not in san_str:
            raise ValueError(f"Invalid SAN format: {san_str}. Must be 'type:value'.")
        
        san_type, value = san_str.split(":", 1)
        san_type = san_type.lower().strip()
        value = value.strip()

        if san_type == "dns":
            general_names.append(x509.DNSName(value))
        elif san_type == "ip":
            general_names.append(x509.IPAddress(ipaddress.ip_address(value)))
        elif san_type == "email":
            general_names.append(x509.RFC822Name(value))
        elif san_type == "uri":
            general_names.append(x509.UniformResourceIdentifier(value))
        else:
            raise ValueError(f"Unsupported SAN type: {san_type}")
    
    return general_names