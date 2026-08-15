from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from django.conf import settings

_ca_private_key = None
_ca_certificate = None
_ca_additional_certs = None


def load_ca():
    global _ca_private_key, _ca_certificate, _ca_additional_certs

    if _ca_private_key is not None:
        return _ca_private_key, _ca_certificate, _ca_additional_certs

    with open(settings.CA_P12_PATH, "rb") as f:
        p12_data = f.read()

    private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
        p12_data,
        password=settings.CA_P12_PASSWORD.encode(),
    )

    _ca_private_key = private_key
    _ca_certificate = certificate
    _ca_additional_certs = additional_certs

    return private_key, certificate, additional_certs