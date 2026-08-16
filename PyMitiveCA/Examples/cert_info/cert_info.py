import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

'''
Przykład pobiera metadane certyfikatu (cert_info/) - w tym algorytm i
długość klucza - bez parsowania samego PEM-a po stronie klienta.

Te same dwie informacje wracają też w nagłówkach odpowiedzi PEM
(X-Public-Key-Algorithm, X-Key-Size), co pokazuje pierwsza część przykładu.
'''

BASE_URL = "https://localhost"

# Serwer używa certyfikatu z lokalnego CA projektu (deploy/nginx).
VERIFY = "../../../deploy/nginx/certs/rootCA.pem"

for algorithm, extra in [
    ("RSA", {"key_size": "8192"}),
    ("ECDSA", {"curve": "secp521r1"}),
    ("ED25519", {}),
    ("ML-KEM", {"key_size": "1024"}),
]:
    response = requests.post(
        f"{BASE_URL}/generate_cert/",
        data={"dn": "CN=Jan Kowalski,O=MyOrg,C=PL", "algorithm": algorithm, **extra},
        verify=VERIFY,
    )

    if response.status_code != 200:
        print("Błąd:", response.status_code, response.text)
        continue

    # Algorytm i długość klucza prosto z nagłówków odpowiedzi.
    print(f"{algorithm}: {response.headers['X-Public-Key-Algorithm']} "
          f"({response.headers['X-Key-Size']} bitów / wariant)")

    certificate = x509.load_pem_x509_certificate(response.content, default_backend())
    info = requests.get(
        f"{BASE_URL}/cert_info/",
        params={"serial": str(certificate.serial_number)},
        verify=VERIFY,
    ).json()

    print("  DN            :", info["subject_dn"])
    print("  Ważny do      :", info["not_after"])
    print("  Klucz         :", info["public_key_algorithm"], "/", info["key_size"])
    print("  Unieważniony  :", info["revoked"], info["revoked_at"] or "", info["revocation_reason"] or "")
    print("  OCSP / CRL    :", info["ocsp_url"], "/", info["crl_url"])
