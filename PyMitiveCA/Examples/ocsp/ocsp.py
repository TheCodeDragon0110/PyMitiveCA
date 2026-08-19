import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ocsp

'''
Przykład sprawdza status certyfikatu w serwisie OCSP (RFC 6960): wystawia
świeży certyfikat, pyta o jego status, unieważnia go i pyta ponownie.

Żądanie OCSP identyfikuje wystawcę skrótami jego nazwy i klucza publicznego,
więc klient musi mieć certyfikat CA - tutaj czytamy go wprost z ca.p12, ale
w realnym wdrożeniu byłby to zaufany certyfikat zainstalowany u klienta.
'''

BASE_URL = "https://localhost"
CA_P12_PATH = "../../PyMitiveCA/certs/ca.p12"
CA_P12_PASSWORD = b"password"

# Serwer używa certyfikatu z lokalnego CA projektu (deploy/nginx) - podaj tu
# ścieżkę do rootCA.pem albo ustaw verify=False na czas eksperymentów.
VERIFY = "../../../deploy/nginx/certs/rootCA.pem"

with open(CA_P12_PATH, "rb") as f:
    _key, ca_cert, _extra = pkcs12.load_key_and_certificates(f.read(), CA_P12_PASSWORD)


def ask_ocsp(cert):
    '''
    Wysyła żądanie OCSP metodą POST i zwraca odpowiedź respondera.
    '''
    ocsp_request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(cert, ca_cert, hashes.SHA1())
        .build()
    )

    response = requests.post(
        f"{BASE_URL}/ocsp/",
        data=ocsp_request.public_bytes(serialization.Encoding.DER),
        headers={"Content-Type": "application/ocsp-request"},
        verify=VERIFY,
    )

    if response.status_code != 200:
        print("Błąd:", response.status_code, response.text)
        return None

    return ocsp.load_der_ocsp_response(response.content)


# 1. Wystawiamy certyfikat, o który będziemy pytać.
issued = requests.post(
    f"{BASE_URL}/generate_cert/",
    data={"dn": "CN=Jan Kowalski,O=MyOrg,C=PL", "algorithm": "RSA"},
    verify=VERIFY,
)
certificate = x509.load_pem_x509_certificate(issued.content, default_backend())
print("Numer seryjny:", certificate.serial_number)

# Adres respondera jest opublikowany w samym certyfikacie (rozszerzenie
# Authority Information Access) - klient nie musi go znać z góry.
aia = certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
print("Adres OCSP z certyfikatu:", [d.access_location.value for d in aia])

# 2. Status przed unieważnieniem.
ocsp_response = ask_ocsp(certificate)
print("Status:", ocsp_response.certificate_status)

# 3. Unieważniamy certyfikat (z powodem - patrz Cert.REASON_CHOICES) i pytamy ponownie.
requests.get(
    f"{BASE_URL}/revoke/",
    params={"serial": str(certificate.serial_number), "reason": "key_compromise"},
    verify=VERIFY,
)

ocsp_response = ask_ocsp(certificate)
print("Status po unieważnieniu:", ocsp_response.certificate_status)
print("Data unieważnienia:", ocsp_response.revocation_time_utc)
print("Powód unieważnienia:", ocsp_response.revocation_reason)
