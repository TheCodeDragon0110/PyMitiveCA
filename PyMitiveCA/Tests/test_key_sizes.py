import pytest
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

'''
Testy długości klucza: każdy obsługiwany algorytm musi raportować swoją
długość klucza - w nagłówkach odpowiedzi PEM oraz w metadanych z cert_info/.
'''

GENERATE_CERT_URL = "https://localhost/generate_cert/"
GENERATE_CSR_URL = "https://localhost/generate_csr/"
CERT_INFO_URL = "https://localhost/cert_info/"

# (parametry żądania, oczekiwana etykieta algorytmu, oczekiwana długość klucza)
KEY_PARAMETERS = [
    ({"algorithm": "RSA"}, "RSA-2048", 2048),
    ({"algorithm": "RSA", "key_size": "3072"}, "RSA-3072", 3072),
    ({"algorithm": "RSA", "key_size": "4096"}, "RSA-4096", 4096),
    ({"algorithm": "RSA", "key_size": "8192"}, "RSA-8192", 8192),
    ({"algorithm": "ECDSA"}, "ECDSA-secp256r1", 256),
    ({"algorithm": "ECDSA", "curve": "secp384r1"}, "ECDSA-secp384r1", 384),
    ({"algorithm": "ECDSA", "curve": "secp521r1"}, "ECDSA-secp521r1", 521),
    ({"algorithm": "ED25519"}, "ED25519", 255),
    ({"algorithm": "ML-KEM"}, "ML-KEM-768", 768),
    ({"algorithm": "ML-KEM", "key_size": "1024"}, "ML-KEM-1024", 1024),
]

KEY_PARAMETER_IDS = [expected_algorithm for _params, expected_algorithm, _size in KEY_PARAMETERS]


@pytest.mark.parametrize(
    "params,expected_algorithm,expected_key_size", KEY_PARAMETERS, ids=KEY_PARAMETER_IDS
)
def test_generate_cert_reports_key_size(params, expected_algorithm, expected_key_size):
    '''
    generate_cert/ zwraca algorytm i długość klucza w nagłówkach, a
    cert_info/ podaje te same wartości w JSON-ie.
    '''
    response = requests.post(GENERATE_CERT_URL, data={"dn": "CN=Jan Kowalski,O=MyOrg,C=PL", **params})
    assert response.status_code == 200

    assert response.headers["X-Public-Key-Algorithm"] == expected_algorithm
    assert int(response.headers["X-Key-Size"]) == expected_key_size

    cert = x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())
    info = requests.get(CERT_INFO_URL, params={"serial": str(cert.serial_number)}).json()

    assert info["public_key_algorithm"] == expected_algorithm
    assert info["key_size"] == expected_key_size


@pytest.mark.parametrize(
    "params,expected_algorithm,expected_key_size", KEY_PARAMETERS, ids=KEY_PARAMETER_IDS
)
def test_generate_csr_reports_key_size(params, expected_algorithm, expected_key_size):
    '''
    generate_csr/ raportuje długość klucza tak samo - w nagłówkach dla CSR
    (PKCS#10) i w polach JSON-a dla żądania CRMF (ML-KEM).
    '''
    response = requests.post(GENERATE_CSR_URL, data={"dn": "CN=Jan Kowalski,O=MyOrg,C=PL", **params})

    if params["algorithm"] == "ML-KEM":
        assert response.status_code == 201
        body = response.json()
        assert body["public_key_algorithm"] == expected_algorithm
        assert body["key_size"] == expected_key_size
        return

    assert response.status_code == 200
    assert response.headers["X-Public-Key-Algorithm"] == expected_algorithm
    assert int(response.headers["X-Key-Size"]) == expected_key_size


def test_issue_cert_reports_key_size():
    '''
    Długość klucza jest odczytywana z samego CSR-a - także dla klucza
    wygenerowanego poza tym CA, o którym baza nic wcześniej nie wiedziała.
    '''
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP521R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "MyOrg"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Jan Kowalski"),
    ])).sign(private_key, hashes.SHA256())

    response = requests.post(
        "https://localhost/issue_cert/",
        data={"csr_pem": csr.public_bytes(serialization.Encoding.PEM)},
    )

    assert response.status_code == 200
    assert response.headers["X-Public-Key-Algorithm"] == "ECDSA-secp521r1"
    assert int(response.headers["X-Key-Size"]) == 521


def test_issue_cert_accepts_previously_registered_csr():
    '''
    Wysłanie do issue_cert/ CSR-a, który serwer sam wcześniej zarejestrował
    przez generate_csr/, nie może kończyć się błędem - fingerprint_sha256
    tego CSR-a już jest w bazie (CertRequest jest unique po tym polu), więc
    issue_cert/ musi zaktualizować istniejący wpis zamiast wstawiać drugi.
    '''
    csr_response = requests.post(GENERATE_CSR_URL, data={"dn": "CN=Jan Kowalski,O=MyOrg,C=PL", "algorithm": "RSA"})
    assert csr_response.status_code == 200

    response = requests.post("https://localhost/issue_cert/", data={"csr_pem": csr_response.text})

    assert response.status_code == 200
    cert = x509.load_pem_x509_certificate(response.content, default_backend())
    assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "Jan Kowalski"

    # Ten sam CSR można zgłosić do issue_cert/ ponownie - drugie wystawienie
    # certyfikatu z tego samego żądania też nie może się wywalić.
    response_again = requests.post("https://localhost/issue_cert/", data={"csr_pem": csr_response.text})
    assert response_again.status_code == 200


def test_rejected_rsa_key_size():
    '''
    Rozmiary spoza listy dozwolonych są odrzucane wraz z informacją, co jest
    dozwolone.
    '''
    response = requests.post(
        GENERATE_CERT_URL,
        data={"dn": "CN=Jan Kowalski,O=MyOrg,C=PL", "algorithm": "RSA", "key_size": "1024"},
    )

    assert response.status_code == 400
    assert "8192" in response.text


def test_cert_info_requires_identifier():
    '''
    cert_info/ bez identyfikatora certyfikatu nie ma czego zwrócić.
    '''
    response = requests.get(CERT_INFO_URL)

    assert response.status_code == 404


def test_cert_info_unknown_certificate():
    '''
    cert_info/ dla nieistniejącego certyfikatu zwraca 404.
    '''
    response = requests.get(CERT_INFO_URL, params={"serial": "0"})

    assert response.status_code == 404
