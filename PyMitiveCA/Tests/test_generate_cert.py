import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mlkem
import pytest
from django.http import Http404

'''
Test komunikatu generate_cert.
'''

GENERATE_CERT_URL = "https://localhost/generate_cert/"

def test_generate_cert():
    '''
    Test komunikatu generate_cert w normalnych warunkach pracy
    '''
    url = "https://localhost/generate_cert/"
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "valid_days": 365,
        "algorithm": "RSA"
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    cert_pem = response.text
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
    assert cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "Jan Kowalski"
    assert cert.subject.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0].value == "MyOrg"
    assert cert.subject.get_attributes_for_oid(x509.OID_COUNTRY_NAME)[0].value == "PL"
    assert cert.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "PyMitiveCA CA Certificate"
    assert cert.issuer.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0].value == "PyMitiveCA"
    assert cert.issuer.get_attributes_for_oid(x509.OID_COUNTRY_NAME)[0].value == "PL"
def test_generate_cert_one_param_dn():
    '''
        Test komunikatu generate_cert w z jednym parametrem
    '''
    url = "https://localhost/generate_cert/"
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "RSA"
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    cert_pem = response.text
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
    assert cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "Jan Kowalski"
    assert cert.subject.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0].value == "MyOrg"
    assert cert.subject.get_attributes_for_oid(x509.OID_COUNTRY_NAME)[0].value == "PL"
    assert cert.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "PyMitiveCA CA Certificate"
    assert cert.issuer.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0].value == "PyMitiveCA"
    assert cert.issuer.get_attributes_for_oid(x509.OID_COUNTRY_NAME)[0].value == "PL"



def test_generate_cert_one_param_valid_days():
    '''
        Test komunikatu generate_cert w z jednym parametrem
    '''
    url = "https://localhost/generate_cert/"
    data = {
        "valid_days": 365
    }
    response = requests.post(url, data=data)
    assert response.status_code == 404



def test_generate_cert_bad_param():
    '''
        Test komunikatu generate_cert w niewłaściwym parametrem
    '''

    url = "https://localhost/generate_cert/"
    data ={
            "id3": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        }

    response = requests.post(url, data=data)

    assert response.status_code == 404


def test_generate_cert_no_param():
    '''
        Test komunikatu get_csr bez paametrów
    '''

    url = "https://localhost/generate_cert/"
    data = {}

    response = requests.post(url, data=data)

    assert response.status_code == 404


def test_generate_cert_bad_method():
    '''
        Test komunikatu generacte_cert złą metodą
    '''

    url = "https://localhost/generate_cert/"
    data = data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "valid_days": 365
    }

    response = requests.get(url, params=data)

    assert response.status_code == 405


def _assert_common_subject_and_issuer(cert):
    assert cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "Jan Kowalski"
    assert cert.subject.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0].value == "MyOrg"
    assert cert.subject.get_attributes_for_oid(x509.OID_COUNTRY_NAME)[0].value == "PL"
    assert cert.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "PyMitiveCA CA Certificate"


@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
def test_generate_cert_rsa_key_size(key_size):
    '''
    Test generate_cert dla RSA z różnymi dozwolonymi rozmiarami klucza.
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "RSA",
        "key_size": key_size,
    }
    response = requests.post(GENERATE_CERT_URL, data=data)
    assert response.status_code == 200
    cert = x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())
    _assert_common_subject_and_issuer(cert)
    assert cert.public_key().key_size == key_size


def test_generate_cert_rsa_bad_key_size():
    '''
    Test generate_cert dla RSA z niedozwolonym rozmiarem klucza (oczekiwane 400).
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "RSA",
        "key_size": 1024,
    }
    response = requests.post(GENERATE_CERT_URL, data=data)
    assert response.status_code == 400


@pytest.mark.parametrize("curve_name,curve_cls", [
    ("secp256r1", ec.SECP256R1),
    ("secp384r1", ec.SECP384R1),
    ("secp521r1", ec.SECP521R1),
    ("secp256k1", ec.SECP256K1),
])
def test_generate_cert_ecdsa_curves(curve_name, curve_cls):
    '''
    Test generate_cert dla ECDSA na wszystkich obsługiwanych krzywych.
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ECDSA",
        "curve": curve_name,
    }
    response = requests.post(GENERATE_CERT_URL, data=data)
    assert response.status_code == 200
    cert = x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())
    _assert_common_subject_and_issuer(cert)
    public_key = cert.public_key()
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    assert isinstance(public_key.curve, curve_cls)


def test_generate_cert_ecdsa_default_curve():
    '''
    Test generate_cert dla ECDSA bez podania krzywej - powinna zostać
    użyta domyślna (secp256r1).
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ECDSA",
    }
    response = requests.post(GENERATE_CERT_URL, data=data)
    assert response.status_code == 200
    cert = x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())
    assert isinstance(cert.public_key().curve, ec.SECP256R1)


def test_generate_cert_ecdsa_bad_curve():
    '''
    Test generate_cert dla ECDSA z nieobsługiwaną krzywą (oczekiwane 400).
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ECDSA",
        "curve": "sect571k1",
    }
    response = requests.post(GENERATE_CERT_URL, data=data)
    assert response.status_code == 400


def test_generate_cert_ed25519():
    '''
    Test generate_cert dla ED25519.
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ED25519",
    }
    response = requests.post(GENERATE_CERT_URL, data=data)
    assert response.status_code == 200
    cert = x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())
    _assert_common_subject_and_issuer(cert)
    assert isinstance(cert.public_key(), ed25519.Ed25519PublicKey)
    # CA (RSA) podpisuje certyfikat niezależnie od algorytmu klucza podmiotu.
    assert cert.signature_hash_algorithm.name == "sha256"


@pytest.mark.parametrize("key_size,key_cls", [
    (768, mlkem.MLKEM768PublicKey),
    (1024, mlkem.MLKEM1024PublicKey),
])
def test_generate_cert_ml_kem(key_size, key_cls):
    '''
    Test generate_cert dla ML-KEM. Klucz jest generowany po stronie
    serwera (tak jak dla pozostałych algorytmów), więc certyfikat wraca
    od razu w postaci jawnej - spójnie z RSA/ECDSA/ED25519. Serwer nie
    zwraca ani nie przechowuje klucza prywatnego.
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ML-KEM",
        "key_size": key_size,
    }
    response = requests.post(GENERATE_CERT_URL, data=data)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/x-pem-file"

    cert = x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())
    _assert_common_subject_and_issuer(cert)
    assert isinstance(cert.public_key(), key_cls)
    # CA (RSA) podpisuje certyfikat niezależnie od algorytmu klucza podmiotu.
    assert cert.signature_hash_algorithm.name == "sha256"

    # Certyfikat jest od razu dostępny w postaci jawnej przez get_cert/.
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    get_response = requests.get("https://localhost/get_cert/", params={"fingerprint": fingerprint})
    assert get_response.status_code == 200
    assert get_response.text == response.text


def test_generate_cert_ml_kem_bad_key_size():
    '''
    Test generate_cert dla ML-KEM z niedozwolonym key_size (oczekiwane 400)
    - biblioteka cryptography obsługuje tylko warianty 768 i 1024.
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ML-KEM",
        "key_size": 512,
    }
    response = requests.post(GENERATE_CERT_URL, data=data)
    assert response.status_code == 400


def test_generate_cert_missing_algorithm():
    '''
    Test generate_cert bez wymaganego parametru algorithm (oczekiwane 400).
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
    }
    response = requests.post(GENERATE_CERT_URL, data=data)
    assert response.status_code == 400


def test_generate_cert_unsupported_algorithm():
    '''
    Test generate_cert z nieobsługiwanym algorytmem (oczekiwane 400).
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "DSA",
    }
    response = requests.post(GENERATE_CERT_URL, data=data)
    assert response.status_code == 400
