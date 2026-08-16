import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
import pytest
from django.http import Http404

'''
Test komunikatu generate_csr.
'''

GENERATE_CSR_URL = "https://localhost/generate_csr/"

def test_generate_csr():
    '''
    Test komunikatu generate_csr w normalnych warunkach pracy
    '''
    url = "https://localhost/generate_csr/"
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "valid_days": 365,
        "algorithm": "RSA"
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    csr_pem = response.text
    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'), default_backend())
    assert csr.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "Jan Kowalski"
    assert csr.subject.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0].value == "MyOrg"
    assert csr.subject.get_attributes_for_oid(x509.OID_COUNTRY_NAME)[0].value == "PL"

def test_generate_csr_one_param_dn():
    '''
        Test komunikatu generate_csr w z jednym parametrem
    '''
    url = "https://localhost/generate_csr/"
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "RSA"
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    csr_pem = response.text
    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'), default_backend())
    assert csr.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "Jan Kowalski"
    assert csr.subject.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0].value == "MyOrg"
    assert csr.subject.get_attributes_for_oid(x509.OID_COUNTRY_NAME)[0].value == "PL"



def test_generate_csr_one_param_valid_days():
    '''
        Test komunikatu generate_csr w z jednym parametrem
    '''
    url = "https://localhost/generate_csr/"
    data = {
        "valid_days": 365
    }
    response = requests.post(url, data=data)
    assert response.status_code == 404



def test_generate_csr_bad_param():
    '''
        Test komunikatu generate_csr w niewłaściwym parametrem
    '''

    url = "https://localhost/generate_csr/"
    data ={
            "id3": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        }

    response = requests.post(url, data=data)

    assert response.status_code == 404


def test_generate_csr_no_param():
    '''
        Test komunikatu get_csr bez paametrów
    '''

    url = "https://localhost/generate_csr/"
    data = {}

    response = requests.post(url, data=data)

    assert response.status_code == 404


def test_generate_csr_bad_method():
    '''
        Test komunikatu get_csr bez paametrów
    '''

    url = "https://localhost/generate_csr/"
    data = data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "valid_days": 365
    }

    response = requests.get(url, params=data)

    assert response.status_code == 405


@pytest.mark.parametrize("curve_name,curve_cls", [
    ("secp256r1", ec.SECP256R1),
    ("secp384r1", ec.SECP384R1),
    ("secp521r1", ec.SECP521R1),
    ("secp256k1", ec.SECP256K1),
])
def test_generate_csr_ecdsa_curves(curve_name, curve_cls):
    '''
    Test generate_csr dla ECDSA na wszystkich obsługiwanych krzywych -
    CSR jest samopodpisany kluczem podmiotu (ECDSA to potrafi).
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ECDSA",
        "curve": curve_name,
    }
    response = requests.post(GENERATE_CSR_URL, data=data)
    assert response.status_code == 200
    csr = x509.load_pem_x509_csr(response.text.encode('utf-8'), default_backend())
    assert csr.is_signature_valid
    public_key = csr.public_key()
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    assert isinstance(public_key.curve, curve_cls)


def test_generate_csr_ecdsa_bad_curve():
    '''
    Test generate_csr dla ECDSA z nieobsługiwaną krzywą (oczekiwane 400).
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ECDSA",
        "curve": "sect571k1",
    }
    response = requests.post(GENERATE_CSR_URL, data=data)
    assert response.status_code == 400


def test_generate_csr_ed25519():
    '''
    Test generate_csr dla ED25519 - CSR samopodpisany bez jawnego
    algorytmu hashującego (Ed25519 ma niejawne hashowanie).
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ED25519",
    }
    response = requests.post(GENERATE_CSR_URL, data=data)
    assert response.status_code == 200
    csr = x509.load_pem_x509_csr(response.text.encode('utf-8'), default_backend())
    assert csr.is_signature_valid
    assert isinstance(csr.public_key(), ed25519.Ed25519PublicKey)


@pytest.mark.parametrize("key_size", [768, 1024])
def test_generate_csr_ml_kem(key_size):
    '''
    Test generate_csr dla ML-KEM. ML-KEM nie potrafi samopodpisać CSR
    (PKCS#10 wymaga klucza zdolnego do podpisu), więc endpoint zwraca
    201 z żądaniem CRMF (RFC 4211) zamiast gotowego CSR-a.
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ML-KEM",
        "key_size": key_size,
    }
    response = requests.post(GENERATE_CSR_URL, data=data)
    assert response.status_code == 201
    assert response.headers["Content-Type"].startswith("application/json")

    body = response.json()
    assert "-----BEGIN CRMF CERTIFICATE REQUEST-----" in body["crmf_pem"]
    assert "-----BEGIN PRIVATE KEY-----" in body["private_key_pem"]
    assert body["fingerprint"]


def test_generate_csr_missing_algorithm():
    '''
    Test generate_csr bez wymaganego parametru algorithm (oczekiwane 400).
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
    }
    response = requests.post(GENERATE_CSR_URL, data=data)
    assert response.status_code == 400


def test_generate_csr_unsupported_algorithm():
    '''
    Test generate_csr z nieobsługiwanym algorytmem (oczekiwane 400).
    '''
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "DSA",
    }
    response = requests.post(GENERATE_CSR_URL, data=data)
    assert response.status_code == 400
