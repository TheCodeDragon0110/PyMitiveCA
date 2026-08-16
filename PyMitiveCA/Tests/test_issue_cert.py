import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
import pytest

'''
Test komunikatu issue_cert.
'''

ISSUE_CERT_URL = "https://localhost/issue_cert/"

def test_issue_cert_cert():
    '''
    Test komunikatu issue_cert w normalnych warunkach pracy
    '''
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "MyOrg"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Jan Kowalski"),
        ])).sign(private_key, hashes.SHA256())


    csr_pem = csr.public_bytes(serialization.Encoding.PEM)



    url = "https://localhost/issue_cert/"
    data = {
        "csr_pem": csr_pem,
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
def test_issue_cert_bad_param():
    '''
        Test komunikatu issue_cert w ze złym parametrem
    '''
    url = "https://localhost/issue_cert/"

    with open("PyMitiveCA/Tests/test_cert.pem") as f:
        csr_pem = f.read()

    data = {
        "csr_pem": csr_pem,
    }
    response = requests.post(url, data=data)
    assert response.status_code == 404



def test_issue_cert_no_param():
    '''
        Test komunikatu get_csr bez paametrów
    '''

    url = "https://localhost/issue_cert/"
    data = {}

    response = requests.post(url, data=data)

    assert response.status_code == 404


def test_issue_cert_bad_method():
    '''
        Test komunikatu issue_cert złą metodą
    '''

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "MyOrg"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Jan Kowalski"),
    ])).sign(private_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    url = "https://localhost/issue_cert/"
    data = {
        "csr_pem": csr_pem,
    }

    response = requests.get(url, params=data)

    assert response.status_code == 405


def _subject():
    return x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "MyOrg"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Jan Kowalski"),
    ])


def test_issue_cert_ecdsa_csr():
    '''
    Test issue_cert dla CSR samopodpisanego kluczem ECDSA (klient sam
    generuje klucz i CSR - tak jak przy prawdziwym użyciu tego endpointu).
    '''
    private_key = ec.generate_private_key(ec.SECP384R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(_subject()).sign(private_key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    response = requests.post(ISSUE_CERT_URL, data={"csr_pem": csr_pem})
    assert response.status_code == 200
    cert = x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())
    assert cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "Jan Kowalski"
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert isinstance(cert.public_key().curve, ec.SECP384R1)
    # Certyfikat i tak podpisuje CA swoim kluczem RSA, niezależnie od
    # algorytmu klucza podmiotu.
    assert cert.signature_hash_algorithm.name == "sha256"


def test_issue_cert_ed25519_csr():
    '''
    Test issue_cert dla CSR samopodpisanego kluczem ED25519.
    '''
    private_key = ed25519.Ed25519PrivateKey.generate()
    csr = x509.CertificateSigningRequestBuilder().subject_name(_subject()).sign(private_key, None)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    response = requests.post(ISSUE_CERT_URL, data={"csr_pem": csr_pem})
    assert response.status_code == 200
    cert = x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())
    assert cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "Jan Kowalski"
    assert isinstance(cert.public_key(), ed25519.Ed25519PublicKey)


def test_issue_cert_crmf_ml_kem():
    '''
    Test issue_cert dla żądania CRMF (klucz ML-KEM nie potrafi
    samopodpisać CSR). Żądanie CRMF pochodzi z generate_csr/ - to jedyny
    sposób, żeby uzyskać poprawnie zbudowane żądanie bez duplikowania
    logiki kodującej ASN.1 w teście. issue_cert/ nie zna klucza
    prywatnego (to klient go wygenerował), więc odpowiedź nie powinna go
    zawierać - inaczej niż w generate_cert/generate_csr.
    '''
    csr_response = requests.post("https://localhost/generate_csr/", data={
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ML-KEM",
    })
    assert csr_response.status_code == 201
    crmf_pem = csr_response.json()["crmf_pem"]

    response = requests.post(ISSUE_CERT_URL, data={"crmf_pem": crmf_pem})
    assert response.status_code == 202
    assert response.headers["Content-Type"].startswith("application/json")

    body = response.json()
    assert body["pop_pending"] is True
    assert "private_key_pem" not in body


def test_issue_cert_crmf_bad_request():
    '''
    Test issue_cert z uszkodzonym żądaniem CRMF (oczekiwane 400).
    '''
    response = requests.post(ISSUE_CERT_URL, data={
        "crmf_pem": "-----BEGIN CRMF CERTIFICATE REQUEST-----\nZm9v\n-----END CRMF CERTIFICATE REQUEST-----\n",
    })
    assert response.status_code == 400
