import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

'''
Test komunikatu issue_cert. 
'''

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



    url = "http://localhost:8000/issue_cert/"
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
    url = "http://localhost:8000/issue_cert/"

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

    url = "http://localhost:8000/issue_cert/"
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

    url = "http://localhost:8000/issue_cert/"
    data = {
        "csr_pem": csr_pem,
    }

    response = requests.get(url, params=data)

    assert response.status_code == 405
