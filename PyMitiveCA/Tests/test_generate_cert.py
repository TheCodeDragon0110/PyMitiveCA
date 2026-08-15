import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import pytest
from django.http import Http404

'''
Test komunikatu generate_cert. 
'''

def test_generate_cert():
    '''
    Test komunikatu generate_cert w normalnych warunkach pracy
    '''
    url = "http://localhost:8000/generate_cert/"
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "valid_days": 365
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
    url = "http://localhost:8000/generate_cert/"
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL"
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
    url = "http://localhost:8000/generate_cert/"
    data = {
        "valid_days": 365
    }
    response = requests.post(url, data=data)
    assert response.status_code == 404



def test_generate_cert_bad_param():
    '''
        Test komunikatu generate_cert w niewłaściwym parametrem
    '''

    url = "http://localhost:8000/generate_cert/"
    data ={
            "id3": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        }

    response = requests.post(url, data=data)

    assert response.status_code == 404


def test_generate_cert_no_param():
    '''
        Test komunikatu get_csr bez paametrów
    '''

    url = "http://localhost:8000/generate_cert/"
    data = {}

    response = requests.post(url, data=data)

    assert response.status_code == 404


def test_generate_cert_bad_method():
    '''
        Test komunikatu generacte_cert złą metodą
    '''

    url = "http://localhost:8000/generate_cert/"
    data = data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "valid_days": 365
    }

    response = requests.get(url, params=data)

    assert response.status_code == 405
