import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import pytest
from django.http import Http404

'''
Test komunikatu get_crl. 
'''

def test_get_crl():
    '''
    Test komunikatu get_crl w normalnych warunkach pracy
    '''
    url = "http://localhost:8000/get_crl/"
    response = requests.get(url)

    assert response.status_code == 200
    crl_pem = response.text
    crl = x509.load_pem_x509_crl(crl_pem.encode('utf-8'), default_backend())
    l = [revoked_cert.serial_number for revoked_cert in crl]
    assert l != []


def test_get_csr_param():
    '''
        Test komunikatu get_csr w niewłaściwym parametrem
    '''
    with open("PyMitiveCA/Tests/test_cert.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_cert/"
    data ={
            "id3": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        }

    response = requests.get(url, params=data)

    assert response.status_code == 404


def test_get_csr_bad_method():
    '''
        Test komunikatu get_crl ze złą metodą
    '''
    with open("PyMitiveCA/Tests/test_csr.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_crl/"

    response = requests.post(url)

    assert response.status_code == 405
