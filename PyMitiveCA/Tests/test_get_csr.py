import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import pytest
from django.http import Http404

'''
Test komunikatu get_csr. 
'''



def test_get_csr():
    '''
    Test komunikatu get_csr w normalnych warunkach pracy
    '''
    with open("PyMitiveCA/Tests/test_csr.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_csr/"
    data = [
        {
            "fingerprint": "4010ee636d96eb035adb76c3bc9327d439f0996952a8c6a6fd0edf83fe04301b",
        },
        {
            "id": "1",
        }
    ]
    for _ in range(len(data)):
        response = requests.get(url, params=data[_])

        assert response.status_code == 200
        cert_pem = response.text
        assert cert_pem == test_cert

def test_get_cert_both_params():
    '''
        Test komunikatu get_csr w z dwoma parametrami
    '''
    with open("PyMitiveCA/Tests/test_cert.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_cert/"
    data ={
            "fingerprint": "4010ee636d96eb035adb76c3bc9327d439f0996952a8c6a6fd0edf83fe04301b",
            "id": "1",
        };

    response = requests.get(url, params=data)
    print(response)

    assert response.status_code == 404



def test_get_csr_bad_param():
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


def test_get_csr_no_param():
    '''
        Test komunikatu get_csr bez paametrów
    '''
    with open("PyMitiveCA/Tests/test_csr.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_csr/"
    data = {}

    response = requests.get(url, params=data)

    assert response.status_code == 404


def test_get_csr_bad_method():
    '''
        Test komunikatu get_csr bez paametrów
    '''
    with open("PyMitiveCA/Tests/test_csr.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_csr/"
    data = {
            "fingerprint": "4010ee636d96eb035adb76c3bc9327d439f0996952a8c6a6fd0edf83fe04301b",
        }

    response = requests.post(url, data=data)

    assert response.status_code == 405
