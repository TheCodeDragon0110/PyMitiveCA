import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import pytest
from django.http import Http404

'''
Test komunikatu get_cert. 
'''



def test_get_cert():
    '''
    Test komunikatu get_cert w normalnych warunkach pracy
    '''
    with open("PyMitiveCA/Tests/test_cert.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_cert/"
    data = [
        {
            "fingerprint": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        },
        {
            "serial": "1769461001946839",
        }
    ]
    for _ in range(len(data)):
        response = requests.get(url, params=data[_])

        assert response.status_code == 200
        cert_pem = response.text
        assert cert_pem == test_cert

def test_get_cert_both_params():
    '''
        Test komunikatu get_cert w z dwoma parametrami
    '''
    with open("PyMitiveCA/Tests/test_cert.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_cert/"
    data ={
            "fingerprint": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
            "serial": "1769461001946839"
        };

    response = requests.get(url, params=data)
    print(response)

    assert response.status_code == 200
    cert_pem = response.text
    assert cert_pem == test_cert


def test_get_cert_bad_param():
    '''
        Test komunikatu get_cert w niewłaściwym parametrem
    '''
    with open("PyMitiveCA/Tests/test_cert.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_cert/"
    data ={
            "id": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        }

    response = requests.get(url, params=data)

    assert response.status_code == 404


def test_get_cert_no_param():
    '''
        Test komunikatu get_cert bez paametrów
    '''
    with open("PyMitiveCA/Tests/test_cert.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_cert/"
    data = {}

    response = requests.get(url, params=data)

    assert response.status_code == 404


def test_get_cert_bad_method():
    '''
        Test komunikatu get_cert bez paametrów
    '''
    with open("PyMitiveCA/Tests/test_cert.pem", "r") as f:
        test_cert = f.read()

    url = "http://localhost:8000/get_cert/"
    data = {
            "fingerprint": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        }

    response = requests.post(url, data=data)

    assert response.status_code == 405
