import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import pytest
from django.http import Http404

'''
Test komunikatu get_cert. 
'''



def _issue_fresh_cert():
    '''
    Wystawia świeży certyfikat przez generate_cert/ i zwraca (cert_pem,
    fingerprint, serial) wyliczone z odpowiedzi. generate_cert/ nie zwraca
    już certyfikatu deterministycznie (serial_number/not_valid_before
    zależą od bieżącego czasu), więc testy get_cert/ muszą same wystawić
    certyfikat, którego szukają, zamiast zakładać istnienie konkretnego
    rekordu z wcześniejszego uruchomienia.
    '''
    url = "https://localhost/generate_cert/"
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "RSA",
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    cert_pem = response.text
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    serial = str(cert.serial_number)
    return cert_pem, fingerprint, serial


def test_get_cert():
    '''
    Test komunikatu get_cert w normalnych warunkach pracy
    '''
    cert_pem, fingerprint, serial = _issue_fresh_cert()

    url = "https://localhost/get_cert/"
    data = [
        {
            "fingerprint": fingerprint,
        },
        {
            "serial": serial,
        }
    ]
    for _ in range(len(data)):
        response = requests.get(url, params=data[_])

        assert response.status_code == 200
        assert response.text == cert_pem

def test_get_cert_both_params():
    '''
        Test komunikatu get_cert w z dwoma parametrami
    '''
    cert_pem, fingerprint, serial = _issue_fresh_cert()

    url = "https://localhost/get_cert/"
    data = {
            "fingerprint": fingerprint,
            "serial": serial,
        }

    response = requests.get(url, params=data)

    assert response.status_code == 200
    assert response.text == cert_pem


def test_get_cert_bad_param():
    '''
        Test komunikatu get_cert w niewłaściwym parametrem
    '''
    with open("PyMitiveCA/Tests/test_cert.pem", "r") as f:
        test_cert = f.read()

    url = "https://localhost/get_cert/"
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

    url = "https://localhost/get_cert/"
    data = {}

    response = requests.get(url, params=data)

    assert response.status_code == 404


def test_get_cert_bad_method():
    '''
        Test komunikatu get_cert bez paametrów
    '''
    with open("PyMitiveCA/Tests/test_cert.pem", "r") as f:
        test_cert = f.read()

    url = "https://localhost/get_cert/"
    data = {
            "fingerprint": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        }

    response = requests.post(url, data=data)

    assert response.status_code == 405
