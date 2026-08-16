import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import pytest
from django.http import Http404

'''
Test komunikatu get_csr. 
'''



def test_get_csr():
    '''
    Test komunikatu get_csr w normalnych warunkach pracy

    generate_csr/ nie zwraca identyfikatora bazodanowego (id) rekordu
    CertRequest, więc black-boxowo (samym HTTP) da się przetestować tylko
    wyszukiwanie po fingerprint - CSR jest przy tym wystawiany świeżo w
    tym teście, zamiast zakładać istnienie konkretnego rekordu z
    wcześniejszego uruchomienia (fingerprint zależy od losowego klucza,
    więc nigdy nie jest deterministyczny między uruchomieniami).
    '''
    url = "https://localhost/generate_csr/"
    data = {
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "RSA",
    }
    gen_response = requests.post(url, data=data)
    assert gen_response.status_code == 200
    csr_pem = gen_response.text
    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'), default_backend())
    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(csr.public_bytes(serialization.Encoding.DER))
    fingerprint = fingerprint.finalize().hex()

    url = "https://localhost/get_csr/"
    response = requests.get(url, params={"fingerprint": fingerprint})

    assert response.status_code == 200
    assert response.text == csr_pem

def test_get_cert_both_params():
    '''
        Test komunikatu get_csr w z dwoma parametrami
    '''
    with open("PyMitiveCA/Tests/test_cert.pem", "r") as f:
        test_cert = f.read()

    url = "https://localhost/get_cert/"
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

    url = "https://localhost/get_cert/"
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

    url = "https://localhost/get_csr/"
    data = {}

    response = requests.get(url, params=data)

    assert response.status_code == 404


def test_get_csr_bad_method():
    '''
        Test komunikatu get_csr bez paametrów
    '''
    with open("PyMitiveCA/Tests/test_csr.pem", "r") as f:
        test_cert = f.read()

    url = "https://localhost/get_csr/"
    data = {
            "fingerprint": "4010ee636d96eb035adb76c3bc9327d439f0996952a8c6a6fd0edf83fe04301b",
        }

    response = requests.post(url, data=data)

    assert response.status_code == 405
