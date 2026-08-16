import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import pytest
from django.http import Http404

'''
Test komunikatu get_crl. 
'''

def test_get_crl():
    '''
    Test komunikatu get_crl w normalnych warunkach pracy

    Crl.get_or_create_current_crl() cache'uje CRL na validity_days (7 dni)
    - odwołanie świeżego certyfikatu tuż przed zapytaniem nie gwarantuje
    więc, że akurat ta lista trafi do CRL (mógł już istnieć ważny, starszy
    CRL wystawiony przed tym odwołaniem). Test sprawdza to, co faktycznie
    gwarantuje endpoint niezależnie od historii wcześniejszych uruchomień:
    zwraca poprawnie sparsowalną listę CRL podpisaną przez to CA.
    '''
    # Wystaw i odwołaj certyfikat, żeby CA na pewno miało już co najmniej
    # jeden odwołany certyfikat (przydatne, gdy CRL jest generowany od zera).
    gen_response = requests.post("https://localhost/generate_cert/", data={
        "dn": "CN=Do odwolania,O=MyOrg,C=PL",
        "algorithm": "RSA",
    })
    assert gen_response.status_code == 200
    cert = x509.load_pem_x509_certificate(gen_response.text.encode('utf-8'), default_backend())
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    issuer = cert.issuer.rfc4514_string()

    revoke_response = requests.get("https://localhost/revoke/", params={"fingerprint": fingerprint})
    assert revoke_response.status_code == 200

    url = "https://localhost/get_crl/"
    response = requests.get(url)

    assert response.status_code == 200
    crl_pem = response.text
    crl = x509.load_pem_x509_crl(crl_pem.encode('utf-8'), default_backend())
    assert crl.issuer.rfc4514_string() == issuer


def test_get_csr_param():
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


def test_get_csr_bad_method():
    '''
        Test komunikatu get_crl ze złą metodą
    '''
    with open("PyMitiveCA/Tests/test_csr.pem", "r") as f:
        test_cert = f.read()

    url = "https://localhost/get_crl/"

    response = requests.post(url)

    assert response.status_code == 405
