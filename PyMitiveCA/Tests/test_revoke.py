import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

'''
Test komunikatu revoke. 
'''

def test_revoke_cert():
    '''
    Test komunikatu issue_cert w normalnych warunkach pracy
    '''
    url = "http://localhost:8000/revoke/"
    data = [
        {
            "fingerprint": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        },
        {
            "serial": "1769461061043067",
        }
    ]
    for _ in range(len(data)):
        response = requests.get(url, params=data[_])
        assert response.status_code == 200



def test_revoke_cert_both_params():
    '''
        Test komunikatu revoke_cert w ze złym parametrem
    '''
    url = "http://localhost:8000/revoke/"
    data = {
            "fingerprint": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
            "serial": "1769461061043067"
        }
    response = requests.get(url, params=data)
    assert response.status_code == 200



def test_issue_cert_no_param():
    '''
        Test komunikatu get_csr bez paametrów
    '''

    url = "http://localhost:8000/issue_cert/"
    data = {}

    response = requests.post(url, data=data)

    assert response.status_code == 404


def test_revoke_cert_bad_param():
    '''
        Test komunikatu revoke_cert w ze złym parametrem
    '''
    url = "http://localhost:8000/revoke/"
    data = {
            "ids": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        }
    response = requests.get(url, params=data)
    assert response.status_code == 404


def test_issue_cert_bad_method():
    '''
        Test komunikatu issue_cert złą metodą
    '''

    url = "http://localhost:8000/revoke/"
    data = {
        "fingerprint": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049"
    }

    response = requests.get(url, params=data)

    assert response.status_code == 200
