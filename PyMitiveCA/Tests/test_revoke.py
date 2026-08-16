import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

'''
Test komunikatu revoke. 
'''

def _issue_fresh_cert():
    '''
    Wystawia świeży certyfikat przez generate_cert/ i zwraca (fingerprint,
    serial) wyliczone z odpowiedzi - revoke/ operuje na realnie istniejącym
    certyfikacie, więc test musi go najpierw sam wystawić (fingerprint i
    serial nie są deterministyczne między uruchomieniami).
    '''
    response = requests.post("https://localhost/generate_cert/", data={
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "RSA",
    })
    assert response.status_code == 200
    cert = x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())
    return cert.fingerprint(hashes.SHA256()).hex(), str(cert.serial_number)


def test_revoke_cert():
    '''
    Test komunikatu issue_cert w normalnych warunkach pracy
    '''
    url = "https://localhost/revoke/"

    fingerprint, _ = _issue_fresh_cert()
    response = requests.get(url, params={"fingerprint": fingerprint})
    assert response.status_code == 200

    _, serial = _issue_fresh_cert()
    response = requests.get(url, params={"serial": serial})
    assert response.status_code == 200



def test_revoke_cert_both_params():
    '''
        Test komunikatu revoke_cert w ze złym parametrem
    '''
    url = "https://localhost/revoke/"
    fingerprint, serial = _issue_fresh_cert()
    data = {
            "fingerprint": fingerprint,
            "serial": serial,
        }
    response = requests.get(url, params=data)
    assert response.status_code == 200



def test_issue_cert_no_param():
    '''
        Test komunikatu get_csr bez paametrów
    '''

    url = "https://localhost/issue_cert/"
    data = {}

    response = requests.post(url, data=data)

    assert response.status_code == 404


def test_revoke_cert_bad_param():
    '''
        Test komunikatu revoke_cert w ze złym parametrem
    '''
    url = "https://localhost/revoke/"
    data = {
            "ids": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        }
    response = requests.get(url, params=data)
    assert response.status_code == 404


def test_issue_cert_bad_method():
    '''
        Test komunikatu issue_cert złą metodą
    '''

    url = "https://localhost/revoke/"
    fingerprint, _ = _issue_fresh_cert()

    response = requests.get(url, params={"fingerprint": fingerprint})

    assert response.status_code == 200


def test_revoke_with_reason():
    '''
    Podany powód unieważnienia jest zapisywany i widoczny w cert_info/.
    '''
    fingerprint, serial = _issue_fresh_cert()

    response = requests.get(
        "https://localhost/revoke/", params={"serial": serial, "reason": "key_compromise"}
    )
    assert response.status_code == 200

    info = requests.get("https://localhost/cert_info/", params={"serial": serial}).json()
    assert info["revoked"] is True
    assert info["revocation_reason"] == "key_compromise"
    assert info["revoked_at"] is not None


def test_revoke_without_reason_defaults_to_unspecified():
    '''
    Bez podanego `reason` powód domyślnie to "unspecified".
    '''
    fingerprint, serial = _issue_fresh_cert()

    response = requests.get("https://localhost/revoke/", params={"serial": serial})
    assert response.status_code == 200

    info = requests.get("https://localhost/cert_info/", params={"serial": serial}).json()
    assert info["revocation_reason"] == "unspecified"


def test_revoke_rejects_unknown_reason():
    '''
    Nieznana wartość `reason` jest odrzucana (400), a certyfikat pozostaje
    nieunieważniony.
    '''
    fingerprint, serial = _issue_fresh_cert()

    response = requests.get(
        "https://localhost/revoke/", params={"serial": serial, "reason": "not-a-real-reason"}
    )
    assert response.status_code == 400

    info = requests.get("https://localhost/cert_info/", params={"serial": serial}).json()
    assert info["revoked"] is False


def test_revoke_twice_keeps_first_reason():
    '''
    Powtórne unieważnienie z innym powodem nie nadpisuje już zapisanego
    powodu ani daty - pierwsze unieważnienie jest rozstrzygające.
    '''
    fingerprint, serial = _issue_fresh_cert()

    first = requests.get(
        "https://localhost/revoke/", params={"serial": serial, "reason": "key_compromise"}
    )
    assert first.status_code == 200
    first_info = requests.get("https://localhost/cert_info/", params={"serial": serial}).json()

    second = requests.get(
        "https://localhost/revoke/", params={"serial": serial, "reason": "superseded"}
    )
    assert second.status_code == 200
    second_info = requests.get("https://localhost/cert_info/", params={"serial": serial}).json()

    assert second_info["revocation_reason"] == "key_compromise"
    assert second_info["revoked_at"] == first_info["revoked_at"]
