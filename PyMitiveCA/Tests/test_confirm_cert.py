import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

'''
Test komunikatu confirm_cert.

confirm_cert/ kończy Proof-of-Possession dla certyfikatów wystawionych
dla kluczy KEM (ML-KEM) przez issue_cert/ (crmf_pem) - to jedyna ścieżka,
gdzie serwer faktycznie nigdy nie poznaje klucza prywatnego (klient sam
go generuje), więc szyfrowanie certyfikatu i wymaganie odszyfrowania ma
sens jako dowód posiadania klucza. generate_cert/ generuje klucz po
stronie serwera i zwraca certyfikat od razu w postaci jawnej (spójnie z
resztą algorytmów) - tam confirm_cert/ nie wchodzi w grę.
'''

CONFIRM_CERT_URL = "https://localhost/confirm_cert/"


def _generate_pending_ml_kem_cert():
    '''
    Tworzy certyfikat ML-KEM oczekujący na potwierdzenie POP, symulując
    prawdziwego klienta: klucz i żądanie CRMF pochodzą z generate_csr/
    (żeby nie duplikować w teście logiki kodującej ASN.1), ale samo
    wystawienie certyfikatu idzie przez issue_cert/ - jedyny endpoint,
    który faktycznie nie zna klucza prywatnego i zwraca pop_pending.
    '''
    csr_response = requests.post("https://localhost/generate_csr/", data={
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ML-KEM",
    })
    assert csr_response.status_code == 201
    csr_body = csr_response.json()

    issue_response = requests.post("https://localhost/issue_cert/", data={
        "crmf_pem": csr_body["crmf_pem"],
    })
    assert issue_response.status_code == 202
    bundle = issue_response.json()
    bundle["private_key_pem"] = csr_body["private_key_pem"]
    return bundle


def test_confirm_cert_success():
    '''
    Test confirm_cert w normalnych warunkach pracy - poprawny klucz
    prywatny odszyfrowuje certyfikat i odblokowuje jego postać jawną.
    '''
    bundle = _generate_pending_ml_kem_cert()

    response = requests.post(CONFIRM_CERT_URL, data={
        "serial": bundle["serial"],
        "private_key_pem": bundle["private_key_pem"],
    })
    assert response.status_code == 200
    cert = x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())
    assert cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "Jan Kowalski"
    assert str(cert.serial_number) == bundle["serial"]

    # Certyfikat powinien być teraz dostępny w postaci jawnej przez get_cert/.
    get_response = requests.get("https://localhost/get_cert/", params={"serial": bundle["serial"]})
    assert get_response.status_code == 200
    assert get_response.text == response.text


def test_confirm_cert_by_fingerprint():
    '''
    Test confirm_cert z identyfikatorem po fingerprint zamiast serial.
    '''
    bundle = _generate_pending_ml_kem_cert()

    response = requests.post(CONFIRM_CERT_URL, data={
        "fingerprint": bundle["fingerprint"],
        "private_key_pem": bundle["private_key_pem"],
    })
    assert response.status_code == 200


def test_confirm_cert_wrong_key():
    '''
    Test confirm_cert z niepasującym kluczem prywatnym (oczekiwane 403) -
    to jest właśnie weryfikacja POP: zły klucz nie odszyfruje certyfikatu.
    '''
    bundle = _generate_pending_ml_kem_cert()
    other_bundle = _generate_pending_ml_kem_cert()

    response = requests.post(CONFIRM_CERT_URL, data={
        "serial": bundle["serial"],
        "private_key_pem": other_bundle["private_key_pem"],
    })
    assert response.status_code == 403


def test_confirm_cert_already_confirmed():
    '''
    Test confirm_cert wywołanego drugi raz na tym samym certyfikacie
    (oczekiwane 400 - nie oczekuje już na potwierdzenie POP).
    '''
    bundle = _generate_pending_ml_kem_cert()
    data = {"serial": bundle["serial"], "private_key_pem": bundle["private_key_pem"]}

    first = requests.post(CONFIRM_CERT_URL, data=data)
    assert first.status_code == 200

    second = requests.post(CONFIRM_CERT_URL, data=data)
    assert second.status_code == 400


def test_confirm_cert_not_pending():
    '''
    Test confirm_cert na zwykłym certyfikacie RSA (nigdy nie był
    pop_pending), oczekiwane 400.
    '''
    gen_response = requests.post("https://localhost/generate_cert/", data={
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "RSA",
    })
    assert gen_response.status_code == 200
    cert = x509.load_pem_x509_certificate(gen_response.text.encode('utf-8'), default_backend())
    serial = str(cert.serial_number)

    response = requests.post(CONFIRM_CERT_URL, data={
        "serial": serial,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n",
    })
    assert response.status_code == 400


def test_confirm_cert_no_identifier():
    '''
    Test confirm_cert bez fingerprint/serial (oczekiwane 404).
    '''
    response = requests.post(CONFIRM_CERT_URL, data={"private_key_pem": "cokolwiek"})
    assert response.status_code == 404


def test_confirm_cert_no_private_key():
    '''
    Test confirm_cert bez private_key_pem (oczekiwane 400).
    '''
    bundle = _generate_pending_ml_kem_cert()
    response = requests.post(CONFIRM_CERT_URL, data={"serial": bundle["serial"]})
    assert response.status_code == 400


def test_confirm_cert_bad_private_key_format():
    '''
    Test confirm_cert z nieprawidłowym formatem private_key_pem (oczekiwane 400).
    '''
    bundle = _generate_pending_ml_kem_cert()
    response = requests.post(CONFIRM_CERT_URL, data={
        "serial": bundle["serial"],
        "private_key_pem": "to nie jest klucz PEM",
    })
    assert response.status_code == 400


def test_confirm_cert_nonexistent():
    '''
    Test confirm_cert dla nieistniejącego certyfikatu (oczekiwane 404).
    '''
    response = requests.post(CONFIRM_CERT_URL, data={
        "serial": "0",
        "private_key_pem": "cokolwiek",
    })
    assert response.status_code == 404


def test_confirm_cert_bad_method():
    '''
    Test confirm_cert złą metodą (oczekiwane 405).
    '''
    bundle = _generate_pending_ml_kem_cert()
    response = requests.get(CONFIRM_CERT_URL, params={
        "serial": bundle["serial"],
        "private_key_pem": bundle["private_key_pem"],
    })
    assert response.status_code == 405


def test_confirm_cert_full_crmf_flow():
    '''
    Pełny przepływ: generate_csr/ (CRMF, ML-KEM) -> issue_cert/ (crmf_pem)
    -> confirm_cert/ - symuluje prawdziwego klienta, który sam generuje
    klucz i dopiero na końcu odszyfrowuje wydany certyfikat.
    '''
    csr_response = requests.post("https://localhost/generate_csr/", data={
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": "ML-KEM",
    })
    assert csr_response.status_code == 201
    csr_body = csr_response.json()

    issue_response = requests.post("https://localhost/issue_cert/", data={
        "crmf_pem": csr_body["crmf_pem"],
    })
    assert issue_response.status_code == 202
    issue_body = issue_response.json()

    confirm_response = requests.post(CONFIRM_CERT_URL, data={
        "fingerprint": issue_body["fingerprint"],
        "private_key_pem": csr_body["private_key_pem"],
    })
    assert confirm_response.status_code == 200
    cert = x509.load_pem_x509_certificate(confirm_response.text.encode('utf-8'), default_backend())
    assert cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value == "Jan Kowalski"
