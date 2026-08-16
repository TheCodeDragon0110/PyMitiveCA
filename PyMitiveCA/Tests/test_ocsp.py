import base64
import urllib.parse

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp

'''
Testy serwisu OCSP (RFC 6960). Odpowiedzi są podpisywane kluczem CA, więc
oprócz samego statusu sprawdzamy też podpis - responder bez poprawnego
podpisu jest dla klienta bezwartościowy.
'''

OCSP_URL = "https://localhost/ocsp/"


def _issue_fresh_cert(algorithm="RSA"):
    '''
    Wystawia świeży certyfikat przez generate_cert/ - testy OCSP muszą
    operować na certyfikacie realnie zapisanym w bazie CA.
    '''
    response = requests.post("https://localhost/generate_cert/", data={
        "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
        "algorithm": algorithm,
    })
    assert response.status_code == 200
    return x509.load_pem_x509_certificate(response.text.encode('utf-8'), default_backend())


def _ca_certificate():
    '''
    Wczytuje certyfikat CA aplikacji z ca.p12 - żądanie OCSP identyfikuje
    wystawcę skrótami jego nazwy i klucza publicznego, więc test musi mieć
    dokładnie ten certyfikat, którym CA podpisuje.

    Uwaga: to inny urząd niż rootCA.pem z deploy/nginx/certs (tamten służy
    wyłącznie do TLS przed aplikacją).
    '''
    import json
    import os

    from cryptography.hazmat.primitives.serialization import pkcs12

    project_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "PyMitiveCA"))
    with open(os.path.join(os.path.dirname(project_dir), "secrets.json")) as secrets_file:
        secrets = json.load(secrets_file)

    with open(os.path.join(project_dir, secrets["CA_P12_PATH"]), "rb") as p12_file:
        _key, ca_cert, _extra = pkcs12.load_key_and_certificates(
            p12_file.read(), secrets["CA_P12_PASSWORD"].encode()
        )
    return ca_cert


def _build_request(cert, algorithm=hashes.SHA1(), nonce=None):
    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, _ca_certificate(), algorithm)
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    return builder.build().public_bytes(serialization.Encoding.DER)


def _post_ocsp(der_request):
    response = requests.post(
        OCSP_URL, data=der_request, headers={"Content-Type": "application/ocsp-request"}
    )
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/ocsp-response"
    return ocsp.load_der_ocsp_response(response.content)


def _revoke(cert):
    response = requests.get("https://localhost/revoke/", params={"serial": str(cert.serial_number)})
    assert response.status_code == 200


def test_ocsp_good_status():
    '''
    Świeżo wystawiony certyfikat ma w OCSP status GOOD.
    '''
    cert = _issue_fresh_cert()
    ocsp_response = _post_ocsp(_build_request(cert))

    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD
    assert ocsp_response.serial_number == cert.serial_number


def test_ocsp_revoked_status():
    '''
    Po unieważnieniu certyfikat ma status REVOKED wraz z datą unieważnienia.
    '''
    cert = _issue_fresh_cert()
    assert _post_ocsp(_build_request(cert)).certificate_status == ocsp.OCSPCertStatus.GOOD

    _revoke(cert)
    ocsp_response = _post_ocsp(_build_request(cert))

    assert ocsp_response.certificate_status == ocsp.OCSPCertStatus.REVOKED
    assert ocsp_response.revocation_time_utc is not None
    assert ocsp_response.this_update_utc >= ocsp_response.revocation_time_utc


def test_ocsp_reports_revocation_reason():
    '''
    Powód podany przy unieważnieniu (revoke/?reason=...) trafia do
    revocationReason w odpowiedzi OCSP.
    '''
    cert = _issue_fresh_cert()

    response = requests.get(
        "https://localhost/revoke/", params={"serial": str(cert.serial_number), "reason": "key_compromise"}
    )
    assert response.status_code == 200

    ocsp_response = _post_ocsp(_build_request(cert))

    assert ocsp_response.certificate_status == ocsp.OCSPCertStatus.REVOKED
    assert ocsp_response.revocation_reason == x509.ReasonFlags.key_compromise


def test_ocsp_unknown_certificate():
    '''
    Pytanie o numer seryjny nieznany temu CA kończy się statusem UNKNOWN,
    a nie błędem HTTP.
    '''
    ca_cert = _ca_certificate()
    der_request = (
        ocsp.OCSPRequestBuilder()
        # Certyfikat CA nie jest zapisany w tabeli wystawionych certyfikatów,
        # więc jego numer seryjny jest dla respondera nieznany.
        .add_certificate(ca_cert, ca_cert, hashes.SHA1())
        .build()
        .public_bytes(serialization.Encoding.DER)
    )

    ocsp_response = _post_ocsp(der_request)

    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert ocsp_response.certificate_status == ocsp.OCSPCertStatus.UNKNOWN


def test_ocsp_signature_is_made_by_ca():
    '''
    Odpowiedź musi być podpisana kluczem CA - inaczej klient nie ma podstaw
    jej zaufać.
    '''
    cert = _issue_fresh_cert()
    ocsp_response = _post_ocsp(_build_request(cert))

    _ca_certificate().public_key().verify(
        ocsp_response.signature,
        ocsp_response.tbs_response_bytes,
        padding.PKCS1v15(),
        ocsp_response.signature_hash_algorithm,
    )


def test_ocsp_nonce_is_echoed():
    '''
    Nonce z żądania wraca w odpowiedzi - to on wiąże odpowiedź z pytaniem
    i chroni przed atakiem powtórzeniowym.
    '''
    cert = _issue_fresh_cert()
    nonce = b"0123456789abcdef"

    ocsp_response = _post_ocsp(_build_request(cert, nonce=nonce))

    echoed = ocsp_response.extensions.get_extension_for_class(x509.OCSPNonce).value
    assert echoed.nonce == nonce


@pytest.mark.parametrize("algorithm", [hashes.SHA1(), hashes.SHA256()], ids=["sha1", "sha256"])
def test_ocsp_accepts_issuer_hash_algorithms(algorithm):
    '''
    Żądanie może identyfikować wystawcę skrótem SHA-1 (domyślnym w RFC 6960)
    albo SHA-256 - responder musi rozpoznać oba.
    '''
    cert = _issue_fresh_cert()
    ocsp_response = _post_ocsp(_build_request(cert, algorithm=algorithm))

    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD


def test_ocsp_get_transport():
    '''
    Transport GET (RFC 6960, Appendix A.1.1) - żądanie zakodowane base64
    w ścieżce URL.
    '''
    cert = _issue_fresh_cert()
    encoded = urllib.parse.quote(base64.b64encode(_build_request(cert)).decode("ascii"), safe="")

    response = requests.get(OCSP_URL + encoded)

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/ocsp-response"
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD


def test_ocsp_malformed_request():
    '''
    Nieczytelne żądanie jest sygnalizowane odpowiedzią OCSP o statusie
    malformedRequest (a nie kodem HTTP - tak wymaga RFC 6960).
    '''
    ocsp_response = _post_ocsp(b"to nie jest DER")

    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST


def test_ocsp_foreign_issuer_is_unauthorized():
    '''
    Pytanie o certyfikat innego wystawcy kończy się statusem unauthorized -
    to CA nie jest dla niego autorytatywne.
    '''
    cert = _issue_fresh_cert()

    foreign_key = _issue_foreign_ca()
    der_request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(cert, foreign_key, hashes.SHA1())
        .build()
        .public_bytes(serialization.Encoding.DER)
    )

    ocsp_response = _post_ocsp(der_request)

    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED


def _issue_foreign_ca():
    '''
    Buduje lokalnie samopodpisany certyfikat obcego CA - służy tylko do
    zbudowania żądania OCSP wskazującego na innego wystawcę.
    '''
    import datetime

    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.OID_COMMON_NAME, "Foreign CA")])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def test_ocsp_bad_method():
    '''
    Endpoint OCSP obsługuje wyłącznie GET i POST.
    '''
    response = requests.delete(OCSP_URL)

    assert response.status_code == 405


def test_ocsp_get_without_request():
    '''
    GET bez zakodowanego żądania nie ma czego przetworzyć.
    '''
    response = requests.get(OCSP_URL)

    assert response.status_code == 400


def test_ocsp_get_bad_base64():
    '''
    Żądanie, którego nie da się zdekodować z base64, kończy się błędem 400.
    '''
    response = requests.get(OCSP_URL + "to-nie-jest-base64!!")

    assert response.status_code == 400


def test_issued_cert_points_to_ocsp():
    '''
    Wystawiane certyfikaty muszą nieść adres respondera (Authority
    Information Access) oraz punkt dystrybucji CRL - bez tego klient nie ma
    jak sam znaleźć serwisu OCSP.
    '''
    cert = _issue_fresh_cert()

    aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    ocsp_urls = [
        description.access_location.value
        for description in aia
        if description.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
    ]
    assert ocsp_urls and ocsp_urls[0].endswith("/ocsp/")

    crl_points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    crl_urls = [name.value for point in crl_points for name in point.full_name]
    assert crl_urls and crl_urls[0].endswith("/get_crl/")


def test_revoked_cert_appears_in_crl_with_matching_serial():
    '''
    CRL i OCSP muszą mówić o tym samym numerze seryjnym - certyfikat
    unieważniony i widoczny w OCSP jako REVOKED musi trafić do CRL pod tym
    samym numerem.
    '''
    cert = _issue_fresh_cert()
    _revoke(cert)

    assert _post_ocsp(_build_request(cert)).certificate_status == ocsp.OCSPCertStatus.REVOKED

    response = requests.get("https://localhost/get_crl/")
    assert response.status_code == 200
    crl = x509.load_pem_x509_crl(response.content, default_backend())

    assert crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None


def test_crl_reports_revocation_reason():
    '''
    Powód unieważnienia trafia też do rozszerzenia CRLReason w CRL, tak
    samo jak do revocationReason w OCSP.
    '''
    cert = _issue_fresh_cert()
    response = requests.get(
        "https://localhost/revoke/", params={"serial": str(cert.serial_number), "reason": "superseded"}
    )
    assert response.status_code == 200

    crl_response = requests.get("https://localhost/get_crl/")
    assert crl_response.status_code == 200
    crl = x509.load_pem_x509_crl(crl_response.content, default_backend())

    entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    assert entry is not None
    reason = entry.extensions.get_extension_for_class(x509.CRLReason).value
    assert reason.reason == x509.ReasonFlags.superseded
