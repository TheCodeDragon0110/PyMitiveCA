"""
Serwis OCSP (Online Certificate Status Protocol, RFC 6960).

Odpowiedzi są podpisywane bezpośrednio kluczem CA - responderID jest
zakodowany jako skrót klucza publicznego CA (byKey), więc klient wie, że
odpowiada sam wystawca i nie potrzebuje osobnego certyfikatu respondera
delegowanego (id-kp-OCSPSigning).

Status certyfikatu wynika wprost z bazy:
* rekord istnieje i nie jest unieważniony -> GOOD
* rekord istnieje i jest unieważniony     -> REVOKED (+ revocationTime)
* brak rekordu                            -> UNKNOWN

Certyfikaty oczekujące na potwierdzenie POP (pop_pending=True) też mają już
numer seryjny i są wystawione, więc raportujemy je normalnie - to, że
żądający nie odebrał jeszcze jawnej postaci, nie zmienia statusu w PKI.
"""
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp as x509_ocsp
from django.utils import timezone

from .ca import load_ca
from .models import Cert

# Jak długo odpowiedź OCSP może być uznawana za aktualną (nextUpdate).
RESPONSE_VALIDITY = datetime.timedelta(hours=1)

# Podpis odpowiedzi - CA projektu jest kluczem RSA, więc SHA-256 jest
# spójne z podpisami certyfikatów i CRL.
SIGNATURE_HASH_ALGORITHM = hashes.SHA256()


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """
    Czyta pojedynczy element DER (tag-length-value) zaczynający się na
    pozycji `offset`.

    :return: (tag, zawartość, pozycja tuż za elementem)
    """
    tag = data[offset]
    length_byte = data[offset + 1]
    if length_byte < 0x80:
        length, header_size = length_byte, 2
    else:
        length_octets = length_byte & 0x7F
        length = int.from_bytes(data[offset + 2:offset + 2 + length_octets], "big")
        header_size = 2 + length_octets
    value_start = offset + header_size
    return tag, data[value_start:value_start + length], value_start + length


def _public_key_bitstring(public_key) -> bytes:
    """
    Zwraca zawartość pola subjectPublicKey (samą wartość BIT STRING, bez
    tagu i bajtu nieużywanych bitów) - to właśnie z niej liczony jest
    issuerKeyHash z żądania OCSP (RFC 6960, sekcja 4.1.1).

    `cryptography` nie udostępnia tego pola wprost (SubjectKeyIdentifier
    liczy skrót na sztywno SHA-1), a żądanie może wskazywać dowolną funkcję
    skrótu - dlatego wyłuskujemy je z DER-a SubjectPublicKeyInfo.
    """
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _tag, spki_body, _end = _read_tlv(spki, 0)          # SEQUENCE SubjectPublicKeyInfo
    _tag, _algorithm, next_offset = _read_tlv(spki_body, 0)  # AlgorithmIdentifier
    _tag, bit_string, _end = _read_tlv(spki_body, next_offset)  # BIT STRING
    return bit_string[1:]  # pierwszy bajt BIT STRING to licznik nieużywanych bitów


def _digest(algorithm: hashes.HashAlgorithm, data: bytes) -> bytes:
    digest = hashes.Hash(algorithm)
    digest.update(data)
    return digest.finalize()


def _request_targets_our_ca(request: x509_ocsp.OCSPRequest, ca_cert: x509.Certificate) -> bool:
    """
    Sprawdza, czy pytanie dotyczy certyfikatu wystawionego przez nasze CA -
    porównuje skróty nazwy i klucza wystawcy z żądania z faktycznym CA.
    """
    name_hash = _digest(request.hash_algorithm, ca_cert.subject.public_bytes())
    key_hash = _digest(request.hash_algorithm, _public_key_bitstring(ca_cert.public_key()))
    return name_hash == request.issuer_name_hash and key_hash == request.issuer_key_hash


def _unsuccessful(status: x509_ocsp.OCSPResponseStatus) -> bytes:
    return x509_ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(serialization.Encoding.DER)


def _copy_nonce(builder: x509_ocsp.OCSPResponseBuilder, request: x509_ocsp.OCSPRequest) -> x509_ocsp.OCSPResponseBuilder:
    """
    Przepisuje nonce z żądania do odpowiedzi - to on wiąże odpowiedź z
    konkretnym pytaniem i chroni klienta przed atakiem powtórzeniowym.
    """
    try:
        nonce = request.extensions.get_extension_for_class(x509.OCSPNonce)
    except x509.ExtensionNotFound:
        return builder
    return builder.add_extension(nonce.value, critical=False)


def _certificate_status(serial_number: int):
    """
    Ustala status certyfikatu o danym numerze seryjnym.

    :return: (cert_status, revocation_time, revocation_reason)
    """
    # Numery seryjne trzymamy w bazie jako zapis dziesiętny (patrz
    # _save_issued_cert w views.py), a żądanie OCSP niesie liczbę.
    cert = Cert.objects.filter(serial_number=str(serial_number)).first()

    if cert is None:
        return x509_ocsp.OCSPCertStatus.UNKNOWN, None, None

    if not cert.revoked:
        return x509_ocsp.OCSPCertStatus.GOOD, None, None

    # revoked_at bywa puste dla certyfikatów unieważnionych przed dodaniem
    # tego pola - wtedy najbezpieczniejszym przybliżeniem jest data wpisu.
    revocation_time = cert.revoked_at or cert.created_at
    return x509_ocsp.OCSPCertStatus.REVOKED, revocation_time, cert.revocation_reason_flag()


def build_ocsp_response(der_request: bytes) -> bytes:
    """
    Buduje podpisaną odpowiedź OCSP na żądanie w formacie DER.

    Zgodnie z RFC 6960 błędy protokołu nie są sygnalizowane kodem HTTP,
    tylko odpowiedzią OCSP o odpowiednim responseStatus (malformedRequest,
    unauthorized) - dlatego funkcja zawsze zwraca poprawny DER.

    :param der_request: żądanie OCSP (DER)
    :return: odpowiedź OCSP (DER)
    :rtype: bytes
    """
    try:
        request = x509_ocsp.load_der_ocsp_request(der_request)
    except ValueError:
        return _unsuccessful(x509_ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

    ca_key, ca_cert, _ = load_ca()

    if not _request_targets_our_ca(request, ca_cert):
        # Pytanie o certyfikat innego wystawcy - nie jesteśmy dla niego
        # autorytatywni.
        return _unsuccessful(x509_ocsp.OCSPResponseStatus.UNAUTHORIZED)

    cert_status, revocation_time, revocation_reason = _certificate_status(request.serial_number)

    now = timezone.now()
    builder = x509_ocsp.OCSPResponseBuilder().add_response_by_hash(
        issuer_name_hash=request.issuer_name_hash,
        issuer_key_hash=request.issuer_key_hash,
        serial_number=request.serial_number,
        algorithm=request.hash_algorithm,
        cert_status=cert_status,
        this_update=now,
        next_update=now + RESPONSE_VALIDITY,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
    ).responder_id(x509_ocsp.OCSPResponderEncoding.HASH, ca_cert)

    builder = _copy_nonce(builder, request)

    response = builder.sign(ca_key, SIGNATURE_HASH_ALGORITHM)
    return response.public_bytes(serialization.Encoding.DER)
