"""
Budowa i parsowanie żądań CRMF (RFC 4211) dla kluczy, które nie potrafią
same podpisać CSR (PKCS#10) - w tym projekcie dotyczy to ML-KEM.

Proof-of-Possession jest zawsze typu keyEncipherment/subsequentMessage
(encrCert) - jedyna metoda możliwa dla czystego KEM, bez zdolności
podpisu. Prawdziwe potwierdzenie posiadania klucza odbywa się później,
przez odszyfrowanie wydanego certyfikatu (patrz kem.py + confirm_cert/).

Uwaga implementacyjna: struktury CertTemplate/ProofOfPossession/POPOPrivKey
zawierają pola typu CHOICE (Name, POPOPrivKey) zagnieżdżone pod tagami
kontekstowymi. Zgodnie z regułami ASN.1 (X.680 §31.2.7) tagowanie typu
CHOICE zawsze staje się efektywnie EXPLICIT, nawet gdy moduł RFC 4211
deklaruje je jako IMPLICIT - stąd budowa i odczyt odbywają się na
poziomie surowych bajtów DER, a nie przez przypisania do obiektów
pyasn1 (te wymuszają dopasowanie tagów przy przypisaniu i nie radzą
sobie automatycznie z tym przypadkiem).
"""
import base64

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules import rfc4211

CRMF_PEM_LABEL = "CRMF CERTIFICATE REQUEST"

_OID_MAP = {
    "C": x509.OID_COUNTRY_NAME,
    "ST": x509.OID_STATE_OR_PROVINCE_NAME,
    "L": x509.OID_LOCALITY_NAME,
    "O": x509.OID_ORGANIZATION_NAME,
    "OU": x509.OID_ORGANIZATIONAL_UNIT_NAME,
    "CN": x509.OID_COMMON_NAME,
}
_OID_STR_MAP = {oid.dotted_string: oid for oid in _OID_MAP.values()}


class InvalidCrmfRequest(ValueError):
    """Żądanie CRMF ma nieprawidłowy format lub nieobsługiwany typ POP."""


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tag_wrap(tag_byte: int, content: bytes) -> bytes:
    return bytes([tag_byte]) + _der_len(len(content)) + content


def _sequence(*parts: bytes) -> bytes:
    content = b"".join(parts)
    return b"\x30" + _der_len(len(content)) + content


def _strip_tlv(der: bytes) -> bytes:
    length_byte = der[1]
    header_len = 2 if length_byte < 0x80 else 2 + (length_byte & 0x7F)
    return der[header_len:]


def _retag_universal_sequence(der: bytes) -> bytes:
    return b"\x30" + der[1:]


def build_crmf_request_pem(subject: x509.Name, public_key) -> str:
    """
    Buduje żądanie CRMF (CertReqMessages z pojedynczym CertReqMsg) dla
    klucza publicznego, którego nie da się użyć do samopodpisania CSR.
    """
    subject_field = _tag_wrap(0xA5, subject.public_bytes())
    spki_der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pubkey_field = _tag_wrap(0xA6, _strip_tlv(spki_der))
    cert_template_der = _sequence(subject_field, pubkey_field)

    cert_req_id = _tag_wrap(0x02, b"\x00")
    cert_request_der = _sequence(cert_req_id, cert_template_der)

    subsequent_message = _tag_wrap(0x81, b"\x00")  # [1] IMPLICIT, encrCert = 0
    key_encipherment = _tag_wrap(0xA2, subsequent_message)  # [2] "implicit" na CHOICE -> explicit

    cert_req_msg_der = _sequence(cert_request_der, key_encipherment)
    cert_req_messages_der = _sequence(cert_req_msg_der)

    # Walidacja przez pyasn1 przed wysłaniem - upewnij się, że to co
    # zbudowaliśmy ręcznie faktycznie parsuje się zgodnie ze schematem.
    _, rest = der_decode(cert_req_messages_der, asn1Spec=rfc4211.CertReqMessages())
    if rest:
        raise InvalidCrmfRequest("Zbudowane żądanie CRMF nie jest poprawne (nadmiarowe bajty)")

    b64 = base64.encodebytes(cert_req_messages_der).decode("ascii")
    return f"-----BEGIN {CRMF_PEM_LABEL}-----\n{b64}-----END {CRMF_PEM_LABEL}-----\n"


def parse_crmf_request_pem(pem_text: str):
    """
    Parsuje żądanie CRMF, zwraca (subject: x509.Name, public_key).

    Akceptowany jest wyłącznie POP typu keyEncipherment/subsequentMessage
    (encrCert) - to jedyny typ możliwy dla kluczy KEM bez zdolności
    podpisu. Inne typy POP (signature, keyAgreement, raVerified) są
    odrzucane.
    """
    lines = [l.strip() for l in pem_text.strip().splitlines() if l.strip()]
    if len(lines) < 3 or not lines[0].startswith("-----BEGIN") or not lines[-1].startswith("-----END"):
        raise InvalidCrmfRequest("Nieprawidłowy format PEM żądania CRMF")

    try:
        der = base64.b64decode("".join(lines[1:-1]))
    except Exception as exc:
        raise InvalidCrmfRequest("Nieprawidłowe kodowanie base64 żądania CRMF") from exc

    try:
        req_messages, rest = der_decode(der, asn1Spec=rfc4211.CertReqMessages())
        if rest:
            raise InvalidCrmfRequest("Żądanie CRMF zawiera nadmiarowe bajty")
    except InvalidCrmfRequest:
        raise
    except Exception as exc:
        raise InvalidCrmfRequest("Nieprawidłowa struktura ASN.1 żądania CRMF") from exc

    if len(req_messages) == 0:
        raise InvalidCrmfRequest("Żądanie CRMF nie zawiera żadnego CertReqMsg")

    req_msg = req_messages[0]
    popo = req_msg["popo"]
    if not popo.isValue or popo.getName() != "keyEncipherment":
        raise InvalidCrmfRequest(
            "Wymagany jest ProofOfPossession typu keyEncipherment "
            "(jedyny obsługiwany dla kluczy KEM, np. ML-KEM)"
        )

    popo_priv_key = popo["keyEncipherment"]
    if popo_priv_key.getName() != "subsequentMessage" or int(popo_priv_key["subsequentMessage"]) != 0:
        raise InvalidCrmfRequest(
            "Wymagany jest POPOPrivKey typu subsequentMessage=encrCert"
        )

    cert_template = req_msg["certReq"]["certTemplate"]
    if not cert_template["subject"].isValue or not cert_template["publicKey"].isValue:
        raise InvalidCrmfRequest("CertTemplate musi zawierać pola subject i publicKey")

    # "subject" jest tagowane jako [5] (efektywnie EXPLICIT, bo Name to CHOICE)
    # - trzeba zdjąć zewnętrzny tag, a wewnętrzny TLV zostaje bez zmian.
    subject_der = _strip_tlv(der_encode(cert_template["subject"]))
    subject = _decode_name(subject_der)

    spki_der = _retag_universal_sequence(der_encode(cert_template["publicKey"]))
    try:
        public_key = serialization.load_der_public_key(spki_der)
    except Exception as exc:
        raise InvalidCrmfRequest("Nieobsługiwany lub uszkodzony klucz publiczny w CertTemplate") from exc

    return subject, public_key


def _decode_name(name_der: bytes) -> x509.Name:
    from pyasn1_modules import rfc3280

    decoded, rest = der_decode(name_der, asn1Spec=rfc3280.Name())
    if rest:
        raise InvalidCrmfRequest("Nieprawidłowa struktura pola subject")

    attributes = []
    for rdn in decoded.getComponent():
        for atv in rdn:
            oid_str = str(atv["type"])
            name_oid = _OID_STR_MAP.get(oid_str)
            if name_oid is None:
                continue
            raw_value = bytes(atv["value"])
            directory_string, _ = der_decode(raw_value, asn1Spec=rfc3280.DirectoryString())
            text = str(directory_string.getComponent())
            attributes.append(x509.NameAttribute(name_oid, text))

    if not attributes:
        raise InvalidCrmfRequest("Pole subject nie zawiera żadnych rozpoznanych atrybutów DN")

    return x509.Name(attributes)
