import base64
import binascii
import datetime
import json
import urllib.parse

from django.conf import settings
from django.http import HttpResponse, Http404, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from django.utils import timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import AuthorityInformationAccessOID
from .ca import load_ca
from . import keygen, crmf, kem, ocsp

from .models import Cert, CertRequest, Crl

_DN_OID_MAP = {
    "C": x509.OID_COUNTRY_NAME,
    "ST": x509.OID_STATE_OR_PROVINCE_NAME,
    "L": x509.OID_LOCALITY_NAME,
    "O": x509.OID_ORGANIZATION_NAME,
    "OU": x509.OID_ORGANIZATIONAL_UNIT_NAME,
    "CN": x509.OID_COMMON_NAME,
}


def _parse_dn(dn_str: str) -> x509.Name:
    """Parsuje DN z formatu CSV (np. "CN=Jan Kowalski,O=MyOrg,C=PL")."""
    name_attributes = []
    for rdn in dn_str.split(","):
        key, value = rdn.strip().split("=", 1)
        if key not in _DN_OID_MAP:
            continue
        name_attributes.append(x509.NameAttribute(_DN_OID_MAP[key], value))
    return x509.Name(name_attributes)


def _key_usage_extension(is_kem: bool) -> x509.KeyUsage:
    """
    KeyUsage dla certyfikatu podmiotu. Klucze KEM (ML-KEM) nie potrafią
    podpisywać, więc dostają keyEncipherment zamiast digitalSignature.
    """
    return x509.KeyUsage(
        digital_signature=not is_kem,
        key_encipherment=True,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _with_key_info(response: HttpResponse, public_key_algorithm: str, key_size) -> HttpResponse:
    """
    Dopisuje do odpowiedzi PEM nagłówki z algorytmem i długością klucza,
    żeby klient nie musiał parsować certyfikatu, aby je poznać.
    """
    response["X-Public-Key-Algorithm"] = public_key_algorithm
    if key_size is not None:
        response["X-Key-Size"] = str(key_size)
    return response


def _cert_metadata(cert: x509.Certificate) -> dict:
    subject_dn = ", ".join(f"{attr.oid._name}={attr.value}" for attr in cert.subject)
    issuer_dn = ", ".join(f"{attr.oid._name}={attr.value}" for attr in cert.issuer)

    try:
        ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        key_usage = ", ".join([k for k, v in ku_ext.__dict__.items() if v is True])
    except x509.ExtensionNotFound:
        key_usage = ""

    try:
        eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        extended_key_usage = ", ".join([oid._name for oid in eku_ext])
    except x509.ExtensionNotFound:
        extended_key_usage = ""

    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False

    return {
        "subject_dn": subject_dn,
        "issuer_dn": issuer_dn,
        "key_usage": key_usage,
        "extended_key_usage": extended_key_usage,
        "is_ca": is_ca,
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
    }


def _revocation_extensions() -> list[tuple[x509.ExtensionType, bool]]:
    """
    Rozszerzenia wskazujące, gdzie sprawdzić status certyfikatu: adres
    respondera OCSP (Authority Information Access) oraz punkt dystrybucji
    CRL. Bez nich klient nie ma jak sam odnaleźć serwisu OCSP.
    """
    return [
        (
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(settings.OCSP_URL),
                ),
            ]),
            False,
        ),
        (
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(settings.CRL_URL)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                ),
            ]),
            False,
        ),
    ]


def _build_and_sign_cert(subject: x509.Name, public_key, valid_days: int, is_kem: bool) -> x509.Certificate:
    """Buduje certyfikat X.509 dla `subject`/`public_key`, podpisany kluczem CA."""
    ca_key, ca_cert, _ = load_ca()
    serial_number = int(datetime.datetime.now(datetime.UTC).timestamp() * 1_000_000)

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage_extension(is_kem), critical=True)
        # Powiązanie certyfikatu z kluczem CA - klient OCSP dopasowuje po nim
        # odpowiedź (responderID byKey) do wystawcy.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )

    for extension, critical in _revocation_extensions():
        cert_builder = cert_builder.add_extension(extension, critical=critical)

    return cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def _save_issued_cert(cert: x509.Certificate, public_key, public_key_algorithm: str, key_size) -> Cert:
    """Zapisuje wydany certyfikat w bazie w postaci jawnej (algorytmy zdolne do podpisu)."""
    meta = _cert_metadata(cert)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return Cert.objects.create(
        pem_data=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        fingerprint_sha256=meta["fingerprint"],
        serial_number=str(cert.serial_number),
        subject_dn=meta["subject_dn"],
        issuer_dn=meta["issuer_dn"],
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        public_key_algorithm=public_key_algorithm,
        signature_algorithm=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "N/A",
        key_size=key_size,
        encrypted_private_key=None,
        public_key=public_key_pem,
        is_ca=meta["is_ca"],
        key_usage=meta["key_usage"],
        extended_key_usage=meta["extended_key_usage"],
        revoked=False,
        created_at=timezone.now(),
    )


def _save_pending_kem_cert(cert: x509.Certificate, public_key, public_key_algorithm: str, key_size) -> tuple[Cert, dict]:
    """
    Zapisuje certyfikat wystawiony dla klucza KEM (ML-KEM) w stanie
    pop_pending=True - pem_data zostaje puste, a sam certyfikat jest
    szyfrowany do klucza publicznego podmiotu (Proof-of-Possession przez
    subsequentMessage/encrCert, patrz kem.py). Zwraca (Cert, bundle_dict).
    """
    meta = _cert_metadata(cert)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    cert_pem_bytes = cert.public_bytes(serialization.Encoding.PEM)

    kem_ciphertext, nonce, enc_cert = kem.encapsulate_and_encrypt(public_key, cert_pem_bytes)

    cert_obj = Cert.objects.create(
        pem_data="",
        fingerprint_sha256=meta["fingerprint"],
        serial_number=str(cert.serial_number),
        subject_dn=meta["subject_dn"],
        issuer_dn=meta["issuer_dn"],
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        public_key_algorithm=public_key_algorithm,
        signature_algorithm=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "N/A",
        key_size=key_size,
        encrypted_private_key=None,
        public_key=public_key_pem,
        is_ca=meta["is_ca"],
        key_usage=meta["key_usage"],
        extended_key_usage=meta["extended_key_usage"],
        revoked=False,
        created_at=timezone.now(),
        pop_pending=True,
        pop_kem_ciphertext_b64=base64.b64encode(kem_ciphertext).decode("ascii"),
        pop_nonce_b64=base64.b64encode(nonce).decode("ascii"),
        pop_encrypted_cert_b64=base64.b64encode(enc_cert).decode("ascii"),
    )

    bundle = {
        "pop_pending": True,
        "serial": cert_obj.serial_number,
        "fingerprint": cert_obj.fingerprint_sha256,
        "kem_ciphertext_b64": cert_obj.pop_kem_ciphertext_b64,
        "nonce_b64": cert_obj.pop_nonce_b64,
        "encrypted_cert_b64": cert_obj.pop_encrypted_cert_b64,
    }
    return cert_obj, bundle


@csrf_exempt
@require_POST
def generate_cert(request):
    """
    Wystawia certyfikat X.509 na podstawie przesłanego DN.

    :param request: Żądanie HTTP POST
        Parametry POST:
            dn (str): Distinguished Name, np. "CN=Jan Kowalski, O=MyOrg, C=PL"
            valid_days (int, optional): okres ważności certyfikatu (domyślnie 365)
            algorithm (str): RSA | ECDSA | ED25519 | ML-KEM
            key_size (int, optional): rozmiar klucza - RSA (2048/3072/4096)
                lub ML-KEM (768/1024, wybiera wariant)
            curve (str, optional): krzywa dla ECDSA (secp256r1/secp384r1/
                secp521r1/secp256k1)

    :return: Certyfikat X.509 w formacie PEM, niezależnie od algorytmu
        (RSA/ECDSA/ED25519/ML-KEM). Klucz prywatny jest generowany po
        stronie serwera na potrzeby wystawienia certyfikatu i nigdzie nie
        jest zwracany ani przechowywany.
    :rtype: HttpResponse
    """
    dn_str = request.POST.get("dn")
    valid_days = int(request.POST.get("valid_days", 365))
    algorithm = request.POST.get("algorithm")
    key_size = request.POST.get("key_size")
    curve = request.POST.get("curve")

    if not dn_str:
        raise Http404("Brak wymaganego parametru: DN")
    if not algorithm:
        return HttpResponse("Brak wymaganego parametru: algorithm", status=400)

    try:
        private_key, resolved_key_size, resolved_curve = keygen.generate_keypair(algorithm, key_size, curve)
    except keygen.UnsupportedAlgorithmParams as exc:
        return HttpResponse(str(exc), status=400)

    subject = _parse_dn(dn_str)
    public_key = private_key.public_key()
    public_key_algorithm = keygen.public_key_algorithm_label(private_key, resolved_key_size, resolved_curve)
    is_kem = keygen.is_kem_key(private_key)

    # Rekord "żądania" prowadzony dla celów ewidencyjnych - dla algorytmów
    # zdolnych do podpisu to samopodpisany CSR (PKCS#10), dla ML-KEM to
    # żądanie CRMF (RFC 4211) z POP=keyEncipherment/subsequentMessage,
    # bo ML-KEM nie może samodzielnie podpisać CSR.
    if is_kem:
        request_pem = crmf.build_crmf_request_pem(subject, public_key)
    else:
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(private_key, keygen.signing_hash_algorithm(private_key))
        )
        request_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    request_fingerprint = hashes.Hash(hashes.SHA256())
    request_fingerprint.update(request_pem.encode("utf-8"))
    request_fingerprint = request_fingerprint.finalize().hex()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    CertRequest.objects.create(
        csr_pem=request_pem,
        fingerprint_sha256=request_fingerprint,
        subject_dn=dn_str,
        public_key=public_key_pem,
        public_key_algorithm=public_key_algorithm,
        key_size=resolved_key_size,
        signature_algorithm="N/A (KEM)" if is_kem else "RSA_with_SHA256",
        status=CertRequest.STATUS_APPROVED,
        processed_at=timezone.now(),
        created_at=timezone.now(),
    )

    cert = _build_and_sign_cert(subject, public_key, valid_days, is_kem)

    # Klucz jest generowany po stronie serwera (tak jak dla pozostałych
    # algorytmów) - certyfikat wraca od razu w postaci jawnej, spójnie z
    # RSA/ECDSA/ED25519. Prywatny klucz nie jest nigdzie zwracany ani
    # przechowywany (patrz encrypted_private_key=None w _save_issued_cert),
    # więc szyfrowanie certyfikatu "do potwierdzenia POP" nie miałoby tu
    # żadnej realnej wartości - serwer i tak już posiadał ten klucz.
    # Pełny protokół POP (pop_pending + confirm_cert/) zostaje jedynie w
    # issue_cert/ dla crmf_pem, gdzie klucz prywatny faktycznie zna tylko
    # żądający.
    cert_obj = _save_issued_cert(cert, public_key, public_key_algorithm, resolved_key_size)
    response = HttpResponse(cert_obj.pem_data, content_type="application/x-pem-file")
    response["Content-Disposition"] = f'attachment; filename="cert_{cert_obj.fingerprint_sha256}.pem"'
    return _with_key_info(response, public_key_algorithm, resolved_key_size)


@csrf_exempt
@require_POST
def generate_csr(request):
    """
    Wystawia żądanie certyfikatu na podstawie przesłanego DN.

    :param request: Żądanie HTTP POST
        Parametry POST:
            dn (str): Distinguished Name, np. "CN=Jan Kowalski, O=MyOrg, C=PL"
            algorithm (str): RSA | ECDSA | ED25519 | ML-KEM
            key_size (int, optional): rozmiar klucza - RSA (2048/3072/4096)
                lub ML-KEM (768/1024, wybiera wariant)
            curve (str, optional): krzywa dla ECDSA (secp256r1/secp384r1/
                secp521r1/secp256k1)

    :return: Dla RSA/ECDSA/ED25519 - samopodpisany CSR (PKCS#10) w formacie
        PEM. Dla ML-KEM - JSON z żądaniem CRMF (RFC 4211, POP=
        keyEncipherment/subsequentMessage) oraz wygenerowanym kluczem
        prywatnym, bo ML-KEM nie może samodzielnie podpisać CSR.
    :rtype: HttpResponse
    """
    dn_str = request.POST.get("dn")
    algorithm = request.POST.get("algorithm")
    key_size = request.POST.get("key_size")
    curve = request.POST.get("curve")

    if not dn_str:
        raise Http404("Brak wymaganego parametru: DN")
    if not algorithm:
        return HttpResponse("Brak wymaganego parametru: algorithm", status=400)

    try:
        private_key, resolved_key_size, resolved_curve = keygen.generate_keypair(algorithm, key_size, curve)
    except keygen.UnsupportedAlgorithmParams as exc:
        return HttpResponse(str(exc), status=400)

    subject = _parse_dn(dn_str)
    public_key = private_key.public_key()
    public_key_algorithm = keygen.public_key_algorithm_label(private_key, resolved_key_size, resolved_curve)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    if keygen.is_kem_key(private_key):
        crmf_pem = crmf.build_crmf_request_pem(subject, public_key)
        fingerprint = hashes.Hash(hashes.SHA256())
        fingerprint.update(crmf_pem.encode("utf-8"))
        fingerprint = fingerprint.finalize().hex()

        CertRequest.objects.create(
            csr_pem=crmf_pem,
            fingerprint_sha256=fingerprint,
            subject_dn=dn_str,
            public_key=public_key_pem,
            public_key_algorithm=public_key_algorithm,
            key_size=resolved_key_size,
            signature_algorithm="N/A (KEM)",
            status=CertRequest.STATUS_PENDING,
            processed_at=timezone.now(),
            created_at=timezone.now(),
        )

        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode("utf-8")
        return JsonResponse({
            "crmf_pem": crmf_pem,
            "private_key_pem": private_key_pem,
            "fingerprint": fingerprint,
            "public_key_algorithm": public_key_algorithm,
            "key_size": resolved_key_size,
            "note": (
                "ML-KEM nie może samopodpisać CSR (PKCS#10) - to żądanie CRMF "
                "(RFC 4211) z POP=keyEncipherment/subsequentMessage. Prześlij je "
                "do issue_cert/ jako crmf_pem."
            ),
        }, status=201)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, keygen.signing_hash_algorithm(private_key))
    )

    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(csr.public_bytes(serialization.Encoding.DER))
    fingerprint = fingerprint.finalize().hex()

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    csr_request = CertRequest.objects.create(
        csr_pem=csr_pem,
        fingerprint_sha256=fingerprint,
        subject_dn=dn_str,
        public_key=public_key_pem,
        public_key_algorithm=public_key_algorithm,
        key_size=resolved_key_size,
        signature_algorithm="RSA_with_SHA256" if algorithm.upper() == "RSA" else public_key_algorithm,
        status=CertRequest.STATUS_PENDING,
        processed_at=timezone.now(),
        created_at=timezone.now(),
    )

    response = HttpResponse(csr_pem, content_type="application/x-pem-file")
    response["Content-Disposition"] = f'attachment; filename="csr_{csr_request.fingerprint_sha256}.pem"'

    return _with_key_info(response, public_key_algorithm, resolved_key_size)


@csrf_exempt
@require_POST
def issue_cert(request):
    """
    Wystawia certyfikat X.509 na podstawie przesłanego żądania - CSR
    (PKCS#10, algorytmy zdolne do podpisu) lub CRMF (RFC 4211, wymagane
    dla kluczy KEM, np. ML-KEM, które nie mogą samopodpisać CSR).

    :param request: Żądanie HTTP POST
        Parametry POST:
            csr_pem (str): CSR w formacie PEM (wzajemnie wykluczające się z crmf_pem)
            crmf_pem (str): żądanie CRMF w formacie PEM (dla kluczy KEM)
            valid_days (int, optional): okres ważności certyfikatu (domyślnie 365)

    :return: Dla CSR - certyfikat X.509 w formacie PEM. Dla CRMF (klucz KEM)
        - JSON z certyfikatem zaszyfrowanym do klucza z żądania (POP);
        jawny certyfikat wydaje confirm_cert/ po potwierdzeniu POP.
    :rtype: HttpResponse
    """
    csr_pem = request.POST.get("csr_pem")
    crmf_pem = request.POST.get("crmf_pem")
    valid_days = int(request.POST.get("valid_days", 365))

    if not csr_pem and not crmf_pem:
        raise Http404("Brak wymaganego parametru: csr_pem lub crmf_pem")

    if crmf_pem:
        try:
            subject, public_key = crmf.parse_crmf_request_pem(crmf_pem)
        except crmf.InvalidCrmfRequest as exc:
            return HttpResponse(str(exc), status=400)

        key_size = keygen.key_size_of(public_key)
        public_key_algorithm = keygen.public_key_algorithm_label(public_key, key_size)
        cert = _build_and_sign_cert(subject, public_key, valid_days, is_kem=True)
        _cert_obj, bundle = _save_pending_kem_cert(cert, public_key, public_key_algorithm, key_size)
        bundle["public_key_algorithm"] = public_key_algorithm
        bundle["key_size"] = key_size
        bundle["note"] = (
            "Certyfikat wystawiony z żądania CRMF jest zaszyfrowany (POP wymaga "
            "odszyfrowania kluczem prywatnym, który zna tylko żądający). Wyślij "
            "private_key_pem do confirm_cert/, żeby otrzymać certyfikat jawny."
        )
        return JsonResponse(bundle, status=202)

    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except ValueError:
        raise Http404("Nieprawidłowy format CSR")

    public_key = csr.public_key()
    cert = _build_and_sign_cert(csr.subject, public_key, valid_days, is_kem=False)

    key_size = keygen.key_size_of(public_key)
    public_key_algorithm = keygen.public_key_algorithm_label(public_key, key_size)
    cert_obj = _save_issued_cert(cert, public_key, public_key_algorithm, key_size)

    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(csr.public_bytes(serialization.Encoding.DER))
    fingerprint = fingerprint.finalize().hex()

    dn_str = ", ".join(f"{attr.oid._name}={attr.value}" for attr in csr.subject)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Ten sam CSR mógł już być zarejestrowany przez generate_csr/ (status
    # pending) - aktualizujemy taki wpis na "approved" zamiast wstawiać
    # drugi rekord o tym samym fingerprint_sha256 (unique), co kończyłoby
    # się błędem IntegrityError.
    CertRequest.objects.update_or_create(
        fingerprint_sha256=fingerprint,
        defaults=dict(
            csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            subject_dn=dn_str,
            public_key=public_key_pem,
            public_key_algorithm=public_key_algorithm,
            key_size=key_size,
            signature_algorithm="RSA_with_SHA256",
            status=CertRequest.STATUS_APPROVED,
            processed_at=timezone.now(),
        ),
    )

    response = HttpResponse(cert_obj.pem_data, content_type="application/x-pem-file")
    response["Content-Disposition"] = f'attachment; filename="cert_{cert_obj.serial_number}.pem"'

    return _with_key_info(response, public_key_algorithm, key_size)


@csrf_exempt
@require_POST
def confirm_cert(request):
    """
    Potwierdza Proof-of-Possession dla certyfikatu wystawionego z kluczem
    KEM (ML-KEM) i zwraca certyfikat w postaci jawnej.

    Certyfikaty takie są przechowywane zaszyfrowane (pop_pending=True) -
    dopiero poprawne odszyfrowanie podanym kluczem prywatnym (czyli dowód
    jego posiadania) odblokowuje jawną postać certyfikatu.

    :param request: Żądanie HTTP POST
        Parametry POST:
            fingerprint (str) lub serial (str): identyfikator certyfikatu
            private_key_pem (str): klucz prywatny (PEM, PKCS#8, bez hasła)

    :return: Certyfikat X.509 w formacie PEM (200) albo błąd (400/403/404)
    :rtype: HttpResponse
    """
    fingerprint = request.POST.get("fingerprint")
    serial = request.POST.get("serial")
    private_key_pem = request.POST.get("private_key_pem")

    if not fingerprint and not serial:
        raise Http404("Brak identyfikatora certyfikatu")
    if not private_key_pem:
        return HttpResponse("Brak wymaganego parametru: private_key_pem", status=400)

    try:
        if fingerprint:
            cert_obj = Cert.objects.get(fingerprint_sha256=fingerprint)
        else:
            cert_obj = Cert.objects.get(serial_number=serial)
    except Cert.DoesNotExist:
        raise Http404("Certyfikat nie istnieje")

    if not cert_obj.pop_pending:
        return HttpResponse("Ten certyfikat nie oczekuje na potwierdzenie POP.", status=400)

    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except ValueError:
        return HttpResponse("Nieprawidłowy format private_key_pem", status=400)

    kem_ciphertext = base64.b64decode(cert_obj.pop_kem_ciphertext_b64)
    nonce = base64.b64decode(cert_obj.pop_nonce_b64)
    enc_cert = base64.b64decode(cert_obj.pop_encrypted_cert_b64)

    try:
        cert_pem_bytes = kem.decapsulate_and_decrypt(private_key, kem_ciphertext, nonce, enc_cert)
    except kem.PopVerificationFailed as exc:
        return HttpResponse(str(exc), status=403)

    cert_obj.pem_data = cert_pem_bytes.decode("utf-8")
    cert_obj.pop_pending = False
    cert_obj.pop_kem_ciphertext_b64 = None
    cert_obj.pop_nonce_b64 = None
    cert_obj.pop_encrypted_cert_b64 = None
    cert_obj.save(update_fields=[
        "pem_data", "pop_pending", "pop_kem_ciphertext_b64", "pop_nonce_b64", "pop_encrypted_cert_b64",
    ])

    response = HttpResponse(cert_obj.pem_data, content_type="application/x-pem-file")
    response["Content-Disposition"] = f'attachment; filename="cert_{cert_obj.serial_number}.pem"'
    return _with_key_info(response, cert_obj.public_key_algorithm, cert_obj.key_size)


@csrf_exempt
@require_GET
def get_crl(request):
    """
    Funkcja zwracająca najnowszą listę CRL
    :param request: Żądanie pobrania listy CRL
    :return: Odpowiedź na żądanie z najnowszą listą CRL lub błąd 404 jak takiej listy nie ma
    """
    crl = Crl.get_or_create_current_crl()
    if crl is None:
        return HttpResponse("Brak CRL", status=404)

    response = HttpResponse(
        crl.crl_pem,
        content_type="application/x-pem-file"
    )
    response["Content-Disposition"] = (
        f'attachment; filename="cert_{datetime.datetime.now().strftime("YYYYMMDD_HHMMSS")}.pem"'
    )

    return response

@csrf_exempt
@require_GET
def get_csr(request):
    """
    Zwraca CSR (Certificate Signing Request) w formacie PEM.

    :param request: Żądanie pobrania CSR

    Parametry GET:
        fingerprint (str): odcisk palca CSR (SHA-256)
        id (str): ID żądania certyfikatu

        Wybiera się jeden z parametrów.

    :return: CSR w formacie PEM
    :rtype: HttpResponse
    """
    fingerprint = request.GET.get("fingerprint")
    csr_id = request.GET.get("id")

    if not fingerprint and not csr_id:
        raise Http404("Brak identyfikatora żądania CSR")

    try:
        if fingerprint:
            csr_request = CertRequest.objects.get(fingerprint_sha256=fingerprint)
        else:
            csr_request = CertRequest.objects.get(pk=csr_id)
    except CertRequest.DoesNotExist:
        raise Http404("Żądanie certyfikatu nie istnieje")

    csr_pem = csr_request.csr_pem

    response = HttpResponse(
        csr_pem,
        content_type="application/x-pem-file"
    )
    response["Content-Disposition"] = (
        f'attachment; filename="csr_{csr_request.fingerprint_sha256}.pem"'
    )

    return _with_key_info(response, csr_request.public_key_algorithm, csr_request.key_size)

@csrf_exempt
@require_GET
def get_cert(request):
    """
    Zwraca certyfikat X.509 w formacie PEM.


    :param request: Żądanie pobrania certyfikatu

    Parametry GET:
        fingerprint (str): identyfikator certyfikatu\n
        serial (str): numer seryjny certyfikatu

        Wybiera się jeden z parametrów.


    :return: certyfikat w formacie PEM
    :rtype: HttpResponse
    """
    fingerprint = request.GET.get("fingerprint")
    serial = request.GET.get("serial")

    if not fingerprint and not serial:
        raise Http404("Brak identyfikatora certyfikatu")

    try:
        if fingerprint:
            cert = Cert.objects.get(fingerprint_sha256=fingerprint)
        else:
            cert = Cert.objects.get(serial_number=serial)
    except Cert.DoesNotExist:
        raise Http404("Certyfikat nie istnieje")

    if cert.pop_pending:
        return HttpResponse(
            "Certyfikat oczekuje na potwierdzenie POP (patrz confirm_cert/) - "
            "postać jawna nie jest jeszcze dostępna.",
            status=409,
        )

    response = HttpResponse(
        cert.pem_data,
        content_type="application/x-pem-file"
    )
    response["Content-Disposition"] = (
        f'attachment; filename="cert_{cert.serial_number}.pem"'
    )

    return _with_key_info(response, cert.public_key_algorithm, cert.key_size)


@csrf_exempt
@require_GET
def cert_info(request):
    """
    Zwraca metadane certyfikatu w formacie JSON - w tym algorytm i długość
    klucza, bez potrzeby parsowania samego PEM-a po stronie klienta.

    :param request: Żądanie pobrania metadanych certyfikatu

    Parametry GET:
        fingerprint (str): odcisk palca certyfikatu (SHA-256)\n
        serial (str): numer seryjny certyfikatu

        Wybiera się jeden z parametrów.

    :return: metadane certyfikatu w formacie JSON
    :rtype: JsonResponse
    """
    fingerprint = request.GET.get("fingerprint")
    serial = request.GET.get("serial")

    if not fingerprint and not serial:
        raise Http404("Brak identyfikatora certyfikatu")

    try:
        if fingerprint:
            cert = Cert.objects.get(fingerprint_sha256=fingerprint)
        else:
            cert = Cert.objects.get(serial_number=serial)
    except Cert.DoesNotExist:
        raise Http404("Certyfikat nie istnieje")

    return JsonResponse({
        "serial_number": cert.serial_number,
        "fingerprint_sha256": cert.fingerprint_sha256,
        "subject_dn": cert.subject_dn,
        "issuer_dn": cert.issuer_dn,
        "not_before": cert.not_before.isoformat(),
        "not_after": cert.not_after.isoformat(),
        "public_key_algorithm": cert.public_key_algorithm,
        "key_size": cert.key_size,
        "signature_algorithm": cert.signature_algorithm,
        "is_ca": cert.is_ca,
        "key_usage": cert.key_usage,
        "extended_key_usage": cert.extended_key_usage,
        "revoked": cert.revoked,
        "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
        "revocation_reason": cert.revocation_reason,
        "pop_pending": cert.pop_pending,
        "is_valid": cert.is_valid(),
        "ocsp_url": settings.OCSP_URL,
        "crl_url": settings.CRL_URL,
    })


@csrf_exempt
@require_http_methods(["GET", "POST"])
def ocsp_responder(request, encoded_request: str = ""):
    """
    Responder OCSP (RFC 6960) - zwraca podpisany przez CA status
    certyfikatu o wskazanym numerze seryjnym.

    Obsługiwane są obie metody transportu z RFC 6960 (Appendix A):

    * POST na ocsp/ z ciałem żądania w DER
      (Content-Type: application/ocsp-request)
    * GET na ocsp/<żądanie DER zakodowane base64 i URL-encoded>

    Błędy protokołu (nieczytelne żądanie, pytanie o obcego wystawcę) nie są
    zwracane jako kody HTTP, tylko jako odpowiedź OCSP z odpowiednim
    responseStatus - dlatego endpoint odpowiada 200 także dla takich
    przypadków. Kod 400 zostaje wyłącznie dla żądania, którego nie da się
    nawet zdekodować z base64 w URL-u.

    :param request: Żądanie HTTP GET lub POST
    :param encoded_request: żądanie OCSP zakodowane base64 (tylko dla GET)
    :return: odpowiedź OCSP w formacie DER (application/ocsp-response)
    :rtype: HttpResponse
    """
    if request.method == "POST":
        der_request = request.body
    else:
        if not encoded_request:
            return HttpResponse(
                "Brak żądania OCSP - użyj POST z ciałem DER albo GET z żądaniem "
                "zakodowanym base64 w ścieżce.",
                status=400,
            )
        try:
            der_request = base64.b64decode(urllib.parse.unquote(encoded_request), validate=True)
        except (binascii.Error, ValueError):
            return HttpResponse("Nieprawidłowe kodowanie base64 żądania OCSP", status=400)

    der_response = ocsp.build_ocsp_response(der_request)

    response = HttpResponse(der_response, content_type="application/ocsp-response")
    # Odpowiedzi OCSP są krótkoterminowe i podpisane - buforowanie ich w
    # pośrednikach mogłoby ukryć świeże unieważnienie.
    response["Cache-Control"] = "no-store"
    return response


def revoke_cert(request):
    """
    Odwołuje certyfikat X509.


    :param request: Żądanie odwołania certyfikatu

    Parametry GET:
        fingerprint (str): identyfikator certyfikatu\n
        serial (str): numer seryjny certyfikatu

        Wybiera się jeden z parametrów.

        reason (str, optional): powód unieważnienia - jedna z wartości
            Cert.REASON_CHOICES (np. key_compromise, superseded);
            domyślnie "unspecified". Trafia do rozszerzenia CRLReason w CRL
            i revocationReason w odpowiedziach OCSP.


    :return: pusta odpowiedź o statusie 200, albo 400 przy nieznanym `reason`
    :rtype: HttpResponse
    """
    fingerprint = request.GET.get("fingerprint")
    serial = request.GET.get("serial")
    reason = request.GET.get("reason", Cert.REASON_UNSPECIFIED)

    if not fingerprint and not serial:
        raise Http404("Brak identyfikatora certyfikatu")

    try:
        if fingerprint:
            cert = Cert.objects.get(fingerprint_sha256=fingerprint)
        else:
            cert = Cert.objects.get(serial_number=serial)
    except Cert.DoesNotExist:
        raise Http404("Certyfikat nie istnieje")

    try:
        cert.Revoke(reason)
    except ValueError as exc:
        return HttpResponse(str(exc), status=400)

    response = HttpResponse(status=200)

    return response
