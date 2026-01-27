import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from django.http import HttpResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from .ca import load_ca

from .models import Cert, CertRequest, Crl

@csrf_exempt
@require_POST
def generate_cert(request):
    """
    Wystawia certyfikat X.509 na podstawie przesłanego DN.

    :param request: Żądanie HTTP POST
        Parametry POST:
            dn (str): Distinguished Name, np. "CN=Jan Kowalski, O=MyOrg, C=PL"
            valid_days (int, optional): okres ważności certyfikatu (domyślnie 365)

    :return: Certyfikat X.509 w formacie PEM
    :rtype: HttpResponse
    """
    dn_str = request.POST.get("dn")
    valid_days = int(request.POST.get("valid_days", 365))

    if not dn_str:
        raise Http404("Brak wymaganego parametru: DN")

    # Parsowanie DN z formatu CSV
    name_attributes = []
    for rdn in dn_str.split(","):
        key, value = rdn.strip().split("=", 1)
        oid_map = {
            "C": x509.OID_COUNTRY_NAME,
            "ST": x509.OID_STATE_OR_PROVINCE_NAME,
            "L": x509.OID_LOCALITY_NAME,
            "O": x509.OID_ORGANIZATION_NAME,
            "OU": x509.OID_ORGANIZATIONAL_UNIT_NAME,
            "CN": x509.OID_COMMON_NAME,
        }
        if key not in oid_map:
            continue
        name_attributes.append(x509.NameAttribute(oid_map[key], value))

    subject = x509.Name(name_attributes)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    ca_key, ca_cert, _ = load_ca()
    ca_private_key = ca_key
    ca_cert_obj = ca_cert

    serial_number = int(datetime.datetime.now().timestamp() * 1_000_000)

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert_obj.subject)
        .public_key(csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(datetime.datetime.now())
        .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
    )

    cert = cert_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(csr.public_bytes(serialization.Encoding.DER))
    fingerprint = fingerprint.finalize().hex()

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    csr_request = CertRequest.objects.create(
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        fingerprint_sha256=fingerprint,
        subject_dn=dn_str,
        public_key=public_key_pem,
        public_key_algorithm="RSA_with_SHA256",
        key_size=2048,
        signature_algorithm="RSA",
        status=CertRequest.STATUS_APPROVED,
        processed_at=datetime.datetime.now(),
        created_at=datetime.datetime.now(),
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

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

    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    encrypted_private_key = None

    signature_algorithm = cert.signature_hash_algorithm.name

    public_key_algorithm = public_key.__class__.__name__

    if hasattr(public_key, "key_size"):  # np. RSA
        key_size = public_key.key_size
    else:
        key_size = None


    cert_obj = Cert.objects.create(
        pem_data=cert_pem,
        fingerprint_sha256=fingerprint,
        serial_number=str(cert.serial_number),
        subject_dn=subject_dn,
        issuer_dn=issuer_dn,
        not_before=cert.not_valid_before,
        not_after=cert.not_valid_after,
        public_key_algorithm=public_key_algorithm,
        signature_algorithm=signature_algorithm,
        key_size=key_size,
        encrypted_private_key=encrypted_private_key,
        public_key=public_key_pem,
        is_ca=cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        if cert.extensions.get_extension_for_class(x509.BasicConstraints) else False,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        revoked=False,
        created_at=datetime.datetime.now()
    )

    response = HttpResponse(cert_pem, content_type="application/x-pem-file")
    response["Content-Disposition"] = f'attachment; filename="csr_{csr_request.fingerprint_sha256}.pem"'

    return response

@csrf_exempt
@require_POST
def generate_csr(request):
    """
    Wystawia żądanie CSR na podstawie przesłanego DN.

    :param request: Żądanie HTTP POST
        Parametry POST:
            dn (str): Distinguished Name, np. "CN=Jan Kowalski, O=MyOrg, C=PL"
            valid_days (int, optional): okres ważności certyfikatu (domyślnie 365)

    :return: Żądanie CSR w formacie PEM
    :rtype: HttpResponse
    """
    dn_str = request.POST.get("dn")
    valid_days = int(request.POST.get("valid_days", 365))

    if not dn_str:
        raise Http404("Brak wymaganego parametru: DN")

    # Parsowanie DN z formatu CSV
    name_attributes = []
    for rdn in dn_str.split(","):
        key, value = rdn.strip().split("=", 1)
        oid_map = {
            "C": x509.OID_COUNTRY_NAME,
            "ST": x509.OID_STATE_OR_PROVINCE_NAME,
            "L": x509.OID_LOCALITY_NAME,
            "O": x509.OID_ORGANIZATION_NAME,
            "OU": x509.OID_ORGANIZATIONAL_UNIT_NAME,
            "CN": x509.OID_COMMON_NAME,
        }
        if key not in oid_map:
            continue
        name_attributes.append(x509.NameAttribute(oid_map[key], value))

    subject = x509.Name(name_attributes)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")



    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(csr.public_bytes(serialization.Encoding.DER))
    fingerprint = fingerprint.finalize().hex()

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    csr_request = CertRequest.objects.create(
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        fingerprint_sha256=fingerprint,
        subject_dn=dn_str,
        public_key=public_key_pem,
        public_key_algorithm="RSA_with_SHA256",
        key_size=2048,
        signature_algorithm="RSA",
        status=CertRequest.STATUS_PENDING,
        processed_at=datetime.datetime.now(),
        created_at=datetime.datetime.now(),
    )

    response = HttpResponse(csr_pem, content_type="application/x-pem-file")
    response["Content-Disposition"] = f'attachment; filename="csr_{csr_request.fingerprint_sha256}.pem"'

    return response

@csrf_exempt
@require_POST
def issue_cert(request):
    ca_key, ca_cert, _ = load_ca()
    """
    Wystawia certyfikat X.509 na podstawie przesłanego CSR w formacie PEM.

    :param request: Żądanie HTTP POST
        Parametry POST:
            csr_pem (str): CSR w formacie PEM
            ca_key_pem (str): prywatny klucz CA w formacie PEM
            ca_cert_pem (str): certyfikat CA w formacie PEM

    :return: Certyfikat X.509 w formacie PEM
    :rtype: HttpResponse
    """


    csr_pem = request.POST.get("csr_pem")
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    valid_days = int(request.POST.get("valid_days", 365))

    if not csr_pem:
        raise Http404("Brak wymaganego parametru: csr_pem")

    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except ValueError:
        raise Http404("Nieprawidłowy format CSR")

    # Załaduj klucz i certyfikat CA
    ca_private_key = ca_key
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))

    serial_number = int(datetime.datetime.now(datetime.UTC).timestamp() * 1_000_000)



    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
    )

    cert = cert_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

    public_key = cert.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    if hasattr(public_key, "key_size"):  # np. RSA
        key_size = public_key.key_size
    else:
        key_size = None

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

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

    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    encrypted_private_key = None

    signature_algorithm = cert.signature_hash_algorithm.name

    public_key_algorithm = public_key.__class__.__name__



    cert_obj = Cert.objects.create(
        pem_data=cert_pem,
        fingerprint_sha256=fingerprint,
        serial_number=str(cert.serial_number),
        subject_dn=subject_dn,
        issuer_dn=issuer_dn,
        not_before=cert.not_valid_before,
        not_after=cert.not_valid_after,
        public_key_algorithm=public_key_algorithm,
        signature_algorithm=signature_algorithm,
        key_size=key_size,
        encrypted_private_key=encrypted_private_key,
        public_key=public_key_pem,
        is_ca=cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        if cert.extensions.get_extension_for_class(x509.BasicConstraints) else False,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        revoked=False,
        created_at=datetime.datetime.now()
    )

    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(csr.public_bytes(serialization.Encoding.DER))
    fingerprint = fingerprint.finalize().hex()

    dn_str = ", ".join(f"{attr.oid._name}={attr.value}" for attr in csr.subject)

    public_key = csr.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    csr_request = CertRequest.objects.create(
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        fingerprint_sha256=fingerprint,
        subject_dn=dn_str,
        public_key=public_key_pem,
        public_key_algorithm="RSA_with_SHA256",
        key_size=2048,
        signature_algorithm="RSA",
        status=CertRequest.STATUS_PENDING,
        processed_at=datetime.datetime.now(),
        created_at=datetime.datetime.now(),
    )

    response = HttpResponse(cert_pem, content_type="application/x-pem-file")
    response["Content-Disposition"] = f'attachment; filename="cert_{serial_number}.pem"'

    return response

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

    return response

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

    response = HttpResponse(
        cert.pem_data,
        content_type="application/x-pem-file"
    )
    response["Content-Disposition"] = (
        f'attachment; filename="cert_{cert.serial_number}.pem"'
    )

    return response


def revoke_cert(request):
    """
    Odwołuje certyfikat X509.


    :param request: Żądanie odwołania certyfikatu

    Parametry GET:
        fingerprint (str): identyfikator certyfikatu\n
        serial (str): numer seryjny certyfikatu

        Wybiera się jeden z parametrów.


    :return: pusta odpowiedź o statusie 200
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

    cert.Revoke()

    response = HttpResponse(status=200)

    return response
