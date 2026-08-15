from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from django.db import models
from django.utils import timezone
from datetime import timedelta
from .ca import load_ca

class Cert(models.Model):
    """
    Model reprezentujący certyfikat X.509 przechowywany w systemie.

    Model przechowuje certyfikat w formacie PEM wraz z metadanymi:
    okresem ważności, danymi wystawcy i właściciela, algorytmami
    kryptograficznymi oraz zaszyfrowanym kluczem prywatnym.

    :ivar serial_number: Numer seryjny certyfikatu
    :type serial_number: str

    :ivar fingerprint_sha256: Odcisk palca certyfikatu (SHA-256)
    :type fingerprint_sha256: str

    :ivar subject_dn: Distinguished Name właściciela certyfikatu
    :type subject_dn: str

    :ivar issuer_dn: Distinguished Name wystawcy certyfikatu
    :type issuer_dn: str

    :ivar not_before: Data rozpoczęcia ważności certyfikatu
    :type not_before: datetime.datetime

    :ivar not_after: Data zakończenia ważności certyfikatu
    :type not_after: datetime.datetime

    :ivar public_key_algorithm: Algorytm klucza publicznego
    :type public_key_algorithm: str

    :ivar signature_algorithm: Algorytm podpisu certyfikatu
    :type signature_algorithm: str

    :ivar key_size: Długość klucza w bitach
    :type key_size: int

    :ivar encrypted_private_key: Zaszyfrowany klucz prywatny w PEM (opcjonalny)
    :type encrypted_private_key: str | None

    :ivar public_key: Klucz publiczny w formacie PEM
    :type public_key: str

    :ivar is_ca: Informacja, czy certyfikat jest certyfikatem CA
    :type is_ca: bool

    :ivar key_usage: Ograniczenia użycia klucza
    :type key_usage: str

    :ivar extended_key_usage: Rozszerzone przeznaczenia certyfikatu
    :type extended_key_usage: str

    :ivar pem_data: Pełna treść certyfikatu w formacie PEM
    :type pem_data: str

    :ivar revoked: Informacja o unieważnieniu certyfikatu
    :type revoked: bool

    :ivar created_at: Data utworzenia wpisu w bazie danych
    :type created_at: datetime.datetime
    """

    serial_number = models.CharField(
        max_length=128,
        unique=True,
        help_text="Unikalny numer seryjny certyfikatu X.509."
    )

    fingerprint_sha256 = models.CharField(
        max_length=64,
        unique=True,
        help_text="Odcisk palca certyfikatu w SHA-256."
    )

    subject_dn = models.TextField(
        help_text="Distinguished Name (DN) właściciela certyfikatu."
    )

    issuer_dn = models.TextField(
        help_text="Distinguished Name (DN) wystawcy certyfikatu."
    )

    not_before = models.DateTimeField(
        help_text="Data i czas rozpoczęcia ważności certyfikatu."
    )

    not_after = models.DateTimeField(
        db_index=True,
        help_text="Data i czas zakończenia ważności certyfikatu."
    )

    public_key_algorithm = models.CharField(
        max_length=50,
        help_text="Algorytm klucza publicznego."
    )

    signature_algorithm = models.CharField(
        max_length=100,
        help_text="Algorytm podpisu certyfikatu."
    )

    key_size = models.IntegerField(
        help_text="Długość klucza w bitach."
    )

    encrypted_private_key = models.TextField(
        null=True,
        help_text="Zaszyfrowany klucz prywatny w formacie PEM."
    )

    public_key = models.TextField(
        help_text="Klucz publiczny w formacie PEM."
    )

    is_ca = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Określa, czy certyfikat jest certyfikatem CA."
    )

    key_usage = models.TextField(
        blank=True,
        help_text="Rozszerzenie Key Usage certyfikatu."
    )

    extended_key_usage = models.TextField(
        blank=True,
        help_text="Rozszerzenie Extended Key Usage certyfikatu."
    )

    pem_data = models.TextField(
        help_text="Certyfikat zapisany w formacie PEM."
    )

    revoked = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Określa, czy certyfikat został unieważniony."
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def Revoke(self):
        """
        Metoda do odwołania certyfikatu.
        :return:
        """
        self.revoked = True
        self.save(update_fields=["revoked"])

    def is_valid(self) -> bool:
        """
        Sprawdza, czy certyfikat jest aktualnie ważny.

        Certyfikat jest ważny, jeżeli:
        - aktualny czas mieści się w okresie ważności
        - certyfikat nie został unieważniony

        :return: Informacja, czy certyfikat jest ważny
        :rtype: bool
        """
        now = timezone.now()
        return self.not_before <= now <= self.not_after and not self.revoked

    def __str__(self) -> str:
        """
        Zwraca czytelną reprezentację certyfikatu.

        :return: Certyfikat w formacie PEM
        :rtype: str
        """
        return self.pem_data




class CertRequest(models.Model):
    """
    Model reprezentujący żądanie certyfikatu X.509 (CSR).

    Certificate Signing Request (CSR) zawiera dane identyfikujące
    podmiot, jego klucz publiczny oraz podpis potwierdzający
    posiadanie klucza prywatnego.

    CSR może zostać:
    - zaakceptowany i podpisany przez CA
    - odrzucony
    - przekształcony w certyfikat X.509

    :ivar fingerprint_sha256: Odcisk palca CSR (SHA-256)
    :type fingerprint_sha256: str

    :ivar subject_dn: Distinguished Name podmiotu
    :type subject_dn: str

    :ivar public_key: Klucz publiczny w formacie PEM
    :type public_key: str

    :ivar encrypted_private_key: Zaszyfrowany klucz prywatny powiązany z kluczem publicznym w formacie PEM. (Parametr opcjonalny)
    :type encrypted_private_key: str

    :ivar public_key_algorithm: Algorytm klucza publicznego
    :type public_key_algorithm: str

    :ivar key_size: Długość klucza publicznego w bitach
    :type key_size: int

    :ivar signature_algorithm: Algorytm podpisu CSR
    :type signature_algorithm: str

    :ivar csr_pem: Treść CSR w formacie PEM
    :type csr_pem: str

    :ivar status: Status przetwarzania CSR
    :type status: str

    :ivar created_at: Data utworzenia CSR
    :type created_at: datetime.datetime

    :ivar processed_at: Data przetworzenia CSR
    :type processed_at: datetime.datetime | None
    """

    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"

    STATUS_CHOICES = [
        (STATUS_PENDING, "Oczekujące"),
        (STATUS_APPROVED, "Zatwierdzone"),
        (STATUS_REJECTED, "Odrzucone"),
    ]

    fingerprint_sha256 = models.CharField(
        max_length=64,
        unique=True,
        help_text="Odcisk palca CSR (SHA-256)."
    )

    subject_dn = models.TextField(
        help_text="Distinguished Name (DN) podmiotu żądającego certyfikatu."
    )

    public_key = models.TextField(
        help_text="Klucz publiczny w formacie PEM."
    )

    encrypted_private_key = models.TextField(
        null=True,
        help_text="Zaszyfrowany klucz prywatny powiązany z kluczem publicznym w formacie PEM."
    )

    public_key_algorithm = models.CharField(
        max_length=50,
        help_text="Algorytm klucza publicznego (np. RSA, EC)."
    )

    key_size = models.IntegerField(
        help_text="Długość klucza publicznego w bitach."
    )

    signature_algorithm = models.CharField(
        max_length=100,
        help_text="Algorytm podpisu CSR."
    )

    csr_pem = models.TextField(
        help_text="Żądanie certyfikatu (CSR) w formacie PEM."
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
        help_text="Status przetwarzania CSR."
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Data utworzenia żądania certyfikatu."
    )

    processed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Data przetworzenia żądania certyfikatu."
    )

    def approve(self):
        """
        Oznacza CSR jako zatwierdzone.

        Metoda powinna być wywoływana przed
        wystawieniem certyfikatu X.509.

        :return: None
        """
        self.status = self.STATUS_APPROVED
        self.processed_at = timezone.now()
        self.save(update_fields=["status", "processed_at"])

    def reject(self):
        """
        Oznacza CSR jako odrzucone.

        :return: None
        """
        self.status = self.STATUS_REJECTED
        self.processed_at = timezone.now()
        self.save(update_fields=["status", "processed_at"])

    def __str__(self) -> str:
        """
        Zwraca czytelną reprezentację CSR.

        :return: CSR w formacie PEM
        :rtype: str
        """
        return self.csr_pem


class Crl(models.Model):
    """
    Model reprezentujący listę unieważnionych certyfikatów (CRL).

    CRL zawiera informacje o certyfikatach, które zostały
    unieważnione przez urząd certyfikacji (CA).

    :ivar issuer_dn: Distinguished Name urzędu certyfikacji
    :type issuer_dn: str

    :ivar this_update: Data wygenerowania CRL
    :type this_update: datetime.datetime

    :ivar next_update: Data następnej aktualizacji CRL
    :type next_update: datetime.datetime

    :ivar revoked_certificates: Lista unieważnionych certyfikatów (numery seryjne)
    :type revoked_certificates: list[str]

    :ivar version: Wersja CRL (zwykle 1 lub 2)
    :type version: int

    :ivar created_at: Data dodania wpisu CRL w bazie
    :type created_at: datetime.datetime

    :ivar crl_pem: Lista CRL w formacie PEM
    :type crl_pem: str
    """

    issuer_dn = models.TextField(
        help_text="Distinguished Name (DN) urzędu certyfikacji, który wystawił CRL."
    )

    this_update = models.DateTimeField(
        default=timezone.now,
        help_text="Data i czas wygenerowania CRL."
    )

    next_update = models.DateTimeField(
        help_text="Data i czas następnej aktualizacji CRL."
    )

    version = models.IntegerField(
        default=2,
        help_text="Wersja CRL (zwykle 1 lub 2)."
    )

    # Lista numerów seryjnych certyfikatów w CRL
    revoked_certificates = models.JSONField(
        default=list,
        blank=True,
        help_text="Lista unieważnionych certyfikatów (numery seryjne)."
    )

    created_at = models.DateTimeField(auto_now_add=True)

    crl_pem = models.TextField(
        help_text="CRL (Certificate Revocation List) w formacie PEM, wygenerowany i podpisany przez CA."
    )

    def __str__(self) -> str:
        """
        Zwraca czytelną reprezentację CRL.

        :return: CRL w formacie PEM
        :rtype: str
        """
        return self.crl_pem

    @classmethod
    def get_or_create_current_crl(cls, validity_days=7):
        """
        Zwraca aktualny CRL dla danego CA.
        Jeżeli istniejący CRL jest nieaktualny, tworzy nowy.

        :param validity_days: liczba dni ważności CRL
        :return: obiekt CRL
        :rtype: Crl
        """

        ca_key, ca_cert, _ = load_ca()

        issuer_dn = ", ".join(f"{attr.oid._name}={attr.value}" for attr in ca_cert.issuer)
        print(issuer_dn)

        now = timezone.now()

        crl = cls.objects.filter(issuer_dn=issuer_dn, next_update__gt=now).order_by('-this_update').first()
        if crl:
            return crl

        new_crl = cls(
            issuer_dn=issuer_dn,
            this_update=now,
            next_update=now + timedelta(days=validity_days)
        )

        revoked_certs = Cert.objects.filter(revoked=True, issuer_dn=issuer_dn)

        crl_builder = x509.CertificateRevocationListBuilder() \
            .issuer_name(x509.Name([x509.NameAttribute(attr.oid, attr.value) for attr in ca_cert.issuer])) \
            .last_update(new_crl.this_update) \
            .next_update(new_crl.next_update)

        for cert in revoked_certs:
            revoked_cert = x509.RevokedCertificateBuilder() \
                .serial_number(
                int(cert.serial_number, 16) if isinstance(cert.serial_number, str) else cert.serial_number) \
                .revocation_date(new_crl.this_update) \
                .build()
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

        crl_obj = crl_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
        new_crl.crl_pem = crl_obj.public_bytes(serialization.Encoding.PEM).decode()
        new_crl.save()
        return new_crl