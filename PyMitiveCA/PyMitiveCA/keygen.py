"""
Generowanie par kluczy dla obsługiwanych algorytmów oraz pomocnicze
funkcje do poprawnego podpisywania w zależności od typu klucza.
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mlkem, rsa

ALGORITHM_RSA = "RSA"
ALGORITHM_ECDSA = "ECDSA"
ALGORITHM_ED25519 = "ED25519"
ALGORITHM_ML_KEM = "ML-KEM"

SUPPORTED_ALGORITHMS = (ALGORITHM_RSA, ALGORITHM_ECDSA, ALGORITHM_ED25519, ALGORITHM_ML_KEM)

RSA_KEY_SIZES = (2048, 3072, 4096, 8192)
DEFAULT_RSA_KEY_SIZE = 2048

EC_CURVES = {
    "secp256r1": ec.SECP256R1,
    "secp384r1": ec.SECP384R1,
    "secp521r1": ec.SECP521R1,
    "secp256k1": ec.SECP256K1,
}
DEFAULT_EC_CURVE = "secp256r1"

# Uwaga: cryptography (na dzień pisania) udostępnia tylko warianty
# ML-KEM-768 i ML-KEM-1024 - ML-KEM-512 nie jest obsługiwany.
ML_KEM_VARIANTS = {
    768: mlkem.MLKEM768PrivateKey,
    1024: mlkem.MLKEM1024PrivateKey,
}
DEFAULT_ML_KEM_KEY_SIZE = 768

KEM_PRIVATE_KEY_TYPES = tuple(ML_KEM_VARIANTS.values())
KEM_PUBLIC_KEY_TYPES = (mlkem.MLKEM768PublicKey, mlkem.MLKEM1024PublicKey)

# Wariant ML-KEM rozpoznawany po typie klucza - ani klucz prywatny, ani
# publiczny nie wystawiają atrybutu key_size. Typy z modułu mlkem to klasy
# abstrakcyjne, a konkretne klucze są ich podklasami, więc sprawdzamy je
# przez isinstance, nie przez dokładny typ.
_ML_KEM_SIZES = (
    ((mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey), 768),
    ((mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey), 1024),
)

# Ed25519 opiera się na krzywej Curve25519 o 255-bitowym rzędzie - biblioteka
# nie udostępnia key_size, więc podajemy tę wartość wprost.
ED25519_KEY_SIZE = 255


class UnsupportedAlgorithmParams(ValueError):
    """Nieznany algorytm lub nieprawidłowa kombinacja jego parametrów."""


def generate_keypair(algorithm: str, key_size=None, curve=None):
    """
    Generuje parę kluczy dla wskazanego algorytmu.

    :param algorithm: RSA | ECDSA | ED25519 | ML-KEM
    :param key_size: opcjonalny rozmiar klucza - RSA: 2048/3072/4096/8192,
        ML-KEM: 768/1024 (określa wariant). Ignorowany dla ECDSA/ED25519,
        gdzie długość klucza wynika z krzywej.
    :param curve: opcjonalna krzywa dla ECDSA (patrz EC_CURVES). Ignorowany
        dla pozostałych algorytmów.
    :return: (private_key, resolved_key_size, resolved_curve), gdzie
        resolved_key_size to faktyczna długość wygenerowanego klucza
        (patrz key_size_of) - także dla ECDSA i ED25519.
    """
    algo = (algorithm or "").strip().upper()

    if algo == ALGORITHM_RSA:
        size = int(key_size) if key_size not in (None, "") else DEFAULT_RSA_KEY_SIZE
        if size not in RSA_KEY_SIZES:
            raise UnsupportedAlgorithmParams(
                f"Nieobsługiwany key_size dla RSA: {size}. Dozwolone: {list(RSA_KEY_SIZES)}"
            )
        return rsa.generate_private_key(public_exponent=65537, key_size=size), size, None

    if algo == ALGORITHM_ECDSA:
        curve_name = (curve or DEFAULT_EC_CURVE).strip().lower()
        if curve_name not in EC_CURVES:
            raise UnsupportedAlgorithmParams(
                f"Nieobsługiwana krzywa dla ECDSA: {curve_name}. Dozwolone: {sorted(EC_CURVES)}"
            )
        private_key = ec.generate_private_key(EC_CURVES[curve_name]())
        return private_key, key_size_of(private_key), curve_name

    if algo == ALGORITHM_ED25519:
        return ed25519.Ed25519PrivateKey.generate(), ED25519_KEY_SIZE, None

    if algo == ALGORITHM_ML_KEM:
        size = int(key_size) if key_size not in (None, "") else DEFAULT_ML_KEM_KEY_SIZE
        if size not in ML_KEM_VARIANTS:
            raise UnsupportedAlgorithmParams(
                f"Nieobsługiwany key_size dla ML-KEM: {size}. Dozwolone: {list(ML_KEM_VARIANTS)}"
            )
        return ML_KEM_VARIANTS[size].generate(), size, None

    raise UnsupportedAlgorithmParams(
        f"Nieobsługiwany algorytm: {algorithm!r}. Dozwolone: {list(SUPPORTED_ALGORITHMS)}"
    )


def is_kem_key(key) -> bool:
    """Czy klucz (prywatny lub publiczny) jest kluczem KEM - np. ML-KEM."""
    return isinstance(key, KEM_PRIVATE_KEY_TYPES + KEM_PUBLIC_KEY_TYPES)


def key_size_of(key) -> int | None:
    """
    Zwraca długość klucza dla dowolnego obsługiwanego typu klucza -
    prywatnego lub publicznego.

    Dla RSA i ECDSA jest to liczba bitów (odpowiednio moduł i rząd krzywej),
    dla Ed25519 - 255 bitów krzywej Curve25519, a dla ML-KEM numer wariantu
    (768/1024), bo parametry tego algorytmu nie sprowadzają się do jednej
    długości w bitach.

    :param key: klucz prywatny lub publiczny
    :return: długość klucza albo None dla nieznanego typu klucza
    :rtype: int | None
    """
    for key_types, ml_kem_size in _ML_KEM_SIZES:
        if isinstance(key, key_types):
            return ml_kem_size
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return ED25519_KEY_SIZE
    return getattr(key, "key_size", None)


def signing_hash_algorithm(private_key):
    """
    Zwraca właściwy argument `algorithm=` dla .sign()/CertificateBuilder.sign()
    danego typu klucza (None dla Ed25519, który ma niejawne hashowanie).
    """
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return None
    return hashes.SHA256()


def public_key_algorithm_label(key, key_size=None, curve=None) -> str:
    """
    Czytelna etykieta algorytmu do zapisu w bazie (public_key_algorithm).

    Działa zarówno dla klucza prywatnego (ścieżka generowania), jak i
    publicznego (ścieżka CSR/CRMF, gdzie klucza prywatnego nie znamy).
    Brakujące `key_size`/`curve` są odczytywane z samego klucza.
    """
    if key_size is None:
        key_size = key_size_of(key)

    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return f"RSA-{key_size}" if key_size else "RSA"
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        curve_name = curve or getattr(key.curve, "name", None)
        return f"ECDSA-{curve_name}" if curve_name else "ECDSA"
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "ED25519"
    if is_kem_key(key):
        return f"ML-KEM-{key_size}" if key_size else "ML-KEM"
    return key.__class__.__name__
