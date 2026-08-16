"""
Szyfrowanie/odszyfrowanie certyfikatu do klucza KEM (ML-KEM) - realizuje
Proof-of-Possession typu "keyEncipherment / subsequentMessage(encrCert)"
z CRMF (RFC 4211): wystawiony certyfikat jest szyfrowany kluczem
publicznym żądającego, a jego odszyfrowanie (możliwe tylko przez
posiadacza klucza prywatnego) jest dowodem posiadania klucza.

Schemat: ML-KEM.Encapsulate -> HKDF-SHA256 -> AES-256-GCM.
"""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_HKDF_INFO = b"PyMitiveCA ML-KEM cert encryption v1"
_NONCE_SIZE = 12


class PopVerificationFailed(ValueError):
    """Podany klucz prywatny nie pasuje do zaszyfrowanego certyfikatu."""


def _derive_aes_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(shared_secret)


def encapsulate_and_encrypt(kem_public_key, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Szyfruje `plaintext` (certyfikat PEM) do klucza publicznego KEM.
    Zwraca (kem_ciphertext, nonce, aes_ciphertext) - wszystko potrzebne
    do odszyfrowania przez posiadacza odpowiedniego klucza prywatnego.
    """
    shared_secret, kem_ciphertext = kem_public_key.encapsulate()
    aes_key = _derive_aes_key(shared_secret)
    nonce = os.urandom(_NONCE_SIZE)
    aes_ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    return kem_ciphertext, nonce, aes_ciphertext


def decapsulate_and_decrypt(kem_private_key, kem_ciphertext: bytes, nonce: bytes, aes_ciphertext: bytes) -> bytes:
    """
    Odszyfrowuje bundle zwrócony przez `encapsulate_and_encrypt`. Zgodny
    klucz prywatny jest jedynym sposobem na poprawne odtworzenie sekretu
    KEM, a nieudana weryfikacja tagu AES-GCM = dowód braku posiadania
    właściwego klucza.
    """
    try:
        shared_secret = kem_private_key.decapsulate(kem_ciphertext)
        aes_key = _derive_aes_key(shared_secret)
        return AESGCM(aes_key).decrypt(nonce, aes_ciphertext, None)
    except Exception as exc:
        raise PopVerificationFailed(
            "Nie udało się odszyfrować certyfikatu podanym kluczem prywatnym "
            "- weryfikacja posiadania klucza (POP) nie powiodła się."
        ) from exc
