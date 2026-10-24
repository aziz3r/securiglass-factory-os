"""Tests de robustesse cryptographique et attaques adversariales sur le TDE AES-256-GCM.

Conformité : RGPD Art. 32, OWASP ASVS v4.0 (Crypto Verification), NIST SP 800-38D.
Vérifie la résistance aux attaques de falsification : bit-flipping, corruption
du nonce, corruption du tag d'authentification GCM, attaques par substitution de clé.
"""

from __future__ import annotations

import os
import secrets
import pytest
from cryptography.exceptions import InvalidTag

from app.core.security import decrypt_field, encrypt_field
from app.services.tde_service import (
    DecryptedCustomerPII,
    EncryptedCustomerPII,
    TDEDecryptionError,
    TDEService,
)

# Clé de test CSPRNG 256-bit (32 octets)
_TEST_KEY = secrets.token_bytes(32)
_WRONG_KEY = secrets.token_bytes(32)


def test_tde_nominal_encryption_decryption() -> None:
    plaintext = "SecuriGlass Sensitive Recipe & Customer PII Data"
    ciphertext = encrypt_field(plaintext, _TEST_KEY)
    assert len(ciphertext) >= 12 + 16  # Nonce 12B + Tag 16B + Ciphertext >= 0
    decrypted = decrypt_field(ciphertext, _TEST_KEY)
    assert decrypted == plaintext


def test_tde_bit_flipping_in_ciphertext_rejected() -> None:
    """Attaque Red Team : Bit-flipping dans le corps du message chiffré."""
    plaintext = "CONFIDENTIAL_OPERATIONAL_DATA"
    ciphertext = bytearray(encrypt_field(plaintext, _TEST_KEY))

    # Flips a bit in the ciphertext payload (after the 12-byte nonce, before the 16-byte tag)
    flip_index = 15
    ciphertext[flip_index] ^= 0x01

    with pytest.raises(InvalidTag):
        decrypt_field(bytes(ciphertext), _TEST_KEY)


def test_tde_nonce_corruption_rejected() -> None:
    """Attaque Red Team : Altération du vecteur d'initialisation / nonce (12 premiers octets)."""
    plaintext = "CONFIDENTIAL_OPERATIONAL_DATA"
    ciphertext = bytearray(encrypt_field(plaintext, _TEST_KEY))

    # Alter the first byte of nonce
    ciphertext[0] ^= 0xFF

    with pytest.raises(InvalidTag):
        decrypt_field(bytes(ciphertext), _TEST_KEY)


def test_tde_auth_tag_corruption_rejected() -> None:
    """Attaque Red Team : Corruption d'un octet dans le tag d'authentification GMAC (16 derniers octets)."""
    plaintext = "CONFIDENTIAL_OPERATIONAL_DATA"
    ciphertext = bytearray(encrypt_field(plaintext, _TEST_KEY))

    # Alter the last byte of tag
    ciphertext[-1] ^= 0x55

    with pytest.raises(InvalidTag):
        decrypt_field(bytes(ciphertext), _TEST_KEY)


def test_tde_truncation_attacks() -> None:
    """Attaque Red Team : Troncature du tag ou du ciphertext."""
    plaintext = "CUSTOMER_SECRET_PHONE_+33612345678"
    ciphertext = encrypt_field(plaintext, _TEST_KEY)

    # 1. Truncate completely below minimum length (nonce 12 + tag 16 = 28 octets)
    truncated_short = ciphertext[:20]
    with pytest.raises(ValueError, match="Ciphertext trop court"):
        decrypt_field(truncated_short, _TEST_KEY)

    # 2. Truncate by 1 byte (corrupting authentication tag length)
    truncated_by_one = ciphertext[:-1]
    with pytest.raises(InvalidTag):
        decrypt_field(truncated_by_one, _TEST_KEY)


def test_tde_wrong_key_decryption_rejected() -> None:
    """Attaque Red Team : Tentative de déchiffrement avec une clé non autorisée."""
    plaintext = "CUSTOMER_SECRET_EMAIL_ceo@partner.com"
    ciphertext = encrypt_field(plaintext, _TEST_KEY)

    with pytest.raises(InvalidTag):
        decrypt_field(ciphertext, _WRONG_KEY)


def test_tde_invalid_key_length_rejected() -> None:
    """Attaque Red Team : Utilisation de clés non conformes (non-256 bits)."""
    plaintext = "TEST_DATA"
    invalid_keys = [
        b"",
        secrets.token_bytes(16),  # AES-128 (rejeté car la spec impose AES-256)
        secrets.token_bytes(24),  # AES-192 (rejeté)
        secrets.token_bytes(64),  # 512 bits (rejeté)
    ]
    for key in invalid_keys:
        with pytest.raises(
            ValueError, match="AES-256-GCM requiert une clé de 32 octets"
        ):
            encrypt_field(plaintext, key)

        with pytest.raises(
            ValueError, match="AES-256-GCM requiert une clé de 32 octets"
        ):
            decrypt_field(b"0" * 32, key)


def test_tde_random_garbage_payload_rejected() -> None:
    """Attaque Red Team : Fuzzing / injection de bytes pseudo-aléatoires."""
    garbage = secrets.token_bytes(64)
    with pytest.raises(InvalidTag):
        decrypt_field(garbage, _TEST_KEY)


def test_tde_service_error_handling_and_no_leak() -> None:
    """Vérifie que le service TDE encapsule les erreurs en TDEDecryptionError sans fuite d'info."""
    service = TDEService(key=_TEST_KEY)

    # Valid encrypt
    encrypted = service.encrypt_text("Alice Martin")
    assert isinstance(encrypted, bytes)

    # Tampered payload raises TDEDecryptionError
    tampered = bytearray(encrypted)
    tampered[-2] ^= 0x42
    with pytest.raises(
        TDEDecryptionError, match="Impossible de déchiffrer les données sensibles"
    ):
        service.decrypt_text(bytes(tampered))


def test_tde_service_customer_pii_corrupted_field_rejected() -> None:
    """Vérifie le comportement si un des champs PII client en base a été falsifié."""
    service = TDEService(key=_TEST_KEY)
    pii = service.encrypt_customer_pii(
        contact_name="Directeur Technique",
        email="dt@client-auto.fr",
        phone="+33102030405",
    )

    # Corrompre l'email uniquement
    corrupted_email = bytearray(pii.email_encrypted)
    corrupted_email[14] ^= 0x01

    with pytest.raises(TDEDecryptionError):
        service.decrypt_customer_pii(
            contact_name_encrypted=pii.contact_name_encrypted,
            email_encrypted=bytes(corrupted_email),
            phone_encrypted=pii.phone_encrypted,
        )


def test_tde_empty_plaintext_support() -> None:
    """Vérifie le chiffrement d'une chaîne vide (taille minimale = 28 octets)."""
    ciphertext = encrypt_field("", _TEST_KEY)
    assert len(ciphertext) == 28  # 12 (nonce) + 0 (ciphertext) + 16 (tag)
    decrypted = decrypt_field(ciphertext, _TEST_KEY)
    assert decrypted == ""
