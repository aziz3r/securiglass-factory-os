"""Tests unitaires du service de chiffrement transparent TDE (AES-256-GCM - RGPD)."""

import pytest
from cryptography.exceptions import InvalidTag

from app.core.config import get_settings
from app.services.tde_service import (
    DecryptedCustomerPII,
    EncryptedCustomerPII,
    TDEDecryptionError,
    TDEService,
    get_tde_service,
)


def test_tde_service_encrypt_and_decrypt_nominal() -> None:
    service = get_tde_service()
    contact = "Jean-Pierre Martin"
    email = "jp.martin@securiglass-client.fr"
    phone = "+33 1 42 68 55 00"

    encrypted = service.encrypt_customer_pii(contact, email, phone)
    assert isinstance(encrypted, EncryptedCustomerPII)
    assert encrypted.contact_name_encrypted != contact.encode()
    assert encrypted.email_encrypted != email.encode()
    assert encrypted.phone_encrypted is not None

    decrypted = service.decrypt_customer_pii(
        encrypted.contact_name_encrypted,
        encrypted.email_encrypted,
        encrypted.phone_encrypted,
    )
    assert isinstance(decrypted, DecryptedCustomerPII)
    assert decrypted.contact_name == contact
    assert decrypted.email == email
    assert decrypted.phone == phone


def test_tde_service_handles_optional_phone_none() -> None:
    service = get_tde_service()
    encrypted = service.encrypt_customer_pii("Alice Smith", "alice@example.com", None)
    assert encrypted.phone_encrypted is None

    decrypted = service.decrypt_customer_pii(
        encrypted.contact_name_encrypted,
        encrypted.email_encrypted,
        None,
    )
    assert decrypted.phone is None
    assert decrypted.contact_name == "Alice Smith"
    assert decrypted.email == "alice@example.com"


def test_tde_service_rejects_corrupted_tag() -> None:
    service = get_tde_service()
    encrypted = service.encrypt_text("Sensible Confidential Data")
    # Corruption du dernier octet (tag d'authentification)
    corrupted = bytearray(encrypted)
    corrupted[-1] ^= 0xFF

    with pytest.raises(TDEDecryptionError):
        service.decrypt_text(bytes(corrupted))


def test_tde_service_rejects_invalid_key() -> None:
    key_a = b"\x01" * 32
    key_b = b"\x02" * 32
    svc_a = TDEService(key=key_a)
    svc_b = TDEService(key=key_b)

    cipher = svc_a.encrypt_text("Donnée secrète")
    with pytest.raises(TDEDecryptionError):
        svc_b.decrypt_text(cipher)
