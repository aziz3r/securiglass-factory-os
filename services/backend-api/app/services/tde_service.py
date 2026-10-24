"""Service de Chiffrement Transparent des Données (TDE applicatif - RGPD Art. 32).

Assure le chiffrement symétrique AES-256-GCM au repos et le déchiffrement transparent
à la lecture des colonnes contenant des données à caractère personnel (PII) :
- `contact_name`
- `email`
- `phone`
"""

import logging
from typing import NamedTuple

from app.core.config import get_settings
from app.core.security import decrypt_field, encrypt_field

logger = logging.getLogger("securiglass.tde")


class DecryptedCustomerPII(NamedTuple):
    contact_name: str
    email: str
    phone: str | None


class EncryptedCustomerPII(NamedTuple):
    contact_name_encrypted: bytes
    email_encrypted: bytes
    phone_encrypted: bytes | None


class TDEDecryptionError(Exception):
    """Exception levée en cas d'échec du déchiffrement ou de corruption du tag GCM."""

    pass


class TDEService:
    """Service d'orchestration TDE pour les données sensibles de l'usine."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or get_settings().tde_key_bytes

    def encrypt_text(self, plaintext: str) -> bytes:
        """Chiffre une valeur textuelle en AES-256-GCM."""
        return encrypt_field(plaintext, self._key)

    def decrypt_text(self, ciphertext: bytes) -> str:
        """Déchiffre une valeur AES-256-GCM avec contrôle d'intégrité."""
        try:
            return decrypt_field(ciphertext, self._key)
        except Exception as exc:
            logger.error(
                "Échec du déchiffrement TDE (tag corrompu ou clé invalide) : %s", exc
            )
            raise TDEDecryptionError(
                "Impossible de déchiffrer les données sensibles"
            ) from exc

    def encrypt_customer_pii(
        self,
        contact_name: str,
        email: str,
        phone: str | None = None,
    ) -> EncryptedCustomerPII:
        """Chiffre l'ensemble des champs sensibles d'un client avant persistance SQL."""
        contact_enc = self.encrypt_text(contact_name)
        email_enc = self.encrypt_text(email)
        phone_enc = self.encrypt_text(phone) if phone else None

        return EncryptedCustomerPII(
            contact_name_encrypted=contact_enc,
            email_encrypted=email_enc,
            phone_encrypted=phone_enc,
        )

    def decrypt_customer_pii(
        self,
        contact_name_encrypted: bytes,
        email_encrypted: bytes,
        phone_encrypted: bytes | None = None,
    ) -> DecryptedCustomerPII:
        """Déchiffre les données d'un client pour présentation à un utilisateur habilité."""
        contact_name = self.decrypt_text(contact_name_encrypted)
        email = self.decrypt_text(email_encrypted)
        phone = (
            self.decrypt_text(phone_encrypted) if phone_encrypted is not None else None
        )

        return DecryptedCustomerPII(
            contact_name=contact_name,
            email=email,
            phone=phone,
        )


# Instance singleton par défaut pour les routes FastAPI
_default_tde_service: TDEService | None = None


def get_tde_service() -> TDEService:
    """Fournisseur de dépendance pour le service TDE."""
    global _default_tde_service
    if _default_tde_service is None:
        _default_tde_service = TDEService()
    return _default_tde_service
