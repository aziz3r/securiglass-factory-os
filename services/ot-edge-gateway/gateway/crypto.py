"""Module cryptographique Ed25519 (RFC 8032) pour SecuriGlass Data Diode.

Fournit la génération de clés, le chargement, la signature et la vérification
de sceaux d'intégrité cryptographique pour le flux simplex unidirectionnel.
"""

from __future__ import annotations

from typing import Final
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

SIGNATURE_SIZE_BYTES: Final[int] = 64
PUBLIC_KEY_SIZE_BYTES: Final[int] = 32
PRIVATE_KEY_SIZE_BYTES: Final[int] = 32
SHA256_DIGEST_SIZE_BYTES: Final[int] = 32


def generate_ed25519_keypair() -> (
    tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]
):
    """Génère une nouvelle paire de clés Ed25519."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def private_key_to_raw_bytes(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Exporte la clé privée en 32 octets bruts (Raw)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_raw_bytes(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Exporte la clé publique en 32 octets bruts (Raw)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_private_key_from_raw_bytes(raw_bytes: bytes) -> ed25519.Ed25519PrivateKey:
    """Charge une clé privée Ed25519 depuis 32 octets bruts."""
    if len(raw_bytes) != PRIVATE_KEY_SIZE_BYTES:
        raise ValueError(
            f"Clé privée Ed25519 invalide : attendu {PRIVATE_KEY_SIZE_BYTES} octets, reçu {len(raw_bytes)}"
        )
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)


def load_public_key_from_raw_bytes(raw_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Charge une clé publique Ed25519 depuis 32 octets bruts."""
    if len(raw_bytes) != PUBLIC_KEY_SIZE_BYTES:
        raise ValueError(
            f"Clé publique Ed25519 invalide : attendu {PUBLIC_KEY_SIZE_BYTES} octets, reçu {len(raw_bytes)}"
        )
    return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)


def sign_data(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Signe des données avec Ed25519 (RFC 8032). Retourne 64 octets."""
    return private_key.sign(data)


def verify_signature(
    public_key: ed25519.Ed25519PublicKey, data: bytes, signature: bytes
) -> bool:
    """Vérifie la signature Ed25519 sur les données. Retourne True si valide, False sinon."""
    if len(signature) != SIGNATURE_SIZE_BYTES:
        return False
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False
