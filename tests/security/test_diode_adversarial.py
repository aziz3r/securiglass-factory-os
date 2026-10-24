"""Tests de Sécurité Offensifs & Red Team - Data Diode Simplex Unidirectionnelle.

Référentiels : IEC 62443-3-3, NIST SP 800-82, docs/architecture/DATA_DIODE_SPEC.md.

Scénarios d'attaque :
1. Troncature et altération d'en-tête (Magic bytes, versions, longueurs).
2. Attaques par dérive temporelle (Clock skew injection dans le futur et le passé).
3. Attaques par bit-flipping sur le payload et le hash SHA-256 scellé.
4. Contrefaçon de signature Ed25519 et utilisation d'une clé privée pirate (Rogue Key).
5. Émetteur non enregistré (Untrusted Emitter UUID).
6. Attaques par rejeu de trames (Replay Attacks : séquence antérieure ou égale).
7. Canal caché dans le padding de l'en-tête (Covert channel prevention).
8. Vérification stricte de l'absence de canal retour (Zéro Retour / Simplex Enforcement).
"""

from __future__ import annotations

import hashlib
import json
import struct
import time
import uuid
from typing import Any, Final

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.services.diode_receiver import (
    HEADER_SIZE,
    MAGIC,
    MAX_DATAGRAM,
    MAX_PAYLOAD,
    SEAL_SIZE,
    VERSION,
    DiodeReceiverService,
    DiodeRejected,
    ReplayGuard,
    VerifiedPacket,
    verify_datagram,
)

pytestmark = pytest.mark.unit


# Fixtures de test cryptographiques
@pytest.fixture
def emitter_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture
def rogue_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture
def emitter_uuid() -> uuid.UUID:
    return uuid.uuid4()


def make_valid_payload(seq: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "line_id": "LINE_TEMPER_01",
        "sequence": seq,
        "measured_at": "2026-10-24T18:00:00+00:00",
        "batch_id": None,
        "values": {
            "temp_zone1_c": 680.5,
            "temp_zone2_c": 685.0,
            "temp_zone3_c": 690.0,
            "temp_zone4_c": 675.0,
            "glass_pyrometer_temp_c": 670.0,
            "quench_pressure_bar": 3.5,
            "conveyor_speed_m_min": 4.5,
            "blower_current_amps": 45.0,
            "power_consumption_kw": 120.0,
            "emergency_stop_tripped": False,
            "plc_status_flags": 1,
        },
    }


def build_raw_packet(
    priv_key: ed25519.Ed25519PrivateKey,
    emitter_id: uuid.UUID,
    seq: int,
    payload_dict: dict[str, Any] | None = None,
    timestamp_us: int | None = None,
    magic: bytes = MAGIC,
    version: int = VERSION,
    msg_type: int = 1,
    corrupt_sha: bool = False,
    corrupt_sig: bool = False,
    padding: bytes = b"\x00" * 20,
) -> bytes:
    """Générateur de paquets binaires bruts conforme à DATA_DIODE_SPEC.md."""
    if timestamp_us is None:
        timestamp_us = int(time.time() * 1_000_000)

    if payload_dict is None:
        payload_dict = make_valid_payload(seq)

    payload_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
    payload_len = len(payload_bytes)

    # Construction de l'en-tête (64 octets)
    hdr = struct.pack(
        "!4sHHQQ16sI20s",
        magic,
        version,
        msg_type,
        seq,
        timestamp_us,
        emitter_id.bytes,
        payload_len,
        padding,
    )

    # Calcul du hash scellé : SHA256(Header[:44] + Payload)
    content_to_hash = hdr[:44] + payload_bytes
    sha_hash = hashlib.sha256(content_to_hash).digest()
    if corrupt_sha:
        sha_hash = bytes([b ^ 0xFF for b in sha_hash])

    # Signature Ed25519 sur le hash SHA-256
    sig = priv_key.sign(sha_hash)
    if corrupt_sig:
        sig = bytes([b ^ 0xAA for b in sig])

    seal = sha_hash + sig
    return hdr + payload_bytes + seal


# ==============================================================================
# TESTS RED TEAM : FORMAT, EN-TÊTE & TRONCATURE
# ==============================================================================


def test_redteam_truncated_datagram(emitter_keypair, emitter_uuid):
    """Une trame plus courte que le seuil minimal (Header 64 + Seal 96 = 160) est rejetée net."""
    priv, pub = emitter_keypair
    keys = {emitter_uuid: pub}
    guard = ReplayGuard()

    raw = build_raw_packet(priv, emitter_uuid, 1)
    truncated = raw[:120]  # Moins de 160 octets

    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(truncated, trusted=keys, guard=guard)
    assert exc.value.reason == "bad_size"


def test_redteam_oversized_datagram(emitter_keypair, emitter_uuid):
    """Une trame excédant la taille maximale autorisée est immédiatement éliminée."""
    guard = ReplayGuard()
    huge = b"A" * (MAX_DATAGRAM + 1)
    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(huge, trusted={}, guard=guard)
    assert exc.value.reason == "bad_size"


def test_redteam_invalid_magic_bytes(emitter_keypair, emitter_uuid):
    """Injection d'un mauvais magic byte (tentative d'injection protocolaire étrangère)."""
    priv, pub = emitter_keypair
    keys = {emitter_uuid: pub}
    guard = ReplayGuard()

    corrupt = build_raw_packet(priv, emitter_uuid, 1, magic=b"HACK")
    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(corrupt, trusted=keys, guard=guard)
    assert exc.value.reason == "bad_magic"


def test_redteam_unsupported_protocol_version(emitter_keypair, emitter_uuid):
    """Tentative de rétrogradation de protocole (Downgrade attack v1.0)."""
    priv, pub = emitter_keypair
    keys = {emitter_uuid: pub}
    guard = ReplayGuard()

    corrupt = build_raw_packet(priv, emitter_uuid, 1, version=0x0001)
    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(corrupt, trusted=keys, guard=guard)
    assert exc.value.reason == "bad_version"


def test_redteam_unknown_message_type(emitter_keypair, emitter_uuid):
    """Tentative d'envoi d'un type de message inconnu ou réservé."""
    priv, pub = emitter_keypair
    keys = {emitter_uuid: pub}
    guard = ReplayGuard()

    corrupt = build_raw_packet(priv, emitter_uuid, 1, msg_type=0x9999)
    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(corrupt, trusted=keys, guard=guard)
    assert exc.value.reason == "unsupported_message_type"


def test_redteam_covert_channel_padding(emitter_keypair, emitter_uuid):
    """Détection de canal caché (stéganographie) dans les 20 octets de padding."""
    priv, pub = emitter_keypair
    keys = {emitter_uuid: pub}
    guard = ReplayGuard()

    covert_padding = b"COVERT_CHANNEL_EXFIL"[:20]
    packet = build_raw_packet(priv, emitter_uuid, 1, padding=covert_padding)
    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(packet, trusted=keys, guard=guard)
    assert exc.value.reason == "nonzero_padding"


# ==============================================================================
# TESTS RED TEAM : DÉRIVE TEMPORELLE (CLOCK SKEW) & ANTI-DISSIMULATION
# ==============================================================================


def test_redteam_clock_skew_future_injection(emitter_keypair, emitter_uuid):
    """Tentative d'injection d'un datagramme daté dans le futur (> 30s) pour manipuler les séries temporelles."""
    priv, pub = emitter_keypair
    keys = {emitter_uuid: pub}
    guard = ReplayGuard()

    future_us = int((time.time() + 60) * 1_000_000)  # +60 secondes
    packet = build_raw_packet(priv, emitter_uuid, 1, timestamp_us=future_us)

    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(packet, trusted=keys, guard=guard)
    assert exc.value.reason == "clock_skew"


def test_redteam_clock_skew_past_rejection(emitter_keypair, emitter_uuid):
    """Tentative d'injection d'un datagramme antidaté (> 30s dans le passé)."""
    priv, pub = emitter_keypair
    keys = {emitter_uuid: pub}
    guard = ReplayGuard()

    past_us = int((time.time() - 45) * 1_000_000)  # -45 secondes
    packet = build_raw_packet(priv, emitter_uuid, 1, timestamp_us=past_us)

    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(packet, trusted=keys, guard=guard)
    assert exc.value.reason == "clock_skew"


# ==============================================================================
# TESTS RED TEAM : CRYPTOGRAPHIE, INTÉGRITÉ & REJET DE CLÉ PIRATE
# ==============================================================================


def test_redteam_sha256_hash_tampering(emitter_keypair, emitter_uuid):
    """Détection immédiate si le hash SHA-256 ne correspond pas au contenu."""
    priv, pub = emitter_keypair
    keys = {emitter_uuid: pub}
    guard = ReplayGuard()

    corrupt = build_raw_packet(priv, emitter_uuid, 1, corrupt_sha=True)
    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(corrupt, trusted=keys, guard=guard)
    assert exc.value.reason == "bad_hash"


def test_redteam_ed25519_signature_corruption(emitter_keypair, emitter_uuid):
    """Altération de la signature Ed25519 -> Rejet systématique."""
    priv, pub = emitter_keypair
    keys = {emitter_uuid: pub}
    guard = ReplayGuard()

    corrupt = build_raw_packet(priv, emitter_uuid, 1, corrupt_sig=True)
    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(corrupt, trusted=keys, guard=guard)
    assert exc.value.reason == "bad_signature"


def test_redteam_rogue_private_key_rejection(
    emitter_keypair, rogue_keypair, emitter_uuid
):
    """Tentative d'émission avec une clé privée Ed25519 pirate non certifiée dans le récepteur."""
    _priv_auth, pub_auth = emitter_keypair
    priv_rogue, _pub_rogue = rogue_keypair

    # Le récepteur ne fait confiance qu'à pub_auth
    keys = {emitter_uuid: pub_auth}
    guard = ReplayGuard()

    # L'attaquant signe avec priv_rogue en prétendant être emitter_uuid
    rogue_packet = build_raw_packet(priv_rogue, emitter_uuid, 1)

    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(rogue_packet, trusted=keys, guard=guard)
    assert exc.value.reason == "bad_signature"


def test_redteam_untrusted_emitter_uuid(emitter_keypair):
    """Un émetteur dont l'UUID n'est pas dans le keystore de confiance est rejeté sans calcul lourd."""
    priv, _pub = emitter_keypair
    unknown_uuid = uuid.uuid4()
    guard = ReplayGuard()

    packet = build_raw_packet(priv, unknown_uuid, 1)

    with pytest.raises(DiodeRejected) as exc:
        verify_datagram(packet, trusted={}, guard=guard)
    assert exc.value.reason == "untrusted_emitter"


# ==============================================================================
# TESTS RED TEAM : ATTAQUES PAR REJEU (REPLAY ATTACKS)
# ==============================================================================


def test_redteam_monotonic_sequence_replay_rejection(emitter_keypair, emitter_uuid):
    """Rejet strict de tout paquet dont la séquence est inférieure ou égale à la dernière vue."""
    priv, pub = emitter_keypair
    keys = {emitter_uuid: pub}
    guard = ReplayGuard()

    # Paquet nominal séquence 100
    pkt1 = build_raw_packet(priv, emitter_uuid, 100)
    verified = verify_datagram(pkt1, trusted=keys, guard=guard)
    assert verified.sequence == 100
    guard.commit(emitter_uuid, 100)

    # Attaque Rejeu 1 : Rejouer le paquet 100
    with pytest.raises(DiodeRejected) as exc1:
        verify_datagram(pkt1, trusted=keys, guard=guard)
    assert exc1.value.reason == "replay_or_stale_sequence"

    # Attaque Rejeu 2 : Injecter un paquet antérieur (séquence 99)
    pkt_stale = build_raw_packet(priv, emitter_uuid, 99)
    with pytest.raises(DiodeRejected) as exc2:
        verify_datagram(pkt_stale, trusted=keys, guard=guard)
    assert exc2.value.reason == "replay_or_stale_sequence"

    # Séquence 101 acceptée
    pkt2 = build_raw_packet(priv, emitter_uuid, 101)
    verified2 = verify_datagram(pkt2, trusted=keys, guard=guard)
    assert verified2.sequence == 101


# ==============================================================================
# TESTS RED TEAM : ZÉRO RETOUR / SIMPLEX ENFORCEMENT
# ==============================================================================


def test_redteam_zero_backchannel_guarantee():
    """Vérifie formellement par introspection que le récepteur diode n'expose aucune fonction d'émission vers l'OT."""
    svc = DiodeReceiverService(trusted={})
    forbidden_methods = ["send", "sendto", "emit", "write", "respond", "ack"]
    for method in forbidden_methods:
        assert not hasattr(
            svc, method
        ), f"Violation de la Diode : {method} trouvé sur le récepteur !"
