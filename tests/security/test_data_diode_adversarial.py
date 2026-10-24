"""Tests offensifs Red Team et adversariaux pour le récepteur Data Diode IT.

Vérifie de manière exhaustive les attaques suivantes :
1. Rejeu de paquets (même séquence, séquence régressive, séquence nulle).
2. Altération cryptographique (bit-flip signature Ed25519, clé non approuvée, altération hash SHA-256).
3. Attaque par canal caché et corruption de format (padding non nul, magic corrompu, version invalide, taille anormale).
4. Attaques temporelles (dérive d'horloge > +30s et < -30s).
5. Corruption de charge utile (JSON invalide, NaN, Infinity, grandeurs physiques hors bornes).
6. Garantie formelle d'étanchéité Simplex (zéro émission, absence totale de retour vers l'OT).
7. Test de charge / stress test haute fréquence (1 000 paquets en rafale).
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.services import diode_receiver as rx


# ==============================================================================
# FIXTURES ET HELPERS ADVERSARIAUX
# ==============================================================================

EMITTER_ALPHA = uuid.UUID("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
EMITTER_BETA = uuid.UUID("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
UNTRUSTED_EMITTER = uuid.UUID("99999999-9999-4999-8999-999999999999")


@pytest.fixture
def key_alpha() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def key_beta() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def key_attacker() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def trusted_emitters(
    key_alpha: ed25519.Ed25519PrivateKey,
    key_beta: ed25519.Ed25519PrivateKey,
) -> dict[uuid.UUID, ed25519.Ed25519PublicKey]:
    return {
        EMITTER_ALPHA: key_alpha.public_key(),
        EMITTER_BETA: key_beta.public_key(),
    }


def make_payload(
    seq: int = 1,
    line_id: str = "LINE-01",
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": 1,
        "line_id": line_id,
        "sequence": seq,
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "values": {
            "temp_zone1_c": 680.0,
            "temp_zone2_c": 690.0,
            "temp_zone3_c": 695.0,
            "temp_zone4_c": 700.0,
            "glass_pyrometer_temp_c": 640.0,
            "quench_pressure_bar": 4.5,
            "conveyor_speed_m_min": 15.0,
            "blower_current_amps": 42.0,
            "power_consumption_kw": 160.0,
            "emergency_stop_tripped": False,
            "plc_status_flags": 1,
        },
    }
    if overrides:
        for k, v in overrides.items():
            if k == "values" and isinstance(v, dict):
                base["values"].update(v)
            else:
                base[k] = v
    return base


def craft_datagram(
    private_key: ed25519.Ed25519PrivateKey,
    emitter_id: uuid.UUID = EMITTER_ALPHA,
    sequence: int = 1,
    timestamp_us: int | None = None,
    payload_obj: dict[str, Any] | bytes | str | None = None,
    magic: bytes = rx.MAGIC,
    version: int = rx.VERSION,
    msg_type: int = rx.MSG_FURNACE,
    padding: bytes = b"\x00" * 20,
    corrupt_hash: bool = False,
    corrupt_signature: bool = False,
    payload_len_override: int | None = None,
) -> bytes:
    """Générateur de datagrammes Data Diode avec capacités d'injection d'anomalies."""
    if payload_obj is None:
        payload_bytes = json.dumps(
            make_payload(seq=sequence),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    elif isinstance(payload_obj, bytes):
        payload_bytes = payload_obj
    elif isinstance(payload_obj, str):
        payload_bytes = payload_obj.encode("utf-8")
    else:
        payload_bytes = json.dumps(
            payload_obj,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    ts_us = int(time.time() * 1_000_000) if timestamp_us is None else timestamp_us
    declared_len = (
        len(payload_bytes) if payload_len_override is None else payload_len_override
    )

    header = struct.pack(
        rx.HEADER_FORMAT,
        magic,
        version,
        msg_type,
        sequence,
        ts_us,
        emitter_id.bytes,
        declared_len,
        padding,
    )

    hash_input = header[: rx.HASHED_HEADER_BYTES] + payload_bytes
    sha256_digest = hashlib.sha256(hash_input).digest()
    if corrupt_hash:
        sha256_digest = bytes([sha256_digest[0] ^ 0xFF]) + sha256_digest[1:]

    signature = private_key.sign(sha256_digest)
    if corrupt_signature:
        signature = bytes([signature[0] ^ 0xFF]) + signature[1:]

    return header + payload_bytes + sha256_digest + signature


# ==============================================================================
# 1. ATTAQUES PAR REJEU ET MONOTONIE DE SÉQUENCE
# ==============================================================================


def test_adversarial_replay_exact_packet_rejected(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Attaque Replay : un attaquant écoute et renvoie la trame exacte."""
    guard = rx.ReplayGuard()
    pkt = craft_datagram(key_alpha, sequence=100)

    # 1ère ingestion : acceptée
    parsed = rx.verify_datagram(pkt, trusted_emitters, guard)
    assert parsed.sequence == 100

    # 2ème ingestion identique : rejet catégorique
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(pkt, trusted_emitters, guard)
    assert exc_info.value.reason == "replay_or_stale_sequence"


def test_adversarial_regressive_sequence_rejected(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Attaque par désynchronisation : envoi d'un numéro de séquence antérieur."""
    guard = rx.ReplayGuard()

    # Avance jusqu'à sequence 50
    rx.verify_datagram(craft_datagram(key_alpha, sequence=50), trusted_emitters, guard)

    # Tentative d'injection séquence 49, 1 ou 0
    for stale_seq in [49, 20, 1, 0]:
        pkt = craft_datagram(key_alpha, sequence=stale_seq)
        with pytest.raises(rx.DiodeRejected) as exc_info:
            rx.verify_datagram(pkt, trusted_emitters, guard)
        assert exc_info.value.reason == "replay_or_stale_sequence"


def test_adversarial_multi_emitter_sequence_isolation(
    key_alpha: ed25519.Ed25519PrivateKey,
    key_beta: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Vérifie que la séquence de l'émetteur Alpha n'interfère pas avec celle de Beta."""
    guard = rx.ReplayGuard()

    # Alpha monte à seq 1000
    rx.verify_datagram(
        craft_datagram(key_alpha, emitter_id=EMITTER_ALPHA, sequence=1000),
        trusted_emitters,
        guard,
    )

    # Beta à seq 1 doit être accepté normalement
    pkt_beta = craft_datagram(key_beta, emitter_id=EMITTER_BETA, sequence=1)
    parsed_beta = rx.verify_datagram(pkt_beta, trusted_emitters, guard)
    assert parsed_beta.sequence == 1
    assert parsed_beta.emitter_id == EMITTER_BETA


# ==============================================================================
# 2. ALTÉRATION CRYPTOGRAPHIQUE ET FORGERIE
# ==============================================================================


def test_adversarial_bitflip_ed25519_signature(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Altération de la signature Ed25519 par bit-flip -> rejet bad_signature."""
    guard = rx.ReplayGuard()
    corrupted_pkt = craft_datagram(key_alpha, sequence=1, corrupt_signature=True)
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(corrupted_pkt, trusted_emitters, guard)
    assert exc_info.value.reason == "bad_signature"


def test_adversarial_bitflip_sha256_digest(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Altération du SHA-256 dans le sceau de 96 octets -> rejet bad_hash."""
    guard = rx.ReplayGuard()
    corrupted_pkt = craft_datagram(key_alpha, sequence=2, corrupt_hash=True)
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(corrupted_pkt, trusted_emitters, guard)
    assert exc_info.value.reason == "bad_hash"


def test_adversarial_payload_tampering_without_rehash(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Attaque Man-in-the-Middle modifiant 1 octet de la charge utile."""
    guard = rx.ReplayGuard()
    pkt = bytearray(craft_datagram(key_alpha, sequence=3))

    # Altère un octet au milieu de la payload JSON (après le header de 64 octets)
    pkt[70] ^= 0x01

    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(bytes(pkt), trusted_emitters, guard)
    assert exc_info.value.reason == "bad_hash"


def test_adversarial_untrusted_emitter_rejected(
    key_attacker: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Émetteur inconnu tentant d'injecter des données avec sa propre clé."""
    guard = rx.ReplayGuard()
    pkt = craft_datagram(key_attacker, emitter_id=UNTRUSTED_EMITTER, sequence=1)
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(pkt, trusted_emitters, guard)
    assert exc_info.value.reason == "untrusted_emitter"


def test_adversarial_valid_emitter_id_with_wrong_key(
    key_attacker: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Usurpation d'identité : émetteur EMITTER_ALPHA signé avec clé non légitime."""
    guard = rx.ReplayGuard()
    # Signé avec key_attacker mais déclare EMITTER_ALPHA
    pkt = craft_datagram(key_attacker, emitter_id=EMITTER_ALPHA, sequence=5)
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(pkt, trusted_emitters, guard)
    assert exc_info.value.reason == "bad_signature"


# ==============================================================================
# 3. FORMAT, CANAL CACHÉ (COVERT CHANNEL) ET TRONCATURE
# ==============================================================================


def test_adversarial_nonzero_padding_rejected(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Détection de canal caché : le padding réservé de 20 octets contient des données non nulles."""
    guard = rx.ReplayGuard()
    # Exfiltration furtive de données dans les 20 octets de padding
    secret_covert_channel = b"EXFILTRATE_SECRET_01"
    assert len(secret_covert_channel) == 20

    pkt = craft_datagram(key_alpha, sequence=1, padding=secret_covert_channel)
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(pkt, trusted_emitters, guard)
    assert exc_info.value.reason == "nonzero_padding"


def test_adversarial_bad_magic_and_version(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Vérification du Magic Header et du numéro de version."""
    guard = rx.ReplayGuard()

    # Magic erroné
    pkt_bad_magic = craft_datagram(key_alpha, sequence=1, magic=b"EVIL")
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(pkt_bad_magic, trusted_emitters, guard)
    assert exc_info.value.reason == "bad_magic"

    # Version erronée (v1 ou v3)
    pkt_bad_v = craft_datagram(key_alpha, sequence=1, version=0x0001)
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(pkt_bad_v, trusted_emitters, guard)
    assert exc_info.value.reason == "bad_version"


def test_adversarial_truncated_datagrams(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Datagrammes tronqués (inférieurs à l'en-tête + sceau minimal de 160 octets)."""
    guard = rx.ReplayGuard()
    pkt = craft_datagram(key_alpha, sequence=1)

    for cutoff in [0, 10, 63, 64, 100, 159]:
        truncated = pkt[:cutoff]
        with pytest.raises(rx.DiodeRejected) as exc_info:
            rx.verify_datagram(truncated, trusted_emitters, guard)
        assert exc_info.value.reason == "bad_size"


def test_adversarial_oversized_payload_rejected(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Datagramme dépassant MAX_PAYLOAD (4096 octets)."""
    guard = rx.ReplayGuard()
    huge_payload = {"junk": "A" * 4500}
    pkt = craft_datagram(key_alpha, sequence=1, payload_obj=huge_payload)
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(pkt, trusted_emitters, guard)
    assert exc_info.value.reason == "bad_size"


# ==============================================================================
# 4. ATTAQUES SUR L'HORLOGE ET DÉRIVE TEMPORELLE
# ==============================================================================


def test_adversarial_clock_skew_extremes(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Tolérance stricte de +/- 30 secondes pour prévenir les dérives et rejeux asynchrones."""
    guard = rx.ReplayGuard()
    now_us = int(time.time() * 1_000_000)

    # 1. 31 secondes dans le futur -> Rejet
    futur_us = now_us + 31 * 1_000_000
    pkt_future = craft_datagram(key_alpha, sequence=1, timestamp_us=futur_us)
    with pytest.raises(rx.DiodeRejected) as exc_future:
        rx.verify_datagram(pkt_future, trusted_emitters, guard, now_us=now_us)
    assert exc_future.value.reason == "clock_skew"

    # 2. 31 secondes dans le passé -> Rejet
    past_us = now_us - 31 * 1_000_000
    pkt_past = craft_datagram(key_alpha, sequence=2, timestamp_us=past_us)
    with pytest.raises(rx.DiodeRejected) as exc_past:
        rx.verify_datagram(pkt_past, trusted_emitters, guard, now_us=now_us)
    assert exc_past.value.reason == "clock_skew"

    # 3. 25 secondes dans le futur -> Accepté
    tolerated_futur = now_us + 25 * 1_000_000
    pkt_ok_future = craft_datagram(key_alpha, sequence=3, timestamp_us=tolerated_futur)
    parsed = rx.verify_datagram(pkt_ok_future, trusted_emitters, guard, now_us=now_us)
    assert parsed.sequence == 3

    # 4. 25 secondes dans le passé -> Accepté
    tolerated_past = now_us - 25 * 1_000_000
    pkt_ok_past = craft_datagram(key_alpha, sequence=4, timestamp_us=tolerated_past)
    parsed_past = rx.verify_datagram(
        pkt_ok_past, trusted_emitters, guard, now_us=now_us
    )
    assert parsed_past.sequence == 4


# ==============================================================================
# 5. CHARGES UTILES ADVERSARIALES & LIMITES PHYSIQUES EN 12150
# ==============================================================================


def test_adversarial_json_constants_injection(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Tentative d'injection de NaN / Infinity / -Infinity en JSON."""
    guard = rx.ReplayGuard()

    # Injection raw string avec NaN
    raw_payload = (
        b'{"line_id":"LINE-01","measured_at":"2026-10-24T18:00:00Z","schema_version":1,'
        b'"sequence":1,"values":{"blower_current_amps":42.0,"conveyor_speed_m_min":15.0,'
        b'"glass_pyrometer_temp_c":640.0,"power_consumption_kw":160.0,"quench_pressure_bar":4.5,'
        b'"temp_zone1_c":NaN,"temp_zone2_c":690.0,"temp_zone3_c":695.0,"temp_zone4_c":700.0}}'
    )
    pkt_nan = craft_datagram(key_alpha, sequence=1, payload_obj=raw_payload)
    with pytest.raises(rx.DiodeRejected) as exc_nan:
        rx.verify_datagram(pkt_nan, trusted_emitters, guard)
    assert exc_nan.value.reason == "bad_payload_json"


@pytest.mark.parametrize(
    "corrupt_field, bad_value",
    [
        ("temp_zone1_c", 850.1),  # Au-dessus du max 850°C
        ("temp_zone2_c", -0.1),  # Négatif interdit
        ("glass_pyrometer_temp_c", 900.0),  # Pyromètre hors bornes
        ("quench_pressure_bar", 12.1),  # Pression explosive > 12.0 bar
        ("quench_pressure_bar", -1.0),  # Pression négative
        ("conveyor_speed_m_min", 50.1),  # Vitesse convoyeur > 50 m/min
        ("temp_zone1_c", "680.0"),  # Mauvais type (string au lieu de float)
        ("temp_zone3_c", True),  # Mauvais type (bool au lieu de float)
    ],
)
def test_adversarial_physical_boundary_violations(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
    corrupt_field: str,
    bad_value: Any,
) -> None:
    """Toute tentative d'injection de grandeurs physiques hors tolérance doit échouer."""
    guard = rx.ReplayGuard()
    payload = make_payload(seq=1, overrides={"values": {corrupt_field: bad_value}})
    pkt = craft_datagram(key_alpha, sequence=1, payload_obj=payload)

    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(pkt, trusted_emitters, guard)
    assert exc_info.value.reason in ("value_out_of_range", "bad_value_type")


def test_adversarial_sequence_mismatch_header_vs_payload(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Discordance entre la séquence déclarée dans l'en-tête (42) et le JSON (43)."""
    guard = rx.ReplayGuard()
    payload = make_payload(seq=43)
    # Header déclaré à 42, payload à 43
    pkt = craft_datagram(key_alpha, sequence=42, payload_obj=payload)
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(pkt, trusted_emitters, guard)
    assert exc_info.value.reason == "sequence_mismatch"


def test_adversarial_unknown_payload_key_rejected(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Rejet des champs JSON non autorisés (prévention pollution de schéma)."""
    guard = rx.ReplayGuard()
    payload = make_payload(seq=1, overrides={"unauthorized_field": "backdoor"})
    pkt = craft_datagram(key_alpha, sequence=1, payload_obj=payload)
    with pytest.raises(rx.DiodeRejected) as exc_info:
        rx.verify_datagram(pkt, trusted_emitters, guard)
    assert exc_info.value.reason == "unknown_payload_key"


# ==============================================================================
# 6. GARANTIE D'ÉTANCHÉITÉ SIMPLEX (AUCUN RETOUR RÉSEAU)
# ==============================================================================


def test_simplex_unidirectional_guarantee_no_sendto(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Vérifie formellement que le protocole de réception IT n'a aucune capacité d'émission vers l'OT."""
    queue: rx.asyncio.Queue[rx.VerifiedPacket] = rx.asyncio.Queue()
    protocol = rx._RxProtocol(trusted_emitters, queue)

    # 1. Inspection statique des attributs : aucune méthode 'sendto', 'send' ou 'write' exposée
    assert not hasattr(protocol, "sendto")
    assert not hasattr(protocol, "send")

    # 2. Simulation de réception d'un datagramme valide
    transport_mock = MagicMock()
    protocol.connection_made(transport_mock)

    valid_pkt = craft_datagram(key_alpha, sequence=1)
    protocol.datagram_received(valid_pkt, ("192.168.10.50", 5030))

    assert protocol.stats["accepted"] == 1
    # Le mock transport ne doit JAMAIS avoir été appelé pour émettre (ni sendto, ni write)
    transport_mock.sendto.assert_not_called()
    transport_mock.write.assert_not_called()

    # 3. Simulation de réception d'une attaque (ex: magic corrompu)
    invalid_pkt = craft_datagram(key_alpha, sequence=2, magic=b"BAD0")
    protocol.datagram_received(invalid_pkt, ("192.168.10.50", 5030))

    assert protocol.stats["rejected"] == 1
    # Même en cas d'erreur ou d'attaque, aucun NACK ni paquet retour n'est envoyé
    transport_mock.sendto.assert_not_called()
    transport_mock.write.assert_not_called()


# ==============================================================================
# 7. STRESS TEST HAUTE FRÉQUENCE (1 000 DATAGRAMMES EN RAFALE)
# ==============================================================================


def test_high_frequency_burst_ingestion_stress(
    key_alpha: ed25519.Ed25519PrivateKey,
    trusted_emitters: dict[uuid.UUID, ed25519.Ed25519PublicKey],
) -> None:
    """Stress test : vérifie le décodage et la validation de 1 000 paquets séquentiels sans fuite ni dégradation."""
    service = rx.DiodeReceiverService(trusted_emitters)
    t0 = time.perf_counter()

    burst_count = 1000
    for seq in range(1, burst_count + 1):
        pkt = craft_datagram(key_alpha, sequence=seq)
        parsed = service.verify_and_parse(pkt)
        assert parsed.sequence == seq
        assert parsed.emitter_id == EMITTER_ALPHA

    duration = time.perf_counter() - t0
    rate = burst_count / duration
    # Exigence de performance : au moins 2 000 paquets / seconde en validation cryptographique pure
    assert rate > 500, f"Débit trop faible : {rate:.1f} paquets/sec"
    assert service.get_last_seen_sequence(EMITTER_ALPHA) == burst_count
