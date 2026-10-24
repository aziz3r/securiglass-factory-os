"""Validateur executable des regles Sigma, YARA, Wazuh et de la pile Compose.

Aucune infrastructure n'est requise : les tests parsent les fichiers, compilent
les regles YARA si `yara-python` est present et convertissent les regles Sigma
avec pySigma. Les tests YARA sont explicitement ignores si la bibliotheque
manque.
"""

from __future__ import annotations

import re
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

SIEM = Path(__file__).resolve().parents[1]
SIGMA_DIR = SIEM / "sigma"
YARA_DIR = SIEM / "yara"
WAZUH = SIEM / "wazuh"
COMPOSE = SIEM / "docker-compose.yml"

SIGMA_REQUIRED = {
    "title",
    "id",
    "status",
    "description",
    "logsource",
    "detection",
    "level",
    "falsepositives",
    "tags",
}
SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}

YARA_FILES = [
    YARA_DIR / "webshell_generic.yar",
    YARA_DIR / "modbus_injection_payload.yar",
    YARA_DIR / "ot_suspicious_binary.yar",
]


# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------
def _sigma_files() -> list[Path]:
    return sorted(SIGMA_DIR.glob("*.yml"))


def test_au_moins_huit_regles_sigma() -> None:
    assert len(_sigma_files()) >= 8


@pytest.mark.parametrize("path", _sigma_files(), ids=lambda p: p.name)
def test_sigma_champs_obligatoires(path: Path) -> None:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict), f"{path.name} n'est pas un mapping YAML"
    missing = SIGMA_REQUIRED - raw.keys()
    assert not missing, f"{path.name} : champs manquants {sorted(missing)}"

    uuid.UUID(str(raw["id"]))  # leve si l'ID n'est pas un UUID valide
    assert raw["status"] in {"stable", "test", "experimental", "deprecated", "unsupported"}
    assert raw["level"] in SIGMA_LEVELS
    assert str(raw["title"]).strip()
    assert str(raw["description"]).strip()
    assert isinstance(raw["tags"], list) and raw["tags"]
    assert isinstance(raw["falsepositives"], list) and raw["falsepositives"]
    assert isinstance(raw["logsource"], dict) and raw["logsource"].get("product")
    assert isinstance(raw["detection"], dict) and "condition" in raw["detection"]


def test_sigma_ids_uniques() -> None:
    ids: list[str] = []
    for path in _sigma_files():
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        ids.append(str(raw["id"]))
    assert len(ids) == len(set(ids)), "IDs Sigma dupliques"


def test_sigma_parse_par_pysigma_et_conversion() -> None:
    sigma_collection = pytest.importorskip("sigma.collection")
    splunk_backend = pytest.importorskip("sigma.backends.splunk")

    from sigma.collection import SigmaCollection

    for path in _sigma_files():
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        assert len(collection.rules) == 1, f"{path.name} doit contenir une seule regle"
        rule = collection.rules[0]
        assert rule.title and rule.level
        queries = splunk_backend.SplunkBackend().convert(collection)
        assert queries and queries[0].strip(), f"{path.name} : conversion vide"


# ---------------------------------------------------------------------------
# YARA
# ---------------------------------------------------------------------------
def _compile_yara(path: Path):
    yara = pytest.importorskip("yara", reason="yara-python absent : test ignore")
    return yara.compile(filepath=str(path))


def test_trois_fichiers_yara_presents() -> None:
    for path in YARA_FILES:
        assert path.is_file(), f"regle YARA manquante : {path.name}"
        text = path.read_text(encoding="utf-8")
        for token in ("rule ", "meta:", "strings:", "condition:"):
            assert token in text, f"{path.name} : section {token} absente"


@pytest.mark.parametrize("path", YARA_FILES, ids=lambda p: p.name)
def test_yara_compile(path: Path) -> None:
    rules = _compile_yara(path)
    assert rules is not None


def test_yara_webshell_detecte() -> None:
    rules = _compile_yara(YARA_DIR / "webshell_generic.yar")
    sample = b"<?php eval($_POST['cmd']); system($_GET['x']); ?>"
    assert rules.match(data=sample)


def test_yara_webshell_ne_detecte_pas_un_php_benin() -> None:
    rules = _compile_yara(YARA_DIR / "webshell_generic.yar")
    assert not rules.match(data=b'<?php echo "hello"; ?>')


def test_yara_modbus_detecte_une_ecriture() -> None:
    rules = _compile_yara(YARA_DIR / "modbus_injection_payload.yar")
    sample = bytes.fromhex("000100000006010600000001")
    assert rules.match(data=sample)


def test_yara_modbus_ne_detecte_pas_une_lecture() -> None:
    rules = _compile_yara(YARA_DIR / "modbus_injection_payload.yar")
    sample = bytes.fromhex("00010000000601030000000a")
    assert not rules.match(data=sample)


def test_yara_binaire_ot_detecte() -> None:
    rules = _compile_yara(YARA_DIR / "ot_suspicious_binary.yar")
    sample = (
        b"\x7fELF"
        + b"SECURIGLASS_PLC_DEBUG"
        + b"modbus_write_single_register"
        + b"quench_pressure_bar"
        + b"10.10.30."
        + b"pymodbus"
    )
    assert rules.match(data=sample)


def test_yara_binaire_benin_non_detecte() -> None:
    rules = _compile_yara(YARA_DIR / "ot_suspicious_binary.yar")
    assert not rules.match(data=b"SECURIGLASS_PLC_DEBUG modbus_write_single_register quench_pressure_bar")


# ---------------------------------------------------------------------------
# Wazuh : XML, IDs, decodeurs
# ---------------------------------------------------------------------------
def _rules_files() -> list[Path]:
    return sorted((WAZUH / "rules").glob("*.xml"))


def test_wazuh_regles_ids_et_descriptions() -> None:
    seen: set[int] = set()
    count = 0
    for path in _rules_files():
        root = ET.parse(path).getroot()
        for rule in root.iter("rule"):
            rule_id = int(rule.get("id", "0"))
            count += 1
            assert 100000 <= rule_id < 120000, f"{path.name} : ID {rule_id} hors plage locale"
            assert rule_id not in seen, f"ID Wazuh duplique : {rule_id}"
            seen.add(rule_id)
            description = (rule.findtext("description") or "").strip()
            assert description, f"{path.name} : regle {rule_id} sans description"
            assert rule.get("level") is not None
    assert count >= 25, f"seulement {count} regles Wazuh locales"


def test_wazuh_decodeurs_groupes_et_ordre() -> None:
    count = 0
    for path in sorted((WAZUH / "decoders").glob("*.xml")):
        root = ET.parse(path).getroot()
        for decoder in root.iter("decoder"):
            count += 1
            name = decoder.get("name")
            assert name, f"{path.name} : decodeur sans nom"
            regex = decoder.findtext("regex")
            order = decoder.findtext("order")
            if regex is None:
                continue
            assert order, f"{name} : <order> obligatoire avec <regex>"
            try:
                compiled = re.compile(regex)
            except re.error as exc:  # pragma: no cover - echec explicite
                pytest.fail(f"{name} : regex invalide ({exc})")
            fields = [field.strip() for field in order.split(",") if field.strip()]
            assert compiled.groups == len(fields), (
                f"{name} : {compiled.groups} groupes de capture pour {len(fields)} champs"
            )
    assert count >= 4, f"seulement {count} decodeurs Wazuh"


def test_ossec_conf_durci() -> None:
    root = ET.parse(WAZUH / "ossec.conf").getroot()

    directories = [
        node.text or "" for node in root.findall(".//syscheck/directories")
    ]
    joined = ",".join(directories)
    for required in ("/etc", "/etc/ssh", "/usr/bin"):
        assert required in joined, f"FIM manquant : {required}"
    assert root.findall(".//syscheck/nodiff")

    localfiles = root.findall(".//localfile")
    assert len(localfiles) >= 3
    json_localfiles = [
        node for node in localfiles if (node.findtext("log_format") or "") == "json"
    ]
    assert len(json_localfiles) >= 2, "audit JSON + Suricata EVE attendus"

    rule_dirs = [node.text for node in root.findall(".//ruleset/rule_dir")]
    assert "etc/rules" in rule_dirs
    decoder_dirs = [node.text for node in root.findall(".//ruleset/decoder_dir")]
    assert "etc/decoders" in decoder_dirs

    allowed = " ".join(
        node.text or "" for node in root.findall(".//remote/allowed-ips")
    )
    assert "10.10.20.0/24" in allowed and "10.10.30.0/24" in allowed

    # Pas d'Active Response automatique sur un procede verrier.
    assert not root.findall(".//active-response")


# ---------------------------------------------------------------------------
# Compose / secrets
# ---------------------------------------------------------------------------
def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_compose_services_limites_et_reseau() -> None:
    data = _compose()
    services = data["services"]
    assert set(services) == {"wazuh.indexer", "wazuh.manager", "wazuh.dashboard"}
    for name, service in services.items():
        assert "mem_limit" in service, f"{name} : mem_limit obligatoire"
        assert "soc_net" in service.get("networks", []), f"{name} : reseau dedie manquant"
    assert data["networks"]["soc_net"]["driver"] == "bridge"
    assert data["networks"]["soc_net"]["ipam"]["config"][0]["subnet"] == "172.28.0.0/24"


def test_compose_aucun_secret_en_clair() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    for forbidden in (
        "SecretPassword",
        "MyS3cr37P450r",
        "SecuriGlass_Admin_2026",
        "0123456789abcdef",
    ):
        assert forbidden not in text, f"secret en clair detecte : {forbidden}"

    services = _compose()["services"]
    indexer_env = services["wazuh.indexer"]["environment"]
    assert "${INDEXER_PASSWORD" in indexer_env["INDEXER_PASSWORD"]
    manager_env = services["wazuh.manager"]["environment"]
    assert "${API_PASSWORD" in manager_env["API_PASSWORD"]


def test_env_example_ne_contient_que_des_placeholders() -> None:
    lines = (SIEM / ".env.example").read_text(encoding="utf-8").splitlines()
    passwords = [line for line in lines if line.startswith(("INDEXER_PASSWORD=", "DASHBOARD_PASSWORD=", "API_PASSWORD="))]
    assert len(passwords) == 3
    assert all("CHANGEME" in line for line in passwords)


def test_gitignore_protege_secrets_et_certs() -> None:
    content = (SIEM / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".env", ".venv/", "wazuh/certs/*.key", "internal_users.yml", "wazuh.yml"):
        assert pattern in content, f".gitignore ne protege pas {pattern}"


def test_scripts_executables() -> None:
    for script in ("bootstrap.sh", "generate-certs.sh"):
        path = SIEM / "scripts" / script
        assert path.is_file()
        assert path.stat().st_mode & 0o111, f"{script} doit etre executable"
