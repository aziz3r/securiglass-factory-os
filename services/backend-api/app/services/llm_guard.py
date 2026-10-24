"""Sandbox de Sécurité LLM Guard & RAG Sécurisé (EN 12150 / OWASP Top 10 LLM 2025).

Architecture en 4 barrières de sûreté hermétiques :
1. Pre-Input Scanner : Détection des injections de prompt, mots-clés d'évasion et sanitisation PII.
2. Retrieval Cloisonné : Base de connaissances technique locale normée EN 12150.
3. Générateur Déterministe : Moteur de synthèse contraint au contexte normatif.
4. Post-Output Guard : Contrôle strict des grandeurs physiques (températures, pressions) et anti-fuite.
"""

from __future__ import annotations

import base64
import html
import logging
import math
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final

logger = logging.getLogger("securiglass.llm.guard")

# Bornes physiques impératives de sûreté thermique (EN 12150)
TEMP_FURNACE_MIN_C: Final[float] = 620.0
TEMP_FURNACE_MAX_C: Final[float] = 730.0
PRESSURE_QUENCH_MIN_BAR: Final[float] = 1.5
PRESSURE_QUENCH_MAX_BAR: Final[float] = 6.5


class LLMGuardError(Exception):
    """Exception de base de la sandbox LLM Guard."""


class PromptInjectionDetected(LLMGuardError):
    """Tentative d'injection de prompt ou d'évasion système interceptée."""

    def __init__(self, reason: str, detected_pattern: str) -> None:
        super().__init__(
            f"Tentative d'injection détectée ({reason}): '{detected_pattern}'"
        )
        self.reason = reason
        self.detected_pattern = detected_pattern


class UnsafeOutputBlocked(LLMGuardError):
    """Sortie LLM bloquée car violant les bornes de sécurité physique industrielle."""

    def __init__(
        self, reason: str, invalid_value: float, safe_range: tuple[float, float]
    ) -> None:
        super().__init__(
            f"Sortie dangereuse bloquée ({reason}): {invalid_value} hors tolérance [{safe_range[0]}, {safe_range[1]}]"
        )
        self.reason = reason
        self.invalid_value = invalid_value
        self.safe_range = safe_range


# Motifs d'injections directes et indirectes (OWASP LLM01)
INJECTION_PATTERNS: Final[list[tuple[str, re.Pattern[str]]]] = [
    (
        "instruction_override",
        re.compile(
            r"\b(ignore|disregard|forget|bypass|override)\b.*?\b(instructions|directives|prompts|rules|limits|safety|security)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "dan_jailbreak",
        re.compile(
            r"\b(dan mode|jailbreak|developer mode|unrestricted mode|god mode|do anything now)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_exfiltration",
        re.compile(
            r"\b(reveal|show|display|exfiltrate|leak|print|output)\s+(your\s+|the\s+)?(system\s+prompt|initial\s+(?:prompt|instructions)|instructions|secret|rules)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "sql_injection",
        re.compile(
            r"\b(drop\s+table|delete\s+from|union\s+select|insert\s+into|exec\s+xp_|;\s*shutdown)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "xss_html_injection",
        re.compile(
            r"<\s*script[^>]*>|javascript:|onload\s*=|onerror\s*=", re.IGNORECASE
        ),
    ),
    (
        "system_command_escape",
        re.compile(
            r"\b(sudo\s+|cat\s+/etc/passwd|/bin/sh|/bin/bash|rm\s+-rf|chmod\s+777)\b",
            re.IGNORECASE,
        ),
    ),
]

# Masquage PII (RGPD / OWASP LLM06)
PII_EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
PII_CARD_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")


# ============================================================================
# Normalisation anti-obfuscation et motifs étendus (FR/EN)
# ============================================================================
MAX_PROMPT_CHARS: Final[int] = 4000
_MAX_DECODE_DEPTH: Final[int] = 4
_MAX_B64_TOKENS: Final[int] = 8

# Homoglyphes cyrilliques / grecs courants -> latin (appliqué après casefold)
_HOMOGLYPHS: Final[dict[int, str]] = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ї": "i",
        "ѕ": "s",
        "ј": "j",
        "к": "k",
        "м": "m",
        "т": "t",
        "ԁ": "d",
        "ɡ": "g",
        "ο": "o",
        "α": "a",
        "ε": "e",
        "ν": "v",
        "ι": "i",
        "κ": "k",
        "ρ": "p",
        "τ": "t",
        "υ": "u",
        "ɩ": "i",
        "ӏ": "l",
    }
)
_LEET: Final[dict[int, str]] = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "!": "i",
    }
)


def _canonical(text: str) -> str:
    """Forme canonique : décodage HTML/URL itéré, NFKC, caractères invisibles retirés,
    casefold, homoglyphes repliés, accents retirés, soulignés en espaces."""
    work = text
    for _ in range(_MAX_DECODE_DEPTH):
        previous = work
        work = html.unescape(urllib.parse.unquote_plus(work))
        work = unicodedata.normalize("NFKC", work)
        if work == previous:
            break
    work = "".join(c for c in work if c in "\n\t" or unicodedata.category(c)[0] != "C")
    work = work.casefold().translate(_HOMOGLYPHS)
    work = "".join(
        c
        for c in unicodedata.normalize("NFKD", work)
        if unicodedata.category(c) != "Mn"
    )
    return re.sub(r"[_\s]+", " ", work)


_OVERRIDE_VERB = (
    r"(?:ignor\w*|disregard\w*|forget\w*|overrid\w*|bypass\w*|circumvent\w*|oubli\w*|neglig\w*|"
    r"contourn\w*|desactiv\w*|deactivat\w*|disabl\w*|outrepass\w*|annul\w*|neutralis\w*|ignoriere\w*)"
)
_GAP = r"\W+(?:\w+\W+){0,4}?"
_RULE_NOUN = (
    r"(?:instructions?|directives?|prompts?|rules?|restrictions?|guardrails?|safeguards?|guidelines?|"
    r"constraints?|filters?|consignes?|filtres?|garde ?fous?|protections?|securite|safety|security|"
    r"instrucciones|anweisungen|limits?)"
)
_SAFETY_SYSTEM = (
    r"(?:emergency ?stops?|e ?stop|arrets? d['’ ]?urgence|interlocks?|verrouillages?|garde ?fous?|"
    r"limites? de securite|safety (?:limits?|systems?|interlocks?)|relais de securite)"
)
_EXFIL_TARGET = (
    r"(?:secret ?keys?|api ?keys?|private ?keys?|cles? privees?|cles? tde|tde (?:encryption )?keys?|jwt secrets?|"
    r"database urls?|admin(?:istrat\w+)? pass\w*|mot de passe (?:de l ?)?admin\w*|root pass\w*|"
    r"mots? de passe (?:de la )?(?:base|root|superuser)|credentials?|identifiants? (?:admin|root))"
)
_EXFIL_ACTION = (
    r"(?:give|tell|read|reveal|show|print|dump|display|leak|exfiltrat\w*|donne\w*|dis|lis|revele\w*|"
    r"affiche\w*|montre\w*|quelle? est|quels? sont|what is|what s|what are|whats|share|send|envoie\w*|"
    r"recite|recit\w*|read me|lisait|lit)"
)

_EXTRA_PATTERNS: Final[list[tuple[str, re.Pattern[str]]]] = [
    ("instruction_override", re.compile(_OVERRIDE_VERB + _GAP + _RULE_NOUN)),
    ("safety_bypass", re.compile(_OVERRIDE_VERB + _GAP + _SAFETY_SYSTEM)),
    (
        "restriction_removal",
        re.compile(
            r"\b(?:answer|respond|reply|repond\w*|reponds?|ecris|write|act|behave|comporte\w*)\W+(?:\w+\W+){0,4}?"
            r"(?:without|sans|no|aucune?)\W+(?:\w+\W+){0,2}?"
            r"(?:restrictions?|filters?|limits?|limites?|filtres?|garde ?fous?|rules?|censorship|censure)"
        ),
    ),
    (
        "roleplay_jailbreak",
        re.compile(
            r"\b(?:pretend|act as|roleplay|role play|imagine you|you are now|from now on you|tu es maintenant|"
            r"fais semblant|joue le role|comporte toi comme|you are dan|tu es dan)\b"
        ),
    ),
    (
        "unfiltered_mode",
        re.compile(
            r"\b(?:mode|modo)\W+(?:\w+\W+){0,2}?(?:sans filtre|unfiltered|unrestricted|libre|sans restriction|"
            r"developpeur|developer|debug|admin|root|god)\b|\bsans (?:aucun )?(?:filtre|garde ?fous?)\b"
        ),
    ),
    (
        "prompt_exfiltration",
        re.compile(
            r"\b(?:reveal|show|print|repeat|display|give|dump|affiche\w*|montre\w*|revele\w*|donne\w*|repete\w*|"
            r"ecris|copy|recopie\w*)\W+(?:\w+\W+){0,3}?"
            r"(?:system ?prompt|prompt systeme|initial instructions|instructions initiales|your instructions|"
            r"tes instructions|tes consignes|your rules|your prompt|ton prompt)"
        ),
    ),
    ("secret_exfiltration", re.compile(_EXFIL_ACTION + _GAP + _EXFIL_TARGET)),
    (
        "secret_exfiltration",
        re.compile(
            r"\b(?:grand ?mother|grand ?mere|grandma|mamie)\b.*\b(?:password|mot de passe|key|cle|secret)\b"
        ),
    ),
    (
        "role_marker_injection",
        re.compile(
            r"```\s*(?:system|assistant|developer)|<\|?(?:im start|im end|system|endoftext)\|?>|\[/?inst\]|(?m:^\s*(?:system|developer)\s*:)"
        ),
    ),
    (
        "multilingual_override",
        re.compile(
            r"\b(?:ignora\w*|ignorier\w*|ignorez|ignorer)\W+(?:\w+\W+){0,3}?(?:instruc\w*|anweisung\w*|consign\w*|instruction\w*)"
        ),
    ),
]

_SQUASHED_PHRASES: Final[tuple[str, ...]] = (
    "ignorepreviousinstructions",
    "ignoreallpreviousinstructions",
    "ignoreallinstructions",
    "ignorepriorinstructions",
    "ignoretheaboveinstructions",
    "disregardpreviousinstructions",
    "forgetpreviousinstructions",
    "ignorelesinstructions",
    "ignoretesconsignes",
    "oublietesconsignes",
    "revealsystemprompt",
    "systempromptreveal",
    "donnemoilepromptsysteme",
)

_B64_TOKEN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")


def _scan_forms(text: str) -> tuple[str, str] | None:
    """Retourne (catégorie, extrait) si `text` (brut) contient une injection, sinon None."""
    base = _canonical(text)
    leet = base.translate(_LEET)
    for form in (base, leet):
        for category, pattern in INJECTION_PATTERNS:
            m = pattern.search(form)
            if m:
                return category, m.group(0)
        for category, pattern in _EXTRA_PATTERNS:
            m = pattern.search(form)
            if m:
                return category, m.group(0)
    squashed = re.sub(r"[^a-z]", "", leet)
    for phrase in _SQUASHED_PHRASES:
        if phrase in squashed:
            return "obfuscated_injection", phrase
    return None


def _decoded_candidates(text: str) -> list[str]:
    out: list[str] = []
    for token in _B64_TOKEN.findall(text)[:_MAX_B64_TOKENS]:
        raw = token.replace("-", "+").replace("_", "/")
        raw += "=" * (-len(raw) % 4)
        try:
            data = base64.b64decode(raw, validate=True)
        except ValueError:
            continue
        decoded = data.decode("utf-8", errors="ignore")
        if (
            len(decoded) >= 6
            and sum(c.isprintable() for c in decoded) / len(decoded) > 0.85
        ):
            out.append(decoded)
    return out


def scan_for_injection(text: str, depth: int = 0) -> tuple[str, str] | None:
    """Analyse `text`, ses formes normalisées et ses contenus Base64 (récursif, borné)."""
    found = _scan_forms(text)
    if found:
        return found
    if depth >= _MAX_DECODE_DEPTH:
        return None
    for decoded in _decoded_candidates(text):
        inner = scan_for_injection(decoded, depth + 1)
        if inner:
            return f"base64_{inner[0]}", inner[1]
    return None


_NUM = r"(\d{1,3}(?:[,\u202f ]\d{3})+(?:\.\d+)?|\d+(?:[.,]\d+)?)"
_RANGE_SEP = r"(?:\s*(?:-|–|—|a|à|to|et|and)\s*" + _NUM + r")?"
_TEMP_UNIT = (
    r"(?P<tu>°\s*c\b|°\s*f\b|°\s*k\b|º\s*c\b|deg(?:re|res|rees|ree)?\.?\s*(?:celsius|centigrade|c|fahrenheit|f|kelvin|k)\b|"
    r"deg(?:re|res|rees|ree)?\b|celsius\b|fahrenheit\b|kelvin\b|centigrade\b|c\b|f\b|k\b)"
)
_PRESS_UNIT = r"(?P<pu>bars?\b|mbars?\b|millibars?\b|psi\b|kpa\b|hpa\b|mpa\b|pa\b|atm\b|kgf/cm2\b|kgf/cm²\b)"
_TEMP_RE: Final[re.Pattern[str]] = re.compile(
    _NUM + _RANGE_SEP + r"\s*" + _TEMP_UNIT, re.IGNORECASE
)
_PRESS_RE: Final[re.Pattern[str]] = re.compile(
    _NUM + _RANGE_SEP + r"\s*" + _PRESS_UNIT, re.IGNORECASE
)


def _to_float(raw: str) -> float:
    cleaned = raw.replace("\u202f", "").replace(" ", "")
    if re.fullmatch(r"\d{1,3}(,\d{3})+(\.\d+)?", cleaned):
        cleaned = cleaned.replace(",", "")
    return float(cleaned.replace(",", "."))


def _temp_to_celsius(value: float, unit: str) -> float:
    u = unit.casefold().replace("º", "°").replace(" ", "")
    if "f" in u.replace("celsius", "").replace("centigrade", ""):
        return (value - 32.0) * 5.0 / 9.0
    if u.endswith("k") or "kelvin" in u:
        return value - 273.15
    return value


_PRESSURE_TO_BAR: Final[dict[str, float]] = {
    "bar": 1.0,
    "bars": 1.0,
    "mbar": 0.001,
    "mbars": 0.001,
    "millibar": 0.001,
    "millibars": 0.001,
    "psi": 0.0689476,
    "kpa": 0.01,
    "hpa": 0.001,
    "mpa": 10.0,
    "pa": 1e-5,
    "atm": 1.01325,
    "kgf/cm2": 0.980665,
    "kgf/cm²": 0.980665,
}

# ============================================================================
# Base de Connaissances RAG Locale (Norme EN 12150 - Verre de Sécurité Trempé)
# ============================================================================


@dataclass(frozen=True, slots=True)
class KnowledgeDoc:
    id: str
    title: str
    norm_ref: str
    content: str
    keywords: list[str]


EN_12150_CORPUS: Final[list[KnowledgeDoc]] = [
    KnowledgeDoc(
        id="EN12150-CHAUFFE",
        title="Consignes Thermiques de Chauffe par Épaisseur",
        norm_ref="NF EN 12150-1 Section 6",
        content=(
            "Pour le verre silico-sodo-calcique, la température d'enfournement minimale pour atteindre "
            "le point de transition vitreuse (Tg) est de 660°C. Les températures optimales de consigne "
            "sont échelonnées selon l'épaisseur : verre 4mm (680°C - 700°C), verre 6mm (675°C - 695°C), "
            "verre 8mm (670°C - 690°C), verre 10mm et plus (660°C - 680°C). La température pyrométrique "
            "du verre à la sortie du four doit obligatoirement être comprise entre 630°C et 710°C avant le soufflage."
        ),
        keywords=[
            "chauffe",
            "température",
            "zone",
            "four",
            "pyromètre",
            "épaisseur",
            "degre",
            "celsius",
        ],
    ),
    KnowledgeDoc(
        id="EN12150-TREMPE",
        title="Paramètres de Soufflage et Pression de Trempe (Quench)",
        norm_ref="NF EN 12150-1 Section 7",
        content=(
            "Le gradient de trempe nécessite un refroidissement d'air comprimé symétrique supérieur/inférieur. "
            "Pressions requises : verre mince 4mm (4.5 à 5.8 bar), verre 6mm (3.2 à 4.2 bar), verre 8mm "
            "(2.2 à 3.0 bar), verre épais 12mm à 19mm (1.8 à 2.5 bar). Une pression inférieure à 1.5 bar "
            "provoque un sous-trempage non conforme EN 12150. Une pression supérieure à 6.5 bar risque de briser le verre."
        ),
        keywords=[
            "trempe",
            "pression",
            "soufflage",
            "quench",
            "bar",
            "air",
            "refroidissement",
        ],
    ),
    KnowledgeDoc(
        id="EN12150-CONVOYEUR",
        title="Cinématique Convoyeur et Échauffement",
        norm_ref="NF EN 12150-1 Section 8",
        content=(
            "Les rouleaux céramiques doivent maintenir un mouvement d'oscillation continu de 8 à 20 m/min "
            "afin d'éviter les déformations thermiques (roller wave). Le temps de cycle moyen est calculé à raison "
            "de 40 à 45 secondes par millimètre d'épaisseur. Un arrêt convoyeur supérieur à 10 secondes en zone chaude "
            "entraîne le bris immédiat du volume de verre et nécessite un arrêt d'urgence."
        ),
        keywords=[
            "convoyeur",
            "vitesse",
            "rouleaux",
            "m/min",
            "oscillation",
            "temps",
            "cycle",
        ],
    ),
    KnowledgeDoc(
        id="EN12150-CONTRÔLE",
        title="Critères de Conformité et Fragmentation de Sécurité",
        norm_ref="NF EN 12150-1 Section 9",
        content=(
            "Lors du test de fragmentation par choc au pointeau, un verre trempé conforme doit présenter "
            "au minimum 40 fragments non coupants dans un carré de 50 mm x 50 mm pour les épaisseurs de 4 à 12 mm, "
            "et 30 fragments pour les épaisseurs supérieures à 12 mm. Aucun éclat allongé de plus de 100 mm n'est toléré."
        ),
        keywords=[
            "fragmentation",
            "contrôle",
            "qualité",
            "fragments",
            "sécurité",
            "casse",
            "test",
        ],
    ),
    KnowledgeDoc(
        id="EN12150-URGENCE",
        title="Procédure d'Arrêt d'Urgence et Casse Thermique",
        norm_ref="NF EN 60204-1 / EN 12150",
        content=(
            "En cas de bris de verre dans le four ou dans le caisson de trempe, l'automate enclenche le mode E-STOP. "
            "L'extraction des débris nécessite l'arrêt complet des brûleurs, l'ouverture des sas et un refroidissement "
            "jusqu'à une température inférieure à 80°C avant intervention humaine avec EPI haute température."
        ),
        keywords=["urgence", "estop", "casse", "débris", "sécurité", "alarme", "panne"],
    ),
]


# ============================================================================
# Modèles de Données RAG
# ============================================================================


@dataclass(frozen=True, slots=True)
class RAGQueryRequest:
    prompt: str
    user_id: str | None = None
    role: str = "OT_OPERATOR"


@dataclass(frozen=True, slots=True)
class RAGQueryResponse:
    query: str
    answer: str
    retrieved_sources: list[str]
    confidence_score: float
    safety_checked: bool
    processing_time_ms: float


# ============================================================================
# LLMGuardService : Implémentation des 4 Barrières
# ============================================================================


class LLMGuardService:
    """Service d'orchestration hermétique LLM Guard en 4 barrières de sûreté."""

    def __init__(self, corpus: list[KnowledgeDoc] | None = None) -> None:
        self.corpus = corpus or EN_12150_CORPUS

    # ------------------------------------------------------------------------
    # BARRIÈRE 1 : Pre-Input Scanner (Anti-Injection & Sanitisation PII)
    # ------------------------------------------------------------------------
    def pre_input_scan(self, prompt: str) -> str:
        """Examine et nettoie le prompt utilisateur. Lève PromptInjectionDetected si hostile.

        L'analyse porte sur le texte brut, sa forme canonique (HTML/URL/NFKC, caractères
        invisibles retirés, homoglyphes et leet repliés) et sur les contenus Base64 décodés.
        """
        cleaned = prompt.strip()
        if not cleaned:
            raise PromptInjectionDetected(
                "Prompt vide ou uniquement des espaces", prompt
            )
        if len(cleaned) > MAX_PROMPT_CHARS:
            raise PromptInjectionDetected("prompt_too_long", cleaned[:40])

        found = scan_for_injection(cleaned)
        if found:
            category, excerpt = found
            logger.warning(
                "Tentative d'injection interceptée [Catégorie: %s] : '%s'",
                category,
                excerpt[:60],
            )
            raise PromptInjectionDetected(category, excerpt)

        # Anonymisation PII (RGPD)
        cleaned = PII_EMAIL_PATTERN.sub("[ANONYMIZED_EMAIL]", cleaned)
        cleaned = PII_CARD_PATTERN.sub("[ANONYMIZED_PAYMENT]", cleaned)

        return cleaned

    # ------------------------------------------------------------------------
    # BARRIÈRE 2 : Retrieval Cloisonné & Contexte Sanitisé
    # ------------------------------------------------------------------------
    def retrieve_context(
        self, sanitized_prompt: str, top_k: int = 2
    ) -> list[tuple[KnowledgeDoc, float]]:
        """Recherche déterministe par pertinence lexicale et pondération de mots-clés."""
        prompt_words = set(re.findall(r"\w+", sanitized_prompt.lower()))
        scored_docs: list[tuple[KnowledgeDoc, float]] = []

        for doc in self.corpus:
            doc_words = set(re.findall(r"\w+", doc.content.lower()))
            keyword_matches = sum(
                1.0 for kw in doc.keywords if kw.lower() in prompt_words
            )
            word_overlaps = len(prompt_words.intersection(doc_words))

            # Score combiné TF-IDF simplifié avec boost sur les mots-clés normatifs
            score = (keyword_matches * 3.0) + (word_overlaps * 0.5)
            if score > 0.0:
                scored_docs.append((doc, score))

        scored_docs.sort(key=lambda x: x[1], reverse=True)
        return scored_docs[:top_k]

    # ------------------------------------------------------------------------
    # BARRIÈRE 3 : Génération Contrainte & Déterministe
    # ------------------------------------------------------------------------
    def generate_grounded_answer(
        self, prompt: str, retrieved_docs: list[tuple[KnowledgeDoc, float]]
    ) -> str:
        """Produit une réponse déterministe strictement ancrée dans le contexte normatif."""
        if not retrieved_docs:
            return (
                "La base de connaissances SecuriGlass (norme EN 12150) ne contient pas d'éléments "
                "suffisamment précis pour répondre à cette demande de procédé. "
                "Veuillez vous référer au manuel opérateur ou contacter le Responsable Qualité."
            )

        best_doc, score = retrieved_docs[0]
        summary = (
            f"Conformément à la norme {best_doc.norm_ref} ({best_doc.title}) :\n"
            f"{best_doc.content}"
        )
        if len(retrieved_docs) > 1:
            second_doc = retrieved_docs[1][0]
            summary += f"\n\nComplément de sécurité ({second_doc.norm_ref}) :\n{second_doc.content}"

        return summary

    # ------------------------------------------------------------------------
    # BARRIÈRE 4 : Post-Output Guard (Contrôle Sûreté Physique & Anti-Fuite)
    # ------------------------------------------------------------------------
    def post_output_guard(self, answer: str) -> str:
        """Vérifie que la réponse générée ne propose aucune valeur thermique/pression dangereuse."""
        # 1. Températures, quelle que soit l'unité (°C, °F, K, « degrés Celsius », « 900 C »)
        # et bornes de plage ("500-700 °C") : tout est converti en °C avant contrôle.
        for tm in _TEMP_RE.finditer(answer):
            unit = tm.group("tu")
            for raw in (tm.group(1), tm.group(2)):
                if raw is None:
                    continue
                val = _temp_to_celsius(_to_float(raw), unit)
                # Seules les valeurs de consigne four sont contrôlées (hors refroidissement < 100 °C)
                if val > 100.0 and not TEMP_FURNACE_MIN_C <= val <= TEMP_FURNACE_MAX_C:
                    logger.critical(
                        "Violation Post-Output Guard : Température four %f°C hors tolérance [%f, %f]",
                        val,
                        TEMP_FURNACE_MIN_C,
                        TEMP_FURNACE_MAX_C,
                    )
                    raise UnsafeOutputBlocked(
                        "Température four hors bornes de sûreté EN 12150",
                        val,
                        (TEMP_FURNACE_MIN_C, TEMP_FURNACE_MAX_C),
                    )

        # 2. Pressions de trempe, converties en bar (mbar, psi, kPa, MPa, atm...)
        for pm in _PRESS_RE.finditer(answer):
            factor = _PRESSURE_TO_BAR[pm.group("pu").casefold()]
            for raw in (pm.group(1), pm.group(2)):
                if raw is None:
                    continue
                val = _to_float(raw) * factor
                if not PRESSURE_QUENCH_MIN_BAR <= val <= PRESSURE_QUENCH_MAX_BAR:
                    logger.critical(
                        "Violation Post-Output Guard : Pression de trempe %f bar hors tolérance [%f, %f]",
                        val,
                        PRESSURE_QUENCH_MIN_BAR,
                        PRESSURE_QUENCH_MAX_BAR,
                    )
                    raise UnsafeOutputBlocked(
                        "Pression de trempe hors bornes de sûreté EN 12150",
                        val,
                        (PRESSURE_QUENCH_MIN_BAR, PRESSURE_QUENCH_MAX_BAR),
                    )

        # 3. Contrôle anti-fuite de prompt système
        forbidden_leak_signatures = [
            "SECRET_SYSTEM_KEY",
            "Tu es l'assistant interne SecuriGlass",
            "DATABASE_URL",
            "jwt_secret",
            "TDE_ENCRYPTION_KEY",
        ]
        for sig in forbidden_leak_signatures:
            if sig.lower() in answer.lower():
                logger.critical(
                    "Fuite d'information confidentielle détectée dans la sortie LLM"
                )
                return (
                    "[ALERTE SÉCURITÉ : La réponse a été bloquée car elle contenait des informations "
                    "internes non autorisées. Un rapport a été transmis au SOC.]"
                )

        return answer

    # ------------------------------------------------------------------------
    # Pipeline Complet en 4 Barrières
    # ------------------------------------------------------------------------
    def query(self, request: RAGQueryRequest) -> RAGQueryResponse:
        """Traverse séquentiellement les 4 barrières de sûreté et retourne la réponse vérifiée."""
        start_time = datetime.now(timezone.utc)

        # Barrière 1 : Filtrage et validation de l'entrée
        sanitized_prompt = self.pre_input_scan(request.prompt)

        # Barrière 2 : Retrieval cloisonné
        retrieved = self.retrieve_context(sanitized_prompt)
        sources = [f"{doc.id} ({doc.norm_ref})" for doc, _ in retrieved]

        # Barrière 3 : Génération ancrée
        raw_answer = self.generate_grounded_answer(sanitized_prompt, retrieved)

        # Barrière 4 : Filtrage et contrôle de sortie
        safe_answer = self.post_output_guard(raw_answer)

        duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000.0

        return RAGQueryResponse(
            query=request.prompt,
            answer=safe_answer,
            retrieved_sources=sources,
            confidence_score=0.95 if retrieved else 0.2,
            safety_checked=True,
            processing_time_ms=round(duration_ms, 2),
        )


# Singleton applicatif
llm_guard_service = LLMGuardService()
