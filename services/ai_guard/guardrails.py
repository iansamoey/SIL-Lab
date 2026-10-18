"""Guardrail engine: PII/PHI detection, secret detection and prompt-injection scoring.

Design notes
  * PII/PHI detection uses Microsoft Presidio. Its built-in recognisers are tuned for
    US/EU formats, so we add Kenyan ones (national ID, +254/07xx phones, KRA PIN,
    SHA/NHIF member numbers) plus clinical-context recognisers (ICD-10 codes, terms).
  * "PHI" here means an identifier appearing together with clinical information.
    Identifiers alone are redacted; identifiers plus clinical context are blocked.
  * Prompt-injection detection here is heuristic (weighted patterns after
    normalisation). It is a first line only: production adds an ML classifier
    (e.g. LLM Guard / Prompt Guard), and output-side canary checks catch what slips through.
"""
import re
import unicodedata
from dataclasses import dataclass, field

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

# ---------------------------------------------------------------------------
# PII / PHI recognisers
# ---------------------------------------------------------------------------

IDENTIFIER_ENTITIES = {
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE",
    "KE_NATIONAL_ID", "KE_PHONE", "KE_KRA_PIN", "KE_SHA_NUMBER",
}
CLINICAL_ENTITIES = {"ICD10_CODE", "CLINICAL_TERM"}

# Terms that make a passage clinical. Extend with the organisation's own vocabulary,
# including Swahili terms used in clinical notes (see limitations in the README).
CLINICAL_TERMS = [
    "diagnosis", "diagnosed", "hiv", "aids", "arv", "art regimen", "viral load", "cd4",
    "tuberculosis", "tb", "diabetes", "diabetic", "hypertension", "hypertensive",
    "malaria", "cancer", "chemotherapy", "pregnant", "pregnancy", "antenatal",
    "mental health", "depression", "schizophrenia", "prescription", "prescribed",
    "lab result", "biopsy", "admitted", "discharge summary", "medical history",
]


def _kenyan_recognisers() -> list[PatternRecognizer]:
    return [
        # 7-8 digit numbers are everywhere (amounts, invoice numbers), so the base score is
        # low and only context words ("ID", "national") lift it over the threshold.
        PatternRecognizer(
            supported_entity="KE_NATIONAL_ID",
            patterns=[Pattern("ke_national_id", r"\b\d{7,8}\b", 0.2)],
            context=["id", "national", "identity", "idno", "id number", "kitambulisho"],
        ),
        PatternRecognizer(
            supported_entity="KE_PHONE",
            patterns=[
                Pattern("ke_phone_intl", r"(?<!\d)\+?254[\s-]?[17]\d{2}[\s-]?\d{3}[\s-]?\d{3}\b", 0.85),
                Pattern("ke_phone_local", r"\b0[17]\d{2}[\s-]?\d{3}[\s-]?\d{3}\b", 0.6),
            ],
            context=["phone", "tel", "mobile", "call", "contact", "whatsapp", "mpesa"],
        ),
        PatternRecognizer(
            supported_entity="KE_KRA_PIN",
            patterns=[Pattern("kra_pin", r"\b[AP]\d{9}[A-Z]\b", 0.85)],
            context=["kra", "pin", "tax"],
        ),
        # Member number formats vary; this requires context to fire. Confirm the
        # current SHA format with the claims team before relying on it.
        PatternRecognizer(
            supported_entity="KE_SHA_NUMBER",
            patterns=[Pattern("sha_member", r"\b[A-Z]{0,3}\d{8,12}\b", 0.1)],
            context=["sha", "nhif", "shif", "member", "membership", "cover"],
        ),
        PatternRecognizer(
            supported_entity="ICD10_CODE",
            patterns=[Pattern("icd10", r"\b[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b", 0.4)],
            context=["icd", "icd-10", "icd10", "diagnosis", "code", "dx"],
        ),
        PatternRecognizer(supported_entity="CLINICAL_TERM", deny_list=CLINICAL_TERMS),
    ]


def build_analyzer(model: str = "en_core_web_sm") -> AnalyzerEngine:
    nlp = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": model}],
    }).create_engine()
    registry = RecognizerRegistry(supported_languages=["en"])
    registry.load_predefined_recognizers(languages=["en"], nlp_engine=nlp)
    for rec in _kenyan_recognisers():
        registry.add_recognizer(rec)
    return AnalyzerEngine(nlp_engine=nlp, registry=registry, supported_languages=["en"])


# ---------------------------------------------------------------------------
# Secrets: never allowed to leave the network, in either direction
# ---------------------------------------------------------------------------

SECRET_PATTERNS = {
    "DB_CONNECTION_STRING": r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql|sqlserver|amqp)://[^\s:@/]+:[^\s@/]+@",
    "PASSWORD_ASSIGNMENT": r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?[^\s'\";]{6,}",
    "AWS_ACCESS_KEY": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "GITHUB_TOKEN": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "LLM_API_KEY": r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b",
}
_SECRET_RES = {name: re.compile(rx) for name, rx in SECRET_PATTERNS.items()}


def find_secrets(text: str) -> list[str]:
    return [name for name, rx in _SECRET_RES.items() if rx.search(text)]


def redact_secrets(text: str) -> str:
    for name, rx in _SECRET_RES.items():
        text = rx.sub(f"<{name}>", text)
    return text


# ---------------------------------------------------------------------------
# Prompt injection
# ---------------------------------------------------------------------------

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)

INJECTION_PATTERNS = [
    (r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|earlier|all|any|your|system)\b.{0,30}\b(instructions?|rules|prompts?|guidelines|polic(y|ies)|guardrails?)", 0.9),
    (r"\b(reveal|show|print|repeat|output|display|leak|tell me)\b.{0,30}\b(system|hidden|initial|original)\s+(prompt|instructions?|message)", 0.8),
    (r"\byou are now\b|\bfrom now on,? you\b|\bnew instructions?:", 0.5),
    (r"\b(dan|do anything now|developer mode|jailbreak|god mode)\b", 0.6),
    (r"\b(act|pretend|roleplay)\b.{0,20}\b(as|to be)\b.{0,30}\b(unrestricted|unfiltered|no (rules|restrictions|limits))", 0.7),
    (r"</?\s*(system|assistant|instructions?)\s*>|^\s*#{2,}\s*system\b|\[/?inst\]", 0.6),
    (r"\b(exfiltrate|send|post|upload)\b.{0,40}\b(https?://|webhook|endpoint)", 0.5),
]
_INJECTION_RES = [(re.compile(rx, re.IGNORECASE | re.MULTILINE), w) for rx, w in INJECTION_PATTERNS]
_LONG_BASE64 = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


def normalise(text: str) -> str:
    """Undo common obfuscation: full-width/compatibility characters, zero-width joiners."""
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


def injection_score(text: str) -> tuple[float, list[str]]:
    t = normalise(text)
    score, hits = 0.0, []
    for i, (rx, weight) in enumerate(_INJECTION_RES):
        if rx.search(t):
            score += weight
            hits.append(f"pattern_{i}")
    if _LONG_BASE64.search(t):  # encoded payloads are a common smuggling technique
        score += 0.3
        hits.append("long_base64")
    return min(score, 1.0), hits


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def replace_spans(text: str, results) -> str:
    """Replace each detected span with <ENTITY_TYPE>.

    Deliberately implemented here rather than with presidio-anonymizer: that package pins
    cryptography below 49, which blocked security fixes available only in cryptography 50.
    Removing a dependency to unblock a patch also shrinks the attack surface. Overlapping
    spans are resolved by keeping the earliest-starting, longest match.
    """
    kept, last_end = [], -1
    for r in sorted(results, key=lambda r: (r.start, -(r.end - r.start))):
        if r.start >= last_end:
            kept.append(r)
            last_end = r.end
    for r in reversed(kept):
        text = text[:r.start] + f"<{r.entity_type}>" + text[r.end:]
    return text


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    entities: dict = field(default_factory=dict)   # entity type -> count
    secrets: list = field(default_factory=list)
    injection: float = 0.0
    injection_hits: list = field(default_factory=list)

    @property
    def identifiers(self) -> set:
        return set(self.entities) & IDENTIFIER_ENTITIES

    @property
    def clinical(self) -> set:
        return set(self.entities) & CLINICAL_ENTITIES


class Scanner:
    def __init__(self, analyzer: AnalyzerEngine, threshold: float = 0.5):
        self.analyzer = analyzer
        self.threshold = threshold
        self.entities = sorted(IDENTIFIER_ENTITIES | CLINICAL_ENTITIES)

    def _analyse(self, text: str):
        results = self.analyzer.analyze(text=text, language="en", entities=self.entities,
                                        score_threshold=self.threshold)
        # Drop overlaps where a broad pattern (e.g. SHA number) sits inside a better match.
        return [r for r in results
                if not any(o is not r and o.start <= r.start and r.end <= o.end and o.score > r.score
                           for o in results)]

    def scan(self, text: str) -> Finding:
        text = normalise(text)
        f = Finding(secrets=find_secrets(text))
        for r in self._analyse(text):
            f.entities[r.entity_type] = f.entities.get(r.entity_type, 0) + 1
        f.injection, f.injection_hits = injection_score(text)
        return f

    def redact_identifiers(self, text: str) -> str:
        """Replace identifiers with <ENTITY_TYPE> placeholders. Clinical terms are kept,
        because de-identified clinical text is what makes the request useful."""
        text = redact_secrets(normalise(text))
        results = [r for r in self._analyse(text) if r.entity_type in IDENTIFIER_ENTITIES]
        return replace_spans(text, results)
