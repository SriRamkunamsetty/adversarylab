"""OWASP Top 10 for LLM Applications (2025 Edition) taxonomy, mapping, and severity catalog."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class OWASPEntry:
    code: str
    name: str
    year: int
    severity: Severity
    description: str
    remediation: str

    @property
    def identifier(self) -> str:
        return f"{self.code}:{self.year} {self.name}"


OWASP_CATALOG: dict[str, OWASPEntry] = {
    "LLM01": OWASPEntry(
        code="LLM01",
        name="Prompt Injection",
        year=2025,
        severity=Severity.CRITICAL,
        description="Crafted inputs manipulate model behavior, bypassing guardrails or hijacking downstream tools.",
        remediation="Enforce strict separation between system instructions and untrusted content. Apply AgentShield guardrails and deterministic privilege boundaries.",
    ),
    "LLM02": OWASPEntry(
        code="LLM02",
        name="Sensitive Information Disclosure",
        year=2025,
        severity=Severity.CRITICAL,
        description="Model reveals proprietary data, internal system prompts, API keys, credentials, or personal information.",
        remediation="Deploy canary secret detection, real-time output sanitization, scrub training/RAG datasets, and implement strict output redacting.",
    ),
    "LLM03": OWASPEntry(
        code="LLM03",
        name="Supply Chain Vulnerabilities",
        year=2025,
        severity=Severity.HIGH,
        description="Compromised third-party pre-trained models, datasets, plugins, or software dependencies.",
        remediation="Sign model artifacts with Cosign, verify checksums, enforce SBOM generation and automated dependency scanning.",
    ),
    "LLM04": OWASPEntry(
        code="LLM04",
        name="Data and Model Poisoning",
        year=2025,
        severity=Severity.HIGH,
        description="Adversarial manipulation of training, fine-tuning data, or RAG corpora to introduce backdoors.",
        remediation="Sanitize ingested documents, monitor drift and anomaly scores, and isolate document ingestion pipelines.",
    ),
    "LLM05": OWASPEntry(
        code="LLM05",
        name="Improper Output Handling",
        year=2025,
        severity=Severity.HIGH,
        description="Unvalidated model outputs passed directly to downstream interpreters (browsers, SQL, shells).",
        remediation="Contextually encode all LLM output before presentation (HTML escaping, parameterized queries, safe serialization).",
    ),
    "LLM06": OWASPEntry(
        code="LLM06",
        name="Excessive Agency",
        year=2025,
        severity=Severity.CRITICAL,
        description="Autonomous agents granted overly broad capabilities, unbounded filesystem access, or network egress.",
        remediation="Enforce deny-by-default execution sandboxes, path confinement, egress filtering, and strict invocation budgets via AgentShield.",
    ),
    "LLM07": OWASPEntry(
        code="LLM07",
        name="System Prompt Leakage",
        year=2025,
        severity=Severity.MEDIUM,
        description="Attacker extracts the developer's hidden instructions, context, or persona definitions.",
        remediation="Assume prompt confidentiality cannot be guaranteed solely by model compliance; keep architectural secrets in external secure stores.",
    ),
    "LLM08": OWASPEntry(
        code="LLM08",
        name="Vector and Embedding Weaknesses",
        year=2025,
        severity=Severity.HIGH,
        description="Vulnerabilities in vector databases, nearest-neighbor searches, or embedding inversion.",
        remediation="Enforce tenant isolation in vector stores and validate document origins before ingestion into embedding indexes.",
    ),
    "LLM09": OWASPEntry(
        code="LLM09",
        name="Misinformation",
        year=2025,
        severity=Severity.MEDIUM,
        description="Generation of false, hallucinatory, or ungrounded assertions presented as factual truth.",
        remediation="Pair generation with deterministic ground-truth verification, claim verification pipelines, and hallucination scoring.",
    ),
    "LLM10": OWASPEntry(
        code="LLM10",
        name="Unbounded Consumption",
        year=2025,
        severity=Severity.HIGH,
        description="Denial of service via resource exhaustion, token loops, excessive context size, or infinite recursion.",
        remediation="Enforce strict rate limits, token budgets per session, execution timeouts, and request size caps.",
    ),
}

# Standard string aliases for backward compatibility with existing tests
OWASP_INJECTION = OWASP_CATALOG["LLM01"].identifier
OWASP_DISCLOSURE = OWASP_CATALOG["LLM02"].identifier
OWASP_AGENCY = OWASP_CATALOG["LLM06"].identifier
OWASP_LEAKAGE = OWASP_CATALOG["LLM07"].identifier
OWASP_CONSUMPTION = OWASP_CATALOG["LLM10"].identifier


def classify_finding(attack: str, verdict: str, details: Optional[dict] = None) -> list[OWASPEntry]:
    """Classify an attack run and verdict into one or more OWASP entries."""
    entries = [OWASP_CATALOG["LLM01"]]

    if attack in ("indirect-injection", "rag-poisoning", "tool-hijack"):
        entries.append(OWASP_CATALOG["LLM06"])
    if attack in ("dos-unbounded", "token-exhaustion", "recursion"):
        entries.append(OWASP_CATALOG["LLM10"])
    if "prompt" in attack or "system" in attack:
        entries.append(OWASP_CATALOG["LLM07"])

    if verdict == "leak":
        entries.append(OWASP_CATALOG["LLM02"])

    # Deduplicate while preserving order
    seen = set()
    result = []
    for e in entries:
        if e.code not in seen:
            seen.add(e.code)
            result.append(e)
    return result


def owasp_for(attack: str, verdict: str) -> str:
    """Format matching OWASP identifiers as a semicolon-separated string (backwards compatible)."""
    return "; ".join(e.identifier for e in classify_finding(attack, verdict))
