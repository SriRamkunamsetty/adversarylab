"""Scanner for Sensitive Information Disclosure, High-Entropy Secrets, and PII."""
from __future__ import annotations

import math
import re

PATTERNS = {
    "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "OpenAI API Key": re.compile(r"\bsk-[a-zA-Z0-9]{32,}\b"),
    "GitHub Token": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
    "Generic Bearer/JWT": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    "Private Key Header": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----"),
    "Email Address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "Credit Card (Luhn candidate)": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    "Social Security Number": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string (bits per symbol). High entropy (> 4.2) often indicates secrets."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for count in (data.count(c) for c in set(data)):
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


def scan_pii_and_secrets(text: str) -> list[dict[str, str]]:
    """Scan text for known credential signatures, PII patterns, and high-entropy secret tokens."""
    findings = []
    for label, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        for m in matches:
            val = m if isinstance(m, str) else m[0]
            findings.append({
                "type": label,
                "snippet": val[:4] + "..." + val[-3:] if len(val) > 8 else "***",
                "entropy": round(calculate_shannon_entropy(val), 2),
            })

    # Check for standalone high-entropy words (>24 chars, entropy > 4.2)
    for word in text.split():
        clean = word.strip(" '\"`()[]{}<>.,:;")
        if len(clean) >= 24 and calculate_shannon_entropy(clean) > 4.3:
            if not any(f["snippet"].startswith(clean[:4]) for f in findings):
                findings.append({
                    "type": "High-Entropy Secret Token",
                    "snippet": clean[:4] + "..." + clean[-3:],
                    "entropy": round(calculate_shannon_entropy(clean), 2),
                })

    return findings
