"""SARIF v2.1.0 export generator for GitHub Code Scanning and Enterprise SecOps."""
from __future__ import annotations

from typing import Any


def generate_sarif_report(campaign_id: int, target: str, findings: list[dict[str, Any]]) -> dict:
    """Generate a standard SARIF v2.1.0 JSON object representing campaign security findings."""
    rules = [
        {
            "id": "LLM01",
            "name": "PromptInjectionVulnerability",
            "shortDescription": {"text": "LLM01:2025 Prompt Injection"},
            "helpUri": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
            "properties": {"precision": "very-high", "problem.severity": "error"},
        },
        {
            "id": "LLM02",
            "name": "SensitiveInformationDisclosure",
            "shortDescription": {"text": "LLM02:2025 Sensitive Information Disclosure"},
            "helpUri": "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
            "properties": {"precision": "very-high", "problem.severity": "error"},
        },
        {
            "id": "LLM06",
            "name": "ExcessiveAgencyToolMisuse",
            "shortDescription": {"text": "LLM06:2025 Excessive Agency"},
            "helpUri": "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
            "properties": {"precision": "high", "problem.severity": "error"},
        },
    ]

    results = []
    for f in findings:
        verdict = f.get("verdict", "")
        if verdict in ("leak", "review"):
            attack = f.get("attack", "generic")
            rule_id = "LLM06" if attack == "indirect-injection" else ("LLM02" if verdict == "leak" else "LLM01")
            level = "error" if verdict == "leak" else "warning"

            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": (
                        f"Target '{target}' vulnerable to {attack} attack (verdict: {verdict}). "
                        f"Goal: {f.get('goal', 'n/a')}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"targets/{target}"},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "campaignId": campaign_id,
                    "attack": attack,
                    "owasp": f.get("owasp", ""),
                    "prompt": f.get("prompt", "")[:200],
                    "response": f.get("response", "")[:200],
                },
            })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AdversaryLab",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/SriRamkunamsetty/adversarylab",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
