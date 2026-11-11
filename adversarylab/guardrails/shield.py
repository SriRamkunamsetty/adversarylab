"""AgentShield: Deny-by-default execution sandbox, egress firewall, and guardrail controls."""
from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

# Baseline injection regexes (preserves 100% compatibility with existing tests)
INJECTION = [
    re.compile(p, re.I)
    for p in (
        r"ignore (all |any )?(previous|prior) instructions",
        r"reveal (the |your )?system prompt",
        r"send .* to https?://",
        r"\byou are now\b",
    )
]

# Sensitive metadata IP addresses (cloud instance metadata, AWS/GCP/Azure)
BLOCKED_METADATA_IPS = {"169.254.169.254", "metadata.google.internal"}


class PolicyError(PermissionError):
    """Raised when an agent tool call violates AgentShield security boundaries."""
    pass


def scan_untrusted(text: str) -> list[str]:
    """Flag indirect prompt-injection patterns in tool / RAG output (pattern-based: one layer only)."""
    return [p.pattern for p in INJECTION if p.search(text)]


def is_safe_egress_host(hostname: str | None, allowed_hosts: set[str], block_private_ranges: bool = False) -> bool:
    """Verify if a hostname is allowed and does not resolve to cloud metadata or internal services."""
    if not hostname:
        return False
    if hostname in BLOCKED_METADATA_IPS:
        return False
    if hostname not in allowed_hosts:
        return False

    if block_private_ranges:
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            # Domain name (e.g., example.org), valid if present in allowed_hosts
            pass

    return True


@dataclass
class Sandbox:
    """Deny-by-default execution sandbox for autonomous agent tool invocations."""
    tools: dict[str, Callable]
    allowed: set[str]
    root: str = "/sandbox"
    allowed_hosts: set[str] = field(default_factory=set)
    max_calls: int = 10
    audit: list[dict] = field(default_factory=list)
    block_internal_ips: bool = False

    def _deny(self, name: str, why: str):
        self.audit.append({"tool": name, "ok": False, "reason": why})
        raise PolicyError(f"{name}: {why}")

    def _safe_path(self, path: str) -> str:
        full = posixpath.normpath(posixpath.join(self.root, path.lstrip("/")))
        if full != self.root and not full.startswith(self.root + "/"):
            raise ValueError("path escapes sandbox")
        return full

    def call(self, name: str, **args):
        if len(self.audit) >= self.max_calls:
            self._deny(name, "call budget exceeded")
        if name not in self.allowed or name not in self.tools:
            self._deny(name, "tool not allowed")
        if "path" in args:
            try:
                args["path"] = self._safe_path(args["path"])
            except ValueError:
                self._deny(name, "path escapes sandbox")
        if "url" in args:
            parsed = urlparse(args["url"])
            if not is_safe_egress_host(parsed.hostname, self.allowed_hosts, self.block_internal_ips):
                self._deny(name, "egress blocked")
        out = self.tools[name](**args)
        self.audit.append({"tool": name, "ok": True})
        return out


class AgentShield:
    """High-level enterprise guardrails controller."""

    @staticmethod
    def inspect_prompt(prompt: str) -> dict:
        """Analyze inbound prompt for direct or indirect injection indicators."""
        matches = scan_untrusted(prompt)
        risk = "HIGH" if matches else "LOW"
        return {
            "is_flagged": bool(matches),
            "risk_level": risk,
            "patterns_matched": matches,
            "sanitized_preview": prompt[:150] + ("..." if len(prompt) > 150 else ""),
        }

    @staticmethod
    def sanitize_output(output: str, canary: str | None = None) -> str:
        """Scrub known canary secrets and sensitive metadata from model output."""
        cleaned = output
        if canary and canary in cleaned:
            cleaned = cleaned.replace(canary, "[REDACTED_CONFIDENTIAL_CANARY]")
        return cleaned
