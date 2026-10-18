"""Deterministic secret/PII detectors for trace attribute values.

Every detector is a pure function over strings — no network, no models —
so results are reproducible and safe to run against production trace exports.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    finding_class: str  # e.g. "anthropic_api_key"
    label: str          # human label, e.g. "Anthropic API key"
    redacted: str       # e.g. "[REDACTED:anthropic_api_key]"
    matched: str        # the exact matched substring (never printed in reports)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _credit_card_scanner(value: str):
    for m in re.finditer(r"\b(?:\d[ -]?){13,19}\b", value):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            yield m.group(0)


PATTERNS: list[tuple[str, str, object]] = [
    # (finding_class, label, compiled-regex-or-scanner)
    ("anthropic_api_key", "Anthropic API key",
     re.compile(r"sk-ant-(?:api03|admin)-[A-Za-z0-9_-]{20,}")),
    ("openai_api_key", "OpenAI API key",
     re.compile(r"sk-(?!ant-)[A-Za-z0-9]{20,}")),
    ("xai_api_key", "xAI API key",
     re.compile(r"xai-[A-Za-z0-9]{20,}")),
    ("aws_access_key_id", "AWS access key ID",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", "AWS secret access key",
     re.compile(r"(?i)aws.{0,20}secret.{0,5}[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
    ("gcp_api_key", "Google Cloud API key",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("github_token", "GitHub token",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("private_key", "PEM private key",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("jwt_token", "JWT bearer token",
     re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("bearer_token", "Bearer token",
     re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}")),
    ("email", "Email address",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ssn", "US Social Security number",
     re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("phone", "Phone number",
     re.compile(r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")),
    ("credit_card", "Credit card number", _credit_card_scanner),
    ("openai_org", "OpenAI org ID",
     re.compile(r"\borg-[A-Za-z0-9]{20,}\b")),
]

DETECTORS = [(cls, label) for cls, label, _ in PATTERNS]


def scan_value(value: str) -> list[Finding]:
    """Return every detector hit in a single attribute value string."""
    findings: list[Finding] = []
    for finding_class, label, pattern in PATTERNS:
        if callable(pattern) and not hasattr(pattern, "finditer"):
            matches = (m for m in pattern(value))
        else:
            matches = (m.group(0) for m in pattern.finditer(value))
        for matched in matches:
            findings.append(Finding(
                finding_class=finding_class,
                label=label,
                redacted=f"[REDACTED:{finding_class}]",
                matched=matched,
            ))
    return findings


def redact_value(value: str) -> str:
    """Replace every detected secret/PII in a string with its placeholder."""
    out = value
    for finding_class, label, pattern in PATTERNS:
        if callable(pattern) and not hasattr(pattern, "finditer"):
            matches = sorted({m for m in pattern(out)}, key=len, reverse=True)
            for m in matches:
                out = out.replace(m, f"[REDACTED:{finding_class}]")
        else:
            out = pattern.sub(f"[REDACTED:{finding_class}]", out)
    return out
