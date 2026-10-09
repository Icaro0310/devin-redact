"""Detection patterns for secrets and PII.

Each entry maps a *category* to a list of compiled regular expressions.
A pattern may define a capture group; when it does, group 1 is treated as
the sensitive value (so a context-required pattern still reports only the
secret itself). Otherwise the whole match is the sensitive value.

Categories that count as *secrets* (they block publication) are listed in
``SECRET_CATEGORIES``; the remaining categories are PII / hygiene findings.
"""

from __future__ import annotations

import re


def _rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


PATTERNS: dict[str, list[re.Pattern[str]]] = {
    # --- secrets -------------------------------------------------------
    "api_key": [
        # OpenAI-style keys: sk-..., sk-proj-..., sk_live_... (Stripe)
        _rx(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"),
        _rx(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
        _rx(r"\brk_live_[A-Za-z0-9]{16,}\b"),
        # AWS access key id
        _rx(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        # Google API key
        _rx(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        # Slack tokens
        _rx(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ],
    "bearer_token": [
        # "Authorization: Bearer <token>" — group 1 is the token
        _rx(r"[Bb]earer\s+([A-Za-z0-9._~+/=-]{16,})"),
        # JWTs (header.payload.signature)
        _rx(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
    ],
    "github_token": [
        _rx(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        _rx(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    ],
    "private_key": [
        # Whole PEM block, header through footer.
        _rx(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ],
    "env_assignment": [
        # KEY=value assignments for sensitive-looking variable names.
        _rx(
            r"(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*"
            r"(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z0-9_]*"
            r"\s*=\s*\S[^\n]*"
        ),
    ],
    "devin_pairing_code": [
        # Pairing codes only count with explicit context — group 1 is the code.
        _rx(
            r"(?i)(?:pairing|pair)[ -]?code\s*[:=]?\s*"
            r"([A-Z0-9]{4}(?:-[A-Z0-9]{4}){1,3})"
        ),
    ],
    # --- PII / hygiene --------------------------------------------------
    "email": [
        _rx(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ],
    "absolute_path": [
        # Windows user paths: C:\Users\<name>\...
        _rx(r"\b[A-Za-z]:\\Users\\[^\s\"'<>|]+"),
        # POSIX home paths: /home/<name>/... and macOS /Users/<name>/...
        _rx(r"(?<![\w/.-])/(?:home|Users)/[^\s\"'<>|]+"),
    ],
}

SECRET_CATEGORIES = frozenset(
    {
        "api_key",
        "bearer_token",
        "github_token",
        "private_key",
        "env_assignment",
        "devin_pairing_code",
    }
)

PII_CATEGORIES = frozenset(PATTERNS) - SECRET_CATEGORIES

# Pattern names used when reporting, one per regex (index-based fallback).
_PATTERN_NAMES: dict[str, list[str]] = {
    "api_key": ["openai_key", "stripe_live_key", "stripe_restricted_key", "aws_access_key_id", "google_api_key", "slack_token"],
    "bearer_token": ["bearer_header", "jwt"],
    "github_token": ["github_token", "github_fine_grained_pat"],
    "private_key": ["pem_private_key"],
    "env_assignment": ["env_assignment"],
    "devin_pairing_code": ["devin_pairing_code"],
    "email": ["email"],
    "absolute_path": ["windows_user_path", "posix_home_path"],
}


def pattern_name(category: str, index: int) -> str:
    """Human-readable name for ``PATTERNS[category][index]``."""
    names = _PATTERN_NAMES.get(category, [])
    if 0 <= index < len(names):
        return names[index]
    return f"{category}[{index}]"


def sensitive_match(match: re.Match[str]) -> str:
    """Return the sensitive value of a regex match (group 1 if present)."""
    if match.lastindex:
        return match.group(1)
    return match.group(0)
