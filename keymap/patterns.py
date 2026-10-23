"""Known provider key patterns.

Every pattern carries only the *public* literal prefix (e.g. ``sk-ant-``).
keymap never prints key characters beyond that prefix — matches are
reported by provider, file, line and a SHA-256 fingerprint prefix, so the
same key can be recognised across files without revealing it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderPattern:
    provider: str
    regex: re.Pattern
    prefix: str  # public literal prefix, safe to display
    description: str


def _compile(provider: str, pattern: str, prefix: str, description: str) -> ProviderPattern:
    return ProviderPattern(provider, re.compile(pattern), prefix, description)


PATTERNS: list[ProviderPattern] = [
    _compile(
        "anthropic",
        r"sk-ant-api03-[A-Za-z0-9_\-]{20,}",
        "sk-ant-",
        "Anthropic API key",
    ),
    _compile(
        "openai",
        r"sk-proj-[A-Za-z0-9_\-]{20,}",
        "sk-proj-",
        "OpenAI project API key",
    ),
    _compile(
        "openai",
        r"sk-svcacct-[A-Za-z0-9_\-]{20,}",
        "sk-svcacct-",
        "OpenAI service-account key",
    ),
    _compile(
        "openai",
        r"sk-[A-Za-z0-9]{20,}",
        "sk-",
        "OpenAI legacy API key (also matches other sk- keys)",
    ),
    _compile(
        "google",
        r"AIza[0-9A-Za-z_\-]{35}",
        "AIza",
        "Google API key (AI Studio / Cloud)",
    ),
    _compile(
        "github",
        r"github_pat_[A-Za-z0-9_]{22,}",
        "github_pat_",
        "GitHub fine-grained personal access token",
    ),
    _compile(
        "github",
        r"ghp_[A-Za-z0-9]{36}",
        "ghp_",
        "GitHub classic personal access token",
    ),
    _compile(
        "github",
        r"gho_[A-Za-z0-9]{36}",
        "gho_",
        "GitHub OAuth access token",
    ),
    _compile(
        "github",
        r"ghs_[A-Za-z0-9]{36}",
        "ghs_",
        "GitHub server-to-server token",
    ),
    _compile(
        "aws",
        r"AKIA[0-9A-Z]{16}",
        "AKIA",
        "AWS access key ID (identifier — pairs with a secret key)",
    ),
    _compile(
        "slack",
        r"xox[baprs]-[A-Za-z0-9\-]{10,}",
        "xox",
        "Slack token",
    ),
    _compile(
        "stripe",
        r"sk_live_[A-Za-z0-9]{16,}",
        "sk_live_",
        "Stripe live secret key",
    ),
    _compile(
        "stripe",
        r"rk_live_[A-Za-z0-9]{16,}",
        "rk_live_",
        "Stripe live restricted key",
    ),
    _compile(
        "openrouter",
        r"sk-or-v1-[A-Za-z0-9]{32,}",
        "sk-or-v1-",
        "OpenRouter API key",
    ),
    _compile(
        "groq",
        r"gsk_[A-Za-z0-9]{20,}",
        "gsk_",
        "Groq API key",
    ),
]

# Generic `NAME = value` assignments whose name smells like a secret but
# whose value matches no known provider pattern. Caught as "unrecognized".
GENERIC_SECRET_ASSIGN = re.compile(
    r"""(?P<name>[A-Za-z0-9_.\-]*?(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)[A-Za-z0-9_.\-]*)"""
    r"""\s*[:=]\s*["']?(?P<value>[^\s"'#;,]{8,})""",
    re.IGNORECASE,
)

# Values that are obviously not real keys: docs, examples, placeholders.
PLACEHOLDER_HINTS = (
    "example", "sample", "placeholder", "changeme", "change-me", "your-",
    "your_", "test", "fake", "dummy", "todo", "xxx", "***", "null", "none",
    "insert", "replace", "here", "redacted",
)

# Where to revoke / rotate each provider's keys. Shown in the report so a
# breach cleanup turns into a checklist instead of a scavenger hunt.
ROTATION_URLS = {
    "anthropic": "https://console.anthropic.com/settings/keys",
    "openai": "https://platform.openai.com/api-keys",
    "google": "https://aistudio.google.com/apikey",
    "github": "https://github.com/settings/tokens",
    "aws": "https://console.aws.amazon.com/iam/home#/security_credentials",
    "slack": "https://api.slack.com/apps",
    "stripe": "https://dashboard.stripe.com/apikeys",
    "openrouter": "https://openrouter.ai/settings/keys",
    "groq": "https://console.groq.com/keys",
    "unrecognized": "",
}


def looks_like_placeholder(value: str) -> bool:
    """True when a matched value is clearly a doc/example/placeholder."""
    lowered = value.strip().lower().strip("\"'")
    if not lowered or len(set(lowered)) <= 2:
        return True
    if lowered.startswith(("$", "{", "<")):
        return True  # ${VAR}, <paste-key-here>, $OPENAI_API_KEY
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)
