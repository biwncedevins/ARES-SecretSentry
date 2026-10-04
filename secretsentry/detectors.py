"""Detector registry + built-in pattern detectors.

Adding a new detector is as simple as:

.. code-block:: python

    detector(
        id="my_service_key",
        name="MyService API Key",
        category="Cloud Credentials",
        severity=Severity.HIGH,
        patterns=(("\\bmsc_[A-Za-z0-9]{32}\\b", 0),),
        weight=80,
    )

Each entry in ``patterns`` is a ``(regex, value_group)`` tuple. ``value_group``
is the capture group whose text is the secret itself (0 = whole match).

Tuning knobs:

* ``min_entropy`` / ``max_entropy`` - gate retention on the value's Shannon entropy.
* ``confidence`` - how strongly a bare match implies a real secret.
* ``weight`` - dedupe priority when matches overlap on the same line
  (higher weight wins; generic detectors use low weights).
* ``value_blacklist`` - common-placeholder values to drop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Sequence, Tuple

from .entropy import shannon_entropy
from .models import Confidence, RawMatch, Severity

PatternSpec = Tuple[str, int]


@dataclass
class Detector:
    id: str
    name: str
    category: str
    severity: Severity
    patterns: Sequence[PatternSpec] = field(default_factory=list)
    confidence: Confidence = Confidence.HIGH
    min_entropy: Optional[float] = None
    max_entropy: Optional[float] = None
    min_character_classes: int = 1
    weight: int = 0
    value_blacklist: tuple[str, ...] = ()
    description: str = ""
    ignore_case: bool = False
    # Called with the raw value -> bool. Returning True forces the match to be kept
    # even when ``min_entropy`` is not satisfied (and vice-versa is not applied).
    force_keep: Optional[Callable[[str], bool]] = None
    _compiled: list[tuple[re.Pattern, int]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        flags = re.IGNORECASE if self.ignore_case else 0
        self._compiled = [
            (re.compile(regex, flags), group)
            for regex, group in self.patterns
        ]

    def find(self, line: str) -> Iterable[RawMatch]:
        for regex, group in self._compiled:
            for m in regex.finditer(line):
                start = m.start(group)
                end = m.end(group)
                if start < 0:
                    continue
                value = m.group(group)
                if value is None:
                    continue
                if self.value_blacklist and value.strip().lower() in self.value_blacklist:
                    continue
                if self.min_entropy is not None:
                    entropy = shannon_entropy(value)
                    below = entropy < self.min_entropy
                    if below and not (self.force_keep and self.force_keep(value)):
                        continue
                if self.max_entropy is not None and shannon_entropy(value) > self.max_entropy:
                    continue
                if self.min_character_classes > 1:
                    from .entropy import distinct_character_classes
                    if distinct_character_classes(value) < self.min_character_classes:
                        continue
                yield RawMatch(value=value, start=start, end=end, detector=self)


DETECTOR_REGISTRY: list[Detector] = []


def detector(
    id: str,
    name: str,
    category: str,
    severity: Severity,
    patterns: Sequence[PatternSpec],
    *,
    confidence: Confidence = Confidence.HIGH,
    min_entropy: Optional[float] = None,
    max_entropy: Optional[float] = None,
    min_character_classes: int = 1,
    weight: int = 0,
    value_blacklist: Sequence[str] = (),
    description: str = "",
    ignore_case: bool = False,
    force_keep: Optional[Callable[[str], bool]] = None,
) -> Detector:
    d = Detector(
        id=id,
        name=name,
        category=category,
        severity=severity,
        patterns=patterns,
        confidence=confidence,
        min_entropy=min_entropy,
        max_entropy=max_entropy,
        min_character_classes=min_character_classes,
        weight=weight,
        value_blacklist=tuple(value_blacklist),
        description=description,
        ignore_case=ignore_case,
        force_keep=force_keep,
    )
    DETECTOR_REGISTRY.append(d)
    return d


# --------------------------------------------------------------------------
# Built-in detectors. Ordered roughly from most specific to most generic.
# --------------------------------------------------------------------------

# -- Cloud / service credentials --------------------------------------------
detector(
    id="aws_access_key",
    name="AWS Access Key ID",
    category="Cloud Credentials",
    severity=Severity.CRITICAL,
    patterns=((r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{16}\b", 0),),
    weight=110,
    description="20-character AWS credential identifier.",
)

detector(
    id="aws_secret_access_key",
    name="AWS Secret Access Key",
    category="Cloud Credentials",
    severity=Severity.CRITICAL,
    patterns=((r"\b[0-9A-Za-z/+=]{40}\b", 0),),
    confidence=Confidence.MEDIUM,
    min_entropy=4.5,
    weight=100,
    description="40-character base64 value consistent with an AWS secret key.",
)

detector(
    id="google_api_key",
    name="Google API Key",
    category="Cloud Credentials",
    severity=Severity.CRITICAL,
    patterns=((r"\bAIza[0-9A-Za-z_\-]{35}\b", 0),),
    weight=110,
    description="39-character Google API key.",
)

detector(
    id="google_oauth_client",
    name="Google OAuth Client ID",
    category="Cloud Credentials",
    severity=Severity.HIGH,
    patterns=((r"\b[0-9]{12,20}-[0-9A-Za-z_\-]{20,50}\.apps\.googleusercontent\.com\b", 0),),
    weight=90,
    description="A Google OAuth client identifier.",
)

detector(
    id="github_token",
    name="GitHub Access Token",
    category="Source Control",
    severity=Severity.CRITICAL,
    patterns=((r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", 0),),
    weight=120,
    description="GitHub personal / OAuth / app token.",
)

detector(
    id="github_fine_grained",
    name="GitHub Fine-grained Token",
    category="Source Control",
    severity=Severity.HIGH,
    patterns=((r"\bgithub_pat_[A-Za-z0-9_]{22,}\b", 0),),
    weight=110,
    description="GitHub fine-grained personal access token.",
)

detector(
    id="slack_token",
    name="Slack API Token",
    category="Communication",
    severity=Severity.CRITICAL,
    patterns=((r"\bxox[baprs]-[A-Za-z0-9\-]{10,72}\b", 0),),
    weight=120,
    description="Slack bot, app, or user token.",
)

detector(
    id="slack_webhook",
    name="Slack Webhook URL",
    category="Communication",
    severity=Severity.HIGH,
    patterns=((r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[0-9A-Za-z]{20,}", 0),),
    weight=70,
    description="Incoming Slack webhook endpoint with signing secret.",
)

detector(
    id="stripe_live_secret",
    name="Stripe Live Secret Key",
    category="Payments",
    severity=Severity.CRITICAL,
    patterns=((r"\bsk_live_[0-9a-zA-Z]{24,}\b", 0),),
    weight=120,
    description="Stripe live secret key.",
)

detector(
    id="stripe_restricted",
    name="Stripe Restricted Key",
    category="Payments",
    severity=Severity.HIGH,
    patterns=((r"\brk_live_[0-9a-zA-Z]{24,}\b", 0),),
    weight=110,
    description="Stripe restricted API key.",
)

detector(
    id="stripe_test_secret",
    name="Stripe Test Secret Key",
    category="Payments",
    severity=Severity.LOW,
    patterns=((r"\bsk_test_[0-9a-zA-Z]{24,}\b", 0),),
    weight=110,
    description="Stripe test secret key (safe to commit, but worth reviewing).",
)

detector(
    id="openai_api_key",
    name="OpenAI API Key",
    category="AI Services",
    severity=Severity.HIGH,
    patterns=((r"\bsk-[A-Za-z0-9]{32,64}\b", 0), (r"\bsk-proj-[A-Za-z0-9_\-]{20,128}\b", 0)),
    min_entropy=3.6,
    weight=100,
    description="OpenAI platform or project key.",
)

detector(
    id="anthropic_api_key",
    name="Anthropic API Key",
    category="AI Services",
    severity=Severity.HIGH,
    patterns=((r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", 0),),
    weight=110,
    description="Anthropic API key.",
)

# -- Package / registry tokens ----------------------------------------------
detector(
    id="npm_access_token",
    name="npm Access Token",
    category="Package Registries",
    severity=Severity.CRITICAL,
    patterns=((r"\bnpm_[A-Za-z0-9]{36}\b", 0),),
    weight=120,
    description="npm registry access token.",
)

detector(
    id="pypi_token",
    name="PyPI API Token",
    category="Package Registries",
    severity=Severity.HIGH,
    patterns=((r"\bpypi-[A-Za-z0-9_\-]{20,}\b", 0),),
    weight=110,
    description="PyPI upload token (pypi-<user>-<token>).",
)

# -- Messaging / transactional ----------------------------------------------
detector(
    id="twilio_api_key",
    name="Twilio API Key",
    category="Communication",
    severity=Severity.HIGH,
    patterns=((r"\bSK[0-9a-f]{32}\b", 0),),
    weight=100,
    description="Twilio API key SID (SK followed by 32 hex chars).",
)

detector(
    id="sendgrid_api_key",
    name="SendGrid API Key",
    category="Communication",
    severity=Severity.HIGH,
    patterns=((r"\bSG\.[A-Za-z0-9_\-\.]{22,}\b", 0),),
    weight=110,
    description="SendGrid API key (SG.xxxx).",
)

detector(
    id="mailgun_api_key",
    name="Mailgun API Key",
    category="Communication",
    severity=Severity.HIGH,
    patterns=((r"\bkey-[0-9a-zA-Z]{32}\b", 0),),
    weight=110,
    description="Mailgun API key.",
)

# -- Private keys & crypto material -----------------------------------------
detector(
    id="private_key",
    name="Private Key Material",
    category="Cryptographic Keys",
    severity=Severity.CRITICAL,
    patterns=(
        (r"-----BEGIN ((?:[A-Z0-9]+ )+)?PRIVATE KEY( BLOCK)?-----", 0),
        (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", 0),
    ),
    weight=200,
    description="PEM-encoded private key block header.",
)

detector(
    id="jwt_token",
    name="JWT / Signed Token",
    category="Authentication",
    severity=Severity.HIGH,
    patterns=((r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", 0),),
    confidence=Confidence.MEDIUM,
    weight=70,
    description="Three-part base64url token consistent with a JSON Web Token.",
)

detector(
    id="bearer_token",
    name="Bearer Token",
    category="Authentication",
    severity=Severity.HIGH,
    patterns=((r"(?i)\bBearer[ =]+([A-Za-z0-9\-._~+/]+={0,2})", 1),),
    confidence=Confidence.MEDIUM,
    min_entropy=4.0,
    weight=50,
    description="Authorization header or assignment carrying a bearer credential.",
)

# -- URLs / connection strings with embedded credentials --------------------
detector(
    id="credentials_in_url",
    name="Credentials in URL",
    category="URL Credentials",
    severity=Severity.CRITICAL,
    patterns=((r"\b[a-z][a-z0-9+.\-]*://([^:\s/@]+):([^@/\s]+)@[^\s]+", 2),),
    weight=90,
    description="A URL embedding username:password before the host.",
)

detector(
    id="connection_string",
    name="Database Connection String",
    category="URL Credentials",
    severity=Severity.CRITICAL,
    patterns=(
        (r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|rabbitmq|mssql|snowflake)://[^\s'\"]+", 0),
    ),
    weight=60,
    description="Datasource URL that may embed credentials.",
)

# -- Generic assignments -----------------------------------------------------
detector(
    id="password_assignment",
    name="Password / Key Assignment",
    category="Generic Credentials",
    severity=Severity.MEDIUM,
    patterns=(
        (r"(?i)\b(?:password|passwd|pwd|user_password|db_password|ssh_password)\b\s*[:=]\s*[\"']?([^\s\"',;]+)", 1),
        (r"(?i)\b(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|consumer[_-]?secret|access_key|secret_key|token)\b\s*[:=]\s*[\"']?([^\s\"',;]+)", 1),
    ),
    confidence=Confidence.LOW,
    min_entropy=3.6,
    weight=40,
    value_blacklist=(
        "password", "pass", "passwd", "changeme", "change_me", "secret",
        "example", "sample", "yourpassword", "your-secret", "default", "root",
        "admin", "test", "testing", "123456", "12345678", "1234567890",
        "qwerty", "letmein", "welcome", "iloveyou", "monkey", "dragon",
        "undefined", "null", "true", "false", "none", "xxxxx", "xxx",
        "placeholder", "todo", "put-your-key-here", "your_key_here", "",
        "api_key", "api-key", "token", "secret_key", "the-secret",
    ),
    description="Key/value assignment where the value looks like a generic credential.",
)

# -- Generic high-entropy (unknown secret) hints -----------------------------
detector(
    id="high_entropy_string",
    name="High-Entropy String",
    category="Possible Secret",
    severity=Severity.LOW,
    patterns=((r"\b[A-Za-z0-9][A-Za-z0-9_\-\.+/]{23,79}\b", 0),),
    confidence=Confidence.LOW,
    min_entropy=4.3,
    min_character_classes=3,
    weight=5,
    description="A long string with high Shannon entropy that does not match a known format.",
)


# --------------------------------------------------------------------------
# Public helpers
# --------------------------------------------------------------------------
def all_detectors() -> list[Detector]:
    return list(DETECTOR_REGISTRY)


def detectors_by_id() -> dict[str, Detector]:
    return {d.id: d for d in DETECTOR_REGISTRY}