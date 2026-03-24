"""
detection_engine.py — Scans text for 13 sensitive data / security patterns.
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional


# ──────────────────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────────────────
@dataclass
class Finding:
    type: str
    risk_level: str          # critical / high / medium / low
    score: int
    line_number: int
    raw_value: str
    masked_value: str
    context: str


@dataclass
class DetectionResult:
    findings: List[Finding] = field(default_factory=list)
    total_score: int = 0
    risk_level: str = "low"


# ──────────────────────────────────────────────────────────
# Masking helpers
# ──────────────────────────────────────────────────────────
def _mask_credit_card(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return f"****-****-****-{digits[-4:]}"
    return "****"


def _mask_api_key(value: str) -> str:
    v = value.strip()
    if len(v) <= 6:
        return "***"
    return f"{v[:3]}***{v[-3:]}"


def _mask_email(value: str) -> str:
    parts = value.split("@")
    if len(parts) != 2:
        return "***@***"
    local = parts[0]
    return f"{local[0]}***@{parts[1]}"


def _mask_token(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "***"
    return f"{v[:4]}***{v[-4:]}"


def _mask_password(value: str) -> str:
    return _mask_api_key(value)


# ──────────────────────────────────────────────────────────
# Pattern definitions
# ──────────────────────────────────────────────────────────
# Each entry: (name, risk_level, score, compiled_regex, value_group_index, mask_fn)
_PATTERNS = [
    (
        "password",
        "critical",
        10,
        re.compile(r"(?:password|pwd)\s*[=:]\s*(\S+)", re.IGNORECASE),
        1,
        _mask_password,
    ),
    (
        "aws_key",
        "critical",
        10,
        re.compile(r"(AKIA[0-9A-Z]{16})", re.IGNORECASE),
        1,
        _mask_api_key,
    ),
    (
        "sql_injection",
        "critical",
        10,
        re.compile(
            r"((?:'|\"|`)\s*(?:OR|AND)\s+(?:'|\"|`)?1(?:'|\"|`)?\s*=\s*(?:'|\"|`)?1"
            r"|--\s*$"
            r"|;\s*DROP\s+TABLE"
            r"|UNION\s+SELECT"
            r"|SELECT\s+\*\s+FROM)",
            re.IGNORECASE | re.MULTILINE,
        ),
        1,
        lambda v: "[SQL_INJECTION]",
    ),
    (
        "credit_card",
        "critical",
        10,
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
        0,
        _mask_credit_card,
    ),
    (
        "api_key",
        "high",
        8,
        re.compile(r"(?:api[_-]?key|x-api-key)\s*[=:]\s*(\S+)", re.IGNORECASE),
        1,
        _mask_api_key,
    ),
    (
        "secret_key",
        "high",
        8,
        re.compile(r"(?:secret[_-]?key|client[_-]?secret)\s*[=:]\s*(\S+)", re.IGNORECASE),
        1,
        _mask_api_key,
    ),
    (
        "bearer_token",
        "high",
        7,
        re.compile(r"(?:Authorization\s*:\s*Bearer\s+|Bearer\s+)([\w\-\.]+)", re.IGNORECASE),
        1,
        _mask_token,
    ),
    (
        "failed_login",
        "high",
        8,
        re.compile(r"(failed\s+login|authentication\s+failed|login\s+attempt)", re.IGNORECASE),
        1,
        lambda v: v,
    ),
    (
        "stack_trace",
        "medium",
        4,
        re.compile(r"((?:at\s+[\w\.\$]+\([\w\.]+:\d+\))|(?:Exception|Error)\s*:)", re.IGNORECASE),
        1,
        lambda v: v,
    ),
    (
        "ipv4_address",
        "medium",
        3,
        re.compile(r"\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b"),
        1,
        lambda v: v,
    ),
    (
        "debug_mode",
        "medium",
        3,
        re.compile(r"(DEBUG\s*=\s*True|debug\s+mode\s+enabled)", re.IGNORECASE),
        1,
        lambda v: v,
    ),
    (
        "email_address",
        "low",
        2,
        re.compile(r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"),
        1,
        _mask_email,
    ),
    (
        "phone_number",
        "low",
        2,
        re.compile(r"\b(\+?1?\s*[-.]?\s*\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4})\b"),
        1,
        lambda v: "***-***-****",
    ),
]


def _risk_level_from_score(score: int) -> str:
    if score >= 10:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


# ──────────────────────────────────────────────────────────
# Main engine
# ──────────────────────────────────────────────────────────
class DetectionEngine:
    def scan(self, text: str, base_line: int = 0) -> DetectionResult:
        """Scan *text* (may be multi‑line) and return a DetectionResult."""
        lines = text.splitlines() if text else []
        findings: List[Finding] = []

        for line_offset, line in enumerate(lines):
            actual_line = base_line + line_offset + 1
            self._scan_line(line, actual_line, findings)

        total: int = min(sum(f.score for f in findings), 20)
        risk = _risk_level_from_score(total)
        return DetectionResult(findings=findings, total_score=total, risk_level=risk)

    # ------------------------------------------------------------------
    def _scan_line(self, line: str, line_number: int, findings: List[Finding]) -> None:
        for name, risk_level, score, pattern, grp, mask_fn in _PATTERNS:
            for match in pattern.finditer(line):
                try:
                    raw = match.group(grp)
                except IndexError:
                    raw = match.group(0)
                masked = mask_fn(raw)
                start = max(0, match.start() - 30)
                end = min(len(line), match.end() + 30)
                context = line[start:end].strip()
                findings.append(
                    Finding(
                        type=name,
                        risk_level=risk_level,
                        score=score,
                        line_number=line_number,
                        raw_value=raw,
                        masked_value=masked,
                        context=context,
                    )
                )


# ──────────────────────────────────────────────────────────
# Convenience pattern registry (for GET /patterns)
# ──────────────────────────────────────────────────────────
PATTERN_REGISTRY = [
    {"name": "Password Leak",         "risk_level": "critical", "score": 10, "description": "Detects plain-text passwords in key=value pairs"},
    {"name": "AWS Access Key",        "risk_level": "critical", "score": 10, "description": "AWS IAM key starting with AKIA"},
    {"name": "SQL Injection",         "risk_level": "critical", "score": 10, "description": "Common SQL injection payloads (OR 1=1, DROP TABLE, UNION SELECT)"},
    {"name": "Credit Card Number",    "risk_level": "critical", "score": 10, "description": "Visa, Mastercard, Amex, Discover card numbers"},
    {"name": "API Key",               "risk_level": "high",     "score": 8,  "description": "api_key / x-api-key assignments"},
    {"name": "Secret Key",            "risk_level": "high",     "score": 8,  "description": "secret_key / client_secret assignments"},
    {"name": "Bearer Token",          "risk_level": "high",     "score": 7,  "description": "Authorization: Bearer <token> headers"},
    {"name": "Failed Login",          "risk_level": "high",     "score": 8,  "description": "Failed login or authentication failure messages"},
    {"name": "Stack Trace",           "risk_level": "medium",   "score": 4,  "description": "Java/Python stack trace fragments or Exception messages"},
    {"name": "IPv4 Address",          "risk_level": "medium",   "score": 3,  "description": "Internal or external IP addresses"},
    {"name": "Debug Mode",            "risk_level": "medium",   "score": 3,  "description": "DEBUG=True or debug mode enabled flags"},
    {"name": "Email Address",         "risk_level": "low",      "score": 2,  "description": "Email addresses in content"},
    {"name": "Phone Number",          "risk_level": "low",      "score": 2,  "description": "US/international phone numbers"},
]
