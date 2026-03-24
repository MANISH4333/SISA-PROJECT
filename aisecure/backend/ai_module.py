"""
ai_module.py — Groq-powered insights and summaries with full rule-based fallback.
"""
import os
import json
import logging
from typing import List

from dotenv import load_dotenv
from pathlib import Path

# Search for .env in backend/ first, then one level up (aisecure/)
_env_path = Path(__file__).parent / ".env"
if not _env_path.exists():
    _env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=_env_path)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────
# Groq client (optional)
# ──────────────────────────────────────────────────────────
_client = None
_ai_available = False

try:
    from groq import Groq
    _key = os.getenv("GROQ_API_KEY", "").strip()
    if _key and _key != "your_groq_key_here":
        _client = Groq(api_key=_key)
        _ai_available = True
        logger.info("Groq AI client initialised successfully.")
    else:
        logger.info("GROQ_API_KEY not set — using rule-based fallback.")
except Exception as exc:
    logger.warning("Groq SDK unavailable: %s", exc)


def is_ai_available() -> bool:
    return _ai_available


# ──────────────────────────────────────────────────────────
# Rule-based fallback advice
# ──────────────────────────────────────────────────────────
_FALLBACK_ADVICE: dict = {
    "password":        "Plaintext password detected — hash with bcrypt immediately",
    "aws_key":         "AWS key exposed — revoke in IAM console immediately",
    "sql_injection":   "SQL injection pattern found — use parameterised queries",
    "credit_card":     "Credit card data exposed — enforce PCI-DSS tokenisation",
    "api_key":         "API key leaked — rotate and store in secrets manager",
    "secret_key":      "Secret key exposed — rotate and store in vault",
    "bearer_token":    "Bearer token found — invalidate and re-issue immediately",
    "failed_login":    "Brute-force detected — enable account lock-out & rate limiting",
    "stack_trace":     "Stack trace in logs — suppress in production, use log levels",
    "ipv4_address":    "Internal IP exposed — review network segmentation policies",
    "debug_mode":      "Debug mode enabled in production — disable immediately",
    "email_address":   "Email address in logs — apply PII scrubbing before logging",
    "phone_number":    "Phone number exposed — apply PII masking in logs",
}

_DEFAULT_ADVICE = "Review this finding and apply least-privilege security controls"


def _call_groq(prompt: str, max_tokens: int = 256) -> str:
    """Call Groq API and return the raw response text."""
    completion = _client.chat.completions.create(
        model="llama3-8b-8192",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        temperature=0.3,
    )
    return completion.choices[0].message.content.strip()


# ──────────────────────────────────────────────────────────
# Public functions
# ──────────────────────────────────────────────────────────
def generate_insights(findings: list, content_type: str) -> List[str]:
    """Return 3-5 short, actionable security insights."""
    if not findings:
        return ["No sensitive findings detected — content appears clean"]

    types_summary = ", ".join({f.get("type", str(f)) if isinstance(f, dict) else f.type for f in findings})

    if _ai_available:
        try:
            prompt = (
                f'You are a security analyst. '
                f'Content type: {content_type}. '
                f'Detected issues: {types_summary}. '
                f'Give 3-5 short actionable security insights, max 12 words each. '
                f'Return a JSON array of strings only, no markdown, no explanation.'
            )
            raw = _call_groq(prompt, max_tokens=300)
            # Strip markdown code fences if present
            raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            insights = json.loads(raw)
            if isinstance(insights, list) and insights:
                return [str(i) for i in insights[:5]]
        except Exception as exc:
            logger.warning("Groq insights failed, using fallback: %s", exc)

    # Fallback
    seen = set()
    result = []
    for f in findings:
        ftype = f.get("type") if isinstance(f, dict) else f.type
        if ftype not in seen:
            seen.add(ftype)
            result.append(_FALLBACK_ADVICE.get(ftype, _DEFAULT_ADVICE))
    return result[:5] if result else [_DEFAULT_ADVICE]


def generate_summary(content_type: str, findings: list, risk_level: str) -> str:
    """Return a 1-2 sentence security scan summary."""
    n = len(findings)
    if n == 0:
        return f"Scan of {content_type} content completed — no sensitive data detected."

    types_list = list({f.get("type") if isinstance(f, dict) else f.type for f in findings})
    types_str = ", ".join(types_list[:4])

    if _ai_available:
        try:
            prompt = (
                f'In 1-2 sentences summarise this security scan: '
                f'type={content_type}, risk={risk_level}, found={types_str}. '
                f'Be direct and professional. No markdown.'
            )
            raw = _call_groq(prompt, max_tokens=120)
            if raw:
                return raw
        except Exception as exc:
            logger.warning("Groq summary failed, using fallback: %s", exc)

    # Fallback
    top = types_str if types_str else "unknown issues"
    return (
        f"Scan found {n} issue{'s' if n != 1 else ''} including {top} "
        f"at {risk_level} risk level. Immediate remediation is recommended."
    )
