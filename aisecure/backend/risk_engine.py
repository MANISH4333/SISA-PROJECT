"""
risk_engine.py — Aggregates findings into a risk score and report.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class RiskReport:
    risk_score: int
    risk_level: str
    breakdown: Dict[str, int] = field(default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    top_findings: List[Any] = field(default_factory=list)


def _risk_level_from_score(score: int) -> str:
    if score >= 10:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


class RiskEngine:
    def calculate(self, findings: list) -> RiskReport:
        """Compute a RiskReport from a list of Finding objects or dicts."""
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_score = 0

        for f in findings:
            if isinstance(f, dict):
                rl = f.get("risk_level", "low")
                sc = f.get("score", 0)
            else:
                rl = f.risk_level
                sc = f.score
            breakdown[rl] = breakdown.get(rl, 0) + 1
            total_score += sc

        risk_score = min(total_score, 20)
        risk_level = _risk_level_from_score(risk_score)

        # Top 3 findings by score (descending)
        def _score(f):
            return f.get("score", 0) if isinstance(f, dict) else f.score

        top_findings = sorted(findings, key=_score, reverse=True)[:3]

        return RiskReport(
            risk_score=risk_score,
            risk_level=risk_level,
            breakdown=breakdown,
            top_findings=top_findings,
        )
