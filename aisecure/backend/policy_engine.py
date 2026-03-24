"""
policy_engine.py — Applies data masking and blocking policies to scanned content.
"""
from dataclasses import dataclass, field
from typing import List, Any, Dict


@dataclass
class PolicyResult:
    action: str                        # allowed | masked | blocked
    masked_content: str
    applied_rules: List[str] = field(default_factory=list)


class PolicyEngine:
    def apply(
        self,
        content: str,
        findings: list,
        risk_report: Any,
        options: Dict[str, bool],
    ) -> PolicyResult:
        """
        Apply policy rules to *content* based on *options*.

        options keys:
          mask          (bool) — replace raw values with masked versions
          block_high_risk (bool) — block if risk is high or critical
          log_analysis  (bool) — informational, no extra action here
        """
        mask = options.get("mask", True)
        block_high_risk = options.get("block_high_risk", False)

        applied_rules: List[str] = []
        risk_level = risk_report.risk_level if hasattr(risk_report, "risk_level") else risk_report.get("risk_level", "low")

        # Rule 1: Block
        if block_high_risk and risk_level in ("high", "critical"):
            applied_rules.append(f"BLOCK: content blocked due to {risk_level} risk level")
            return PolicyResult(
                action="blocked",
                masked_content="[BLOCKED: Content withheld due to high/critical risk]",
                applied_rules=applied_rules,
            )

        # Rule 2: Mask
        masked_content = content
        if mask and findings:
            applied_rules.append("MASK: sensitive values replaced with masked equivalents")
            for f in findings:
                if isinstance(f, dict):
                    raw = f.get("raw_value", "")
                    masked = f.get("masked_value", "***")
                else:
                    raw = f.raw_value
                    masked = f.masked_value
                if raw and raw != masked:
                    masked_content = masked_content.replace(raw, masked)
            return PolicyResult(
                action="masked",
                masked_content=masked_content,
                applied_rules=applied_rules,
            )

        # Rule 3: Allow
        applied_rules.append("ALLOW: content passed policy checks")
        return PolicyResult(
            action="allowed",
            masked_content=content,
            applied_rules=applied_rules,
        )
