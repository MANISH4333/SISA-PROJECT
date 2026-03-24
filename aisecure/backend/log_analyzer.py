"""
log_analyzer.py — Parses structured log text line-by-line and detects anomalies.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any

from detection_engine import DetectionEngine, Finding


@dataclass
class FlaggedLine:
    line_number: int
    content: str
    findings: List[Finding]
    risk_level: str


@dataclass
class LogAnalysisResult:
    total_lines: int
    flagged_lines: List[FlaggedLine] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    all_findings: List[Finding] = field(default_factory=list)


class LogAnalyzer:
    def __init__(self):
        self._engine = DetectionEngine()

    def analyze(self, log_text: str) -> LogAnalysisResult:
        lines = log_text.splitlines() if log_text else []
        result = LogAnalysisResult(total_lines=len(lines))

        failed_login_streak = 0
        stack_trace_streak = 0
        brute_force_detected = False
        stack_block_detected = False

        for idx, line in enumerate(lines):
            line_number = idx + 1

            # Per-line detection
            dr = self._engine.scan(line, base_line=idx)
            if dr.findings:
                fl = FlaggedLine(
                    line_number=line_number,
                    content=line,
                    findings=dr.findings,
                    risk_level=dr.risk_level,
                )
                result.flagged_lines.append(fl)
                result.all_findings.extend(dr.findings)
                for f in dr.findings:
                    result.stats[f.risk_level] = result.stats.get(f.risk_level, 0) + 1

            # Brute-force streak counter
            lower = line.lower()
            is_failed_login = (
                "failed login" in lower
                or "authentication failed" in lower
                or "login attempt" in lower
            )
            if is_failed_login:
                failed_login_streak += 1
                if failed_login_streak >= 3 and not brute_force_detected:
                    result.anomalies.append(
                        f"Brute-force attack detected: {failed_login_streak} consecutive failed login attempts (starting line {line_number - failed_login_streak + 1})"
                    )
                    brute_force_detected = True
            else:
                failed_login_streak = 0

            # Stack trace block counter
            stripped = line.lstrip()
            is_stack_line = stripped.startswith("at ") or "Exception" in line or "Error" in line
            if is_stack_line:
                stack_trace_streak += 1
                if stack_trace_streak >= 3 and not stack_block_detected:
                    result.anomalies.append(
                        f"Stack trace block detected: {stack_trace_streak}+ consecutive trace lines (starting near line {line_number - stack_trace_streak + 1})"
                    )
                    stack_block_detected = True
            else:
                stack_trace_streak = 0

            # Debug leak
            if "DEBUG=True" in line or "debug mode enabled" in lower:
                result.anomalies.append(f"Debug mode leak detected on line {line_number}")

        return result
