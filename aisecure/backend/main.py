"""
main.py — FastAPI application for AI Secure Data Intelligence Platform.
"""
import io
import os
import sys
import time
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# Ensure backend directory is on path when running from elsewhere
sys.path.insert(0, str(Path(__file__).parent))

from detection_engine import DetectionEngine, PATTERN_REGISTRY, Finding
from log_analyzer import LogAnalyzer
from risk_engine import RiskEngine
from policy_engine import PolicyEngine
import ai_module

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aisecure")

app = FastAPI(title="AI Secure Data Intelligence Platform", version="1.0.0")

# ── CORS ──────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static files ──────────────────────────────────────────
STATIC_DIR = Path(__file__).parent.parent / "frontend" / "static"

# ── Singletons ────────────────────────────────────────────
_detection = DetectionEngine()
_log_analyzer = LogAnalyzer()
_risk_engine = RiskEngine()
_policy_engine = PolicyEngine()


# ──────────────────────────────────────────────────────────
# Pydantic schemas
# ──────────────────────────────────────────────────────────
class AnalyzeOptions(BaseModel):
    mask: bool = True
    block_high_risk: bool = False
    log_analysis: bool = False


class AnalyzeRequest(BaseModel):
    input_type: str = "text"   # text | sql | chat | log
    content: str
    options: AnalyzeOptions = AnalyzeOptions()


# ──────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────
def _finding_to_dict(f: Finding) -> dict:
    return {
        "type": f.type,
        "risk_level": f.risk_level,
        "score": f.score,
        "line_number": f.line_number,
        "raw_value": f.raw_value,
        "masked_value": f.masked_value,
        "context": f.context,
    }


def _run_analysis(content: str, input_type: str, options: dict) -> dict:
    t0 = time.time()

    use_log = input_type == "log" and options.get("log_analysis", False)

    all_findings = []
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    lines_analyzed = 1
    anomalies = []

    if use_log:
        log_result = _log_analyzer.analyze(content)
        all_findings = log_result.all_findings
        stats = log_result.stats
        lines_analyzed = log_result.total_lines
        anomalies = log_result.anomalies
    else:
        dr = _detection.scan(content)
        all_findings = dr.findings

    risk_report = _risk_engine.calculate(all_findings)

    policy_result = _policy_engine.apply(
        content,
        all_findings,
        risk_report,
        options,
    )

    findings_dicts = [_finding_to_dict(f) for f in all_findings]

    # AI module — never crash
    insights = []
    summary = ""
    try:
        insights = ai_module.generate_insights(all_findings, input_type)
        summary = ai_module.generate_summary(input_type, all_findings, risk_report.risk_level)
    except Exception as exc:
        logger.warning("AI module error (non-fatal): %s", exc)
        summary = f"Scan found {len(all_findings)} issue(s) at {risk_report.risk_level} risk."

    for rl in stats:
        stats[rl] = stats.get(rl, 0)

    processing_time_ms = round((time.time() - t0) * 1000, 2)

    return {
        "summary": summary,
        "content_type": input_type,
        "findings": findings_dicts,
        "risk_score": risk_report.risk_score,
        "risk_level": risk_report.risk_level,
        "action": policy_result.action,
        "insights": insights,
        "masked_content": policy_result.masked_content,
        "processing_time_ms": processing_time_ms,
        "anomalies": anomalies,
        "applied_rules": policy_result.applied_rules,
        "stats": {
            "total_findings": len(all_findings),
            "lines_analyzed": lines_analyzed,
            "risk_breakdown": risk_report.breakdown,
            "ai_powered": ai_module.is_ai_available(),
        },
    }


# ──────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────
@app.get("/")
async def serve_index():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse({"error": "Frontend not found"}, status_code=404)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "ai_available": ai_module.is_ai_available(),
        "version": "1.0.0",
    }


@app.get("/patterns")
async def patterns():
    return PATTERN_REGISTRY


@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    if not req.content or not req.content.strip():
        raise HTTPException(status_code=400, detail="Content must not be empty")
    return _run_analysis(
        req.content,
        req.input_type,
        req.options.model_dump(),
    )


@app.post("/analyze/file")
async def analyze_file(
    file: UploadFile = File(...),
    mask: str = Form("true"),
    block_high_risk: str = Form("false"),
):
    MAX_SIZE = 5 * 1024 * 1024  # 5 MB

    raw = await file.read()
    if len(raw) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds 5 MB limit")

    filename = file.filename or ""
    ext = Path(filename).suffix.lower()

    content = ""
    input_type = "text"

    if ext in (".txt", ".log"):
        content = raw.decode("utf-8", errors="replace")
        input_type = "log"
    elif ext == ".pdf":
        try:
            import pdfplumber
            with pdfplumber.open(io.BytesIO(raw)) as pdf:
                pages = [p.extract_text() or "" for p in pdf.pages]
            content = "\n".join(pages)
            input_type = "text"
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"PDF parsing failed: {exc}")
    elif ext == ".docx":
        try:
            from docx import Document
            doc = Document(io.BytesIO(raw))
            content = "\n".join(p.text for p in doc.paragraphs)
            input_type = "text"
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"DOCX parsing failed: {exc}")
    else:
        raise HTTPException(status_code=415, detail=f"Unsupported file type: {ext}")

    options = {
        "mask": mask.lower() in ("true", "1", "yes"),
        "block_high_risk": block_high_risk.lower() in ("true", "1", "yes"),
        "log_analysis": input_type == "log",
    }

    return _run_analysis(content, input_type, options)


# ── Mount static after routes ─────────────────────────────
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
