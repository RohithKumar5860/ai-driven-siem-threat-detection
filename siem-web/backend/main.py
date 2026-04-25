"""
AI-Based SIEM Threat Detection System — FastAPI Backend
"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend import ml_model, rule_engine, scorer
from backend.models import BlockedIPEntry, LogEntry, LogResponse, ProcessedLog
from backend import storage
from backend.utils import current_utc_iso, get_logger

logger = get_logger(__name__)

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(_BASE_DIR, "frontend")


# ---------------------------------------------------------------------------
# Lifespan — runs on startup/shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SIEM backend starting up...")
    storage.init_storage()
    ml_model._load_model()   # pre-warm model cache
    yield
    logger.info("SIEM backend shutting down...")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI-Based SIEM Threat Detection",
    description="Hybrid rule-based + ML threat detection with automatic IP blocking.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


# ---------------------------------------------------------------------------
# Routes — UI
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="Frontend not found.")
    return FileResponse(index_path)


# ---------------------------------------------------------------------------
# Routes — API
# ---------------------------------------------------------------------------

@app.post("/log", response_model=LogResponse, summary="Submit a new log entry")
async def submit_log(entry: LogEntry):
    """
    Accept a log entry, run it through the full detection pipeline,
    store the result, and optionally block the source IP.
    """
    # 1) Rule-based detection
    rule_score: int = rule_engine.evaluate(
        entry.source_ip, entry.port, entry.payload_size, entry.action
    )

    # 2) ML-based detection
    ml_anomaly, ml_score = ml_model.predict(entry.port, entry.payload_size)

    # 3) Scoring
    total_score, severity, is_threat = scorer.compute(rule_score, ml_score)

    # 4) Build processed log object
    processed = ProcessedLog(
        source_ip=entry.source_ip,
        port=entry.port,
        payload_size=entry.payload_size,
        action=entry.action,
        rule_score=rule_score,
        ml_score=ml_score,
        total_score=total_score,
        severity=severity,
        is_threat=is_threat,
        ml_anomaly=ml_anomaly,
        blocked=False,
    )

    # 5) Auto-block if threshold reached
    if scorer.should_block(total_score):
        newly_blocked = storage.block_ip(
            entry.source_ip,
            reason=f"Threat score {total_score} >= 70 (severity={severity})",
        )
        processed.blocked = newly_blocked
        if newly_blocked:
            logger.warning(f"AUTO-BLOCK: {entry.source_ip} blocked (score={total_score})")

    # 6) Persist log
    storage.save_log(processed.model_dump())

    return LogResponse(message="Log processed successfully.", log=processed)


@app.get("/logs", summary="Retrieve all logs")
async def get_logs():
    """Return every stored log entry."""
    return JSONResponse(content=storage.get_all_logs())


@app.get("/threats", summary="Retrieve detected threats only")
async def get_threats():
    """Return log entries flagged as threats (total_score > 0)."""
    return JSONResponse(content=storage.get_threats())


@app.get("/blocked-ips", summary="Retrieve blocked IP list")
async def get_blocked_ips():
    """Return all IP addresses that have been automatically blocked."""
    return JSONResponse(content=storage.get_blocked_ips())


@app.post("/reload-model", summary="Reload ML model from disk")
async def reload_model():
    """Hot-reload model.pkl without restarting the server."""
    success = ml_model.reload_model()
    if success:
        return {"message": "ML model reloaded successfully."}
    raise HTTPException(status_code=500, detail="Failed to reload model. Check server logs.")


@app.get("/health", summary="Health check")
async def health():
    model_loaded = ml_model._model is not None
    return {
        "status": "ok",
        "model_loaded": model_loaded,
        "timestamp": current_utc_iso(),
    }
