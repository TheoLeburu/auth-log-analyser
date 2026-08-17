"""FastAPI front end.

The analyser package imports nothing from here. This module is one interface
onto the engine; app/cli.py is another.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .analyser.pipeline import analyse

STATIC_DIR = Path(__file__).parent / "static"
SAMPLE_LOG = Path(__file__).parent.parent / "samples" / "auth.log"

# Uploads are held in memory during analysis, so the ceiling is deliberate.
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_PASTE_LINES = 50_000

app = FastAPI(
    title="Auth Log Analyser",
    description=(
        "Finds brute-force attempts, credential spraying and successful compromises "
        "in SSH and web authentication logs."
    ),
    version="1.0.0",
)


class AnalyseTextRequest(BaseModel):
    content: str = Field(..., min_length=1, description="Raw log lines")
    bucket_minutes: int = Field(60, ge=1, le=1440)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/")
async def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "dashboard.html")


@app.post("/api/analyse")
async def analyse_upload(
    file: Annotated[UploadFile, File(...)],
    bucket_minutes: int = 60,
) -> dict:
    """Analyse an uploaded log file."""
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File is larger than the {MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit.",
        )

    text = raw.decode("utf-8", errors="replace")
    report = await asyncio.to_thread(
        analyse, text.splitlines(), bucket_minutes=bucket_minutes
    )
    payload = report.to_dict()
    payload["source"] = file.filename
    return payload


@app.post("/api/analyse-text")
async def analyse_text(payload: AnalyseTextRequest) -> dict:
    """Analyse pasted log lines."""
    lines = payload.content.splitlines()
    if len(lines) > MAX_PASTE_LINES:
        raise HTTPException(
            status_code=413,
            detail=f"Paste is longer than {MAX_PASTE_LINES} lines. Upload the file instead.",
        )

    report = await asyncio.to_thread(analyse, lines, bucket_minutes=payload.bucket_minutes)
    result = report.to_dict()
    result["source"] = "pasted text"
    return result


@app.get("/api/sample")
async def analyse_sample() -> dict:
    """Analyse the bundled sample log, so the dashboard has something to show."""
    if not SAMPLE_LOG.exists():
        raise HTTPException(status_code=404, detail="Sample log is not present in this deployment.")

    text = SAMPLE_LOG.read_text(encoding="utf-8", errors="replace")
    report = await asyncio.to_thread(analyse, text.splitlines())
    payload = report.to_dict()
    payload["source"] = "samples/auth.log"
    return payload
