"""
VulnGuard AI — FastAPI Backend
Serves the AI agent via REST and Server-Sent Events (SSE).

Endpoints:
  GET  /health              — health check
  POST /api/scan            — run a full scan, returns JSON result
  GET  /api/stream?file_path=...  — stream agent logs in real-time via SSE
  GET  /api/findings        — return mock historical findings for dashboard

Run with:
  uvicorn backend.main:app --reload --port 8000
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Add project root so backend.agents imports work when run from project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.agents.scanner import scanner_graph, build_scanner_graph
from backend.agents.state import ScanState


# ─────────────────────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="VulnGuard AI",
    description="AI-powered security vulnerability scanner using LangGraph agents",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    file_path: str
    repo: str = "local"


class ScanResult(BaseModel):
    file_path: str
    findings_count: int
    confirmed_count: int
    patches_count: int
    findings: list
    patches: list
    logs: list
    error: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# SSE helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sse_event(event: str, data: dict) -> str:
    """Format a Server-Sent Event string."""
    payload = json.dumps(data, default=str)
    return f"event: {event}\ndata: {payload}\n\n"


def _node_to_step_type(node: str) -> str:
    """Map LangGraph node name to frontend AgentStep type."""
    mapping = {
        "scan": "scanning",
        "verify": "verifying",
        "patch": "patching",
    }
    return mapping.get(node, "scanning")


async def _stream_scan(file_path: str) -> AsyncGenerator[str, None]:
    """
    Run the LangGraph scanner graph and yield SSE events for each log entry.

    LangGraph streaming pattern (from LangGraph skill):
      Use graph.stream() to iterate over state snapshots per node.
      Each snapshot contains the updated fields returned by that node.
    """
    initial_state: ScanState = {
        "file_path": file_path,
        "file_content": "",
        "findings": [],
        "verified_indices": [],
        "patches": [],
        "logs": [],
        "current_node": "scan",
        "error": None,
    }

    # Send a "started" event so the frontend can clear previous state
    yield _sse_event("started", {
        "file_path": file_path,
        "message": f"Starting scan of {file_path}",
    })

    seen_log_count = 0
    final_state = None

    try:
        # graph.stream() yields one dict per node update
        # Each dict has keys = node_name, value = the partial state returned by that node
        for chunk in scanner_graph.stream(initial_state):
            # chunk looks like: {"scan": {"findings": [...], "logs": [...], ...}}
            for node_name, node_output in chunk.items():
                # Stream each new log entry that appeared in this node
                new_logs = node_output.get("logs", [])
                for log in new_logs[seen_log_count:]:
                    step_type = _node_to_step_type(log.get("node", node_name))
                    yield _sse_event("log", {
                        "type": step_type,
                        "message": log.get("message", ""),
                        "detail": log.get("detail"),
                        "node": log.get("node", node_name),
                        "level": log.get("level", "info"),
                    })
                    # Small delay so the frontend can animate each entry
                    await asyncio.sleep(0.15)

                seen_log_count = len(new_logs)

                # Track new findings as they're discovered
                findings = node_output.get("findings", [])
                if findings and node_name == "scan":
                    for f in findings:
                        yield _sse_event("finding", {
                            "severity": f.get("severity"),
                            "vuln_type": f.get("vuln_type"),
                            "cwe": f.get("cwe"),
                            "line": f.get("line"),
                            "description": f.get("description"),
                            "confidence": f.get("confidence"),
                            "owasp_category": f.get("owasp_category"),
                        })
                        await asyncio.sleep(0.1)

                # Emit patch events as they're generated
                patches = node_output.get("patches", [])
                if patches and node_name == "patch":
                    for p in patches:
                        yield _sse_event("patch", {
                            "finding_id": p.get("finding_id"),
                            "description": p.get("description"),
                            "patched_code": p.get("patched_code", "")[:500],
                            "explanation": p.get("explanation"),
                        })
                        await asyncio.sleep(0.1)

                # Keep last node output for the final summary
                final_state = node_output

    except Exception as e:
        yield _sse_event("error", {
            "message": str(e),
            "type": "error",
        })
        yield _sse_event("done", {"success": False, "error": str(e)})
        return

    # Send the final summary event
    findings = final_state.get("findings", []) if final_state else []
    patches = final_state.get("patches", []) if final_state else []
    verified = final_state.get("verified_indices", []) if final_state else []

    yield _sse_event("done", {
        "success": True,
        "findings_count": len(findings),
        "confirmed_count": len(verified) if isinstance(verified[0] if verified else 0, int) else len(verified),
        "patches_count": len(patches),
        "error": None,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "VulnGuard AI"}


@app.get("/")
async def root():
    return {"message": "VulnGuard AI API is running. See /docs for API reference."}


@app.get("/api/stream")
async def stream_scan(
    file_path: str = Query(..., description="Local path or owner/repo/path to scan"),
):
    """
    Stream the agent's scanning process via Server-Sent Events.

    Events emitted:
      started  — scan has begun
      log      — a single agent log entry (maps to AgentFeed step)
      finding  — a vulnerability was detected
      patch    — a patch suggestion was generated
      error    — an error occurred
      done     — scan complete with summary stats
    """
    return StreamingResponse(
        _stream_scan(file_path),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",   # Disable nginx buffering
        },
    )


@app.post("/api/scan", response_model=ScanResult)
async def run_scan(request: ScanRequest):
    """
    Run a full scan synchronously and return the complete JSON result.
    Use /api/stream for the real-time streaming experience.
    """
    initial_state: ScanState = {
        "file_path": request.file_path,
        "file_content": "",
        "findings": [],
        "verified_indices": [],
        "patches": [],
        "logs": [],
        "current_node": "scan",
        "error": None,
    }

    try:
        result = scanner_graph.invoke(initial_state)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    findings = result.get("findings", [])
    patches = result.get("patches", [])
    verified = result.get("verified_indices", [])

    return ScanResult(
        file_path=request.file_path,
        findings_count=len(findings),
        confirmed_count=len(verified),
        patches_count=len(patches),
        findings=findings,
        patches=patches,
        logs=result.get("logs", []),
        error=result.get("error"),
    )


@app.get("/api/findings")
async def get_mock_findings():
    """
    Return mock historical vulnerability data for the dashboard table.
    In Phase 4 this will be backed by PostgreSQL.
    """
    return {
        "findings": [
            {
                "id": "f-001",
                "severity": "critical",
                "vuln_type": "Broken Access Control",
                "file": "src/auth/middleware.php",
                "line": 47,
                "cwe": "CWE-639",
                "status": "patching",
                "owasp_category": "A01:2021",
            },
            {
                "id": "f-002",
                "severity": "high",
                "vuln_type": "SQL Injection",
                "file": "src/api/users.php",
                "line": 112,
                "cwe": "CWE-89",
                "status": "open",
                "owasp_category": "A03:2021",
            },
            {
                "id": "f-003",
                "severity": "high",
                "vuln_type": "Reflected XSS",
                "file": "src/templates/profile.html",
                "line": 23,
                "cwe": "CWE-79",
                "status": "open",
                "owasp_category": "A03:2021",
            },
            {
                "id": "f-004",
                "severity": "high",
                "vuln_type": "Unrestricted File Upload",
                "file": "src/upload/handler.php",
                "line": 34,
                "cwe": "CWE-434",
                "status": "open",
                "owasp_category": "A04:2021",
            },
            {
                "id": "f-005",
                "severity": "medium",
                "vuln_type": "Hardcoded Credential",
                "file": "config/database.php",
                "line": 8,
                "cwe": "CWE-798",
                "status": "patched",
                "owasp_category": "A07:2021",
            },
            {
                "id": "f-006",
                "severity": "medium",
                "vuln_type": "Session Fixation",
                "file": "src/session/manager.php",
                "line": 19,
                "cwe": "CWE-384",
                "status": "patched",
                "owasp_category": "A07:2021",
            },
        ],
        "stats": {
            "total": 6,
            "critical": 1,
            "high": 3,
            "medium": 2,
            "patched": 2,
        },
    }
