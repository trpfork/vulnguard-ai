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
from fastapi.responses import StreamingResponse, RedirectResponse
from pydantic import BaseModel
import httpx
from dotenv import load_dotenv

load_dotenv()

# Add project root so backend.agents imports work when run from project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.agents.scanner import scanner_graph, build_scanner_graph
from backend.agents.state import ScanState
from backend.models import User, Finding, Patch, create_db_and_tables, engine
from sqlmodel import Session, select


# ─────────────────────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="VulnGuard AI",
    description="AI-powered security vulnerability scanner using LangGraph agents",
    version="0.1.0",
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

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
    access_token: str | None = None


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


async def _stream_scan(file_path: str, access_token: str | None = None) -> AsyncGenerator[str, None]:
    """
    Run the LangGraph scanner graph and yield SSE events for each log entry.
    """
    initial_state: ScanState = {
        "file_path": file_path,
        "file_content": "",
        "access_token": access_token,
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

    final_findings = []
    final_patches = []
    seen_logs = set()

    try:
        # Using astream for async streaming
        async for event in scanner_graph.astream(initial_state, config={"configurable": {"thread_id": "1"}}):
            # event is a dict: {node_name: {updated_state_keys}}
            for node_name, output in event.items():
                # 1. Handle logs
                if "logs" in output:
                    for log in output["logs"]:
                        # Use a simple deduplication if logs are repeated in state
                        log_key = f"{log.get('node')}:{log.get('message')}"
                        if log_key not in seen_logs:
                            seen_logs.add(log_key)
                            step_type = _node_to_step_type(log.get("node", node_name))
                            yield _sse_event("log", {
                                "type": step_type,
                                "message": log.get("message", ""),
                                "detail": log.get("detail"),
                                "node": log.get("node", node_name),
                                "level": log.get("level", "info"),
                            })
                            await asyncio.sleep(0.05)
                
                # 2. Handle findings
                if "findings" in output:
                    # In LangGraph, usually the whole list is returned or appended.
                    # We only want to stream NEW findings if possible, but for simplicity
                    # we can stream them as they appear in the 'scan' node output.
                    for finding in output["findings"]:
                        if finding not in final_findings:
                            final_findings.append(finding)
                            yield _sse_event("finding", finding)
                            await asyncio.sleep(0.1)
                
                # 3. Handle patches
                if "patches" in output:
                    for patch in output["patches"]:
                        if patch not in final_patches:
                            final_patches.append(patch)
                            yield _sse_event("patch", patch)
                            await asyncio.sleep(0.1)

        # 4. Save to DB if we have a user
        if access_token:
            with Session(engine) as session:
                user = session.exec(select(User).where(User.access_token == access_token)).first()
                if user:
                    for idx, f in enumerate(final_findings):
                        db_finding = Finding(
                            user_id=user.id,
                            file_path=file_path,
                            line=f.get("line", 0),
                            severity=f.get("severity", "medium"),
                            vuln_type=f.get("vuln_type", "unknown"),
                            cwe=f.get("cwe", ""),
                            description=f.get("description", ""),
                            code_snippet=f.get("code_snippet", ""),
                            confidence=f.get("confidence", 0.0),
                            owasp_category=f.get("owasp_category", ""),
                            status="open"
                        )
                        session.add(db_finding)
                        session.commit()
                        session.refresh(db_finding)

                        # Match patches by finding_id (which is the index as a string)
                        for p in final_patches:
                            if p.get("finding_id") == str(idx):
                                db_patch = Patch(
                                    finding_id=db_finding.id,
                                    description=p.get("description", ""),
                                    original_code=p.get("original_code", ""),
                                    patched_code=p.get("patched_code", ""),
                                    explanation=p.get("explanation", "")
                                )
                                session.add(db_patch)
                    
                    session.commit()

        yield _sse_event("done", {
            "success": True, 
            "findings_count": len(final_findings), 
            "patches_count": len(final_patches)
        })

    except Exception as e:
        yield _sse_event("error", {
            "message": str(e),
            "type": "error",
        })
        yield _sse_event("done", {"success": False, "error": str(e)})


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
    token: str | None = Query(None, description="GitHub OAuth token"),
):
    """
    SSE endpoint that streams the Scan-Verify-Patch agent workflow.
    """
    if ".." in file_path or file_path.startswith("/") or ":" in file_path:
        raise HTTPException(status_code=400, detail="Invalid path or path traversal detected")

    return StreamingResponse(
        _stream_scan(file_path, token),
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
        "access_token": request.access_token,
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
async def get_findings(token: str = Query(..., description="GitHub OAuth token")):
    """Fetch all saved findings for the authenticated user."""
    with Session(engine) as session:
        user = session.exec(select(User).where(User.access_token == token)).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        statement = select(Finding).where(Finding.user_id == user.id)
        findings = session.exec(statement).all()
        
        return [
            {
                "id": str(f.id),
                "file": f.file_path,
                "line": f.line,
                "severity": f.severity,
                "type": f.vuln_type,
                "description": f.description,
                "cwe": f.cwe,
                "status": f.status,
            }
            for f in findings
        ]


@app.get("/api/findings/{finding_id}/patch")
async def get_patch(finding_id: int, token: str = Query(..., description="GitHub OAuth token")):
    """Fetch the patch associated with a specific finding."""
    with Session(engine) as session:
        user = session.exec(select(User).where(User.access_token == token)).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Ensure finding belongs to user
        finding = session.get(Finding, finding_id)
        if not finding or finding.user_id != user.id:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        patch = session.exec(select(Patch).where(Patch.finding_id == finding_id)).first()
        if not patch:
            raise HTTPException(status_code=404, detail="Patch not found")
        
        return patch


# ─────────────────────────────────────────────────────────────────────────────
# Auth Routes (Phase 1)
# ─────────────────────────────────────────────────────────────────────────────

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

@app.get("/api/auth/github")
async def github_login():
    """Redirect user to GitHub OAuth authorize page."""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GITHUB_CLIENT_ID not configured")
    
    scope = "repo read:user user:email"
    url = f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope={scope}"
    return RedirectResponse(url)


@app.get("/api/auth/callback")
async def github_callback(code: str):
    """Handle the OAuth callback from GitHub."""
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="GitHub OAuth credentials not configured")

    async with httpx.AsyncClient() as client:
        # 1. Exchange code for access token
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            params={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_response.json()
        
        if "error" in token_data:
            raise HTTPException(status_code=400, detail=token_data.get("error_description"))
        
        access_token = token_data.get("access_token")
        
        # 2. Get user profile
        user_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
        user_data = user_response.json()
        
        # 3. Save or update user in database
        with Session(engine) as session:
            statement = select(User).where(User.github_id == str(user_data["id"]))
            user = session.exec(statement).first()
            
            if not user:
                user = User(
                    github_id=str(user_data["id"]),
                    username=user_data["login"],
                    email=user_data.get("email"),
                    access_token=access_token,
                    avatar_url=user_data.get("avatar_url"),
                )
                session.add(user)
            else:
                user.access_token = access_token
                user.username = user_data["login"]
                user.avatar_url = user_data.get("avatar_url")
                session.add(user)
            
            session.commit()

        # For Phase 1/2, we'll redirect back to the frontend with the token (temporary).
        # In Phase 3, the frontend will use this to verify the session.
        frontend_url = "http://localhost:3000/dashboard"
        # Use URL fragment (#) instead of query parameter (?) to protect the token
    return RedirectResponse(f"{frontend_url}#token={access_token}&username={user_data.get('login')}")


@app.get("/api/user/repos")
async def get_user_repos(token: str = Query(..., description="GitHub OAuth token")):
    """Fetch list of repositories for the authenticated user."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.github.com/user/repos",
            params={"sort": "updated", "per_page": 20},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Failed to fetch repositories")
        
        repos = response.json()
        return [
            {
                "id": r["id"],
                "full_name": r["full_name"],
                "description": r["description"],
                "private": r["private"],
                "url": r["html_url"],
            }
            for r in repos
        ]


@app.get("/api/me")
async def get_me(token: str = Query(..., description="GitHub OAuth token")):
    """Get profile of the authenticated user."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Failed to fetch user profile")
        
        return response.json()


@app.get("/api/repos/{owner}/{repo}/contents")
async def get_repo_contents(
    owner: str,
    repo: str,
    path: str = Query("", description="Path within the repository"),
    token: str = Query(..., description="GitHub OAuth token"),
):
    """Fetch files and directories within a repository path."""
    async with httpx.AsyncClient() as client:
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        response = await client.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Failed to fetch contents")
        
        items = response.json()
        if not isinstance(items, list):
            # If path is a file, GitHub returns a single object. 
            # We wrap it in a list to keep the UI simple.
            items = [items]

        return response.json()
