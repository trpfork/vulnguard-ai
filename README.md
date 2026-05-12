# VulnGuard AI

> **AI-powered GitHub security vulnerability scanner** — a production-grade portfolio project demonstrating LangGraph agents, real-time SSE streaming, and AI evaluation suites.

![Dashboard](docs/assets/dashboard-preview.png)

## What it does

VulnGuard AI scans source code repositories for security vulnerabilities using a multi-step AI agent built with LangGraph. It streams the agent's reasoning to a Next.js dashboard in real time via Server-Sent Events.

**Scan → Verify → Patch** — three LLM calls, each with a focused role:

| Node | Role |
|------|------|
| `scan` | Read source file, identify vulnerabilities (severity, CWE, OWASP category) |
| `verify` | Second-pass review to confirm findings and filter false positives |
| `patch` | Generate secure code patches for each confirmed vulnerability |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | Next.js 15, TypeScript, Vanilla CSS (dark/light themes) |
| **Backend** | FastAPI + uvicorn |
| **AI Agent** | LangGraph `StateGraph` (Scan-Verify-Patch loop) |
| **LLM** | Google Gemini → OpenAI GPT-4o → Anthropic Claude (fallback chain) |
| **Streaming** | Server-Sent Events (`/api/stream`) |
| **Evaluation** | Custom eval suite (Accuracy, Precision, Recall, F1) |

## Project Structure

```
.
├── frontend/                 # Next.js 15 dashboard
│   ├── app/
│   │   ├── dashboard/page.tsx
│   │   └── globals.css
│   ├── components/
│   │   ├── AgentFeed.tsx     # Real-time SSE feed
│   │   ├── Sidebar.tsx
│   │   └── ThemeToggle.tsx   # Dark/light mode
│   ├── hooks/
│   │   └── useAgentStream.ts # EventSource hook
│   └── context/
│       └── ThemeContext.tsx
│
├── backend/
│   ├── main.py               # FastAPI app + /api/stream SSE endpoint
│   ├── agents/
│   │   ├── scanner.py        # LangGraph StateGraph (Scan-Verify-Patch)
│   │   ├── state.py          # TypedDict state + reducers
│   │   └── llm_client.py     # LLM fallback chain
│   ├── scripts/
│   │   └── eval_suite.py     # AI evaluation benchmarking tool
│   └── data/
│       └── benchmark.json    # 20-sample ground-truth dataset
│
├── tests/
│   └── mocks/
│       └── vuln.php          # Mock vulnerable PHP file for testing
│
└── docs/
    └── plans/
        └── 2026-05-12-vulnguard-ai-implementation.md
```

## Quick Start

### 1. Set up environment variables

```bash
cp .env.example .env
# Edit .env and add at least one API key:
#   GEMINI_API_KEY   — Google AI Studio (free tier available)
#   OPENAI_API_KEY   — OpenAI
#   ANTHROPIC_API_KEY — Anthropic
```

### 2. Install backend dependencies

```bash
pip install -r backend/requirements.txt
```

### 3. Start the FastAPI backend

```bash
uvicorn backend.main:app --reload --port 8000
```

### 4. Start the Next.js frontend

```bash
cd frontend
npm install
npm run dev
```

### 5. Open the dashboard

Navigate to **http://localhost:3000/dashboard** and click **▶ Run Scan**.

## CLI Usage

### Run the scanner on any file

```bash
python backend/agents/scanner.py --test-file tests/mocks/vuln.php
```

Expected output (with a real API key):
```
[CRITICAL] Broken Access Control (CWE-639) — Line 24  [CONFIRMED]
[HIGH    ] SQL Injection (CWE-89) — Line 38            [CONFIRMED]
[HIGH    ] Reflected XSS (CWE-79) — Line 52            [CONFIRMED]
[MEDIUM  ] Hardcoded Credential (CWE-798) — Line 14   [CONFIRMED]
```

### Run the evaluation suite

```bash
python backend/scripts/eval_suite.py
```

Outputs Accuracy, Precision, Recall, F1 across 20 benchmark samples.

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/api/stream?file_path=...` | GET | SSE stream — scan a file in real time |
| `/api/scan` | POST | Synchronous scan, returns full JSON result |
| `/api/findings` | GET | Mock historical vulnerability data |
| `/docs` | GET | Auto-generated FastAPI Swagger UI |

### SSE Event Types (`/api/stream`)

```
started  → { file_path, message }
log      → { type, message, detail, node, level }
finding  → { severity, vuln_type, cwe, line, description, confidence }
patch    → { finding_id, description, patched_code, explanation }
error    → { message }
done     → { success, findings_count, confirmed_count, patches_count }
```

## Key Engineering Decisions

### LangGraph Conditional Routing

```
START → [scan] ──(no findings)──→ END
                ──(findings found)──→ [verify] → [patch] → END
```

The graph skips `verify` and `patch` entirely if scan finds nothing — no wasted LLM calls.

### LLM Fallback Chain

```python
Gemini (gemini-3-flash-preview)  → if GEMINI_API_KEY set
  OpenAI (gpt-4o)                → elif OPENAI_API_KEY set
    Anthropic (claude-sonnet)    → elif ANTHROPIC_API_KEY set
      Mock                       → always works (for offline testing)
```

### SSE Streaming Architecture

```
Browser (EventSource)
    ↕ SSE
FastAPI /api/stream
    ↕ generator (yields per-node)
LangGraph graph.stream()
    ↕ node updates
scanner_graph (scan → verify → patch)
```

### Theme System

CSS variables + `data-theme` attribute on `<html>` — no flash of unstyled content via inline anti-FOUC script in `layout.tsx`.

## Evaluation Metrics

Run `eval_suite.py` to benchmark the agent against 20 hand-labeled code samples (10 vulnerable, 10 clean) across PHP, Python, and JavaScript. Reports:

- **Accuracy** — binary label (vulnerable/clean) correctness
- **Precision** — false-positive rate
- **Recall** — miss rate
- **F1** — overall balance
- **Per-type hit rate** — which vulnerability types are detected most reliably

## Portfolio Signals Demonstrated

| Signal | Implementation |
|--------|---------------|
| LangGraph multi-step agent | `backend/agents/scanner.py` |
| Structured output / JSON parsing | `_extract_json()` in scanner |
| Real-time SSE streaming | `/api/stream` + `useAgentStream` hook |
| LLM fallback chain | `llm_client.py` |
| AI evaluation suite | `eval_suite.py` |
| Dark/light theme system | `ThemeContext` + CSS variables |
| Anti-FOUC | Inline script in `layout.tsx` |
| Persistent state | `localStorage` theme preference |
