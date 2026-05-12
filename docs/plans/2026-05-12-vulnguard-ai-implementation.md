# VulnGuard AI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a premium web dashboard that uses an AI Agent to identify, verify, and fix security vulnerabilities in GitHub repositories.

**Architecture:** A Next.js 15 frontend with a FastAPI (Python) backend for the AI Agent. The agent uses LangGraph for the "Scan-Verify-Patch" loop and streams its reasoning to the frontend via Server-Sent Events (SSE).

**Tech Stack:** 
- **Frontend**: Next.js 15, Tailwind CSS, Framer Motion, Monaco Editor.
- **Backend**: FastAPI, LangGraph, OpenAI/Anthropic SDKs.
- **Database**: PostgreSQL (Prisma), Pinecone (for vulnerability pattern matching).
- **Infrastructure**: GitHub API, Docker (for sandboxed verification).

---

### Phase 1: Foundation & Dashboard UI

#### Task 1.1: Project Scaffolding
**Files:**
- Create: `frontend/package.json`
- Create: `backend/main.py`
- Create: `.env`

**Step 1: Initialize Next.js project**
Run: `npx -y create-next-app@latest frontend --typescript --tailwind --eslint`

**Step 2: Initialize FastAPI project**
Run: `mkdir backend && cd backend && pip install fastapi uvicorn langgraph openai`

**Step 3: Setup .env template**
Create `.env` with placeholders for `OPENAI_API_KEY`, `GITHUB_TOKEN`, and `DATABASE_URL`.

**Step 4: Commit**
```bash
git add .
git commit -m "chore: initial project scaffolding"
```

#### Task 1.2: Premium Dashboard Layout
**Files:**
- Create: `frontend/app/dashboard/page.tsx`
- Modify: `frontend/app/globals.css`

**Step 1: Define design tokens**
Update `globals.css` with a sleek dark-mode palette (deep purples/blacks).

**Step 2: Build the Sidebar and Feed components**
Create a responsive layout with a "Live Agent Feed" panel on the right and a "Repo List" on the left.

**Step 3: Commit**
```bash
git commit -m "feat: add dashboard layout and design system"
```

---

### Phase 2: The AI Core (Agentic Logic)

#### Task 2.1: The Scanning Node
**Files:**
- Create: `backend/agents/scanner.py`

**Step 1: Implement the scanner logic**
Write a LangGraph node that takes a file path, reads it via GitHub API, and asks an LLM to identify security flaws.

**Step 2: Test with a mock vulnerable file**
Run: `python backend/agents/scanner.py --test-file tests/mocks/vuln.php`
Expected: Agent identifies "Broken Access Control".

---

### Phase 3: The Interactive Web Experience

#### Task 3.1: Streaming "Agent Thinking"
**Files:**
- Modify: `backend/main.py`
- Create: `frontend/hooks/useAgentStream.ts`

**Step 1: Setup SSE in FastAPI**
Create an endpoint `/api/stream` that yields logs from the LangGraph execution.

**Step 2: Connect frontend hook**
Implement a hook that listens to the SSE stream and updates the dashboard feed in real-time.

---

### Phase 4: Evaluation & Polish

#### Task 4.1: AI Evaluation Suite
**Files:**
- Create: `backend/scripts/eval_suite.py`

**Step 1: Define benchmark data**
Add a JSON file with 20 code samples and their "Ground Truth" vulnerability status.

**Step 2: Run evaluation**
Run: `python backend/scripts/eval_suite.py`
Expected: Output showing Accuracy, Precision, and Recall scores.
