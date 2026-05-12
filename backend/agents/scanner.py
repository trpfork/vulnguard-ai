"""
VulnGuard AI — Scanner Agent (LangGraph)

Implements the Scan-Verify-Patch loop as a LangGraph StateGraph.

Graph topology (from LangGraph skill — Conditional Branching pattern):

    START
      │
      ▼
   [scan]  ──── no findings ──→  END
      │
   found findings
      │
      ▼
  [verify]
      │
      ▼
  [patch]  ─────────────────→  END

Each node:
  - Appends to `state["logs"]` for SSE streaming (Phase 3)
  - Returns only the fields it modifies (LangGraph skill: partial state updates)
  - Is fully standalone and testable

Usage (CLI):
    python backend/agents/scanner.py --test-file tests/mocks/vuln.php
"""

import argparse
import json
import re
import sys
import os
from pathlib import Path
from typing import Annotated, Optional
from operator import add

# Add project root to path so backend imports work regardless of cwd
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from typing import TypedDict
from langgraph.graph import StateGraph, START, END

from backend.agents.state import ScanState, Finding, PatchSuggestion, AgentLog
from backend.agents.llm_client import generate_text


# ─────────────────────────────────────────────────────────────────────────────
# PROMPTS
# ─────────────────────────────────────────────────────────────────────────────

SCANNER_SYSTEM = """\
You are an expert application security engineer (AppSec).
Your job is to identify security vulnerabilities in source code.

You must respond with ONLY a JSON array of findings.
Each finding object must have exactly these fields:
  - severity: "critical" | "high" | "medium" | "low"
  - vuln_type: string (e.g., "Broken Access Control", "SQL Injection")
  - cwe: string (e.g., "CWE-89")
  - line: integer (approximate line number)
  - description: string (clear explanation of the vulnerability)
  - code_snippet: string (the vulnerable code fragment)
  - confidence: float 0.0–1.0
  - owasp_category: string (e.g., "A01:2021 — Broken Access Control")

Focus on real vulnerabilities only. Do not include style issues.
If no vulnerabilities are found, return an empty array: []
"""

SCANNER_PROMPT = """\
Analyze the following source code for security vulnerabilities.
File: {file_path}

```
{file_content}
```

Return a JSON array of all findings. Respond with ONLY the JSON — no prose, no markdown fences.
"""

VERIFIER_SYSTEM = """\
You are a senior security engineer performing a second-pass review.
You will be given a list of candidate vulnerability findings.
Your task: confirm which ones are genuine vulnerabilities (not false positives).

Respond with ONLY a JSON array of integer indices (0-based) from the input list
that represent CONFIRMED vulnerabilities. Example: [0, 2, 3]
If all are confirmed: return all indices. If none: return [].
"""

VERIFIER_PROMPT = """\
File: {file_path}

Source code:
```
{file_content}
```

Candidate findings (0-indexed):
{findings_json}

Return a JSON array of confirmed finding indices only. Respond with ONLY the JSON array.
"""

PATCHER_SYSTEM = """\
You are a senior security engineer who specialises in writing secure code patches.
For each confirmed vulnerability finding provided, generate a patch suggestion.

Respond with ONLY a JSON array of patch objects.
Each patch object must have:
  - finding_id: string (the 0-based index of the finding as a string)
  - description: string (what the patch does)
  - original_code: string (the exact vulnerable code to replace)
  - patched_code: string (the secure replacement code)
  - explanation: string (why this fix eliminates the vulnerability)
"""

PATCHER_PROMPT = """\
File: {file_path}

Source code:
```
{file_content}
```

Confirmed vulnerability findings to patch:
{findings_json}

Generate a secure patch for each finding. Return ONLY the JSON array.
"""


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _extract_json(text: str):
    """Extract JSON from LLM response that may contain markdown fences."""
    # Strip code fences if present
    text = re.sub(r"```(?:json)?\s*", "", text).strip()
    text = text.rstrip("`").strip()
    return json.loads(text)


def _log(node: str, level: str, message: str, detail: Optional[str] = None) -> AgentLog:
    return AgentLog(node=node, level=level, message=message, detail=detail)


def _read_file_content(file_path: str, access_token: Optional[str] = None) -> str:
    """
    Fetch file content. Supports:
    - Local file paths (for testing)
    - GitHub repository paths (owner/repo/path format)
    """
    # 1. Local file
    local = Path(file_path)
    if local.exists():
        return local.read_text(encoding="utf-8")

    # 2. GitHub API (preferred as it handles default branch automatically)
    token = access_token or os.getenv("GITHUB_TOKEN", "")
    if token and "/" in file_path:
        import urllib.request
        import base64
        
        # Basic heuristic: if it has at least 2 slashes, it's likely owner/repo/path
        # e.g. trpfork/devsecops/sqli/src/index.php
        parts = file_path.split("/", 2)
        if len(parts) == 3:
            owner, repo, path = parts[0], parts[1], parts[2]
            api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
            
            try:
                req = urllib.request.Request(api_url, headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/json",
                    "User-Agent": "VulnGuardAI-Agent"
                })
                with urllib.request.urlopen(req) as r:
                    data = json.loads(r.read().decode("utf-8"))
                    if isinstance(data, dict):
                        if data.get("encoding") == "base64" and data.get("content"):
                            # The API returns content as base64 but often with newlines
                            encoded_content = data["content"].replace("\n", "").replace("\r", "")
                            return base64.b64decode(encoded_content).decode("utf-8")
                        elif "download_url" in data:
                            # Fallback to raw download URL if content not in response
                            raw_req = urllib.request.Request(data["download_url"], headers={
                                "Authorization": f"token {token}",
                                "User-Agent": "VulnGuardAI-Agent"
                            })
                            with urllib.request.urlopen(raw_req) as raw_r:
                                return raw_r.read().decode("utf-8")
            except Exception as e:
                # Log to stderr and try fallback
                print(f"[Agent] GitHub API fetch failed: {e}", file=sys.stderr)

    # 3. GitHub raw URL fallback (previous simple logic)
    if token and "/" in file_path:
        import urllib.request
        # This often fails with 404 because it lacks branch (e.g. /main/)
        # But we keep it as a last-resort attempt
        url = f"https://raw.githubusercontent.com/{file_path}"
        try:
            req = urllib.request.Request(url, headers={
                "Authorization": f"token {token}",
                "User-Agent": "VulnGuardAI-Agent"
            })
            with urllib.request.urlopen(req) as r:
                return r.read().decode("utf-8")
        except:
            pass

    raise FileNotFoundError(f"Cannot read file: {file_path}")


# ─────────────────────────────────────────────────────────────────────────────
# NODE 1: SCAN
# Reads the file and uses LLM to identify vulnerabilities.
# ─────────────────────────────────────────────────────────────────────────────

def scan_node(state: ScanState) -> dict:
    """
    LangGraph node: Scan.
    Reads file content and asks LLM to identify vulnerabilities.
    Returns partial state: logs + findings.
    """
    logs = [_log("scan", "info", f"Reading file: {state['file_path']}")]

    try:
        content = _read_file_content(state["file_path"], state.get("access_token"))
    except Exception as e:
        return {
            "file_content": "",
            "findings": [],
            "logs": logs + [_log("scan", "error", f"Failed to read file: {e}")],
            "current_node": "scan",
            "error": str(e),
        }

    logs.append(_log("scan", "info",
                     "Analysing code with security LLM...",
                     f"File size: {len(content)} chars"))

    prompt = SCANNER_PROMPT.format(
        file_path=state["file_path"],
        file_content=content,
    )

    raw = generate_text(prompt, system=SCANNER_SYSTEM)

    try:
        findings_raw = _extract_json(raw)
        findings: list[Finding] = []
        for f in findings_raw:
            # Ensure file_path is present for the UI
            f["file_path"] = f.get("file_path", state["file_path"])
            findings.append(Finding(**f))
    except Exception as e:
        return {
            "file_content": content,
            "findings": [],
            "logs": logs + [_log("scan", "error", f"Failed to parse LLM findings: {e}", raw[:500])],
            "current_node": "scan",
            "error": f"Parse error: {e}",
        }

    logs.append(_log(
        "scan", "info",
        f"Scan complete — {len(findings)} potential finding(s) identified",
        ", ".join(f['vuln_type'] for f in findings) or "none",
    ))

    return {
        "file_content": content,
        "findings": findings,
        "logs": logs,
        "current_node": "scan",
        "error": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# NODE 2: VERIFY
# Second-pass LLM review to confirm findings and filter false positives.
# ─────────────────────────────────────────────────────────────────────────────

def verify_node(state: ScanState) -> dict:
    """
    LangGraph node: Verify.
    Asks a second LLM pass to confirm findings are genuine.
    """
    logs = [_log("verify", "info",
                 f"Verifying {len(state['findings'])} finding(s) against OWASP patterns...")]

    prompt = VERIFIER_PROMPT.format(
        file_path=state["file_path"],
        file_content=state["file_content"],
        findings_json=json.dumps(state["findings"], indent=2),
    )

    raw = generate_text(prompt, system=VERIFIER_SYSTEM)

    try:
        parsed = _extract_json(raw)
        # Ensure we have a list of integers regardless of what the mock/LLM returns
        verified_indices: list[int] = []
        for item in parsed:
            if isinstance(item, int):
                verified_indices.append(item)
            elif isinstance(item, dict):
                # LLM returned finding objects instead of indices — confirm all
                verified_indices = list(range(len(state["findings"])))
                break
            else:
                try:
                    verified_indices.append(int(item))
                except (TypeError, ValueError):
                    pass
    except Exception as e:
        # If parsing fails, confirm all findings (conservative approach)
        verified_indices = list(range(len(state["findings"])))
        logs.append(_log("verify", "warn",
                         f"Could not parse verifier response, confirming all: {e}"))

    rejected = len(state["findings"]) - len(verified_indices)
    logs.append(_log(
        "verify", "info",
        f"Verification complete — {len(verified_indices)} confirmed, {rejected} rejected as false positive",
        f"Confirmed indices: {verified_indices}",
    ))

    return {
        "verified_indices": verified_indices,
        "logs": logs,
        "current_node": "verify",
    }


# ─────────────────────────────────────────────────────────────────────────────
# NODE 3: PATCH
# Generate secure patch suggestions for each confirmed finding.
# ─────────────────────────────────────────────────────────────────────────────

def patch_node(state: ScanState) -> dict:
    """
    LangGraph node: Patch.
    Generates secure code patches for all confirmed vulnerability findings.
    """
    # Safely coerce verified_indices to a list of ints.
    # LangGraph may return them as plain ints or as serialised dicts depending on version.
    raw_indices = state.get("verified_indices", list(range(len(state["findings"]))))
    verified_int: list[int] = []
    for idx in raw_indices:
        if isinstance(idx, int):
            verified_int.append(idx)
        elif isinstance(idx, dict) and "index" in idx:
            verified_int.append(int(idx["index"]))
        else:
            try:
                verified_int.append(int(idx))
            except (TypeError, ValueError):
                pass

    confirmed = [
        state["findings"][i]
        for i in verified_int
        if i < len(state["findings"])
    ]

    logs = [_log("patch", "info",
                 f"Generating patches for {len(confirmed)} confirmed finding(s)...")]

    if not confirmed:
        logs.append(_log("patch", "info", "No confirmed findings to patch."))
        return {"patches": [], "logs": logs, "current_node": "done"}

    prompt = PATCHER_PROMPT.format(
        file_path=state["file_path"],
        file_content=state["file_content"],
        findings_json=json.dumps(confirmed, indent=2),
    )

    raw = generate_text(prompt, system=PATCHER_SYSTEM)

    try:
        patches_raw = _extract_json(raw)
        # Handle cases where LLM returns a single object instead of a list
        if isinstance(patches_raw, dict):
            patches_raw = [patches_raw]
        
        patches: list[PatchSuggestion] = [PatchSuggestion(**p) for p in patches_raw]
    except Exception as e:
        logs.append(_log("patch", "error", f"Failed to parse patch suggestions: {e}", raw[:500]))
        return {
            "patches": [],
            "logs": logs,
            "current_node": "done",
            "error": f"Patch parse error: {e}",
        }

    logs.append(_log(
        "patch", "info",
        f"Patch generation complete — {len(patches)} patch(es) ready",
        " | ".join(p['description'][:60] for p in patches),
    ))

    return {"patches": patches, "logs": logs, "current_node": "done"}


# ─────────────────────────────────────────────────────────────────────────────
# ROUTING FUNCTION
# After scan: if no findings → END, else → verify
# ─────────────────────────────────────────────────────────────────────────────

def route_after_scan(state: ScanState) -> str:
    """Conditional edge: route to 'verify' if findings exist, otherwise END."""
    if state.get("error"):
        return END
    if not state.get("findings"):
        return END
    return "verify"


# ─────────────────────────────────────────────────────────────────────────────
# BUILD THE LANGGRAPH STATE GRAPH
# ─────────────────────────────────────────────────────────────────────────────

def build_scanner_graph() -> StateGraph:
    """
    Construct the Scan-Verify-Patch LangGraph.

    Follows the LangGraph skill: Basic Agent Graph + Conditional Branching patterns.

    Topology:
        START → scan → [conditional] → verify → patch → END
                                   ↘
                                    END (no findings)
    """
    graph = StateGraph(ScanState)

    # Add nodes
    graph.add_node("scan", scan_node)
    graph.add_node("verify", verify_node)
    graph.add_node("patch", patch_node)

    # Add edges
    graph.add_edge(START, "scan")
    graph.add_conditional_edges(
        "scan",
        route_after_scan,
        {"verify": "verify", END: END},
    )
    graph.add_edge("verify", "patch")
    graph.add_edge("patch", END)

    return graph.compile()


# Compiled graph — importable by FastAPI (Phase 3)
scanner_graph = build_scanner_graph()


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRYPOINT — for Task 2.1 Step 2 testing
# ─────────────────────────────────────────────────────────────────────────────

def _print_section(title: str):
    w = 70
    print(f"\n{'=' * w}")
    print(f"  {title}")
    print(f"{'=' * w}")


def run_cli(file_path: str):
    """Run the scanner graph from the CLI and print a structured report."""
    _print_section(f"VulnGuard AI — Scanning: {file_path}")

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

    print("\n[*] Running Scan-Verify-Patch graph...\n")
    result = scanner_graph.invoke(initial_state)

    # Print agent logs
    _print_section("Agent Execution Logs")
    for log in result.get("logs", []):
        icon = {"info": "[i]", "warn": "[!]", "error": "[x]"}.get(log["level"], "   ")
        print(f"  [{log['node'].upper():8}] {icon} {log['message']}")
        if log.get("detail"):
            print(f"              -> {log['detail']}")

    # Print findings
    findings = result.get("findings", [])
    raw_verified = result.get("verified_indices", list(range(len(findings))))
    verified: set[int] = set()
    for idx in raw_verified:
        try:
            verified.add(int(idx))
        except (TypeError, ValueError):
            pass

    _print_section(f"Findings ({len(findings)} total, {len(verified)} confirmed)")
    if not findings:
        print("  [OK] No vulnerabilities detected.")
    else:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i, f in enumerate(sorted(findings, key=lambda x: severity_order.get(x["severity"], 4))):
            status = "[CONFIRMED]" if i in verified else "[REJECTED — false positive]"
            sev = f["severity"].upper()
            print(f"\n  [{sev:8}] {f['vuln_type']} ({f['cwe']}) — Line {f['line']}")
            print(f"           {status}")
            print(f"           {f['description']}")
            print(f"           OWASP: {f['owasp_category']} | Confidence: {f['confidence']:.0%}")

    # Print patches
    patches = result.get("patches", [])
    _print_section(f"Patch Suggestions ({len(patches)} generated)")
    if not patches:
        print("  No patches generated.")
    else:
        for idx, p in enumerate(patches):
            print(f"\n  [PATCH #{p.get('finding_id', idx)}] {p.get('description', 'N/A')}")
            print(f"  Explanation: {p.get('explanation', 'N/A')}")
            if p.get("patched_code"):
                print(f"  Fix preview:")
                for line in p["patched_code"][:300].split("\\n"):
                    print(f"    + {line}")

    # Summary
    _print_section("Summary")
    error = result.get("error")
    if error:
        print(f"  [ERROR] Agent encountered an error: {error}")
        sys.exit(1)
    else:
        critical = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        print(f"  File: {file_path}")
        print(f"  Findings: {len(findings)} ({critical} critical, {high} high)")
        print(f"  Confirmed: {len(verified)}")
        print(f"  Patches: {len(patches)}")
        print(f"\n  {'[FAIL] VULNERABILITIES FOUND' if findings else '[PASS] CLEAN -- No issues detected'}")

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnGuard AI — Security Scanner Agent")
    parser.add_argument(
        "--test-file",
        required=True,
        help="Path to the file to scan (local path or owner/repo/path for GitHub)",
    )
    args = parser.parse_args()
    run_cli(args.test_file)
