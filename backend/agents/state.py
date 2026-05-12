"""
VulnGuard AI — Agent State Definitions
Shared TypedDicts used across all LangGraph nodes.
"""

from typing import Annotated, TypedDict, Optional
from operator import add


class Finding(TypedDict):
    """A single vulnerability finding from the scanner node."""
    severity: str            # "critical" | "high" | "medium" | "low"
    vuln_type: str           # e.g., "Broken Access Control"
    cwe: str                 # e.g., "CWE-639"
    line: int                # Line number in the file
    description: str         # Human-readable explanation
    code_snippet: str        # The vulnerable code fragment
    confidence: float        # 0.0–1.0 confidence score
    owasp_category: str      # e.g., "A01:2021"


class PatchSuggestion(TypedDict):
    """A suggested fix produced by the patcher node."""
    finding_id: str          # References Finding by index
    description: str         # What the fix does
    original_code: str       # The code to replace
    patched_code: str        # The secure replacement
    explanation: str         # Why this fix works


class AgentLog(TypedDict):
    """A single log entry streamed to the frontend."""
    node: str                # Which node emitted this log
    level: str               # "info" | "warn" | "error"
    message: str             # Human-readable message
    detail: Optional[str]    # Optional extra detail


class ScanState(TypedDict):
    """
    Top-level LangGraph state for the Scan-Verify-Patch loop.

    Reducer rules (from LangGraph skill):
    - `logs`: accumulated with `add` — each node appends, never overwrites
    - `findings`: accumulated with `add` — scanner appends findings
    - `patches`: accumulated with `add` — patcher appends patches
    - `file_path`, `file_content`, `current_node`, `error`: plain overwrite
    """
    # Input
    file_path: str
    file_content: str

    # Findings — accumulated across nodes
    findings: Annotated[list[Finding], add]

    # Verified finding indices (after verify node)
    verified_indices: list[int]

    # Patch suggestions — accumulated
    patches: Annotated[list[PatchSuggestion], add]

    # Streaming logs — accumulated
    logs: Annotated[list[AgentLog], add]

    # Control flow
    current_node: str        # "scan" | "verify" | "patch" | "done"
    error: Optional[str]     # Set if any node fails
