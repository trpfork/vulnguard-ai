/**
 * VulnGuard AI — useAgentStream hook
 *
 * Connects to the FastAPI /api/stream SSE endpoint and provides
 * real-time typed events to the AgentFeed component.
 *
 * Usage:
 *   const { steps, findings, stats, isRunning, startScan, stopScan } = useAgentStream();
 */

"use client";

import { useState, useRef, useCallback } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────

export type StepType =
  | "scanning"
  | "verifying"
  | "patching"
  | "complete"
  | "error";

export interface AgentStep {
  id: string;
  type: StepType;
  message: string;
  detail?: string;
  timestamp: Date;
  node?: string;
}

export interface FindingEvent {
  file_path: string;
  severity: "critical" | "high" | "medium" | "low";
  vuln_type: string;
  cwe: string;
  line: number;
  description: string;
  confidence: number;
  owasp_category: string;
}

export interface PatchEvent {
  finding_id: string;
  description: string;
  patched_code: string;
  explanation: string;
}

export interface StreamStats {
  findingsCount: number;
  confirmedCount: number;
  patchesCount: number;
}

export interface UseAgentStreamReturn {
  steps: AgentStep[];
  findings: FindingEvent[];
  patches: PatchEvent[];
  stats: StreamStats;
  isRunning: boolean;
  isConnected: boolean;
  error: string | null;
  startScan: (filePath: string, token?: string) => void;
  stopScan: () => void;
  clearFeed: () => void;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

/** Map backend node name to frontend step type */
function nodeToStepType(node: string, level: string): StepType {
  if (level === "error") return "error";
  const map: Record<string, StepType> = {
    scan: "scanning",
    verify: "verifying",
    patch: "patching",
  };
  return map[node] ?? "scanning";
}

const EMPTY_STATS: StreamStats = {
  findingsCount: 0,
  confirmedCount: 0,
  patchesCount: 0,
};

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useAgentStream(): UseAgentStreamReturn {
  const [steps, setSteps] = useState<AgentStep[]>([]);
  const [findings, setFindings] = useState<FindingEvent[]>([]);
  const [patches, setPatches] = useState<PatchEvent[]>([]);
  const [stats, setStats] = useState<StreamStats>(EMPTY_STATS);
  const [isRunning, setIsRunning] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Hold EventSource ref so we can close it on stopScan
  const esRef = useRef<EventSource | null>(null);

  // ── Internal: append a step ────────────────────────────────────────────────
  const addStep = useCallback(
    (type: StepType, message: string, detail?: string, node?: string) => {
      setSteps((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          type,
          message,
          detail,
          node,
          timestamp: new Date(),
        },
      ]);
    },
    []
  );

  // ── Internal: close EventSource ────────────────────────────────────────────
  const closeStream = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    setIsRunning(false);
    setIsConnected(false);
  }, []);

  // ── Public: stop scan ──────────────────────────────────────────────────────
  const stopScan = useCallback(() => {
    closeStream();
    addStep("error", "Scan cancelled by user.");
  }, [closeStream, addStep]);

  // ── Public: clear feed ────────────────────────────────────────────────────
  const clearFeed = useCallback(() => {
    setSteps([]);
    setFindings([]);
    setPatches([]);
    setStats(EMPTY_STATS);
    setError(null);
  }, []);

  // ── Public: start scan ────────────────────────────────────────────────────
  const startScan = useCallback(
    (filePath: string, token?: string) => {
      // Close any existing stream
      closeStream();
      clearFeed();

      let url = `${API_BASE}/api/stream?file_path=${encodeURIComponent(filePath)}`;
      if (token) {
        url += `&token=${encodeURIComponent(token)}`;
      }

      let es: EventSource;
      try {
        es = new EventSource(url);
        esRef.current = es;
      } catch (err) {
        setError(`Failed to connect to agent: ${err}`);
        return;
      }

      setIsRunning(true);
      setIsConnected(true);
      setError(null);

      // ── Event: started ───────────────────────────────────────────────────
      es.addEventListener("started", (e) => {
        const data = JSON.parse(e.data);
        addStep("scanning", data.message ?? "Scan started", data.file_path);
      });

      // ── Event: log ───────────────────────────────────────────────────────
      es.addEventListener("log", (e) => {
        const data = JSON.parse(e.data);
        const stepType = nodeToStepType(data.node ?? "", data.level ?? "info");
        addStep(stepType, data.message, data.detail, data.node);
      });

      // ── Event: finding ───────────────────────────────────────────────────
      es.addEventListener("finding", (e) => {
        const finding: FindingEvent = JSON.parse(e.data);
        setFindings((prev) => [...prev, finding]);
        setStats((prev) => ({
          ...prev,
          findingsCount: prev.findingsCount + 1,
        }));
        addStep(
          "verifying",
          `Found ${finding.severity.toUpperCase()}: ${finding.vuln_type} (${finding.cwe})`,
          `Line ${finding.line} — ${finding.owasp_category} | Confidence: ${Math.round(
            (finding.confidence ?? 0) * 100
          )}%`,
          "verify"
        );
      });

      // ── Event: patch ─────────────────────────────────────────────────────
      es.addEventListener("patch", (e) => {
        const patch: PatchEvent = JSON.parse(e.data);
        setPatches((prev) => [...prev, patch]);
        setStats((prev) => ({
          ...prev,
          patchesCount: prev.patchesCount + 1,
        }));
        addStep(
          "patching",
          `Patch ready: ${patch.description}`,
          patch.explanation,
          "patch"
        );
      });

      // ── Event: error ─────────────────────────────────────────────────────
      es.addEventListener("error", (e) => {
        if (e instanceof MessageEvent) {
          const data = JSON.parse(e.data);
          setError(data.message);
          addStep("error", `Agent error: ${data.message}`);
        } else {
          // SSE connection error (network issue)
          setError("Lost connection to agent.");
          addStep("error", "Connection to agent lost. Is the backend running?");
          closeStream();
        }
      });

      // ── Event: done ───────────────────────────────────────────────────────
      es.addEventListener("done", (e) => {
        const data = JSON.parse(e.data);
        if (data.success) {
          setStats({
            findingsCount: data.findings_count ?? 0,
            confirmedCount: data.confirmed_count ?? 0,
            patchesCount: data.patches_count ?? 0,
          });
          addStep(
            "complete",
            `Scan complete — ${data.findings_count} finding(s), ${data.patches_count} patch(es) ready`,
            data.error ?? undefined
          );
        } else {
          addStep("error", `Scan failed: ${data.error}`);
        }
        closeStream();
      });

      // ── Native SSE onerror (connection-level errors) ──────────────────────
      es.onerror = () => {
        if (es.readyState === EventSource.CLOSED) {
          closeStream();
        }
      };
    },
    [addStep, clearFeed, closeStream]
  );

  return {
    steps,
    findings,
    patches,
    stats,
    isRunning,
    isConnected,
    error,
    startScan,
    stopScan,
    clearFeed,
  };
}
