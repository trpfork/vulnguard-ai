/**
 * VulnGuard AI — Live Agent Feed Component (Phase 3: Real SSE streaming)
 *
 * Receives stream state from the parent (DashboardPage) so that the feed
 * panel and the vulnerability table share a single useAgentStream() instance.
 */
"use client";

import { useEffect, useRef } from "react";
import type { AgentStep, StreamStats, StepType } from "@/hooks/useAgentStream";

// ─── Config ───────────────────────────────────────────────────────────────────

const TYPE_CONFIG: Record<
  StepType,
  { color: string; icon: string; label: string }
> = {
  scanning: {
    color: "var(--agent-scanning)",
    icon: "🔍",
    label: "SCANNING",
  },
  verifying: {
    color: "var(--agent-verifying)",
    icon: "⚡",
    label: "VERIFYING",
  },
  patching: {
    color: "var(--agent-patching)",
    icon: "🔧",
    label: "PATCHING",
  },
  complete: {
    color: "var(--color-success)",
    icon: "✅",
    label: "COMPLETE",
  },
  error: {
    color: "var(--agent-error)",
    icon: "❌",
    label: "ERROR",
  },
};

// ─── Component ────────────────────────────────────────────────────────────────

interface AgentFeedProps {
  /** Stream state — provided by the parent's useAgentStream() hook */
  steps: AgentStep[];
  stats: StreamStats;
  isRunning: boolean;
  isConnected: boolean;
  error: string | null;
  startScan: (filePath: string, token?: string) => void;
  stopScan: () => void;
  clearFeed: () => void;
  /** Path or repo ref to scan when the user clicks "Run Scan" from the feed. */
  filePath?: string;
  /** GitHub token for authenticated scans */
  token?: string;
}

export function AgentFeed({
  steps,
  stats,
  isRunning,
  isConnected,
  error,
  startScan,
  stopScan,
  clearFeed,
  filePath = "tests/mocks/vuln.php",
  token,
}: AgentFeedProps) {

  const feedRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom whenever new steps arrive
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [steps]);

  const handleRunScan = () => {
    if (isRunning) {
      stopScan();
    } else {
      startScan(filePath, token);
    }
  };

  return (
    <aside
      style={{
        width: "var(--feed-width)",
        minWidth: "var(--feed-width)",
        height: "100vh",
        background: "var(--bg-surface)",
        borderLeft: "1px solid var(--border-subtle)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "16px",
          borderBottom: "1px solid var(--border-subtle)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          height: "var(--header-height)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {/* Live indicator dot */}
          <div
            className={isRunning ? "live-dot" : undefined}
            style={
              !isRunning
                ? {
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: "var(--text-muted)",
                  }
                : undefined
            }
          />
          <span
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: "var(--text-primary)",
              letterSpacing: "-0.01em",
            }}
          >
            Agent Feed
          </span>

          {/* LIVE badge */}
          {isRunning && (
            <span
              style={{
                fontSize: 10,
                fontWeight: 600,
                letterSpacing: "0.06em",
                textTransform: "uppercase",
                color: "var(--color-success)",
                padding: "2px 6px",
                borderRadius: 4,
                background: "rgba(16, 185, 129, 0.1)",
                border: "1px solid rgba(16, 185, 129, 0.25)",
              }}
            >
              LIVE
            </span>
          )}

          {/* Error badge */}
          {error && !isRunning && (
            <span
              style={{
                fontSize: 10,
                fontWeight: 600,
                letterSpacing: "0.06em",
                textTransform: "uppercase",
                color: "var(--agent-error)",
                padding: "2px 6px",
                borderRadius: 4,
                background: "rgba(239, 68, 68, 0.1)",
                border: "1px solid rgba(239, 68, 68, 0.25)",
              }}
            >
              OFFLINE
            </span>
          )}
        </div>

        <div style={{ display: "flex", gap: 6 }}>
          {/* Clear button — only shown when there's content */}
          {steps.length > 0 && !isRunning && (
            <button
              id="btn-clear-feed"
              onClick={clearFeed}
              style={{
                padding: "6px 10px",
                borderRadius: 8,
                border: "1px solid var(--border-subtle)",
                background: "transparent",
                color: "var(--text-muted)",
                fontSize: 11,
                cursor: "pointer",
                transition: "all var(--transition-fast)",
              }}
            >
              Clear
            </button>
          )}

          {/* Run / Stop button */}
          <button
            id="btn-run-scan"
            onClick={handleRunScan}
            style={{
              padding: "6px 14px",
              borderRadius: 8,
              background: isRunning
                ? "rgba(239, 68, 68, 0.15)"
                : "linear-gradient(135deg, var(--accent-primary), #6366f1)",
              color: isRunning ? "var(--agent-error)" : "white",
              fontSize: 12,
              fontWeight: 600,
              cursor: "pointer",
              transition: "all var(--transition-fast)",
              boxShadow: isRunning ? "none" : "var(--shadow-glow-sm)",
              border: isRunning ? "1px solid rgba(239,68,68,0.3)" : "none",
            } as React.CSSProperties}
          >
            {isRunning ? "⏹ Stop" : "▶ Run Scan"}
          </button>
        </div>
      </div>

      {/* Feed content */}
      <div
        ref={feedRef}
        style={{
          flex: 1,
          overflowY: "auto",
          padding: "12px",
          display: "flex",
          flexDirection: "column",
          gap: 8,
        }}
      >
        {/* Empty state */}
        {steps.length === 0 && !isRunning && (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              height: "100%",
              gap: 12,
              color: "var(--text-muted)",
              textAlign: "center",
            }}
          >
            <div style={{ fontSize: 40, opacity: 0.4 }}>🤖</div>
            <div style={{ fontSize: 13 }}>
              Click{" "}
              <strong style={{ color: "var(--text-secondary)" }}>
                Run Scan
              </strong>{" "}
              to watch the AI agent analyze your repository in real-time.
            </div>
            {error && (
              <div
                style={{
                  fontSize: 11,
                  color: "var(--agent-error)",
                  padding: "8px 12px",
                  background: "rgba(239,68,68,0.08)",
                  borderRadius: 8,
                  border: "1px solid rgba(239,68,68,0.2)",
                  maxWidth: 260,
                }}
              >
                ⚠️ {error}
                <br />
                <span style={{ opacity: 0.7 }}>
                  Make sure the backend is running on port 8000.
                </span>
              </div>
            )}
          </div>
        )}

        {/* Step cards */}
        {steps.map((step, i) => {
          const config = TYPE_CONFIG[step.type];
          return (
            <div
              key={step.id}
              className="animate-fade-in"
              style={{
                animationDelay: `${Math.min(i * 20, 200)}ms`,
                background: "var(--bg-card)",
                border: `1px solid ${config.color}22`,
                borderLeft: `3px solid ${config.color}`,
                borderRadius: 8,
                padding: "10px 12px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  justifyContent: "space-between",
                  marginBottom: step.detail ? 6 : 0,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ fontSize: 13 }}>{config.icon}</span>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      letterSpacing: "0.06em",
                      color: config.color,
                    }}
                  >
                    {config.label}
                  </span>
                </div>
                <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
                  {step.timestamp.toLocaleTimeString()}
                </span>
              </div>

              <div
                style={{
                  fontSize: 12,
                  color: "var(--text-primary)",
                  lineHeight: 1.5,
                  marginBottom: step.detail ? 4 : 0,
                }}
              >
                {step.message}
              </div>

              {step.detail && (
                <div
                  style={{
                    fontSize: 11,
                    color: "var(--text-muted)",
                    fontFamily: "JetBrains Mono, monospace",
                    lineHeight: 1.4,
                    background: "rgba(0,0,0,0.2)",
                    borderRadius: 4,
                    padding: "4px 6px",
                    marginTop: 4,
                  }}
                >
                  {step.detail}
                </div>
              )}
            </div>
          );
        })}

        {/* Typing / connecting indicator */}
        {isRunning && (
          <div
            className="animate-fade-in"
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--border-subtle)",
              borderRadius: 8,
              padding: "10px 14px",
              display: "flex",
              gap: 4,
              alignItems: "center",
            }}
          >
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "var(--accent-bright)",
                  animation: `typing-dot 1.2s ease-in-out ${i * 0.2}s infinite`,
                }}
              />
            ))}
            <span
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                marginLeft: 6,
              }}
            >
              {isConnected ? "Agent thinking..." : "Connecting..."}
            </span>
          </div>
        )}
      </div>

      {/* Stats footer */}
      <div
        style={{
          padding: "12px 16px",
          borderTop: "1px solid var(--border-subtle)",
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          gap: 8,
        }}
      >
        {[
          {
            label: "Findings",
            value: stats.findingsCount > 0 ? String(stats.findingsCount) : "—",
          },
          {
            label: "Confirmed",
            value:
              stats.confirmedCount > 0 ? String(stats.confirmedCount) : "—",
          },
          {
            label: "Patches",
            value: stats.patchesCount > 0 ? String(stats.patchesCount) : "—",
          },
        ].map((stat) => (
          <div
            key={stat.label}
            style={{
              textAlign: "center",
              background: "var(--bg-card)",
              borderRadius: 8,
              padding: "8px 4px",
              border: "1px solid var(--border-subtle)",
              transition: "all var(--transition-fast)",
            }}
          >
            <div
              style={{
                fontSize: 16,
                fontWeight: 700,
                color:
                  stat.value !== "—"
                    ? "var(--text-primary)"
                    : "var(--text-muted)",
                lineHeight: 1,
              }}
            >
              {stat.value}
            </div>
            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
              {stat.label}
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
}
