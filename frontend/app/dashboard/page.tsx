/**
 * VulnGuard AI — Main Dashboard Page
 * Central view: vulnerability summary cards + file vulnerability table
 */
"use client";

import { Sidebar } from "@/components/Sidebar";
import { AgentFeed } from "@/components/AgentFeed";
import { ThemeToggle } from "@/components/ThemeToggle";
import LoginButton from "@/components/LoginButton";
import { useAuth } from "@/context/AuthContext";
import { useAgentStream, FindingEvent } from "@/hooks/useAgentStream";
import { PatchModal } from "@/components/PatchModal";
import { useState, useEffect, useMemo, useCallback } from "react";


type Vulnerability = {
  id: string;
  file: string;
  line: number;
  severity: "critical" | "high" | "medium" | "low";
  type: string;
  description: string;
  cwe: string;
  status: "open" | "patching" | "patched";
};

const MOCK_VULNS: Vulnerability[] = [
  {
    id: "v1",
    file: "src/auth/middleware.php",
    line: 47,
    severity: "critical",
    type: "Broken Access Control",
    description: "Direct object reference without authorization check",
    cwe: "CWE-639",
    status: "patching",
  },
  {
    id: "v2",
    file: "src/api/users.php",
    line: 112,
    severity: "high",
    type: "SQL Injection",
    description: "Unsanitized user input in raw SQL query",
    cwe: "CWE-89",
    status: "open",
  },
  {
    id: "v3",
    file: "src/templates/profile.html",
    line: 23,
    severity: "high",
    type: "Reflected XSS",
    description: "User-controlled data rendered without escaping",
    cwe: "CWE-79",
    status: "open",
  },
  {
    id: "v4",
    file: "config/database.php",
    line: 8,
    severity: "medium",
    type: "Hardcoded Credential",
    description: "Database password stored in plaintext source file",
    cwe: "CWE-798",
    status: "patched",
  },
  {
    id: "v5",
    file: "src/upload/handler.php",
    line: 34,
    severity: "high",
    type: "Unrestricted File Upload",
    description: "No MIME type or extension validation on uploads",
    cwe: "CWE-434",
    status: "open",
  },
  {
    id: "v6",
    file: "src/session/manager.php",
    line: 19,
    severity: "medium",
    type: "Session Fixation",
    description: "Session ID not regenerated after authentication",
    cwe: "CWE-384",
    status: "patched",
  },
];

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const sorted = [...MOCK_VULNS].sort(
  (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
);

const STATS = [
  { label: "Critical", count: 1, color: "var(--color-critical)" },
  { label: "High", count: 3, color: "var(--color-high)" },
  { label: "Medium", count: 2, color: "var(--color-medium)" },
  { label: "Patched", count: 2, color: "var(--color-success)" },
];

const STATUS_STYLES: Record<string, { bg: string; color: string; label: string }> = {
  open: {
    bg: "rgba(239,68,68,0.12)",
    color: "var(--color-critical)",
    label: "Open",
  },
  patching: {
    bg: "rgba(59,130,246,0.12)",
    color: "var(--agent-scanning)",
    label: "Patching…",
  },
  patched: {
    bg: "rgba(16,185,129,0.12)",
    color: "var(--color-success)",
    label: "Patched",
  },
};

export default function DashboardPage() {
  const { user, isLoading: isAuthLoading } = useAuth();
  const {
    steps,
    findings: streamFindings,
    patches,
    stats: streamStats,
    isRunning,
    isConnected,
    error: scanError,
    startScan,
    stopScan,
    clearFeed,
  } = useAgentStream();

  const [dbFindings, setDbFindings] = useState<Vulnerability[]>([]);
  const [isDataLoading, setIsDataLoading] = useState(false);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedFilePath, setSelectedFilePath] = useState<string>("tests/mocks/vuln.php");

  // 1. Listen for file selection from Sidebar
  useEffect(() => {
    const handleSelectFile = (e: any) => {
      const filePath = e.detail;
      setSelectedFilePath(filePath);
      if (user?.token) {
        startScan(filePath, user.token);
      }
    };
    window.addEventListener("select-file", handleSelectFile);
    return () => window.removeEventListener("select-file", handleSelectFile);
  }, [user, startScan]);

  const fetchDbFindings = useCallback(() => {
    if (user?.token) {
      setIsDataLoading(true);
      fetch(`http://localhost:8000/api/findings?token=${user.token}`)
        .then((res) => res.json())
        .then((data) => setDbFindings(data))
        .catch((err) => console.error("Failed to fetch findings:", err))
        .finally(() => setIsDataLoading(false));
    }
  }, [user]);

  // 2. Fetch historical findings on load
  useEffect(() => {
    fetchDbFindings();
  }, [fetchDbFindings]);

  // 4. Refresh DB findings after scan completes
  useEffect(() => {
    // If we just finished running a scan, wait a second for DB commit then refresh
    if (!isRunning && steps.length > 0 && steps[steps.length - 1].type === "complete") {
      const timer = setTimeout(() => {
        fetchDbFindings();
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [isRunning, steps, fetchDbFindings]);

  // 3. Merge stream findings with DB findings
  const allFindings = useMemo(() => {
    const findings = [...dbFindings];
    
    // Add stream findings if they aren't already in the list
    streamFindings.forEach((sf, idx) => {
      // Avoid adding if we already have it in dbFindings (basic check)
      const exists = findings.some(df => 
        df.file === sf.file_path && 
        df.line === sf.line && 
        df.type === sf.vuln_type
      );
      
      if (!exists) {
        findings.unshift({
          id: `stream-${idx}`,
          file: sf.file_path || "Selected File",
          line: sf.line,
          severity: sf.severity,
          type: sf.vuln_type,
          description: sf.description,
          cwe: sf.cwe,
          status: isRunning ? "patching" : "open"
        });
      }
    });

    return findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }, [dbFindings, streamFindings, isRunning]);

  if (isAuthLoading) {
    return (
      <div className="flex items-center justify-center h-screen bg-surface">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent"></div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex flex-col items-center justify-center h-screen bg-surface p-6 text-center">
        <div className="mb-8 p-6 rounded-2xl bg-card border border-subtle shadow-xl max-w-md">
          <h1 className="text-2xl font-bold text-primary mb-4">Authentication Required</h1>
          <p className="text-muted mb-8">
            Please sign in with your GitHub account to access the security dashboard and start scanning your repositories.
          </p>
          <LoginButton />
        </div>
      </div>
    );
  }

  return (
    <>
      <Sidebar />

      {/* Main Content */}
      <main
        style={{
          flex: 1,
          height: "100vh",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Top Header */}
        <header
          style={{
            height: "var(--header-height)",
            padding: "0 24px",
            borderBottom: "1px solid var(--border-subtle)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            background: "var(--bg-surface)",
            flexShrink: 0,
          }}
        >
          <div>
            <h1
              style={{
                fontSize: 15,
                fontWeight: 600,
                color: "var(--text-primary)",
                letterSpacing: "-0.02em",
              }}
            >
              Security Dashboard
            </h1>
            <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 1 }}>
              {isRunning ? "Scan in progress..." : "Select a file from the sidebar to start a security audit"}
            </p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                fontSize: 12,
                color: "var(--text-secondary)",
                padding: "5px 10px",
                background: "var(--bg-card)",
                borderRadius: 8,
                border: "1px solid var(--border-subtle)",
              }}
            >
              <span>🕐</span>
              <span>Auto-scan: 6h</span>
            </div>
            <ThemeToggle />
            <LoginButton />
            <button
              id="btn-new-scan"
              style={{
                padding: "6px 16px",
                borderRadius: 8,
                border: "none",
                background:
                  "linear-gradient(135deg, var(--accent-primary), #6366f1)",
                color: "white",
                fontSize: 12,
                fontWeight: 600,
                cursor: "pointer",
                boxShadow: "var(--shadow-glow-sm)",
              }}
            >
              + New Scan
            </button>
          </div>
        </header>

        {/* Scrollable body */}
        <div
          style={{ flex: 1, overflowY: "auto", padding: "20px 24px", gap: 20, display: "flex", flexDirection: "column" }}
        >
          {/* Summary stats */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
            {[
              { label: "Critical", count: allFindings.filter(f => f.severity === "critical").length, color: "var(--color-critical)" },
              { label: "High", count: allFindings.filter(f => f.severity === "high").length, color: "var(--color-high)" },
              { label: "Medium", count: allFindings.filter(f => f.severity === "medium").length, color: "var(--color-medium)" },
              { label: "Patched", count: allFindings.filter(f => f.status === "patched").length, color: "var(--color-success)" },
            ].map((stat) => (
              <div
                key={stat.label}
                id={`stat-${stat.label.toLowerCase()}`}
                className="glass-card"
                style={{
                  padding: "16px 20px",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <div>
                  <div
                    style={{
                      fontSize: 28,
                      fontWeight: 700,
                      color: stat.color,
                      lineHeight: 1,
                      textShadow: `0 0 20px ${stat.color}55`,
                    }}
                  >
                    {stat.count}
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 4 }}>
                    {stat.label}
                  </div>
                </div>
                <div
                  style={{
                    width: 40,
                    height: 40,
                    borderRadius: 10,
                    background: `${stat.color}18`,
                    border: `1px solid ${stat.color}30`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: 18,
                  }}
                >
                  {stat.label === "Critical" ? "🔴" : stat.label === "High" ? "🟠" : stat.label === "Medium" ? "🟡" : "✅"}
                </div>
              </div>
            ))}
          </div>

          {/* Vulnerability Table */}
          <div className="glass-card" style={{ overflow: "hidden" }}>
            <div
              style={{
                padding: "14px 20px",
                borderBottom: "1px solid var(--border-subtle)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <h2
                style={{
                  fontSize: 14,
                  fontWeight: 600,
                  color: "var(--text-primary)",
                  letterSpacing: "-0.01em",
                }}
              >
                Detected Vulnerabilities
              </h2>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {allFindings.length} findings
              </span>
            </div>

            <div style={{ overflow: "auto" }}>
              <table
                style={{
                  width: "100%",
                  borderCollapse: "collapse",
                  fontSize: 12,
                }}
              >
                <thead>
                  <tr style={{ background: "var(--bg-elevated)" }}>
                    {["Severity", "File", "Line", "Type", "CWE", "Status", "Action"].map(
                      (col) => (
                        <th
                          key={col}
                          style={{
                            padding: "10px 14px",
                            textAlign: "left",
                            color: "var(--text-muted)",
                            fontWeight: 600,
                            fontSize: 11,
                            letterSpacing: "0.04em",
                            textTransform: "uppercase",
                            borderBottom: "1px solid var(--border-subtle)",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {col}
                        </th>
                      )
                    )}
                  </tr>
                </thead>
                <tbody>
                  {allFindings.map((vuln, i) => (
                    <tr
                      key={vuln.id}
                      id={`vuln-row-${vuln.id}`}
                      style={{
                        borderBottom:
                          i < allFindings.length - 1
                            ? "1px solid var(--border-subtle)"
                            : "none",
                        transition: "background var(--transition-fast)",
                      }}
                      onMouseEnter={(e) => {
                        (e.currentTarget as HTMLElement).style.background =
                          "var(--bg-hover)";
                      }}
                      onMouseLeave={(e) => {
                        (e.currentTarget as HTMLElement).style.background = "transparent";
                      }}
                    >
                      <td style={{ padding: "12px 14px" }}>
                        <span className={`badge badge-${vuln.severity}`}>
                          {vuln.severity}
                        </span>
                      </td>
                      <td style={{ padding: "12px 14px" }}>
                        <span
                          style={{
                            fontFamily: "JetBrains Mono, monospace",
                            color: "var(--text-secondary)",
                            fontSize: 11,
                          }}
                        >
                          {vuln.file}
                        </span>
                      </td>
                      <td style={{ padding: "12px 14px" }}>
                        <span
                          style={{
                            fontFamily: "JetBrains Mono, monospace",
                            color: "var(--text-muted)",
                          }}
                        >
                          :{vuln.line}
                        </span>
                      </td>
                      <td style={{ padding: "12px 14px", color: "var(--text-primary)" }}>
                        <div style={{ fontWeight: 500 }}>{vuln.type}</div>
                        <div style={{ color: "var(--text-muted)", fontSize: 11, marginTop: 1 }}>
                          {vuln.description}
                        </div>
                      </td>
                      <td style={{ padding: "12px 14px" }}>
                        <span
                          style={{
                            fontFamily: "JetBrains Mono, monospace",
                            fontSize: 11,
                            color: "var(--text-muted)",
                            background: "var(--bg-elevated)",
                            padding: "2px 6px",
                            borderRadius: 4,
                          }}
                        >
                          {vuln.cwe}
                        </span>
                      </td>
                      <td style={{ padding: "12px 14px" }}>
                        <span
                          style={{
                            fontSize: 11,
                            fontWeight: 600,
                            padding: "3px 8px",
                            borderRadius: 6,
                            background: STATUS_STYLES[vuln.status].bg,
                            color: STATUS_STYLES[vuln.status].color,
                          }}
                        >
                          {STATUS_STYLES[vuln.status].label}
                        </span>
                      </td>
                      <td style={{ padding: "12px 14px" }}>
                        <button
                          id={`btn-patch-${vuln.id}`}
                          disabled={vuln.status === "patched"}
                          onClick={() => !vuln.id.startsWith("stream") && setSelectedFindingId(vuln.id)}
                          style={{
                            padding: "4px 10px",
                            borderRadius: 6,
                            border: "1px solid var(--border-accent)",
                            background:
                              vuln.status === "patched"
                                ? "transparent"
                                : "var(--accent-subtle)",
                            color:
                              vuln.status === "patched"
                                ? "var(--text-muted)"
                                : "var(--accent-bright)",
                            fontSize: 11,
                            fontWeight: 600,
                            cursor:
                              vuln.status === "patched" || vuln.id.startsWith("stream") ? "default" : "pointer",
                            transition: "all var(--transition-fast)",
                            opacity: vuln.id.startsWith("stream") ? 0.5 : 1
                          }}
                        >
                          {vuln.status === "patched" ? "Fixed" : "Auto-Patch"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </main>

      <AgentFeed
        steps={steps}
        stats={streamStats}
        isRunning={isRunning}
        isConnected={isConnected}
        error={scanError}
        startScan={startScan}
        stopScan={stopScan}
        clearFeed={clearFeed}
        filePath={selectedFilePath}
        token={user?.token}
      />

      {selectedFindingId && user?.token && (
        <PatchModal 
          findingId={selectedFindingId} 
          token={user.token} 
          onClose={() => setSelectedFindingId(null)} 
        />
      )}
    </>
  );
}
