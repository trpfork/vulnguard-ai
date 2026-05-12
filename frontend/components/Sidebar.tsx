/**
 * VulnGuard AI — Sidebar Component
 * Left navigation: branding, repo list, scan controls
 */
"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/context/AuthContext";

const NAV_ITEMS = [
  { icon: "⬡", label: "Dashboard", href: "/dashboard", active: true },
  { icon: "🔍", label: "Scan Repo", href: "/dashboard/scan", active: false },
  { icon: "📋", label: "Reports", href: "/dashboard/reports", active: false },
  { icon: "🧩", label: "Patterns", href: "/dashboard/patterns", active: false },
  { icon: "⚙️", label: "Settings", href: "/dashboard/settings", active: false },
];

const MOCK_REPOS = [
  { name: "api-gateway", branch: "main", status: "critical", vulns: 3 },
  { name: "auth-service", branch: "develop", status: "high", vulns: 7 },
  { name: "data-pipeline", branch: "main", status: "low", vulns: 1 },
  { name: "web-frontend", branch: "feature/login", status: "medium", vulns: 4 },
];

const STATUS_COLORS: Record<string, string> = {
  critical: "var(--color-critical)",
  high: "var(--color-high)",
  medium: "var(--color-medium)",
  low: "var(--color-low)",
};

export function Sidebar() {
  const { user } = useAuth();
  const [repos, setRepos] = useState<any[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
  const [files, setFiles] = useState<any[]>([]);
  const [currentPath, setCurrentPath] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isFilesLoading, setIsFilesLoading] = useState(false);

  useEffect(() => {
    if (!user?.token) return;

    const controller = new AbortController();
    setIsLoading(true);

    (async () => {
      try {
        const res = await fetch(
          `http://localhost:8000/api/user/repos?token=${user.token}`,
          { signal: controller.signal }
        );
        if (!res.ok) {
          console.warn(`Repos fetch failed with status ${res.status}`);
          return;
        }
        const data = await res.json();
        if (!controller.signal.aborted && Array.isArray(data)) {
          setRepos(data);
        }
      } catch (err: any) {
        if (err?.name !== "AbortError") {
          console.warn("Failed to fetch repos (backend may be offline):", err?.message);
        }
      } finally {
        if (!controller.signal.aborted) setIsLoading(false);
      }
    })();

    return () => controller.abort();
  }, [user]);

  useEffect(() => {
    if (selectedRepo && user?.token) {
      fetchContents("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedRepo, user]);

  const fetchContents = async (path: string) => {
    if (!selectedRepo || !user?.token) return;

    setIsFilesLoading(true);
    const [owner, repo] = selectedRepo.split("/");

    try {
      const res = await fetch(
        `http://localhost:8000/api/repos/${owner}/${repo}/contents?path=${path}&token=${user.token}`
      );
      if (!res.ok) {
        console.warn(`Contents fetch failed with status ${res.status}`);
        return;
      }
      const data = await res.json();
      if (Array.isArray(data)) {
        setFiles(data);
        setCurrentPath(path);
      }
    } catch (err: any) {
      console.warn("Failed to fetch contents (backend may be offline):", err?.message);
    } finally {
      setIsFilesLoading(false);
    }
  };

  const handleItemClick = (item: any) => {
    if (item.type === "dir") {
      fetchContents(item.path);
    } else {
      // It's a file!
      // In Task 2.1, we'll pass this to the Dashboard to trigger a scan.
      const fullPath = `${selectedRepo}/${item.path}`;
      window.dispatchEvent(new CustomEvent("select-file", { detail: fullPath }));
    }
  };

  const goBack = () => {
    const parts = currentPath.split("/");
    parts.pop();
    fetchContents(parts.join("/"));
  };


  return (
    <aside
      style={{
        width: "var(--sidebar-width)",
        minWidth: "var(--sidebar-width)",
        height: "100vh",
        background: "var(--bg-surface)",
        borderRight: "1px solid var(--border-subtle)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {/* Branding */}
      <div
        style={{
          padding: "20px 16px",
          borderBottom: "1px solid var(--border-subtle)",
          display: "flex",
          alignItems: "center",
          gap: "10px",
        }}
      >
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: 10,
            background: "linear-gradient(135deg, var(--accent-primary), #60a5fa)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 18,
            boxShadow: "var(--shadow-glow-sm)",
          }}
        >
          🛡️
        </div>
        <div>
          <div
            style={{
              fontWeight: 700,
              fontSize: 15,
              letterSpacing: "-0.02em",
              background: "linear-gradient(135deg, var(--accent-bright), #60a5fa)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
            }}
          >
            VulnGuard AI
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
            v0.1.0 — beta
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ padding: "12px 8px" }}>
        {NAV_ITEMS.map((item) => (
          <a
            key={item.label}
            href={item.href}
            id={`nav-${item.label.toLowerCase().replace(/\s+/g, "-")}`}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "8px 10px",
              borderRadius: 8,
              textDecoration: "none",
              color: item.active ? "var(--text-primary)" : "var(--text-secondary)",
              background: item.active ? "var(--accent-subtle)" : "transparent",
              border: item.active ? "1px solid var(--border-accent)" : "1px solid transparent",
              marginBottom: 2,
              transition: "all var(--transition-fast)",
              fontSize: 13,
              fontWeight: item.active ? 500 : 400,
            }}
          >
            <span style={{ fontSize: 15, lineHeight: 1 }}>{item.icon}</span>
            {item.label}
          </a>
        ))}
      </nav>

      {/* Repository List */}
      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: "0 8px",
        }}
      >
        <div
          style={{
            padding: "8px 10px 6px",
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: "var(--text-muted)",
          }}
        >
          Repositories
        </div>

        {isLoading ? (
          <div style={{ padding: "20px", textAlign: "center", color: "var(--text-muted)", fontSize: 12 }}>
            <div className="animate-spin mb-2">⌛</div>
            Loading repositories...
          </div>
        ) : !selectedRepo ? (
          repos.length === 0 ? (
            <div style={{ padding: "20px", textAlign: "center", color: "var(--text-muted)", fontSize: 12 }}>
              No repositories found.
            </div>
          ) : (
            repos.map((repo) => (
              <button
                key={repo.id}
                id={`repo-${repo.id}`}
                onClick={() => setSelectedRepo(repo.full_name)}
                className="repo-item"
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: 8,
                  border: "1px solid transparent",
                  background: "transparent",
                  cursor: "pointer",
                  marginBottom: 4,
                  transition: "all var(--transition-fast)",
                  textAlign: "left",
                }}
              >
                <div style={{ flex: 1, overflow: "hidden" }}>
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 500,
                      color: "var(--text-primary)",
                      fontFamily: "JetBrains Mono, monospace",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis"
                    }}
                  >
                    {repo.full_name.split("/")[1]}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {repo.full_name.split("/")[0]}
                  </div>
                </div>
                {repo.private && (
                  <span style={{ fontSize: 10, opacity: 0.5 }}>🔒</span>
                )}
              </button>
            ))
          )
        ) : (
          <div className="file-explorer">
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12, padding: "0 4px" }}>
              <button 
                onClick={() => setSelectedRepo(null)}
                style={{ background: "none", border: "none", color: "var(--accent-bright)", cursor: "pointer", fontSize: 14 }}
              >
                ←
              </button>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis" }}>
                {selectedRepo.split("/")[1]}
              </div>
            </div>

            {currentPath && (
              <button 
                onClick={goBack}
                style={{ width: "100%", textAlign: "left", padding: "6px 8px", fontSize: 12, color: "var(--text-secondary)", background: "none", border: "none", cursor: "pointer" }}
              >
                📁 ..
              </button>
            )}

            {isFilesLoading ? (
               <div style={{ padding: "10px", textAlign: "center", color: "var(--text-muted)", fontSize: 11 }}>
                 Loading files...
               </div>
            ) : (
              files.map((item) => (
                <button
                  key={item.path}
                  onClick={() => handleItemClick(item)}
                  style={{
                    display: "block",
                    width: "100%",
                    padding: "6px 8px",
                    textAlign: "left",
                    fontSize: 12,
                    color: "var(--text-secondary)",
                    background: "none",
                    border: "none",
                    cursor: "pointer",
                    borderRadius: 4,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap"
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = "var(--bg-elevated)"}
                  onMouseLeave={(e) => e.currentTarget.style.background = "none"}
                >
                  {item.type === "dir" ? "📁" : "📄"} {item.name}
                </button>
              ))
            )}
          </div>
        )}
      </div>

      {/* Footer */}
      <div
        style={{
          padding: "12px 16px",
          borderTop: "1px solid var(--border-subtle)",
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}
      >
        <div
          style={{
            width: 28,
            height: 28,
            borderRadius: "50%",
            background: "linear-gradient(135deg, var(--accent-primary), #3b82f6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 12,
          }}
        >
          👤
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 12, fontWeight: 500, color: "var(--text-primary)" }}>
            {user?.username || "Guest User"}
          </div>
          <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
            {user ? "GitHub Pro" : "Not Logged In"}
          </div>
        </div>
      </div>
    </aside>
  );
}
