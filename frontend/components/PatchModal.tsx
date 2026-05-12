"use client";

import { useState, useEffect } from "react";

interface PatchModalProps {
  findingId: string;
  token: string;
  onClose: () => void;
}

export function PatchModal({ findingId, token, onClose }: PatchModalProps) {
  const [patch, setPatch] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`http://localhost:8000/api/findings/${findingId}/patch?token=${token}`)
      .then((res) => res.json())
      .then((data) => setPatch(data))
      .catch((err) => console.error("Failed to fetch patch:", err))
      .finally(() => setLoading(false));
  }, [findingId, token]);

  if (loading) return null;

  return (
    <div style={{
      position: "fixed",
      inset: 0,
      backgroundColor: "rgba(0,0,0,0.7)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      zIndex: 1000,
      backdropFilter: "blur(4px)"
    }}>
      <div style={{
        width: "90%",
        maxWidth: "800px",
        maxHeight: "85vh",
        backgroundColor: "var(--bg-card)",
        borderRadius: "16px",
        border: "1px solid var(--border-subtle)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.5)"
      }}>
        {/* Header */}
        <div style={{ padding: "20px 24px", borderBottom: "1px solid var(--border-subtle)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h3 style={{ fontSize: "18px", fontWeight: 600, color: "var(--text-primary)" }}>AI Suggested Patch</h3>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: "20px" }}>×</button>
        </div>

        {/* Content */}
        <div style={{ padding: "24px", overflowY: "auto", flex: 1 }}>
          <div style={{ marginBottom: "20px" }}>
            <h4 style={{ fontSize: "14px", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "8px" }}>Description</h4>
            <p style={{ fontSize: "14px", color: "var(--text-muted)" }}>{patch?.description}</p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "20px" }}>
            <div>
              <h4 style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-critical)", textTransform: "uppercase", marginBottom: "8px" }}>Vulnerable</h4>
              <pre style={{ 
                padding: "12px", 
                backgroundColor: "rgba(239, 68, 68, 0.1)", 
                borderRadius: "8px", 
                fontSize: "12px", 
                color: "var(--color-critical)", 
                overflow: "auto",
                fontFamily: "JetBrains Mono, monospace"
              }}>
                {patch?.original_code}
              </pre>
            </div>
            <div>
              <h4 style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-success)", textTransform: "uppercase", marginBottom: "8px" }}>Fixed</h4>
              <pre style={{ 
                padding: "12px", 
                backgroundColor: "rgba(16, 185, 129, 0.1)", 
                borderRadius: "8px", 
                fontSize: "12px", 
                color: "var(--color-success)", 
                overflow: "auto",
                fontFamily: "JetBrains Mono, monospace"
              }}>
                {patch?.patched_code}
              </pre>
            </div>
          </div>

          <div>
            <h4 style={{ fontSize: "14px", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "8px" }}>Explanation</h4>
            <div style={{ fontSize: "13px", color: "var(--text-muted)", backgroundColor: "var(--bg-elevated)", padding: "16px", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
              {patch?.explanation}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div style={{ padding: "16px 24px", borderTop: "1px solid var(--border-subtle)", display: "flex", justifyContent: "flex-end", gap: "12px" }}>
          <button onClick={onClose} style={{ padding: "8px 16px", borderRadius: "8px", border: "1px solid var(--border-subtle)", backgroundColor: "transparent", color: "var(--text-primary)", cursor: "pointer" }}>Close</button>
          <button 
            style={{ 
              padding: "8px 16px", 
              borderRadius: "8px", 
              border: "none", 
              backgroundColor: "var(--accent-primary)", 
              color: "white", 
              fontWeight: 600, 
              cursor: "pointer" 
            }}
            onClick={() => alert("Patch application is simulated. In a real environment, this would create a PR.")}
          >
            Apply Fix
          </button>
        </div>
      </div>
    </div>
  );
}
