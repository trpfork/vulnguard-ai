/**
 * VulnGuard AI — Dashboard Layout
 * Responsive shell: Sidebar | Main Content | Live Agent Feed
 */

import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "VulnGuard AI — Security Dashboard",
  description:
    "AI-powered vulnerability scanner and patcher for GitHub repositories.",
};

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        width: "100vw",
        overflow: "hidden",
        background: "var(--bg-base)",
      }}
    >
      {children}
    </div>
  );
}
