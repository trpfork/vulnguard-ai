/**
 * VulnGuard AI — Theme Context
 *
 * Provides a "dark" | "light" theme that:
 * 1. Persists to localStorage
 * 2. Falls back to the user's OS preference on first visit
 * 3. Applies `data-theme` attribute to <html> for CSS variable switching
 * 4. Adds a short `.theme-transitioning` class to animate color changes
 */
"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from "react";

export type Theme = "dark" | "light";

interface ThemeContextValue {
  theme: Theme;
  toggleTheme: () => void;
  setTheme: (t: Theme) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

const STORAGE_KEY = "vulnguard-theme";
const TRANSITION_CLASS = "theme-transitioning";
const TRANSITION_DURATION = 230; // ms — must match CSS transition duration

function getInitialTheme(): Theme {
  if (typeof window === "undefined") return "dark";
  const stored = localStorage.getItem(STORAGE_KEY) as Theme | null;
  if (stored === "dark" || stored === "light") return stored;
  return window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
}

function applyTheme(theme: Theme) {
  const root = document.documentElement;

  // Add transition class to animate all color changes smoothly
  root.classList.add(TRANSITION_CLASS);
  root.setAttribute("data-theme", theme);

  // Remove the transition class after the animation completes
  setTimeout(() => {
    root.classList.remove(TRANSITION_CLASS);
  }, TRANSITION_DURATION);
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>("dark"); // SSR-safe default

  // Initialise from localStorage / OS preference after mount
  useEffect(() => {
    const initial = getInitialTheme();
    setThemeState(initial);
    applyTheme(initial);
  }, []);

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next);
    localStorage.setItem(STORAGE_KEY, next);
    applyTheme(next);
  }, []);

  const toggleTheme = useCallback(() => {
    setThemeState((prev) => {
      const next: Theme = prev === "dark" ? "light" : "dark";
      localStorage.setItem(STORAGE_KEY, next);
      applyTheme(next);
      return next;
    });
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used inside <ThemeProvider>");
  return ctx;
}
