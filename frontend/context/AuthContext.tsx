"use client";

import React, { createContext, useContext, useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";

interface User {
  username: string;
  token: string;
}

interface AuthContextType {
  user: User | null;
  login: () => void;
  logout: () => void;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function AuthHandler({ setUser, setIsLoading }: { 
  setUser: (user: User | null) => void, 
  setIsLoading: (loading: boolean) => void 
}) {
  const searchParams = useSearchParams();
  const router = useRouter();

  useEffect(() => {
    // 1. Check search params (legacy)
    let token = searchParams.get("token");
    let username = searchParams.get("username");

    // 2. Check URL fragment (secure)
    if (!token && window.location.hash) {
      const hash = window.location.hash.substring(1);
      const params = new URLSearchParams(hash);
      token = params.get("token");
      username = params.get("username");
    }

    if (token && username) {
      const newUser = { token, username };
      localStorage.setItem("vulnguard_user", JSON.stringify(newUser));
      setUser(newUser);
      
      // Clean URL and redirect to avoid showing token in address bar
      const newUrl = window.location.pathname;
      window.history.replaceState({}, "", newUrl);
    } else {
      const stored = localStorage.getItem("vulnguard_user");
      if (stored) {
        try {
          setUser(JSON.parse(stored));
        } catch (e) {
          localStorage.removeItem("vulnguard_user");
        }
      }
    }
    setIsLoading(false);
  }, [searchParams, setUser, setIsLoading]);

  return null;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const login = () => {
    window.location.href = "http://localhost:8000/api/auth/github";
  };

  const logout = () => {
    localStorage.removeItem("vulnguard_user");
    setUser(null);
    window.location.href = "/";
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, isLoading }}>
      <Suspense fallback={null}>
        <AuthHandler setUser={setUser} setIsLoading={setIsLoading} />
      </Suspense>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
