# Implementation Plan: GitHub OAuth Integration

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the static `GITHUB_TOKEN` with a dynamic GitHub OAuth flow to allow users to sign in with their own accounts and scan their repositories.

**Architecture:** 
- **GitHub App:** A registered app on GitHub to handle OAuth.
- **FastAPI Backend:** Endpoints to initiate the OAuth flow and exchange the temporary code for an access token.
- **Next.js Frontend:** UI for authentication state and protected routes.
- **Database:** PostgreSQL to store user profiles and encrypted access tokens.

---

### Phase 1: GitHub App & Backend Foundation

#### Task 1.1: GitHub App Registration
**Action:** (Manual Step for User)
- Register a new GitHub App at `github.com/settings/apps`.
- Set Callback URL to `http://localhost:8000/api/auth/callback`.
- Generate a `Client ID` and `Client Secret`.

#### Task 1.2: Backend Auth Endpoints
**Files:**
- Modify: `backend/main.py`
- Modify: `.env`

**Step 1: Update .env**
Add `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.

**Step 2: Implement `/api/auth/github`**
Redirect the user to GitHub's OAuth authorization page.

**Step 3: Implement `/api/auth/callback`**
Exchange the `code` from GitHub for an `access_token` and return it to the frontend (or set a cookie).

---

### Phase 2: Frontend Auth Integration

#### Task 2.1: Auth State Management
**Files:**
- Create: `frontend/context/AuthContext.tsx`
- Modify: `frontend/app/layout.tsx`

**Step 1: Create AuthContext**
Manage `user` state and `isAuthenticated` status using React Context.

**Step 2: Wrap Application**
Ensure the entire app has access to the auth state.

#### Task 2.2: Login Component
**Files:**
- Create: `frontend/components/LoginButton.tsx`
- Modify: `frontend/app/dashboard/page.tsx`

**Step 1: Build the button**
A premium "Sign in with GitHub" button with a GitHub icon.

**Step 2: Protected Dashboard**
Redirect unauthenticated users from `/dashboard` back to a landing page or login modal.

---

### Phase 3: Secure Token Persistence

#### Task 3.1: Database Schema Update
**Files:**
- Modify: `backend/models.py` (or similar)
- Run: Database migration

**Step 1: Add User table**
Store `github_id`, `username`, `email`, and `access_token` (encrypted).

#### Task 3.2: Session Handling
**Files:**
- Modify: `backend/main.py`

**Step 1: JWT Implementation**
Issue a secure JWT to the frontend after successful OAuth callback to maintain session state.

---

### Phase 4: Using OAuth for Scans

#### Task 4.1: Dynamic Repository Fetching
**Files:**
- Modify: `backend/agents/scanner.py`

**Step 1: Inject Token**
Update the scanner to use the user's `access_token` instead of the global `GITHUB_TOKEN`.

**Step 2: Fetch User Repos**
Create an endpoint `/api/user/repos` to list repositories the user has access to.
