"""
VulnGuard AI — LLM Client
Initialises the LLM backend with fallback chain:
  1. Google Gemini (google-genai SDK) — primary
  2. OpenAI GPT-4o                    — fallback
  3. Anthropic Claude                 — fallback

Follows the gemini-api-dev skill: uses `google-genai` SDK,
model `gemini-3-flash-preview` (fast, balanced, 1M context).
"""

import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


def get_gemini_client():
    """Return a configured google-genai client or None if key missing."""
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return None, None
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        return client, "gemini-3-flash-preview"
    except ImportError:
        return None, None


def get_openai_client():
    """Return a configured OpenAI client or None if key missing."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or api_key.startswith("your_"):
        return None, None
    try:
        from openai import OpenAI
        return OpenAI(api_key=api_key), "gpt-4o"
    except ImportError:
        return None, None


def get_anthropic_client():
    """Return a configured Anthropic client or None if key missing."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key.startswith("your_"):
        return None, None
    try:
        import anthropic
        return anthropic.Anthropic(api_key=api_key), "claude-sonnet-4-5"
    except ImportError:
        return None, None


def generate_text(prompt: str, system: Optional[str] = None) -> str:
    """
    Send a prompt to the best available LLM.
    Falls back through: Gemini → OpenAI → Anthropic → mock response.
    """
    # 1. Try Gemini
    client, model = get_gemini_client()
    if client:
        try:
            contents = prompt
            if system:
                contents = f"System instructions:\n{system}\n\n---\n\n{prompt}"
            response = client.models.generate_content(
                model=model,
                contents=contents,
            )
            return response.text
        except Exception as e:
            print(f"[LLM] Gemini failed: {e}, trying OpenAI...")

    # 2. Try OpenAI
    client, model = get_openai_client()
    if client:
        try:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            resp = client.chat.completions.create(model=model, messages=messages)
            return resp.choices[0].message.content
        except Exception as e:
            print(f"[LLM] OpenAI failed: {e}, trying Anthropic...")

    # 3. Try Anthropic
    client, model = get_anthropic_client()
    if client:
        try:
            kwargs = {"model": model, "max_tokens": 4096,
                      "messages": [{"role": "user", "content": prompt}]}
            if system:
                kwargs["system"] = system
            resp = client.messages.create(**kwargs)
            return resp.content[0].text
        except Exception as e:
            print(f"[LLM] Anthropic failed: {e}")

    # 4. Mock fallback — for testing without any API key
    print("[LLM] No API key found — using mock response for testing.")
    return _mock_response(prompt)


def _mock_response(prompt: str) -> str:
    """Return a deterministic mock response for offline testing."""
    if "identify" in prompt.lower() or "scan" in prompt.lower():
        return """
[
  {
    "severity": "critical",
    "vuln_type": "Broken Access Control",
    "cwe": "CWE-639",
    "line": 24,
    "description": "Direct object reference without authorization check — any user can read any profile by manipulating user_id.",
    "code_snippet": "$result = $db->query(\\"SELECT * FROM users WHERE id = \\" . $user_id);",
    "confidence": 0.97,
    "owasp_category": "A01:2021"
  },
  {
    "severity": "high",
    "vuln_type": "SQL Injection",
    "cwe": "CWE-89",
    "line": 38,
    "description": "Unsanitized user input concatenated directly into SQL query.",
    "code_snippet": "$sql = \\"SELECT id, username, email FROM users WHERE username LIKE '%\\" . $query . \\"%'\\";",
    "confidence": 0.99,
    "owasp_category": "A03:2021"
  },
  {
    "severity": "high",
    "vuln_type": "Reflected XSS",
    "cwe": "CWE-79",
    "line": 52,
    "description": "User-controlled $_GET['name'] rendered without HTML escaping.",
    "code_snippet": "echo \\"<h1>Welcome, \\" . $name . \\"!</h1>\\";",
    "confidence": 0.95,
    "owasp_category": "A03:2021"
  },
  {
    "severity": "medium",
    "vuln_type": "Hardcoded Credential",
    "cwe": "CWE-798",
    "line": 14,
    "description": "Database password hardcoded in source code.",
    "code_snippet": "$db_password = \\"super_secret_pass123\\";",
    "confidence": 1.0,
    "owasp_category": "A07:2021"
  }
]
"""
    if "confirm" in prompt.lower() or "verif" in prompt.lower() or "candidate" in prompt.lower():
        # Verifier: return integer indices of confirmed findings
        return "[0, 1, 2, 3]"
        return """
```json
[
  {
    "finding_id": "0",
    "description": "Add authorization check before fetching user profile",
    "original_code": "$result = $db->query(\\\"SELECT * FROM users WHERE id = \\\" . $user_id);",
    "patched_code": "if ($user_id !== $_SESSION['user_id'] && !isAdmin()) { http_response_code(403); exit('Forbidden'); }\\n    $stmt = $db->prepare('SELECT * FROM users WHERE id = ?');\\n    $stmt->bind_param('i', $user_id);\\n    $stmt->execute();\\n    $result = $stmt->get_result();",
    "explanation": "Check that the requesting user is authorized to view the requested profile. Use prepared statements to prevent SQL injection."
  }
]
```
"""
    return '{"result": "mock response"}'
