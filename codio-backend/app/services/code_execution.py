"""
Codio Backend - Code Execution & Completion Service
Handles Piston API proxy, local fallback execution, and AI code completion.
Logic is unchanged from the original monolithic API file.
"""

import os
import sys
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

import google.generativeai as genai

from config.settings import (
    PISTON_TIMEOUT_SECONDS,
    CODE_COMPLETION_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local Python Execution Fallback
# ---------------------------------------------------------------------------

def execute_python_code_locally(code: str) -> dict:
    """Fallback runner when upstream execution service is unavailable."""
    try:
        completed = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=PISTON_TIMEOUT_SECONDS,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        return {
            "code": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "output": f"{stdout}{stderr}",
        }
    except subprocess.TimeoutExpired:
        return {
            "code": 124,
            "stdout": "",
            "stderr": f"Execution timed out after {PISTON_TIMEOUT_SECONDS}s",
            "output": "",
        }
    except Exception as e:
        return {
            "code": 1,
            "stdout": "",
            "stderr": f"Local execution fallback failed: {e}",
            "output": "",
        }


# ---------------------------------------------------------------------------
# Code Completion
# ---------------------------------------------------------------------------

def fallback_code_completion(prefix: str) -> str:
    """Simple deterministic fallback completion when AI is unavailable."""
    text = (prefix or "").rstrip()
    stripped = text.splitlines()[-1].lstrip() if text.splitlines() else ""

    if stripped.endswith("for") or stripped.endswith("for "):
        return " i in range(10):\n    "
    if stripped.endswith("if") or stripped.endswith("if "):
        return " True:\n    "
    if stripped.endswith("while") or stripped.endswith("while "):
        return " True:\n    "
    if stripped.endswith("def") or stripped.endswith("def "):
        return " function_name():\n    "
    if stripped.endswith("class") or stripped.endswith("class "):
        return " ClassName:\n    def __init__(self):\n        pass"
    if stripped.endswith("print"):
        return "()"

    return ""


def clean_completion_text(text: str) -> str:
    """Strip markdown fences and cap length."""
    completion = (text or "").strip()
    if completion.startswith("```"):
        lines = completion.split("\n")
        completion = "\n".join(lines[1:-1]).strip()
    return completion[:700]


def generate_ai_code_completion(code: str, cursor_position: int) -> tuple[str, str]:
    """Return (completion, source)."""
    safe_code = code or ""
    cursor = max(0, min(int(cursor_position or 0), len(safe_code)))
    before_cursor = safe_code[:cursor]
    after_cursor = safe_code[cursor:]

    context_before = "\n".join(before_cursor.splitlines()[-40:])
    context_after = "\n".join(after_cursor.splitlines()[:10])

    fallback = fallback_code_completion(context_before)

    api_key = os.getenv("PAUSE_TO_CODE_GEMINI_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return fallback, "fallback"

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        prompt = f"""You are a Python coding assistant for inline code completion.

Task:
- Suggest the most likely next code text at the cursor.
- Return ONLY the code to insert at cursor (no markdown, no explanations).
- Keep it short and useful (typically 1-5 lines).
- Respect existing indentation and style.

Code before cursor:
{context_before}

Code after cursor:
{context_after}
"""

        def _generate_text() -> str:
            response = model.generate_content(prompt)
            return (response.text or "").strip()

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_generate_text)
            try:
                raw = future.result(timeout=CODE_COMPLETION_TIMEOUT_SECONDS)
            except FutureTimeoutError:
                future.cancel()
                return fallback, "fallback"

        cleaned = clean_completion_text(raw)
        if not cleaned:
            return fallback, "fallback"
        return cleaned, "gemini"
    except Exception as e:
        logger.warning(f"AI code completion fallback used: {e}")
        return fallback, "fallback"
