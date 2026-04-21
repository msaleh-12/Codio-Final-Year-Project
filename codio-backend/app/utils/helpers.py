"""
Codio Backend - Shared Helper Utilities
Extracted from the original monolithic API file. Logic is unchanged.
"""

import re


def sanitize_error_text(value: str) -> str:
    """Remove ANSI color codes and trim noisy stderr output."""
    text = str(value or "")
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    return text.strip()


def normalize_question_text(text: str) -> str:
    """Normalize question text for deduplication comparison."""
    return " ".join((text or "").strip().lower().split())
