"""AI Code Reviewer Bot — offline, deterministic code review.

No LLM, no network, no API key: AST + pattern rules review Python
code and produce a scored verdict with a concrete fix for every issue.
"""
from __future__ import annotations

from .diff import ChangedLines, parse_diff
from .findings import Finding
from .report import ReviewResult, render_markdown, score_findings
from .rules import review_file, review_path, review_source

__all__ = [
    "ChangedLines", "Finding", "ReviewResult", "parse_diff",
    "render_markdown", "review_file", "review_path", "review_source",
    "score_findings",
]

__version__ = "1.0.0"
