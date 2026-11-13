"""Tests for diff parsing, scoring/verdicts and the Markdown report."""
from reviewbot import parse_diff, render_markdown, review_source, score_findings
from reviewbot.findings import Finding

DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 import os
+import pickle
 x = 1
-y = 2
 z = 3
@@ -10,2 +11,3 @@
 def f():
+    return eval(x)
     return 1
"""


def test_parse_diff_added_lines_only():
    changed = parse_diff(DIFF)
    assert changed.is_changed("app.py", 2)   # +import pickle
    assert changed.is_changed("app.py", 12)  # +return eval(x)
    assert not changed.is_changed("app.py", 1)  # context
    assert not changed.is_changed("app.py", 3)  # context
    assert not changed.is_changed("app.py", 4)  # removed line y = 2


def test_parse_diff_unknown_file():
    assert not parse_diff(DIFF).is_changed("other.py", 2)


def test_empty_diff():
    assert parse_diff("").changed_files() == []


def test_score_clean_code():
    result = score_findings([])
    assert result.score == 100
    assert result.verdict == "Approve"


def test_score_critical_blocks():
    findings = review_source("eval(x)\n")
    result = score_findings(findings)
    assert result.verdict == "Block"
    assert result.score == 85  # 100 - 15 for one critical


def test_score_request_changes():
    findings = [
        Finding("SEC003", "high", "security", "t", "m", "a.py", 1),
        Finding("SEC003", "high", "security", "t", "m", "a.py", 2),
        Finding("SEC003", "high", "security", "t", "m", "a.py", 3),
        Finding("SEC003", "high", "security", "t", "m", "a.py", 4),
        Finding("SEC003", "high", "security", "t", "m", "a.py", 5),
        Finding("SEC003", "high", "security", "t", "m", "a.py", 6),
    ]
    result = score_findings(findings)
    assert result.score == 52
    assert result.verdict == "Request changes"


def test_markdown_report_lists_fixes():
    result = score_findings(review_source("eval(x)\n"))
    md = render_markdown(result)
    assert "Block" in md
    assert "SEC001" in md
    assert "Fix:" in md


def test_markdown_clean_report():
    md = render_markdown(score_findings([]))
    assert "No issues found" in md
