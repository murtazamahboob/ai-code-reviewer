"""Scoring and reporting: turn findings into a verdict + a review report."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .findings import Finding


@dataclass
class ReviewResult:
    findings: list[Finding]
    files_reviewed: int
    score: int  # 0-100
    verdict: str  # Approve | Comment | Request changes | Block

    @property
    def by_severity(self) -> Counter:
        return Counter(f.severity for f in self.findings)

    @property
    def by_category(self) -> Counter:
        return Counter(f.category for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "files_reviewed": self.files_reviewed,
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": dict(self.by_severity),
            "by_category": dict(self.by_category),
        }


def score_findings(findings: list[Finding], files_reviewed: int = 0) -> ReviewResult:
    """Score 100 minus the severity weights, floored at 0.

    Verdict rules, in order:
    * any critical finding -> Block
    * score < 60 -> Request changes
    * score < 85 -> Comment
    * otherwise -> Approve
    """
    score = max(0, 100 - sum(f.weight for f in findings))
    if any(f.severity == "critical" for f in findings):
        verdict = "Block"
    elif score < 60:
        verdict = "Request changes"
    elif score < 85:
        verdict = "Comment"
    else:
        verdict = "Approve"
    files = files_reviewed or len({f.file for f in findings})
    return ReviewResult(findings=list(findings), files_reviewed=files,
                        score=score, verdict=verdict)


def render_markdown(result: ReviewResult) -> str:
    """A PR-comment-ready Markdown report."""
    lines = [
        "# Code Review",
        "",
        f"**Score: {result.score}/100 — {result.verdict}**",
        "",
        f"Findings: {len(result.findings)} "
        f"({result.by_severity.get('critical', 0)} critical, "
        f"{result.by_severity.get('high', 0)} high, "
        f"{result.by_severity.get('medium', 0)} medium, "
        f"{result.by_severity.get('low', 0)} low)",
        "",
    ]
    if not result.findings:
        lines.append("No issues found. Ship it. ✅")
        return "\n".join(lines) + "\n"
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ordered = sorted(result.findings,
                     key=lambda f: (severity_order[f.severity], f.file, f.line))
    for finding in ordered:
        lines += [
            f"## {finding.severity.upper()} · {finding.rule} — {finding.title}",
            "",
            f"**{finding.file}:{finding.line}** — {finding.message}",
            "",
        ]
        if finding.evidence:
            lines += ["```python", finding.evidence, "```", ""]
        if finding.suggestion:
            lines += [f"**Fix:** {finding.suggestion}", ""]
    return "\n".join(lines)
