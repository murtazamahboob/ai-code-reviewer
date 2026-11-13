"""CLI: review a file, directory, or unified diff; demo on a sample file."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reviewbot import parse_diff, render_markdown, review_path, review_source, score_findings
from reviewbot.rules import review_file


def _emit(result, fmt: str, output: Path | None) -> None:
    if fmt == "json":
        text = json.dumps(result.to_dict(), indent=2)
    else:
        text = render_markdown(result)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"Wrote {output} ({result.score}/100 — {result.verdict})")
    else:
        print(text)


def _review_target(target: Path, changed_only: bool, diff_text: str | None):
    findings = review_path(target)
    files_reviewed = 1 if target.is_file() else len(
        [p for p in target.rglob("*.py") if ".venv" not in p.parts
         and "__pycache__" not in p.parts]) if target.is_dir() else 0
    if changed_only and diff_text:
        changed = parse_diff(diff_text)
        findings = [f for f in findings
                    if changed.is_changed(f.file, f.line)
                    or changed.is_changed(Path(f.file).name, f.line)]
    return score_findings(findings, files_reviewed=files_reviewed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="reviewbot",
        description="Offline AI code reviewer: AST + pattern rules, scored verdict, fix suggestions.")
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="Review a Python file or directory")
    review.add_argument("path", help="Python file or directory to review")
    review.add_argument("--diff", dest="diff", default=None,
                        help="Unified diff file: only review added lines")
    review.add_argument("--format", choices=["md", "json"], default="md")
    review.add_argument("--output", default=None, help="Write the report to this file")
    review.add_argument("--fail-under", type=int, default=None,
                        help="Exit 1 when the score is below this value")

    sub.add_parser("demo", help="Review the bundled vulnerable sample and write outputs/")

    args = parser.parse_args(argv)

    if args.command == "demo":
        root = Path(__file__).resolve().parents[2]  # src/reviewbot/cli.py -> project root
        sample = root / "examples" / "sample_vulnerable.py"
        findings = review_file(sample)
        result = score_findings(findings, files_reviewed=1)
        out_dir = root / "outputs"
        out_dir.mkdir(exist_ok=True)
        (out_dir / "review.md").write_text(render_markdown(result), encoding="utf-8")
        (out_dir / "summary.json").write_text(
            json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"Reviewed {sample.name}: {len(findings)} findings, "
              f"score {result.score}/100 — {result.verdict}")
        for f in findings:
            print(f"  {f.severity:8} {f.rule} {f.file}:{f.line} {f.title}")
        return 0

    target = Path(args.path)
    if not target.exists():
        print(f"error: no such file or directory: {target}", file=sys.stderr)
        return 2
    diff_text = Path(args.diff).read_text(encoding="utf-8") if args.diff else None
    result = _review_target(target, changed_only=bool(diff_text), diff_text=diff_text)
    _emit(result, args.format, Path(args.output) if args.output else None)
    if args.fail_under is not None and result.score < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
