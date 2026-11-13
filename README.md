# AI Code Reviewer Bot — Offline Code Review for Python Pull Requests

**Review Python code like a senior engineer — fully offline, no LLM, no API key, deterministic.** Most AI code reviewers send your diff to a cloud model and charge per review. This one doesn't: it parses your code with Python's own AST and 24 deterministic rules, finds bugs, security holes and quality problems in files or PR diffs, and returns a scored verdict — **Approve, Comment, Request changes or Block** — with a concrete fix for every single finding.

## Results (measured, not claimed)

The bundled demo reviews a deliberately vulnerable sample file (`examples/sample_vulnerable.py`):

| Metric | Measured |
|---|---|
| Findings on the sample | **24** (2 critical, 8 high, 7 medium, 7 low) |
| Score / verdict | **0/100 — Block** |
| Security findings | 10 (eval, pickle, shell, hardcoded secret, SQL injection, …) |
| Bug findings | 10 (mutable defaults, bare except, unreachable code, …) |
| Quality findings | 4 |
| Test suite | **46/46 tests pass**, verified twice — including in a fresh venv |
| Runtime dependencies | **none** (stdlib only) |

## Features

- **24 deterministic rules, three categories** — Security (SEC001–SEC010): `eval`/`exec`, unsafe `pickle`/`yaml.load`, `shell=True` / `os.system`, hardcoded secrets, SQL built by string formatting, `verify=False`, weak hashes, insecure randomness for tokens. Bugs (BUG001–BUG010): mutable default arguments, bare `except`, silent `except: pass`, `== None`, `is` with a literal, unreachable code, unused imports/variables, `assert` for validation, syntax errors. Quality (QLT001–QLT008): functions too long, too many parameters, deep nesting, cyclomatic complexity > 10, long lines, TODO markers, `print()` in code, duplicated function bodies.
- **Diff-aware PR review** — give it a unified diff and it reviews only the lines the PR actually added, so old code never blocks a new change.
- **Scored verdict** — 100 minus severity weights (critical 15, high 8, medium 4, low 1). Any critical finding blocks; under 60 requests changes; under 85 comments; otherwise approves.
- **A fix for every finding** — each issue carries the exact evidence line and a concrete suggestion, not a vague hint. Safe patterns are not flagged: parameterised SQL queries, `yaml.safe_load()`, `json.loads()` and placeholder secrets all pass clean.
- **CI-ready CLI** — `--fail-under N` exits non-zero below a score threshold; `--format json` for tooling; `--output` writes the Markdown report.

## Quickstart

```bash
pip install -r requirements.txt
pip install -e .

# Review a file or a whole project
reviewbot review my_script.py
reviewbot review ./src --format json --output review.json

# Review only what a PR changed (diff-aware)
reviewbot review ./src --diff changes.diff

# Gate a CI job: fail when the score drops below 80
reviewbot review ./src --fail-under 80

# Run the full demo (reviews the vulnerable sample, writes outputs/)
python examples/demo.py
```

## Python API

```python
from reviewbot import review_source, review_path, score_findings, render_markdown

findings = review_source("eval(user_input)\n")
result = score_findings(findings)
result.score      # 85
result.verdict    # 'Block' — any critical finding blocks
print(render_markdown(result))

# Diff-aware: only findings on added lines survive
from reviewbot import parse_diff
changed = parse_diff(open("changes.diff").read())
kept = [f for f in review_path("./src") if changed.is_changed(f.file, f.line)]
```

## How the review works

1. **Parse** — Python's `ast` module parses the source; a syntax error is itself a critical finding (BUG000), because nothing else can be reviewed until the file parses.
2. **Detect** — a single AST visitor applies every rule in one pass, plus line rules (long lines, TODO markers) and cross-function rules (duplicated bodies, unused imports). Each finding records the rule id, severity, exact line and the evidence line.
3. **Score** — findings are weighted by severity and mapped to a verdict. The report is a PR-comment-ready Markdown file with a **Fix:** line under every issue.

## Project structure

```
ai-code-reviewer/
├── src/reviewbot/
│   ├── __init__.py      # public API: review_source, review_path, score_findings, ...
│   ├── rules.py         # 24 AST + pattern detectors (SEC/BUG/QLT)
│   ├── diff.py          # unified-diff parser: added lines per file
│   ├── findings.py      # Finding dataclass + severity weights
│   ├── report.py        # scoring, verdicts, Markdown report
│   └── cli.py           # review / demo commands, --fail-under, --format
├── examples/
│   ├── sample_vulnerable.py   # deliberately bad code — the demo input
│   └── demo.py                # runs the demo, writes outputs/
├── tests/               # 46 tests: security rules, bug/quality rules, diff, report, CLI
├── outputs/
│   ├── review.md        # demo report: 24 findings, 0/100 — Block
│   └── summary.json     # demo results as JSON
├── pyproject.toml
└── requirements.txt     # stdlib-only runtime; pytest for tests
```

## Tech stack

Python 3.10+ · standard library only (`ast`, `argparse`, `re`, `hashlib`) · pytest 9.2.0 for tests · no network, no API key, no model downloads.

## License

MIT — see [LICENSE](LICENSE).
