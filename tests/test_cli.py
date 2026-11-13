"""Tests for the CLI: review, --diff, --format json, --fail-under, demo."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def run_cli(*args):
    env = {"PYTHONPATH": str(SRC)}
    import os
    full_env = dict(os.environ, **env)
    return subprocess.run([sys.executable, "-m", "reviewbot.cli", *args],
                          capture_output=True, text=True, cwd=ROOT, env=full_env)


def test_cli_review_bad_file(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("eval(x)\n", encoding="utf-8")
    proc = run_cli("review", str(bad))
    assert proc.returncode == 0
    assert "SEC001" in proc.stdout
    assert "Block" in proc.stdout


def test_cli_review_json(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("eval(x)\n", encoding="utf-8")
    proc = run_cli("review", str(bad), "--format", "json")
    data = json.loads(proc.stdout)
    assert data["verdict"] == "Block"
    assert data["findings"][0]["rule"] == "SEC001"


def test_cli_fail_under(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("eval(x)\n", encoding="utf-8")
    proc = run_cli("review", str(bad), "--fail-under", "90")
    assert proc.returncode == 1


def test_cli_diff_only_changed_lines(tmp_path):
    code = tmp_path / "app.py"
    code.write_text("import pickle\nx = eval(y)\n", encoding="utf-8")
    diff = tmp_path / "change.diff"
    # Only line 1 (the import) is in the diff; the eval on line 2 is old code.
    diff.write_text("diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
                    "@@ -1,1 +1,2 @@\n+import pickle\n x = eval(y)\n",
                    encoding="utf-8")
    proc = run_cli("review", str(code), "--diff", str(diff))
    assert "SEC001" not in proc.stdout


def test_cli_missing_path():
    proc = run_cli("review", "does-not-exist.py")
    assert proc.returncode == 2


def test_cli_demo_writes_outputs():
    proc = run_cli("demo")
    assert proc.returncode == 0
    assert (ROOT / "outputs" / "review.md").exists()
    assert (ROOT / "outputs" / "summary.json").exists()
    summary = json.loads((ROOT / "outputs" / "summary.json").read_text())
    assert summary["verdict"] == "Block"
    assert summary["score"] < 60
