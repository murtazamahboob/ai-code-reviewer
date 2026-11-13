"""Demo: review the bundled vulnerable sample and write outputs/.

Run from the project root:  python examples/demo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reviewbot.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["demo"]))
