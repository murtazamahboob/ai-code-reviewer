"""Unified-diff parsing: review only the lines a PR actually changed."""
from __future__ import annotations

import re
from dataclasses import dataclass

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")


@dataclass
class ChangedLines:
    """New-file line numbers that were added, per file."""

    files: dict[str, set[int]]

    def is_changed(self, filename: str, line: int) -> bool:
        return line in self.files.get(filename, set())

    def changed_files(self) -> list[str]:
        return sorted(self.files)


def parse_diff(diff_text: str) -> ChangedLines:
    """Parse a unified diff into {filename: {added new-file line numbers}}.

    Only lines starting with '+' (and not '+++') count, and only inside
    a hunk — so headers and context lines are never treated as changed.
    """
    files: dict[str, set[int]] = {}
    current_file: str | None = None
    new_line = 0
    in_hunk = False

    for raw in diff_text.splitlines():
        line = raw.rstrip("\n")
        file_match = _FILE_RE.match(line)
        if file_match:
            current_file = file_match.group(1)
            files.setdefault(current_file, set())
            in_hunk = False
            continue
        hunk = _HUNK_RE.match(line)
        if hunk:
            new_line = int(hunk.group(1))
            in_hunk = True
            continue
        if not in_hunk or current_file is None:
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            files[current_file].add(new_line)
            new_line += 1
        elif line.startswith("-"):
            pass  # removed line: does not advance the new-file counter
        else:
            new_line += 1  # context line
    return ChangedLines(files)
