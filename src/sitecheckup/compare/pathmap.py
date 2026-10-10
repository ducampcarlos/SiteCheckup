"""Intentional URL changes: a CSV mapping old paths to new paths."""

from __future__ import annotations

import csv
from pathlib import Path


class PathMapError(ValueError):
    """Raised for a malformed path-map file."""


def _normalize(value: str) -> str:
    value = value.strip()
    if "://" in value:
        return value
    return value if value.startswith("/") else f"/{value}"


def load_path_map(path: Path) -> dict[str, str]:
    """Read ``old_path,new_path`` rows from a CSV file.

    A header row (``old_path,new_path``) and ``#`` comment lines are optional.
    Paths may omit the leading slash; ``new_path`` may be an absolute URL.
    """
    mapping: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for number, row in enumerate(csv.reader(handle), start=1):
            if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                continue
            if number == 1 and row[0].strip().lower() in {"old", "old_path", "source"}:
                continue
            if len(row) < 2 or not row[1].strip():
                raise PathMapError(f"{path}:{number}: expected 'old_path,new_path'")
            mapping[_normalize(row[0])] = _normalize(row[1])
    return mapping
