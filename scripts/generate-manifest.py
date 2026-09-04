#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "MANIFEST.sha256"
DELTA = ROOT / "MANIFEST.delta.sha256"
EXCLUDED_TOP_LEVEL = {
    ".git",
    ".ee",
    ".beads",
    ".claude",
    ".ntm",
    "target",
    "dist",
    "secrets",
    "credentials",
    "captures",
    "archive-spool",
    "model-cache",
}
EXCLUDED_PREFIXES = {
    Path("device-fixtures/private"),
    Path("qualification-artifacts"),
}


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if path.name == ".DS_Store" or "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
        return False
    if relative in {Path("MANIFEST.sha256"), Path("MANIFEST.delta.sha256")}:
        return False
    if relative.parts and relative.parts[0] in EXCLUDED_TOP_LEVEL:
        return False
    return not any(relative == prefix or prefix in relative.parents for prefix in EXCLUDED_PREFIXES)


entries: list[str] = []
for path in sorted(candidate for candidate in ROOT.rglob("*") if candidate.is_file() and included(candidate)):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    entries.append(f"{digest}  {path.relative_to(ROOT).as_posix()}")
OUTPUT.write_text("\n".join(entries) + "\n", encoding="utf-8")
DELTA.write_text("", encoding="utf-8")
print(f"compacted {OUTPUT.relative_to(ROOT)} with {len(entries)} entries; cleared {DELTA.name}")
