#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "MANIFEST.sha256"
DELTA = ROOT / "MANIFEST.delta.sha256"
MANIFEST_FILES = {Path("MANIFEST.sha256"), Path("MANIFEST.delta.sha256")}
EXCLUDED_TOP_LEVEL = {
    ".git",
    ".ee",
    ".beads",
    ".claude",
    ".ntm",
    ".agent_mail.db",
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
LINE = re.compile(r"([0-9a-f]{64})  ([^\r\n]+)")


class ManifestError(ValueError):
    """Fail-closed audit failure carrying every finding from one run, sorted."""

    def __init__(self, findings: list[str] | str) -> None:
        if isinstance(findings, str):
            findings = [findings]
        self.findings: list[str] = sorted(set(findings))
        super().__init__("\n".join(self.findings))


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if relative in MANIFEST_FILES:
        return False
    if path.name == ".DS_Store" or "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
        return False
    if relative.parts and relative.parts[0] in EXCLUDED_TOP_LEVEL:
        return False
    return not any(relative == prefix or prefix in relative.parents for prefix in EXCLUDED_PREFIXES)


def source_paths() -> set[str]:
    return {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file() and included(path)
    }


def parse_manifest_rows(path: Path, findings: list[str]) -> dict[str, str]:
    """Parse one layer, appending every malformed/unsafe/duplicate finding instead of stopping."""
    if not path.is_file():
        findings.append(f"missing manifest layer: {path.name}")
        return {}
    rows: dict[str, str] = {}
    duplicates: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        match = LINE.fullmatch(line)
        if match is None:
            findings.append(f"malformed {path.name} line {line_number}")
            continue
        digest, relative_text = match.groups()
        relative = Path(relative_text)
        if relative.is_absolute() or ".." in relative.parts or relative_text in {"MANIFEST.sha256", "MANIFEST.delta.sha256"}:
            findings.append(f"unsafe/self-referential manifest path in {path.name}: {relative_text}")
            continue
        if relative_text in rows:
            duplicates.add(relative_text)
            continue
        rows[relative_text] = digest
    findings.extend(f"duplicate path in {path.name}: {relative_text}" for relative_text in sorted(duplicates))
    return rows


def parse_manifest(path: Path) -> dict[str, str]:
    findings: list[str] = []
    rows = parse_manifest_rows(path, findings)
    if findings:
        raise ManifestError(findings)
    return rows


def audit(base: Path = BASE, delta: Path = DELTA) -> dict[str, object]:
    findings: list[str] = []
    base_rows = parse_manifest_rows(base, findings)
    delta_rows = parse_manifest_rows(delta, findings)
    merged = dict(base_rows)
    changed = 0
    added = 0
    for relative, digest in delta_rows.items():
        prior = merged.get(relative)
        if prior == digest:
            findings.append(f"redundant unchanged delta entry: {relative}")
        if prior is None:
            added += 1
        else:
            changed += 1
        merged[relative] = digest

    expected = source_paths()
    missing = sorted(expected - set(merged))
    stale = sorted(set(merged) - expected)
    if missing:
        findings.append("source files missing from layered manifest: " + ", ".join(missing))
    if stale:
        findings.append("layered manifest lists excluded/unknown files: " + ", ".join(stale))

    for relative in sorted(expected & set(merged)):
        path = ROOT / relative
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != merged[relative]:
            layer = "delta" if relative in delta_rows else "base"
            findings.append(
                f"{layer} manifest digest mismatch: {relative}: expected {merged[relative]}, observed {actual}"
            )

    if findings:
        raise ManifestError(findings)

    root_hasher = hashlib.sha256()
    for relative in sorted(merged):
        root_hasher.update(bytes.fromhex(merged[relative]))
        root_hasher.update(b"\0")
        root_hasher.update(relative.encode("utf-8"))
        root_hasher.update(b"\n")
    return {
        "schema": "fss.repository_manifest_audit.v1",
        "baseEntries": len(base_rows),
        "deltaEntries": len(delta_rows),
        "changedEntries": changed,
        "addedEntries": added,
        "effectiveEntries": len(merged),
        "effectiveRoot": "sha256:" + root_hasher.hexdigest(),
        "status": "passed",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the base + incremental FSS repository SHA-256 manifest")
    parser.add_argument("--base", type=Path, default=BASE)
    parser.add_argument("--delta", type=Path, default=DELTA)
    args = parser.parse_args()
    try:
        report = audit(args.base, args.delta)
    except ManifestError as exc:
        for finding in exc.findings:
            print(f"layered manifest audit failed: {finding}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"layered manifest audit failed: {exc}", file=sys.stderr)
        return 1
    for key, value in report.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
