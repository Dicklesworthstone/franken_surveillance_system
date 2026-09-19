#!/usr/bin/env python3
"""Fail-closed gate tying manifested source paths to the layered integrity manifest.

ADR-0013 requires every commit that changes a manifested source path to carry the
change into MANIFEST.delta.sha256. The repository's working pattern lands code
commits first and a manifest refresh chore directly after, so this gate is
installed at `pre-push` (where the whole pushed tree must already be covered)
and can also be run manually in staged mode before each commit.

Install (local, same discipline as the commit-msg bead guard):

    printf '#!/usr/bin/env sh\npython3 -B scripts/manifest_delta_gate.py --worktree\n' \
        > .git/hooks/pre-push && chmod +x .git/hooks/pre-push

Exit codes: 0 = every covered path matches the effective manifest; 1 = listed
paths are missing from or stale in the layered manifest (remediation: append a
delta row with the current sha256, or run scripts/generate-manifest.py as a
deliberate compaction).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/manifest_audit.py"
spec = importlib.util.spec_from_file_location("manifest_audit", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def _digest(bytes_: bytes) -> str:
    return hashlib.sha256(bytes_).hexdigest()


def effective_manifest() -> dict[str, str]:
    base = module.parse_manifest(module.BASE)
    try:
        delta = module.parse_manifest(module.DELTA)
    except module.ManifestError:
        delta = {}
    return {**base, **delta}


def check(paths: dict[str, str]) -> list[str]:
    effective = effective_manifest()
    findings = []
    for relative, digest in sorted(paths.items()):
        if relative in module.MANIFEST_FILES:
            continue
        if not module.included(ROOT / relative):
            continue
        recorded = effective.get(relative)
        if recorded is None:
            findings.append(f"not manifested: {relative} (append a MANIFEST.delta.sha256 row)")
        elif recorded != digest:
            findings.append(
                f"stale manifest row: {relative} (delta row must record {digest})"
            )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate commits/pushes on layered-manifest coverage")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="verify git staged blobs")
    mode.add_argument("--worktree", action="store_true", help="verify the whole worktree (implies audit)")
    args = parser.parse_args()

    if args.worktree:
        try:
            report = module.audit()
        except module.ManifestError as exc:
            for finding in exc.findings:
                print(f"manifest delta gate: {finding}", file=sys.stderr)
            return 1
        print(f"manifest delta gate: worktree covered, effectiveRoot={report['effectiveRoot']}")
        return 0

    names = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR").splitlines()
    staged: dict[str, str] = {}
    for name in names:
        blob = subprocess.run(
            ["git", "show", f":{name}"], cwd=ROOT, capture_output=True, check=True
        ).stdout
        staged[name] = _digest(blob)
    findings = check(staged)
    if findings:
        for finding in findings:
            print(f"manifest delta gate: {finding}", file=sys.stderr)
        print(
            "manifest delta gate: refresh MANIFEST.delta.sha256 for the paths above before committing",
            file=sys.stderr,
        )
        return 1
    print(f"manifest delta gate: {len(staged)} staged path(s) covered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
