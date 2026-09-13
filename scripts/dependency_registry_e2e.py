#!/usr/bin/env python3
"""End-to-end conformance script for the dependency registry row DEP-OWNED-001 (fss-x4a.30.88.1).

Runs the real entry points (``scripts/dependency_registry_checker.py`` as a subprocess and
``dependency_audit.audit_workspace`` for the dependency-class census) over isolated copies of the
repository's dependency authority, through a nominal pass, the highest-loss failures, and recovery:

  S0 nominal        live authority copy                          -> pass
  S1 flag-flip      allowlist c_or_cpp_ffi_allowed flipped        -> CONST-INVARIANT + ALLOWLIST-DIGEST-DIVERGED
  S2 row-tamper     DEP-OWNED-001 scope changed, re-digested      -> FREEZE-DIVERGENCE + REGISTRY-DRIFT
  S3 symlink        allowlist replaced by a symlink to a copy     -> CORRUPT-FILE (+ unresolved producers)
  S4 pending-crate  serde reaches a manifest and Cargo.lock       -> DEP-AUD-047 refusal naming fss-ndxis
  S5 recovery       S1's tree restored from the live authority    -> pass

Every step appends one JSON record to ``<out>/transcript.jsonl`` and stores its full report as a
content-addressed artifact ``<out>/artifacts/sha256-<digest>.json``. Records carry the requirement and
scenario/step ids, the registry generation, source digests and ContractBasis link, the deterministic
seed/schedule, the authority/privacy scope, the operational budget, expected and actual typed outcomes,
the registered repair guidance for each code, and the cleanup state. The script reads nothing secret and
performs no external effect; there is no cancellation path because no step starts background work.
The transcript is byte-identical across runs. Exit status is 1 if any step's outcome differs from the
expectation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dependency_audit  # noqa: E402
import dependency_authority as authority  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENT = "DEP-OWNED-001"
AUTHORITY_FILES = (
    "architecture/dependencies.json",
    "architecture/dependency_constitution.json",
    "architecture/dependency_allowlist.toml",
    "architecture/franken_imports.json",
    "architecture/local_qualification.toml",
    "architecture/stable_id_resolution.json",
    "architecture/agent_contracts.json",
    "registries/DEPENDENCIES.md",
    "registries/ERRORS.md",
    "scripts/dependency_audit.py",
    "scripts/dependency_authority.py",
    "scripts/dependency_registry_checker.py",
    "scripts/dependency_constitution_checker.py",
    "scripts/check-policy.py",
)


def copy_authority(source: Path, dest: Path) -> None:
    for rel in AUTHORITY_FILES:
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / rel, dest / rel)


def repair_guidance(source: Path) -> dict[str, str]:
    text = (source / "registries/ERRORS.md").read_text(encoding="utf-8")
    guidance: dict[str, str] = {}
    for code, _meaning, retry in re.findall(r"^\| `(ERR-DEP-[A-Z0-9-]+)` \| (.*?) \| (.*?) \|$", text, flags=re.MULTILINE):
        guidance[code] = retry
    for code, *_rest, remediation in [(m[0], m[3]) for m in re.findall(r"^\| `(DEP-AUD-[0-9]{3})` \| `?([a-z]+)`? \| (.*?) \| (.*?) \|", text, flags=re.MULTILINE)]:
        guidance[code] = remediation
    return guidance


def run_registry_checker(tree: Path) -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, "-B", str(tree / "scripts/dependency_registry_checker.py"), "--json", "--repo-root", str(tree)],
        capture_output=True, text=True, timeout=300,
    )
    report = json.loads(proc.stdout)
    report["exitCode"] = proc.returncode
    return report


def scenario_pending_crate(tree: Path) -> dict[str, Any]:
    """serde declared by a member and locked: the census and the manifest enumeration refuse it as pending."""
    shutil.copy2(tree / "architecture/dependency_allowlist.toml", tree / "policy.toml")
    (tree / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/fss-e2e"]\n\n[workspace.lints.rust]\nunsafe_code = "forbid"\n', encoding="utf-8")
    crate = tree / "crates" / "fss-e2e"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text('[package]\nname = "fss-e2e"\nversion = "0.0.1"\nedition = "2024"\n\n[dependencies]\nserde = { version = "1", default-features = false }\n', encoding="utf-8")
    (crate / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
    (tree / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "fss-e2e"\nversion = "0.0.1"\ndependencies = ["serde"]\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://example.invalid/index"\n', encoding="utf-8")
    (tree / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-08-31"\n', encoding="utf-8")
    report, rc = dependency_audit.audit_workspace(tree, tree / "policy.toml")
    errors = [f for f in report["findings"] if f["severity"] == "error" and f.get("params", {}).get("package") == "serde"]
    return {
        "passed": rc == 0,
        "errors": [{"code": f["code"], "file_path": f["path"], "target": "#serde", "message": f["message"]} for f in errors],
        "census": report.get("dependencyClassCensus", {}).get("DEP-FUND-001"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="directory for transcript.jsonl and artifacts/")
    parser.add_argument("--repo-root", type=Path, default=ROOT, help="repository whose dependency authority is exercised")
    args = parser.parse_args()
    source = args.repo_root.resolve()
    out = args.out
    (out / "artifacts").mkdir(parents=True, exist_ok=True)
    guidance = repair_guidance(source)
    live = authority.load_authority(source)
    base_record = {
        "requirement": REQUIREMENT,
        "registryGeneration": (live.registry or {}).get("generation"),
        "contractBasis": (live.registry or {}).get("contractBasis"),
        "sourceDigests": {
            "registry": live.registry_digest,
            "allowlist": live.allowlist_digest,
            "constitution": live.constitution_digest,
        },
        "seed": None,
        "schedule": "sequential, single process, no clock or randomness",
        "authority": "read-only copies of repository dependency-authority inputs",
        "privacy": "no secrets, credentials or protected media are read or logged",
        "budget": {"maxInputBytes": authority.MAX_INPUT_FILE_BYTES},
    }
    steps = [
        ("S0", "nominal", lambda tree: None, set()),
        ("S1", "flag-flip", lambda tree: (tree / "architecture/dependency_allowlist.toml").write_text(
            (tree / "architecture/dependency_allowlist.toml").read_text(encoding="utf-8").replace("c_or_cpp_ffi_allowed = false", "c_or_cpp_ffi_allowed = true", 1), encoding="utf-8"),
         {authority.ERR_DEP_CONST_INVARIANT, authority.ERR_DEP_ALLOWLIST_DIGEST_DIVERGED}),
        ("S2", "row-tamper", None, {authority.ERR_DEP_FREEZE_DIVERGENCE, authority.ERR_DEP_REGISTRY_DRIFT}),
        ("S3", "symlink", None, {authority.ERR_DEP_CORRUPT_FILE, authority.ERR_DEP_TRACE_UNRESOLVED}),
        ("S4", "pending-crate", None, {"DEP-AUD-023", "DEP-AUD-047"}),
        ("S5", "recovery", None, set()),
    ]

    def tamper_row(tree: Path) -> None:
        path = tree / "architecture/dependencies.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        next(r for r in data["dependencies"] if r["id"] == REQUIREMENT)["scope"] = "Development only"
        data["freezeDigest"] = authority.compute_canonical_dependencies_digest(data)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def symlink_allowlist(tree: Path) -> None:
        path = tree / "architecture/dependency_allowlist.toml"
        target = tree / "outside-allowlist.toml"
        shutil.move(path, target)
        path.symlink_to(target)

    mismatches = 0
    records: list[str] = []
    with tempfile.TemporaryDirectory(prefix="dep-e2e-") as scratch:
        flip_tree = Path(scratch) / "flip"
        for step_id, scenario, mutate, expected in steps:
            tree = Path(scratch) / step_id
            copy_authority(source, tree)
            if scenario == "row-tamper":
                tamper_row(tree)
            elif scenario == "symlink":
                symlink_allowlist(tree)
            elif mutate is not None:
                mutate(tree)
            if scenario == "flag-flip":
                shutil.copytree(tree, flip_tree)
            if scenario == "recovery":
                shutil.rmtree(tree)
                shutil.copytree(flip_tree, tree)
                shutil.copy2(source / "architecture/dependency_allowlist.toml", tree / "architecture/dependency_allowlist.toml")
            report = scenario_pending_crate(tree) if scenario == "pending-crate" else run_registry_checker(tree)
            actual = sorted({e["code"] for e in report.get("errors", [])})
            outcome = "pass" if report.get("passed") else "fail"
            matched = set(actual) == expected and (outcome == "pass") == (not expected)
            if scenario == "pending-crate":
                matched = matched and all("pending owner decision fss-ndxis" in e["message"] for e in report["errors"] if e["code"] == "DEP-AUD-047")
            mismatches += 0 if matched else 1
            artifact_bytes = json.dumps(report, sort_keys=True, ensure_ascii=False).replace(str(tree), "<tree>").encode("utf-8")
            digest = hashlib.sha256(artifact_bytes).hexdigest()
            (out / "artifacts" / f"sha256-{digest}.json").write_bytes(artifact_bytes)
            record = dict(base_record)
            record.update({
                "scenario": scenario,
                "step": step_id,
                "expected": {"outcome": "pass" if not expected else "fail", "codes": sorted(expected)},
                "actual": {"outcome": outcome, "codes": actual},
                "matched": matched,
                "repair": {code: guidance.get(code, "unregistered code") for code in actual},
                "cleanup": "temporary tree removed after the run",
                "artifact": f"sha256:{digest}",
            })
            records.append(json.dumps(record, sort_keys=True, ensure_ascii=False))
    summary = dict(base_record)
    summary.update({"scenario": "summary", "step": "END", "steps": len(steps), "mismatches": mismatches, "outcome": "pass" if mismatches == 0 else "fail"})
    records.append(json.dumps(summary, sort_keys=True, ensure_ascii=False))
    (out / "transcript.jsonl").write_text("\n".join(records) + "\n", encoding="utf-8")
    print(f"dependency registry e2e: {len(steps)} steps, {mismatches} mismatches; transcript {out / 'transcript.jsonl'}")
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
