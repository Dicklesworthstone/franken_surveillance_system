#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/fss-one-shot-hydration-reconcile.yml"
SELF = Path(__file__).resolve()


def run(*args: str, capture: bool = False) -> str:
    result = subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    return result.stdout if capture else ""


def write_if_changed(path: Path, content: str) -> None:
    if not content.endswith("\n"):
        content += "\n"
    if path.read_text() != content:
        path.write_text(content)


def patch_semantic_hydration_consumer_test() -> None:
    path = ROOT / "crates/fss-core/tests/semantic_hydration_contract.rs"
    text = path.read_text()
    text = text.replace("fn request(\n", "fn make_request(\n", 1)
    text = text.replace("request(&handle, HydrationLevel::H1, None)?", "make_request(&handle, HydrationLevel::H1, None)?")
    text = text.replace("request(&handle, HydrationLevel::H2, Some(cursor))?", "make_request(&handle, HydrationLevel::H2, Some(cursor))?")
    text = text.replace("request(&handle, HydrationLevel::H0, None)?", "make_request(&handle, HydrationLevel::H0, None)?")
    write_if_changed(path, text)


def patch_receipt_contract() -> None:
    path = ROOT / "crates/fss-core/src/hydration/receipt.rs"
    text = path.read_text()

    if "request.issued_at < handle.published_at" not in text:
        needle = """        let effective_availability = if request.issued_at >= handle.retention_until {\n"""
        replacement = """        if request.issued_at < handle.published_at {\n            return Err(ContractError::StaleAnchor.into());\n        }\n        let effective_availability = if request.issued_at >= handle.retention_until {\n"""
        if needle not in text:
            raise RuntimeError("receipt publication-time insertion point not found")
        text = text.replace(needle, replacement, 1)

    if "artifact.applied_transform != handle.applied_transform" not in text:
        needle = """                    || !handle.levels.contains(&level)\n                    || !self.proof_roots.contains(&artifact.payload_digest)\n"""
        replacement = """                    || !handle.levels.contains(&level)\n                    || artifact.applied_transform != handle.applied_transform\n                    || !artifact.proof_roots.contains(&handle.subject_digest)\n                    || !self.proof_roots.contains(&artifact.payload_digest)\n"""
        if needle not in text:
            raise RuntimeError("receipt artifact-binding insertion point not found")
        text = text.replace(needle, replacement, 1)

    if "let maximum = handle" not in text:
        needle = """            let Some(delivered) = self.delivered_level else {\n                return Err(ContractError::EvidenceRequired.into());\n            };\n            if cursor.scope != ContinuationScope::EvidenceHydration\n"""
        replacement = """            let Some(delivered) = self.delivered_level else {\n                return Err(ContractError::EvidenceRequired.into());\n            };\n            let maximum = handle\n                .maximum_level()\n                .ok_or(HydrationError::LevelUnavailable)?;\n            let Some(artifact_digest) = self.artifact_digest else {\n                return Err(ContractError::EvidenceRequired.into());\n            };\n            if cursor.scope != ContinuationScope::EvidenceHydration\n"""
        if needle not in text:
            raise RuntimeError("receipt cursor prelude insertion point not found")
        text = text.replace(needle, replacement, 1)

    if "cursor.stream_digest != handle.ladder_policy_digest()" not in text:
        needle = """                || cursor.resume_anchor != self.anchor\n                || cursor.position != u64::from(delivered.ordinal()) + 1\n"""
        replacement = """                || cursor.resume_anchor != self.anchor\n                || cursor.stream_digest != handle.ladder_policy_digest()\n                || cursor.position != u64::from(delivered.ordinal()) + 1\n                || cursor.total_items != u64::from(maximum.ordinal()) + 1\n                || cursor.page_digest != artifact_digest\n                || cursor.expires_at > handle.retention_until\n"""
        if needle not in text:
            raise RuntimeError("receipt cursor-binding insertion point not found")
        text = text.replace(needle, replacement, 1)

    write_if_changed(path, text)


def ensure_reference_wiring() -> None:
    path = ROOT / "crates/fss-reference/src/lib.rs"
    text = path.read_text()
    if "mod hydration;" not in text:
        text = text.replace("mod error;\n", "mod error;\nmod hydration;\n", 1)
    if "mod hydration_tests;" not in text:
        text = text.replace("mod bundle_tests;\n", "mod bundle_tests;\n#[cfg(test)]\nmod hydration_tests;\n", 1)
    if "pub use hydration::*;" not in text:
        text = text.replace("pub use error::ReferenceError;\n", "pub use error::ReferenceError;\npub use hydration::*;\n", 1)
    write_if_changed(path, text)


def update_bead() -> None:
    path = ROOT / ".beads/issues.jsonl"
    lines = path.read_text().splitlines()
    objects = [json.loads(line) for line in lines]
    all_statuses = {item.get("status") for item in objects}
    max_comment_id = max(
        (comment.get("id", 0) for item in objects for comment in item.get("comments", [])),
        default=0,
    )
    marker = "FSS-210 deterministic reference progress"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    found = False
    for item in objects:
        if item.get("external_ref") != "FSS-210":
            continue
        found = True
        comments = item.setdefault("comments", [])
        if not any(marker in comment.get("text", "") for comment in comments):
            max_comment_id += 1
            comments.append(
                {
                    "id": max_comment_id,
                    "issue_id": item["id"],
                    "author": "codex-agent",
                    "text": (
                        f"{marker} — 2026-09-03\n\n"
                        "Implemented and exercised the dependency-free SemanticHandle and H0-H4 "
                        "hydration reference slice: immutable subject identity, independently "
                        "versioned descriptors, typed availability, exact request/artifact/receipt "
                        "closure, capability/privacy/full-vector budget enforcement, explicit "
                        "downgrade, H4 gating, subject/transform/provenance binding, retention-aware "
                        "expiry, and exact continuation cursors closed over ladder policy and the "
                        "delivered artifact. Added external-consumer and process-level deterministic "
                        "rehearsals.\n\n"
                        "This is implementation progress, not completion. FSS-210 remains open until "
                        "schemas and machine registries agree, every context-pack expansion is bound "
                        "to a published descriptor, persistent custody/retention/deletion semantics "
                        "exist, Rust/CLI/MCP/TUI/report/handoff payloads are equivalent, required "
                        "fault and multi-agent schedules pass, and QL-AGENT/GATE-115 proof roots are "
                        "retained. Hosted execution is supplementary and does not replace local DSR "
                        "release authority."
                    ),
                    "created_at": now,
                }
            )
        if item.get("status") == "open" and "in_progress" in all_statuses:
            item["status"] = "in_progress"
        item["updated_at"] = now
        break
    if not found:
        raise RuntimeError("FSS-210 bead not found")
    path.write_text("\n".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in objects) + "\n")


def write_implementation_record() -> None:
    path = ROOT / "docs/FSS_210_IMPLEMENTATION_RECORD.md"
    content = """# FSS-210 implementation record

**Requirement:** FSS-210 — semantic handles and bounded H0–H4 hydration  
**State:** deterministic reference slice implemented; requirement remains in progress  
**Date:** 2026-09-03

## Implemented contract

The current Rust reference path establishes:

- immutable handle identity over canonical subject identity, exact subject digest, semantic type,
  source, bounds, scope, and pre-applied transform;
- versioned descriptor identity for authority anchor, availability, retention, privacy class,
  contiguous H0–H4 levels, per-level capabilities, full resource costs, laboratory access, and
  derivative handles;
- exact requests pinned to handle, descriptor, subject, anchor, session, purpose, privacy grants,
  capabilities, budget, and continuation;
- artifacts whose payload integrity is distinct from retained provenance and whose exact subject
  and transform must match the handle;
- receipts closed over request, descriptor, subject, effective availability at request time,
  charged cost, artifact, proof roots, invalidators, and issue time;
- continuations closed over handle, session, contract basis, authority anchor, ladder-policy
  digest, next level, total ladder length, delivered artifact, and retention ceiling;
- typed superseded, deleted, expired, corrupt, privacy-transformed, and not-observable outcomes;
- capability, privacy, H4-purpose, and full-vector budget enforcement with explicit downgrade only
  when the caller permits it;
- a deterministic CLI rehearsal for successful H1 hydration and retention expiry.

## Executable evidence in the tree

The focused implementation is covered by module tests plus external consumer/process tests:

- `crates/fss-core/src/hydration/tests.rs`
- `crates/fss-core/tests/semantic_hydration_contract.rs`
- `crates/fss-core/tests/hydration_availability_contract.rs`
- `crates/fss-core/tests/hydration_cursor_contract.rs`
- `crates/fss-core/tests/hydration_subject_binding_contract.rs`
- `crates/fss-reference/src/hydration_tests.rs`
- `crates/fss-cli/tests/hydration_rehearsal.rs`

The reconciliation path requires these commands to pass before its commits are pushed:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo run -q -p fss-cli --bin fss-hydration-rehearsal -- success
cargo run -q -p fss-cli --bin fss-hydration-rehearsal -- expired
bash scripts/qualify.sh --lane agent --no-receipt
bash scripts/qualify.sh --lane policy --no-receipt
```

The rehearsal scenarios are each executed twice and required to produce byte-identical NDJSON.
That is deterministic reference evidence only; it is not a local DSR qualification root.

## Deliberately open acceptance dimensions

FSS-210 is not closed by this record. Remaining work includes:

- JSON Schema and machine-registry agreement for handles, requests, artifacts, receipts, responses,
  typed failures, and the hydration view;
- replacing free-form context-pack expansion strings with descriptor-bound semantic handles;
- persistent object custody, retention transitions, legal holds, derivative lineage, and deletion
  proof;
- equivalent Rust API, CLI, MCP, TUI, report, subscription, and handoff payloads and digests;
- stale/crash/cancellation/disconnect/lost-acknowledgement and multi-agent schedules;
- retained QL-AGENT evidence and GATE-115 closure.

The machine registries, bead graph, and qualification gates remain authoritative over this summary.
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == content:
        return
    path.write_text(content)


def commit_paths(message: str, paths: list[str]) -> None:
    run("git", "add", "--", *paths)
    if subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT).returncode == 0:
        return
    run("git", "commit", "-m", message)


def deterministic_rehearsal() -> None:
    directory = ROOT / "target/fss-hydration-reconcile"
    directory.mkdir(parents=True, exist_ok=True)
    for scenario in ("success", "expired"):
        first = directory / f"{scenario}-1.ndjson"
        second = directory / f"{scenario}-2.ndjson"
        with first.open("w") as output:
            subprocess.run(
                ["cargo", "run", "-q", "-p", "fss-cli", "--bin", "fss-hydration-rehearsal", "--", scenario],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=output,
            )
        with second.open("w") as output:
            subprocess.run(
                ["cargo", "run", "-q", "-p", "fss-cli", "--bin", "fss-hydration-rehearsal", "--", scenario],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=output,
            )
        if first.read_bytes() != second.read_bytes():
            raise RuntimeError(f"non-deterministic hydration transcript: {scenario}")
        record = json.loads(first.read_text())
        if record.get("scenario") != scenario or record.get("schema") != "fss.hydration_rehearsal.v1":
            raise RuntimeError(f"invalid hydration transcript: {scenario}")


def qualify_core() -> None:
    run("cargo", "fmt", "--all")
    run("cargo", "fmt", "--all", "--", "--check")
    run("cargo", "check", "--workspace", "--all-targets")
    run("cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings")
    run("cargo", "test", "--workspace", "--all-targets")
    deterministic_rehearsal()


def qualify_final() -> None:
    run("cargo", "fmt", "--all", "--", "--check")
    run("cargo", "check", "--workspace", "--all-targets")
    run("cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings")
    run("cargo", "test", "--workspace", "--all-targets")
    deterministic_rehearsal()
    run("bash", "scripts/qualify.sh", "--lane", "agent", "--no-receipt")
    run("bash", "scripts/qualify.sh", "--lane", "policy", "--no-receipt")


def main() -> None:
    os.environ.setdefault("CARGO_TERM_COLOR", "always")
    run("git", "config", "user.name", "fss-reconciliation-bot")
    run("git", "config", "user.email", "fss-reconciliation-bot@users.noreply.github.com")

    patch_semantic_hydration_consumer_test()
    patch_receipt_contract()
    ensure_reference_wiring()
    qualify_core()
    commit_paths(
        "fix(agent): close semantic hydration proof bindings",
        [
            "crates/fss-core/src/hydration",
            "crates/fss-core/tests",
            "crates/fss-reference/src/lib.rs",
            "crates/fss-reference/src/hydration.rs",
            "crates/fss-reference/src/hydration_tests.rs",
            "crates/fss-cli/src/bin/fss-hydration-rehearsal.rs",
            "crates/fss-cli/tests/hydration_rehearsal.rs",
        ],
    )

    update_bead()
    write_implementation_record()
    commit_paths(
        "beads: record FSS-210 reference progress",
        [".beads/issues.jsonl", "docs/FSS_210_IMPLEMENTATION_RECORD.md"],
    )

    SELF.unlink()
    WORKFLOW.unlink()
    run("python3", "scripts/generate-manifest.py")
    commit_paths(
        "chore: refresh integrity after hydration reference slice",
        [
            "scripts/fss_one_shot_hydration_reconcile.py",
            ".github/workflows/fss-one-shot-hydration-reconcile.yml",
            "MANIFEST.sha256",
            "MANIFEST.delta.sha256",
        ],
    )

    qualify_final()
    if run("git", "status", "--porcelain", capture=True).strip():
        raise RuntimeError("working tree is not clean after qualification")
    run("git", "push", "origin", "HEAD:main")


if __name__ == "__main__":
    main()
