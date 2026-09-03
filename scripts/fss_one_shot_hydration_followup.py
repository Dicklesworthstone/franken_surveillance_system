#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKER = "FSS-210 deterministic reference progress"
TRANSIENTS = [
    ".github/workflows/fss-one-shot-hydration-reconcile.yml",
    "scripts/fss_one_shot_hydration_reconcile.py",
    ".github/workflows/fss-one-shot-hydration-followup.yml",
    "scripts/fss_one_shot_hydration_followup.py",
]


def command(args: list[str], *, capture: bool = False) -> str:
    completed = subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    return completed.stdout if capture else ""


def git(*args: str, capture: bool = False) -> str:
    return command(["git", *args], capture=capture)


def write(path: Path, content: str) -> None:
    if not content.endswith("\n"):
        content += "\n"
    if not path.exists() or path.read_text() != content:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def synchronize_tip() -> None:
    git("fetch", "origin", "main")
    git("checkout", "-B", "main", "origin/main")
    git("config", "user.name", "fss-reconciliation-bot")
    git("config", "user.email", "fss-reconciliation-bot@users.noreply.github.com")


def patch_consumer_test() -> None:
    path = ROOT / "crates/fss-core/tests/semantic_hydration_contract.rs"
    text = path.read_text()
    text = text.replace("fn request(\n", "fn make_request(\n", 1)
    text = text.replace("request(&handle, HydrationLevel::H1, None)?", "make_request(&handle, HydrationLevel::H1, None)?")
    text = text.replace("request(&handle, HydrationLevel::H2, Some(cursor))?", "make_request(&handle, HydrationLevel::H2, Some(cursor))?")
    text = text.replace("request(&handle, HydrationLevel::H0, None)?", "make_request(&handle, HydrationLevel::H0, None)?")
    write(path, text)


def patch_handle_api() -> None:
    path = ROOT / "crates/fss-core/src/hydration/handle.rs"
    text = path.read_text()
    text = re.sub(
        r"(?m)^\s*(?:pub\(crate\)\s+)?const fn unavailable_completeness\(",
        "    pub const fn unavailable_completeness(",
        text,
        count=1,
    )
    write(path, text)


def patch_artifact_provenance() -> None:
    path = ROOT / "crates/fss-core/src/hydration/artifact.rs"
    text = path.read_text()
    if "roots.is_empty() || roots.iter().all" not in text:
        old = """        let mut roots: BTreeSet<_> = proof_roots.into_iter().collect();\n        roots.insert(payload_digest);\n"""
        new = """        let mut roots: BTreeSet<_> = proof_roots.into_iter().collect();\n        if roots.is_empty() || roots.iter().all(|root| *root == payload_digest) {\n            return Err(ContractError::EvidenceRequired.into());\n        }\n        roots.insert(payload_digest);\n"""
        if old not in text:
            raise RuntimeError("artifact publication insertion point not found")
        text = text.replace(old, new, 1)
    if "any(|root| *root != self.payload_digest)" not in text:
        old = """            || !self.proof_roots.contains(&self.payload_digest)\n            || self\n"""
        new = """            || !self.proof_roots.contains(&self.payload_digest)\n            || !self\n                .proof_roots\n                .iter()\n                .any(|root| *root != self.payload_digest)\n            || self\n"""
        if old not in text:
            raise RuntimeError("artifact validation insertion point not found")
        text = text.replace(old, new, 1)
    write(path, text)


def patch_receipt_contract() -> None:
    path = ROOT / "crates/fss-core/src/hydration/receipt.rs"
    text = path.read_text()
    if "request.issued_at < handle.published_at" not in text:
        needle = "        let effective_availability = if request.issued_at >= handle.retention_until {\n"
        replacement = (
            "        if request.issued_at < handle.published_at {\n"
            "            return Err(ContractError::StaleAnchor.into());\n"
            "        }\n"
            "        let effective_availability = if request.issued_at >= handle.retention_until {\n"
        )
        if needle not in text:
            raise RuntimeError("receipt publication-time insertion point not found")
        text = text.replace(needle, replacement, 1)
    if "self.availability != effective_availability" not in text:
        needle = "            || self.requested_level != request.requested_level\n"
        replacement = (
            "            || self.requested_level != request.requested_level\n"
            "            || self.availability != effective_availability\n"
            "            || self.issued_at != request.issued_at\n"
        )
        if needle not in text:
            raise RuntimeError("receipt availability insertion point not found")
        text = text.replace(needle, replacement, 1)
    if "artifact.applied_transform != handle.applied_transform" not in text:
        needle = (
            "                    || !handle.levels.contains(&level)\n"
            "                    || !self.proof_roots.contains(&artifact.payload_digest)\n"
        )
        replacement = (
            "                    || !handle.levels.contains(&level)\n"
            "                    || artifact.applied_transform != handle.applied_transform\n"
            "                    || !artifact.proof_roots.contains(&handle.subject_digest)\n"
            "                    || !self.proof_roots.contains(&artifact.payload_digest)\n"
        )
        if needle not in text:
            raise RuntimeError("receipt artifact-binding insertion point not found")
        text = text.replace(needle, replacement, 1)
    if "let maximum = handle" not in text:
        needle = (
            "            let Some(delivered) = self.delivered_level else {\n"
            "                return Err(ContractError::EvidenceRequired.into());\n"
            "            };\n"
            "            if cursor.scope != ContinuationScope::EvidenceHydration\n"
        )
        replacement = (
            "            let Some(delivered) = self.delivered_level else {\n"
            "                return Err(ContractError::EvidenceRequired.into());\n"
            "            };\n"
            "            let maximum = handle\n"
            "                .maximum_level()\n"
            "                .ok_or(HydrationError::LevelUnavailable)?;\n"
            "            let Some(artifact_digest) = self.artifact_digest else {\n"
            "                return Err(ContractError::EvidenceRequired.into());\n"
            "            };\n"
            "            if cursor.scope != ContinuationScope::EvidenceHydration\n"
        )
        if needle not in text:
            raise RuntimeError("receipt cursor prelude insertion point not found")
        text = text.replace(needle, replacement, 1)
    if "cursor.stream_digest != handle.ladder_policy_digest()" not in text:
        needle = (
            "                || cursor.resume_anchor != self.anchor\n"
            "                || cursor.position != u64::from(delivered.ordinal()) + 1\n"
        )
        replacement = (
            "                || cursor.resume_anchor != self.anchor\n"
            "                || cursor.stream_digest != handle.ladder_policy_digest()\n"
            "                || cursor.position != u64::from(delivered.ordinal()) + 1\n"
            "                || cursor.total_items != u64::from(maximum.ordinal()) + 1\n"
            "                || cursor.page_digest != artifact_digest\n"
            "                || cursor.expires_at > handle.retention_until\n"
        )
        if needle not in text:
            raise RuntimeError("receipt cursor-binding insertion point not found")
        text = text.replace(needle, replacement, 1)
    write(path, text)


def patch_reference_wiring() -> None:
    path = ROOT / "crates/fss-reference/src/lib.rs"
    text = path.read_text()
    if "mod hydration;" not in text:
        text = text.replace("mod error;\n", "mod error;\nmod hydration;\n", 1)
    if "mod hydration_tests;" not in text:
        text = text.replace("mod bundle_tests;\n", "mod bundle_tests;\n#[cfg(test)]\nmod hydration_tests;\n", 1)
    if "pub use hydration::*;" not in text:
        text = text.replace("pub use error::ReferenceError;\n", "pub use error::ReferenceError;\npub use hydration::*;\n", 1)
    write(path, text)


def patch_cli_error_conversions() -> None:
    path = ROOT / "crates/fss-cli/src/bin/fss-hydration-rehearsal.rs"
    text = path.read_text()
    text = text.replace(
        '.ok_or("missing H1 cost")?',
        '.ok_or_else(|| std::io::Error::other("missing H1 cost"))?',
    )
    text = text.replace(
        '.ok_or("missing level cost")?',
        '.ok_or_else(|| std::io::Error::other("missing level cost"))?',
    )
    write(path, text)


def run_rust_gates() -> None:
    command(["cargo", "fmt", "--all"])
    command(["cargo", "fmt", "--all", "--", "--check"])
    command(["cargo", "check", "--workspace", "--all-targets"])
    command(["cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"])
    command(["cargo", "test", "--workspace", "--all-targets"])
    for scenario in ("success", "expired"):
        first = command(
            ["cargo", "run", "-q", "-p", "fss-cli", "--bin", "fss-hydration-rehearsal", "--", scenario],
            capture=True,
        )
        second = command(
            ["cargo", "run", "-q", "-p", "fss-cli", "--bin", "fss-hydration-rehearsal", "--", scenario],
            capture=True,
        )
        if first != second:
            raise RuntimeError(f"non-deterministic transcript for {scenario}")
        payload = json.loads(first)
        if payload.get("schema") != "fss.hydration_rehearsal.v1" or payload.get("scenario") != scenario:
            raise RuntimeError(f"invalid transcript for {scenario}")


def commit(message: str, paths: list[str]) -> None:
    git("add", "--", *paths)
    if subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT).returncode != 0:
        git("commit", "-m", message)


def bead_source_lines() -> list[str]:
    current = (ROOT / ".beads/issues.jsonl").read_text().splitlines()
    if not any(MARKER in line for line in current):
        return current
    commits = git("log", "-G", MARKER, "--format=%H", "--", ".beads/issues.jsonl", capture=True).splitlines()
    if not commits:
        return current
    try:
        original = git("show", f"{commits[0]}^:.beads/issues.jsonl", capture=True)
    except subprocess.CalledProcessError:
        return current
    return original.splitlines()


def update_bead_minimally() -> None:
    path = ROOT / ".beads/issues.jsonl"
    lines = bead_source_lines()
    parsed = []
    max_comment_id = 0
    statuses = set()
    for line in lines:
        item = json.loads(line)
        parsed.append((line, item))
        statuses.add(item.get("status"))
        for comment in item.get("comments", []):
            max_comment_id = max(max_comment_id, int(comment.get("id", 0)))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    output = []
    found = False
    for raw, item in parsed:
        if item.get("external_ref") != "FSS-210":
            output.append(raw)
            continue
        found = True
        comments = item.setdefault("comments", [])
        if not any(MARKER in comment.get("text", "") for comment in comments):
            max_comment_id += 1
            comments.append(
                {
                    "id": max_comment_id,
                    "issue_id": item["id"],
                    "author": "codex-agent",
                    "text": (
                        f"{MARKER} — 2026-09-03\n\n"
                        "Implemented the dependency-free SemanticHandle and H0-H4 hydration "
                        "reference slice with immutable subject identity, versioned descriptors, "
                        "typed availability, exact request/artifact/receipt closure, provenance and "
                        "transform binding, retention-aware expiry, capability/privacy/full-vector "
                        "budget enforcement, explicit downgrade, H4 gating, and exact continuation "
                        "cursors closed over ladder policy and delivered artifacts. Added external "
                        "consumer tests and deterministic process-level success/expiry rehearsals.\n\n"
                        "FSS-210 remains in progress. Schema/registry agreement, descriptor-bound "
                        "context expansion, persistent custody/retention/deletion, all public "
                        "surface equivalence, complete fault/multi-agent schedules, QL-AGENT, and "
                        "GATE-115 retained proof are still required. Hosted reconciliation is "
                        "supplementary and is not local DSR release authority."
                    ),
                    "created_at": now,
                }
            )
        if item.get("status") == "open" and "in_progress" in statuses:
            item["status"] = "in_progress"
        item["updated_at"] = now
        output.append(json.dumps(item, ensure_ascii=True, separators=(",", ":")))
    if not found:
        raise RuntimeError("FSS-210 bead not found")
    path.write_text("\n".join(output) + "\n")


def write_record() -> None:
    path = ROOT / "docs/FSS_210_IMPLEMENTATION_RECORD.md"
    content = """# FSS-210 implementation record

**Requirement:** FSS-210 — semantic handles and bounded H0–H4 hydration  
**State:** deterministic reference slice implemented; requirement remains in progress  
**Date:** 2026-09-03

## Implemented contract

The Rust reference path now establishes immutable subject-bound handles, independently versioned
descriptors, contiguous H0–H4 ladders, exact request/artifact/receipt closure, typed availability,
capability and privacy checks, full resource-vector enforcement, explicit downgrade, H4 purpose
gating, retention-aware expiry, and exact continuation cursors.

Artifact integrity is not treated as provenance. Every artifact retains at least one supporting root
distinct from its own payload digest, and successful receipt validation requires the artifact to
retain the exact subject digest and transform named by the handle. A request cannot predate the
descriptor publication it cites.

Continuation validation binds the cursor to the handle, session, contract basis, authority anchor,
hydration view, ladder-policy digest, next level, total ladder length, delivered artifact, and
retention ceiling. A syntactically valid cursor cannot be rebound to another semantic stream.

## Executable evidence in the tree

- `crates/fss-core/src/hydration/tests.rs`
- `crates/fss-core/tests/semantic_hydration_contract.rs`
- `crates/fss-core/tests/hydration_availability_contract.rs`
- `crates/fss-core/tests/hydration_cursor_contract.rs`
- `crates/fss-core/tests/hydration_subject_binding_contract.rs`
- `crates/fss-reference/src/hydration_tests.rs`
- `crates/fss-cli/tests/hydration_rehearsal.rs`

Before the reconciliation commits are pushed, the exact tree must pass formatting, workspace check,
Clippy with warnings denied, all workspace targets, byte-identical repeated success and expiry
rehearsals, and the repository-owned agent and policy lanes.

## Deliberately open dimensions

FSS-210 is not closed by code presence. JSON Schema and registry agreement, descriptor-bound context
expansion, persistent custody/retention/deletion, Rust/CLI/MCP/TUI/report/subscription/handoff
equivalence, complete fault and multi-agent schedules, QL-AGENT evidence, and GATE-115 remain open.
Hosted execution is supplementary and is not a local DSR qualification root.
"""
    write(path, content)


def remove_transients() -> None:
    existing = [path for path in TRANSIENTS if (ROOT / path).exists()]
    if existing:
        git("rm", "-f", "--", *existing)


def final_gates() -> None:
    run_rust_gates()
    command(["bash", "scripts/qualify.sh", "--lane", "agent", "--no-receipt"])
    command(["bash", "scripts/qualify.sh", "--lane", "policy", "--no-receipt"])
    if git("status", "--porcelain", capture=True).strip():
        raise RuntimeError("qualification left a dirty worktree")


def main() -> None:
    synchronize_tip()
    patch_consumer_test()
    patch_handle_api()
    patch_artifact_provenance()
    patch_receipt_contract()
    patch_reference_wiring()
    patch_cli_error_conversions()
    run_rust_gates()
    commit(
        "fix(agent): complete semantic hydration cross-object validation",
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
    update_bead_minimally()
    write_record()
    commit(
        "beads: retain bounded FSS-210 implementation state",
        [".beads/issues.jsonl", "docs/FSS_210_IMPLEMENTATION_RECORD.md"],
    )
    remove_transients()
    command(["python3", "scripts/generate-manifest.py"])
    commit(
        "chore: seal hydration reference integrity",
        [*TRANSIENTS, "MANIFEST.sha256", "MANIFEST.delta.sha256"],
    )
    final_gates()
    git("push", "origin", "HEAD:main")


if __name__ == "__main__":
    main()
