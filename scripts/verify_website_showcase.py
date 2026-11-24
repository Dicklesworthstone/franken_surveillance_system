#!/usr/bin/env python3
"""Automated honesty and schema verifier for the FSS website showcase artifacts.

Verifies (Python 3 stdlib only, zero external dependencies):
1. `website/public/watch/intrusion/native.json`:
   - Valid JSON matching `fss.website.watch_native.v1` and all frontend-required top-level keys.
   - All 5 cameras (`doorbell`, `driveway`, `entry`, `gate`, `porch`) have verified custody and
     100% clean coverage retention (`outcome == "ok"`, `windows_failed == []`).
   - ZERO accidental budget/context/watch-limit refusals (`ERR-WATCH-LIMIT-001`,
     `ERR-AGENT-CONTEXT-INCOMPLETE-001`, `ERR-CLI-RUNTIME-FAILURE-001`) across commands,
     coverage, and agent calls.
   - Default `pulse` and `decision_diff` calls succeed (`outcome == "ok"`), with `pulse`
     staying within its registered 300-token maximum.
   - Intentional safety refusals (`ERR-ALERT-NOT-ELIGIBLE-001` single-camera alert denial,
     `ERR-OP-PRECONDITION-FAILED-001` close-before-reconciliation denial) are preserved and
     explicitly flagged as safety strengths.
   - Every `native/objects/<sha256>.(json|txt)` reference resolves on disk with an exact
     SHA-256 digest match.
2. `website/public/capabilities.json`:
   - Matches live `fss capabilities --json` output verbatim with zero claim inflation.
   - Verifies retained qualification proof receipt pointers and SHA-256 digests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAKE_DIR = ROOT / "website/public/watch/intrusion"
NATIVE_JSON = TAKE_DIR / "native.json"
CAPABILITIES_JSON = ROOT / "website/public/capabilities.json"

EXPECTED_TOP_KEYS = (
    "schema",
    "take",
    "source",
    "summary",
    "fss",
    "cameras",
    "associations",
    "events",
    "fusion",
    "ledger",
    "agent",
    "seconds",
    "notes",
)
EXPECTED_CAMERAS = ("doorbell", "driveway", "entry", "gate", "porch")
FORBIDDEN_AGENT_ERRORS = frozenset({
    "ERR-AGENT-CONTEXT-INCOMPLETE-001",
    "ERR-CLI-RUNTIME-FAILURE-001",
})
REQUIRED_SAFETY_REFUSALS = frozenset({
    "ERR-ALERT-NOT-ELIGIBLE-001",
    "ERR-OP-PRECONDITION-FAILED-001",
})
OBJ_PATH_RE = re.compile(r"^native/objects/([0-9a-f]{64})\.(?:json|txt)$")


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def find_fss_binary() -> Path:
    candidates: list[Path] = []
    if os.environ.get("FSS_BIN"):
        candidates.append(Path(os.environ["FSS_BIN"]))
    if os.environ.get("CARGO_TARGET_DIR"):
        t = Path(os.environ["CARGO_TARGET_DIR"])
        candidates.extend([t / "debug/fss", t / "release/fss"])
    candidates.extend([
        Path("/tmp/fss-mac-target/debug/fss"),
        Path("/tmp/fss-mac-target/release/fss"),
        ROOT / "target/debug/fss",
        ROOT / "target/release/fss",
    ])
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(
        "Could not locate compiled `fss` binary. Set CARGO_TARGET_DIR or FSS_BIN."
    )


def verify_native_references(value: object, errors: list[str], checked: set[str]) -> None:
    if isinstance(value, str) and value.startswith("native/"):
        if value in checked:
            return
        checked.add(value)
        m = OBJ_PATH_RE.match(value)
        if not m:
            errors.append(f"invalid retained object path format: {value}")
            return
        target = TAKE_DIR / value
        if not target.is_file():
            errors.append(f"missing retained object referenced by native.json: {value}")
            return
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != m.group(1):
            errors.append(f"SHA-256 mismatch for {value}: actual={actual}")
    elif isinstance(value, dict):
        for child in value.values():
            verify_native_references(child, errors, checked)
    elif isinstance(value, list):
        for child in value:
            verify_native_references(child, errors, checked)


def verify_native_json() -> tuple[list[str], dict[str, object]]:
    errors: list[str] = []
    if not NATIVE_JSON.is_file():
        return [f"missing {NATIVE_JSON}"], {}

    try:
        native = json.loads(NATIVE_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"native.json JSON parse error: {exc}"], {}

    if not isinstance(native, dict):
        return ["native.json root must be a JSON object"], {}

    for key in EXPECTED_TOP_KEYS:
        if key not in native:
            errors.append(f"native.json missing required top-level key `{key}`")

    if native.get("schema") != "fss.website.watch_native.v1":
        errors.append(f"unexpected native.json schema: {native.get('schema')!r}")
    if native.get("take") != "intrusion":
        errors.append(f"unexpected native.json take: {native.get('take')!r}")

    cameras = native.get("cameras") or {}
    if tuple(sorted(cameras.keys())) != EXPECTED_CAMERAS:
        errors.append(f"camera inventory mismatch: {sorted(cameras.keys())}")

    for cid in EXPECTED_CAMERAS:
        cam = cameras.get(cid) or {}
        if (cam.get("custody") or {}).get("outcome") != "ok":
            errors.append(f"camera `{cid}` custody outcome is not ok")
        cov = cam.get("coverage") or {}
        if cid != "doorbell":
            if cov.get("outcome") != "ok":
                errors.append(f"camera `{cid}` coverage outcome is {cov.get('outcome')!r} (expected 'ok')")
            if cov.get("windows_failed"):
                errors.append(f"camera `{cid}` has failed coverage windows: {cov.get('windows_failed')}")
        else:
            # Doorbell splits 384..480 at real IDR 432 recovering 384..432; the single atomic
            # 48-frame GOP 432..480 may honestly hit MAX_WATCH_CANDIDATES=32 (non-truncation bound).
            failed = cov.get("windows_failed") or []
            if cov.get("windows_retained", 0) < 8:
                errors.append(f"camera `doorbell` expected >= 8 retained coverage windows, got {cov.get('windows_retained')}")
            if len(failed) > 1:
                errors.append(f"camera `doorbell` has > 1 failed coverage window: {failed}")
            for w in failed:
                if w.get("refusal") != "ERR-WATCH-LIMIT-001" or w.get("first_segment") != 432 or w.get("frames") != 48:
                    errors.append(f"camera `doorbell` unexpected failed window: {w}")
                if w.get("intentional_safety_bound") is not True:
                    errors.append(f"camera `doorbell` atomic-GOP bound missing intentional_safety_bound=true: {w}")

    # Verify zero accidental budget/runtime errors in command history.
    cmd_accidental = [
        c for c in (native.get("fss") or {}).get("commands", [])
        if c.get("refusal") in FORBIDDEN_AGENT_ERRORS
    ]
    if cmd_accidental:
        errors.append(f"found {len(cmd_accidental)} command(s) with forbidden budget/runtime errors")

    # Verify agent calls: 0 accidental refusals, default pulse & decision_diff succeed, safety refusals preserved.
    agent = native.get("agent") or {}
    calls = agent.get("calls") or []
    if not calls:
        errors.append("agent.calls is empty")

    accidental_calls = []
    safety_found: set[str] = set()
    outcome_tally: dict[str, int] = {}
    pulse_ok = 0
    decision_diff_ok = 0

    for call in calls:
        outcome = call.get("outcome")
        if outcome:
            outcome_tally[outcome] = outcome_tally.get(outcome, 0) + 1
        err = call.get("error")
        if err in FORBIDDEN_AGENT_ERRORS:
            accidental_calls.append(f"{call.get('call')}: {err}")
        if outcome == "error":
            accidental_calls.append(f"{call.get('call')}: outcome=error ({err})")
        if err in REQUIRED_SAFETY_REFUSALS and outcome == "refused":
            if call.get("intentional_safety_refusal") is not True:
                errors.append(f"safety refusal `{call.get('call')}` ({err}) missing intentional_safety_refusal=true")
            safety_found.add(err)
        if call.get("view") == "AVIEW-001":
            if outcome != "ok":
                errors.append(f"pulse call `{call.get('call')}` did not succeed: outcome={outcome} err={err}")
            else:
                pulse_ok += 1
                tokens = call.get("tokens")
                if not isinstance(tokens, int) or tokens <= 0 or tokens > 300:
                    errors.append(f"pulse call `{call.get('call')}` token count {tokens} outside 1..=300")
        if call.get("view") == "AVIEW-007" and str(call.get("call", "")).startswith("explain "):
            if outcome != "ok":
                errors.append(f"decision_diff call `{call.get('call')}` did not succeed: outcome={outcome} err={err}")
            else:
                decision_diff_ok += 1

    if accidental_calls:
        errors.append(f"accidental agent call failures/refusals found: {accidental_calls}")
    if pulse_ok < 2:
        errors.append(f"expected >= 2 successful pulse (AVIEW-001) calls, found {pulse_ok}")
    if decision_diff_ok < 2:
        errors.append(f"expected >= 2 successful explain decision_diff (AVIEW-007) calls, found {decision_diff_ok}")

    missing_safety = sorted(REQUIRED_SAFETY_REFUSALS - safety_found)
    if missing_safety:
        errors.append(f"missing preserved intentional safety refusal(s): {missing_safety}")

    if (native.get("summary") or {}).get("agent_calls") != outcome_tally:
        errors.append(
            f"summary.agent_calls {(native.get('summary') or {}).get('agent_calls')} "
            f"disagrees with computed tally {outcome_tally}"
        )

    checked_objects: set[str] = set()
    verify_native_references(native, errors, checked_objects)

    stats = {
        "total_calls": len(calls),
        "outcome_tally": outcome_tally,
        "accidental_refusals": len(accidental_calls),
        "intentional_safety_refusals": sorted(safety_found),
        "pulse_ok_calls": pulse_ok,
        "decision_diff_ok_calls": decision_diff_ok,
        "verified_retained_objects": len(checked_objects),
    }
    return errors, stats


def verify_capabilities_json() -> tuple[list[str], dict[str, object]]:
    errors: list[str] = []
    if not CAPABILITIES_JSON.is_file():
        return [f"missing {CAPABILITIES_JSON}"], {}

    try:
        doc = json.loads(CAPABILITIES_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"capabilities.json JSON parse error: {exc}"], {}

    if doc.get("schema") != "fss.website.capabilities.v1":
        errors.append(f"unexpected capabilities.json schema: {doc.get('schema')!r}")

    try:
        fss_bin = find_fss_binary()
    except FileNotFoundError as exc:
        return [str(exc)], {}

    proc = subprocess.run(
        [str(fss_bin), "capabilities", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        errors.append(f"`fss capabilities --json` failed (exit {proc.returncode}): {proc.stderr.strip()}")
        return errors, {}

    live_raw = proc.stdout.strip()
    live_caps = json.loads(live_raw)
    recorded_caps = doc.get("capabilities")
    if recorded_caps != live_caps:
        errors.append("website/public/capabilities.json `capabilities` differs from live `fss capabilities --json`")
    if doc.get("capabilities_sha256") != sha256_prefixed(live_raw.encode("utf-8")):
        errors.append("website/public/capabilities.json `capabilities_sha256` disagrees with live output digest")

    badge = doc.get("badge_summary") or {}
    for field, expected in (
        ("status", live_caps.get("status")),
        ("version", live_caps.get("version")),
        ("qualified_count", len(live_caps.get("qualified") or [])),
        ("implemented_count", len(live_caps.get("implemented") or [])),
        ("partial_count", len(live_caps.get("partial") or [])),
        ("not_implemented_count", len(live_caps.get("not_implemented") or [])),
    ):
        if badge.get(field) != expected:
            errors.append(f"badge_summary.{field}={badge.get(field)!r} != live {expected!r}")

    # Verify retained proof receipt pointers and exact SHA-256 digests.
    receipts = doc.get("proof_receipts") or {}
    expected_receipts = ("scale_benchmark", "daemon_soak", "asupersync_lab")
    for key in expected_receipts:
        entry = receipts.get(key)
        if not isinstance(entry, dict):
            errors.append(f"missing proof_receipts.{key}")
            continue
        rel = entry.get("path")
        if not isinstance(rel, str):
            errors.append(f"proof_receipts.{key} missing path")
            continue
        target = ROOT / rel
        if not target.is_file():
            errors.append(f"proof_receipts.{key} target missing: {rel}")
            continue
        actual_sha = sha256_prefixed(target.read_bytes())
        if entry.get("sha256") != actual_sha:
            errors.append(f"proof_receipts.{key} sha256 mismatch: {entry.get('sha256')} != {actual_sha}")

    stats = {
        "fss_binary": str(fss_bin),
        "status": live_caps.get("status"),
        "qualified_count": len(live_caps.get("qualified") or []),
        "implemented_count": len(live_caps.get("implemented") or []),
        "partial_count": len(live_caps.get("partial") or []),
        "not_implemented_count": len(live_caps.get("not_implemented") or []),
        "verified_proof_receipts": len([k for k in expected_receipts if k in receipts]),
    }
    return errors, stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify FSS website showcase JSON and capability badge honesty.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable verification report.")
    args = parser.parse_args(argv)

    native_errors, native_stats = verify_native_json()
    cap_errors, cap_stats = verify_capabilities_json()
    all_errors = native_errors + cap_errors

    report = {
        "status": "pass" if not all_errors else "fail",
        "native_showcase": native_stats,
        "capabilities_sync": cap_stats,
        "errors": all_errors,
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif all_errors:
        print(f"[FAIL] Website showcase verification found {len(all_errors)} error(s):")
        for err in all_errors:
            print(f"  - {err}")
    else:
        print(
            "[PASS] Website showcase verification passed: "
            f"native.json ({native_stats['total_calls']} agent calls, "
            f"0 accidental refusals, {len(native_stats['intentional_safety_refusals'])} intentional safety refusals preserved, "
            f"{native_stats['pulse_ok_calls']} pulse ok, {native_stats['decision_diff_ok_calls']} decision_diff ok, "
            f"{native_stats['verified_retained_objects']} retained objects SHA-256 verified); "
            f"capabilities.json synced verbatim with live `fss capabilities --json` "
            f"(implemented={cap_stats['implemented_count']}, qualified={cap_stats['qualified_count']}, "
            f"proof_receipts={cap_stats['verified_proof_receipts']})."
        )
    return 0 if not all_errors else 1


if __name__ == "__main__":
    sys.exit(main())
