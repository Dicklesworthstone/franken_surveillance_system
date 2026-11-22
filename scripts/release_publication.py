#!/usr/bin/env python3
"""scripts/release_publication.py — Upload-then-download-and-verify root-last
release publication state machine (FSS-192, bead fss-x4a.26.12).

Composes with:
  * scripts/release_artifacts.py (FSS-189): exact asset enumeration, symlink and
    leftover atomic-temp refusal, SHA-256 inventory.
  * scripts/sbom_crosscheck.py (FSS-190): SBOM / license inventory / Cargo.lock /
    metadata / qualification receipt agreement before any remote write.
  * scripts/signing_authority.py (FSS-191): separated builder != signer authority
    and detached signature binding over the exact manifest digest.
  * scripts/qualification_receipt.py: atomic file writer.

Lifecycle & publication states (strictly distinct, never conflated):
  staged -> prepared -> uploaded_unverified -> download_verified -> published
  Terminal/non-published states: cancelled, indeterminate, failed

Key invariants (INV-008/017/021/023/049/051/052/077):
  1. Root-last publication: payloads upload first; root manifest + detached
     signature are written LAST, ONLY after every uploaded asset is downloaded
     back into a clean scratch directory and verified byte-for-byte against
     the local manifest with zero missing and zero unexpected extra files.
  2. Post-publish verification: after writing the root manifest, the publisher
     downloads the root manifest back from the remote store and verifies its
     digest and signature before declaring state='published'.
  3. Explicit authority & least privilege: requires caller-supplied principal,
     capability ('release:publish'), monotonic lease_fence, builder != signer,
     and non-floating immutable release version (forbidding 'latest').
  4. Explicit idempotency, cancellation, and crash/restart reconciliation:
     every transition appends to a hash-chained durable journal; lost-ACK at
     the root publish boundary enters 'indeterminate' and blocks conflicting
     publishes until explicitly reconciled.

Output: one JSON envelope (schema fss.release_publication.v1) on stdout.
Exit codes: 0 published/verified/reconciled, 1 refused/failed/indeterminate, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qualification_receipt import atomic_write_bytes, is_atomic_temp_name, write_json_atomic
from release_artifacts import LeftoverAtomicTempFileError, release_artifact_files, sha256
from sbom_crosscheck import crosscheck as sbom_crosscheck

SCHEMA = "fss.release_publication.v1"
ROOT_MANIFEST_NAME = "RELEASE_ROOT.json"
ROOT_SIG_NAME = "RELEASE_ROOT.json.minisig"
JOURNAL_FILENAME = "publication_journal.jsonl"
ZERO_SHA256 = "0" * 64

MAX_RELEASE_ASSETS = 128
MAX_ASSET_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_LABEL_BYTES = 128
MAX_JOURNAL_ENTRIES = 4096

REQUIRED_PUBLISH_CAPABILITY = "release:publish"
VALID_PRESSURES = ("nominal", "elevated", "constrained", "critical")
ALLOWED_PUBLISH_PRESSURES = ("nominal", "elevated")

FORBIDDEN_ASSET_PATTERNS = (
    re.compile(r"(?i)(^|/)\.env(\.|$)"),
    re.compile(r"(?i)\.(pem|key|p12|pfx|kdbx)$"),
    re.compile(r"(?i)(^|/)(id_rsa|id_ed25519|credentials\.json|secrets\.(json|yaml|yml))$"),
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_label(field_name: str, value: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return f"{field_name} must be non-empty"
    raw = value.encode("utf-8")
    if len(raw) > MAX_LABEL_BYTES or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return f"{field_name} exceeds {MAX_LABEL_BYTES} bytes or contains control characters"
    return None


def _is_forbidden_latest(version: str) -> bool:
    tokens = re.split(r"[:/\-_.]", version.strip().lower())
    return any(tok == "latest" for tok in tokens)


def _check_secret_filename(rel_path: str) -> str | None:
    for pat in FORBIDDEN_ASSET_PATTERNS:
        if pat.search(rel_path):
            return f"forbidden sensitive/private filename refused in release bundle: {rel_path}"
    return None


@dataclass(frozen=True)
class FaultSchedule:
    """Deterministic laboratory fault injection for FSS-192 failure & recovery proofs."""

    cancel_at: str | None = None  # prepare | upload_asset | download_verify | publish_root
    corrupt_download_asset: str | None = None
    drop_from_remote_list: str | None = None
    inject_extra_remote_asset: str | None = None
    lost_ack_on_root_publish: bool = False
    store_unavailable: bool = False
    partial_write_asset: str | None = None


class RemoteStoreError(RuntimeError):
    """Raised when the remote release store rejects or fails an I/O call."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class DirectoryReleaseStore:
    """Deterministic reference remote release store backed by an isolated directory.

    Maintains separate `payloads/` and `root/` namespaces so root-last publication
    is structurally observable: until `put_root` completes atomically, `get_root`
    returns None and readers observe no published release.
    """

    def __init__(self, root_dir: Path, faults: FaultSchedule | None = None) -> None:
        self.root_dir = root_dir
        self.payloads_dir = root_dir / "payloads"
        self.root_meta_dir = root_dir / "root"
        self.faults = faults or FaultSchedule()
        self.payloads_dir.mkdir(parents=True, exist_ok=True)
        self.root_meta_dir.mkdir(parents=True, exist_ok=True)
        self.upload_bytes_written = 0
        self.download_bytes_read = 0
        self.upload_calls = 0
        self.download_calls = 0

    def _safe_rel(self, base: Path, rel_name: str) -> Path:
        if rel_name.startswith("/") or ".." in Path(rel_name).parts:
            raise RemoteStoreError("invalid_asset_path", f"unsafe asset path: {rel_name}")
        target = (base / rel_name).resolve()
        if base.resolve() not in target.parents and target != base.resolve():
            raise RemoteStoreError("invalid_asset_path", f"asset escapes store root: {rel_name}")
        return target

    def _check_available(self) -> None:
        if self.faults.store_unavailable:
            raise RemoteStoreError("store_unavailable", "remote release store unavailable (injected)")

    def put_asset(self, rel_name: str, data: bytes) -> None:
        self._check_available()
        self.upload_calls += 1
        target = self._safe_rel(self.payloads_dir, rel_name)
        target.parent.mkdir(parents=True, exist_ok=True)
        if self.faults.partial_write_asset == rel_name:
            truncated = data[: max(1, len(data) // 2)] if data else b""
            atomic_write_bytes(target, truncated)
            self.upload_bytes_written += len(truncated)
            raise RemoteStoreError("partial_io", f"simulated partial upload on {rel_name}")
        atomic_write_bytes(target, data)
        self.upload_bytes_written += len(data)

    def list_assets(self) -> list[str]:
        self._check_available()
        names: list[str] = []
        for path in sorted(self.payloads_dir.rglob("*")):
            if path.is_file() and not is_atomic_temp_name(path.name):
                rel = path.relative_to(self.payloads_dir).as_posix()
                if self.faults.drop_from_remote_list == rel:
                    continue
                names.append(rel)
        if self.faults.inject_extra_remote_asset:
            extra = self.faults.inject_extra_remote_asset
            if extra not in names:
                extra_path = self._safe_rel(self.payloads_dir, extra)
                extra_path.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_bytes(extra_path, b"unexpected-extra-remote-asset")
                names.append(extra)
                names.sort()
        return names

    def get_asset(self, rel_name: str) -> bytes:
        self._check_available()
        self.download_calls += 1
        target = self._safe_rel(self.payloads_dir, rel_name)
        if not target.is_file():
            raise RemoteStoreError("asset_missing", f"remote asset missing: {rel_name}")
        data = target.read_bytes()
        self.download_bytes_read += len(data)
        if self.faults.corrupt_download_asset == rel_name and data:
            corrupted = bytearray(data)
            corrupted[0] ^= 0xFF
            return bytes(corrupted)
        return data

    def put_root(self, root_bytes: bytes, sig_bytes: bytes | None) -> None:
        self._check_available()
        self.upload_calls += 1
        if sig_bytes is not None:
            atomic_write_bytes(self.root_meta_dir / ROOT_SIG_NAME, sig_bytes)
            self.upload_bytes_written += len(sig_bytes)
        atomic_write_bytes(self.root_meta_dir / ROOT_MANIFEST_NAME, root_bytes)
        self.upload_bytes_written += len(root_bytes)
        if self.faults.lost_ack_on_root_publish:
            # Root actually landed on remote store, but response ACK was lost!
            raise RemoteStoreError(
                "lost_ack_root_publish",
                "root manifest publish acknowledgement lost; outcome is indeterminate",
            )

    def get_root(self) -> tuple[bytes, bytes | None] | None:
        self._check_available()
        self.download_calls += 1
        root_path = self.root_meta_dir / ROOT_MANIFEST_NAME
        if not root_path.is_file():
            return None
        root_bytes = root_path.read_bytes()
        self.download_bytes_read += len(root_bytes)
        sig_path = self.root_meta_dir / ROOT_SIG_NAME
        sig_bytes = sig_path.read_bytes() if sig_path.is_file() else None
        if sig_bytes is not None:
            self.download_bytes_read += len(sig_bytes)
        return root_bytes, sig_bytes


@dataclass
class PublicationJournal:
    """Append-only, hash-chained durable publication state journal."""

    path: Path
    entries: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "PublicationJournal":
        journal = cls(path=path, entries=[])
        if not path.is_file():
            return journal
        expected_prev = ZERO_SHA256
        lines = path.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError as exc:
                raise ValueError(f"journal line {idx} invalid JSON: {exc}") from exc
            if entry.get("sequence") != idx:
                raise ValueError(f"journal sequence gap at line {idx}: observed {entry.get('sequence')}")
            if entry.get("prevDigest") != expected_prev:
                raise ValueError(f"journal hash chain break at sequence {idx}")
            recorded_digest = entry.get("entryDigest")
            body = {k: v for k, v in entry.items() if k != "entryDigest"}
            recomputed = _sha256_bytes(_canonical_json_bytes(body))
            if recorded_digest != recomputed:
                raise ValueError(
                    f"journal entry {idx} digest mismatch: expected {recorded_digest}, observed {recomputed}"
                )
            journal.entries.append(entry)
            expected_prev = recorded_digest
        return journal

    def append(self, release_id: str, state: str, payload: dict[str, Any]) -> dict[str, Any]:
        if len(self.entries) >= MAX_JOURNAL_ENTRIES:
            raise ValueError(f"publication journal exceeded MAX_JOURNAL_ENTRIES={MAX_JOURNAL_ENTRIES}")
        seq = len(self.entries) + 1
        prev_digest = self.entries[-1]["entryDigest"] if self.entries else ZERO_SHA256
        body = {
            "sequence": seq,
            "prevDigest": prev_digest,
            "releaseId": release_id,
            "state": state,
            "payload": payload,
        }
        entry_digest = _sha256_bytes(_canonical_json_bytes(body))
        entry = {**body, "entryDigest": entry_digest}
        self.entries.append(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        serialized = "\n".join(json.dumps(e, sort_keys=True, separators=(",", ":")) for e in self.entries) + "\n"
        atomic_write_bytes(self.path, serialized.encode("utf-8"))
        return entry

    def highest_lease_fence(self) -> int:
        highest = 0
        for entry in self.entries:
            fence = entry.get("payload", {}).get("leaseFence")
            if isinstance(fence, int) and fence > highest:
                highest = fence
        return highest

    def latest_for_release(self, release_id: str) -> dict[str, Any] | None:
        for entry in reversed(self.entries):
            if entry.get("releaseId") == release_id:
                return entry
        return None

    def active_indeterminate(self) -> dict[str, Any] | None:
        seen: dict[str, dict[str, Any]] = {}
        for entry in self.entries:
            seen[entry["releaseId"]] = entry
        for entry in seen.values():
            if entry.get("state") == "indeterminate":
                return entry
        return None

    def head_digest(self) -> str:
        return self.entries[-1]["entryDigest"] if self.entries else ZERO_SHA256


@dataclass(frozen=True)
class PublishConfig:
    release_id: str
    version: str
    artifacts_dir: Path
    remote_store_dir: Path
    state_dir: Path
    principal: str
    capability: str
    lease_fence: int
    builder_identity: str
    signer_identity: str
    contract_basis_digest: str
    toolchain_id: str
    expected_assets: list[str] | None = None
    pressure: str = "nominal"
    max_total_bytes: int = MAX_TOTAL_BYTES
    sbom_path: Path | None = None
    license_inventory_path: Path | None = None
    cargo_lock_path: Path | None = None
    metadata_path: Path | None = None
    qualification_receipt_path: Path | None = None
    signature_path: Path | None = None
    public_key: str | None = None
    faults: FaultSchedule = field(default_factory=FaultSchedule)


def _compute_plan_digest(plan: dict[str, Any]) -> str:
    return "sha256:" + _sha256_bytes(_canonical_json_bytes(plan))


def _enumerate_staged_assets(
    artifacts_dir: Path,
    expected_assets: list[str] | None,
    max_total_bytes: int,
) -> tuple[dict[str, dict[str, Any]] | None, str | None, str | None]:
    """Enumerates local release artifacts with FSS-189 exact-set & secret-free checks."""
    if not artifacts_dir.is_dir():
        return None, "missing_artifacts_dir", f"artifacts directory does not exist: {artifacts_dir}"
    try:
        files = release_artifact_files(artifacts_dir)
    except LeftoverAtomicTempFileError as exc:
        return None, "leftover_atomic_temp", str(exc)
    except ValueError as exc:
        return None, "symlink_or_invalid_input", str(exc)

    if not files:
        return None, "empty_artifacts_dir", f"no release artifacts found under {artifacts_dir}"
    if len(files) > MAX_RELEASE_ASSETS:
        return None, "asset_count_exceeded", f"{len(files)} assets exceeds MAX_RELEASE_ASSETS={MAX_RELEASE_ASSETS}"

    inventory: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    for path in files:
        rel = path.relative_to(artifacts_dir).as_posix()
        if rel in (ROOT_MANIFEST_NAME, ROOT_SIG_NAME):
            return None, "reserved_root_name_in_payloads", f"payload dir must not contain reserved root file {rel}"
        secret_err = _check_secret_filename(rel)
        if secret_err:
            return None, "forbidden_secret_asset", secret_err
        size = path.stat().st_size
        if size > MAX_ASSET_BYTES:
            return None, "asset_size_exceeded", f"asset {rel} ({size} bytes) exceeds MAX_ASSET_BYTES"
        total_bytes += size
        if total_bytes > max_total_bytes:
            return None, "budget_exceeded", f"total release bytes {total_bytes} exceeds budget {max_total_bytes}"
        inventory[rel] = {
            "sha256": sha256(path),
            "sizeBytes": size,
        }

    if expected_assets is not None:
        want = sorted(set(expected_assets))
        have = sorted(inventory.keys())
        if want != have:
            missing = sorted(set(want) - set(have))
            extra = sorted(set(have) - set(want))
            return (
                None,
                "asset_set_mismatch",
                f"exact asset enumeration mismatch: missing={missing} extra={extra}",
            )

    return inventory, None, None


def _run_sbom_leg(cfg: PublishConfig) -> tuple[bool, str | None]:
    if not any((cfg.sbom_path, cfg.license_inventory_path, cfg.cargo_lock_path)):
        return True, None
    if not (cfg.sbom_path and cfg.license_inventory_path and cfg.cargo_lock_path):
        return False, "sbom, license_inventory, and cargo_lock must all be supplied together"
    try:
        sbom = json.loads(cfg.sbom_path.read_text(encoding="utf-8"))
        inv = json.loads(cfg.license_inventory_path.read_text(encoding="utf-8"))
        lock_text = cfg.cargo_lock_path.read_text(encoding="utf-8")
        meta = json.loads(cfg.metadata_path.read_text(encoding="utf-8")) if cfg.metadata_path else None
        rcpt = (
            json.loads(cfg.qualification_receipt_path.read_text(encoding="utf-8"))
            if cfg.qualification_receipt_path
            else None
        )
    except (OSError, ValueError) as exc:
        return False, f"failed reading SBOM/qualification inputs: {exc}"
    failures = sbom_crosscheck(sbom, inv, lock_text, meta, rcpt)
    if failures:
        return False, "; ".join(failures)
    return True, None


def _verify_detached_signature(
    root_bytes: bytes,
    builder: str,
    signer: str,
    sig_bytes: bytes | None,
    public_key: str | None,
) -> tuple[bool, str | None]:
    if sig_bytes is None and public_key is None:
        return True, None
    if sig_bytes is None or public_key is None:
        return False, "detached signature and public_key must both be supplied for cryptographic verification"
    if shutil.which("minisign") is None:
        return False, "minisign binary unavailable for detached signature verification"
    from signing_authority import _minisign_verify  # local module

    manifest_digest = "sha256:" + _sha256_bytes(root_bytes)
    payload = _canonical_json_bytes({"manifestDigest": manifest_digest, "builder": builder, "signer": signer})
    if not _minisign_verify(public_key, payload, sig_bytes):
        return False, "minisign detached signature verification failed"
    return True, None


def publish_release(cfg: PublishConfig) -> dict[str, Any]:
    """Executes the full FSS-192 state machine:
    staged -> prepared -> uploaded_unverified -> download_verified -> published.
    """
    transitions: list[str] = []

    def fail(code: str, detail: str, state: str = "failed", **extra: Any) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "releaseId": cfg.release_id,
            "version": cfg.version,
            "state": state,
            "errorCode": code,
            "detail": detail,
            "transitions": transitions,
            "remediation": _remediation_for(code),
            **extra,
        }

    # 1. Input, anti-"latest", pressure, and authority separation checks.
    for fname, val in (
        ("release_id", cfg.release_id),
        ("version", cfg.version),
        ("principal", cfg.principal),
        ("capability", cfg.capability),
        ("builder_identity", cfg.builder_identity),
        ("signer_identity", cfg.signer_identity),
        ("toolchain_id", cfg.toolchain_id),
    ):
        err = _validate_label(fname, val)
        if err:
            return fail("invalid_input", err)

    if _is_forbidden_latest(cfg.version):
        return fail("forbidden_latest_alias", f"floating 'latest' version is forbidden: {cfg.version}")

    if not re.fullmatch(r"sha256:[0-9a-f]{64}", cfg.contract_basis_digest):
        return fail("invalid_input", "contract_basis_digest must match sha256:<64-hex>")

    if cfg.capability != REQUIRED_PUBLISH_CAPABILITY:
        return fail(
            "authority_refused",
            f"capability mismatch: required '{REQUIRED_PUBLISH_CAPABILITY}', supplied '{cfg.capability}'",
        )

    if cfg.builder_identity == cfg.signer_identity:
        return fail(
            "same_authority_refused",
            "builder and signer identities coincide; signing_separate_from_build forbids this",
        )

    if cfg.pressure not in VALID_PRESSURES:
        return fail("invalid_input", f"unknown resource pressure: {cfg.pressure}")
    if cfg.pressure not in ALLOWED_PUBLISH_PRESSURES:
        return fail(
            "pressure_refused",
            f"resource pressure '{cfg.pressure}' refuses new release publication",
        )

    # 2. Load durable hash-chained journal and check lease fence + indeterminate lock.
    journal_path = cfg.state_dir / JOURNAL_FILENAME
    try:
        journal = PublicationJournal.load(journal_path)
    except ValueError as exc:
        return fail("journal_corrupt", str(exc))

    highest_fence = journal.highest_lease_fence()
    if cfg.lease_fence < highest_fence:
        return fail(
            "stale_lease_fence",
            f"lease fence {cfg.lease_fence} < highest committed {highest_fence}",
        )

    indet = journal.active_indeterminate()
    if indet is not None:
        return fail(
            "indeterminate_pending",
            f"release '{indet['releaseId']}' is indeterminate and blocks publication until reconciled",
            pendingReleaseId=indet["releaseId"],
            journalHeadDigest=journal.head_digest(),
        )

    # 3. Stage & enumerate local assets (FSS-189) + SBOM/qualification cross-check (FSS-190).
    inventory, inv_err_code, inv_err_detail = _enumerate_staged_assets(
        cfg.artifacts_dir, cfg.expected_assets, cfg.max_total_bytes
    )
    if inventory is None:
        return fail(inv_err_code or "stage_failed", inv_err_detail or "staging failed")
    transitions.append("staged")

    sbom_ok, sbom_err = _run_sbom_leg(cfg)
    if not sbom_ok:
        return fail("sbom_crosscheck_failed", sbom_err or "SBOM cross-check failed")

    # 4. Build immutable root manifest & plan digest; check idempotency replay vs conflict.
    root_manifest = {
        "schema": "fss.release_root_manifest.v1",
        "releaseId": cfg.release_id,
        "version": cfg.version,
        "builder": cfg.builder_identity,
        "signer": cfg.signer_identity,
        "contractBasisDigest": cfg.contract_basis_digest,
        "toolchainId": cfg.toolchain_id,
        "assets": inventory,
    }
    root_bytes = _canonical_json_bytes(root_manifest)
    root_digest = "sha256:" + _sha256_bytes(root_bytes)
    plan_digest = _compute_plan_digest(
        {
            "releaseId": cfg.release_id,
            "rootDigest": root_digest,
            "principal": cfg.principal,
            "builder": cfg.builder_identity,
            "signer": cfg.signer_identity,
        }
    )

    sig_bytes: bytes | None = None
    if cfg.signature_path is not None:
        if not cfg.signature_path.is_file():
            return fail("signature_missing", f"detached signature unreadable: {cfg.signature_path}")
        sig_bytes = cfg.signature_path.read_bytes()
    sig_ok, sig_err = _verify_detached_signature(
        root_bytes, cfg.builder_identity, cfg.signer_identity, sig_bytes, cfg.public_key
    )
    if not sig_ok:
        return fail("signature_verify_failed", sig_err or "signature verification failed")

    prior = journal.latest_for_release(cfg.release_id)
    if prior is not None and prior.get("state") == "published":
        if prior.get("payload", {}).get("planDigest") == plan_digest:
            return {
                "schema": SCHEMA,
                "releaseId": cfg.release_id,
                "version": cfg.version,
                "state": "published",
                "idempotentReplay": True,
                "planDigest": plan_digest,
                "rootDigest": root_digest,
                "assetCount": len(inventory),
                "transitions": ["staged", "published"],
                "journalHeadDigest": journal.head_digest(),
            }
        return fail(
            "idempotency_conflict",
            f"release '{cfg.release_id}' already published with a different plan digest",
            existingPlanDigest=prior.get("payload", {}).get("planDigest"),
            requestedPlanDigest=plan_digest,
        )

    # 5. Phase 1: Prepare (check cancellation before persisting intent).
    if cfg.faults.cancel_at == "prepare":
        return fail("cancelled", "publication cancelled cleanly at prepare checkpoint", state="cancelled")

    journal.append(
        cfg.release_id,
        "prepared",
        {
            "planDigest": plan_digest,
            "rootDigest": root_digest,
            "principal": cfg.principal,
            "leaseFence": cfg.lease_fence,
            "assetCount": len(inventory),
            "assets": inventory,
            "version": cfg.version,
            "builder": cfg.builder_identity,
            "signer": cfg.signer_identity,
            "contractBasisDigest": cfg.contract_basis_digest,
            "toolchainId": cfg.toolchain_id,
        },
    )
    transitions.append("prepared")

    store = DirectoryReleaseStore(cfg.remote_store_dir, faults=cfg.faults)

    # 6. Phase 2: Upload all payload assets (root NOT written yet!).
    for rel_name in sorted(inventory.keys()):
        if cfg.faults.cancel_at == "upload_asset":
            journal.append(
                cfg.release_id,
                "cancelled",
                {"planDigest": plan_digest, "stage": "upload_asset", "leaseFence": cfg.lease_fence},
            )
            transitions.append("cancelled")
            return fail(
                "cancelled",
                "publication cancelled cleanly before root publication during asset upload",
                state="cancelled",
                planDigest=plan_digest,
                journalHeadDigest=journal.head_digest(),
            )
        asset_bytes = (cfg.artifacts_dir / rel_name).read_bytes()
        try:
            store.put_asset(rel_name, asset_bytes)
        except RemoteStoreError as exc:
            journal.append(
                cfg.release_id,
                "failed",
                {"planDigest": plan_digest, "errorCode": exc.code, "detail": exc.detail, "leaseFence": cfg.lease_fence},
            )
            transitions.append("failed")
            return fail(
                exc.code,
                exc.detail,
                planDigest=plan_digest,
                rootPublished=False,
                journalHeadDigest=journal.head_digest(),
            )

    journal.append(
        cfg.release_id,
        "uploaded_unverified",
        {
            "planDigest": plan_digest,
            "rootDigest": root_digest,
            "uploadedAssets": len(inventory),
            "uploadBytes": store.upload_bytes_written,
            "leaseFence": cfg.lease_fence,
        },
    )
    transitions.append("uploaded_unverified")

    # 7. Phase 3: Download EVERY asset into an isolated scratch dir & verify exact enumeration + SHA-256!
    if cfg.faults.cancel_at == "download_verify":
        journal.append(
            cfg.release_id,
            "cancelled",
            {"planDigest": plan_digest, "stage": "download_verify", "leaseFence": cfg.lease_fence},
        )
        transitions.append("cancelled")
        return fail(
            "cancelled",
            "publication cancelled cleanly before root publication during download verification",
            state="cancelled",
            planDigest=plan_digest,
            journalHeadDigest=journal.head_digest(),
        )

    verify_ok, verify_code, verify_detail = _download_and_verify_payloads(store, inventory)
    if not verify_ok:
        journal.append(
            cfg.release_id,
            "failed",
            {
                "planDigest": plan_digest,
                "errorCode": verify_code,
                "detail": verify_detail,
                "leaseFence": cfg.lease_fence,
            },
        )
        transitions.append("failed")
        return fail(
            verify_code or "download_verify_failed",
            verify_detail or "download verification failed",
            planDigest=plan_digest,
            rootPublished=False,
            journalHeadDigest=journal.head_digest(),
        )

    journal.append(
        cfg.release_id,
        "download_verified",
        {
            "planDigest": plan_digest,
            "rootDigest": root_digest,
            "verifiedAssets": len(inventory),
            "downloadBytes": store.download_bytes_read,
            "leaseFence": cfg.lease_fence,
        },
    )
    transitions.append("download_verified")

    # 8. Phase 4: Root-last publication (atomic root manifest + detached sig), then download-verify root!
    if cfg.faults.cancel_at == "publish_root":
        journal.append(
            cfg.release_id,
            "cancelled",
            {"planDigest": plan_digest, "stage": "publish_root", "leaseFence": cfg.lease_fence},
        )
        transitions.append("cancelled")
        return fail(
            "cancelled",
            "publication cancelled cleanly before root manifest commit",
            state="cancelled",
            planDigest=plan_digest,
            journalHeadDigest=journal.head_digest(),
        )

    try:
        store.put_root(root_bytes, sig_bytes)
    except RemoteStoreError as exc:
        if exc.code == "lost_ack_root_publish":
            journal.append(
                cfg.release_id,
                "indeterminate",
                {
                    "planDigest": plan_digest,
                    "rootDigest": root_digest,
                    "reason": exc.detail,
                    "leaseFence": cfg.lease_fence,
                },
            )
            transitions.append("indeterminate")
            return fail(
                exc.code,
                exc.detail,
                state="indeterminate",
                planDigest=plan_digest,
                rootDigest=root_digest,
                journalHeadDigest=journal.head_digest(),
            )
        journal.append(
            cfg.release_id,
            "failed",
            {"planDigest": plan_digest, "errorCode": exc.code, "detail": exc.detail, "leaseFence": cfg.lease_fence},
        )
        transitions.append("failed")
        return fail(
            exc.code,
            exc.detail,
            planDigest=plan_digest,
            rootPublished=False,
            journalHeadDigest=journal.head_digest(),
        )

    # Download back the published root manifest and verify byte-exact parity!
    fetched_root = store.get_root()
    if fetched_root is None:
        return fail("root_not_retrievable", "root manifest missing on post-publish download check")
    fetched_root_bytes, fetched_sig_bytes = fetched_root
    if "sha256:" + _sha256_bytes(fetched_root_bytes) != root_digest:
        return fail("root_digest_mismatch", "downloaded root manifest digest differs from published root")
    if sig_bytes is not None and fetched_sig_bytes != sig_bytes:
        return fail("root_signature_mismatch", "downloaded detached signature differs from published signature")

    journal.append(
        cfg.release_id,
        "published",
        {
            "planDigest": plan_digest,
            "rootDigest": root_digest,
            "assetCount": len(inventory),
            "uploadBytes": store.upload_bytes_written,
            "downloadBytes": store.download_bytes_read,
            "leaseFence": cfg.lease_fence,
        },
    )
    transitions.append("published")

    return {
        "schema": SCHEMA,
        "releaseId": cfg.release_id,
        "version": cfg.version,
        "state": "published",
        "idempotentReplay": False,
        "planDigest": plan_digest,
        "rootDigest": root_digest,
        "contractBasisDigest": cfg.contract_basis_digest,
        "toolchainId": cfg.toolchain_id,
        "builder": cfg.builder_identity,
        "signer": cfg.signer_identity,
        "assetCount": len(inventory),
        "costs": {
            "uploadCalls": store.upload_calls,
            "downloadCalls": store.download_calls,
            "uploadBytes": store.upload_bytes_written,
            "downloadBytes": store.download_bytes_read,
        },
        "transitions": transitions,
        "journalHeadDigest": journal.head_digest(),
    }


def _download_and_verify_payloads(
    store: DirectoryReleaseStore,
    expected_inventory: dict[str, dict[str, Any]],
) -> tuple[bool, str | None, str | None]:
    """Downloads every payload asset into a clean temp dir and checks exact enumeration + SHA-256."""
    try:
        remote_names = store.list_assets()
    except RemoteStoreError as exc:
        return False, exc.code, exc.detail

    expected_names = sorted(expected_inventory.keys())
    if remote_names != expected_names:
        missing = sorted(set(expected_names) - set(remote_names))
        extra = sorted(set(remote_names) - set(expected_names))
        return (
            False,
            "remote_asset_set_mismatch",
            f"remote store inventory mismatch before root publish: missing={missing} extra={extra}",
        )

    with tempfile.TemporaryDirectory(prefix="fss-rel-dlverify-") as td:
        dl_root = Path(td)
        for rel_name in expected_names:
            try:
                data = store.get_asset(rel_name)
            except RemoteStoreError as exc:
                return False, exc.code, exc.detail
            dl_path = dl_root / rel_name
            dl_path.parent.mkdir(parents=True, exist_ok=True)
            dl_path.write_bytes(data)
            expected_meta = expected_inventory[rel_name]
            actual_size = dl_path.stat().st_size
            actual_sha = sha256(dl_path)
            if actual_size != expected_meta["sizeBytes"] or actual_sha != expected_meta["sha256"]:
                return (
                    False,
                    "download_digest_mismatch",
                    f"downloaded asset {rel_name} mismatch: expected {expected_meta['sha256']} ({expected_meta['sizeBytes']}B), "
                    f"observed {actual_sha} ({actual_size}B)",
                )
    return True, None, None


def reconcile_indeterminate(
    release_id: str,
    remote_store_dir: Path,
    state_dir: Path,
    public_key: str | None = None,
) -> dict[str, Any]:
    """Conclusively reconciles an indeterminate release by inspecting the remote store
    and running full download-and-verify if the root manifest is present.
    """
    journal_path = state_dir / JOURNAL_FILENAME
    try:
        journal = PublicationJournal.load(journal_path)
    except ValueError as exc:
        return {"schema": SCHEMA, "releaseId": release_id, "state": "failed", "errorCode": "journal_corrupt", "detail": str(exc)}

    latest = journal.latest_for_release(release_id)
    if latest is None or latest.get("state") != "indeterminate":
        return {
            "schema": SCHEMA,
            "releaseId": release_id,
            "state": "failed",
            "errorCode": "not_indeterminate",
            "detail": f"release '{release_id}' is not in indeterminate state",
        }

    # Find the matching prepared entry to recover exact expected inventory & root digest.
    prepared = None
    for entry in reversed(journal.entries):
        if entry.get("releaseId") == release_id and entry.get("state") == "prepared":
            prepared = entry
            break
    if prepared is None:
        return {
            "schema": SCHEMA,
            "releaseId": release_id,
            "state": "failed",
            "errorCode": "journal_corrupt",
            "detail": f"no prepared record found for indeterminate release '{release_id}'",
        }

    prep_payload = prepared["payload"]
    expected_root_digest = prep_payload["rootDigest"]
    expected_inventory = prep_payload["assets"]
    plan_digest = prep_payload["planDigest"]
    lease_fence = prep_payload["leaseFence"]

    store = DirectoryReleaseStore(remote_store_dir)
    fetched = store.get_root()
    if fetched is None:
        journal.append(
            release_id,
            "failed",
            {
                "planDigest": plan_digest,
                "errorCode": "reconciled_not_published",
                "detail": "remote store has no root manifest; safe to retry publication",
                "leaseFence": lease_fence,
            },
        )
        return {
            "schema": SCHEMA,
            "releaseId": release_id,
            "state": "failed",
            "reconciled": "confirmed_not_published",
            "planDigest": plan_digest,
            "journalHeadDigest": journal.head_digest(),
        }

    root_bytes, sig_bytes = fetched
    actual_root_digest = "sha256:" + _sha256_bytes(root_bytes)
    if actual_root_digest != expected_root_digest:
        return {
            "schema": SCHEMA,
            "releaseId": release_id,
            "state": "failed",
            "errorCode": "reconcile_root_mismatch",
            "detail": f"remote root digest {actual_root_digest} != expected {expected_root_digest}",
        }

    sig_ok, sig_err = _verify_detached_signature(
        root_bytes,
        prep_payload["builder"],
        prep_payload["signer"],
        sig_bytes,
        public_key,
    )
    if not sig_ok:
        return {
            "schema": SCHEMA,
            "releaseId": release_id,
            "state": "failed",
            "errorCode": "signature_verify_failed",
            "detail": sig_err or "detached signature check failed during reconciliation",
        }

    ok, err_code, err_detail = _download_and_verify_payloads(store, expected_inventory)
    if not ok:
        return {
            "schema": SCHEMA,
            "releaseId": release_id,
            "state": "failed",
            "errorCode": err_code or "download_verify_failed",
            "detail": err_detail or "payload verification failed during reconciliation",
        }

    journal.append(
        release_id,
        "published",
        {
            "planDigest": plan_digest,
            "rootDigest": expected_root_digest,
            "reconciled": "confirmed_published",
            "assetCount": len(expected_inventory),
            "leaseFence": lease_fence,
        },
    )
    return {
        "schema": SCHEMA,
        "releaseId": release_id,
        "state": "published",
        "reconciled": "confirmed_published",
        "planDigest": plan_digest,
        "rootDigest": expected_root_digest,
        "assetCount": len(expected_inventory),
        "journalHeadDigest": journal.head_digest(),
    }


def verify_published_release(
    remote_store_dir: Path,
    public_key: str | None = None,
) -> dict[str, Any]:
    """Independent read-only verifier: downloads root manifest + every declared asset
    and proves exact enumeration, digest integrity, separated authority, and signature."""
    store = DirectoryReleaseStore(remote_store_dir)
    fetched = store.get_root()
    if fetched is None:
        return {
            "schema": SCHEMA,
            "state": "failed",
            "errorCode": "root_missing",
            "detail": "no published root manifest found in remote store",
        }
    root_bytes, sig_bytes = fetched
    try:
        manifest = json.loads(root_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return {
            "schema": SCHEMA,
            "state": "failed",
            "errorCode": "root_corrupt",
            "detail": f"root manifest invalid JSON: {exc}",
        }
    if manifest.get("schema") != "fss.release_root_manifest.v1":
        return {
            "schema": SCHEMA,
            "state": "failed",
            "errorCode": "root_schema_mismatch",
            "detail": f"unexpected root schema: {manifest.get('schema')!r}",
        }
    if manifest.get("builder") == manifest.get("signer"):
        return {
            "schema": SCHEMA,
            "state": "failed",
            "errorCode": "same_authority_refused",
            "detail": "published root manifest violates builder != signer separation",
        }
    if _is_forbidden_latest(str(manifest.get("version", ""))):
        return {
            "schema": SCHEMA,
            "state": "failed",
            "errorCode": "forbidden_latest_alias",
            "detail": "published root manifest contains forbidden 'latest' version",
        }
    if public_key is not None:
        sig_ok, sig_err = _verify_detached_signature(
            root_bytes, manifest["builder"], manifest["signer"], sig_bytes, public_key
        )
        if not sig_ok:
            return {
                "schema": SCHEMA,
                "state": "failed",
                "errorCode": "signature_verify_failed",
                "detail": sig_err or "detached signature verification failed",
            }
    ok, err_code, err_detail = _download_and_verify_payloads(store, manifest.get("assets", {}))
    if not ok:
        return {
            "schema": SCHEMA,
            "state": "failed",
            "errorCode": err_code or "download_verify_failed",
            "detail": err_detail or "downloaded assets failed verification",
        }
    return {
        "schema": SCHEMA,
        "state": "verified",
        "releaseId": manifest.get("releaseId"),
        "version": manifest.get("version"),
        "rootDigest": "sha256:" + _sha256_bytes(root_bytes),
        "assetCount": len(manifest.get("assets", {})),
        "builder": manifest.get("builder"),
        "signer": manifest.get("signer"),
        "downloadBytes": store.download_bytes_read,
    }


def _remediation_for(code: str) -> str:
    guides = {
        "forbidden_latest_alias": "Pin an explicit immutable semver/generation version; floating 'latest' is forbidden.",
        "same_authority_refused": "Use distinct builder and signer principals (signing_separate_from_build=true).",
        "authority_refused": "Supply an authorized principal carrying capability 'release:publish'.",
        "stale_lease_fence": "Refresh the publication lease fence above the highest committed journal fence.",
        "indeterminate_pending": "Run `release_publication.py reconcile` against the remote store before starting new publications.",
        "lost_ack_root_publish": "Inspect the remote store via `release_publication.py reconcile` to determine whether the root landed.",
        "download_digest_mismatch": "Remote payload was corrupted or truncated; root was NOT published. Repair remote store and retry.",
        "remote_asset_set_mismatch": "Remote store contains missing or extra unexpected files; clean remote payload prefix and retry.",
        "sbom_crosscheck_failed": "Regenerate SBOM, license inventory, Cargo.lock, and qualification receipt until FSS-190 passes.",
        "leftover_atomic_temp": "Confirm no packaging process is active, remove leftover atomic temp files, and re-run.",
        "forbidden_secret_asset": "Remove sensitive/key/env files from the release staging directory immediately.",
        "idempotency_conflict": "Mint a new immutable release_id for modified release artifacts rather than overwriting an existing release.",
        "pressure_refused": "Wait for resource pressure to drop to 'nominal' or 'elevated' before publishing.",
    }
    return guides.get(code, "Inspect errorCode and detail, repair the failing invariant, and retry.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FSS-192 upload then download-and-verify release publication")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_pub = sub.add_parser("publish", help="Stage, upload payloads, download-verify, and root-last publish")
    p_pub.add_argument("--release-id", required=True)
    p_pub.add_argument("--version", required=True)
    p_pub.add_argument("--artifacts-dir", type=Path, required=True)
    p_pub.add_argument("--remote-store-dir", type=Path, required=True)
    p_pub.add_argument("--state-dir", type=Path, required=True)
    p_pub.add_argument("--principal", required=True)
    p_pub.add_argument("--capability", default=REQUIRED_PUBLISH_CAPABILITY)
    p_pub.add_argument("--lease-fence", type=int, default=1)
    p_pub.add_argument("--builder", required=True)
    p_pub.add_argument("--signer", required=True)
    p_pub.add_argument("--contract-basis-digest", required=True)
    p_pub.add_argument("--toolchain-id", default="nightly-2026-08-31-x86_64-unknown-linux-gnu")
    p_pub.add_argument("--pressure", default="nominal")
    p_pub.add_argument("--max-total-bytes", type=int, default=MAX_TOTAL_BYTES)
    p_pub.add_argument("--expected-asset", action="append", default=None)
    p_pub.add_argument("--sbom", type=Path, default=None)
    p_pub.add_argument("--license-inventory", type=Path, default=None)
    p_pub.add_argument("--cargo-lock", type=Path, default=None)
    p_pub.add_argument("--metadata", type=Path, default=None)
    p_pub.add_argument("--qualification-receipt", type=Path, default=None)
    p_pub.add_argument("--signature", type=Path, default=None)
    p_pub.add_argument("--public-key", default=None)

    p_rec = sub.add_parser("reconcile", help="Reconcile an indeterminate release against remote store")
    p_rec.add_argument("--release-id", required=True)
    p_rec.add_argument("--remote-store-dir", type=Path, required=True)
    p_rec.add_argument("--state-dir", type=Path, required=True)
    p_rec.add_argument("--public-key", default=None)

    p_ver = sub.add_parser("verify", help="Independently download and verify a published release")
    p_ver.add_argument("--remote-store-dir", type=Path, required=True)
    p_ver.add_argument("--public-key", default=None)

    args = parser.parse_args(argv)

    if args.cmd == "publish":
        cfg = PublishConfig(
            release_id=args.release_id,
            version=args.version,
            artifacts_dir=args.artifacts_dir,
            remote_store_dir=args.remote_store_dir,
            state_dir=args.state_dir,
            principal=args.principal,
            capability=args.capability,
            lease_fence=args.lease_fence,
            builder_identity=args.builder,
            signer_identity=args.signer,
            contract_basis_digest=args.contract_basis_digest,
            toolchain_id=args.toolchain_id,
            expected_assets=args.expected_asset,
            pressure=args.pressure,
            max_total_bytes=args.max_total_bytes,
            sbom_path=args.sbom,
            license_inventory_path=args.license_inventory,
            cargo_lock_path=args.cargo_lock,
            metadata_path=args.metadata,
            qualification_receipt_path=args.qualification_receipt,
            signature_path=args.signature,
            public_key=args.public_key,
        )
        res = publish_release(cfg)
    elif args.cmd == "reconcile":
        res = reconcile_indeterminate(args.release_id, args.remote_store_dir, args.state_dir, args.public_key)
    else:
        res = verify_published_release(args.remote_store_dir, args.public_key)

    print(json.dumps(res, sort_keys=True))
    return 0 if res.get("state") in ("published", "verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
