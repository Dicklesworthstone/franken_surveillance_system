#!/usr/bin/env python3
"""The one durable writer for qualification receipts and release receipt outputs (fss-1geb3).

Every receipt byte that ``scripts/qualify.sh``, ``scripts/release_qualify.sh``,
``scripts/release_artifacts.py`` (verification.json, STAGE/ARTIFACT_SHA256SUMS.txt, the JSON and
checksum release assets) and ``scripts/claim_proof_bundle_checker.py`` persist goes through
:func:`atomic_write_bytes` (release archives themselves are not receipts):

1. missing parent directories are created one at a time and each new entry is fsynced into its
   parent, so a crash cannot lose the directory that holds a durable receipt;
2. the payload is written to a unique ``.<name>.tmp.*`` file in the target directory whose mode is
   set before the data is fsynced;
3. the temp file is renamed over the target with ``os.replace`` and the directory is fsynced.

A reader therefore sees either the previous complete file or the new complete file, never a
partial one. A crash (SIGKILL, power loss) can leave a ``.<name>.tmp.*`` file behind; its name
never equals ``qualification-receipt.json`` or a proof-bundle suffix, so the repository audit never
reads it as a receipt. The name shape is defined once, as :data:`ATOMIC_TEMP_NAME_RE`;
``release_artifacts.py package`` refuses an artifacts directory that still holds such a file.

Command-line entry points used by the shell scripts (stdlib only):

``prepare-run-dir (--unique BASE | --exact DIR)``
    Creates the per-run receipt directory and exclusively creates its empty ``commands.jsonl``;
    prints the absolute directory. ``--unique`` appends ``-<pid>[-<n>]`` and never reuses an
    existing directory; ``--exact`` refuses (exit 4) a directory that already holds a run's log
    and a path that is (or lies under) a regular file.
``finalize --output ... --records ... --lane ... [...]``
    Builds the qualification receipt from ``commands.jsonl`` and writes it atomically. Any
    malformed record becomes a failed ``corrupt_record`` command and fails the receipt. Prints the
    receipt status.
``capture --output FILE [--merge-stderr] -- COMMAND...``
    Runs COMMAND and atomically writes its stdout (plus stderr with ``--merge-stderr``) to FILE
    only if it exits 0; otherwise FILE is left untouched and the exit status is propagated.
``mkdirs DIR``
    Creates DIR (and missing parents) durably.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

RECORDS_FILENAME = "commands.jsonl"
RECEIPT_SCHEMA = "fss.release_qualification_receipt.v1"
COMMAND_STATUSES = frozenset({"passed", "failed", "skipped"})
# Mirrors schemas/release_qualification_receipt.v1.json commands[].outputDigest.
OUTPUT_DIGEST_RE = re.compile(r"^[a-z0-9][a-z0-9:+._-]{7,255}$")
ARGV_ITEM_MAX = 4096
UNIQUE_DIR_ATTEMPTS = 1000
EXIT_RUN_DIR_IN_USE = 4

# The single definition of the atomic writer's same-directory temp-file name (fss-0uofb):
# ``tempfile.mkstemp(prefix=atomic_temp_prefix(name))`` yields ``.<name>.tmp.<random suffix>``.
# Consumers that enumerate a directory the writer targets (release_artifacts.py package) import
# ATOMIC_TEMP_NAME_RE / is_atomic_temp_name instead of re-spelling the pattern. The suffix is
# matched as any non-empty run of non-separator characters rather than mkstemp's current
# 8-character alphabet, so a leftover is recognised regardless of the stdlib's random-name format.
ATOMIC_TEMP_INFIX = ".tmp."
ATOMIC_TEMP_NAME_RE = re.compile(r"\A\.(?P<target>.+)" + re.escape(ATOMIC_TEMP_INFIX) + r"(?P<suffix>[^/\\]+)\Z")


def atomic_temp_prefix(target_name: str) -> str:
    """The ``mkstemp`` prefix atomic_write_bytes uses for a temp file replacing ``target_name``."""
    return f".{target_name}{ATOMIC_TEMP_INFIX}"


def is_atomic_temp_name(name: str) -> bool:
    """True when ``name`` has the shape of an atomic_write_bytes temp file (possibly a crash leftover)."""
    return ATOMIC_TEMP_NAME_RE.fullmatch(name) is not None

LANE_IDS = {
    "policy": "QL-POLICY-001", "docs": "QL-POLICY-001", "rust": "QL-RUST-001",
    "full": "QL-RUST-001", "lab": "QL-LAB-001", "adapter": "QL-ADAPTER-001",
    "media": "QL-MEDIA-001", "archive": "QL-ARCHIVE-001", "model": "QL-MODEL-001",
    "geometry": "QL-GEOMETRY-001", "threat": "QL-THREAT-001", "agent": "QL-AGENT-001",
    "privacy": "QL-PRIVACY-001", "release-preflight": "QL-RELEASE-001", "release": "QL-RELEASE-001",
}


def fsync_directory(path: Path) -> None:
    dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def make_durable_dirs(path: Path | str) -> Path:
    """Creates ``path`` and any missing ancestors, fsyncing each new entry into its parent."""
    target = Path(path).resolve()
    missing: list[Path] = []
    probe = target
    while not probe.is_dir():
        missing.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent
    for directory in reversed(missing):
        try:
            os.mkdir(directory)
        except FileExistsError:
            if not directory.is_dir():
                raise NotADirectoryError(
                    errno.ENOTDIR, "exists and is not a directory", os.fspath(directory)
                ) from None
            continue
        fsync_directory(directory.parent)
    return target


def _discard_temp(temp_path: Path) -> None:
    """Removes an unrenamed temp file while a write is failing. A removal error other than
    FileNotFoundError is attached to the in-flight exception and logged, never raised in its
    place: the caller must see why the write failed, not why the cleanup failed."""
    original = sys.exc_info()[1]
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass
    except OSError as secondary:
        if original is None:
            raise
        note = f"additionally failed to remove temp file {temp_path}: {secondary!r}"
        # BaseException.add_note is Python >= 3.11; the repository declares no minimum Python
        # version, so on older interpreters the note is only logged (below), never lost silently.
        if hasattr(original, "add_note"):
            original.add_note(note)
        print(f"qualification_receipt: {note}", file=sys.stderr)


def atomic_write_bytes(output_path: Path | str, data: bytes, mode: int = 0o644) -> Path:
    """Durably and atomically replaces ``output_path`` with ``data`` (see module docstring)."""
    target = Path(output_path).resolve()
    make_durable_dirs(target.parent)
    descriptor, temp_name = tempfile.mkstemp(prefix=atomic_temp_prefix(target.name), dir=target.parent)
    temp_path = Path(temp_name)
    replaced = False
    try:
        handle = None
        try:
            os.fchmod(descriptor, mode)
            handle = os.fdopen(descriptor, "wb")
        finally:
            if handle is None:
                os.close(descriptor)
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
        replaced = True
        fsync_directory(target.parent)
    finally:
        if not replaced:
            _discard_temp(temp_path)
    return target


def write_json_atomic(output_path: Path | str, document: Any, *, sort_keys: bool = False) -> Path:
    return atomic_write_bytes(output_path, (json.dumps(document, indent=2, sort_keys=sort_keys) + "\n").encode("utf-8"))


def write_qualification_receipt(output_path: Path | str, receipt: dict[str, Any]) -> Path:
    """Atomically writes a qualification receipt (the only receipt writer in the repository)."""
    return write_json_atomic(output_path, receipt)


def _corrupt_command(raw: bytes) -> dict[str, Any]:
    return {
        "argv": ["corrupt_record"],
        "status": "failed",
        "outputDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }


def _valid_command(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    argv, status, digest = row.get("argv"), row.get("status"), row.get("outputDigest")
    if not isinstance(argv, list) or not argv:
        return None
    if not all(isinstance(item, str) and len(item) <= ARGV_ITEM_MAX for item in argv):
        return None
    if not isinstance(status, str) or status not in COMMAND_STATUSES:
        return None
    if not isinstance(digest, str) or not OUTPUT_DIGEST_RE.fullmatch(digest):
        return None
    return {"argv": argv, "status": status, "outputDigest": digest}


def load_command_records(records_path: Path | str) -> tuple[list[dict[str, Any]], bool]:
    """Reads ``commands.jsonl``. Returns (commands, any_malformed); every line that is not a
    well-formed command object becomes a failed ``corrupt_record`` command."""
    path = Path(records_path)
    try:
        raw_bytes = path.read_bytes()
    except FileNotFoundError:
        return [], False
    except OSError as exc:
        return [_corrupt_command(f"unreadable {RECORDS_FILENAME}: {exc.strerror or exc}".encode("utf-8"))], True
    commands: list[dict[str, Any]] = []
    malformed = False
    for raw in raw_bytes.split(b"\n"):
        raw = raw.strip()
        if not raw:
            continue
        try:
            command = _valid_command(json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, ValueError, RecursionError):
            command = None
        if command is None:
            commands.append(_corrupt_command(raw))
            malformed = True
        else:
            commands.append(command)
    return commands, malformed


def build_receipt(
    *,
    commands: list[dict[str, Any]],
    malformed: bool,
    lane: str,
    source_commit: str,
    source_tree: str,
    sibling_digest: str,
    host_digest: str,
    toolchain: str,
    target: str,
    started_ns: int,
    finished_ns: int,
    status: str,
    manifest_root: str,
    cargo_lock: Path,
) -> dict[str, Any]:
    if malformed:
        status = "failed"
    if not commands:
        commands = [{
            "argv": ["scripts/qualify.sh", "--lane", lane],
            "status": "failed",
            "outputDigest": "sha256:" + hashlib.sha256(b"no-command-record").hexdigest(),
        }]
        status = "failed"
    if status == "passed" and any(command["status"] == "failed" for command in commands):
        status = "failed"
    return {
        "schema": RECEIPT_SCHEMA,
        "receiptId": f"local:{lane}:{source_commit.split(':', 1)[-1][:16]}",
        "laneId": LANE_IDS[lane],
        "sourceCommit": source_commit,
        "sourceTree": source_tree,
        "siblingClosureDigest": sibling_digest,
        "cargoLockDigest": "sha256:" + hashlib.sha256(cargo_lock.read_bytes()).hexdigest() if cargo_lock.is_file() else None,
        "toolchain": toolchain[:256],
        "hostIdentity": host_digest,
        "target": target[:256],
        "features": [],
        "commands": commands,
        "artifactManifestDigest": manifest_root if manifest_root.startswith("sha256:") else None,
        "startedAt": {"earliestNs": started_ns, "latestNs": started_ns, "clockBasis": "host-realtime"},
        "finishedAt": {"earliestNs": finished_ns, "latestNs": finished_ns, "clockBasis": "host-realtime"},
        "status": status,
    }


def _create_records_file(run_dir: Path) -> None:
    descriptor = os.open(run_dir / RECORDS_FILENAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(run_dir)


def prepare_unique_run_dir(base: Path | str) -> Path:
    base_path = Path(base).resolve()
    parent = make_durable_dirs(base_path.parent)
    pid = os.getpid()
    for attempt in range(UNIQUE_DIR_ATTEMPTS):
        suffix = f"-{pid}" if attempt == 0 else f"-{pid}-{attempt}"
        candidate = parent / f"{base_path.name}{suffix}"
        try:
            os.mkdir(candidate)
        except FileExistsError:
            continue
        fsync_directory(parent)
        _create_records_file(candidate)
        return candidate
    raise FileExistsError(f"no unused run directory for {base_path} after {UNIQUE_DIR_ATTEMPTS} attempts")


def prepare_exact_run_dir(run_dir: Path | str) -> Path:
    """Raises FileExistsError if ``run_dir`` already holds another run's ``commands.jsonl``."""
    directory = make_durable_dirs(run_dir)
    _create_records_file(directory)
    return directory


def _run_capture(output: str, merge_stderr: bool, command: list[str]) -> int:
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("capture: missing command after --", file=sys.stderr)
        return 2
    try:
        completed = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT if merge_stderr else None, check=False
        )
    except FileNotFoundError:
        print(f"capture: command not found: {command[0]}", file=sys.stderr)
        return 127
    except PermissionError:
        print(f"capture: command not executable: {command[0]}", file=sys.stderr)
        return 126
    if completed.returncode != 0:
        sys.stderr.buffer.write(completed.stdout)
        sys.stderr.flush()
        print(f"capture: {command[0]} exited {completed.returncode}; {output} left untouched", file=sys.stderr)
        return completed.returncode if completed.returncode > 0 else 128 - completed.returncode
    atomic_write_bytes(output, completed.stdout)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="action", required=True)

    prep = sub.add_parser("prepare-run-dir", help="create a fresh per-run receipt directory")
    group = prep.add_mutually_exclusive_group(required=True)
    group.add_argument("--unique", metavar="BASE")
    group.add_argument("--exact", metavar="DIR")

    fin = sub.add_parser("finalize", help="build and atomically write a qualification receipt")
    fin.add_argument("--output", required=True)
    fin.add_argument("--records", required=True)
    fin.add_argument("--lane", required=True, choices=sorted(LANE_IDS))
    fin.add_argument("--source-commit", required=True)
    fin.add_argument("--source-tree", required=True)
    fin.add_argument("--sibling-digest", required=True)
    fin.add_argument("--host-digest", required=True)
    fin.add_argument("--toolchain", required=True)
    fin.add_argument("--target", required=True)
    fin.add_argument("--started-ns", required=True, type=int)
    fin.add_argument("--finished-ns", required=True, type=int)
    fin.add_argument("--status", required=True, choices=["passed", "failed", "partial", "interrupted"])
    fin.add_argument("--manifest-root", required=True)
    fin.add_argument("--cargo-lock", default="Cargo.lock")

    cap = sub.add_parser("capture", help="atomically capture a command's output")
    cap.add_argument("--output", required=True)
    cap.add_argument("--merge-stderr", action="store_true")
    cap.add_argument("command", nargs=argparse.REMAINDER)

    mk = sub.add_parser("mkdirs", help="durably create a directory")
    mk.add_argument("directory")

    args = parser.parse_args(argv)
    if args.action == "prepare-run-dir":
        try:
            run_dir = prepare_unique_run_dir(args.unique) if args.unique else prepare_exact_run_dir(args.exact)
        except NotADirectoryError as exc:
            where = args.unique or args.exact
            print(
                f"refusing qualification run directory {where}: {exc.filename} is not a directory "
                f"(it is an existing regular or special file); choose a fresh --receipt-dir",
                file=sys.stderr,
            )
            return EXIT_RUN_DIR_IN_USE
        except FileExistsError as exc:
            where = args.unique or args.exact
            print(
                f"refusing to reuse qualification run directory {where}: it already holds a run's "
                f"{RECORDS_FILENAME} ({exc.strerror or exc}); choose a fresh --receipt-dir",
                file=sys.stderr,
            )
            return EXIT_RUN_DIR_IN_USE
        print(run_dir)
        return 0
    if args.action == "finalize":
        commands, malformed = load_command_records(args.records)
        receipt = build_receipt(
            commands=commands,
            malformed=malformed,
            lane=args.lane,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            sibling_digest=args.sibling_digest,
            host_digest=args.host_digest,
            toolchain=args.toolchain,
            target=args.target,
            started_ns=args.started_ns,
            finished_ns=args.finished_ns,
            status=args.status,
            manifest_root=args.manifest_root,
            cargo_lock=Path(args.cargo_lock),
        )
        write_qualification_receipt(args.output, receipt)
        print(receipt["status"])
        return 0
    if args.action == "capture":
        return _run_capture(args.output, args.merge_stderr, args.command)
    make_durable_dirs(args.directory)
    return 0


if __name__ == "__main__":
    sys.exit(main())
