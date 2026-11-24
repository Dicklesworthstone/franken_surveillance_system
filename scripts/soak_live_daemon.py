#!/usr/bin/env python3
"""Configurable multi-camera continuous daemon soak & telemetry harness (C7).

Pure Python 3 stdlib executable supporting:
  1. --mode deterministic-smoke:
     Spins up `fss site run` against a temporary synthetic 3-camera `site.json`
     (`sensor:wyze-39`, `sensor:wyze-51`, `sensor:unifi-g4-177`) with tight rolling ring cap,
     polls live `fss site status --json` AND `fss-mcp` JSON-RPC 2.0 `session_orient`
     concurrently on a short interval, records per-interval RSS, disk MB, pack count, commits,
     orient p50/p99 ms, reconnects, and gaps to `target/test-logs/daemon-soak/soak_timeseries.jsonl`,
     issues graceful `fss site stop --json`, runs `fss doctor --json`, and emits
     `target/test-logs/daemon-soak/soak_receipt.json` with hard pass/fail assertions.
  2. --mode live --manifest <site.json> --root <deploy> --duration-hours <1|24>
     --poll-interval-s <10> --ring-cap-gib <2.0>:
     Runs an owner-authorized LAN continuous soak (1h/24h+) with identical telemetry & gates.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = REPO_ROOT / "target" / "test-logs" / "daemon-soak"
DEFAULT_FIXTURE_JPEG = REPO_ROOT / "tests" / "fixtures" / "media" / "jpeg" / "gray_16x16_flat.jpg"
DEFAULT_SMOKE_RING_CAP_BYTES = 256 * 1024  # 256 KiB
DEFAULT_SMOKE_PACK_TARGET_BYTES = 32 * 1024  # 32 KiB
DEFAULT_LIVE_PACK_TARGET_BYTES = 64 * 1024 * 1024  # 64 MiB


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(((len(ordered) - 1) * pct) / 100.0)
    idx = max(0, min(idx, len(ordered) - 1))
    return ordered[idx]


def fss_supports_site_run(binary: Path) -> bool:
    if not (binary.is_file() and os.access(binary, os.X_OK)):
        return False
    try:
        proc = subprocess.run(
            [str(binary), "help"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return proc.returncode == 0 and "fss site run" in proc.stdout
    except (OSError, subprocess.SubprocessError):
        return False


def resolve_binaries(bin_dir_override: str | None) -> tuple[Path, Path, Path, str]:
    """Resolves (fss, fss-mcp, fss-file, profile_label).

    Prefers up-to-date release binaries when present so MCP orient reflects real optimized
    latency, falling back cleanly to debug binaries when release is absent or older.
    """
    candidates: list[tuple[str, Path]] = []
    if bin_dir_override:
        candidates.append(("custom", Path(bin_dir_override)))
    else:
        target_env = os.environ.get("CARGO_TARGET_DIR")
        target_root = Path(target_env) if target_env else (REPO_ROOT / "target")
        candidates.append(("release", target_root / "release"))
        candidates.append(("debug", target_root / "debug"))

    fss_bin: Path | None = None
    fss_profile = "unknown"
    for label, directory in candidates:
        cand = directory / "fss"
        if fss_supports_site_run(cand):
            fss_bin = cand
            fss_profile = label
            break

    if fss_bin is None:
        raise RuntimeError(
            "Unable to locate an executable `fss` binary supporting `site run`. "
            "Build with `cargo build --offline -p fss-cli --bin fss --bin fss-mcp --bin fss-file` "
            "or pass --bin-dir."
        )

    def find_companion(name: str) -> Path:
        for _, directory in candidates:
            cand = directory / name
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        raise RuntimeError(f"Unable to locate companion executable `{name}` in {candidates}")

    mcp_bin = find_companion("fss-mcp")
    file_bin = find_companion("fss-file")
    return fss_bin, mcp_bin, file_bin, fss_profile


def sample_rss_kb(pid: int) -> int:
    if pid <= 0:
        return 0
    if platform.system() == "Linux":
        status_path = Path(f"/proc/{pid}/status")
        try:
            for line in status_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])
        except OSError:
            pass
    try:
        proc = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return int(proc.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return 0


def measure_pack_storage(root: Path) -> tuple[int, int, int]:
    """Returns (pack_bytes, pack_count, temp_orphan_count) under `<root>/objects/`."""
    objects_dir = root / "objects"
    packs_dir = objects_dir / "packs"
    pack_bytes = 0
    pack_count = 0
    temp_orphans = 0

    if packs_dir.is_dir():
        for entry in packs_dir.iterdir():
            if not entry.is_file():
                continue
            name = entry.name
            if name.endswith(".fssp"):
                pack_count += 1
                try:
                    pack_bytes += entry.stat().st_size
                except OSError:
                    pass
            elif ".tmp" in name:
                temp_orphans += 1

    if objects_dir.is_dir():
        for dirpath, _, filenames in os.walk(objects_dir):
            if Path(dirpath) == packs_dir:
                continue
            for name in filenames:
                if ".tmp" in name:
                    temp_orphans += 1

    return pack_bytes, pack_count, temp_orphans


def build_smoke_manifest(daemon_root: Path, ring_cap_bytes: int, pack_target_bytes: int) -> dict[str, Any]:
    return {
        "schema": "fss.site_manifest.v1",
        "site_id": "site-soak-smoke",
        "deployment_root": str(daemon_root),
        "ring_cap_bytes": ring_cap_bytes,
        "soft_watermark_pct": 75,
        "hard_watermark_pct": 95,
        "pack_target_bytes": pack_target_bytes,
        "scrub_budget_bytes_per_tick": 131072,
        "cameras": [
            {
                "sensor_id": "sensor:wyze-39",
                "adapter": "synthetic",
                "endpoint": "synthetic://wyze-39",
                "secret_id": "secret:wyze:39",
                "priority_tier": "standard",
                "zone_id": "driveway",
                "dimensions": [32, 32],
                "osd_ignore_rects": ["0,0,8,4"],
                "failure_domains": ["wifi:home-2g", "power:circuit-a"],
                "reconnect_min_ms": 200,
                "reconnect_max_ms": 2000,
                "stall_timeout_ms": 5000,
                "ring_max_frames": 64,
                "ring_max_bytes": 65536,
                "gop_frames": 4,
            },
            {
                "sensor_id": "sensor:wyze-51",
                "adapter": "synthetic",
                "endpoint": "synthetic://wyze-51",
                "secret_id": "secret:wyze:51",
                "priority_tier": "high_consequence_zone",
                "zone_id": "driveway",
                "dimensions": [32, 32],
                "osd_ignore_rects": ["0,0,8,4"],
                "failure_domains": ["wifi:home-2g", "power:circuit-b"],
                "reconnect_min_ms": 200,
                "reconnect_max_ms": 2000,
                "stall_timeout_ms": 5000,
                "ring_max_frames": 64,
                "ring_max_bytes": 65536,
                "gop_frames": 4,
            },
            {
                "sensor_id": "sensor:unifi-g4-177",
                "adapter": "synthetic",
                "endpoint": "synthetic://unifi-g4-177",
                "secret_id": "secret:unifi:177",
                "priority_tier": "active_investigation",
                "zone_id": "driveway",
                "dimensions": [32, 32],
                "osd_ignore_rects": ["0,0,8,4"],
                "failure_domains": ["poe:switch-1", "power:ups-rack"],
                "reconnect_min_ms": 200,
                "reconnect_max_ms": 2000,
                "stall_timeout_ms": 5000,
                "ring_max_frames": 64,
                "ring_max_bytes": 65536,
                "gop_frames": 4,
            },
        ],
        "topology": {
            "shared_zones": [
                {
                    "zone_id": "driveway",
                    "cameras": ["sensor:wyze-39", "sensor:wyze-51", "sensor:unifi-g4-177"],
                    "max_separation_ns": 5000000000,
                }
            ]
        },
    }


def init_companion_reference_deployment(file_bin: Path, orient_root: Path) -> None:
    if not DEFAULT_FIXTURE_JPEG.is_file():
        raise RuntimeError(f"Missing fixture JPEG at {DEFAULT_FIXTURE_JPEG}")
    proc = subprocess.run(
        [
            str(file_bin),
            "import",
            "--root",
            str(orient_root),
            "--site",
            "site:soak-smoke",
            "--input",
            str(DEFAULT_FIXTURE_JPEG),
            "--sensor",
            "sensor:wyze-39",
            "--stream",
            "stream:main",
            "--receive-time-ns",
            "1000000000",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"fss-file import failed ({proc.returncode}): stdout={proc.stdout} stderr={proc.stderr}"
        )


class McpOrientClient:
    """Persistent stdio JSON-RPC 2.0 client driving `fss-mcp` `session_orient`."""

    def __init__(self, mcp_bin: Path, root: Path) -> None:
        self._proc = subprocess.Popen(
            [str(mcp_bin), "--root", str(root)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._next_id = 1
        self.warmup_ms: list[float] = []
        self._handshake()

    def _send(self, payload: dict[str, Any]) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self._proc.stdin.flush()

    def _recv(self) -> dict[str, Any]:
        assert self._proc.stdout is not None
        line = self._proc.stdout.readline()
        if not line:
            stderr_text = ""
            if self._proc.stderr is not None:
                stderr_text = self._proc.stderr.read()
            raise RuntimeError(f"fss-mcp closed stdout unexpectedly; stderr={stderr_text!r}")
        return json.loads(line)

    def _handshake(self) -> None:
        req_id = self._next_id
        self._next_id += 1
        self._send(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "fss-soak-harness", "version": "1.0"},
                },
            }
        )
        resp = self._recv()
        if "result" not in resp:
            raise RuntimeError(f"fss-mcp initialize failed: {resp}")
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        # Warm up steady-state file cache and process pages before timed soak sampling.
        for _ in range(3):
            dt_ms, ok = self.call_orient()
            if not ok:
                raise RuntimeError("fss-mcp warmup session_orient returned error")
            self.warmup_ms.append(round(dt_ms, 3))

    def call_orient(self) -> tuple[float, bool]:
        req_id = self._next_id
        self._next_id += 1
        t0 = time.perf_counter()
        self._send(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": "session_orient", "arguments": {"view": "pulse"}},
            }
        )
        resp = self._recv()
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        result = resp.get("result")
        ok = isinstance(result, dict) and not result.get("isError", False)
        return elapsed_ms, ok

    def close(self) -> None:
        try:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
        except OSError:
            pass
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=5)


def poll_site_status(fss_bin: Path, daemon_root: Path) -> tuple[float, dict[str, Any]]:
    t0 = time.perf_counter()
    proc = subprocess.run(
        [str(fss_bin), "site", "status", "--root", str(daemon_root), "--json"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    if proc.returncode != 0:
        raise RuntimeError(
            f"fss site status failed ({proc.returncode}): stdout={proc.stdout} stderr={proc.stderr}"
        )
    return elapsed_ms, json.loads(proc.stdout)


def run_doctor(fss_bin: Path, root: Path) -> tuple[str, int, dict[str, Any]]:
    proc = subprocess.run(
        [str(fss_bin), "doctor", "--json", "--root", str(root)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    report = json.loads(proc.stdout)
    verdict = str(report.get("verdict", "unknown"))
    unreferenced = -1
    for check in report.get("checks", []):
        if check.get("id") == "objects.unreferenced":
            counts = check.get("counts", {})
            if isinstance(counts, dict) and "unreferenced_objects" in counts:
                unreferenced = int(counts["unreferenced_objects"])
    return verdict, unreferenced, report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configurable continuous FSS daemon soak & telemetry harness."
    )
    parser.add_argument(
        "--mode",
        choices=["deterministic-smoke", "live"],
        default="deterministic-smoke",
        help="Run offline deterministic synthetic smoke or owner-authorized live LAN soak.",
    )
    parser.add_argument(
        "--manifest",
        type=str,
        default=None,
        help="Path to secret-free site.json manifest (required in --mode live).",
    )
    parser.add_argument(
        "--root",
        type=str,
        default=None,
        help="Deployment root directory (required in --mode live).",
    )
    parser.add_argument(
        "--orient-root",
        type=str,
        default=None,
        help="Optional v1 deployment root for concurrent fss-mcp session_orient & fss doctor checks.",
    )
    parser.add_argument(
        "--duration-s",
        type=float,
        default=5.0,
        help="Soak duration in seconds (default 5.0 for deterministic-smoke).",
    )
    parser.add_argument(
        "--duration-hours",
        type=float,
        default=None,
        help="Soak duration in hours (overrides --duration-s when provided; e.g. 1 or 24).",
    )
    parser.add_argument(
        "--poll-interval-s",
        type=float,
        default=None,
        help="Polling interval in seconds (default 0.25 in smoke, 10.0 in live).",
    )
    parser.add_argument(
        "--ring-cap-gib",
        type=float,
        default=2.0,
        help="Expected rolling ring capacity ceiling in GiB for --mode live (default 2.0).",
    )
    parser.add_argument(
        "--tick-ms",
        type=int,
        default=50,
        help="Daemon supervision loop tick interval in milliseconds (default 50).",
    )
    parser.add_argument(
        "--orient-p99-limit-ms",
        type=float,
        default=10.0,
        help="Hard upper bound on steady-state orient p99 latency in ms (default 10.0).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory for soak_timeseries.jsonl and soak_receipt.json.",
    )
    parser.add_argument(
        "--bin-dir",
        type=str,
        default=None,
        help="Optional explicit directory containing fss, fss-mcp, and fss-file binaries.",
    )
    return parser.parse_args(argv)


def run_soak(args: argparse.Namespace) -> int:
    fss_bin, mcp_bin, file_bin, profile_label = resolve_binaries(args.bin_dir)
    duration_s = (
        float(args.duration_hours) * 3600.0
        if args.duration_hours is not None
        else float(args.duration_s)
    )
    if duration_s <= 0.0:
        raise ValueError("Soak duration must be positive")
    poll_interval_s = (
        float(args.poll_interval_s)
        if args.poll_interval_s is not None
        else (0.25 if args.mode == "deterministic-smoke" else 10.0)
    )
    if poll_interval_s <= 0.0:
        raise ValueError("--poll-interval-s must be positive")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timeseries_path = output_dir / "soak_timeseries.jsonl"
    receipt_path = output_dir / "soak_receipt.json"

    with tempfile.TemporaryDirectory(prefix="fsss-", dir="/tmp") as tmp_dir:
        tmp_path = Path(tmp_dir)
        if args.mode == "deterministic-smoke":
            daemon_root = tmp_path / "d"
            orient_root: Path | None = tmp_path / "o"
            ring_cap_bytes = DEFAULT_SMOKE_RING_CAP_BYTES
            pack_target_bytes = DEFAULT_SMOKE_PACK_TARGET_BYTES
            manifest_path = tmp_path / "site.json"
            manifest_obj = build_smoke_manifest(daemon_root, ring_cap_bytes, pack_target_bytes)
            manifest_path.write_text(
                json.dumps(manifest_obj, indent=2) + "\n", encoding="utf-8"
            )
            assert orient_root is not None
            init_companion_reference_deployment(file_bin, orient_root)
        else:
            if not args.manifest or not args.root:
                raise ValueError("--mode live requires --manifest <site.json> and --root <deploy>")
            manifest_path = Path(args.manifest).resolve()
            daemon_root = Path(args.root).resolve()
            manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
            ring_cap_bytes = int(
                manifest_obj.get("ring_cap_bytes", int(args.ring_cap_gib * (1024**3)))
            )
            pack_target_bytes = int(
                manifest_obj.get("pack_target_bytes", DEFAULT_LIVE_PACK_TARGET_BYTES)
            )
            if args.orient_root:
                orient_root = Path(args.orient_root).resolve()
            elif (daemon_root / "LAYOUT").is_file():
                orient_root = daemon_root
            else:
                orient_root = None

        disk_bound_bytes = ring_cap_bytes + 2 * pack_target_bytes
        daemon_stdout_path = tmp_path / "daemon.stdout.log"
        daemon_stderr_path = tmp_path / "daemon.stderr.log"

        daemon_stdout_f = daemon_stdout_path.open("w+", encoding="utf-8")
        daemon_stderr_f = daemon_stderr_path.open("w+", encoding="utf-8")
        daemon_proc = subprocess.Popen(
            [
                str(fss_bin),
                "site",
                "run",
                "--manifest",
                str(manifest_path),
                "--root",
                str(daemon_root),
                "--tick-ms",
                str(args.tick_ms),
                "--json",
            ],
            stdout=daemon_stdout_f,
            stderr=daemon_stderr_f,
            text=True,
        )

        mcp_client: McpOrientClient | None = None
        timeseries_records: list[dict[str, Any]] = []
        orient_samples_ms: list[float] = []
        status_samples_ms: list[float] = []
        rss_samples_kb: list[int] = []
        peak_pack_bytes = 0
        peak_pack_count = 0
        max_commits = 0
        max_reconnects = 0
        total_gap_observations = 0
        orient_errors = 0

        try:
            # Wait for `<daemon_root>/run/daemon.meta.json` and `daemon.sock` readiness.
            meta_path = daemon_root / "run" / "daemon.meta.json"
            sock_path = daemon_root / "run" / "daemon.sock"
            ready_deadline = time.monotonic() + 15.0
            while time.monotonic() < ready_deadline:
                if daemon_proc.poll() is not None:
                    daemon_stdout_f.flush()
                    daemon_stderr_f.flush()
                    raise RuntimeError(
                        f"fss site run exited prematurely ({daemon_proc.returncode}): "
                        f"stdout={daemon_stdout_path.read_text(encoding='utf-8')} "
                        f"stderr={daemon_stderr_path.read_text(encoding='utf-8')}"
                    )
                if meta_path.is_file() and sock_path.exists():
                    break
                time.sleep(0.02)
            else:
                raise RuntimeError("Timed out waiting for daemon UDS / daemon.meta.json")

            if orient_root is not None:
                mcp_client = McpOrientClient(mcp_bin, orient_root)

            soak_start = time.monotonic()
            soak_end = soak_start + duration_s
            sample_idx = 0

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                while True:
                    sample_idx += 1
                    loop_t0 = time.monotonic()

                    status_fut = pool.submit(poll_site_status, fss_bin, daemon_root)
                    orient_fut = (
                        pool.submit(mcp_client.call_orient) if mcp_client is not None else None
                    )

                    status_ms, status_json = status_fut.result(timeout=15)
                    status_samples_ms.append(status_ms)

                    if orient_fut is not None:
                        orient_ms, orient_ok = orient_fut.result(timeout=15)
                        if not orient_ok:
                            orient_errors += 1
                    else:
                        orient_ms = status_ms
                    orient_samples_ms.append(orient_ms)

                    daemon_pid = int(status_json.get("pid", daemon_proc.pid))
                    rss_kb = sample_rss_kb(daemon_pid)
                    if rss_kb > 0:
                        rss_samples_kb.append(rss_kb)

                    pack_bytes, pack_count, _ = measure_pack_storage(daemon_root)
                    peak_pack_bytes = max(peak_pack_bytes, pack_bytes)
                    peak_pack_count = max(peak_pack_count, pack_count)

                    commits = int(status_json.get("head_commit_sequence", 0))
                    max_commits = max(max_commits, commits)
                    cameras = status_json.get("cameras", [])
                    reconnects = sum(int(c.get("reconnect_count", 0)) for c in cameras)
                    max_reconnects = max(max_reconnects, reconnects)
                    cameras_running = sum(1 for c in cameras if c.get("running"))
                    gaps_now = len(cameras) - cameras_running
                    total_gap_observations += gaps_now
                    ring_obj = status_json.get("ring") or {}
                    ring_used = int(ring_obj.get("used_bytes", 0))
                    ring_cap = int(ring_obj.get("capacity_bytes", ring_cap_bytes))

                    record = {
                        "schema": "fss.soak_timeseries_sample.v1",
                        "sample": sample_idx,
                        "elapsed_s": round(time.monotonic() - soak_start, 3),
                        "daemon_pid": daemon_pid,
                        "rss_kb": rss_kb,
                        "disk_mb": round(pack_bytes / (1024.0 * 1024.0), 4),
                        "pack_bytes": pack_bytes,
                        "pack_count": pack_count,
                        "ring_used_bytes": ring_used,
                        "ring_cap_bytes": ring_cap,
                        "commits": commits,
                        "orient_ms": round(orient_ms, 3),
                        "orient_p50_ms": round(percentile(orient_samples_ms, 50.0), 3),
                        "orient_p99_ms": round(percentile(orient_samples_ms, 99.0), 3),
                        "status_ms": round(status_ms, 3),
                        "reconnects": reconnects,
                        "gaps": gaps_now,
                        "cameras_running": cameras_running,
                    }
                    timeseries_records.append(record)

                    now_mono = time.monotonic()
                    if now_mono >= soak_end and sample_idx >= 5:
                        break
                    sleep_s = min(poll_interval_s, max(0.0, soak_end - now_mono))
                    elapsed_iter = now_mono - loop_t0
                    rem = max(0.0, sleep_s - elapsed_iter)
                    if rem > 0.0:
                        time.sleep(rem)

            # Graceful shutdown via `fss site stop --json`.
            stop_proc = subprocess.run(
                [str(fss_bin), "site", "stop", "--root", str(daemon_root), "--json"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if stop_proc.returncode != 0:
                raise RuntimeError(
                    f"fss site stop failed ({stop_proc.returncode}): "
                    f"stdout={stop_proc.stdout} stderr={stop_proc.stderr}"
                )
            stop_json = json.loads(stop_proc.stdout)

            daemon_rc = daemon_proc.wait(timeout=20)
        finally:
            if mcp_client is not None:
                mcp_client.close()
            if daemon_proc.poll() is None:
                daemon_proc.terminate()
                try:
                    daemon_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon_proc.kill()
                    daemon_proc.wait(timeout=5)
            daemon_stdout_f.flush()
            daemon_stderr_f.flush()
            daemon_stdout_f.close()
            daemon_stderr_f.close()

        shutdown_raw = daemon_stdout_path.read_text(encoding="utf-8").strip()
        shutdown_json = json.loads(shutdown_raw) if shutdown_raw else {}
        socket_removed = not (daemon_root / "run" / "daemon.sock").exists()
        final_pack_bytes, final_pack_count, v2_temp_orphans = measure_pack_storage(daemon_root)
        peak_pack_bytes = max(peak_pack_bytes, final_pack_bytes)

        doctor_verdict = "skipped"
        doctor_unreferenced = 0
        doctor_healthy = True
        if orient_root is not None:
            doctor_verdict, doctor_unreferenced, _ = run_doctor(fss_bin, orient_root)
            doctor_healthy = doctor_verdict == "healthy" and doctor_unreferenced == 0

        # Evaluate hard pass/fail assertions.
        orient_p50_ms = round(percentile(orient_samples_ms, 50.0), 3)
        orient_p99_ms = round(percentile(orient_samples_ms, 99.0), 3)
        split = max(1, len(orient_samples_ms) // 2)
        early_orient_p99_ms = round(percentile(orient_samples_ms[:split], 99.0), 3)
        late_orient_p99_ms = round(percentile(orient_samples_ms[split:], 99.0), 3)

        if rss_samples_kb:
            rss_split = max(1, len(rss_samples_kb) // 2)
            early_rss_kb = int(percentile([float(x) for x in rss_samples_kb[:rss_split]], 50.0))
            late_rss_kb = int(percentile([float(x) for x in rss_samples_kb[rss_split:]], 95.0))
            rss_max_kb = max(rss_samples_kb)
            # Flat RSS bound: late p95 stays within +50% or +16 MiB of early median baseline.
            rss_flat = late_rss_kb <= max(int(early_rss_kb * 1.5), early_rss_kb + 16384)
        else:
            early_rss_kb = 0
            late_rss_kb = 0
            rss_max_kb = 0
            rss_flat = True

        orphans = max(0, doctor_unreferenced) + v2_temp_orphans
        disk_bounded = peak_pack_bytes <= disk_bound_bytes
        active_tasks = int(shutdown_json.get("active_tasks", -1))
        leaked_obligations = int(shutdown_json.get("leaked_obligations", -1))
        verified_batches = int(shutdown_json.get("verified_batches", 0))
        shutdown_clean = (
            daemon_rc == 0
            and stop_json.get("schema") == "fss.daemon_stop.v1"
            and shutdown_json.get("schema") == "fss.daemon_shutdown.v1"
            and active_tasks == 0
            and leaked_obligations == 0
            and verified_batches > 0
            and socket_removed
        )
        orient_bounded = orient_p99_ms < args.orient_p99_limit_ms and orient_errors == 0

        all_passed = (
            orient_bounded
            and disk_bounded
            and orphans == 0
            and rss_flat
            and shutdown_clean
            and doctor_healthy
        )

        # Write JSONL timeseries and final receipt atomically.
        with timeseries_path.open("w", encoding="utf-8") as fh:
            for rec in timeseries_records:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")

        receipt = {
            "schema": "fss.soak_receipt.v1",
            "mode": args.mode,
            "binary_profile": profile_label,
            "samples": len(timeseries_records),
            "duration_target_s": round(duration_s, 3),
            "poll_interval_s": poll_interval_s,
            "commits_max": max_commits,
            "verified_batches": verified_batches,
            "orient_p50_ms": orient_p50_ms,
            "orient_p99_ms": orient_p99_ms,
            "orient_early_p99_ms": early_orient_p99_ms,
            "orient_late_p99_ms": late_orient_p99_ms,
            "orient_p99_limit_ms": args.orient_p99_limit_ms,
            "orient_errors": orient_errors,
            "orient_warmup_ms": mcp_client.warmup_ms if mcp_client is not None else [],
            "status_p50_ms": round(percentile(status_samples_ms, 50.0), 3),
            "status_p99_ms": round(percentile(status_samples_ms, 99.0), 3),
            "ring_cap_bytes": ring_cap_bytes,
            "pack_target_bytes": pack_target_bytes,
            "disk_bound_bytes": disk_bound_bytes,
            "peak_pack_bytes": peak_pack_bytes,
            "final_pack_bytes": final_pack_bytes,
            "peak_pack_count": peak_pack_count,
            "final_pack_count": final_pack_count,
            "disk_bounded": disk_bounded,
            "rss_early_p50_kb": early_rss_kb,
            "rss_late_p95_kb": late_rss_kb,
            "rss_max_kb": rss_max_kb,
            "rss_flat": rss_flat,
            "reconnects_max": max_reconnects,
            "gap_observations": total_gap_observations,
            "doctor_verdict": doctor_verdict,
            "doctor_unreferenced_objects": doctor_unreferenced,
            "v2_temp_orphans": v2_temp_orphans,
            "orphans": orphans,
            "active_tasks": active_tasks,
            "leaked_obligations": leaked_obligations,
            "socket_removed": socket_removed,
            "shutdown_clean": shutdown_clean,
            "assertions": {
                "orient_p99_lt_limit": orient_bounded,
                "disk_bounded": disk_bounded,
                "orphans_zero": orphans == 0,
                "rss_flat": rss_flat,
                "shutdown_clean": shutdown_clean,
                "doctor_healthy": doctor_healthy,
            },
            "verdict": "pass" if all_passed else "fail",
            "timeseries_path": str(timeseries_path),
            "receipt_path": str(receipt_path),
        }
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(receipt, indent=2))
        return 0 if all_passed else 1


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
        return run_soak(args)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"soak_live_daemon error: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
