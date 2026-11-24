#!/usr/bin/env bash
# QL-SCALE-001 — Crash-Cut (SIGKILL) Recovery & 100-Camera / 1M-Commit Scale Benchmark Lane.
#
# Usage:
#   scripts/lanes/scale_benchmark.sh          # Full 1,000,000-commit / 100-camera / 56-SIGKILL campaign
#   scripts/lanes/scale_benchmark.sh --fast   # Fast smoke mode (100k commits + full 56-SIGKILL campaign)
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

FAST_MODE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast)
      FAST_MODE=1
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--fast]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

export RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fss-mac-target}"
export FSS_SCALE_LOG_DIR="${FSS_SCALE_LOG_DIR:-$ROOT/target/test-logs/scale-benchmark}"

if [[ "$FAST_MODE" -eq 1 ]]; then
  export FSS_SCALE_FAST=1
else
  unset FSS_SCALE_FAST || true
fi

TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then
  RUN=(rustup run "$TOOLCHAIN")
else
  RUN=()
fi

mkdir -p "$FSS_SCALE_LOG_DIR"

CMD1="${RUN[*]} cargo test --release --offline -p fss-projection-store --test scale_million_commit_benchmark -- --nocapture"
CMD2="${RUN[*]} cargo test --release --offline -p fss-projection-store --test scale_sigkill_e2e -- --nocapture"
CMD3="${RUN[*]} cargo test --release --offline -p fss-reference --test scale_migration_sigkill_e2e -- --nocapture"

echo "[QL-SCALE-001] Mode: $([[ "$FAST_MODE" -eq 1 ]] && echo fast || echo full)"
echo "[QL-SCALE-001] Artifacts dir: $FSS_SCALE_LOG_DIR"
echo "[QL-SCALE-001] Step 1/3: 100-camera / 1M-commit scale benchmark..."
"${RUN[@]}" cargo test --release --offline -p fss-projection-store \
  --test scale_million_commit_benchmark -- --nocapture

echo "[QL-SCALE-001] Step 2/3: 50-cut real OS SIGKILL crash-recovery campaign..."
"${RUN[@]}" cargo test --release --offline -p fss-projection-store \
  --test scale_sigkill_e2e -- --nocapture

echo "[QL-SCALE-001] Step 3/3: v1->v2 migration SIGKILL recovery & orient speedup..."
"${RUN[@]}" cargo test --release --offline -p fss-reference \
  --test scale_migration_sigkill_e2e -- --nocapture

echo "[QL-SCALE-001] Aggregating consolidated proof bundle..."
python3 - "$FSS_SCALE_LOG_DIR" "$FAST_MODE" "$CMD1" "$CMD2" "$CMD3" <<'PYEOF'
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

log_dir = Path(sys.argv[1])
fast_mode = sys.argv[2] == "1"
cmd1, cmd2, cmd3 = sys.argv[3], sys.argv[4], sys.argv[5]

def read_cmd(args):
    try:
        out = subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True).strip()
        return out
    except Exception:
        return "unknown"

scale_report = json.loads((log_dir / "scale_million_report.json").read_text(encoding="utf-8"))

sigkill_lines = [
    json.loads(line)
    for line in (log_dir / "sigkill_campaign.jsonl").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
sigkill_cuts = [r for r in sigkill_lines if r.get("record_type") == "cut"]
sigkill_summary = next((r for r in sigkill_lines if r.get("record_type") == "summary"), {})

mig_lines = [
    json.loads(line)
    for line in (log_dir / "migration_speedup.jsonl").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
mig_cuts = [r for r in mig_lines if r.get("record_type") == "sigkill_cut"]
mig_summary = next((r for r in mig_lines if r.get("record_type") == "speedup_summary"), {})

total_sigkill_cuts = len(sigkill_cuts) + len(mig_cuts)
sigkill_all_passed = (
    total_sigkill_cuts >= 55
    and all(
        c.get("killed_by_sigkill")
        and c.get("data_loss_count") == 0
        and c.get("partial_roots_count") == 0
        and c.get("orphan_files_after_recovery") == 0
        and c.get("scrubber_clean")
        and c.get("projection_equivalent")
        for c in sigkill_cuts
    )
    and all(
        c.get("killed_by_sigkill")
        and c.get("sentinel_present")
        and c.get("source_v1_untouched")
        for c in mig_cuts
    )
)

by_category = {}
for c in sigkill_cuts:
    cat = c["category"]
    by_category[cat] = by_category.get(cat, 0) + 1
by_category["migration_v1_to_v2"] = len(mig_cuts)

slo_gates = dict(scale_report.get("slo_gates", {}))
slo_gates["sigkill_campaign_ge_55_cuts_zero_loss"] = sigkill_all_passed
slo_gates["migration_equivalence_verified"] = bool(mig_summary.get("equivalence_verified"))
all_slos_pass = all(bool(v) for v in slo_gates.values())

platform_info = {
    "system": platform.system(),
    "release": platform.release(),
    "machine": platform.machine(),
    "uname": read_cmd(["uname", "-a"]),
    "cpu_brand": read_cmd(["sysctl", "-n", "machdep.cpu.brand_string"]),
    "cpu_count": os.cpu_count(),
    "mem_bytes": read_cmd(["sysctl", "-n", "hw.memsize"]),
}

consolidated = {
    "schema": "fss.scale_benchmark_report.v1",
    "lane_id": "QL-SCALE-001",
    "mode": "fast" if fast_mode else "full",
    "status": "PASS" if all_slos_pass else "FAIL",
    "platform": platform_info,
    "commands": [cmd1, cmd2, cmd3],
    "scale_benchmark": scale_report,
    "sigkill_campaign": {
        "total_sigkill_cuts": total_sigkill_cuts,
        "core_storage_cuts": len(sigkill_cuts),
        "migration_cuts": len(mig_cuts),
        "cuts_by_category": by_category,
        "data_loss_total": sigkill_summary.get("data_loss_total", 0),
        "partial_roots_total": sigkill_summary.get("partial_roots_total", 0),
        "orphans_total": sigkill_summary.get("orphans_total", 0),
        "all_scrubber_clean": sigkill_summary.get("all_scrubber_clean", False),
        "all_projection_equivalent": sigkill_summary.get("all_projection_equivalent", False),
    },
    "migration_benchmark": mig_summary,
    "slo_gates": slo_gates,
    "artifacts": {
        "consolidated_report": str(log_dir / "scale_benchmark_report.json"),
        "scale_million_report": str(log_dir / "scale_million_report.json"),
        "scale_timeseries_jsonl": str(log_dir / "scale_timeseries.jsonl"),
        "sigkill_campaign_jsonl": str(log_dir / "sigkill_campaign.jsonl"),
        "migration_speedup_jsonl": str(log_dir / "migration_speedup.jsonl"),
    },
}

out_path = log_dir / "scale_benchmark_report.json"
out_path.write_text(json.dumps(consolidated, indent=2) + "\n", encoding="utf-8")
print(f"[QL-SCALE-001] Wrote consolidated report: {out_path} (status={consolidated['status']}, sigkill_cuts={total_sigkill_cuts})")

if not all_slos_pass:
    failed = [k for k, v in slo_gates.items() if not v]
    print(f"[QL-SCALE-001] FAILED SLO gates: {failed}", file=sys.stderr)
    sys.exit(1)
PYEOF
