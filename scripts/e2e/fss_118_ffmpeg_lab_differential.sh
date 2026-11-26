#!/usr/bin/env bash
# FSS-118 (`fss-x4a.12.17`) E2E verification: sealed lab-only FFmpeg/ffprobe media differential
# runner (build shipped fss-probe, run 10-case positive+negative differential against ffprobe/ffmpeg,
# verify self-signed canonical receipt, verify exit 5 fail-closed missing-tool behavior, and run
# production-absence proofs lab_oracle_absence.py + foreign_model_runtime_absence.py).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_118_ffmpeg_lab_differential.sh"

e2e_init "fss_118_ffmpeg_lab_differential" "fss-x4a.12.17" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

DIFF_OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fss-118-e2e.XXXXXX")"

e2e_step "build_fss_probe_offline" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline build --locked -q -p fss-cli --bin fss-probe
e2e_expect_exit "build_fss_probe_offline" 0

e2e_step "run_ffmpeg_lab_differential" -- \
  python3 "${ROOT}/scripts/lab/ffmpeg_media_differential.py" --output-dir "${DIFF_OUT_DIR}"
e2e_expect_exit "run_ffmpeg_lab_differential" 0

e2e_step "verify_ffmpeg_differential_receipt" -- \
  python3 "${ROOT}/scripts/lab/ffmpeg_media_differential.py" --verify-receipt "${DIFF_OUT_DIR}/ffmpeg-differential-receipt.json"
e2e_expect_exit "verify_ffmpeg_differential_receipt" 0

e2e_step "verify_missing_tool_fails_closed" -- \
  python3 "${ROOT}/scripts/lab/ffmpeg_media_differential.py" --output-dir "${DIFF_OUT_DIR}/missing" --simulate-missing-tool
e2e_expect_exit "verify_missing_tool_fails_closed" 5

e2e_step "fss_118_unit_and_negative_controls" -- \
  python3 -m unittest "${ROOT}/tests/test_fss_118_ffmpeg_lab_differential.py"
e2e_expect_exit "fss_118_unit_and_negative_controls" 0

e2e_step "verify_lab_oracle_production_absence" -- \
  python3 "${ROOT}/scripts/lab_oracle_absence.py"
e2e_expect_exit "verify_lab_oracle_production_absence" 0

e2e_step "verify_foreign_model_runtime_absence" -- \
  python3 "${ROOT}/scripts/foreign_model_runtime_absence.py"
e2e_expect_exit "verify_foreign_model_runtime_absence" 0

e2e_summary
