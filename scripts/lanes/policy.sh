#!/usr/bin/env bash
# Policy qualification lane wrapper (includes Asupersync structured concurrency guard, fss-x4a.31.5.2).
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

python3 "$ROOT/scripts/asupersync_concurrency_guard.py" --self-test
python3 "$ROOT/scripts/asupersync_concurrency_guard.py"
python3 "$ROOT/scripts/check-policy.py" --skip-manifest
python3 "$ROOT/scripts/semantic_plane_checker.py"
python3 "$ROOT/scripts/lab_oracle_absence.py"
python3 "$ROOT/scripts/unsafe_prohibition_checker.py"
