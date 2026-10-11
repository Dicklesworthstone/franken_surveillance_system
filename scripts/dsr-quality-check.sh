#!/usr/bin/env bash
# scripts/dsr-quality-check.sh — DSR-invoked qualification lane for FSS
# (bead fss-x4a.28.41 DSR-receipt evidence / QL-POLICY-001 transport).
#
# Runs the repository's own qualification entrypoint on the CURRENT tree and
# prints the receipt path + verdict. DSR's own snapshot discipline (clean
# clone on a controlled host) supplies the clean-source fence; this script
# is intentionally a thin transport to scripts/qualify.sh — all semantic
# authority stays in the lane, not in CI/DSR YAML (LOCAL_QUALIFICATION).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
bash scripts/qualify.sh policy
