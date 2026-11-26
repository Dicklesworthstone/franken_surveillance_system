#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-035 (`fss-x4a.9.5`: backup/restore manifest).
# Exercises exact local recovery through real journals, held/deleted originals, root-last
# MANIFEST publication, irreversible restore-fence enforcement, cancellation boundaries,
# exact authority revocation, tamper refusal, agent profile isolation, and CLI workflows.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "fss-reference::deployment_backup_contract"
  echo "fss-cli::deployment_backup_cli"
  exit 0
fi

cd "${ROOT_DIR}"
cargo test --locked --offline -p fss-reference --test deployment_backup_contract -- --nocapture "$@"
exec cargo test --locked --offline -p fss-cli --test deployment_backup_cli -- --nocapture "$@"
