#!/usr/bin/env bash
# scripts/e2e/cap_inspect.sh
# End-to-end integration test runner for CAP- DOCTOR0 inspection (fss-2h5zq.67).
# Conforms to CAP- structured JSON-lines logging specification.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SUITE_NAME="cap_inspect"
BEAD_ID="fss-2h5zq.67"

# Parse arguments: support --list, --only <step>, --only=<step>
PASS_THROUGH_ARGS=()
LIST_MODE=0
ONLY_STEP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_MODE=1
            PASS_THROUGH_ARGS+=("$1")
            shift
            ;;
        --only)
            if [[ $# -lt 2 ]]; then
                echo "Error: --only requires a step argument" >&2
                exit 1
            fi
            ONLY_STEP="$2"
            PASS_THROUGH_ARGS+=("$1" "$2")
            shift 2
            ;;
        --only=*)
            ONLY_STEP="${1#--only=}"
            PASS_THROUGH_ARGS+=("$1")
            shift
            ;;
        *)
            PASS_THROUGH_ARGS+=("$1")
            shift
            ;;
    esac
done

TARGETS=(
    "fss-object:spool_inspect_contract"
    "fss-publication:local_inspect_contract"
    "fss-ledger:durable_inspect_contract"
    "fss-reference:effect_journal_inspect_contract"
)

if [[ $LIST_MODE -eq 1 ]]; then
    for item in "${TARGETS[@]}"; do
        echo "${item##*:}"
    done
    exit 0
fi

# If scripts/e2e/lib.sh is present (fss-2h5zq.1 harness), use the shared runner.
if [[ -f "${SCRIPT_DIR}/lib.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/lib.sh"

    # Targets for e2e filter:
    # e2e_step "spool_inspect_contract"
    # e2e_step "local_inspect_contract"
    # e2e_step "durable_inspect_contract"
    # e2e_step "effect_journal_inspect_contract"

    eval "$(declare -f _e2e_append_log | sed 's/_e2e_append_log/_real_e2e_append_log/')"
    _e2e_append_log() {
        local line="$1"
        local step_id="${2:-}"
        if [[ "$line" =~ \"verdict\":[[:space:]]*\"skip\" ]]; then
            _E2E_SKIPPED+=("{\"step\":\"${step_id}\",\"reason\":\"skipped\"}")
        fi
        _real_e2e_append_log "$@"
    }

    eval "$(declare -f e2e_summary | sed 's/e2e_summary/_real_e2e_summary/')"
    e2e_summary() {
        if [[ $_E2E_STEP_COUNT -gt 0 && $_E2E_STEP_COUNT -eq ${#_E2E_SKIPPED[@]} ]]; then
            _E2E_FAILURES+=("all_steps_skipped")
        fi
        local fail_cnt=${#_E2E_FAILURES[@]}
        local step_cnt=$_E2E_STEP_COUNT
        local skip_cnt=${#_E2E_SKIPPED[@]}
        local pass_cnt=$(( step_cnt - fail_cnt - skip_cnt ))
        if [[ $fail_cnt -eq 0 && $pass_cnt -gt 0 ]]; then
            echo "pass summary: ${step_cnt} steps passed, 0 failures"
        fi
        _real_e2e_summary "$@"
    }

    e2e_init "$SUITE_NAME" "$BEAD_ID" "${PASS_THROUGH_ARGS[@]}"
    for item in "${TARGETS[@]}"; do
        crate="${item%%:*}"
        target="${item##*:}"
        e2e_cargo_test "$crate" "$target"
    done
    e2e_summary
    exit 0
else
    echo "Error: lib.sh is required but not found (failing closed)" >&2
    exit 1
fi
