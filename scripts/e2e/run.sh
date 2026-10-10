#!/usr/bin/env bash
# scripts/e2e/run.sh - the parent runner for CAP- e2e scripts (fss-2h5zq.1).
#
# Usage: scripts/e2e/run.sh <scripts/e2e/cap_*.sh | scripts/e2e/selftest.sh> [script args...]
#
# This is the supported way to run an e2e script, by hand, from qualify.sh and from any loop.
# The script runs as a CHILD process with FSS_E2E_LOG_DIR pointed at a fresh private directory
# (<log base>/runs/<UTC stamp>-XXXXXX, log base = FSS_E2E_LOG_DIR or target/e2e-logs). When it
# has finished, scripts/e2e/runner_verdict.py judges the run from the LOG it left: PASS only if
# the child exited 0, exactly one run log exists, it validates (validate_log.py), it ends with
# exactly one summary whose verdict is pass, and it holds no fail, harness or malformed record.
# Everything else is FAIL (exit 1). A cap script can tamper with its own shell (disarm the
# harness EXIT trap with `builtin trap - EXIT`, redefine `trap`, `exec` away) and exit 0, but it
# cannot turn a missing or failing summary into a pass here: the in-script protections in lib.sh
# are defense in depth, this runner is the verdict.
#
# Exit status: 0 PASS, 1 FAIL, 2 usage error. `--list` / `--help` are passed through and print
# "NO VERDICT"; they never count as a pass of the run (exit 3 when the child exited 0).
set -uo pipefail

RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${RUNNER_DIR}/../.." && pwd)"

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
    sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
fi

script="$1"
shift
if [[ ! -f "$script" || ! -r "$script" ]]; then
    echo "e2e runner: no readable script at '${script}'" >&2
    exit 2
fi

for arg in "$@"; do
    case "$arg" in
        --list|-h|--help)
            bash "$script" "$@"
            rc=$?
            echo "e2e runner: NO VERDICT for ${script} (${arg} does not run steps; child exit ${rc})" >&2
            if [[ $rc -eq 0 ]]; then
                exit 3
            fi
            exit "$rc"
            ;;
    esac
done

log_base="${FSS_E2E_LOG_DIR:-${REPO_ROOT}/target/e2e-logs}"
if ! mkdir -p "${log_base}/runs"; then
    echo "e2e runner: cannot create ${log_base}/runs (FAIL)" >&2
    exit 1
fi
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$(mktemp -d "${log_base}/runs/${stamp}-XXXXXX")" || {
    echo "e2e runner: cannot create a private run directory under ${log_base}/runs (FAIL)" >&2
    exit 1
}

echo "e2e runner: ${script} -> ${run_dir}" >&2
child_rc=0
# Every child runs under the supervisor: new process group, optional
# FSS_E2E_DEADLINE_S wall-clock budget, orphan reaping at exit, and a
# runner_supervision.json sidecar. A deadline kill or orphan leak can never
# become a PASS: the verdict still comes from the log the child left.
FSS_E2E_LOG_DIR="$run_dir" python3 "${RUNNER_DIR}/supervised_child.py" bash "$script" "$@" || child_rc=$?

verdict_rc=0
python3 "${RUNNER_DIR}/runner_verdict.py" --run-dir "$run_dir" --child-exit "$child_rc" \
    --script "$script" || verdict_rc=$?

if [[ $verdict_rc -eq 0 && $child_rc -eq 0 ]]; then
    echo "e2e runner: PASS ${script}" >&2
    exit 0
fi
echo "e2e runner: FAIL ${script} (child exit ${child_rc}, judge exit ${verdict_rc}; see ${run_dir}/runner_verdict.json)" >&2
echo "e2e runner: repro: scripts/e2e/run.sh ${script}${*:+ $*}" >&2
exit 1
