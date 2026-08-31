#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LANE="full"
RECEIPT_DIR="${FSS_RECEIPT_DIR:-}"
WRITE_RECEIPT=1

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/qualify.sh [--lane LANE] [--receipt-dir DIR] [--no-receipt]
       scripts/qualify.sh [policy|docs|rust|full|lab|adapter|media|archive|model|geometry|threat|privacy|release-preflight|release]

The repository-local qualifier is the semantic qualification entrypoint. Doodlestein
Self-Releaser executes it from clean, exact source/sibling snapshots on controlled native hosts.
Workflow YAML is a portable supplementary job graph and contains no unique release authority.

Implemented now: policy, docs, rust, full, release-preflight, release.
Claim-specific lanes fail closed until their dedicated Rust harness exists under scripts/lanes/.
USAGE
}

while (($#)); do
  case "$1" in
    --lane)
      LANE="${2:?missing lane after --lane}"
      shift 2
      ;;
    --receipt-dir)
      RECEIPT_DIR="${2:?missing directory after --receipt-dir}"
      shift 2
      ;;
    --no-receipt)
      WRITE_RECEIPT=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    policy|docs|rust|full|lab|adapter|media|archive|model|geometry|threat|privacy|release-preflight|release)
      LANE="$1"
      shift
      ;;
    *)
      printf 'unknown argument or lane: %s\n' "$1" >&2
      usage
      exit 4
      ;;
  esac
done

cd "$ROOT"
started_ns="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"
if [[ -z "$RECEIPT_DIR" ]]; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  RECEIPT_DIR="$ROOT/qualification-artifacts/local/${stamp}-${LANE}"
fi
mkdir -p "$RECEIPT_DIR"
records="$RECEIPT_DIR/commands.jsonl"
: > "$records"
final_status="passed"

append_record() {
  local id="$1" status="$2" digest="$3"
  shift 3
  python3 - "$records" "$id" "$status" "$digest" "$@" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
record = {
    "id": sys.argv[2],
    "status": sys.argv[3],
    "outputDigest": sys.argv[4],
    "argv": sys.argv[5:],
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, separators=(",", ":")) + "\n")
PY
}

run() {
  local id="$1"
  shift
  local log="$RECEIPT_DIR/${id}.log"
  printf '==> [%s]' "$id" >&2
  printf ' %q' "$@" >&2
  printf '\n' >&2
  set +e
  "$@" > >(tee "$log") 2> >(tee -a "$log" >&2)
  local rc=$?
  set -e
  local digest
  digest="sha256:$(python3 - "$log" <<'PY'
import hashlib
import pathlib
import sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
  if ((rc == 0)); then
    append_record "$id" passed "$digest" "$@"
  else
    append_record "$id" failed "$digest" "$@"
    final_status="failed"
    return "$rc"
  fi
}

pinned_toolchain() {
  python3 - <<'PY'
import pathlib
import tomllib
print(tomllib.loads(pathlib.Path("rust-toolchain.toml").read_text())["toolchain"]["channel"])
PY
}

policy_lane() {
  run policy python3 scripts/check-policy.py
  run dependency-audit python3 scripts/dependency_audit.py
  run diff-check git diff --check
  run shell-syntax bash -n scripts/qualify.sh scripts/release_qualify.sh scripts/publish_to_github.sh
  run python-syntax env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 -m py_compile \
    scripts/check-policy.py scripts/dependency_audit.py scripts/generate-manifest.py scripts/release_artifacts.py
}

docs_lane() {
  run docs-policy python3 scripts/check-policy.py
}

rust_lane() {
  local toolchain
  toolchain="$(pinned_toolchain)"
  run rustup-present bash -c 'command -v rustup >/dev/null 2>&1'
  run rustc-version rustup run "$toolchain" rustc -Vv
  run cargo-version rustup run "$toolchain" cargo -V
  run metadata rustup run "$toolchain" cargo metadata --locked --offline --format-version 1
  run fmt rustup run "$toolchain" cargo fmt --all --check
  run check rustup run "$toolchain" cargo check --locked --offline --workspace --all-targets
  run clippy rustup run "$toolchain" cargo clippy --locked --offline --workspace --all-targets -- -D warnings
  run test rustup run "$toolchain" cargo test --locked --offline --workspace --all-targets
}

claim_lane() {
  local script="$ROOT/scripts/lanes/${LANE}.sh"
  policy_lane
  if [[ ! -x "$script" ]]; then
    printf 'qualification lane %s is specified but not implemented: %s is absent\n' "$LANE" "$script" >&2
    final_status="failed"
    return 2
  fi
  run "$LANE" "$script"
}

clean_tree_lane() {
  run git-clean bash -c 'test -z "$(git status --porcelain --untracked-files=all)"'
  run lock-present test -f Cargo.lock
}

finalize() {
  local rc=$?
  trap - EXIT
  set +e
  ((rc == 0)) || final_status="failed"
  local finished_ns source_commit source_tree sibling_digest host_digest toolchain target
  finished_ns="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"
  source_commit="git:$(git rev-parse HEAD 2>/dev/null || printf unknown00000000)"
  source_tree="git-tree:$(git rev-parse HEAD^{tree} 2>/dev/null || printf unknown00000000)"
  if [[ -n "${FSS_DSR_SIBLING_CLOSURE_DIGEST:-}" ]]; then
    sibling_digest="$FSS_DSR_SIBLING_CLOSURE_DIGEST"
  else
    sibling_digest="sha256:$(python3 - <<'PY'
import hashlib
import pathlib
parts=[]
for name in ["architecture/franken_imports.json", "architecture/dependency_allowlist.toml", "rust-toolchain.toml"]:
    path=pathlib.Path(name)
    parts.append(name.encode()+b"\0"+path.read_bytes())
print(hashlib.sha256(b"\0".join(parts)).hexdigest())
PY
)"
  fi
  host_digest="sha256:$(python3 - <<'PY'
import hashlib
import os
import platform
value="|".join([platform.node(), platform.platform(), platform.machine(), os.environ.get("FSS_DSR_HOST_ID", "")])
print(hashlib.sha256(value.encode()).hexdigest())
PY
)"
  toolchain="$(pinned_toolchain 2>/dev/null || printf unavailable)"
  target="${FSS_TARGET_TRIPLE:-${CARGO_BUILD_TARGET:-$(uname -s 2>/dev/null || printf unknown)-$(uname -m 2>/dev/null || printf unknown)}}"

  if ((WRITE_RECEIPT)); then
    python3 - "$RECEIPT_DIR/qualification-receipt.json" "$records" "$LANE" "$source_commit" "$source_tree" "$sibling_digest" "$host_digest" "$toolchain" "$target" "$started_ns" "$finished_ns" "$final_status" <<'PY'
import hashlib
import json
import pathlib
import sys
(
    output_path,
    records_path,
    lane,
    source_commit,
    source_tree,
    sibling_digest,
    host_digest,
    toolchain,
    target,
    started,
    finished,
    status,
) = sys.argv[1:]
lane_ids = {
    "policy": "QL-POLICY-001",
    "docs": "QL-POLICY-001",
    "rust": "QL-RUST-001",
    "full": "QL-RUST-001",
    "lab": "QL-LAB-001",
    "adapter": "QL-ADAPTER-001",
    "media": "QL-MEDIA-001",
    "archive": "QL-ARCHIVE-001",
    "model": "QL-MODEL-001",
    "geometry": "QL-GEOMETRY-001",
    "threat": "QL-THREAT-001",
    "privacy": "QL-PRIVACY-001",
    "release-preflight": "QL-RELEASE-001",
    "release": "QL-RELEASE-001",
}
commands=[]
for line in pathlib.Path(records_path).read_text(encoding="utf-8").splitlines():
    row=json.loads(line)
    commands.append({"argv": row["argv"], "status": row["status"], "outputDigest": row["outputDigest"]})
if not commands:
    commands=[{"argv":["scripts/qualify.sh","--lane",lane],"status":"failed","outputDigest":"sha256:"+hashlib.sha256(b"no-command-record").hexdigest()}]
lock=pathlib.Path("Cargo.lock")
receipt={
    "schema":"fss.release_qualification_receipt.v1",
    "receiptId":f"local:{lane}:{source_commit.split(':',1)[-1][:16]}",
    "laneId":lane_ids[lane],
    "sourceCommit":source_commit,
    "sourceTree":source_tree,
    "siblingClosureDigest":sibling_digest,
    "cargoLockDigest":"sha256:"+hashlib.sha256(lock.read_bytes()).hexdigest() if lock.exists() else None,
    "toolchain":toolchain[:256],
    "hostIdentity":host_digest,
    "target":target[:256],
    "features":[],
    "commands":commands,
    "artifactManifestDigest":None,
    "startedAt":{"earliestNs":int(started),"latestNs":int(started),"clockBasis":"host-realtime"},
    "finishedAt":{"earliestNs":int(finished),"latestNs":int(finished),"clockBasis":"host-realtime"},
    "status":status,
}
pathlib.Path(output_path).write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf-8")
PY
    printf 'qualification receipt: %s\n' "$RECEIPT_DIR/qualification-receipt.json" >&2
  fi
  exit "$rc"
}
trap finalize EXIT

case "$LANE" in
  policy)
    policy_lane
    ;;
  docs)
    docs_lane
    ;;
  rust)
    policy_lane
    rust_lane
    ;;
  full)
    policy_lane
    rust_lane
    ;;
  lab|adapter|media|archive|model|geometry|threat|privacy)
    claim_lane
    ;;
  release-preflight)
    policy_lane
    clean_tree_lane
    rust_lane
    ;;
  release)
    policy_lane
    rust_lane
    clean_tree_lane
    ;;
  *)
    printf 'unknown qualification lane: %s\n' "$LANE" >&2
    exit 4
    ;;
esac
printf 'qualification lane %s completed\n' "$LANE" >&2
