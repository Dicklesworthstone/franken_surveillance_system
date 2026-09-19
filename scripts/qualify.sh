#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Sealed-offline qualification (fss-x4a.26.3, DEP-AUD-027): every cargo process started below,
# including the `cargo metadata` cargo-fmt runs internally, inherits Cargo's offline mode, and
# every cargo invocation also passes --offline. This seals Cargo resolution only; it is not
# OS-level network isolation (no network namespace / `unshare -n` is used).
export CARGO_NET_OFFLINE=true
# rustup must not fetch a missing pinned toolchain either (DEP-AUD-027); RUSTUP_AUTO_INSTALL=0 was
# observed honoured by rustup 1.29.1. `rustup run` without --install does not install regardless.
export RUSTUP_AUTO_INSTALL=0
# OS-level network seal (fss-x4a.26.3, FSS-183): when `unshare -n` works, every lane step runs
# inside a network namespace whose only interface is down loopback, so build scripts, tests, and
# doc tooling cannot reach the network even by accident - stronger than the Cargo/rustup env
# seals above, which remain in force as defense in depth. When the namespace primitive is
# unavailable the run degrades to the env-only seal and the netseal step records that in the
# receipt; FSS_SEAL_NETWORK=required upgrades the degraded path to a hard failure (controlled
# DSR hosts must provide unshare).
SEAL_MODE="namespace"
if ! command -v unshare >/dev/null 2>&1 || ! unshare -n true 2>/dev/null; then
  SEAL_MODE="unavailable"
fi
if [[ "$SEAL_MODE" == "unavailable" && "${FSS_SEAL_NETWORK:-auto}" == "required" ]]; then
  printf 'FSS_SEAL_NETWORK=required but unshare -n is unavailable; refusing to run unsealed\n' >&2
  exit 5
fi
export QUALIFY_SEAL_MODE="$SEAL_MODE"
# Hermetic environment (fss-n4xr9): strip toolchain-injection variables at run time so a caller
# cannot smuggle -Z features, a different toolchain, or build-behavior flags into the lanes past
# the static text checks. The scrub deny-list is prefix-aware (CARGO_UNSTABLE_*, RUSTDOC_*) and
# keeps everything the lanes legitimately need (PATH, HOME, CARGO_HOME, RUSTUP_HOME,
# CARGO_NET_OFFLINE, RUSTUP_AUTO_INSTALL, QUALIFY_SEAL_MODE, FSS_*).
SCRUB_DENY_PREFIXES=("CARGO_UNSTABLE_" "RUSTDOC_")
SCRUB_DENY_EXACT=(
  RUSTUP_TOOLCHAIN RUSTFLAGS RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
  RUSTC_BOOTSTRAP RUST_MIN_STACK CARGO CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR
)
SCRUB_FLAGS=()
SCRUBBED_LIST=""
while IFS='=' read -r var _; do
  scrub_it=0
  for exact in "${SCRUB_DENY_EXACT[@]}"; do
    [[ "$var" == "$exact" ]] && { scrub_it=1; break; }
  done
  if ((scrub_it == 0)); then
    for prefix in "${SCRUB_DENY_PREFIXES[@]}"; do
      [[ "$var" == "$prefix"* ]] && { scrub_it=1; break; }
    done
  fi
  if ((scrub_it == 1)); then
    SCRUB_FLAGS+=(-u "$var")
    SCRUBBED_LIST+="$var "
  fi
done < <(env)
if ((${#SCRUB_FLAGS[@]} > 0)); then
  printf 'hermetic env scrub: unsetting %s\n' "$SCRUBBED_LIST" >&2
fi
# rustc flag-recording wrapper (fss-x4a.26.3, FSS-183): a PATH-prepended rustc shim
# refuses -Z at the point of injection and records every invocation for audit.
# The shim execs the real rustc (resolved before PATH modification). PATH-only:
# RUSTC is not overridden, so the toolchain-identity check remains satisfied.
REAL_RUSTC="$(command -v rustc 2>/dev/null || printf '')"
if [[ -z "$REAL_RUSTC" ]]; then
  printf 'rustc not found on PATH; cannot install the sealed rustc wrapper\n' >&2
  exit 5
fi
RUSTC_WRAPPER_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fss-rustc-seal.XXXXXX")"
FSS_RUSTC_LOG="$(mktemp "${TMPDIR:-/tmp}/fss-rustc-log.XXXXXX")"
export FSS_RUSTC_LOG
{
  echo '#!/usr/bin/env bash'
  echo 'set -Eu'
  echo 'for arg in "$@"; do'
  echo '  if [[ "$arg" == "-Z" || "$arg" == "-Z"* ]]; then'
  echo '    printf "FSS-RUSTC-SEAL: refused -Z flag in sealed qualification: %s\n" "$arg" >&2'
  echo '    exit 101'
  echo '  fi'
  echo 'done'
  echo 'if [[ -n "${FSS_RUSTC_LOG:-}" ]]; then'
  echo '  printf "rustc %s\n" "$*" >> "${FSS_RUSTC_LOG}"'
  echo 'fi'
  echo "exec '${REAL_RUSTC}' \"\$@\""
} > "$RUSTC_WRAPPER_DIR/rustc"
chmod +x "$RUSTC_WRAPPER_DIR/rustc"
export PATH="$RUSTC_WRAPPER_DIR:$PATH"
LANE="full"
RECEIPT_DIR="${FSS_RECEIPT_DIR:-}"
WRITE_RECEIPT=1

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/qualify.sh [--lane LANE] [--receipt-dir DIR] [--no-receipt]
       scripts/qualify.sh [policy|docs|rust|full|lab|adapter|media|archive|model|geometry|threat|agent|privacy|release-preflight|release]

The repository-local qualifier is the semantic qualification entrypoint. Doodlestein
Self-Releaser executes it from clean, exact source/sibling snapshots on controlled native hosts.
Workflow YAML is a portable supplementary job graph and contains no unique release authority.

Implemented now: policy, docs, rust, full, release-preflight, release.
Claim-specific lanes fail closed until their dedicated Rust harness exists under scripts/lanes/.
USAGE
}

while (($#)); do
  case "$1" in
    --lane) LANE="${2:?missing lane after --lane}"; shift 2 ;;
    --receipt-dir) RECEIPT_DIR="${2:?missing directory after --receipt-dir}"; shift 2 ;;
    --no-receipt) WRITE_RECEIPT=0; shift ;;
    -h|--help) usage; exit 0 ;;
    policy|docs|rust|full|lab|adapter|media|archive|model|geometry|threat|agent|privacy|release-preflight|release)
      LANE="$1"; shift ;;
    *) printf 'unknown argument or lane: %s\n' "$1" >&2; usage; exit 4 ;;
  esac
done

cd "$ROOT"
started_ns="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"
# Every run owns a fresh directory and an exclusively created commands.jsonl: same-second runs of
# the same lane get distinct directories, and an explicit directory that already holds another
# run's log is refused (exit 4) instead of truncated.
if [[ -z "$RECEIPT_DIR" ]]; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --unique "$ROOT/qualification-artifacts/local/${stamp}-${LANE}")" || exit $?
else
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --exact "$RECEIPT_DIR")" || exit $?
fi
records="$RECEIPT_DIR/commands.jsonl"
final_status="passed"

append_record() {
  local id="$1" status="$2" digest="$3"
  shift 3
  python3 - "$records" "$id" "$status" "$digest" "$@" <<'PY'
import json
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
record = {"id": sys.argv[2], "status": sys.argv[3], "outputDigest": sys.argv[4], "argv": sys.argv[5:]}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, separators=(",", ":")) + "\n")
    handle.flush()
    os.fsync(handle.fileno())
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
  if declare -f "$1" > /dev/null 2>&1; then
    # Shell function: inherits the script's environment (exports at the top
    # provide the seals). No env(1) scrub needed — the function's own
    # external-command invocations go through run() and get scrubbed there.
    if [[ "$SEAL_MODE" == "namespace" ]]; then
      unshare -n "$@"
    else
      "$@"
    fi
  elif [[ "$SEAL_MODE" == "namespace" ]]; then
    env "${SCRUB_FLAGS[@]}" unshare -n "$@" > >(tee "$log") 2> >(tee -a "$log" >&2)
  else
    env "${SCRUB_FLAGS[@]}" "$@" > >(tee "$log") 2> >(tee -a "$log" >&2)
  fi
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

semantic_plane_doctest_map() {
  python3 - docs/enforcement/three_semantic_planes_contract.md <<'PY'
"""Verifies the ADR-0001 contract doc maps every invariant to a real fss doctest or test."""
import pathlib
import re
import sys

doc_path = pathlib.Path(sys.argv[1])
doc = doc_path.read_text(encoding="utf-8")
errors = []

for line_no, line in enumerate(doc.splitlines(), start=1):
    stripped = line.strip()
    if stripped.startswith("```") or stripped.startswith("~~~"):
        info = stripped[3:].strip()
        if info != "text":
            errors.append(f"{doc_path}:{line_no}: code fence {stripped!r} would be an untested rustdoc block")

invariants = set(re.findall(r"^## Invariant (\d+):", doc, re.MULTILINE))
if not invariants:
    errors.append(f"{doc_path}: no '## Invariant N:' sections found")

row_re = re.compile(
    r"^\|\s*(?P<inv>[^|`]+?)\s*\|\s*`(?P<kind>[^`]+)`\s*\|\s*`(?P<path>[^`]+)`\s*\|"
    r"\s*`(?P<item>[^`]+)`\s*\|\s*`(?P<marker>[^`]+)`\s*\|\s*$",
    re.MULTILINE,
)
rows = [m.groupdict() for m in row_re.finditer(doc)]
mapped = {row["inv"] for row in rows}
for inv in sorted(invariants - mapped):
    errors.append(f"{doc_path}: Invariant {inv} has no enforcement row")
for inv in sorted(mapped - invariants - {"legal-path"}):
    errors.append(f"{doc_path}: enforcement row names unknown invariant {inv!r}")
if not any(row["inv"] == "legal-path" and row["kind"] == "doctest" for row in rows):
    errors.append(f"{doc_path}: no compiling legal-path doctest row")


def attached_doc_blocks(lines, item):
    decl = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:struct|enum|fn|type|trait|mod)\s+" + re.escape(item) + r"\b")
    for index, line in enumerate(lines):
        if not decl.match(line):
            continue
        start = index
        while start > 0 and lines[start - 1].lstrip().startswith(("///", "#[")):
            start -= 1
        docs = [l.lstrip()[3:] for l in lines[start:index] if l.lstrip().startswith("///")]
        docs = [d[1:] if d.startswith(" ") else d for d in docs]
        blocks, info, body = [], None, []
        for text in docs:
            if text.strip().startswith("```"):
                if info is None:
                    info, body = text.strip()[3:].strip(), []
                else:
                    blocks.append((info, "\n".join(body)))
                    info = None
            elif info is not None:
                body.append(text)
        yield blocks


markers_seen = set()
for row in rows:
    path = pathlib.Path(row["path"])
    label = f"Invariant {row['inv']} ({row['marker']})"
    if row["marker"] in markers_seen:
        errors.append(f"{label}: marker listed twice")
    markers_seen.add(row["marker"])
    if not path.is_file():
        errors.append(f"{label}: {path} does not exist")
        continue
    lines = path.read_text(encoding="utf-8").splitlines()
    if row["kind"] == "test":
        if not re.search(r"#\[test\]\s*\n\s*fn\s+" + re.escape(row["item"]) + r"\s*\(", "\n".join(lines)):
            errors.append(f"{label}: no #[test] fn {row['item']} in {path}")
        continue
    if row["kind"] == "doctest":
        ok_kind = lambda info: info in ("", "rust")
    elif re.fullmatch(r"compile_fail,E\d{4}", row["kind"]):
        ok_kind = lambda info, kind=row["kind"]: info == kind
    else:
        errors.append(f"{label}: unsupported kind {row['kind']!r}")
        continue
    found = False
    any_item = False
    for blocks in attached_doc_blocks(lines, row["item"]):
        any_item = True
        for info, body in blocks:
            if ok_kind(info) and re.search(r"//\s*" + re.escape(row["marker"]) + r"\b", body):
                if "fss_core::" not in body and "fss_reference::" not in body:
                    errors.append(f"{label}: doctest does not exercise real fss types")
                found = True
    if not any_item:
        errors.append(f"{label}: item {row['item']} not declared in {path}")
    elif not found:
        errors.append(f"{label}: no `{row['kind']}` doctest carrying the marker is attached to {row['item']} in {path}")

if errors:
    for error in errors:
        print(f"[FAIL] {error}")
    sys.exit(1)
print(f"[PASS] ADR-0001 contract maps {len(invariants)} invariants to {len(rows)} real doctest/test rows")
PY
}

policy_lane() {
  run policy python3 scripts/check-policy.py --skip-manifest
  run schema-validate python3 scripts/schema_validate.py
  run slo-validate python3 scripts/slo_validate.py
  run architecture-registry-consistency python3 scripts/architecture_registry_consistency.py
  run manifest-audit python3 scripts/manifest_audit.py
  run stable-id-audit python3 scripts/stable_id_audit.py
  run seed-requirements python3 scripts/seed_requirement_checker.py
  run dependency-audit python3 scripts/dependency_audit.py
  run schema-validate-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_schema_validate.py
  run slo-validate-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_slo_validate.py
  run slo-cost-consistency-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_slo_operation_cost_consistency.py
  run architecture-registry-consistency-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_architecture_registry_consistency.py
  run manifest-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_manifest_audit.py
  run stable-id-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_stable_id_audit.py
  run seed-requirements-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_seed_requirement_checker.py
  run dependency-dag-checker python3 scripts/dependency_dag_checker.py
  run dependency-dag-checker-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_dependency_dag_checker.py
  run claim-proof-bundle-checker python3 scripts/claim_proof_bundle_checker.py
  run claim-proof-bundle-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_claim_proof_bundle_checker.py
  run unsafe-prohibition-checker python3 scripts/unsafe_prohibition_checker.py
  run unsafe-prohibition-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_unsafe_prohibition_checker.py
  run dependency-closure-scanner python3 scripts/dependency_closure_scanner.py --allow-unresolved-runtime
  run dependency-closure-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_dependency_closure_scanner.py
  run semantic-plane-checker python3 scripts/semantic_plane_checker.py
  run semantic-plane-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_semantic_plane_checker.py
  run semantic-plane-doctests semantic_plane_doctest_map
  run standards-first-adapter-checker python3 scripts/standards_first_adapter_checker.py
  run standards-first-adapter-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_standards_first_adapter_checker.py
  run release-artifact-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_release_artifacts.py
  run robot-docs python3 scripts/robot_docs_checker.py
  run robot-docs-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_robot_docs.py
  run diff-check git diff --check
  run shell-syntax bash -n scripts/qualify.sh scripts/release_qualify.sh scripts/publish_to_github.sh
  run python-syntax env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 -m py_compile \
    scripts/check-policy.py scripts/dependency_audit.py scripts/manifest_audit.py scripts/stable_id_audit.py \
    scripts/schema_validate.py scripts/slo_validate.py scripts/architecture_registry_consistency.py \
    scripts/dependency_dag_checker.py scripts/claim_proof_bundle_checker.py scripts/unsafe_prohibition_checker.py \
    scripts/dependency_closure_scanner.py scripts/semantic_plane_checker.py scripts/qualification_receipt.py \
    scripts/standards_first_adapter_checker.py scripts/generate_robot_docs.py scripts/robot_docs_checker.py \
    scripts/generate-manifest.py scripts/release_artifacts.py \
    tests/test_manifest_audit.py tests/test_stable_id_audit.py tests/test_release_artifacts.py \
    tests/test_schema_validate.py tests/test_slo_validate.py tests/test_slo_operation_cost_consistency.py \
    tests/test_architecture_registry_consistency.py tests/test_dependency_dag_checker.py \
    tests/test_claim_proof_bundle_checker.py tests/test_unsafe_prohibition_checker.py \
    tests/test_dependency_closure_scanner.py tests/test_semantic_plane_checker.py \
    tests/test_standards_first_adapter_checker.py tests/test_robot_docs.py
}

docs_lane() {
  run docs-policy python3 scripts/check-policy.py --skip-manifest
  run docs-slo-validate python3 scripts/slo_validate.py
  run docs-manifest-audit python3 scripts/manifest_audit.py
  run docs-stable-id-audit python3 scripts/stable_id_audit.py
  run docs-robot-docs python3 scripts/robot_docs_checker.py
  run docs-robot-docs-tests env PYTHONPYCACHEPREFIX="$RECEIPT_DIR/pycache" python3 tests/test_robot_docs.py
}

rust_lane() {
  local toolchain
  toolchain="$(pinned_toolchain)"
  run rustup-present bash -c 'command -v rustup >/dev/null 2>&1'
  run rustc-version rustup run "$toolchain" rustc -Vv
  run cargo-version rustup run "$toolchain" cargo --offline -V
  run metadata rustup run "$toolchain" cargo metadata --locked --offline --format-version 1
  run fmt rustup run "$toolchain" cargo --offline fmt --all --check
  run check rustup run "$toolchain" cargo check --locked --offline --workspace --all-targets
  run clippy rustup run "$toolchain" cargo clippy --locked --offline --workspace --all-targets -- -D warnings
  run test rustup run "$toolchain" cargo test --locked --offline --workspace --all-targets
  run doctest rustup run "$toolchain" cargo test --locked --offline --workspace --doc
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
  local finished_ns source_commit source_tree sibling_digest host_digest toolchain target manifest_root
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
  manifest_root="$(python3 scripts/manifest_audit.py 2>/dev/null | sed -n 's/^effectiveRoot=//p' | head -1)"
  [[ -n "$manifest_root" ]] || manifest_root="unavailable"

  if ((WRITE_RECEIPT)); then
    local receipt_path="$RECEIPT_DIR/qualification-receipt.json" receipt_status writer_rc
    receipt_status="$(python3 "$ROOT/scripts/qualification_receipt.py" finalize \
      --output "$receipt_path" --records "$records" --lane "$LANE" \
      --source-commit "$source_commit" --source-tree "$source_tree" \
      --sibling-digest "$sibling_digest" --host-digest "$host_digest" \
      --toolchain "$toolchain" --target "$target" \
      --started-ns "$started_ns" --finished-ns "$finished_ns" \
      --status "$final_status" --manifest-root "$manifest_root" \
      --cargo-lock "$ROOT/Cargo.lock")"
    writer_rc=$?
    if ((writer_rc == 0)) && [[ -f "$receipt_path" ]]; then
      printf 'qualification receipt: %s\n' "$receipt_path" >&2
      # A malformed command record downgrades the receipt; the run must not exit 0 behind it.
      [[ "$receipt_status" == passed ]] || ((rc != 0)) || rc=1
    else
      printf 'qualification receipt NOT written (writer exit %s): %s\n' "$writer_rc" "$receipt_path" >&2
      ((rc != 0)) || rc=1
    fi
  fi
  exit "$rc"
}
trap finalize EXIT

run netseal python3 "$ROOT/scripts/netseal_selftest.py"

case "$LANE" in
  policy) policy_lane ;;
  docs) docs_lane ;;
  rust) policy_lane; rust_lane ;;
  full) policy_lane; rust_lane ;;
  lab|adapter|media|archive|model|geometry|threat|agent|privacy) claim_lane ;;
  release-preflight) policy_lane; clean_tree_lane; rust_lane ;;
  release) policy_lane; rust_lane; clean_tree_lane ;;
  *) printf 'unknown qualification lane: %s\n' "$LANE" >&2; exit 4 ;;
esac
printf 'qualification lane %s completed\n' "$LANE" >&2
