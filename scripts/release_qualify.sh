#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
  cat <<'USAGE'
Usage: scripts/release_qualify.sh <release-preflight|build|verify|package|all>

Environment:
  FSS_RELEASE_VERSION   exact version label (default: workspace package version)
  FSS_TARGET_TRIPLE     native Rust target triple (default: host triple)
  FSS_RELEASE_ROOT      output root (default: qualification-artifacts/release)
  SOURCE_DATE_EPOCH     deterministic archive timestamp (default: source commit time)
USAGE
}

pinned_toolchain() {
  sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml
}

workspace_version() {
  python3 - <<'PY'
import tomllib
from pathlib import Path
root = tomllib.loads(Path("Cargo.toml").read_text(encoding="utf-8"))
print(root["workspace"]["package"]["version"])
PY
}

host_triple() {
  local toolchain="$1"
  rustup run "$toolchain" rustc -Vv | sed -n 's/^host: //p'
}

validate_component() {
  local label="$1" value="$2"
  case "$value" in
    ""|*[!A-Za-z0-9._+-]*)
      printf 'invalid %s: %s\n' "$label" "$value" >&2
      exit 2
      ;;
  esac
}

release_context() {
  TOOLCHAIN="$(pinned_toolchain)"
  [ -n "$TOOLCHAIN" ] || { printf '%s\n' 'cannot read pinned toolchain' >&2; exit 3; }
  command -v rustup >/dev/null 2>&1 || { printf '%s\n' 'rustup is unavailable' >&2; exit 3; }
  VERSION="${FSS_RELEASE_VERSION:-$(workspace_version)}"
  HOST_TARGET="$(host_triple "$TOOLCHAIN")"
  TARGET="${FSS_TARGET_TRIPLE:-${CARGO_BUILD_TARGET:-$HOST_TARGET}}"
  validate_component version "$VERSION"
  validate_component target "$TARGET"
  [ "$TARGET" = "$HOST_TARGET" ] || {
    printf 'release builds must be native: requested %s, host %s\n' "$TARGET" "$HOST_TARGET" >&2
    exit 3
  }
  RELEASE_ROOT="${FSS_RELEASE_ROOT:-qualification-artifacts/release}"
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
  case "$SOURCE_DATE_EPOCH" in
    ""|*[!0-9]*) printf 'invalid SOURCE_DATE_EPOCH: %s\n' "$SOURCE_DATE_EPOCH" >&2; exit 2 ;;
  esac
  STAGE_DIR="$RELEASE_ROOT/$VERSION/$TARGET/stage"
  ARTIFACT_DIR="$RELEASE_ROOT/$VERSION/$TARGET/artifacts"
  RECEIPT_DIR="$RELEASE_ROOT/$VERSION/$TARGET/receipts"
  export TOOLCHAIN VERSION HOST_TARGET TARGET RELEASE_ROOT SOURCE_DATE_EPOCH STAGE_DIR ARTIFACT_DIR RECEIPT_DIR
}

release_preflight() {
  release_context
  bash scripts/qualify.sh --lane policy
  python3 scripts/dependency_audit.py --require-metadata > /dev/null
  git diff --quiet
  git diff --cached --quiet
  [ -z "$(git status --porcelain --untracked-files=normal)" ] || {
    printf '%s\n' 'release preflight requires a clean source tree' >&2
    exit 5
  }
  git fsck --full
  test -f Cargo.lock
  test -f MANIFEST.sha256
  test -f MANIFEST.delta.sha256
  python3 scripts/check-policy.py --skip-manifest
  python3 scripts/manifest_audit.py
  python3 scripts/stable_id_audit.py > /dev/null
  rustup run "$TOOLCHAIN" cargo metadata --locked --offline --format-version 1 > /dev/null
}

build_release() {
  release_context
  bash scripts/qualify.sh --lane rust
  rm -rf "$STAGE_DIR" "$ARTIFACT_DIR" "$RECEIPT_DIR"
  mkdir -p "$STAGE_DIR" "$ARTIFACT_DIR" "$RECEIPT_DIR"

  rustup run "$TOOLCHAIN" cargo metadata --locked --offline --format-version 1 > "$RECEIPT_DIR/cargo-metadata.json"
  rustup run "$TOOLCHAIN" cargo build --release --workspace --locked --offline --target "$TARGET"

  local executable="fss"
  local source="target/$TARGET/release/$executable"
  case "$TARGET" in
    *windows*) source="$source.exe" ;;
  esac
  [ -f "$source" ] || { printf 'expected binary missing: %s\n' "$source" >&2; exit 6; }
  cp "$source" "$STAGE_DIR/$(basename "$source")"
  cp README.md LICENSE IMPLEMENTATION_STATUS.md MANIFEST.sha256 MANIFEST.delta.sha256 "$STAGE_DIR/"
  cp COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md FRANKENSTACK_DEEP_DIVE.md "$STAGE_DIR/"
  cp DEPENDENCY_CONSTITUTION.md GRAPH_ANALYTICS_AND_SENSOR_MESH.md "$STAGE_DIR/"
  cp ATP_AND_DISTRIBUTED_EVIDENCE.md PURE_RUST_MODEL_RUNTIME.md "$STAGE_DIR/"
  cp LOCAL_QUALIFICATION_AND_RELEASE.md "$STAGE_DIR/"
  mkdir -p "$STAGE_DIR/docs"
  cp docs/ONE_VERSION_UNIVERSE.md docs/MVCC_EVIDENCE_LEDGER.md "$STAGE_DIR/docs/"
  cp docs/STREAMING_AND_MEDIA_KERNEL.md docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md "$STAGE_DIR/docs/"
  cp docs/GRAPH_ALGORITHM_ATLAS.md docs/ATP_ARCHIVE_AND_REPLICATION.md "$STAGE_DIR/docs/"
  cp docs/LOCAL_QUALIFICATION_WITH_DSR.md docs/PLAN_ERRATA.md "$STAGE_DIR/docs/"

  "$STAGE_DIR/$(basename "$source")" --help > "$RECEIPT_DIR/smoke-help.txt" 2>&1
  "$STAGE_DIR/$(basename "$source")" capabilities --json > "$RECEIPT_DIR/capabilities.json"
  python3 scripts/manifest_audit.py > "$RECEIPT_DIR/repository-manifest-audit.txt"
  python3 - "$RECEIPT_DIR/build.json" <<'PY'
import hashlib, json, os, subprocess, sys
from pathlib import Path

def digest(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

manifest_root = None
for line in Path(os.path.join(os.environ["RECEIPT_DIR"], "repository-manifest-audit.txt")).read_text(encoding="utf-8").splitlines():
    if line.startswith("effectiveRoot="):
        manifest_root = line.split("=", 1)[1]
if not manifest_root or not manifest_root.startswith("sha256:"):
    raise SystemExit("effective repository manifest root missing")

receipt = {
    "schema": "fss.release_build_receipt.v1",
    "version": os.environ["VERSION"],
    "target": os.environ["TARGET"],
    "hostTarget": os.environ["HOST_TARGET"],
    "toolchain": os.environ["TOOLCHAIN"],
    "sourceCommit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "sourceDateEpoch": int(os.environ["SOURCE_DATE_EPOCH"]),
    "cargoLockSha256": digest("Cargo.lock"),
    "repositoryManifestBaseSha256": digest("MANIFEST.sha256"),
    "repositoryManifestDeltaSha256": digest("MANIFEST.delta.sha256"),
    "repositoryManifestEffectiveRoot": manifest_root,
    "cargoMetadataSha256": digest(os.path.join(os.environ["RECEIPT_DIR"], "cargo-metadata.json")),
    "smokeHelpSha256": digest(os.path.join(os.environ["RECEIPT_DIR"], "smoke-help.txt")),
    "capabilitiesSha256": digest(os.path.join(os.environ["RECEIPT_DIR"], "capabilities.json")),
    "claimBoundary": "design_skeleton",
}
Path(sys.argv[1]).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

verify_release() {
  release_context
  [ -d "$STAGE_DIR" ] || { printf 'stage directory missing: %s\n' "$STAGE_DIR" >&2; exit 7; }
  python3 scripts/release_artifacts.py verify \
    --version "$VERSION" --target "$TARGET" --stage "$STAGE_DIR" \
    --artifacts "$ARTIFACT_DIR" --receipts "$RECEIPT_DIR" \
    --source-date-epoch "$SOURCE_DATE_EPOCH"
}

package_release() {
  release_context
  [ -f "$RECEIPT_DIR/cargo-metadata.json" ] || {
    printf 'cargo metadata receipt missing: %s\n' "$RECEIPT_DIR/cargo-metadata.json" >&2
    exit 7
  }
  python3 scripts/release_artifacts.py package \
    --version "$VERSION" --target "$TARGET" --stage "$STAGE_DIR" \
    --artifacts "$ARTIFACT_DIR" --receipts "$RECEIPT_DIR" \
    --source-date-epoch "$SOURCE_DATE_EPOCH" \
    --metadata "$RECEIPT_DIR/cargo-metadata.json" \
    --source-commit "$(git rev-parse HEAD)"
}

run_all() {
  release_preflight
  build_release
  verify_release
  package_release
}

case "${1:-}" in
  release-preflight) release_preflight ;;
  build) build_release ;;
  verify) verify_release ;;
  package) package_release ;;
  all) run_all ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
