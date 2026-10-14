#!/usr/bin/env bash
# Focused native supervision contracts; supplementary evidence, not release authority.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
channel=$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' rust-toolchain.toml)
[[ -n "$channel" ]] || { echo 'missing pinned toolchain' >&2; exit 1; }
evidence=${FSS_SUPERVISION_EVIDENCE_DIR:-$(mktemp -d)}
mkdir -p "$evidence" || exit 1
evidence=$(cd "$evidence" && pwd) || exit 1
status=0
run() {
  local name=$1; shift
  "$@" 2>&1 | tee "$evidence/$name.log" || status=1
}
git rev-parse HEAD > "$evidence/commit.txt" || exit 1
rustc +"$channel" --version --verbose > "$evidence/compiler.txt" || exit 1
run automatic cargo +"$channel" test --locked --offline -p fss-reference --lib rtsp::live_avc -- --nocapture
run avc-keepalive cargo +"$channel" test --locked --offline -p fss-reference --test automatic_avc_keepalive_contract --test rtsp_payload_selection_streaming -- --nocapture
run hevc cargo +"$channel" test --locked --offline -p fss-reference --test supervised_hevc_recording_contract --test live_hevc_recording_contract --test hevc_capture_contract --test hevc_recording_publication_contract -- --nocapture
sources=(
  crates/fss-reference/src/rtsp/avc_client.rs
  crates/fss-reference/src/rtsp/avc_client/authenticated.rs
  crates/fss-reference/tests/automatic_avc_keepalive_contract.rs
  crates/fss-reference/src/rtsp/live_avc/automatic/reconnect.rs
  crates/fss-reference/src/rtsp/live_avc/automatic/reconnect/hevc.rs
  crates/fss-reference/tests/supervised_hevc_recording_contract.rs
)
run formatting rustfmt +"$channel" --check --edition 2024 --config skip_children=true "${sources[@]}"
sha256sum "${sources[@]}" > "$evidence/sources.sha256" || status=1
# Suggestions are separate copies: compiler inputs are never modified by qualification.
for source in "${sources[@]}"; do
  mkdir -p "$evidence/formatted/$(dirname "$source")" || { status=1; continue; }
  cp "$source" "$evidence/formatted/$source" || { status=1; continue; }
  rustfmt +"$channel" --edition 2024 --config skip_children=true "$evidence/formatted/$source" || status=1
done
# Optional exact tracked-source/compiler capture for offline reproduction on the same host ABI.
# Neither archive reads credentials, environment secrets, runtime footage, nor untracked files.
if [[ ${FSS_SUPERVISION_OFFLINE_BUNDLE:-0} == 1 ]]; then
  git archive --format=tar.gz HEAD > "$evidence/source.tar.gz" || status=1
  sysroot=$(rustc +"$channel" --print sysroot) || exit 1
  tar -C "$sysroot" -czf "$evidence/compiler.tar.gz" bin lib || status=1
  (cd "$evidence" && sha256sum source.tar.gz compiler.tar.gz > offline.sha256) || status=1
fi
printf 'supervision evidence: %s\n' "$evidence"
exit "$status"
