#!/usr/bin/env bash
# Supplementary native contracts; never a replacement for scripts/qualify.sh.
set -uo pipefail
cd "$(dirname "$0")/.."
evidence=${1:?supply an evidence output directory}
mkdir -p "$evidence/formatted"
git rev-parse HEAD > "$evidence/commit.txt"
# Retain exact public inputs alongside failures so a disconnected editor can reproduce the tree.
tar -czf "$evidence/source-context.tar.gz" AGENTS.md COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md .beads/issues.jsonl crates/fss-cli/src/bin/fss-file.rs crates/fss-cli/src/bin/fss-file crates/fss-cli/tests/file* crates/fss-cli/tests/video_publication_cli.rs crates/fss-cli/tests/video_selection_cli.rs
status=0
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --test file_video_stream_core -- --nocapture 2>&1 | tee "$evidence/core.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --bin fss-file 2>&1 | tee "$evidence/cli-unit.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --test file_video_stream_cli --test file_cli_contract --test rtsp_import_cli --test capture_rtsp_index_cli 2>&1 | tee "$evidence/process.log" || status=1
for source in crates/fss-cli/src/bin/fss-file/pgm_stream.rs crates/fss-cli/tests/file_video_stream_core.rs crates/fss-cli/tests/file_video_stream_cli.rs crates/fss-cli/src/bin/fss-file/media.rs crates/fss-cli/src/bin/fss-file.rs; do
  rustfmt +nightly-2026-08-31 --edition 2024 --config skip_children=true --emit stdout "$source" > "$evidence/formatted/$(basename "$source")" || status=1
done
exit "$status"
