#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-115 (`fss-x4a.12.14`: deterministic fragmented MP4/CMAF writer
# and reader). Executes AVC/HEVC fragmented MP4 mux/demux round-trips, independent golden layout
# oracle checks, explicit timeline/source-span preservation, bounds/refusal transitivity, and
# malformed media/demux gauntlets.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "fss_115_fragmented_mp4_cmaf_contract"
  echo "avc_mux_contract"
  echo "hevc_remux_contract"
  echo "implicit_fragment_contract"
  echo "inband_mp4"
  echo "mixed_mp4"
  echo "movie_output_contract"
  echo "movie_timing_contract"
  echo "demux_malformed_gauntlet"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  --offline \
  -p fss-container \
  --test fss_115_fragmented_mp4_cmaf_contract \
  --test avc_mux_contract \
  --test hevc_remux_contract \
  --test implicit_fragment_contract \
  --test inband_mp4 \
  --test mixed_mp4 \
  --test movie_output_contract \
  --test movie_timing_contract \
  --test demux_malformed_gauntlet \
  -- --nocapture "$@"
