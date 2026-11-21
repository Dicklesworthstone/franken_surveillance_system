#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_geometry_visibility.sh"
e2e_init "geometry_visibility" "fss-2h5zq.54" "$@"
export FSS_EXPECTED_ROSTER="open_yard,half_wall,translated_wall,moved_wall,facing_away,wall_ray_budget,retained_open_sensor:vis-mesh-east,retained_open_sensor:vis-mesh-west,retained_occluded_sensor:vis-mesh-east,retained_occluded_sensor:vis-mesh-west"
e2e_cargo_test "fss-reference" "ground_visibility_coverage_contract"
e2e_summary
