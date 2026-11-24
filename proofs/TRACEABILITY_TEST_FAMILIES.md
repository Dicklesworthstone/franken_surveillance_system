# Test Family Traceability Index (`registries/TESTS.md`)

This index maps every registered `TEST-*-001` qualification family from
[`registries/TESTS.md`](../registries/TESTS.md) to its exact existing verification surfaces and
honest current qualification status (`AGENTS.md` §12: no claim may be upgraded beyond retained proof).

| Test Family | Gate | Current Status | Concrete Verification Surfaces & Next Qualification Owner |
|---|---|---|---|
| `TEST-CONTRACT-001` | `GATE-010` | Implemented | `crates/fss-core/tests/contract_property_family.rs`, `scripts/qualify.sh` (`contract-property-family`) |
| `TEST-REPLAY-001` | `GATE-010` | Implemented | `crates/fss-cli/tests/archive_replay_process.rs`, `crates/fss-reference/tests/reference_deployment_recovery_contract.rs` |
| `TEST-SCHEDULE-001` | `GATE-020` | Implemented | `crates/fss-runtime/tests/`, `crates/fss-cli/src/orient_cmd/cancellation_tests.rs`, `crates/fss-reference/src/doctor/cancellation.rs` |
| `TEST-MEDIA-MALFORMED-001` | `GATE-020` | Implemented | `crates/fss-codec-mjpeg/tests/`, `crates/fss-codec-h264/tests/`, `crates/fss-codec-h265/tests/`, `scripts/lanes/media.sh` |
| `TEST-UVC-001` | `GATE-020` | Planned / Scoped | Local UVC capture harness deferred behind RTSP/TUTK/UniFi live ingest (`fss-x4a.31.3.1`, `fss-x4a.31.3.4`) |
| `TEST-RTSP-001` | `GATE-030` | Implemented (expanding) | `crates/fss-cli/tests/capture_rtsp_cli.rs`, `crates/fss-cli/tests/capture_rtsp_reconnect_cli.rs`, `tests/test_rtsp_reconnect_recovery.py`; in-band SPS/PPS expansion tracked in `fss-x4a.31.3.1` |
| `TEST-ONVIF-001` | `GATE-030` | Implemented | `crates/fss-cli/tests/onvif_*`, `crates/fss-reference/src/onvif/`, `crates/fss-cli/src/site_probe/onvif_tests.rs` |
| `TEST-LEDGER-CRASH-001` | `GATE-040` | Implemented (scaling) | `crates/fss-ledger/tests/ledger_repair_contract.rs`, `crates/fss-ledger/tests/durable_inspect_contract.rs`, `crates/fss-publication/tests/process_death_crash_harness.rs`; 50+ SIGKILL crash-cut suite tracked in `fss-x4a.31.1.8` |
| `TEST-ARCHIVE-001` | `GATE-040` | Implemented | `crates/fss-object/tests/durable_upload_contract.rs`, `crates/fss-cli/tests/archive_s3_upload_process.rs`, `crates/fss-cli/tests/archive_s3_restore_process.rs`, `scripts/lanes/archive.sh` |
| `TEST-MODEL-HOST-001` | `GATE-050` | Implemented (scaling) | `crates/fss-cli/tests/detector_cascade_cli_contract.rs`, `crates/fss-reference/src/image_kernels_simd.rs`; batched ML worker pool tracked in `fss-x4a.31.3.5` |
| `TEST-MODEL-QUALITY-001` | `GATE-080` | Partial | `crates/fss-cli/tests/evaluation_cli.rs`, `crates/fss-cli/tests/detection_tracking_cli_contract.rs`; expanded real-camera evaluation tracked in `fss-x4a.31.3.7` |
| `TEST-TIME-001` | `GATE-060` | Implemented | `crates/fss-cli/tests/clock_alignment_cli.rs`, `crates/fss-cli/tests/clock_drift_cli.rs`, `crates/fss-cli/tests/clock_validation_cli.rs` |
| `TEST-CALIBRATION-001` | `GATE-070` | Implemented | `crates/fss-geometry/`, `crates/fss-twin/`, `crates/fss-reference/src/ingest/calibration_monitor.rs` |
| `TEST-COVERAGE-001` | `GATE-070` | Implemented | `crates/fss-cli/tests/coverage_cli_contract.rs`, `crates/fss-cli/tests/coverage_geometry_gap_cli_contract.rs`, `crates/fss-cli/tests/coverage_timeline_cli.rs` |
| `TEST-ASSOCIATION-001` | `GATE-080` | Implemented | `crates/fss-cli/tests/corroborate_cli_contract.rs`, `crates/fss-cli/tests/corroborate_fusion_cli_contract.rs`, `crates/fss-fusion/src/` |
| `TEST-INTRUSION-001` | `GATE-080` | Implemented | `crates/fss-cli/tests/event_fusion_cli.rs`, `crates/fss-cli/tests/fusion_sequence_cli.rs`, `crates/fss-reference/src/scenario.rs` |
| `TEST-BENIGN-001` | `GATE-080` | Implemented | `crates/fss-cli/tests/fusion_ablation_cli.rs`, `crates/fss-cli/tests/historical_health_cli.rs`, `crates/fss-core/src/familiarity/tests.rs` |
| `TEST-TAMPER-001` | `GATE-080` | Implemented | `crates/fss-cli/tests/historical_health_corroboration_cli.rs`, `crates/fss-reference/src/sensor_health/` |
| `TEST-VENDOR-001` | `GATE-090` | Partial | `crates/fss-tutk/`, `crates/fss-tuya/`, `crates/fss-cli/src/bin/fss-unifi-discover.rs`; real-hardware soak tracked in `fss-x4a.31.3.2`, `fss-x4a.31.3.4`, `fss-x4a.31.3.7` |
| `TEST-AGENT-001` | `GATE-110` | Implemented | `crates/fss-cli/tests/agent_effect_cli_contract.rs`, `crates/fss-cli/tests/agent_rehearsal_contract.rs`, `tests/test_fss_mcp_bridge.py` |
| `TEST-PRIVACY-001` | `GATE-120` | Implemented (expanding) | `crates/fss-cli/tests/deletion_cli_contract.rs`, `crates/fss-cli/tests/deletion_scope_cli_contract.rs`, `crates/fss-cli/tests/evidence_hold_cli_contract.rs`; masked H2/H3 hydration tracked in `fss-x4a.31.4.1` |
| `TEST-RELEASE-001` | `GATE-120` | Partial | `tests/test_release_artifacts.py`, `tests/test_release_publication.py`, `scripts/release_qualify.sh`; full scale release gauntlet tracked in `fss-x4a.31.5.6` |
| `TEST-AGENT-ORIENT-001` | `GATE-115` | Implemented (expanding) | `crates/fss-cli/src/orient_cmd/`, `crates/fss-reference/src/agent_orient.rs`; pulse/decision_diff budget redesign tracked in `fss-x4a.31.2.3` |
| `TEST-AGENT-EPISTEMIC-001` | `GATE-115` | Implemented | `tests/test_knowledge_state_checker.py`, `tests/test_provenance_registry_checker.py`, `crates/fss-core/src/agent_cognitive.rs` |
| `TEST-AGENT-COMPRESSION-001` | `GATE-115` | Implemented (expanding) | `crates/fss-reference/src/agent_orient.rs`, `tests/test_hydration_transcript.py`; large-fleet rollups tracked in `fss-x4a.31.2.3` |
| `TEST-AGENT-VOI-001` | `GATE-115` | Implemented | `crates/fss-cli/src/probe_cmd/`, `crates/fss-reference/src/deployment_session/probe.rs` |
| `TEST-AGENT-CONTROL-001` | `GATE-115` | Implemented | `crates/fss-cli/tests/alert_lifecycle_cli.rs`, `crates/fss-cli/tests/agent_effect_cli_contract.rs`, `crates/fss-object/tests/effect_journal_contract.rs` |
| `TEST-AGENT-HANDOFF-001` | `GATE-115` | Implemented | `crates/fss-reference/src/deployment_session/tests.rs`, `crates/fss-reference/src/agent_session/` |
| `TEST-AGENT-MULTI-001` | `GATE-115` | Implemented (expanding) | `crates/fss-reference/src/agent_session/checkpoint/journal/coordination/`, `crates/fss-cli/tests/finding_cli_contract.rs`; 14-tool MCP multi-agent E2E tracked in `fss-x4a.31.4.5` |
| `TEST-AGENT-ACCRETION-001` | `GATE-115` | Implemented | `crates/fss-reference/src/deployment_session/learning.rs`, `crates/fss-cli/src/bin/fss_mcp/feedback.rs` |
| `TEST-AGENT-TRANSPORT-001` | `GATE-115` | Implemented (expanding) | `tests/test_fss_mcp_bridge.py`, `crates/fss-cli/src/bin/fss_mcp/`; expanded operational MCP E2E tracked in `fss-x4a.31.4.2`, `fss-x4a.31.4.5` |
| `TEST-AGENT-TAINT-001` | `GATE-115` | Implemented (expanding) | `tests/test_provenance_registry_checker.py`, `crates/fss-core/src/agent_cognitive.rs`; adversarial MCP security suite tracked in `fss-x4a.31.4.5` |
| `TEST-AGENT-SITUATION-001` | `GATE-115` | Implemented | `crates/fss-reference/src/situation.rs`, `crates/fss-reference/src/situation_guard.rs`, `crates/fss-cli/tests/event_changes_cli_contract.rs` |
| `TEST-AGENT-FOLLOW-001` | `GATE-115` | Implemented | `crates/fss-cli/tests/follow_cli_contract.rs`, `crates/fss-cli/tests/follow_subscription_cli_contract.rs` |
| `TEST-AGENT-CASE-001` | `GATE-115` | Implemented | `crates/fss-cli/src/probe_cmd/case.rs`, `crates/fss-reference/src/deployment_session/probe/case.rs` |
| `TEST-AGENT-AFFORDANCE-001` | `GATE-115` | Implemented | `crates/fss-reference/src/agent_orient.rs`, `crates/fss-cli/tests/explain_fusion_cli_contract.rs` |
| `TEST-AGENT-WORLD-ENVELOPE-001` | `GATE-115` | Implemented | `crates/fss-core/src/agent_world.rs`, `crates/fss-cli/tests/event_counterfactual_cli_contract.rs`, `crates/fss-cli/src/orient_cmd/what_if.rs` |
| `TEST-AGENT-LEARNING-001` | `GATE-115` | Implemented (scaling) | `crates/fss-reference/src/deployment_session/learning.rs`; lifting `MAX_CAPTURED_LEARNING=16` tracked in `fss-x4a.31.1.9` |
| `TEST-AGENT-RESOURCE-001` | `GATE-115` | Implemented (scaling) | `tests/test_slo_operation_cost_consistency.py`, `crates/fss-cli/src/supervisor/retained/budget.rs`; 100-camera scale benchmarks tracked in `fss-x4a.31.1.8` |
