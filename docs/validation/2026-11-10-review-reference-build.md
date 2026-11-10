# First review checkpoint: supplementary build evidence

Source commit: `d3d11eeb7665ad63088e6b7b2af371a37c8b617b`.

Automatic workflow: [pinned nightly reference tests](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/42745633540/job/129596928829).

The complete reference library and its unit-test executable compiled on the pinned
nightly. This includes the new retained review production modules and renderer/grant
unit-test source. The workflow did not select the new review unit or lifecycle tests
at this checkpoint; compilation does not establish their runtime results.

Selected existing regression targets passed: original media export (23), deployment
contracts (15), and deployment recovery (36). These are regression evidence for the
existing owners, not new review lifecycle test results.

The overall workflow failed. Its concrete compiler blockers were an existing
`fss-event/delete.rs` child-module path and an existing RTSP catalog test calling
`stage_manifest` without its slot. Existing formatting findings also remain.
The next integration-fix checkpoint repairs those two compiler blockers, explicit
paths for the newly added review CLI children, and stale `current_mask` calls in
the new lifecycle/CLI fixtures. No test assertion or qualification gate is weakened.

## Reference unit-test build excerpt

```text
warning: `fss-reference` (lib test) generated 67 warnings (run `cargo fix --lib -p fss-reference --tests` to apply 1 suggestion)
    Finished `test` profile [unoptimized] target(s) in 59.39s
     Running unittests src/lib.rs (target/debug/build/fss-reference/ee12eb2447f744c4/out/fss_reference-ee12eb2447f744c4)

running 38 tests
test agent_session::checkpoint::journal::supervision::compatibility_tests::frozen_v1_command_records_decode_and_reencode_byte_for_byte ... ok
```

## Selected complete regression results

The following is verbatim job output with timestamps and ANSI color removed.

```text
     Running tests/original_media_export_contract.rs (target/debug/build/fss-reference/cc2e01f0e08c8372/out/original_media_export_contract-cc2e01f0e08c8372)

running 23 tests
test authority_deadline_is_exclusive_at_preview_approval_and_final_revalidation ... ok
test an_event_computed_under_the_current_mask_still_cannot_export_unmasked_originals ... ok
test cold_event_export_keeps_all_playable_original_bytes_and_explicit_context_without_writes ... ok
test generic_mp4_is_not_disclosed_as_video_only_without_native_source_attestation ... ok
test mask_change_between_approval_and_output_refuses_the_whole_unmasked_source ... ok
test corroborated_event_discloses_exactly_one_selected_camera_and_binds_switching_to_new_approval ... ok
test missing_whole_source_acknowledgement_expired_time_and_excess_bounds_fail_before_io ... ok
test offline_verifier_requires_the_independent_root_and_every_original_byte ... ok
test current_event_revision_and_committed_source_deletion_invalidate_prepared_media ... ok
test package::package_approval_cannot_release_after_source_or_provenance_custody_loss ... ok
test package::package_export_cannot_substitute_a_source_or_downgrade_its_profile ... ok
test package::package_candidate_cold_export_preserves_footage_uncertainty_and_exact_custody ... ok
test package::reviewed::package_review_cannot_rewrite_native_probability_even_with_retained_statement_and_event_roots ... ok
test package::reviewed::current_reviewed_package_cold_export_preserves_native_origin_and_every_operator_assertion ... ok
test package::reviewed::reviewed_package_rechecks_native_source_analysis_and_intermediate_operator_custody ... ok
test recipient_purpose_destination_time_and_budget_are_exact_approval_inputs ... ok
test reviewed::cold_multi_review_export_binds_current_case_to_exact_native_source_and_redacted_history ... ok
test reviewed::offline_reviewed_record_rejects_inconsistent_current_summary_and_unbounded_or_trailing_chain ... ok
test reviewed::intermediate_review_corruption_and_cancellation_never_return_original_media ... ok
test source_corruption_and_cancellation_never_return_a_successful_package ... ok
test reviewed::reviewed_package_rechecks_current_review_privacy_and_deletion_before_delivery ... ok
test reviewed::superficially_linked_operator_successor_cannot_change_native_facts ... ok
test package::package_media_masks_deletion_and_operator_successors_invalidate_release has been running for over 60 seconds
test package::package_media_masks_deletion_and_operator_successors_invalidate_release ... ok

test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 66.36s

     Running tests/reference_deployment_contract.rs (target/debug/build/fss-reference/029fb96473ecbbe8/out/reference_deployment_contract-029fb96473ecbbe8)

running 15 tests
test exported_constants_and_tables_integrity ... ok
test cooperative_cancellation_aborts_operations_and_drains ... ok
test not_a_deployment_on_non_empty_root_without_layout ... ok
test capacity_limits_refusals_name_limits ... ok
test append_batch_idempotency_and_conflict ... ok
test incomplete_journal_tail_surfaces_typed_error_and_open_for_recovery_truncates ... ok
test open_and_reopen_empty_and_existing_root ... ok
test recovery_refuses_corrupt_history_with_structurally_valid_record ... ok
test recovery_applies_sealed_repair_for_non_record_foreign_bytes ... ok
test repeated_payload_roles_cannot_evade_pre_deduplication_input_limit ... ok
test path_independence_produces_identical_digests_and_anchors ... ok
test refused_second_open_leaves_both_journals_byte_identical ... ok
test second_concurrent_open_returns_deployment_locked ... ok
test repeated_payload_roles_share_a_canonical_child_and_retry_after_cold_reopen ... ok
test simulated_alert_dispatch_routes_through_deployment_provider ... ok

test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s

     Running tests/reference_deployment_recovery_contract.rs (target/debug/build/fss-reference/4c601f3d12a7c18c/out/reference_deployment_recovery_contract-4c601f3d12a7c18c)

running 36 tests
test p01_lock_path_exact_and_recovery_locked ... ok
test p02_lock_taken_before_journals ... ok
test batch_entries_bound_admits_exactly_n_deltas_and_children ... ok
test manifest_children_bound_admits_exactly_n ... ok
test p03_layout_exact_and_no_temp_leftover ... ok
test p04_reopen_same_params_is_noop ... ok
test journal_record_bound_admits_exactly_n_and_refuses_n_plus_one ... ok
test p05_reopen_different_params_refused_typed ... ok
test p09_lineage_validation_before_layout_write ... ok
test p07_torn_layout ... ok
test p06_crash_skeleton_without_layout ... ok
test p08_layout_relpaths_not_validated ... ok
test p11_effect_tail_typed_and_recoverable ... ok
test p12_plan_digest_mismatch_refused_untouched ... ok
test p15_cancellation_matrix ... ok
test p10_recovery_on_healthy_root_changes_nothing ... ok
test p14_crash_after_root_durable ... ok
test p16_root_kinds ... ok
test p17_stage_and_publish_bypasses_ledger ... ok
test p18_orphan_staging_surfaces_on_reopen ... ok
test p20_capacity_refusals ... ok
test p19_children_order_idempotency ... ok
test scan_bound_admits_exactly_n_root_entries_and_refuses_n_plus_one ... ok
test scan_limit_refusal_reports_a_lower_bound ... ok
test test_f3_directory_fsync_error_propagation ... ok
test test_f3_injected_directory_fsync_failure_propagates_after_rename ... ok
test publish_event_retry_of_the_same_decision_is_idempotent ... ok
test test_k4_effect_incomplete_tail_truncation_receipt_and_file_length ... ok
test test_l2_duplicate_layout_key_refused ... ok
test test_k3_ledger_incomplete_tail_truncation_receipt_and_file_length ... ok
test test_cancellation_c04_c09_c11_c12 ... ok
test test_m4_atomic_layout_failure_preserves_previous_layout ... ok
test test_symlink_lock_refused_in_recovery ... ok
test test_typed_parameter_mismatch_errors ... ok
test reopen_after_crash_at_each_cut_point_reports_literal_root_state ... ok
test test_publish_event_compile_situation_seal_handoff_lifecycle ... ok

test result: ok. 36 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s

```
