#![forbid(unsafe_code)]
//! Genuine retained localization discovery, exact continuations and immutable metadata custody.

#[path = "twin_localization_query_support/mod.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::{
    ContentDigest, ContextAuthority, Generation, KnowledgeState, ObjectId, OperationId,
    PrincipalId, RootAuthoritySpec, RuntimeGrant, SensorId, StreamId, TombstoneReason,
    TombstoneRecord,
};
use fss_object::SpoolLimits;
use fss_publication::{
    LOCAL_ROOTS_DIR, LOCAL_TOMBSTONES_DIR, LocalPublicationLimits, LocalRootPublisher,
    ROOT_RECORD_SUFFIX,
};
use fss_reference::ReplayCx;
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_localizations::{
    LocalizationsQueryError, LocalizationsQueryFilter, LocalizationsQueryLimits,
    LocalizationsQueryRequest, query_localizations, row_json,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use support::{Fixture, PRINCIPAL, SITE, Test};

fn request() -> Test<LocalizationsQueryRequest> {
    Ok(LocalizationsQueryRequest {
        filter: LocalizationsQueryFilter::default(),
        principal: PrincipalId::parse(PRINCIPAL)?,
        max_entries: 16,
        expected_anchor: None,
        continuation: None,
    })
}

fn context(
    root: &Path,
    request: &LocalizationsQueryRequest,
    limits: LocalizationsQueryLimits,
) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:localizations-query-contract".into(),
        operation_id: OperationId::parse("operation:localizations-query-contract")?,
        principal: request.principal.as_str().to_owned(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            RuntimeGrant::AgentQuery.as_str().into(),
        ],
        deadline: None,
        priority: 10,
        budgets: limits.allowance()?,
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    assert!(!authority.has_capability(RuntimeGrant::ReadMedia.as_str()));
    Ok(ReplayCx::from_context_authority_read_only(
        &authority, root,
    )?)
}

fn files(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) -> Test {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                visit(root, &path, result)?;
            } else {
                result.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result)?;
    Ok(result)
}

#[test]
fn every_native_outcome_remains_discoverable_as_metadata_under_a_live_writer() -> Test {
    let fixture = Fixture::new("native-outcomes")?;
    assert_eq!(
        fixture
            .records
            .iter()
            .map(|record| record.outcome)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["candidates", "geometric_failure", "insufficient_matches"]),
    );
    let root = fixture.root();
    fs::write(
        root.join("LAYOUT.tmp.localizations-preserve"),
        b"no reader recovery",
    )?;
    let before = files(root)?;
    let request = request()?;
    let limits = LocalizationsQueryLimits::default();
    let cx = context(root, &request, limits)?;
    // Fixture intentionally retains its writer lock; discovery must open an immutable owner.
    let query = query_localizations(root, &request, limits, &cx, &|| false)?;
    assert_eq!(query.scanned_localizations, 3);
    assert_eq!(query.matched_localizations, 3);
    assert_eq!(query.rows.len(), 3);
    assert_eq!(query.remaining_localizations(), 0);
    assert!(!query.snapshot.doctor_inspected);
    for (row, original) in query.rows.iter().zip(&fixture.records) {
        let metadata = &row.metadata;
        assert_eq!(metadata.package_identity, original.identity);
        assert_eq!(metadata.publication_root, original.root);
        assert_eq!(metadata.receipt_digest, original.receipt);
        assert_eq!(metadata.import_identity, original.import_identity);
        assert_eq!(metadata.import_root, original.import_root);
        assert_eq!(metadata.source_manifest, original.source_manifest);
        assert_eq!(metadata.capsule_digest, original.capsule);
        assert_eq!(metadata.sensor_id, original.sensor_id);
        assert_eq!(metadata.stream_id, original.stream_id);
        assert_eq!(metadata.twin_digest, original.twin_blob);
        assert_eq!(metadata.atlas_package, original.atlas_blob);
        assert_eq!(metadata.codec, "jpeg");
        assert_eq!(metadata.segment_index, 0);
        assert_eq!(metadata.range_start, 0);
        assert_eq!(metadata.range_count, 1);
        assert!(metadata.committed_sequence > 0);
        let encoded = row_json(row);
        let parsed = fss_core::json_input::parse(&encoded)?;
        let fields = parsed.object().ok_or("localization metadata row")?;
        // Discovery cannot silently become geometric replay or calibration adoption.
        for absent in [
            "pose",
            "candidates",
            "outcome",
            "calibration_certificate",
            "coverage_witness",
        ] {
            assert!(
                !fields.contains_key(absent),
                "unexpected decision field {absent}"
            );
        }
        for unknown in [
            "adoption",
            "current_calibration",
            "physical_coverage",
            "source_payload_availability",
            "archive_payload_availability",
        ] {
            assert_eq!(
                fields
                    .get(unknown)
                    .and_then(fss_core::json_input::Value::text),
                Some("unknown"),
            );
        }
        assert_eq!(
            fields
                .get("replay")
                .and_then(fss_core::json_input::Value::text),
            Some("not_performed"),
        );
        assert_eq!(
            fields
                .get("candidate_outcome")
                .and_then(fss_core::json_input::Value::text),
            Some("not_interpreted"),
        );
        assert_eq!(
            fields
                .get("activation_performed")
                .and_then(fss_core::json_input::Value::boolean),
            Some(false),
        );
        assert!(!encoded.contains(root.to_str().ok_or("fixture root")?));
    }
    assert!(
        query
            .epistemic()
            .propositions
            .iter()
            .any(|cell| cell.state == KnowledgeState::Unknown)
    );
    let repeated = query_localizations(root, &request, limits, &cx, &|| false)?;
    assert_eq!(query, repeated);
    assert_eq!(files(root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn h0_discovery_does_not_open_encoded_media_luma_twin_or_atlas_payloads() -> Test {
    let fixture = Fixture::new("metadata-only")?;
    let root = fixture.root();
    let request = request()?;
    let limits = LocalizationsQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let before = query_localizations(root, &request, limits, &cx, &|| false)?;
    let mut payloads = BTreeSet::new();
    for record in &fixture.records {
        payloads.extend([
            record.source_blob,
            record.luma_blob,
            record.twin_blob,
            record.atlas_blob,
        ]);
    }
    for digest in payloads {
        fs::remove_file(fixture.object_path(digest))?;
    }
    let missing_payloads = files(root)?;
    let after = query_localizations(root, &request, limits, &cx, &|| false)?;
    assert_eq!(after.rows, before.rows);
    assert_eq!(after.selection_witness, before.selection_witness);
    assert_eq!(after.decision_digest, before.decision_digest);
    assert_eq!(after.read_usage, before.read_usage);
    assert_eq!(files(root)?, missing_payloads);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn exact_conjunctive_filters_never_change_the_complete_index_or_protected_context() -> Test {
    let fixture = Fixture::new("exact-filters")?;
    let root = fixture.root();
    let mut request = request()?;
    let limits = LocalizationsQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let all = query_localizations(root, &request, limits, &cx, &|| false)?;
    let candidate = fixture
        .records
        .iter()
        .find(|record| record.outcome == "candidates")
        .ok_or("candidate fixture")?;
    for dimension in 0..4 {
        request.filter = LocalizationsQueryFilter::default();
        match dimension {
            0 => request.filter.sensor_id = Some(candidate.sensor_id.clone()),
            1 => request.filter.stream_id = Some(candidate.stream_id.clone()),
            2 => request.filter.import_identity = Some(candidate.import_identity),
            _ => request.filter.twin_digest = Some(candidate.twin_blob),
        }
        let exact = query_localizations(root, &request, limits, &cx, &|| false)?;
        assert_eq!(exact.scanned_localizations, 3);
        assert_eq!(exact.rows.len(), if dimension == 3 { 3 } else { 2 });
        assert_eq!(exact.snapshot, all.snapshot);
        assert_eq!(exact.read_usage, all.read_usage);
    }
    request.filter = LocalizationsQueryFilter {
        sensor_id: Some(candidate.sensor_id.clone()),
        stream_id: Some(candidate.stream_id.clone()),
        import_identity: Some(candidate.import_identity),
        twin_digest: Some(candidate.twin_blob),
    };
    let exact = query_localizations(root, &request, limits, &cx, &|| false)?;
    assert_eq!(exact.rows.len(), 2);
    request.filter.stream_id = Some(StreamId::parse("stream:localization:other")?);
    let mismatched = query_localizations(root, &request, limits, &cx, &|| false)?;
    assert!(mismatched.rows.is_empty());
    assert_eq!(mismatched.scanned_localizations, 3);
    assert_eq!(mismatched.snapshot, all.snapshot);
    request.filter = LocalizationsQueryFilter {
        sensor_id: Some(SensorId::parse("sensor:localization")?),
        ..LocalizationsQueryFilter::default()
    };
    let prefix = query_localizations(root, &request, limits, &cx, &|| false)?;
    assert!(
        prefix.rows.is_empty(),
        "sensor prefixes are not exact identities"
    );
    assert!(
        prefix
            .epistemic()
            .propositions
            .iter()
            .any(|cell| cell.state == KnowledgeState::Unknown)
    );
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn native_continuations_bind_every_selector_principal_page_size_and_read_limit() -> Test {
    let fixture = Fixture::new("continuations")?;
    let root = fixture.root();
    let mut request = request()?;
    request.max_entries = 1;
    let limits = LocalizationsQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let first = query_localizations(root, &request, limits, &cx, &|| false)?;
    assert_eq!(first.remaining_localizations(), 2);
    request.expected_anchor = Some(AnchorToken::parse(&first.anchor_token).ok_or("anchor")?);
    request.continuation = Some(
        first
            .page
            .next_cursor
            .as_ref()
            .ok_or("next")?
            .token()
            .to_owned(),
    );
    let second = query_localizations(root, &request, limits, &cx, &|| false)?;
    assert_eq!(second.cursor.position, 1);
    assert_eq!(second.remaining_localizations(), 1);
    assert_eq!(second.selection_witness, first.selection_witness);
    assert_ne!(second.request_digest, first.request_digest);
    assert_ne!(second.rows, first.rows);
    for dimension in 0..9 {
        let mut changed = request.clone();
        let mut changed_limits = limits;
        match dimension {
            0 => changed.filter.sensor_id = Some(fixture.records[0].sensor_id.clone()),
            1 => changed.filter.stream_id = Some(fixture.records[0].stream_id.clone()),
            2 => changed.filter.import_identity = Some(fixture.records[0].import_identity),
            3 => changed.filter.twin_digest = Some(fixture.records[0].twin_blob),
            4 => changed.max_entries = 2,
            5 => changed_limits.max_localizations -= 1,
            6 => changed_limits.max_objects -= 1,
            7 => changed_limits.read.max_read_bytes -= 1,
            _ => changed_limits.read.max_read_objects -= 1,
        }
        assert!(
            matches!(
                query_localizations(root, &changed, changed_limits, &cx, &|| false),
                Err(LocalizationsQueryError::Continuation(_)),
            ),
            "continuation dimension {dimension}"
        );
    }
    let mut changed = request.clone();
    changed.principal = PrincipalId::parse("principal:another-localization-reader")?;
    let other_cx = context(root, &changed, limits)?;
    assert!(matches!(
        query_localizations(root, &changed, limits, &other_cx, &|| false),
        Err(LocalizationsQueryError::Continuation(_)),
    ));
    other_cx.drain_and_finalize();
    request.continuation = Some(
        second
            .page
            .next_cursor
            .as_ref()
            .ok_or("third page")?
            .token()
            .to_owned(),
    );
    let last = query_localizations(root, &request, limits, &cx, &|| false)?;
    assert_eq!(last.cursor.position, 2);
    assert_eq!(last.remaining_localizations(), 0);
    assert!(last.page.next_cursor.is_none());
    let ids: Vec<_> = first
        .rows
        .iter()
        .chain(&second.rows)
        .chain(&last.rows)
        .map(|row| row.metadata.package_identity)
        .collect();
    assert_eq!(
        ids,
        fixture
            .records
            .iter()
            .map(|record| record.identity)
            .collect::<Vec<_>>()
    );
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn excluded_corrupt_recipe_receipt_source_or_publication_refuses_the_entire_page() -> Test {
    let fixture = Fixture::new("excluded-custody")?;
    let root = fixture.root();
    let mut request = request()?;
    request.max_entries = 1;
    request.filter.sensor_id = Some(SensorId::parse("sensor:localization:a")?);
    let limits = LocalizationsQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let excluded = fixture
        .records
        .iter()
        .find(|record| record.sensor_id.as_str() == "sensor:localization:b")
        .ok_or("excluded source")?;
    query_localizations(root, &request, limits, &cx, &|| false)?;
    let before = files(root)?;
    for digest in [
        excluded.identity,
        excluded.receipt,
        excluded.root,
        excluded.source_manifest,
        excluded.capsule,
    ] {
        let path = fixture.object_path(digest);
        let original = fs::read(&path)?;
        fs::write(&path, b"corrupt excluded localization metadata")?;
        let damaged = files(root)?;
        assert!(query_localizations(root, &request, limits, &cx, &|| false).is_err());
        assert_eq!(
            files(root)?,
            damaged,
            "a refused read must not repair metadata"
        );
        fs::write(path, original)?;
    }
    assert_eq!(files(root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn current_privacy_invalidates_even_a_localization_outside_the_selected_page() -> Test {
    let mut fixture = Fixture::new("privacy-invalidated")?;
    let root = fixture.root().to_path_buf();
    let mut request = request()?;
    request.filter.sensor_id = Some(SensorId::parse("sensor:localization:a")?);
    let limits = LocalizationsQueryLimits::default();
    let cx = context(&root, &request, limits)?;
    assert_eq!(
        query_localizations(&root, &request, limits, &cx, &|| false)?
            .rows
            .len(),
        2
    );
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:localization:b")?,
        [96, 96],
        &[[0, 0, 96, 96]],
    )?;
    let approval = preview_mask(&fixture.deployment, &policy)?.approval;
    declare_mask(&mut fixture.deployment, &policy, approval, &fixture.cx)?;
    let changed = files(&root)?;
    assert!(query_localizations(&root, &request, limits, &cx, &|| false).is_err());
    assert_eq!(files(&root)?, changed);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn an_excluded_original_media_tombstone_revokes_metadata_without_hydrating_media() -> Test {
    let mut fixture = Fixture::new("excluded-source-tombstone")?;
    let root = fixture.root().to_path_buf();
    let mut request = request()?;
    request.filter.sensor_id = Some(SensorId::parse("sensor:localization:a")?);
    let limits = LocalizationsQueryLimits::default();
    let cx = context(&root, &request, limits)?;
    let excluded = fixture
        .records
        .iter()
        .find(|record| record.sensor_id.as_str() == "sensor:localization:b")
        .ok_or("excluded source")?
        .source_blob;
    assert!(
        fixture
            .records
            .iter()
            .filter(|record| record.sensor_id.as_str() == "sensor:localization:a")
            .all(|record| record.source_blob != excluded)
    );
    let original = query_localizations(&root, &request, limits, &cx, &|| false)?;
    assert_eq!(original.rows.len(), 2);
    // Ordinary source loss preserves H0 handles; explicit revocation must be distinguished.
    fs::remove_file(fixture.object_path(excluded))?;
    assert_eq!(
        query_localizations(&root, &request, limits, &cx, &|| false)?.rows,
        original.rows
    );

    let witness_bytes = b"authorized synthetic localization source deletion witness";
    let witness = fixture.deployment.stage_payload(witness_bytes)?;
    let donor_root = root
        .parent()
        .ok_or("fixture parent")?
        .join("tombstone-donor");
    let mut donor = LocalRootPublisher::open(
        &donor_root,
        LocalPublicationLimits::new(
            8,
            32,
            8,
            64,
            SpoolLimits::new(32, 1024 * 1024, 256 * 1024, 64),
        ),
    )?;
    assert_eq!(donor.stage_object(witness_bytes)?, witness);
    donor.record_tombstone(TombstoneRecord::new(
        ObjectId::parse("object:localization-original-deletion-fixture")?,
        Generation(2),
        Generation(1),
        TombstoneReason::Deleted,
        Some(witness),
        excluded,
    )?)?;
    drop(donor);
    // Inject a native canonical tombstone after the root was published, modelling a
    // revocation visible to the immutable reader while its live writer still has old state.
    for entry in fs::read_dir(donor_root.join(LOCAL_TOMBSTONES_DIR))? {
        let entry = entry?;
        fs::copy(
            entry.path(),
            root.join("objects")
                .join(LOCAL_TOMBSTONES_DIR)
                .join(entry.file_name()),
        )?;
    }
    let revoked = files(&root)?;
    assert!(query_localizations(&root, &request, limits, &cx, &|| false).is_err());
    assert_eq!(files(&root)?, revoked);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn opening_inventory_and_final_rereads_share_one_exact_nonrenewing_allowance() -> Test {
    let fixture = Fixture::new("shared-allowance")?;
    let root = fixture.root();
    let request = request()?;
    let limits = LocalizationsQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let full = query_localizations(root, &request, limits, &cx, &|| false)?;
    assert!(full.read_usage.read_bytes > 1);
    assert!(full.read_usage.read_objects > 1);
    let mut exact = limits;
    exact.read.max_read_bytes = usize::try_from(full.read_usage.read_bytes)?;
    exact.read.max_read_objects = usize::try_from(full.read_usage.read_objects)?;
    let exact_cx = context(root, &request, exact)?;
    let accepted = query_localizations(root, &request, exact, &exact_cx, &|| false)?;
    assert_eq!(accepted.read_usage, full.read_usage);
    exact_cx.drain_and_finalize();
    for dimension in 0..2 {
        let mut short = exact;
        if dimension == 0 {
            short.read.max_read_bytes -= 1;
        } else {
            short.read.max_read_objects -= 1;
        }
        let short_cx = context(root, &request, short)?;
        assert!(query_localizations(root, &request, short, &short_cx, &|| false).is_err());
        short_cx.drain_and_finalize();
    }
    let mut filtered = request.clone();
    filtered.filter.sensor_id = Some(SensorId::parse("sensor:not-retained")?);
    for dimension in 0..2 {
        let mut bounded = limits;
        if dimension == 0 {
            bounded.max_localizations = 2;
        } else {
            bounded.max_objects = 1;
        }
        assert!(matches!(
            query_localizations(root, &filtered, bounded, &cx, &|| false),
            Err(LocalizationsQueryError::OverBudget),
        ));
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn invalid_scalar_inputs_principals_and_roots_never_create_or_repair_a_deployment() -> Test {
    let fixture = Fixture::new("invalid-inputs")?;
    let root = fixture.root().join("absent-reader-root");
    let request = request()?;
    let limits = LocalizationsQueryLimits::default();
    let cx = context(&root, &request, limits)?;
    for dimension in 0..3 {
        let mut invalid = request.clone();
        match dimension {
            0 => invalid.max_entries = 0,
            1 => invalid.max_entries = 33,
            _ => invalid.continuation = Some("continuation:INVALID".into()),
        }
        assert!(matches!(
            query_localizations(&root, &invalid, limits, &cx, &|| false),
            Err(LocalizationsQueryError::InvalidRequest(_)),
        ));
    }
    let mut invalid_limits = limits;
    invalid_limits.max_localizations = 0;
    assert!(matches!(
        query_localizations(&root, &request, invalid_limits, &cx, &|| false),
        Err(LocalizationsQueryError::InvalidRequest(_)),
    ));
    let mut other = request.clone();
    other.principal = PrincipalId::parse("principal:unbound-localization-reader")?;
    assert!(matches!(
        query_localizations(&root, &other, limits, &cx, &|| false),
        Err(LocalizationsQueryError::Unauthorized),
    ));
    assert!(matches!(
        query_localizations(fixture.root(), &request, limits, &cx, &|| false),
        Err(LocalizationsQueryError::Unauthorized),
    ));
    assert!(matches!(
        query_localizations(&root, &request, limits, &cx, &|| true),
        Err(LocalizationsQueryError::Cancelled),
    ));
    assert!(!root.exists());
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn cancellation_at_each_native_phase_and_last_live_admission_releases_no_page() -> Test {
    let fixture = Fixture::new("cancellation")?;
    let root = fixture.root();
    let request = request()?;
    let limits = LocalizationsQueryLimits::default();
    let before = files(root)?;
    for stage in [
        "localizations:open",
        "localizations:index",
        "localizations:metadata",
        "localizations:complete",
    ] {
        let cx = context(root, &request, limits)?;
        cx.set_cancel_at_checkpoint(stage);
        assert!(
            query_localizations(root, &request, limits, &cx, &|| false).is_err(),
            "{stage}"
        );
        cx.drain_and_finalize();
        assert_eq!(files(root)?, before);
    }
    let cx = context(root, &request, limits)?;
    let calls = AtomicUsize::new(0);
    query_localizations(root, &request, limits, &cx, &|| {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    })?;
    let last = calls.load(Ordering::SeqCst);
    assert!(last > 0);
    calls.store(0, Ordering::SeqCst);
    let fired = AtomicBool::new(false);
    assert!(
        query_localizations(root, &request, limits, &cx, &|| {
            let refuse = calls.fetch_add(1, Ordering::SeqCst) + 1 == last;
            if refuse {
                fired.store(true, Ordering::SeqCst);
            }
            refuse
        })
        .is_err()
    );
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(files(root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn a_new_authority_generation_invalidates_exact_anchor_and_continuation() -> Test {
    let mut fixture = Fixture::new("authority-drift")?;
    let root = fixture.root().to_path_buf();
    let mut request = request()?;
    request.max_entries = 1;
    let limits = LocalizationsQueryLimits::default();
    let cx = context(&root, &request, limits)?;
    let first = query_localizations(&root, &request, limits, &cx, &|| false)?;
    request.expected_anchor = Some(AnchorToken::parse(&first.anchor_token).ok_or("anchor")?);
    request.continuation = Some(
        first
            .page
            .next_cursor
            .as_ref()
            .ok_or("next")?
            .token()
            .to_owned(),
    );
    // An unrelated policy is a real authority append without changing these source masks.
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:unrelated-localization-reader")?,
        [96, 96],
        &[[0, 0, 8, 8]],
    )?;
    let approval = preview_mask(&fixture.deployment, &policy)?.approval;
    declare_mask(&mut fixture.deployment, &policy, approval, &fixture.cx)?;
    assert!(matches!(
        query_localizations(&root, &request, limits, &cx, &|| false),
        Err(LocalizationsQueryError::AnchorChanged),
    ));
    request.expected_anchor = None;
    assert!(matches!(
        query_localizations(&root, &request, limits, &cx, &|| false),
        Err(LocalizationsQueryError::Continuation(_)),
    ));
    request.continuation = None;
    let fresh = query_localizations(&root, &request, limits, &cx, &|| false)?;
    assert_ne!(fresh.anchor_token, first.anchor_token);
    assert_eq!(fresh.rows, first.rows);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn final_rereads_reject_receipt_publication_source_and_journal_drift_after_composition() -> Test {
    let fixture = Fixture::new("final-drift")?;
    let root = fixture.root();
    let request = request()?;
    let limits = LocalizationsQueryLimits::default();
    // Measure the real post-composition boundary using the native cancellation checkpoint,
    // then inject immediately after it in an uncancelled request. No sleeps or writer races.
    let probe_cx = context(root, &request, limits)?;
    probe_cx.set_cancel_at_checkpoint("localizations:complete");
    let calls = AtomicUsize::new(0);
    assert!(
        query_localizations(root, &request, limits, &probe_cx, &|| {
            calls.fetch_add(1, Ordering::SeqCst);
            false
        })
        .is_err()
    );
    let complete_calls = calls.load(Ordering::SeqCst);
    assert!(complete_calls > 0);
    probe_cx.drain_and_finalize();
    let record = &fixture.records[0];
    let slot = format!(
        "recorded-localization-{}",
        record.identity.to_text().trim_start_matches("sha256:")
    );
    let paths = [
        fixture.object_path(record.receipt),
        fixture.object_path(record.identity),
        fixture.object_path(record.capsule),
        fixture.object_path(record.source_manifest),
        root.join("objects")
            .join(LOCAL_ROOTS_DIR)
            .join(format!("{slot}{ROOT_RECORD_SUFFIX}")),
        root.join("ledger/journal.fssj"),
    ];
    let before = files(root)?;
    for path in paths {
        let original = fs::read(&path)?;
        let cx = context(root, &request, limits)?;
        calls.store(0, Ordering::SeqCst);
        let fired = AtomicBool::new(false);
        let result = query_localizations(root, &request, limits, &cx, &|| {
            if calls.fetch_add(1, Ordering::SeqCst) == complete_calls {
                assert!(
                    fs::write(&path, b"changed after complete localization composition").is_ok()
                );
                fired.store(true, Ordering::SeqCst);
            }
            false
        });
        assert!(
            fired.load(Ordering::SeqCst),
            "final read boundary not reached"
        );
        assert!(
            result.is_err(),
            "changed final dependency must refuse the entire page: {path:?}"
        );
        fs::write(path, original)?;
        cx.drain_and_finalize();
    }
    assert_eq!(files(root)?, before);
    Ok(())
}
