#![forbid(unsafe_code)]
//! Canonical track queries exercise actual retained imports and first-party package inference.
//! Numeric fixture coefficients establish native parity and boundaries, not detection quality.

#[path = "../../fss-codec-mjpeg/tests/rgb_support/mod.rs"]
mod jpeg_support;
mod package_evaluation_support;
mod package_zone_support;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::json_input::{self, Value};
use fss_core::{
    ContentDigest, ContextAuthority, EffectIntent, IdempotencyKey, KnowledgeState, ObligationId,
    OperationId, PrincipalId, RootAuthoritySpec, RuntimeGrant, SensorId, StreamId, TimestampNs,
};
use fss_reference::ReferenceDeployment;
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_tracks::{
    DeploymentTrackQuery, TrackQueryError, TrackQueryLimits, TrackQueryRequest,
    TrackSourceReadPermit, query_tracks_in_deployment,
};
use fss_reference::deletion::{approval_digest, commit_deletion, plan_deletion};
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_event::{PackageAnalysisReport, retain_package_detection};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest};
use package_evaluation_support::{
    Directory, Fixture, PRINCIPAL, SENSOR, SITE, STREAM, Test, context, tracking,
};

fn request(report_digest: ContentDigest) -> Test<TrackQueryRequest> {
    Ok(TrackQueryRequest {
        report_digest,
        label: "numeric-a".into(),
        config: tracking(),
        principal: PrincipalId::parse(PRINCIPAL)?,
        max_entries: 16,
        expected_anchor: None,
        continuation: None,
    })
}

fn authority_spec(
    request: &TrackQueryRequest,
    limits: TrackQueryLimits,
) -> Test<RootAuthoritySpec> {
    Ok(RootAuthoritySpec {
        trace_id: "trace:canonical-tracks-contract".into(),
        operation_id: OperationId::parse("operation:canonical-tracks-contract")?,
        principal: request.principal.as_str().into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            RuntimeGrant::AgentQuery.as_str().into(),
            RuntimeGrant::ReadMedia.as_str().into(),
        ],
        deadline: None,
        priority: 10,
        budgets: limits.allowance()?,
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: request.report_digest,
        generation: 1,
    })
}

fn attempt(
    root: &Path,
    request: &TrackQueryRequest,
    limits: TrackQueryLimits,
) -> Test<Result<DeploymentTrackQuery, TrackQueryError>> {
    let authority = ContextAuthority::new_root(authority_spec(request, limits)?)?;
    let now = || TimestampNs(0);
    let permit = TrackSourceReadPermit::authorize(&authority, root, request, limits, &now)?;
    Ok(query_tracks_in_deployment(
        root,
        request,
        limits,
        Some(&permit),
        &|| false,
    ))
}

#[test]
fn immutable_query_matches_native_tracks_with_a_live_writer_and_preserves_tentative_history() -> Test
{
    let fixture = Fixture::new("tracks-native-parity", [128, 160, 192], Some(1_000_000))?;
    let request = request(fixture.report)?;
    let cx = context(&fixture.root)?;
    let writer = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let native =
        PackageAnalysisReport::read(&writer, fixture.report, &request.label, request.config, &cx)?;
    let before = fixture.journals()?;
    let temporary = fixture.root.join("LAYOUT.tmp.tracks-must-preserve");
    fs::write(
        &temporary,
        b"source queries do not repair or recover local state",
    )?;
    let limits = TrackQueryLimits::default();
    let query = attempt(&fixture.root, &request, limits)??;
    assert_eq!(query.report.encoded(), native.encoded());
    assert_eq!(query.report.digest(), native.digest());
    assert_eq!(query.total_observations, 3);
    assert_eq!(query.observations.len(), 3);
    assert_eq!(query.remaining_observations(), 0);
    assert!(query.page.next_cursor.is_none());
    query.page.verify()?;
    assert!(query.read_usage.read_bytes > 0);
    assert!(query.read_usage.read_objects > 0);
    assert!(query.read_usage.read_bytes <= limits.read.max_read_bytes as u64);
    assert!(query.read_usage.read_objects <= limits.read.max_read_objects as u64);
    let mut unique = BTreeSet::new();
    for row in &query.observations {
        assert!(unique.insert(row.row_digest));
        let track = native
            .tracks()
            .iter()
            .find(|track| track.identity == row.track_identity)
            .ok_or("native track identity")?;
        let observation = &track.observations[row.observation_index as usize];
        let frame = &native.retained().record().frames[row.frame_index as usize];
        assert_eq!(&row.observation, observation);
        assert_eq!(row.track_id, track.track_id);
        assert_eq!(row.track_ever_confirmed, track.confirmed);
        assert_eq!(
            Some(row.sample_confirmed),
            native.sample_is_confirmed(track.identity, row.observation_index as usize)
        );
        assert_eq!(row.capture, frame.capture);
        assert_eq!(row.sensor_id, frame.sensor_id);
        assert_eq!(row.dimensions, frame.dimensions);
        assert_eq!(row.inference_identity, frame.inference_identity);
        assert_eq!(row.output_digest, frame.output_digest);
        assert_eq!(row.detection_report_digest, frame.detection_report_digest);
        assert_eq!(row.continuity_epoch, 0);
        let proposition = query
            .epistemic
            .propositions
            .iter()
            .find(|proposition| {
                proposition.id == format!("claim:tracks:observation:{}", row.observation_index)
            })
            .ok_or("complete projected observation")?;
        assert_eq!(proposition.state, KnowledgeState::Estimated);
        let value = json_input::parse(proposition.statement.split_once(": ").ok_or("row JSON")?.1)?;
        let value = value.object().ok_or("row object")?;
        assert_eq!(
            value.get("track_identity"),
            Some(&Value::Text(row.track_identity.to_text()))
        );
        assert_eq!(
            value.get("sample_confirmed"),
            Some(&Value::Bool(row.sample_confirmed))
        );
        assert_eq!(
            value.get("track_ever_confirmed"),
            Some(&Value::Bool(row.track_ever_confirmed))
        );
        assert_eq!(
            value.get("capture_earliest_ns"),
            Some(&Value::Number(row.capture.earliest.0.to_string()))
        );
        let assigned = value
            .get("assigned_detection")
            .and_then(Value::object)
            .ok_or("assigned row")?;
        let actual = row.observation.detection.ok_or("native assigned row")?;
        assert_eq!(
            assigned.get("row"),
            Some(&Value::Number(actual.0.to_string()))
        );
        assert_eq!(
            assigned.get("uncalibrated_score_f32_bits"),
            Some(&Value::Number(actual.1.to_string()))
        );
    }
    assert!(!query.observations[0].sample_confirmed);
    assert!(query.observations[0].track_ever_confirmed);
    assert!(
        query.observations[1..]
            .iter()
            .all(|row| row.sample_confirmed)
    );
    assert_eq!(
        query
            .epistemic
            .propositions
            .iter()
            .filter(|row| row.id.starts_with("claim:tracks:frame:"))
            .count(),
        3
    );
    assert!(query.epistemic.propositions.iter().all(|row| {
        !row.statement
            .contains(fixture.root.to_str().unwrap_or("invalid-root"))
    }));
    assert_eq!(fixture.journals()?, before);
    assert_eq!(
        fs::read(&temporary)?,
        b"source queries do not repair or recover local state"
    );
    drop(writer);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn exact_continuations_exhaust_every_native_observation_once_with_stable_plan_and_selection() -> Test
{
    let fixture = Fixture::new("tracks-pagination", [128, 160, 192], Some(1_000_000))?;
    let mut request = request(fixture.report)?;
    request.max_entries = 1;
    let limits = TrackQueryLimits::default();
    let first = attempt(&fixture.root, &request, limits)??;
    let repeated = attempt(&fixture.root, &request, limits)??;
    assert_eq!(first.request_digest, repeated.request_digest);
    assert_eq!(first.decision_digest, repeated.decision_digest);
    assert_eq!(first.observations, repeated.observations);
    assert_eq!(first.coverage().omitted_count, 2);
    let mut seen = vec![first.observations[0].row_digest];
    let mut token = first
        .page
        .next_cursor
        .as_ref()
        .map(|cursor| cursor.token().to_owned());
    for position in 1..3 {
        request.continuation = token.take();
        // Adding a truthful precondition must not change the underlying stream identity.
        request.expected_anchor = Some(AnchorToken::parse(&first.anchor_token).ok_or("anchor")?);
        let page = attempt(&fixture.root, &request, limits)??;
        assert_eq!(page.cursor.position, position);
        assert_eq!(page.plan.plan_digest(), first.plan.plan_digest());
        assert_eq!(page.selection_witness, first.selection_witness);
        assert_eq!(page.session_id, first.session_id);
        assert_eq!(page.report.digest(), first.report.digest());
        assert_ne!(page.request_digest, first.request_digest);
        assert_eq!(page.observations.len(), 1);
        seen.push(page.observations[0].row_digest);
        assert_eq!(page.remaining_observations(), 2 - position as usize);
        token = page
            .page
            .next_cursor
            .as_ref()
            .map(|cursor| cursor.token().to_owned());
    }
    assert!(token.is_none());
    assert_eq!(seen.iter().collect::<BTreeSet<_>>().len(), 3);
    let mut full_request = request.clone();
    full_request.max_entries = 16;
    full_request.continuation = None;
    full_request.expected_anchor = None;
    let full = attempt(&fixture.root, &full_request, limits)??;
    assert_eq!(
        seen,
        full.observations
            .iter()
            .map(|row| row.row_digest)
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn continuation_cannot_change_label_recipe_principal_page_size_or_read_allowance() -> Test {
    let fixture = Fixture::new("tracks-cursor-binding", [128, 160, 192], Some(1_000_000))?;
    let mut original = request(fixture.report)?;
    original.max_entries = 1;
    let limits = TrackQueryLimits::default();
    let first = attempt(&fixture.root, &original, limits)??;
    original.continuation = Some(
        first
            .page
            .next_cursor
            .as_ref()
            .ok_or("next page")?
            .token()
            .into(),
    );
    for change in 0..6 {
        let mut request = original.clone();
        let mut limits = limits;
        match change {
            0 => request.label = "numeric-b".into(),
            1 => request.config.confirmation_hits += 1,
            2 => request.config.maximum_missed_frames += 1,
            3 => request.principal = PrincipalId::parse("principal:another-track-reader")?,
            4 => request.max_entries = 2,
            _ => limits.read.max_read_objects -= 1,
        }
        assert!(matches!(
            attempt(&fixture.root, &request, limits)?,
            Err(TrackQueryError::Continuation(_))
        ));
    }
    let mut spec = authority_spec(&original, limits)?;
    spec.privacy_scope = "privacy:another-grant-scope".into();
    let authority = ContextAuthority::new_root(spec)?;
    let now = || TimestampNs(0);
    let permit =
        TrackSourceReadPermit::authorize(&authority, &fixture.root, &original, limits, &now)?;
    assert!(matches!(
        query_tracks_in_deployment(&fixture.root, &original, limits, Some(&permit), &|| false),
        Err(TrackQueryError::Continuation(_))
    ));
    Ok(())
}

#[test]
fn an_effect_prefix_advance_refuses_the_old_cursor_and_exact_anchor_without_recovery() -> Test {
    let fixture = Fixture::new("tracks-effect-anchor", [128, 160, 192], Some(1_000_000))?;
    let mut request = request(fixture.report)?;
    request.max_entries = 1;
    let limits = TrackQueryLimits::default();
    let first = attempt(&fixture.root, &request, limits)??;
    request.continuation = Some(
        first
            .page
            .next_cursor
            .as_ref()
            .ok_or("next page")?
            .token()
            .into(),
    );
    let cx = context(&fixture.root)?;
    let mut writer = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let original_anchor = writer.current_anchor().clone();
    writer.effects_mut().prepare(
        EffectIntent::new(
            OperationId::parse("operation:tracks-unresolved")?,
            IdempotencyKey::parse("idempotency:tracks-unresolved")?,
            "fixture:tracks-notification",
            ContentDigest::sha256(b"tracks-payload"),
            ContentDigest::sha256(b"tracks-authority"),
        )?,
        ObligationId::parse("obligation:tracks-unresolved")?,
        "fixture unresolved notification",
        TimestampNs(1),
    )?;
    assert_eq!(writer.current_anchor(), &original_anchor);
    let before = fixture.journals()?;
    assert!(matches!(
        attempt(&fixture.root, &request, limits)?,
        Err(TrackQueryError::Continuation(_))
    ));
    request.expected_anchor = Some(AnchorToken::parse(&first.anchor_token).ok_or("anchor")?);
    assert!(matches!(
        attempt(&fixture.root, &request, limits)?,
        Err(TrackQueryError::AnchorChanged)
    ));
    assert_eq!(fixture.journals()?, before);
    drop(writer);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn source_permits_bind_every_required_grant_and_exact_page_before_any_filesystem_access() -> Test {
    let directory = Directory::new("tracks-permits")?;
    let root = directory.0.join("absent");
    let request = request(ContentDigest::sha256(b"retained-tracks"))?;
    let limits = TrackQueryLimits::default();
    let now = || TimestampNs(0);
    assert!(matches!(
        query_tracks_in_deployment(&root, &request, limits, None, &|| false),
        Err(TrackQueryError::Unauthorized)
    ));
    for missing in [
        "ADP-REPLAY-001",
        RuntimeGrant::AgentQuery.as_str(),
        RuntimeGrant::ReadMedia.as_str(),
    ] {
        let mut spec = authority_spec(&request, limits)?;
        spec.capabilities.retain(|grant| grant != missing);
        let authority = ContextAuthority::new_root(spec)?;
        assert!(matches!(
            TrackSourceReadPermit::authorize(&authority, &root, &request, limits, &now),
            Err(TrackQueryError::Unauthorized)
        ));
    }
    for change in 0..4 {
        let mut spec = authority_spec(&request, limits)?;
        match change {
            0 => spec.principal = "principal:wrong-reader".into(),
            1 => spec.anchor_universe = ContentDigest::sha256(b"other-report"),
            2 => spec.generation = 2,
            _ => spec.budgets = fss_core::BudgetVector::ZERO,
        }
        let authority = ContextAuthority::new_root(spec)?;
        assert!(matches!(
            TrackSourceReadPermit::authorize(&authority, &root, &request, limits, &now),
            Err(TrackQueryError::Unauthorized)
        ));
    }
    let authority = ContextAuthority::new_root(authority_spec(&request, limits)?)?;
    let permit = TrackSourceReadPermit::authorize(&authority, &root, &request, limits, &now)?;
    for change in 0..6 {
        let mut altered = request.clone();
        match change {
            0 => altered.report_digest = ContentDigest::sha256(b"another-retained-report"),
            1 => altered.label = "numeric-b".into(),
            2 => altered.config.minimum_iou_ppm += 1,
            3 => altered.principal = PrincipalId::parse("principal:another-reader")?,
            4 => altered.max_entries -= 1,
            _ => altered.continuation = Some("continuation:sha256:1234".into()),
        }
        assert!(matches!(
            query_tracks_in_deployment(&root, &altered, limits, Some(&permit), &|| false),
            Err(TrackQueryError::Unauthorized)
        ));
    }
    let other_root = directory.0.join("also-absent");
    assert!(matches!(
        query_tracks_in_deployment(&other_root, &request, limits, Some(&permit), &|| false),
        Err(TrackQueryError::Unauthorized)
    ));
    assert!(fs::read_dir(&directory.0)?.next().is_none());
    Ok(())
}

#[test]
fn scalar_validation_cancellation_and_deadline_refuse_without_creating_a_root() -> Test {
    let directory = Directory::new("tracks-admission")?;
    let root = directory.0.join("absent");
    let request = request(ContentDigest::sha256(b"time-bound-tracks"))?;
    let limits = TrackQueryLimits::default();
    for change in 0..7 {
        let mut altered = request.clone();
        match change {
            0 => altered.label.clear(),
            1 => altered.label = "invalid\nlabel".into(),
            2 => altered.label = "x".repeat(513),
            3 => altered.config.confirmation_hits = 0,
            4 => altered.config.maximum_missed_frames = 0,
            5 => altered.config.minimum_iou_ppm = 1_000_001,
            _ => altered.max_entries = 33,
        }
        assert!(matches!(
            query_tracks_in_deployment(&root, &altered, limits, None, &|| false),
            Err(TrackQueryError::InvalidRequest)
        ));
    }
    let mut spec = authority_spec(&request, limits)?;
    spec.deadline = Some(TimestampNs(10));
    let authority = ContextAuthority::new_root(spec)?;
    let clock = AtomicI64::new(0);
    let now = || TimestampNs(i128::from(clock.load(Ordering::SeqCst)));
    let permit = TrackSourceReadPermit::authorize(&authority, &root, &request, limits, &now)?;
    assert!(matches!(
        query_tracks_in_deployment(&root, &request, limits, Some(&permit), &|| true),
        Err(TrackQueryError::Cancelled)
    ));
    clock.store(10, Ordering::SeqCst);
    assert!(matches!(
        query_tracks_in_deployment(&root, &request, limits, Some(&permit), &|| false),
        Err(TrackQueryError::Unauthorized)
    ));
    assert!(!root.exists());
    Ok(())
}

#[test]
fn exhausted_budget_corrupt_source_or_unknown_label_is_a_refusal_never_an_empty_page() -> Test {
    let fixture = Fixture::new("tracks-source-refusals", [128, 160, 192], Some(1_000_000))?;
    let mut request = request(fixture.report)?;
    let before = fixture.journals()?;
    for bytes in [true, false] {
        let mut limits = TrackQueryLimits::default();
        if bytes {
            limits.read.max_read_bytes = 1;
        } else {
            limits.read.max_read_objects = 1;
        }
        assert!(matches!(
            attempt(&fixture.root, &request, limits)?,
            Err(TrackQueryError::Source(_))
        ));
    }
    request.label = "not-in-model-vocabulary".into();
    assert!(matches!(
        attempt(&fixture.root, &request, TrackQueryLimits::default())?,
        Err(TrackQueryError::Analysis(_))
    ));
    request.label = "numeric-a".into();
    let mut corrupt = fs::read(&fixture.chunk)?;
    *corrupt.last_mut().ok_or("source bytes")? ^= 1;
    fs::write(&fixture.chunk, &corrupt)?;
    assert!(attempt(&fixture.root, &request, TrackQueryLimits::default())?.is_err());
    assert_eq!(fs::read(&fixture.chunk)?, corrupt);
    assert_eq!(fixture.journals()?, before);
    Ok(())
}

#[test]
fn current_privacy_and_deletion_withdraw_historical_track_readability() -> Test {
    for privacy in [true, false] {
        let fixture = Fixture::new(
            if privacy {
                "tracks-privacy"
            } else {
                "tracks-deletion"
            },
            [128, 160, 192],
            Some(1_000_000),
        )?;
        let request = request(fixture.report)?;
        assert_eq!(
            attempt(&fixture.root, &request, TrackQueryLimits::default())??.total_observations,
            3
        );
        let cx = context(&fixture.root)?;
        let mut writer = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
        if privacy {
            let policy =
                PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [32, 16], &[[0, 0, 32, 16]])?;
            let approval = preview_mask(&writer, &policy)?.approval;
            declare_mask(&mut writer, &policy, approval, &cx)?;
        } else {
            let plan = plan_deletion(&writer, fixture.import, &cx)?;
            assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
            let digest = plan.digest()?;
            let approval = approval_digest(digest, SITE, PRINCIPAL)?;
            commit_deletion(&mut writer, digest, approval, PRINCIPAL, &cx)?;
        }
        let before = fixture.journals()?;
        assert!(attempt(&fixture.root, &request, TrackQueryLimits::default())?.is_err());
        assert_eq!(fixture.journals()?, before);
        drop(writer);
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn missed_and_zero_detection_frames_never_become_synthetic_observations_or_physical_absence() -> Test
{
    for values in [[128, 0, 192], [0, 0, 0]] {
        let fixture = Fixture::new("tracks-missing-samples", values, Some(1_000_000))?;
        let mut request = request(fixture.report)?;
        request.config.confirmation_hits = 1;
        request.config.maximum_missed_frames = 2;
        let query = attempt(&fixture.root, &request, TrackQueryLimits::default())??;
        let segments = query
            .observations
            .iter()
            .map(|row| row.observation.segment)
            .collect::<Vec<_>>();
        if values[0] == 0 {
            assert!(segments.is_empty());
            assert_eq!(query.total_observations, 0);
            assert!(query.page.next_cursor.is_none());
        } else {
            assert_eq!(segments, vec![0, 2]);
            assert_eq!(
                query.observations[0].track_identity,
                query.observations[1].track_identity
            );
            assert!(query.observations.iter().all(|row| row.sample_confirmed));
        }
        assert_eq!(query.report.retained().record().frames.len(), 3);
        assert_eq!(
            query
                .epistemic
                .propositions
                .iter()
                .filter(|row| row.id.starts_with("claim:tracks:frame:"))
                .count(),
            3
        );
        assert!(
            query
                .epistemic
                .propositions
                .iter()
                .any(|row| row.id == "claim:tracks:physical-absence"
                    && row.state == KnowledgeState::Unknown)
        );
        assert!(
            query
                .coverage()
                .not_observable_domain
                .iter()
                .any(|entry| entry.contains("missed-frame"))
        );
    }
    Ok(())
}

#[test]
fn source_dimension_boundary_resets_track_identity_and_confirmation_in_canonical_rows() -> Test {
    let directory = Directory::new("tracks-dimension-boundary")?;
    let root = directory.0.join("deployment");
    let source = directory.0.join("source.mjpeg");
    let mut bytes = package_zone_support::jpeg(128);
    bytes.extend(package_zone_support::jpeg(160));
    bytes.extend(jpeg_support::jpeg(
        64,
        16,
        [1, 1],
        false,
        false,
        false,
        &[[192, 128, 128]],
    ));
    fs::write(&source, &bytes)?;
    let cx = context(&root)?;
    let mut writer = ReferenceDeployment::open(&root, SITE, &cx)?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(&source, SensorId::parse(SENSOR)?, StreamId::parse(STREAM)?)
            .with_receive_time(TimestampNs(10_000_000_000)),
        &cx,
        &mut writer,
    )?;
    fs::remove_file(source)?;
    let bytes = package_zone_support::package()?;
    let scalar = fss_reference::ScalarExecCx::new();
    let package =
        RgbDetectorPackage::load(&bytes, ContentDigest::sha256(&bytes), 1 << 40, &cx, &scalar)?;
    let detection = run_package_detection(
        &writer,
        &package,
        &PackageDetectRequest {
            import_identity: imported.import_identity,
            first_segment: 0,
            segment_count: 3,
            interpretation: ComponentInterpretation::YCbCr,
            minimum_score_ppm: None,
        },
        &PackageDetectLimits::default(),
        &cx,
        &scalar,
    )?;
    retain_package_detection(&mut writer, &package, &detection, &cx)?;
    let query = attempt(
        &root,
        &request(detection.digest)?,
        TrackQueryLimits::default(),
    )??;
    assert_eq!(query.report.boundaries().len(), 1);
    let boundary = query.report.boundaries()[0];
    assert_eq!(boundary.before_segment, 2);
    assert!(boundary.dimensions_changed);
    assert_eq!(query.observations.len(), 3);
    assert_eq!(
        query
            .observations
            .iter()
            .map(|row| row.continuity_epoch)
            .collect::<Vec<_>>(),
        vec![0, 0, 1]
    );
    assert_eq!(
        query
            .observations
            .iter()
            .map(|row| row.sample_confirmed)
            .collect::<Vec<_>>(),
        vec![false, true, false]
    );
    assert_ne!(
        query.observations[0].track_identity,
        query.observations[2].track_identity
    );
    assert!(query.observations[2].track_id > query.observations[0].track_id);
    assert!(
        query
            .epistemic
            .propositions
            .iter()
            .any(|row| row.id == "claim:tracks:boundary:0"
                && row.statement.contains("\"dimensions_changed\":true"))
    );
    drop(writer);
    cx.drain_and_finalize();
    Ok(())
}
