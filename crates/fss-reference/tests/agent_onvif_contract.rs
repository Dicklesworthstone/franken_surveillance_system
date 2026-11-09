#![forbid(unsafe_code)]
//! Genuine retained ONVIF sources under the canonical read-only deployment query.
//! These fixtures establish metadata custody and vendor-claim interpretation only.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, EffectIntent, EffectState,
    IdempotencyKey, KnowledgeState, ObligationId, OperationId, PrincipalId, RootAuthoritySpec,
    SensorId, TimestampNs,
};
use fss_object::{HostSpoolIo, RecordingSpoolIo, SpoolIo, SpoolIoCall};
use fss_packet::{OnvifMetadataLimits, ReorderLimits, StreamKey};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_onvif::{
    DeploymentOnvifQuery, OnvifAnalysis, OnvifAnalysisResult, OnvifQueryError, OnvifQueryLimits,
    OnvifQueryRequest, query_onvif_in_deployment,
};
use fss_reference::deletion::{commit_deletion, plan_deletion};
use fss_reference::onvif::metadata::lifecycle::{
    LifecycleDocumentState, LifecycleReadLimits, RetainedLifecycle,
};
use fss_reference::onvif::metadata::rtp::{self, RtpMetadataConfig, RtpMetadataImportLimits};
use fss_reference::onvif::metadata::tracks::{RetainedTracklets, TrackReadLimits, TrackSourcePin};
use fss_reference::onvif::metadata::zones::contract::VendorZone;
use fss_reference::onvif::metadata::zones::{RetainedZones, ZonePolicy, ZoneReadLimits};
use fss_reference::onvif::metadata::{Interpretation, SourceBinding, retain_with_interpretation};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:agent-onvif-contract";
const PRINCIPAL: &str = "principal:agent-onvif-contract";
const PRIVATE_MODULE: &str = "private_agent_onvif_module";
const FIRST_ID: &str = "910000031";
const SECOND_ID: &str = "910000032";

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-agent-onvif-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture directory capacity".into())
    }

    fn cx(&self) -> Test<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:agent-onvif-contract".into(),
            operation_id: OperationId::parse("operation:agent-onvif-contract")?,
            principal: PRINCIPAL.into(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(128 * 1024 * 1024)
                .storage_operations(16_384)
                .build()?,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority_read_only(
            &authority, &self.0,
        )?)
    }

    fn retain(&self, bytes: &[u8], interpretation: Interpretation) -> Test<TrackSourcePin> {
        let cx = self.cx()?;
        let mut deployment = ReferenceDeployment::open(&self.0, SITE, &cx)?;
        let source = retain_with_interpretation(
            &mut deployment,
            SourceBinding {
                sensor_id: SensorId::parse("sensor:agent-onvif")?,
                device_generation: ContentDigest::sha256(b"agent-onvif-device"),
                profile_generation: ContentDigest::sha256(b"agent-onvif-profile"),
                profile_token: "private_agent_onvif_profile".into(),
                receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
            },
            bytes,
            interpretation,
            &cx,
        )?;
        Ok(TrackSourcePin::Xml {
            identity: source.identity(),
            root: source.publication_root(),
        })
    }

    fn request(&self, pins: &[TrackSourcePin], analysis: OnvifAnalysis) -> Test<OnvifQueryRequest> {
        Ok(OnvifQueryRequest {
            sources: pins.to_vec(),
            analysis,
            max_entries: 32,
            principal: PrincipalId::parse(PRINCIPAL)?,
            expected_anchor: None,
        })
    }

    fn query(&self, request: &OnvifQueryRequest) -> Result<DeploymentOnvifQuery, OnvifQueryError> {
        self.query_with(&HostSpoolIo, request, OnvifQueryLimits::default(), &|| {
            false
        })
    }

    fn query_with(
        &self,
        io: &dyn SpoolIo,
        request: &OnvifQueryRequest,
        limits: OnvifQueryLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<DeploymentOnvifQuery, OnvifQueryError> {
        query_onvif_in_deployment(io, &self.0, request, limits, cancelled)
    }

    fn original_tracks(&self, pins: &[TrackSourcePin]) -> Test<RetainedTracklets> {
        Ok(RetainedTracklets::open(
            &self.0,
            SITE,
            pins,
            TrackReadLimits::default(),
            &self.cx()?,
        )?)
    }

    fn object_path(&self, digest: ContentDigest) -> Test<PathBuf> {
        let cx = self.cx()?;
        let deployment = ReferenceDeployment::open(&self.0, SITE, &cx)?;
        Ok(deployment.publisher().spool().object_path(digest))
    }

    fn retain_rtp(&self, document: &[u8]) -> Test<TrackSourcePin> {
        let cx = self.cx()?;
        let mut deployment = ReferenceDeployment::open(&self.0, SITE, &cx)?;
        let source = rtp::retain(
            &mut deployment,
            &rtp_source(document),
            SourceBinding {
                sensor_id: SensorId::parse("sensor:agent-onvif")?,
                device_generation: ContentDigest::sha256(b"agent-onvif-device"),
                profile_generation: ContentDigest::sha256(b"agent-onvif-profile"),
                profile_token: "private_agent_onvif_profile".into(),
                receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
            },
            RtpMetadataConfig {
                stream: StreamKey {
                    ingress: 17,
                    generation: 3,
                    ssrc: 42,
                },
                payload_type: 107,
                limits: RtpMetadataImportLimits::default(),
                reorder: ReorderLimits::default(),
                metadata: OnvifMetadataLimits::default(),
            },
            &cx,
        )?;
        Ok(TrackSourcePin::Rtp {
            identity: source.identity(),
            root: source.publication_root(),
        })
    }

    fn add_effect(&self, label: &str) -> Test {
        let cx = self.cx()?;
        let mut deployment = ReferenceDeployment::open(&self.0, SITE, &cx)?;
        prepare_effect(&mut deployment, label)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn prepare_effect(deployment: &mut ReferenceDeployment, label: &str) -> Test {
    let intent = EffectIntent::new(
        OperationId::parse(format!("operation:agent-onvif:{label}"))?,
        IdempotencyKey::parse(format!("idempotency:agent-onvif:{label}"))?,
        "fixture:notification",
        ContentDigest::sha256(label.as_bytes()),
        ContentDigest::sha256(b"agent-onvif-effect-authority"),
    )?;
    deployment.effects_mut().prepare(
        intent.clone(),
        ObligationId::parse(format!("obligation:agent-onvif:{label}"))?,
        "notification observed",
        TimestampNs(1),
    )?;
    deployment.effects_mut().transition(
        &intent.operation_id,
        EffectState::Committed,
        TimestampNs(2),
        None,
        None,
    )?;
    Ok(())
}

fn xml(frames: &str) -> Vec<u8> {
    format!(r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics>{frames}</t:VideoAnalytics></t:MetadataStream>"#).into_bytes()
}
fn frame(second: u8, id: &str, left: &str, right: &str, extra: &str) -> String {
    format!(
        r#"<t:Frame UtcTime="2026-11-09T00:00:{second:02}Z" Source="{PRIVATE_MODULE}"><t:Object ObjectId="{id}"><t:Appearance><t:Shape><t:BoundingBox left="{left}" right="{right}" top=".2" bottom=".4"/><t:CenterOfGravity x=".5" y=".5"/></t:Shape></t:Appearance></t:Object>{extra}</t:Frame>"#
    )
}
fn linked_xml() -> Vec<u8> {
    let rename = format!(
        r#"<t:ObjectTree><t:Rename><t:from ObjectId="{FIRST_ID}"/><t:to ObjectId="{SECOND_ID}"/></t:Rename></t:ObjectTree>"#
    );
    xml(&(frame(0, FIRST_ID, "2", "3", "") + &frame(1, SECOND_ID, ".2", ".4", &rename)))
}

fn rtp_source(document: &[u8]) -> Vec<u8> {
    let mut source = b"#!rtpplay1.0 192.0.2.1/5004\n".to_vec();
    source.extend_from_slice(&[0; 16]);
    for (index, (marker, payload)) in [
        (false, b"unknown-start".as_slice()),
        (true, b"unknown-end".as_slice()),
        (true, document),
    ]
    .into_iter()
    .enumerate()
    {
        let sequence = 100 + index as u16;
        let mut packet = vec![0x80, 107 | if marker { 0x80 } else { 0 }];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 1000).to_be_bytes());
        packet.extend_from_slice(&42_u32.to_be_bytes());
        packet.extend_from_slice(payload);
        source.extend_from_slice(&((packet.len() + 8) as u16).to_be_bytes());
        source.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        source.extend_from_slice(&(index as u32).to_be_bytes());
        source.extend_from_slice(&packet);
    }
    source
}
fn policy(tracks: &RetainedTracklets) -> Test<ZonePolicy> {
    let frame = tracks.report().frames.first().ok_or("fixture frame")?;
    let object = tracks
        .report()
        .occurrences
        .first()
        .ok_or("fixture occurrence")?;
    Ok(ZonePolicy {
        zones: vec![VendorZone {
            id: "operator-declared-entry-zone".into(),
            scope: frame.reference.scope,
            module_digest: frame.module_digest.ok_or("fixture module")?,
            frame_transform_digest: frame.transformation_digest,
            object_transform_digest: object.transformation_digest,
            min: [0, 0],
            max: [1_000_000, 1_000_000],
            margin: 0,
        }],
    })
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.is_dir() {
            result.insert(relative, (true, Vec::new()));
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(relative, (false, fs::read(path)?));
        } else {
            return Err("unexpected special fixture entry".into());
        }
    }
    Ok(result)
}

#[test]
fn all_three_queries_equal_original_retained_projectors_and_preserve_uncertainty() -> Test {
    let fixture = Fixture::new("original-projectors")?;
    let pin = fixture.retain(&linked_xml(), Interpretation::AnalyticsV2)?;
    let original = fixture.original_tracks(&[pin])?;
    let zone_policy = policy(&original)?;
    let original_lifecycle = RetainedLifecycle::open(
        &fixture.0,
        SITE,
        &[pin],
        LifecycleReadLimits::default(),
        &fixture.cx()?,
    )?;
    let original_zones = RetainedZones::open(
        &fixture.0,
        SITE,
        &[pin],
        &zone_policy,
        ZoneReadLimits::default(),
        &fixture.cx()?,
    )?;
    let before = tree(&fixture.0)?;
    for analysis in [
        OnvifAnalysis::Tracks,
        OnvifAnalysis::Lifecycle,
        OnvifAnalysis::Zones(zone_policy),
    ] {
        let request = fixture.request(&[pin], analysis)?;
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let query = fixture.query_with(&io, &request, OnvifQueryLimits::default(), &|| false)?;
        assert_eq!(query.native.tracks, *original.report());
        assert_eq!(query.native.sources, original.sources());
        match &query.native.analysis {
            OnvifAnalysisResult::Tracks => {}
            OnvifAnalysisResult::Lifecycle {
                report, documents, ..
            } => {
                assert_eq!(report, original_lifecycle.report());
                assert_eq!(documents, original_lifecycle.documents());
            }
            OnvifAnalysisResult::Zones(report) => assert_eq!(report, original_zones.report()),
        }
        assert_eq!(query.native.read_usage.completed_roots, 2);
        assert_eq!(query.native.read_usage.io_calls, io.calls().len() as u64);
        assert!(io.is_read_only());
        assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
        assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
        assert!(!query.snapshot.doctor_inspected);
        assert!(query.deployment_bytes_read > 0 && query.deployment_metadata_reads > 0);
        let epistemic = query.epistemic(&request);
        let physical = epistemic
            .propositions
            .iter()
            .find(|p| p.id == "claim:onvif:physical-observability")
            .ok_or("physical scope")?;
        assert_eq!(physical.state, KnowledgeState::Unknown);
        assert!(
            epistemic
                .propositions
                .iter()
                .any(|p| p.state == KnowledgeState::Redacted)
        );
        let statements = epistemic
            .propositions
            .iter()
            .map(|p| p.statement.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for withheld in [
            PRIVATE_MODULE,
            FIRST_ID,
            SECOND_ID,
            "private_agent_onvif_profile",
            "2026-11-09T",
        ] {
            assert!(
                !statements.contains(withheld),
                "unexpected vendor disclosure: {withheld}"
            );
        }
        assert_eq!(query.coverage().omitted_count, 0);
        assert_eq!(
            query.coverage().stop_reason,
            "explicit_pinned_sources_exhausted"
        );
        let again = fixture.query(&request)?;
        assert_eq!(query.request_digest, again.request_digest);
        assert_eq!(query.decision_digest, again.decision_digest);
        assert_eq!(tree(&fixture.0)?, before);
    }
    Ok(())
}

#[test]
fn retained_rtp_canonical_queries_preserve_original_packets_documents_and_projections() -> Test {
    let fixture = Fixture::new("rtp-context")?;
    let pin = fixture.retain_rtp(&linked_xml())?;
    let original = fixture.original_tracks(&[pin])?;
    let zone_policy = policy(&original)?;
    let lifecycle = RetainedLifecycle::open(
        &fixture.0,
        SITE,
        &[pin],
        LifecycleReadLimits::default(),
        &fixture.cx()?,
    )?;
    let zones = RetainedZones::open(
        &fixture.0,
        SITE,
        &[pin],
        &zone_policy,
        ZoneReadLimits::default(),
        &fixture.cx()?,
    )?;
    let before = tree(&fixture.0)?;
    for analysis in [
        OnvifAnalysis::Tracks,
        OnvifAnalysis::Lifecycle,
        OnvifAnalysis::Zones(zone_policy),
    ] {
        let request = fixture.request(&[pin], analysis)?;
        let result = fixture.query(&request)?;
        assert_eq!(result.native.sources, original.sources());
        assert_eq!(result.native.tracks, *original.report());
        assert_eq!(result.native.sources[0].documents, 1);
        assert_eq!(result.native.read_usage.completed_roots, 2);
        match &result.native.analysis {
            OnvifAnalysisResult::Tracks => {}
            OnvifAnalysisResult::Lifecycle {
                report, documents, ..
            } => {
                assert_eq!(report, lifecycle.report());
                assert_eq!(documents, lifecycle.documents());
            }
            OnvifAnalysisResult::Zones(report) => assert_eq!(report, zones.report()),
        }
        assert_eq!(tree(&fixture.0)?, before);
    }
    Ok(())
}

#[test]
fn frozen_event_and_empty_sources_remain_explicit_without_analytics_upgrade() -> Test {
    let fixture = Fixture::new("frozen-empty")?;
    let frozen = fixture.retain(&linked_xml(), Interpretation::EventsV1)?;
    let empty = fixture.retain(&xml(""), Interpretation::AnalyticsV2)?;
    let pins = [frozen, empty];
    let request = fixture.request(&pins, OnvifAnalysis::Lifecycle)?;
    let query = fixture.query(&request)?;
    assert_eq!(
        query
            .native
            .sources
            .iter()
            .map(|s| s.pin)
            .collect::<Vec<_>>(),
        pins
    );
    assert!(query.native.tracks.frames.is_empty());
    assert!(query.native.tracks.occurrences.is_empty());
    assert!(query.native.tracks.tracklets.is_empty());
    let OnvifAnalysisResult::Lifecycle {
        report, documents, ..
    } = &query.native.analysis
    else {
        return Err("missing lifecycle result".into());
    };
    assert!(report.operations.is_empty());
    assert_eq!(
        documents.iter().map(|d| d.state).collect::<Vec<_>>(),
        [
            LifecycleDocumentState::FrozenEventsV1,
            LifecycleDocumentState::ParsedEmpty
        ]
    );
    assert_eq!(query.native.read_usage.completed_roots, 4);
    assert!(
        query
            .native
            .reference_digests
            .contains(&ContentDigest::sha256(&xml("")))
    );
    let reversed = fixture.query(&fixture.request(&[empty, frozen], OnvifAnalysis::Lifecycle)?)?;
    assert_ne!(query.native.request_digest, reversed.native.request_digest);
    assert_ne!(query.decision_digest, reversed.decision_digest);
    assert_eq!(reversed.native.sources[0].pin, empty);
    Ok(())
}

#[test]
fn complete_semantic_row_limit_refuses_instead_of_dropping_source_or_occurrence_rows() -> Test {
    let fixture = Fixture::new("complete-rows")?;
    let pin = fixture.retain(&linked_xml(), Interpretation::AnalyticsV2)?;
    let mut request = fixture.request(&[pin], OnvifAnalysis::Tracks)?;
    // One source, two frames, two occurrences, and two separate original runs.
    request.max_entries = 7;
    let complete = fixture.query(&request)?;
    assert_eq!(complete.epistemic(&request).propositions.len(), 7 + 3);
    request.max_entries = 6;
    let before = tree(&fixture.0)?;
    assert!(matches!(
        fixture.query(&request),
        Err(OnvifQueryError::ResultLimit)
    ));
    assert_eq!(tree(&fixture.0)?, before);
    Ok(())
}

#[test]
fn live_writer_and_unobserved_committed_effect_are_neither_locked_nor_reconciled_by_query() -> Test
{
    let fixture = Fixture::new("live-writer")?;
    let pin = fixture.retain(&linked_xml(), Interpretation::AnalyticsV2)?;
    let request = fixture.request(&[pin], OnvifAnalysis::Tracks)?;
    let cx = fixture.cx()?;
    let mut writer = ReferenceDeployment::open(&fixture.0, SITE, &cx)?;
    prepare_effect(&mut writer, "unobserved")?;
    let effect_records = writer.effects().committed_len();
    let before = tree(&fixture.0)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let query = fixture.query_with(&io, &request, OnvifQueryLimits::default(), &|| false)?;
    assert_eq!(query.native.tracks.occurrences.len(), 2);
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
    assert_eq!(writer.effects().committed_len(), effect_records);
    assert_eq!(tree(&fixture.0)?, before);
    drop(writer);
    // The cold read also avoids the ordinary open's restart reconciliation.
    let cold_before = tree(&fixture.0)?;
    assert_eq!(
        fixture.query(&request)?.decision_digest,
        query.decision_digest
    );
    assert_eq!(tree(&fixture.0)?, cold_before);
    Ok(())
}

#[test]
fn expected_anchor_and_principal_bind_context_without_changing_native_claims() -> Test {
    let fixture = Fixture::new("context-identity")?;
    let pin = fixture.retain(&linked_xml(), Interpretation::AnalyticsV2)?;
    let mut request = fixture.request(&[pin], OnvifAnalysis::Tracks)?;
    let first = fixture.query(&request)?;
    request.principal = PrincipalId::parse("principal:another-onvif-audit-label")?;
    let other = fixture.query(&request)?;
    assert_eq!(first.native.tracks, other.native.tracks);
    assert_eq!(first.native.decision_digest, other.native.decision_digest);
    assert_ne!(first.request_digest, other.request_digest);
    assert_ne!(first.session_id, other.session_id);
    request.expected_anchor = Some(AnchorToken::parse(&first.anchor_token).ok_or("anchor token")?);
    fixture.retain(&xml(""), Interpretation::AnalyticsV2)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    assert!(matches!(
        fixture.query_with(&io, &request, OnvifQueryLimits::default(), &|| false),
        Err(OnvifQueryError::AnchorChanged)
    ));
    assert!(io.calls().is_empty());
    request.expected_anchor = None;
    let current = fixture.query(&request)?;
    assert_ne!(current.anchor_token, first.anchor_token);
    assert_eq!(current.native.tracks, first.native.tracks);
    Ok(())
}

#[test]
fn final_caller_checkpoint_cannot_change_effect_history_after_its_last_verification() -> Test {
    let fixture = Fixture::new("late-effect")?;
    let pin = fixture.retain(&linked_xml(), Interpretation::AnalyticsV2)?;
    let request = fixture.request(&[pin], OnvifAnalysis::Tracks)?;
    let observed = AtomicUsize::new(0);
    fixture.query_with(&HostSpoolIo, &request, OnvifQueryLimits::default(), &|| {
        observed.fetch_add(1, Ordering::SeqCst);
        false
    })?;
    let last = observed.load(Ordering::SeqCst);
    assert!(last > 2);
    let seen = AtomicUsize::new(0);
    let changed = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    let result = fixture.query_with(&HostSpoolIo, &request, OnvifQueryLimits::default(), &|| {
        if seen.fetch_add(1, Ordering::SeqCst) + 1 == last {
            changed.store(true, Ordering::SeqCst);
            failed.store(
                fixture.add_effect("late-context-change").is_err(),
                Ordering::SeqCst,
            );
        }
        false
    });
    assert!(changed.load(Ordering::SeqCst));
    assert!(!failed.load(Ordering::SeqCst));
    assert!(
        matches!(result, Err(OnvifQueryError::AnchorChanged)),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn deletion_of_a_selected_empty_source_never_becomes_a_successful_empty_analysis() -> Test {
    let fixture = Fixture::new("deleted-empty")?;
    let pin = fixture.retain(&linked_xml(), Interpretation::AnalyticsV2)?;
    let empty = fixture.retain(&xml(""), Interpretation::AnalyticsV2)?;
    let request = fixture.request(&[pin, empty], OnvifAnalysis::Lifecycle)?;
    assert_eq!(fixture.query(&request)?.native.sources.len(), 2);
    {
        let cx = fixture.cx()?;
        let mut deployment = ReferenceDeployment::open(&fixture.0, SITE, &cx)?;
        let plan = plan_deletion(&deployment, empty.identity(), &cx)?;
        assert!(plan.blockers.is_empty());
        commit_deletion(
            &mut deployment,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &cx,
        )?;
    }
    let before = tree(&fixture.0)?;
    assert!(fixture.query(&request).is_err());
    assert_eq!(tree(&fixture.0)?, before);
    Ok(())
}

#[test]
fn all_source_passes_share_exact_byte_io_root_and_work_allowances() -> Test {
    let fixture = Fixture::new("source-budgets")?;
    let pin = fixture.retain(&linked_xml(), Interpretation::AnalyticsV2)?;
    let empty = fixture.retain(&xml(""), Interpretation::AnalyticsV2)?;
    let request = fixture.request(&[pin, empty], OnvifAnalysis::Lifecycle)?;
    let baseline = fixture.query(&request)?;
    let used = baseline.native.read_usage;
    let mut exact = OnvifQueryLimits::default();
    exact.source.custody.max_read_bytes = used.peak_reserved_read_bytes;
    exact.source.custody.max_io_calls = used.io_calls;
    exact.source.custody.max_catalogue_entries = used.completed_roots;
    exact.source.custody.max_objects = used.objects;
    exact.source.custody.max_edges = used.edges;
    exact.source.max_work_units = baseline.native.reserved_work_units;
    let bounded = fixture.query_with(&HostSpoolIo, &request, exact, &|| false)?;
    assert_eq!(bounded.native.read_usage, used);
    assert_eq!(
        bounded.native.reserved_work_units,
        baseline.native.reserved_work_units
    );
    assert_eq!(bounded.native.tracks, baseline.native.tracks);
    assert_eq!(bounded.native.analysis, baseline.native.analysis);
    assert_ne!(bounded.request_digest, baseline.request_digest);
    for dimension in 0..6 {
        let mut too_small = exact;
        match dimension {
            0 => too_small.source.custody.max_read_bytes -= 1,
            1 => too_small.source.custody.max_io_calls -= 1,
            2 => too_small.source.custody.max_catalogue_entries -= 1,
            3 => too_small.source.custody.max_objects -= 1,
            4 => too_small.source.custody.max_edges -= 1,
            5 => too_small.source.max_work_units -= 1,
            _ => return Err("unexpected fixture resource dimension".into()),
        }
        assert!(
            fixture
                .query_with(&HostSpoolIo, &request, too_small, &|| false)
                .is_err(),
            "one-unit-short resource dimension {dimension} returned success"
        );
    }
    Ok(())
}

#[test]
fn deployment_metadata_rereads_share_one_budget_and_do_not_refill_after_sources() -> Test {
    let fixture = Fixture::new("history-budgets")?;
    let pin = fixture.retain(&linked_xml(), Interpretation::AnalyticsV2)?;
    let request = fixture.request(&[pin], OnvifAnalysis::Tracks)?;
    let baseline = fixture.query(&request)?;
    let exact = OnvifQueryLimits {
        // An absent optional metadata file still needs one byte for its bounded probe.
        deployment_bytes: usize::try_from(baseline.deployment_bytes_read)? + 1,
        deployment_reads: usize::try_from(baseline.deployment_metadata_reads)?,
        ..OnvifQueryLimits::default()
    };
    let bounded = fixture.query_with(&HostSpoolIo, &request, exact, &|| false)?;
    assert_eq!(
        bounded.deployment_bytes_read,
        baseline.deployment_bytes_read
    );
    assert_eq!(
        bounded.deployment_metadata_reads,
        baseline.deployment_metadata_reads
    );
    assert_eq!(
        bounded.native.decision_digest,
        baseline.native.decision_digest
    );
    assert_ne!(bounded.request_digest, baseline.request_digest);
    for too_small in [
        OnvifQueryLimits {
            deployment_bytes: exact.deployment_bytes - 1,
            ..exact
        },
        OnvifQueryLimits {
            deployment_reads: exact.deployment_reads - 1,
            ..exact
        },
    ] {
        assert!(
            fixture
                .query_with(&HostSpoolIo, &request, too_small, &|| false)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn initial_and_late_cancellation_return_no_native_or_context_result() -> Test {
    let fixture = Fixture::new("cancellation")?;
    let pin = fixture.retain(&linked_xml(), Interpretation::AnalyticsV2)?;
    let request = fixture.request(&[pin], OnvifAnalysis::Tracks)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    assert!(matches!(
        fixture.query_with(&io, &request, OnvifQueryLimits::default(), &|| true),
        Err(OnvifQueryError::Cancelled)
    ));
    assert!(io.calls().is_empty());
    let calls = AtomicUsize::new(0);
    fixture.query_with(&HostSpoolIo, &request, OnvifQueryLimits::default(), &|| {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    })?;
    let last = calls.load(Ordering::SeqCst);
    let before = tree(&fixture.0)?;
    for stop in [2, last / 2, last] {
        let seen = AtomicUsize::new(0);
        let result =
            fixture.query_with(&HostSpoolIo, &request, OnvifQueryLimits::default(), &|| {
                seen.fetch_add(1, Ordering::SeqCst) + 1 >= stop
            });
        assert!(
            result.is_err(),
            "cancellation checkpoint {stop} released a result"
        );
        assert_eq!(tree(&fixture.0)?, before);
    }
    Ok(())
}

#[test]
fn invalid_pins_missing_store_and_corrupt_later_empty_source_never_create_or_repair_files() -> Test
{
    let fixture = Fixture::new("refusals")?;
    let pin = fixture.retain(&linked_xml(), Interpretation::AnalyticsV2)?;
    let mut request = fixture.request(&[pin, pin], OnvifAnalysis::Tracks)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    assert!(
        fixture
            .query_with(&io, &request, OnvifQueryLimits::default(), &|| false)
            .is_err()
    );
    assert!(io.calls().is_empty());
    request.sources = vec![pin];
    let missing = fixture.0.join("not-a-deployment");
    assert!(
        query_onvif_in_deployment(
            &io,
            &missing,
            &request,
            OnvifQueryLimits::default(),
            &|| false
        )
        .is_err()
    );
    assert!(!missing.exists());
    let empty_bytes = xml("");
    let empty = fixture.retain(&empty_bytes, Interpretation::AnalyticsV2)?;
    request.sources.push(empty);
    assert_eq!(fixture.query(&request)?.native.sources.len(), 2);
    fs::write(
        fixture.object_path(ContentDigest::sha256(&empty_bytes))?,
        b"corrupt selected empty source",
    )?;
    let before = tree(&fixture.0)?;
    assert!(fixture.query(&request).is_err());
    assert_eq!(tree(&fixture.0)?, before);
    Ok(())
}
