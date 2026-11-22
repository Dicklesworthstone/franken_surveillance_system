#![forbid(unsafe_code)]
//! Real retained XML/RTP -> vendor tracklets, custody refusals and one cumulative query budget.
//! These finite fixtures establish no camera identity, physical continuity or coverage.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, EffectIntent, EffectState,
    IdempotencyKey, ObligationId, OperationId, Plane, ProvenanceClass, RootAuthoritySpec, SensorId,
    TimestampNs,
};
use fss_object::{HostSpoolIo, RecordingSpoolIo};
use fss_packet::{OnvifMetadataLimits, ReorderLimits, StreamKey};
use fss_reference::deletion::{commit_deletion, plan_deletion};
use fss_reference::onvif::metadata::lifecycle::{LifecycleReadLimits, RetainedLifecycle};
use fss_reference::onvif::metadata::native_read::{
    NativeOnvifRead, NativeOnvifReadLimits, OnvifAnalysis, OnvifAnalysisResult,
};
use fss_reference::onvif::metadata::rtp::{self, RtpMetadataConfig, RtpMetadataImportLimits};
use fss_reference::onvif::metadata::tracks::{
    RetainedTrackError, RetainedTracklets, TrackReadLimits, TrackSourcePin,
};
use fss_reference::onvif::metadata::zones::contract::VendorZone;
use fss_reference::onvif::metadata::zones::{RetainedZones, ZonePolicy, ZoneReadLimits};
use fss_reference::onvif::metadata::{MetadataError, SourceBinding, retain};
use fss_reference::{ReferenceDeployment, ReplayAdmissionError, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-tracklets-test";
const PRINCIPAL: &str = "operator:onvif-tracklets-test";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let root = std::env::temp_dir().join(format!(
                "fss-onvif-tracks-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture directory capacity".into())
    }
    fn cx(&self) -> Test<ReplayCx> {
        context(&self.0)
    }
    fn xml(&self, xml: &[u8]) -> Test<TrackSourcePin> {
        let cx = self.cx()?;
        let mut deployment = ReferenceDeployment::open(&self.0, SITE, &cx)?;
        let source = retain(&mut deployment, binding()?, xml, &cx)?;
        Ok(TrackSourcePin::Xml {
            identity: source.identity(),
            root: source.publication_root(),
        })
    }
    fn rtp(&self, documents: &[Vec<u8>]) -> Test<TrackSourcePin> {
        let cx = self.cx()?;
        let mut deployment = ReferenceDeployment::open(&self.0, SITE, &cx)?;
        let source = rtp::retain(
            &mut deployment,
            &rtp_source(documents),
            binding()?,
            config(),
            &cx,
        )?;
        Ok(TrackSourcePin::Rtp {
            identity: source.identity(),
            root: source.publication_root(),
        })
    }
    fn query(&self, pins: &[TrackSourcePin], limits: TrackReadLimits) -> Test<RetainedTracklets> {
        Ok(RetainedTracklets::open(
            &self.0,
            SITE,
            pins,
            limits,
            &self.cx()?,
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:onvif-tracklets-test".into(),
        operation_id: OperationId::parse("operation:onvif-tracklets-test")?,
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
        &authority, root,
    )?)
}
fn binding() -> Test<SourceBinding> {
    Ok(SourceBinding {
        sensor_id: SensorId::parse("sensor:front")?,
        device_generation: ContentDigest::sha256(b"device-generation"),
        profile_generation: ContentDigest::sha256(b"profile-generation"),
        profile_token: "private-profile-token".into(),
        receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
    })
}
fn frame(second: u8) -> String {
    format!(
        r#"<t:Frame UtcTime="2026-10-28T00:00:{second:02}Z" Source="private-analytics-module"><t:Object ObjectId="8675309"><t:Appearance><t:Class><t:Type Likelihood="0.8">PrivateVendorClass</t:Type></t:Class></t:Appearance></t:Object></t:Frame>"#
    )
}
fn xml(seconds: &[u8], extension: &str) -> Vec<u8> {
    let frames: String = seconds.iter().map(|second| frame(*second)).collect();
    format!(r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics>{frames}</t:VideoAnalytics>{extension}</t:MetadataStream>"#).into_bytes()
}
fn config() -> RtpMetadataConfig {
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
    }
}
fn packet(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![0x80, 107 | if marker { 0x80 } else { 0 }];
    result.extend_from_slice(&sequence.to_be_bytes());
    result.extend_from_slice(&(u32::from(sequence) * 1000).to_be_bytes());
    result.extend_from_slice(&42_u32.to_be_bytes());
    result.extend_from_slice(payload);
    result
}
fn rtp_source(documents: &[Vec<u8>]) -> Vec<u8> {
    let mut result = b"#!rtpplay1.0 192.0.2.1/5004\n".to_vec();
    result.extend_from_slice(&[0; 16]);
    let mut packets = vec![
        packet(100, false, b"unknown-start"),
        packet(101, true, b"unknown-end"),
    ];
    for (index, document) in documents.iter().enumerate() {
        packets.push(packet(102 + index as u16, true, document));
    }
    for (index, bytes) in packets.iter().enumerate() {
        result.extend_from_slice(&((bytes.len() + 8) as u16).to_be_bytes());
        result.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        result.extend_from_slice(&(index as u32).to_be_bytes());
        result.extend_from_slice(bytes);
    }
    result
}

#[test]
fn cold_xml_groups_claims_and_preserves_all_source_occurrences() -> Test {
    let dir = Directory::new("xml-cold")?;
    let pin = dir.xml(&xml(&[0, 1, 2], ""))?;
    let result = dir.query(&[pin], TrackReadLimits::default())?;
    assert_eq!(result.report().frames.len(), 3);
    assert_eq!(result.report().occurrences.len(), 3);
    assert_eq!(result.report().tracklets.len(), 1);
    assert_eq!(result.report().tracklets[0].occurrence_indices, [0, 1, 2]);
    assert_eq!(result.report().occurrences[1].vendor_object_id, "8675309");
    assert_eq!(result.sources()[0].pin, pin);
    assert_eq!(result.sources()[0].analytics_frames, 3);
    assert_eq!(result.plane(), Plane::Cognition);
    assert_eq!(result.provenance(), ProvenanceClass::Derived);
    assert_eq!(
        result.observation_provenance(),
        ProvenanceClass::VendorClaimed
    );
    assert!(result.usage().indexed_reads.used_bytes > 0);
    assert!(result.usage().indexed_reads.used_read_attempts >= 8);
    assert!(result.usage().reserved_work_units >= 4_000_000);
    let debug = format!("{result:?}");
    for private in [
        "8675309",
        "private-analytics-module",
        "PrivateVendorClass",
        "private-profile-token",
    ] {
        assert!(!debug.contains(private));
    }
    let cold = dir.query(&[pin], TrackReadLimits::default())?;
    assert_eq!(cold.digest(), result.digest());
    assert_eq!(cold.report(), result.report());
    Ok(())
}

#[test]
fn ordered_independent_imports_are_explicit_continuity_barriers() -> Test {
    let dir = Directory::new("ordered-files")?;
    let first = dir.xml(&xml(&[0, 1], ""))?;
    let second = dir.xml(&xml(&[2, 3], ""))?;
    let result = dir.query(&[first, second], TrackReadLimits::default())?;
    assert_eq!(result.report().tracklets.len(), 2);
    assert_eq!(result.report().occurrences.len(), 4);
    assert_eq!(result.sources()[0].scope, result.sources()[1].scope);
    assert_eq!(
        result.report().frames[2].reference.source_identity,
        second.identity()
    );
    assert!(
        result.report().frames[2]
            .barriers
            .iter()
            .any(|reason| reason.as_str() == "source_boundary")
    );
    assert!(matches!(
        RetainedTracklets::open(
            &dir.0,
            SITE,
            &[first, first],
            TrackReadLimits::default(),
            &dir.cx()?
        ),
        Err(RetainedTrackError::InvalidRequest)
    ));
    Ok(())
}

#[test]
fn rtp_links_only_adjacent_complete_documents_with_original_source_handles() -> Test {
    let dir = Directory::new("rtp-documents")?;
    let docs = [xml(&[0], ""), xml(&[1], ""), xml(&[2], "")];
    let pin = dir.rtp(&docs)?;
    let result = dir.query(&[pin], TrackReadLimits::default())?;
    assert!(result.sources()[0].source_processing_complete);
    assert_eq!(result.sources()[0].documents, 3);
    assert_eq!(result.report().tracklets.len(), 1);
    for (index, frame) in result.report().frames.iter().enumerate() {
        assert_eq!(frame.reference.source_identity, pin.identity());
        assert_eq!(frame.reference.source_root, pin.root());
        assert_eq!(
            frame.reference.source_digest,
            ContentDigest::sha256(&docs[index])
        );
        assert_eq!(frame.reference.document_index, index);
        assert_eq!(frame.reference.frame_index, 0);
    }
    Ok(())
}

#[test]
fn rtp_empty_rejected_and_opaque_documents_never_bridge_repeated_ids() -> Test {
    for (label, middle) in [
        ("empty", xml(&[], "")),
        ("rejected", b"<not-xml".to_vec()),
        ("opaque", xml(&[], "<t:Extension/>")),
    ] {
        let dir = Directory::new(label)?;
        let pin = dir.rtp(&[xml(&[0], ""), middle, xml(&[2], "")])?;
        let result = dir.query(&[pin], TrackReadLimits::default())?;
        assert_eq!(result.report().occurrences.len(), 2);
        assert_eq!(result.report().tracklets.len(), 2, "{label}");
        assert_eq!(result.sources()[0].empty_analytics_documents, 1);
        assert_eq!(
            result.sources()[0].rejected_documents,
            usize::from(label == "rejected")
        );
    }
    Ok(())
}

#[test]
fn outer_unknown_lifecycle_content_prevents_linkage_even_within_one_xml() -> Test {
    let dir = Directory::new("opaque-lifecycle")?;
    let pin = dir.xml(&xml(&[0, 1], "<t:Extension/>"))?;
    let result = dir.query(&[pin], TrackReadLimits::default())?;
    assert_eq!(result.sources()[0].uninterpreted_documents, 1);
    assert_eq!(result.report().tracklets.len(), 2);
    Ok(())
}

#[test]
fn aggregate_read_attempt_byte_and_work_caps_cover_the_second_complete_pass() -> Test {
    let dir = Directory::new("two-pass-budget")?;
    let pin = dir.xml(&xml(&[0, 1], ""))?;
    let base = TrackReadLimits::default();
    let completed = dir.query(&[pin], base)?;
    let usage = completed.usage();
    for limits in [
        TrackReadLimits {
            max_stored_bytes: usage.indexed_reads.used_bytes - 1,
            ..base
        },
        TrackReadLimits {
            max_indexed_reads: usage.indexed_reads.used_read_attempts - 1,
            ..base
        },
        TrackReadLimits {
            max_work_units: usage.reserved_work_units - 1,
            ..base
        },
    ] {
        assert!(RetainedTracklets::open(&dir.0, SITE, &[pin], limits, &dir.cx()?).is_err());
    }
    // Exact admitted balances succeed and cannot hide a budget refill during revalidation.
    let exact = TrackReadLimits {
        max_stored_bytes: usage.indexed_reads.used_bytes,
        max_indexed_reads: usage.indexed_reads.used_read_attempts,
        max_work_units: usage.reserved_work_units,
        ..base
    };
    assert_eq!(
        dir.query(&[pin], exact)?.usage().reserved_work_units,
        usage.reserved_work_units
    );
    Ok(())
}

#[test]
fn missing_existing_store_wrong_root_and_empty_request_fail_without_initialization() -> Test {
    let dir = Directory::new("existing-only")?;
    let missing = dir.0.join("missing");
    let pin = TrackSourcePin::Xml {
        identity: ContentDigest::sha256(b"identity"),
        root: ContentDigest::sha256(b"root"),
    };
    assert!(
        RetainedTracklets::open(
            &missing,
            SITE,
            &[pin],
            TrackReadLimits::default(),
            &context(&missing)?
        )
        .is_err()
    );
    assert!(!missing.exists());
    assert!(
        RetainedTracklets::open(&dir.0, SITE, &[], TrackReadLimits::default(), &dir.cx()?).is_err()
    );
    assert_eq!(fs::read_dir(&dir.0)?.count(), 0);
    let retained = dir.xml(&xml(&[0], ""))?;
    let wrong = TrackSourcePin::Xml {
        identity: retained.identity(),
        root: pin.root(),
    };
    assert!(
        RetainedTracklets::open(
            &dir.0,
            SITE,
            &[wrong],
            TrackReadLimits::default(),
            &dir.cx()?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn revalidation_checks_a_later_source_even_when_it_has_no_analytics() -> Test {
    let dir = Directory::new("later-source-change")?;
    let first = dir.xml(&xml(&[0, 1], ""))?;
    let empty_xml = xml(&[], "");
    let empty = dir.xml(&empty_xml)?;
    let source_path = {
        let cx = dir.cx()?;
        let deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        deployment
            .publisher()
            .spool()
            .object_path(ContentDigest::sha256(&empty_xml))
    };
    let changed = Cell::new(false);
    let cx = dir.cx()?.with_admission(|stage| {
        if stage == "onvif_tracks:revalidate" && !changed.replace(true) {
            fs::write(&source_path, b"changed retained source")
                .map_err(|_| ReplayAdmissionError::Authority)?;
        }
        Ok(())
    });
    assert!(
        RetainedTracklets::open(
            &dir.0,
            SITE,
            &[first, empty],
            TrackReadLimits::default(),
            &cx
        )
        .is_err()
    );
    assert!(changed.get());
    Ok(())
}

#[test]
fn deleted_later_empty_source_is_not_silently_dropped_from_request() -> Test {
    let dir = Directory::new("later-deletion")?;
    let first = dir.xml(&xml(&[0], ""))?;
    let empty = dir.xml(&xml(&[], ""))?;
    {
        let cx = dir.cx()?;
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
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
    let refusal = RetainedTracklets::open(
        &dir.0,
        SITE,
        &[first, empty],
        TrackReadLimits::default(),
        &dir.cx()?,
    );
    assert!(
        matches!(refusal, Err(RetainedTrackError::Source(error)) if matches!(*error, MetadataError::EvidenceDeleted { .. }))
    );
    Ok(())
}

#[test]
fn cooperative_cancellation_on_revalidation_releases_no_partial_track_report() -> Test {
    let dir = Directory::new("cancel-revalidation")?;
    let pin = dir.xml(&xml(&[0, 1], ""))?;
    let cx = dir.cx()?.with_admission(|stage| {
        if stage == "onvif_tracks:revalidate" {
            Err(ReplayAdmissionError::Cancelled)
        } else {
            Ok(())
        }
    });
    assert!(matches!(
        RetainedTracklets::open(&dir.0, SITE, &[pin], TrackReadLimits::default(), &cx),
        Err(RetainedTrackError::Cancelled)
    ));
    Ok(())
}

#[test]
fn final_admission_cannot_change_durable_authority_after_the_last_check() -> Test {
    let dir = Directory::new("final-authority-change")?;
    let pin = dir.xml(&xml(&[0, 1], ""))?;
    let changed = Cell::new(false);
    let cx = dir.cx()?.with_admission(|stage| {
        if stage == "onvif_tracks:complete" && !changed.replace(true) {
            let mut journal = fs::OpenOptions::new()
                .append(true)
                .open(dir.0.join("ledger/journal.fssj"))
                .map_err(|_| ReplayAdmissionError::Authority)?;
            journal
                .write_all(b"uncommitted-tail")
                .map_err(|_| ReplayAdmissionError::Authority)?;
        }
        Ok(())
    });
    assert!(matches!(
        RetainedTracklets::open(&dir.0, SITE, &[pin], TrackReadLimits::default(), &cx),
        Err(RetainedTrackError::Mismatch)
    ));
    assert!(changed.get());
    Ok(())
}

#[test]
fn aggregate_shape_refuses_before_reading_the_next_retained_source() -> Test {
    let dir = Directory::new("early-shape-bound")?;
    let first = dir.xml(&xml(&[0, 1], ""))?;
    let second = dir.xml(&xml(&[2], ""))?;
    let source_admissions = Cell::new(0_usize);
    let cx = dir.cx()?.with_admission(|stage| {
        if stage == "onvif_tracks:source" {
            source_admissions.set(source_admissions.get() + 1);
        }
        Ok(())
    });
    let mut limits = TrackReadLimits::default();
    limits.projection.max_frames = 1;
    assert!(matches!(
        RetainedTracklets::open(&dir.0, SITE, &[first, second], limits, &cx),
        Err(RetainedTrackError::Limit)
    ));
    assert_eq!(source_admissions.get(), 1);
    Ok(())
}

#[test]
fn track_query_does_not_reconcile_prepared_or_committed_effects() -> Test {
    let dir = Directory::new("pending-effects")?;
    let pin = dir.xml(&xml(&[0, 1], ""))?;
    {
        let cx = dir.cx()?;
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        for label in ["prepared", "committed"] {
            let intent = EffectIntent::new(
                OperationId::parse(format!("operation:tracks:{label}"))?,
                IdempotencyKey::parse(format!("idempotency:tracks:{label}"))?,
                "fixture:notification",
                ContentDigest::sha256(label.as_bytes()),
                ContentDigest::sha256(b"track-query-authority"),
            )?;
            deployment.effects_mut().prepare(
                intent.clone(),
                ObligationId::parse(format!("obligation:tracks:{label}"))?,
                "notification observed",
                TimestampNs(1),
            )?;
            if label == "committed" {
                deployment.effects_mut().transition(
                    &intent.operation_id,
                    EffectState::Committed,
                    TimestampNs(2),
                    None,
                    None,
                )?;
            }
        }
    }
    let ledger = dir.0.join("ledger/journal.fssj");
    let effects = dir.0.join("effects/journal.fssj");
    let before = (fs::read(&ledger)?, fs::read(&effects)?);
    assert_eq!(
        dir.query(&[pin], TrackReadLimits::default())?
            .report()
            .tracklets
            .len(),
        1
    );
    assert_eq!(fs::read(ledger)?, before.0);
    assert_eq!(fs::read(effects)?, before.1);
    Ok(())
}


// Include directories and exact file bytes so immutable queries cannot create lock/staging
// entries, repair journals or reconcile effects without this comparison observing the change.
fn immutable_tree(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    fn visit(
        root: &Path,
        path: &Path,
        entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>,
    ) -> Test {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root)?.to_path_buf();
            if entry.file_type()?.is_dir() {
                entries.insert(relative, None);
                visit(root, &path, entries)?;
            } else {
                entries.insert(relative, Some(fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries)?;
    Ok(entries)
}

#[test]
fn immutable_native_full_reports_match_originals_while_capture_holds_writer() -> Test {
    let dir = Directory::new("immutable-native-writer")?;
    let seconds: Vec<u8> = (0..40).collect();
    let xml_pin = dir.xml(&xml(&seconds, ""))?;
    let rtp_pin = dir.rtp(&[
        xml(&[0, 1], ""),
        b"<not-xml".to_vec(),
        xml(&[], ""),
        xml(&[3], ""),
    ])?;
    let empty = dir.xml(&xml(&[], ""))?;
    let pins = [xml_pin, rtp_pin, empty];
    let original = dir.query(&pins, TrackReadLimits::default())?;
    // Native commands return the complete projection, including more than 32 rows. They
    // must not acquire the canonical agent synopsis's deliberately smaller entry ceiling.
    assert!(original.report().frames.len() > 32);
    let first = original.report().frames.first().ok_or("fixture frame")?;
    let object = original
        .report()
        .occurrences
        .first()
        .ok_or("fixture object")?;
    let policy = ZonePolicy {
        zones: vec![VendorZone {
            id: "fixture-zone".into(),
            scope: first.reference.scope,
            module_digest: first.module_digest.ok_or("fixture module")?,
            frame_transform_digest: first.transformation_digest,
            object_transform_digest: object.transformation_digest,
            min: [0, 0],
            max: [1_000_000, 1_000_000],
            margin: 0,
        }],
    };
    let lifecycle = RetainedLifecycle::open(
        &dir.0,
        SITE,
        &pins,
        LifecycleReadLimits::default(),
        &dir.cx()?,
    )?;
    let zones = RetainedZones::open(
        &dir.0,
        SITE,
        &pins,
        &policy,
        ZoneReadLimits::default(),
        &dir.cx()?,
    )?;
    let writer_cx = dir.cx()?;
    let writer = ReferenceDeployment::open(&dir.0, SITE, &writer_cx)?;
    let before = immutable_tree(&dir.0)?;
    for analysis in [
        OnvifAnalysis::Tracks,
        OnvifAnalysis::Lifecycle,
        OnvifAnalysis::Zones(policy),
    ] {
        let actual = NativeOnvifRead::open(
            &dir.0,
            SITE,
            &pins,
            &analysis,
            NativeOnvifReadLimits::default(),
            &dir.cx()?,
        )?;
        assert_eq!(actual.authority_anchor, *writer.current_anchor());
        assert_eq!(&actual.native.tracks, original.report());
        assert_eq!(actual.native.sources, original.sources());
        assert_eq!(actual.native.sources.len(), pins.len());
        assert_eq!(actual.native.sources[2].analytics_frames, 0);
        assert_eq!(actual.native.sources[1].rejected_documents, 1);
        match &actual.native.analysis {
            OnvifAnalysisResult::Tracks => {}
            OnvifAnalysisResult::Lifecycle {
                report, documents, ..
            } => {
                assert_eq!(report, lifecycle.report());
                assert_eq!(documents, lifecycle.documents());
            }
            OnvifAnalysisResult::Zones(report) => assert_eq!(report, zones.report()),
        }
        assert!(actual.native.read_usage.io_calls > 0);
        assert!(actual.deployment_read_bytes > 0);
        assert!(actual.deployment_read_attempts > 0);
        let repeated = NativeOnvifRead::open(
            &dir.0,
            SITE,
            &pins,
            &analysis,
            NativeOnvifReadLimits::default(),
            &dir.cx()?,
        )?;
        assert_eq!(actual.snapshot_digest, repeated.snapshot_digest);
        assert_eq!(immutable_tree(&dir.0)?, before);
    }
    Ok(())
}

#[test]
fn immutable_native_exact_allowances_include_both_passes_and_final_history() -> Test {
    let dir = Directory::new("immutable-native-budget")?;
    let pins = [dir.xml(&xml(&[0, 1], ""))?, dir.xml(&xml(&[], ""))?];
    let analysis = OnvifAnalysis::Lifecycle;
    let measured = NativeOnvifRead::open(
        &dir.0,
        SITE,
        &pins,
        &analysis,
        NativeOnvifReadLimits::default(),
        &dir.cx()?,
    )?;
    let usage = measured.native.read_usage;
    let mut exact = NativeOnvifReadLimits::default();
    // The final empty effects-journal probe still needs one byte of remaining allowance.
    exact.max_deployment_read_bytes = usize::try_from(measured.deployment_read_bytes)? + 1;
    exact.max_deployment_read_attempts =
        usize::try_from(measured.deployment_read_attempts)?;
    exact.source.custody.max_read_bytes = usage.peak_reserved_read_bytes;
    exact.source.custody.max_io_calls = usage.io_calls;
    exact.source.custody.max_catalogue_entries = usage.completed_roots;
    exact.source.custody.max_objects = usage.objects;
    exact.source.custody.max_edges = usage.edges;
    exact.source.max_work_units = measured.native.reserved_work_units;
    let before = immutable_tree(&dir.0)?;
    let admitted = NativeOnvifRead::open(
        &dir.0,
        SITE,
        &pins,
        &analysis,
        exact,
        &dir.cx()?,
    )?;
    assert_eq!(admitted.native.read_usage, usage);
    assert_eq!(
        admitted.native.reserved_work_units,
        measured.native.reserved_work_units
    );
    assert_eq!(admitted.native.tracks, measured.native.tracks);
    assert_eq!(admitted.native.analysis, measured.native.analysis);
    assert_eq!(
        admitted.deployment_read_bytes,
        measured.deployment_read_bytes
    );
    assert_eq!(
        admitted.deployment_read_attempts,
        measured.deployment_read_attempts
    );
    assert_ne!(admitted.snapshot_digest, measured.snapshot_digest);
    for dimension in 0..8 {
        let mut short = exact;
        match dimension {
            0 => short.max_deployment_read_bytes -= 1,
            1 => short.max_deployment_read_attempts -= 1,
            2 => short.source.custody.max_read_bytes -= 1,
            3 => short.source.custody.max_io_calls -= 1,
            4 => short.source.custody.max_catalogue_entries -= 1,
            5 => short.source.custody.max_objects -= 1,
            6 => short.source.custody.max_edges -= 1,
            7 => short.source.max_work_units -= 1,
            _ => return Err("unexpected immutable allowance dimension".into()),
        }
        assert!(
            NativeOnvifRead::open(
                &dir.0,
                SITE,
                &pins,
                &analysis,
                short,
                &dir.cx()?,
            )
            .is_err(),
            "one-unit-short immutable allowance {dimension} released a report"
        );
        assert_eq!(immutable_tree(&dir.0)?, before);
    }
    Ok(())
}

#[test]
fn immutable_native_missing_or_torn_journals_are_refused_without_recovery() -> Test {
    for journal in ["ledger/journal.fssj", "effects/journal.fssj"] {
        for missing in [false, true] {
            let label = format!("immutable-native-{}-{missing}", journal.replace('/', "-"));
            let dir = Directory::new(&label)?;
            let pin = dir.xml(&xml(&[0], ""))?;
            let path = dir.0.join(journal);
            if missing {
                fs::remove_file(&path)?;
            } else {
                fs::OpenOptions::new()
                    .append(true)
                    .open(&path)?
                    .write_all(b"FSS")?;
            }
            let before = immutable_tree(&dir.0)?;
            assert!(
                NativeOnvifRead::open(
                    &dir.0,
                    SITE,
                    &[pin],
                    &OnvifAnalysis::Tracks,
                    NativeOnvifReadLimits::default(),
                    &dir.cx()?,
                )
                .is_err(),
                "accepted incomplete {journal}: missing={missing}"
            );
            assert_eq!(immutable_tree(&dir.0)?, before);
        }
    }
    Ok(())
}

#[test]
fn immutable_native_final_checkpoint_cannot_change_either_journal_after_verification() -> Test {
    for journal in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let dir = Directory::new(&format!(
            "immutable-native-final-{}",
            journal.replace('/', "-")
        ))?;
        let pin = dir.xml(&xml(&[0, 1], ""))?;
        let changed = AtomicBool::new(false);
        let cx = dir.cx()?.with_admission(|stage| {
            if stage == "onvif_tracks:complete" && !changed.swap(true, Ordering::SeqCst) {
                fs::OpenOptions::new()
                    .append(true)
                    .open(dir.0.join(journal))
                    .and_then(|mut file| file.write_all(b"uncommitted-tail"))
                    .map_err(|_| ReplayAdmissionError::Authority)?;
            }
            Ok(())
        });
        let result = NativeOnvifRead::open(
            &dir.0,
            SITE,
            &[pin],
            &OnvifAnalysis::Tracks,
            NativeOnvifReadLimits::default(),
            &cx,
        );
        assert!(changed.load(Ordering::SeqCst), "{journal}");
        assert!(result.is_err(), "{journal}");
        assert!(
            fs::read(dir.0.join(journal))?.ends_with(b"uncommitted-tail"),
            "native read repaired {journal}"
        );
    }
    Ok(())
}

#[test]
fn immutable_native_initial_and_final_cancellation_release_no_report_or_write() -> Test {
    let dir = Directory::new("immutable-native-cancel")?;
    let pin = dir.xml(&xml(&[0, 1], ""))?;
    let before = immutable_tree(&dir.0)?;
    for target in ["onvif_tracks:open", "onvif_tracks:complete"] {
        let reached = AtomicBool::new(false);
        let cx = dir.cx()?.with_admission(|stage| {
            if stage == target {
                reached.store(true, Ordering::SeqCst);
                Err(ReplayAdmissionError::Cancelled)
            } else {
                Ok(())
            }
        });
        assert!(
            NativeOnvifRead::open(
                &dir.0,
                SITE,
                &[pin],
                &OnvifAnalysis::Lifecycle,
                NativeOnvifReadLimits::default(),
                &cx,
            )
            .is_err()
        );
        assert!(reached.load(Ordering::SeqCst), "{target}");
        assert_eq!(immutable_tree(&dir.0)?, before);
    }
    Ok(())
}

#[test]
fn immutable_native_missing_root_and_mismatched_context_never_initialize_a_store() -> Test {
    let dir = Directory::new("immutable-native-root")?;
    let missing = dir.0.join("missing");
    let pin = TrackSourcePin::Xml {
        identity: ContentDigest::sha256(b"immutable-native-identity"),
        root: ContentDigest::sha256(b"immutable-native-root"),
    };
    assert!(
        NativeOnvifRead::open(
            &missing,
            SITE,
            &[pin],
            &OnvifAnalysis::Tracks,
            NativeOnvifReadLimits::default(),
            &context(&missing)?,
        )
        .is_err()
    );
    assert!(!missing.exists());
    assert!(
        NativeOnvifRead::open(
            &dir.0,
            SITE,
            &[pin],
            &OnvifAnalysis::Tracks,
            NativeOnvifReadLimits::default(),
            &context(&missing)?,
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(&dir.0)?.count(), 0);
    Ok(())
}


#[test]
fn immutable_native_non_sync_admission_stops_between_selected_source_reads() -> Test {
    let dir = Directory::new("immutable-native-source-admission")?;
    let pin = dir.rtp(&[xml(&[0], ""), xml(&[], ""), xml(&[2], "")])?;
    let measured_io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    NativeOnvifRead::open_with_io(
        &measured_io,
        &dir.0,
        SITE,
        &[pin],
        &OnvifAnalysis::Lifecycle,
        NativeOnvifReadLimits::default(),
        &dir.cx()?,
    )?;
    let stop_after = measured_io.calls().len() / 2;
    assert!(stop_after > 0);
    let before = immutable_tree(&dir.0)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    // Cell deliberately proves that the native synchronous task owner need not be Sync.
    // Admission must still remain live while the flat closure's I/O is in progress.
    let stopped_at = Cell::new(None);
    let cx = dir.cx()?.with_admission(|stage| {
        if stage == "onvif_native_read:read" && io.calls().len() >= stop_after {
            stopped_at.set(Some(io.calls().len()));
            Err(ReplayAdmissionError::Cancelled)
        } else {
            Ok(())
        }
    });
    assert!(
        NativeOnvifRead::open_with_io(
            &io,
            &dir.0,
            SITE,
            &[pin],
            &OnvifAnalysis::Lifecycle,
            NativeOnvifReadLimits::default(),
            &cx,
        )
        .is_err()
    );
    let stopped_at = stopped_at.get().ok_or("source admission was not checked")?;
    assert_eq!(io.calls().len(), stopped_at);
    assert!(stopped_at < measured_io.calls().len());
    assert!(io.is_read_only());
    assert_eq!(immutable_tree(&dir.0)?, before);
    Ok(())
}
