#![forbid(unsafe_code)]
//! Actual retained XML/RTP lifecycle owner, shared two-pass budgets and custody refusals.
//! These fixtures establish no device qualification, physical identity or coverage.

use std::cell::Cell;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, EffectIntent, EffectState,
    IdempotencyKey, ObligationId, OperationId, Plane, ProvenanceClass, RootAuthoritySpec, SensorId,
    TimestampNs,
};
use fss_packet::{OnvifMetadataLimits, ReorderLimits, StreamKey};
use fss_reference::deletion::{commit_deletion, plan_deletion};
use fss_reference::onvif::metadata::lifecycle::contract::{
    LifecycleEndpointState, LifecycleObservationBasis,
};
use fss_reference::onvif::metadata::lifecycle::{
    LifecycleDocumentState as State, LifecycleReadLimits, RetainedLifecycle, RetainedLifecycleError,
};
use fss_reference::onvif::metadata::rtp::{self, RtpMetadataConfig, RtpMetadataImportLimits};
use fss_reference::onvif::metadata::tracks::{
    RetainedTrackError, RetainedTracklets, TrackSourcePin,
};
use fss_reference::onvif::metadata::{
    Interpretation, MetadataError, SourceBinding, retain_with_interpretation,
};
use fss_reference::onvif::wire::{EventDocumentFormat, lifecycle_parse_work_bound};
use fss_reference::{ReferenceDeployment, ReplayAdmissionError, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-lifecycle-test";
const PRINCIPAL: &str = "operator:onvif-lifecycle-test";
const FIRST: &str = "910000001";
const SECOND: &str = "910000002";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let root = std::env::temp_dir().join(format!(
                "fss-onvif-lifecycle-{label}-{}-{attempt}", std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture directory capacity".into())
    }
    fn cx(&self) -> Test<ReplayCx> { context(&self.0) }
    fn xml(&self, bytes: &[u8], interpretation: Interpretation) -> Test<TrackSourcePin> {
        let cx = self.cx()?;
        let mut deployment = ReferenceDeployment::open(&self.0, SITE, &cx)?;
        let source = retain_with_interpretation(&mut deployment, binding()?, bytes, interpretation, &cx)?;
        Ok(TrackSourcePin::Xml { identity: source.identity(), root: source.publication_root() })
    }
    fn rtp(&self, documents: &[Vec<u8>]) -> Test<TrackSourcePin> {
        let cx = self.cx()?;
        let mut deployment = ReferenceDeployment::open(&self.0, SITE, &cx)?;
        let source = rtp::retain(&mut deployment, &rtp_source(documents), binding()?, config(), &cx)?;
        Ok(TrackSourcePin::Rtp { identity: source.identity(), root: source.publication_root() })
    }
    fn query(&self, pins: &[TrackSourcePin], limits: LifecycleReadLimits) -> Test<RetainedLifecycle> {
        Ok(RetainedLifecycle::open(&self.0, SITE, pins, limits, &self.cx()?)?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:onvif-lifecycle-test".into(),
        operation_id: OperationId::parse("operation:onvif-lifecycle-test")?,
        principal: PRINCIPAL.into(),
        capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).storage_operations(16_384).build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority_read_only(&authority, root)?)
}
fn binding() -> Test<SourceBinding> {
    Ok(SourceBinding {
        sensor_id: SensorId::parse("sensor:front")?,
        device_generation: ContentDigest::sha256(b"device-generation"),
        profile_generation: ContentDigest::sha256(b"profile-generation"),
        profile_token: "private-lifecycle-profile".into(),
        receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
    })
}
fn frame(second: u8, id: &str, extra: &str) -> String {
    format!(r#"<t:Frame UtcTime="2026-11-09T00:00:{second:02}Z" Source="private-lifecycle-module"><t:Object ObjectId="{id}"/>{extra}</t:Frame>"#)
}
fn xml(frames: &str) -> Vec<u8> {
    format!(r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics>{frames}</t:VideoAnalytics></t:MetadataStream>"#).into_bytes()
}
fn rename() -> String {
    format!(r#"<t:ObjectTree><t:Rename><t:from ObjectId="{FIRST}"/><t:to ObjectId="{SECOND}"/></t:Rename></t:ObjectTree>"#)
}
fn linked_xml() -> Vec<u8> { xml(&(frame(0, FIRST, "") + &frame(1, SECOND, &rename()))) }
fn soap() -> Vec<u8> {
    br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl"><s:Body><e:PullMessagesResponse><e:CurrentTime>2026-11-09T00:00:00Z</e:CurrentTime><e:TerminationTime>2026-11-09T00:00:30Z</e:TerminationTime></e:PullMessagesResponse></s:Body></s:Envelope>"#.to_vec()
}
fn config() -> RtpMetadataConfig {
    RtpMetadataConfig {
        stream: StreamKey { ingress: 17, generation: 3, ssrc: 42 },
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
    let mut packets = vec![packet(100, false, b"unknown-start"), packet(101, true, b"unknown-end")];
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
fn cold_xml_adds_vendor_relationships_without_rewriting_original_tracks() -> Test {
    let dir = Directory::new("cold-xml")?;
    let original = linked_xml();
    let pin = dir.xml(&original, Interpretation::AnalyticsV2)?;
    let limits = LifecycleReadLimits::default();
    let result = dir.query(&[pin], limits)?;
    assert_eq!(result.report().operations.len(), 1);
    assert_eq!(result.report().operations[0].state, LifecycleEndpointState::Observed);
    assert_eq!(result.report().operations[0].from[0].observations[0].basis, LifecycleObservationBasis::PreviousModuleFrame);
    assert_eq!(result.report().operations[0].to[0].observations[0].basis, LifecycleObservationBasis::CurrentFrame);
    assert_eq!(result.snapshot().report().tracklets.len(), 2);
    let plain = RetainedTracklets::open(&dir.0, SITE, &[pin], limits.source, &dir.cx()?)?;
    assert_eq!(result.snapshot().report(), plain.report());
    assert_eq!(result.report().tracklet_report_digest, plain.report().report_digest);
    let document = &result.documents()[0];
    assert_eq!(document.pin, pin);
    assert_eq!(document.source_digest, Some(ContentDigest::sha256(&original)));
    assert_eq!(document.state, State::Parsed);
    assert_eq!((document.frame_start, document.frames, document.objects, document.operations, document.references), (0, 2, 2, 1, 2));
    assert_eq!(document.parse_work_units, lifecycle_parse_work_bound(original.len()).ok_or("missing quote")?);
    assert_eq!(result.plane(), Plane::Cognition);
    assert_eq!(result.provenance(), ProvenanceClass::Derived);
    assert_eq!(result.source_provenance(), ProvenanceClass::VendorClaimed);
    for private in [FIRST, SECOND, "private-lifecycle-module", "private-lifecycle-profile", "2026-11-09T"] {
        assert!(!format!("{result:?}").contains(private));
    }
    let cold = dir.query(&[pin], limits)?;
    assert_eq!(cold.digest(), result.digest());
    assert_eq!(cold.report(), result.report());
    assert_eq!(cold.documents(), result.documents());
    Ok(())
}

#[test]
fn recorded_rtp_relationships_keep_each_original_xml_and_packet_owner() -> Test {
    let dir = Directory::new("rtp-lineage")?;
    let documents = [xml(&frame(0, FIRST, "")), xml(&frame(1, SECOND, &rename()))];
    let pin = dir.rtp(&documents)?;
    let result = dir.query(&[pin], LifecycleReadLimits::default())?;
    assert_eq!(result.report().operations[0].state, LifecycleEndpointState::Observed);
    assert_eq!(result.documents().len(), 2);
    for (index, document) in result.documents().iter().enumerate() {
        assert_eq!(document.pin, pin);
        assert_eq!(document.source_ordinal, 0);
        assert_eq!(document.document_index, Some(index));
        assert_eq!(document.source_digest, Some(ContentDigest::sha256(&documents[index])));
        assert_eq!(document.frame_start, index);
    }
    let original = &result.snapshot().report().frames[1].reference;
    assert_eq!(original.source_identity, pin.identity());
    assert_eq!(original.source_root, pin.root());
    assert_eq!(original.document_index, 1);
    Ok(())
}

#[test]
fn frozen_v1_soap_empty_and_zero_document_sources_remain_explicit() -> Test {
    let dir = Directory::new("skipped-generations")?;
    // This VideoAnalytics is valid opaque v1 source but invalid in the newer lifecycle subset.
    let legacy_xml = xml(r#"<t:Frame><t:ObjectTree><t:Rename/></t:ObjectTree></t:Frame>"#);
    let legacy = dir.xml(&legacy_xml, Interpretation::EventsV1)?;
    let soap_pin = dir.xml(&soap(), Interpretation::AnalyticsV2)?;
    let empty = dir.xml(&xml(""), Interpretation::AnalyticsV2)?;
    let zero = dir.rtp(&[])?;
    let result = dir.query(&[legacy, soap_pin, empty, zero], LifecycleReadLimits::default())?;
    assert!(result.report().frames.is_empty());
    assert!(result.report().operations.is_empty());
    assert_eq!(result.snapshot().sources().len(), 4);
    assert_eq!(result.documents().iter().map(|row| row.state).collect::<Vec<_>>(), [State::FrozenEventsV1, State::NonAnalyticsSoap, State::ParsedEmpty, State::NoCompleteDocuments]);
    assert_eq!(result.documents()[0].parse_work_units, 0);
    assert_eq!(result.documents()[0].parser_generation, fss_reference::onvif::metadata::PARSER_GENERATION_V1);
    assert_eq!(result.documents()[1].format, Some(EventDocumentFormat::PullMessages));
    assert_eq!(result.documents()[1].parse_work_units, 0);
    assert!(result.documents()[2].parse_work_units > 0);
    assert_eq!(result.documents()[3].document_index, None);
    assert_eq!(result.documents()[3].source_digest, None);
    for (index, receipt) in result.documents().iter().enumerate() { assert_eq!(receipt.source_ordinal, index); }
    Ok(())
}

#[test]
fn rejected_and_empty_rtp_documents_never_disappear_or_bridge_support() -> Test {
    let dir = Directory::new("rtp-gaps")?;
    let documents = [xml(&frame(0, FIRST, "")), xml(""), b"<invalid-xml".to_vec(), xml(&frame(3, SECOND, &rename()))];
    let pin = dir.rtp(&documents)?;
    let result = dir.query(&[pin], LifecycleReadLimits::default())?;
    assert_eq!(result.documents().iter().map(|row| row.state).collect::<Vec<_>>(), [State::Parsed, State::ParsedEmpty, State::RejectedXml, State::Parsed]);
    assert_eq!(result.documents()[2].source_digest, Some(ContentDigest::sha256(&documents[2])));
    assert!(result.documents()[2].original_parse_error.is_some());
    assert_eq!(result.documents()[2].parse_work_units, 0);
    assert_eq!(result.documents()[3].frame_start, 1);
    assert_eq!(result.report().operations[0].from[0].state, LifecycleEndpointState::Unresolved);
    assert!(result.report().operations[0].from[0].observations.is_empty());
    Ok(())
}

#[test]
fn one_cumulative_allowance_covers_both_source_and_overlay_passes() -> Test {
    let dir = Directory::new("two-pass-budget")?;
    let pin = dir.xml(&linked_xml(), Interpretation::AnalyticsV2)?;
    let base = LifecycleReadLimits::default();
    let completed = dir.query(&[pin], base)?;
    let usage = completed.snapshot().usage();
    for source in [
        fss_reference::onvif::metadata::tracks::TrackReadLimits { max_stored_bytes: usage.indexed_reads.used_bytes - 1, ..base.source },
        fss_reference::onvif::metadata::tracks::TrackReadLimits { max_indexed_reads: usage.indexed_reads.used_read_attempts - 1, ..base.source },
        fss_reference::onvif::metadata::tracks::TrackReadLimits { max_work_units: usage.reserved_work_units - 1, ..base.source },
    ] {
        let second_pass = Cell::new(false);
        let cx = dir.cx()?.with_admission(|stage| {
            if stage == "onvif_tracks:revalidate" { second_pass.set(true); }
            Ok(())
        });
        assert!(matches!(RetainedLifecycle::open(&dir.0, SITE, &[pin], LifecycleReadLimits { source, ..base }, &cx), Err(RetainedLifecycleError::Limit)));
        assert!(second_pass.get());
    }
    let mut exact = base;
    exact.source.max_stored_bytes = usage.indexed_reads.used_bytes;
    exact.source.max_indexed_reads = usage.indexed_reads.used_read_attempts;
    exact.source.max_work_units = usage.reserved_work_units;
    assert_eq!(dir.query(&[pin], exact)?.snapshot().usage().reserved_work_units, usage.reserved_work_units);
    Ok(())
}

#[test]
fn caller_parser_work_cap_is_never_widened_to_the_computed_quote() -> Test {
    let dir = Directory::new("parser-cap")?;
    let original = linked_xml();
    let pin = dir.xml(&original, Interpretation::AnalyticsV2)?;
    let quote = lifecycle_parse_work_bound(original.len()).ok_or("missing quote")?;
    let mut limits = LifecycleReadLimits::default();
    limits.parse.max_work_units = quote - 1;
    let parser_admissions = Cell::new(0);
    let cx = dir.cx()?.with_admission(|stage| {
        if stage == "onvif_lifecycle:parse" { parser_admissions.set(parser_admissions.get() + 1); }
        Ok(())
    });
    assert!(matches!(RetainedLifecycle::open(&dir.0, SITE, &[pin], limits, &cx), Err(RetainedLifecycleError::Limit)));
    assert_eq!(parser_admissions.get(), 0);
    limits.parse.max_work_units = quote;
    let narrowed = dir.query(&[pin], limits)?;
    let wide = dir.query(&[pin], LifecycleReadLimits::default())?;
    assert_eq!(narrowed.report(), wide.report());
    assert_ne!(narrowed.digest(), wide.digest());
    Ok(())
}

#[test]
fn new_operation_caps_stop_before_parsing_the_next_document() -> Test {
    let dir = Directory::new("early-lifecycle-shape")?;
    let first = dir.xml(&xml(&frame(0, FIRST, r#"<t:ObjectTree><t:Delete ObjectId="1"/><t:Delete ObjectId="2"/></t:ObjectTree>"#)), Interpretation::AnalyticsV2)?;
    let second = dir.xml(&linked_xml(), Interpretation::AnalyticsV2)?;
    let mut limits = LifecycleReadLimits::default();
    limits.projection.max_operations = 1;
    let documents = Cell::new(0);
    let cx = dir.cx()?.with_admission(|stage| {
        if stage == "onvif_lifecycle:document" { documents.set(documents.get() + 1); }
        Ok(())
    });
    assert!(matches!(RetainedLifecycle::open(&dir.0, SITE, &[first, second], limits, &cx), Err(RetainedLifecycleError::Limit)));
    assert_eq!(documents.get(), 1);
    Ok(())
}

#[test]
fn malformed_new_lifecycle_semantics_refuse_without_changing_old_custody() -> Test {
    let dir = Directory::new("malformed-overlay")?;
    let original = xml(&frame(0, FIRST, r#"<t:ObjectTree><t:Rename><t:From ObjectId="1"/><t:To ObjectId="2"/></t:Rename></t:ObjectTree>"#));
    let pin = dir.xml(&original, Interpretation::AnalyticsV2)?;
    let limits = LifecycleReadLimits::default();
    assert!(matches!(RetainedLifecycle::open(&dir.0, SITE, &[pin], limits, &dir.cx()?), Err(RetainedLifecycleError::Parse(_))));
    let old = RetainedTracklets::open(&dir.0, SITE, &[pin], limits.source, &dir.cx()?)?;
    assert_eq!(old.report().frames.len(), 1);
    assert_eq!(old.sources()[0].pin, pin);
    Ok(())
}

#[test]
fn later_empty_source_tampering_is_caught_on_the_second_complete_pass() -> Test {
    let dir = Directory::new("later-empty-tamper")?;
    let first = dir.xml(&linked_xml(), Interpretation::AnalyticsV2)?;
    let empty_bytes = xml("");
    let empty = dir.xml(&empty_bytes, Interpretation::AnalyticsV2)?;
    let source_path = {
        let cx = dir.cx()?;
        let deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        deployment.publisher().spool().object_path(ContentDigest::sha256(&empty_bytes))
    };
    let changed = Cell::new(false);
    let cx = dir.cx()?.with_admission(|stage| {
        if stage == "onvif_tracks:revalidate" && !changed.replace(true) {
            fs::write(&source_path, b"changed-empty-source").map_err(|_| ReplayAdmissionError::Authority)?;
        }
        Ok(())
    });
    assert!(RetainedLifecycle::open(&dir.0, SITE, &[first, empty], LifecycleReadLimits::default(), &cx).is_err());
    assert!(changed.get());
    Ok(())
}

#[test]
fn committed_deletion_of_a_later_empty_source_is_not_omitted() -> Test {
    let dir = Directory::new("deleted-empty")?;
    let first = dir.xml(&linked_xml(), Interpretation::AnalyticsV2)?;
    let empty = dir.xml(&xml(""), Interpretation::AnalyticsV2)?;
    {
        let cx = dir.cx()?;
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let plan = plan_deletion(&deployment, empty.identity(), &cx)?;
        assert!(plan.blockers.is_empty());
        commit_deletion(&mut deployment, plan.digest()?, plan.approval_digest(PRINCIPAL)?, PRINCIPAL, &cx)?;
    }
    let result = RetainedLifecycle::open(&dir.0, SITE, &[first, empty], LifecycleReadLimits::default(), &dir.cx()?);
    assert!(matches!(result, Err(RetainedLifecycleError::Source(error)) if matches!(error.as_ref(), RetainedTrackError::Source(metadata) if matches!(metadata.as_ref(), MetadataError::EvidenceDeleted { .. }))));
    Ok(())
}

#[test]
fn impossible_minimum_budget_and_missing_store_do_not_initialize_anything() -> Test {
    let dir = Directory::new("no-initialization")?;
    let pin = TrackSourcePin::Xml { identity: ContentDigest::sha256(b"identity"), root: ContentDigest::sha256(b"root") };
    let mut limits = LifecycleReadLimits::default();
    limits.source.max_work_units = 1;
    assert!(matches!(RetainedLifecycle::open(&dir.0, SITE, &[pin], limits, &dir.cx()?), Err(RetainedLifecycleError::Limit)));
    assert_eq!(fs::read_dir(&dir.0)?.count(), 0);
    let mut replay_only = LifecycleReadLimits::default();
    replay_only.projection.max_work_units = replay_only.source.projection.max_work_units;
    assert!(matches!(RetainedLifecycle::open(&dir.0, SITE, &[pin], replay_only, &dir.cx()?), Err(RetainedLifecycleError::Limit)));
    assert_eq!(fs::read_dir(&dir.0)?.count(), 0);
    let missing = dir.0.join("missing");
    assert!(RetainedLifecycle::open(&missing, SITE, &[pin], LifecycleReadLimits::default(), &context(&missing)?).is_err());
    assert!(!missing.exists());
    assert!(RetainedLifecycle::open(&dir.0, SITE, &[], LifecycleReadLimits::default(), &dir.cx()?).is_err());
    assert_eq!(fs::read_dir(&dir.0)?.count(), 0);
    Ok(())
}

#[test]
fn cancellation_inside_parsing_projection_or_receipts_returns_no_success() -> Test {
    let dir = Directory::new("cancellation")?;
    let pin = dir.xml(&linked_xml(), Interpretation::AnalyticsV2)?;
    for stop in ["onvif_lifecycle:parse", "onvif_lifecycle:group", "onvif_lifecycle:receipt", "onvif_tracks:revalidate"] {
        let cx = dir.cx()?.with_admission(|stage| if stage == stop { Err(ReplayAdmissionError::Cancelled) } else { Ok(()) });
        assert!(matches!(RetainedLifecycle::open(&dir.0, SITE, &[pin], LifecycleReadLimits::default(), &cx), Err(RetainedLifecycleError::Cancelled)));
    }
    Ok(())
}

#[test]
fn final_admission_cannot_change_authority_after_its_last_verification() -> Test {
    let dir = Directory::new("late-authority")?;
    let pin = dir.xml(&linked_xml(), Interpretation::AnalyticsV2)?;
    let changed = Cell::new(false);
    let cx = dir.cx()?.with_admission(|stage| {
        if stage == "onvif_tracks:complete" && !changed.replace(true) {
            let mut journal = fs::OpenOptions::new().append(true).open(dir.0.join("ledger/journal.fssj")).map_err(|_| ReplayAdmissionError::Authority)?;
            journal.write_all(b"uncommitted-tail").map_err(|_| ReplayAdmissionError::Authority)?;
        }
        Ok(())
    });
    assert!(RetainedLifecycle::open(&dir.0, SITE, &[pin], LifecycleReadLimits::default(), &cx).is_err());
    assert!(changed.get());
    Ok(())
}

#[test]
fn lifecycle_query_does_not_reconcile_pending_effects_or_publish_derived_roots() -> Test {
    let dir = Directory::new("pending-effects")?;
    let pin = dir.xml(&linked_xml(), Interpretation::AnalyticsV2)?;
    {
        let cx = dir.cx()?;
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        for label in ["prepared", "committed"] {
            let intent = EffectIntent::new(
                OperationId::parse(format!("operation:lifecycle:{label}"))?,
                IdempotencyKey::parse(format!("idempotency:lifecycle:{label}"))?,
                "fixture:notification", ContentDigest::sha256(label.as_bytes()), ContentDigest::sha256(b"lifecycle-authority"),
            )?;
            deployment.effects_mut().prepare(intent.clone(), ObligationId::parse(format!("obligation:lifecycle:{label}"))?, "notification observed", TimestampNs(1))?;
            if label == "committed" {
                deployment.effects_mut().transition(&intent.operation_id, EffectState::Committed, TimestampNs(2), None, None)?;
            }
        }
    }
    let ledger = dir.0.join("ledger/journal.fssj");
    let effects = dir.0.join("effects/journal.fssj");
    let before = (fs::read(&ledger)?, fs::read(&effects)?);
    assert_eq!(dir.query(&[pin], LifecycleReadLimits::default())?.report().operations.len(), 1);
    assert_eq!(fs::read(ledger)?, before.0);
    assert_eq!(fs::read(effects)?, before.1);
    Ok(())
}
