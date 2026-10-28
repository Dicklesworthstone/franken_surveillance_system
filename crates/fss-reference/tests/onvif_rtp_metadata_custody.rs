#![forbid(unsafe_code)]
//! Actual recorded-packet custody, cold source reconstruction and the existing hold/deletion owner.
//! Finite local fixtures establish no live device, clock, scene or Profile M qualification.

use std::{collections::BTreeSet, fs, path::PathBuf};

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, Plane,
    ProvenanceClass, RootAuthoritySpec, SensorId, TimestampNs,
};
use fss_packet::{OnvifMetadataLimits, ReorderLimits, StreamKey};
use fss_publication::LedgerCutPoint;
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldRequest, HoldState, commit_hold, preview_hold,
};
use fss_reference::deletion::{DeletionScope, commit_deletion, plan_deletion, plan_scope_deletion};
use fss_reference::onvif::metadata::rtp::{
    RetainedRtpMetadata, RtpMetadataConfig, RtpMetadataImportLimits, STAGE_RTP_METADATA_PUBLISH,
    retain,
};
use fss_reference::onvif::metadata::{MetadataError, SourceBinding};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-rtp-metadata-test";
const PRINCIPAL: &str = "principal:onvif-rtp-metadata-test";
const XML: &[u8] = br#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics><t:Frame UtcTime="2026-10-28T00:00:00Z"><t:Object ObjectId="7"><t:Appearance><t:Class><t:Type Likelihood="0.8">Human</t:Type></t:Class></t:Appearance></t:Object></t:Frame></t:VideoAnalytics></t:MetadataStream>"#;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let root = std::env::temp_dir().join(format!(
                "fss-onvif-rtp-metadata-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory capacity".into())
    }
    fn authority(&self) -> Test<ContextAuthority> {
        Ok(ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-rtp-metadata-test".into(),
            operation_id: OperationId::parse("operation:onvif-rtp-metadata-test")?,
            principal: PRINCIPAL.into(),
            capabilities: vec![
                "ADP-REPLAY-001".into(),
                CAP_HOLD_PREPARE.into(),
                CAP_HOLD_COMMIT.into(),
            ],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?)
    }
    fn cx(&self) -> Test<ReplayCx> {
        Ok(ReplayCx::from_context_authority(
            &self.authority()?,
            &self.0,
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn binding() -> Test<SourceBinding> {
    Ok(SourceBinding {
        sensor_id: SensorId::parse("sensor:front")?,
        device_generation: ContentDigest::sha256(b"device-1"),
        profile_generation: ContentDigest::sha256(b"profile-1"),
        profile_token: "main".into(),
        receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
    })
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
fn packet(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 107 | if marker { 0x80 } else { 0 }];
    bytes.extend(sequence.to_be_bytes());
    bytes.extend(timestamp.to_be_bytes());
    bytes.extend(42_u32.to_be_bytes());
    bytes.extend(payload);
    bytes
}
fn decorated_packet(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = packet(sequence, timestamp, marker, &[]);
    bytes[0] = 0xb1; // One CSRC, extension and padding, all outside reconstructed XML.
    bytes.extend(99_u32.to_be_bytes());
    bytes.extend([0xbe, 0xde, 0, 1]);
    bytes.extend([1, 2, 3, 4]);
    bytes.extend(payload);
    bytes.extend([0, 0, 0, 4]);
    bytes
}
fn header() -> Vec<u8> {
    let mut bytes = b"#!rtpplay1.0 192.0.2.1/5004\n".to_vec();
    bytes.extend([0_u8; 16]);
    bytes
}
fn append(bytes: &mut Vec<u8>, packet: &[u8], offset: u32, original_len: u16) {
    bytes.extend(
        u16::try_from(packet.len() + 8)
            .expect("small fixture")
            .to_be_bytes(),
    );
    bytes.extend(original_len.to_be_bytes());
    bytes.extend(offset.to_be_bytes());
    bytes.extend(packet);
}
fn dump(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = header();
    for (index, packet) in packets.iter().enumerate() {
        append(&mut bytes, packet, index as u32, packet.len() as u16);
    }
    bytes
}
fn synchronized(payload: &[u8]) -> Vec<u8> {
    dump(&[
        packet(100, 100, false, b"unknown-start"),
        packet(101, 200, true, b"unknown-end"),
        packet(102, 300, true, payload),
    ])
}

#[test]
fn cold_replay_preserves_arrival_order_packet_spans_and_timestamp_changes() -> Test {
    let dir = Directory::new("reordered")?;
    let cx = dir.cx()?;
    let a = XML.len() / 3;
    let b = a * 2;
    let late = packet(103, 9000, false, &XML[a..b]);
    let input = dump(&[
        packet(100, 0, false, b"unknown"),
        packet(101, 1000, true, b"old-tail"),
        decorated_packet(102, 5000, false, &XML[..a]),
        packet(104, 11000, true, &XML[b..]),
        late.clone(),
        late,
    ]);
    let retained = {
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
        assert!(
            retained.report().processing_complete(),
            "{:?}",
            retained.report()
        );
        assert_eq!(retained.source_mode(), "owner_supplied_rtpdump");
        assert_eq!(retained.source_digest(), ContentDigest::sha256(&input));
        assert_eq!(
            dep.publisher()
                .spool()
                .read_bounded(retained.source_digest(), input.len())?,
            input
        );
        let document = &retained.documents()[0];
        assert_eq!(document.source_digest(), ContentDigest::sha256(XML));
        assert_eq!(
            document.document().ok_or("parsed XML")?.analytics_frames[0].objects[0].object_id,
            "7"
        );
        let proof = document.provenance();
        assert_eq!(proof.boundary.record, 1);
        assert_eq!(
            proof.fragments.iter().map(|f| f.record).collect::<Vec<_>>(),
            vec![2, 4, 3]
        );
        assert_eq!(
            proof
                .fragments
                .iter()
                .map(|f| f.sequence)
                .collect::<Vec<_>>(),
            vec![102, 103, 104]
        );
        assert_eq!(
            proof
                .fragments
                .iter()
                .map(|f| f.timestamp)
                .collect::<Vec<_>>(),
            vec![5000, 9000, 11000]
        );
        assert_eq!(
            proof
                .fragments
                .iter()
                .map(|f| f.replay_received_ns)
                .collect::<Vec<_>>(),
            vec![2_000_000, 4_000_000, 3_000_000]
        );
        for fragment in &proof.fragments {
            assert_eq!(
                &input[fragment.payload.clone()],
                &XML[fragment.document.clone()]
            );
        }
        assert_eq!(
            retained.report().records[0].sequence_class,
            Some("probation")
        );
        assert_eq!(
            retained.report().records[1].reconstruction,
            Some("boundary_observed")
        );
        assert_eq!(retained.report().records[5].result, "duplicate");
        assert_eq!(
            dep.ledger().batches()[0].deltas[0].validity,
            binding()?.receive_interval
        );
        assert_eq!(retained.plane(), Plane::Cognition);
        assert_eq!(retained.provenance(), ProvenanceClass::VendorClaimed);
        let retry = retain(&mut dep, &input, binding()?, config(), &cx)?;
        assert_eq!(retry.identity(), retained.identity());
        assert_eq!(retry.authority_anchor(), retained.authority_anchor());
        assert_eq!(dep.ledger().batches().len(), 1);
        retained
    };
    let dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let reopened = RetainedRtpMetadata::open(
        &dep,
        retained.identity(),
        Some(retained.publication_root()),
        &cx,
    )?;
    assert_eq!(reopened.report(), retained.report());
    assert_eq!(
        reopened.documents()[0].provenance(),
        retained.documents()[0].provenance()
    );
    assert_eq!(reopened.report_digest(), retained.report_digest());
    assert!(
        RetainedRtpMetadata::open(
            &dep,
            retained.identity(),
            Some(ContentDigest::sha256(b"wrong-root")),
            &cx
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn malformed_xml_zero_documents_and_truncated_tail_still_retain_original_source() -> Test {
    for (label, input, count, reason) in [
        (
            "invalid-header",
            b"not a packet dump".to_vec(),
            0,
            "framing_error",
        ),
        (
            "invalid-xml",
            synchronized(b"<!DOCTYPE root><root/>"),
            1,
            "end_of_input",
        ),
        (
            "no-boundary",
            dump(&[packet(100, 1, false, b"x"), packet(101, 1, false, XML)]),
            0,
            "end_of_input",
        ),
        (
            "truncated-tail",
            {
                let mut input = synchronized(XML);
                input.extend([0, 20, 0]);
                input
            },
            1,
            "framing_error",
        ),
    ] {
        let dir = Directory::new(label)?;
        let cx = dir.cx()?;
        let retained = {
            let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
            assert_eq!(retained.documents().len(), count);
            assert_eq!(retained.report().end_reason, reason);
            assert!(!retained.report().processing_complete());
            assert_eq!(
                dep.publisher()
                    .spool()
                    .read_bounded(retained.source_digest(), input.len())?,
                input
            );
            retained
        };
        let dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
        assert_eq!(
            RetainedRtpMetadata::open(&dep, retained.identity(), None, &cx)?.report(),
            retained.report()
        );
        if label == "invalid-xml" {
            assert_eq!(retained.report().rejected_documents, 1);
            assert!(retained.documents()[0].parse_error().is_some());
            assert!(retained.documents()[0].document().is_none());
            assert!(retained.documents()[0].projection_digest().is_none());
        }
    }
    Ok(())
}

#[test]
fn eof_gap_deadline_and_prefix_never_publish_partial_xml_as_a_claim() -> Test {
    let half = XML.len() / 2;
    let base = vec![
        packet(100, 1, false, b"x"),
        packet(101, 1, true, b"old"),
        packet(102, 1, false, &XML[..half]),
    ];
    let mut gap = base.clone();
    gap.push(packet(104, 2, true, &XML[half..]));
    gap.push(packet(105, 3, true, XML));
    let mut deadline = dump(&base);
    append(
        &mut deadline,
        &packet(103, 2, true, &XML[half..]),
        10_000,
        (12 + XML.len() - half) as u16,
    );
    let mut prefix = dump(&base);
    append(&mut prefix, &[0x80, 107, 0], 3, 20);
    for (label, input, documents, issue) in [
        (
            "incomplete-eof",
            dump(&base),
            0,
            "incomplete_document_end_of_input",
        ),
        ("sequence-gap", dump(&gap), 1, "sequence_gap_end_of_input"),
        ("fixed-deadline", deadline, 0, "document_deadline"),
        ("captured-prefix", prefix, 0, "captured_prefix"),
    ] {
        let dir = Directory::new(label)?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
        assert!(!retained.report().processing_complete());
        assert_eq!(retained.documents().len(), documents);
        assert!(
            retained
                .report()
                .issues
                .iter()
                .any(|value| value.reason == issue),
            "{:?}",
            retained.report()
        );
        RetainedRtpMetadata::open(&dep, retained.identity(), None, &cx)?;
    }
    Ok(())
}

#[test]
fn equal_offsets_are_valid_and_clock_regression_stops_with_source_suffix() -> Test {
    let dir = Directory::new("clock")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let mut input = header();
    for packet in [
        packet(100, 0, false, b"x"),
        packet(101, 1, true, b"end"),
        packet(102, 2, true, XML),
    ] {
        append(&mut input, &packet, 7, packet.len() as u16);
    }
    let good = retain(&mut dep, &input, binding()?, config(), &cx)?;
    assert!(good.report().processing_complete());
    let next = packet(103, 4, true, XML);
    append(&mut input, &next, 6, next.len() as u16);
    let stopped = retain(&mut dep, &input, binding()?, config(), &cx)?;
    assert_eq!(stopped.documents().len(), 1);
    assert_eq!(stopped.report().end_reason, "recorded_clock_reversed");
    assert!(stopped.report().unprocessed_span.is_some());
    assert!(!stopped.report().processing_complete());
    Ok(())
}

#[test]
fn output_record_and_byte_limits_refuse_explicitly_without_omitting_original_source() -> Test {
    let dir = Directory::new("bounds")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let mut input = synchronized(XML);
    let next = packet(103, 4, true, XML);
    append(&mut input, &next, 4, next.len() as u16);
    let mut one = config();
    one.limits.max_documents = 1;
    let bounded = retain(&mut dep, &input, binding()?, one, &cx)?;
    assert_eq!(bounded.documents().len(), 1);
    assert_eq!(bounded.report().end_reason, "document_count_limit");
    assert!(!bounded.report().processing_complete());
    assert_eq!(bounded.source_digest(), ContentDigest::sha256(&input));
    RetainedRtpMetadata::open(&dep, bounded.identity(), None, &cx)?;
    let mut records = config();
    records.limits.max_records = 2;
    let bounded = retain(&mut dep, &input, binding()?, records, &cx)?;
    assert_eq!(bounded.report().records.len(), 2);
    assert_eq!(bounded.report().end_reason, "framing_error");
    assert!(
        bounded
            .report()
            .issues
            .iter()
            .any(|issue| issue.reason == "rtpdump_limit")
    );
    let before = dep.ledger().batches().len();
    let mut bytes = config();
    bytes.limits.max_input_bytes = input.len() - 1;
    assert!(matches!(
        retain(&mut dep, &input, binding()?, bytes, &cx),
        Err(MetadataError::Limit)
    ));
    assert_eq!(dep.ledger().batches().len(), before);
    Ok(())
}

#[test]
fn missing_or_changed_original_and_projection_refuse_open_and_retry_without_repair() -> Test {
    for target in ["source", "report", "projection"] {
        let dir = Directory::new(target)?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let input = synchronized(XML);
        let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
        let digest = match target {
            "source" => retained.source_digest(),
            "report" => retained.report_digest(),
            _ => retained.documents()[0]
                .projection_digest()
                .ok_or("projection")?,
        };
        let path = dep.publisher().spool().object_path(digest);
        if target == "source" {
            fs::remove_file(&path)?;
        } else {
            fs::write(&path, b"changed")?;
        }
        assert!(RetainedRtpMetadata::open(&dep, retained.identity(), None, &cx).is_err());
        assert!(retain(&mut dep, &input, binding()?, config(), &cx).is_err());
        if target == "source" {
            assert!(!path.exists());
        } else {
            assert_eq!(fs::read(&path)?, b"changed");
        }
        assert_eq!(dep.ledger().batches().len(), 1);
    }
    Ok(())
}

#[test]
fn cancellation_and_root_only_interruption_resume_one_exact_publication() -> Test {
    for crash in [false, true] {
        let dir = Directory::new(if crash { "root-cut" } else { "cancel" })?;
        let cx = dir.cx()?;
        let input = synchronized(XML);
        {
            let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            if crash {
                dep.inject_ledger_crash_at(LedgerCutPoint::AfterRootDurable);
            } else {
                cx.set_cancel_at_checkpoint(STAGE_RTP_METADATA_PUBLISH);
            }
            assert!(retain(&mut dep, &input, binding()?, config(), &cx).is_err());
            assert!(dep.ledger().batches().is_empty());
        }
        let fresh = dir.cx()?;
        let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &fresh)?;
        let retained = retain(&mut dep, &input, binding()?, config(), &fresh)?;
        assert_eq!(dep.ledger().batches().len(), 1);
        RetainedRtpMetadata::open(&dep, retained.identity(), None, &fresh)?;
    }
    Ok(())
}

#[test]
fn post_commit_cancellation_keeps_the_committed_handle() -> Test {
    let dir = Directory::new("post-commit")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    cx.set_cancel_at_checkpoint("onvif_rtp_metadata:committed");
    let retained = retain(&mut dep, &synchronized(XML), binding()?, config(), &cx)?;
    assert!(!cx.io_authority().is_valid());
    assert_eq!(dep.ledger().batches().len(), 1);
    let fresh = dir.cx()?;
    RetainedRtpMetadata::open(&dep, retained.identity(), None, &fresh)?;
    Ok(())
}

#[test]
fn verified_batch_membership_holds_and_source_deleted_rebinding_use_existing_lifecycle() -> Test {
    let dir = Directory::new("lifecycle")?;
    let authority = dir.authority()?;
    let cx = ReplayCx::from_context_authority(&authority, &dir.0)?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let input = synchronized(XML);
    let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
    let identity = retained.identity();
    let plan = plan_scope_deletion(&dep, &DeletionScope::Sensor(binding()?.sensor_id), &cx)?;
    assert_eq!(plan.imports, vec![identity]);
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for digest in [
        identity,
        retained.publication_root(),
        retained.source_digest(),
        retained.report_digest(),
        retained.documents()[0].source_digest(),
        retained.documents()[0]
            .projection_digest()
            .ok_or("projection")?,
    ] {
        assert!(plan.deleted_set().contains(&digest));
    }
    assert!(plan.units.iter().any(
        |unit| unit.kind == "import_custody" && unit.id.starts_with("slot:onvif-rtp-metadata-")
    ));
    let mut request = HoldRequest {
        hold_id: "incident".into(),
        import_identity: identity,
        state: HoldState::Held,
        reason: "Owner evidence review".into(),
    };
    let preview = preview_hold(&dep, &request, &authority, &cx)?;
    commit_hold(
        &mut dep,
        &request,
        preview.record.approval(),
        &authority,
        &cx,
    )?;
    assert!(
        plan_deletion(&dep, identity, &cx)?
            .blockers
            .iter()
            .any(|finding| finding.kind == "evidence_hold")
    );
    request.state = HoldState::Released;
    let preview = preview_hold(&dep, &request, &authority, &cx)?;
    commit_hold(
        &mut dep,
        &request,
        preview.record.approval(),
        &authority,
        &cx,
    )?;
    let plan = plan_deletion(&dep, identity, &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    commit_deletion(
        &mut dep,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &cx,
    )?;
    assert!(matches!(
        RetainedRtpMetadata::open(&dep, identity, None, &cx),
        Err(MetadataError::EvidenceDeleted { .. })
    ));
    let mut changed_binding = binding()?;
    changed_binding.profile_generation = ContentDigest::sha256(b"new-profile");
    let mut changed_config = config();
    changed_config.stream.generation += 1;
    assert!(matches!(
        retain(&mut dep, &input, changed_binding, changed_config, &cx),
        Err(MetadataError::EvidenceDeleted { .. })
    ));
    assert!(
        !dep.publisher()
            .spool()
            .object_path(retained.source_digest())
            .exists()
    );
    Ok(())
}

#[test]
fn confirmed_restart_retires_current_state_without_remapping_recycled_sequences() -> Test {
    let dir = Directory::new("confirmed-restart")?;
    let cx = dir.cx()?;
    let half = XML.len() / 2;
    let mut input = dump(&[
        packet(100, 0, false, b"unknown-start"),
        packet(101, 1, true, b"unknown-end"),
        packet(102, 2, true, XML),
        packet(103, 3, false, &XML[..half]),
        packet(105, 4, true, &XML[half..]),
        packet(50_000, 5, false, b"new-epoch-start"),
        packet(50_001, 6, true, b"new-epoch-end"),
    ]);
    let unprocessed_at = input.len();
    let recycled = packet(102, 7, true, XML);
    append(&mut input, &recycled, 7, recycled.len() as u16);
    let retained = {
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
        let report = retained.report();
        assert_eq!(report.end_reason, "restart_required");
        assert!(!report.processing_complete());
        assert_eq!(report.unprocessed_span, Some(unprocessed_at..input.len()));
        assert_eq!(report.records.len(), 7);
        assert_eq!(
            report.records[5].sequence_class,
            Some("discontinuity_suspected")
        );
        assert_eq!(report.records[5].sequence, None);
        assert_eq!(report.records[6].sequence_class, Some("restart_required"));
        assert_eq!(report.records[6].sequence, None);
        let retired = report
            .issues
            .iter()
            .find(|issue| issue.reason == "document_restart_required")
            .ok_or("pending document retirement")?;
        assert_eq!(retired.first_sequence, Some(103));
        assert_eq!(retired.last_sequence, Some(103));
        assert_eq!(retired.discarded_bytes, half);
        assert_eq!(retired.discarded_fragments, 1);
        let queued = report
            .issues
            .iter()
            .find(|issue| issue.reason == "queued_packets_retired")
            .ok_or("queued packet retirement")?;
        assert_eq!(queued.first_sequence, Some(105));
        assert_eq!(queued.last_sequence, Some(105));
        assert_eq!(queued.discarded_fragments, 1);
        assert_eq!(retained.documents().len(), 1);
        let document = &retained.documents()[0];
        assert_eq!(document.source_digest(), ContentDigest::sha256(XML));
        assert_eq!(document.provenance().fragments[0].sequence, 102);
        assert_eq!(document.provenance().fragments[0].record, 2);
        assert_eq!(
            dep.publisher()
                .spool()
                .read_bounded(retained.source_digest(), input.len())?,
            input
        );
        retained
    };
    let reopened = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let verified = RetainedRtpMetadata::open(&reopened, retained.identity(), None, &cx)?;
    assert_eq!(verified.report(), retained.report());
    assert_eq!(
        verified.documents()[0].provenance(),
        retained.documents()[0].provenance()
    );
    Ok(())
}

#[test]
fn conflicting_queued_source_keeps_prior_documents_and_retires_incomplete_derivatives() -> Test {
    let dir = Directory::new("conflicting-source")?;
    let cx = dir.cx()?;
    let half = XML.len() / 2;
    let first = packet(105, 4, true, &XML[half..]);
    let conflicting = packet(105, 4, true, b"different-original-payload");
    let mut input = dump(&[
        packet(100, 0, false, b"unknown-start"),
        packet(101, 1, true, b"unknown-end"),
        packet(102, 2, true, XML),
        packet(103, 3, false, &XML[..half]),
        first,
        conflicting,
    ]);
    let unprocessed_at = input.len();
    let later = packet(104, 6, true, &XML[half..]);
    append(&mut input, &later, 6, later.len() as u16);
    let retained = {
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
        let report = retained.report();
        assert_eq!(report.end_reason, "receiver_invalidated");
        assert!(!report.processing_complete());
        assert_eq!(report.unprocessed_span, Some(unprocessed_at..input.len()));
        assert_eq!(report.records.len(), 6);
        assert_eq!(report.records[4].result, "buffered");
        assert_eq!(report.records[4].sequence, Some(105));
        assert_eq!(report.records[4].reconstruction, None);
        assert_eq!(report.records[5].result, "conflicting_duplicate");
        assert_eq!(report.records[5].sequence, None);
        let retired = report
            .issues
            .iter()
            .find(|issue| issue.reason == "document_conflicting_packet")
            .ok_or("pending document retirement")?;
        assert_eq!(retired.first_sequence, Some(103));
        assert_eq!(retired.last_sequence, Some(103));
        assert_eq!(retired.discarded_bytes, half);
        assert_eq!(retired.discarded_fragments, 1);
        let queued = report
            .issues
            .iter()
            .find(|issue| issue.reason == "queued_packets_retired")
            .ok_or("queued packet retirement")?;
        assert_eq!(queued.first_sequence, Some(105));
        assert_eq!(queued.last_sequence, Some(105));
        assert_eq!(queued.discarded_fragments, 1);
        assert_eq!(retained.documents().len(), 1);
        assert_eq!(
            retained.documents()[0].source_digest(),
            ContentDigest::sha256(XML)
        );
        assert_eq!(
            dep.publisher()
                .spool()
                .read_bounded(retained.source_digest(), input.len())?,
            input
        );
        retained
    };
    let reopened = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let verified = RetainedRtpMetadata::open(&reopened, retained.identity(), None, &cx)?;
    assert_eq!(verified.report(), retained.report());
    assert_eq!(verified.documents().len(), 1);
    assert_eq!(
        verified.documents()[0].provenance(),
        retained.documents()[0].provenance()
    );
    Ok(())
}

#[test]
fn malformed_rtp_keeps_completed_claims_and_retires_the_pending_document() -> Test {
    let dir = Directory::new("malformed-packet")?;
    let cx = dir.cx()?;
    let input = dump(&[
        packet(100, 0, false, b"unknown"),
        packet(101, 1, true, b"boundary"),
        packet(102, 2, true, XML),
        packet(103, 3, false, &XML[..XML.len() / 2]),
        vec![0x80, 107, 0],
        packet(104, 4, true, &XML[XML.len() / 2..]),
        packet(105, 5, true, XML),
    ]);
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
    assert_eq!(retained.report().end_reason, "receiver_invalidated");
    assert_eq!(retained.report().usable_documents, 1);
    assert!(!retained.report().processing_complete());
    assert!(
        retained
            .report()
            .issues
            .iter()
            .any(|issue| issue.reason == "document_invalid_packet"
                && issue.discarded_bytes == XML.len() / 2)
    );
    assert!(retained.report().unprocessed_span.is_some());
    assert_eq!(
        dep.publisher()
            .spool()
            .read_bounded(retained.source_digest(), input.len())?,
        input
    );
    assert_eq!(
        RetainedRtpMetadata::open(&dep, retained.identity(), None, &cx)?.report(),
        retained.report()
    );
    Ok(())
}

#[test]
fn rtcp_and_other_stream_packets_remain_source_without_becoming_xml() -> Test {
    let dir = Directory::new("pinned-source")?;
    let cx = dir.cx()?;
    let mut input = header();
    append(&mut input, b"opaque-rtcp", 0, 0);
    for (offset, packet) in [
        packet(100, 0, false, b"unknown"),
        packet(101, 1, true, b"boundary"),
    ]
    .iter()
    .enumerate()
    {
        append(&mut input, packet, offset as u32 + 1, packet.len() as u16);
    }
    let mut wrong_ssrc = packet(102, 2, true, XML);
    wrong_ssrc[8..12].copy_from_slice(&43_u32.to_be_bytes());
    append(&mut input, &wrong_ssrc, 3, wrong_ssrc.len() as u16);
    let mut wrong_payload = packet(102, 2, true, XML);
    wrong_payload[1] = 0x80 | 106;
    append(&mut input, &wrong_payload, 4, wrong_payload.len() as u16);
    let right = packet(102, 2, true, XML);
    append(&mut input, &right, 5, right.len() as u16);
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
    assert_eq!(retained.report().records[0].result, "rtcp_retained");
    assert_eq!(retained.report().records[3].result, "stream_mismatch");
    assert_eq!(retained.report().records[4].result, "payload_type_mismatch");
    assert_eq!(retained.report().usable_documents, 1);
    assert!(!retained.report().processing_complete());
    assert_eq!(retained.documents()[0].provenance().fragments[0].record, 5);
    RetainedRtpMetadata::open(&dep, retained.identity(), None, &cx)?;
    Ok(())
}

#[test]
fn full_sixty_four_document_manifest_reopens_above_the_legacy_recipe_read_bound() -> Test {
    let dir = Directory::new("full-document-bound")?;
    let cx = dir.cx()?;
    let mut packets = vec![
        packet(100, 0, false, b"unknown-start"),
        packet(101, 1, true, b"observed-boundary"),
    ];
    let template = std::str::from_utf8(XML)?;
    for index in 0..64_u16 {
        let xml = template.replace("ObjectId=\"7\"", &format!("ObjectId=\"{}\"", 1000 + index));
        packets.push(packet(
            102 + index,
            90_000 + u32::from(index),
            true,
            xml.as_bytes(),
        ));
    }
    let input = dump(&packets);
    let retained = {
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
        assert!(
            retained.report().processing_complete(),
            "{:?}",
            retained.report()
        );
        assert_eq!(retained.report().complete_documents, 64);
        assert_eq!(retained.report().usable_documents, 64);
        assert_eq!(retained.documents().len(), 64);
        let xml_digests: BTreeSet<_> = retained
            .documents()
            .iter()
            .map(|document| document.source_digest())
            .collect();
        let projection_digests: BTreeSet<_> = retained
            .documents()
            .iter()
            .filter_map(|document| document.projection_digest())
            .collect();
        assert_eq!(xml_digests.len(), 64, "every XML must remain distinct");
        assert_eq!(
            projection_digests.len(),
            64,
            "every projection must remain distinct"
        );
        let manifest_bytes = dep
            .publisher()
            .spool()
            .read_bounded(retained.publication_root(), 16 * 1024)?;
        assert!(
            manifest_bytes.len() > 4096,
            "exercise the root bound, not only the small recipe bound"
        );
        let manifest = fss_object::ObjectManifest::from_canonical_bytes(&manifest_bytes)?;
        assert_eq!(
            manifest.children().len(),
            131,
            "source, recipe, report and 128 distinct derivatives"
        );
        for digest in xml_digests.union(&projection_digests) {
            assert!(manifest.children().contains(digest));
        }
        retained
    };
    let dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let reopened = RetainedRtpMetadata::open(
        &dep,
        retained.identity(),
        Some(retained.publication_root()),
        &cx,
    )?;
    assert!(reopened.report().processing_complete());
    assert_eq!(reopened.documents().len(), 64);
    assert_eq!(reopened.report(), retained.report());
    for (index, document) in reopened.documents().iter().enumerate() {
        assert_eq!(
            document
                .document()
                .ok_or("accepted analytics")?
                .analytics_frames[0]
                .objects[0]
                .object_id,
            (1000 + index).to_string()
        );
    }
    Ok(())
}

#[test]
fn valid_pullmessages_soap_in_rtp_is_retained_as_an_unsupported_container() -> Test {
    let soap = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl"><s:Body><e:PullMessagesResponse><e:CurrentTime>2026-10-28T00:00:00Z</e:CurrentTime><e:TerminationTime>2026-10-28T00:01:00Z</e:TerminationTime></e:PullMessagesResponse></s:Body></s:Envelope>"#;
    let parsed = fss_reference::onvif::wire::parse_metadata_document(soap)?;
    assert_eq!(
        parsed.format,
        fss_reference::onvif::wire::EventDocumentFormat::PullMessages,
        "the source must be valid SOAP, not a generic XML refusal"
    );
    let dir = Directory::new("soap-container")?;
    let cx = dir.cx()?;
    let input = synchronized(soap);
    let retained = {
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let retained = retain(&mut dep, &input, binding()?, config(), &cx)?;
        assert_eq!(retained.report().complete_documents, 1);
        assert_eq!(retained.report().usable_documents, 0);
        assert_eq!(retained.report().rejected_documents, 1);
        assert!(!retained.report().processing_complete());
        let document = &retained.documents()[0];
        assert_eq!(document.parse_error(), Some("unexpected_metadata_format"));
        assert!(document.document().is_none());
        assert!(document.projection_digest().is_none());
        assert!(
            retained
                .report()
                .issues
                .iter()
                .any(|issue| issue.reason == "unexpected_metadata_format")
        );
        assert_eq!(
            dep.publisher()
                .spool()
                .read_bounded(document.source_digest(), soap.len())?,
            soap
        );
        assert_eq!(
            dep.publisher()
                .spool()
                .read_bounded(retained.source_digest(), input.len())?,
            input
        );
        retained
    };
    let dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let reopened = RetainedRtpMetadata::open(
        &dep,
        retained.identity(),
        Some(retained.publication_root()),
        &cx,
    )?;
    assert_eq!(reopened.report(), retained.report());
    assert_eq!(
        reopened.documents()[0].parse_error(),
        Some("unexpected_metadata_format")
    );
    Ok(())
}
