#![forbid(unsafe_code)]
//! Original native acquisition evidence and source-derived replay share one durable root.

use std::{fs, path::PathBuf};

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, TimestampNs,
};
use fss_packet::{OnvifMetadataLimits, ReorderLimits, StreamKey};
use fss_publication::LedgerCutPoint;
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldRequest, HoldState, commit_hold, preview_hold,
};
use fss_reference::deletion::{DeletionScope, commit_deletion, plan_deletion, plan_scope_deletion};
use fss_reference::onvif::metadata::rtp::{
    RetainedRtpMetadata, RtpMetadataConfig, RtpMetadataImportLimits, STAGE_RTP_METADATA_PUBLISH,
    retain, retain_native,
};
use fss_reference::onvif::metadata::{MetadataError, SourceBinding};
use fss_reference::rtsp::client::{ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::framed::{RtspWireFrame, RtspWireIntake};
use fss_reference::rtsp::metadata_source::{
    NativeMetadataConfig, NativeMetadataSource, NativeMetadataStop,
};
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-native-custody";
const PRINCIPAL: &str = "principal:onvif-native-custody";
const ORIGIN: i128 = 1_700_000_000_000_000_000;
const START: u64 = 10_000_000_123;
const END: u64 = START + 4_000_999;
const XML: &[u8] = br#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics><t:Frame UtcTime="2026-10-28T00:00:00Z"><t:Object ObjectId="7"/></t:Frame></t:VideoAnalytics></t:MetadataStream>"#;
const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=application 0 RTP/AVP 107\r\na=rtpmap:107 vnd.onvif.metadata/90000\r\na=control:metadata\r\n";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-native-metadata-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory capacity".into())
    }
    fn authority(&self) -> Test<ContextAuthority> {
        Ok(ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-native-custody".into(),
            operation_id: OperationId::parse("operation:onvif-native-custody")?,
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
fn binding() -> Test<SourceBinding> {
    Ok(SourceBinding {
        sensor_id: SensorId::parse("sensor:front")?,
        device_generation: ContentDigest::sha256(b"device-1"),
        profile_generation: ContentDigest::sha256(b"profile-1"),
        profile_token: "main".into(),
        receive_interval: CaptureInterval::new(
            TimestampNs(ORIGIN + i128::from(START)),
            TimestampNs(ORIGIN + i128::from(END)),
        )?,
    })
}
fn frame(bytes: &[u8], received: u64) -> Test<RtspWireFrame> {
    let mut intake = RtspWireIntake::new();
    intake.ingest(bytes, received)?;
    intake
        .poll(received)?
        .ok_or_else(|| "missing complete fixture frame".into())
}
fn native(include_document: bool, stop: NativeMetadataStop) -> Test<NativeMetadataSource> {
    let protocol = ClientConfig {
        presentation_uri: "rtsp://camera.example/live/".into(),
        control_root_uri: "rtsp://camera.example/live".into(),
        media_index: 0,
        channels: (0, 1),
        response_timeout_ns: 1_000_000_000,
        default_session_timeout_seconds: 60,
    };
    let mut source = NativeMetadataSource::new(NativeMetadataConfig {
        approval: ContentDigest::sha256(b"owner-native-capture"),
        protocol,
        binding: TcpBinding::new(
            config().stream,
            "127.0.0.1:8554".parse()?,
            "camera.example",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?,
        payload_type: 107,
        receive_origin_ns: ORIGIN,
        started_ns: START,
        max_source_bytes: 1024 * 1024,
        max_records: 32,
    })?;
    for (index, state, headers, body) in [
        (
            1,
            ClientState::Described,
            "Content-Type: application/sdp\r\n",
            SDP,
        ),
        (
            2,
            ClientState::Ready,
            "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=0000002a\r\n",
            "",
        ),
        (3, ClientState::Playing, "Session: fixture\r\n", ""),
    ] {
        let bytes = format!(
            "RTSP/1.0 200 OK\r\nCSeq: {index}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        );
        source.observe_control(
            &ClientProgress::Accepted(state),
            &frame(bytes.as_bytes(), START + index * 100)?,
        )?;
    }
    if include_document {
        for (sequence, timestamp, marker, payload, received) in [
            (
                100_u16,
                100_u32,
                false,
                b"unknown".as_slice(),
                START + 1_000_123,
            ),
            (
                101,
                200,
                true,
                b"previous-end".as_slice(),
                START + 2_000_456,
            ),
            (102, 300, true, XML, START + 3_000_789),
        ] {
            let mut packet = vec![0x80, 107 | if marker { 0x80 } else { 0 }];
            packet.extend(sequence.to_be_bytes());
            packet.extend(timestamp.to_be_bytes());
            packet.extend(config().stream.ssrc.to_be_bytes());
            packet.extend_from_slice(payload);
            let mut bytes = vec![b'$', 0];
            bytes.extend((packet.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&packet);
            source.observe_interleaved(&frame(&bytes, received)?)?;
        }
    }
    source.finish(END, stop)?;
    Ok(source)
}

#[test]
fn native_cold_reopen_verifies_original_sdp_exact_receive_clock_and_flat_root() -> Test {
    let dir = Directory::new("cold")?;
    let cx = dir.cx()?;
    let native = native(true, NativeMetadataStop::TargetReached)?;
    let original = native.canonical_bytes()?;
    let projected = native.rtpdump()?;
    let retained = {
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let retained = retain_native(&mut dep, &native, binding()?, config(), &cx)?;
        assert_eq!(retained.source_mode(), "native_rtsp_tcp");
        assert_eq!(
            retained.source_representation(),
            "derived_rtpdump_from_native_observations"
        );
        assert_eq!(retained.source_digest(), ContentDigest::sha256(&projected));
        assert_eq!(
            retained.native_source_digest(),
            Some(ContentDigest::sha256(&original))
        );
        assert_eq!(
            dep.publisher().spool().read_bounded(
                retained
                    .native_source_digest()
                    .ok_or("missing native source")?,
                original.len()
            )?,
            original
        );
        assert_eq!(
            dep.publisher()
                .spool()
                .read_bounded(retained.source_digest(), projected.len())?,
            projected
        );
        assert!(retained.processing_complete(), "{:?}", retained.report());
        assert_eq!(retained.documents().len(), 1);
        assert_eq!(
            retained.documents()[0].source_digest(),
            ContentDigest::sha256(XML)
        );
        assert_eq!(
            retained.documents()[0].provenance().fragments[0].replay_received_ns,
            3_000_000
        );
        let witnessed = retained.native_source().ok_or("missing acquisition")?;
        assert_eq!(
            witnessed.description().ok_or("missing SDP")?.bytes(),
            SDP.as_bytes()
        );
        assert_eq!(witnessed.records()[2].received_ns(), START + 3_000_789);
        assert_eq!(
            dep.ledger().batches().len(),
            1,
            "no separately published child root"
        );
        let retry = retain_native(&mut dep, &native, binding()?, config(), &cx)?;
        assert_eq!(retry.identity(), retained.identity());
        assert_eq!(retry.authority_anchor(), retained.authority_anchor());
        assert_eq!(dep.ledger().batches().len(), 1);
        retained
    };
    let dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let cold = RetainedRtpMetadata::open(
        &dep,
        retained.identity(),
        Some(retained.publication_root()),
        &cx,
    )?;
    assert_eq!(
        cold.native_source()
            .ok_or("missing cold acquisition")?
            .canonical_bytes()?,
        original
    );
    assert_eq!(cold.report(), retained.report());
    assert!(cold.processing_complete());
    Ok(())
}

#[test]
fn native_wrong_receive_interval_stream_and_payload_are_rejected_before_publication() -> Test {
    let dir = Directory::new("pins")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let native = native(true, NativeMetadataStop::TargetReached)?;
    for wrong in 0..4 {
        let mut binding = binding()?;
        let mut config = config();
        match wrong {
            0 => binding.receive_interval.earliest.0 += 1,
            1 => binding.receive_interval.latest.0 += 1,
            2 => config.stream.generation += 1,
            _ => config.payload_type += 1,
        }
        assert!(matches!(
            retain_native(&mut dep, &native, binding, config, &cx),
            Err(MetadataError::InvalidBinding)
        ));
    }
    assert!(dep.ledger().batches().is_empty());
    Ok(())
}

#[test]
fn native_partial_and_zero_document_acquisition_remain_retained_without_complete_claims() -> Test {
    for include_document in [false, true] {
        let dir = Directory::new(if include_document { "timeout" } else { "empty" })?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let native = native(include_document, NativeMetadataStop::Timeout)?;
        let retained = retain_native(&mut dep, &native, binding()?, config(), &cx)?;
        assert!(!retained.processing_complete());
        assert_eq!(retained.documents().len(), usize::from(include_document));
        if include_document {
            assert!(retained.report().processing_complete());
        }
        let cold = RetainedRtpMetadata::open(&dep, retained.identity(), None, &cx)?;
        assert!(!cold.processing_complete());
        assert_eq!(
            cold.native_source().ok_or("lost failure source")?.stop(),
            Some(NativeMetadataStop::Timeout)
        );
    }
    Ok(())
}

#[test]
fn native_original_corruption_and_missing_objects_fail_cold_open_and_retry_without_repair() -> Test
{
    for remove in [false, true] {
        let dir = Directory::new(if remove { "missing" } else { "corrupt" })?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let native = native(true, NativeMetadataStop::TargetReached)?;
        let retained = retain_native(&mut dep, &native, binding()?, config(), &cx)?;
        let path = dep.publisher().spool().object_path(
            retained
                .native_source_digest()
                .ok_or("missing native source")?,
        );
        if remove {
            fs::remove_file(&path)?;
        } else {
            fs::write(&path, b"changed-native-original")?;
        }
        assert!(RetainedRtpMetadata::open(&dep, retained.identity(), None, &cx).is_err());
        assert!(retain_native(&mut dep, &native, binding()?, config(), &cx).is_err());
        if remove {
            assert!(!path.exists());
        } else {
            assert_eq!(fs::read(&path)?, b"changed-native-original");
        }
        assert_eq!(dep.ledger().batches().len(), 1);
    }
    Ok(())
}

#[test]
fn native_cancellation_or_root_only_interruption_resumes_one_exact_publication() -> Test {
    for crash in [false, true] {
        let dir = Directory::new(if crash { "root-cut" } else { "cancel" })?;
        let cx = dir.cx()?;
        let native = native(true, NativeMetadataStop::TargetReached)?;
        {
            let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            if crash {
                dep.inject_ledger_crash_at(LedgerCutPoint::AfterRootDurable);
            } else {
                cx.set_cancel_at_checkpoint(STAGE_RTP_METADATA_PUBLISH);
            }
            assert!(retain_native(&mut dep, &native, binding()?, config(), &cx).is_err());
            assert!(dep.ledger().batches().is_empty());
        }
        let fresh = dir.cx()?;
        let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &fresh)?;
        let retained = retain_native(&mut dep, &native, binding()?, config(), &fresh)?;
        let cold = RetainedRtpMetadata::open(&dep, retained.identity(), None, &fresh)?;
        assert_eq!(cold.native_source_digest(), retained.native_source_digest());
        assert_eq!(dep.ledger().batches().len(), 1);
    }
    Ok(())
}

#[test]
fn native_post_commit_cancellation_preserves_the_original_acquisition_handle() -> Test {
    let dir = Directory::new("committed-cancel")?;
    let cx = dir.cx()?;
    let native = native(true, NativeMetadataStop::TargetReached)?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    cx.set_cancel_at_checkpoint("onvif_rtp_metadata:committed");
    let retained = retain_native(&mut dep, &native, binding()?, config(), &cx)?;
    assert!(!cx.io_authority().is_valid());
    assert_eq!(dep.ledger().batches().len(), 1);
    let fresh = dir.cx()?;
    let cold = RetainedRtpMetadata::open(
        &dep,
        retained.identity(),
        Some(retained.publication_root()),
        &fresh,
    )?;
    assert_eq!(cold.native_source_digest(), retained.native_source_digest());
    assert_eq!(
        cold.native_source()
            .ok_or("missing original acquisition")?
            .canonical_bytes()?,
        native.canonical_bytes()?
    );
    Ok(())
}

#[test]
fn hold_on_native_capture_protects_originals_and_shared_file_projection() -> Test {
    let dir = Directory::new("held-native")?;
    let authority = dir.authority()?;
    let cx = ReplayCx::from_context_authority(&authority, &dir.0)?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let native = native(true, NativeMetadataStop::TargetReached)?;
    let retained = retain_native(&mut dep, &native, binding()?, config(), &cx)?;
    let file = retain(&mut dep, &native.rtpdump()?, binding()?, config(), &cx)?;
    assert_ne!(retained.identity(), file.identity());
    assert_eq!(retained.source_digest(), file.source_digest());
    assert_eq!(file.source_mode(), "owner_supplied_rtpdump");
    assert!(file.native_source().is_none());
    let mut request = HoldRequest {
        hold_id: "native-incident".into(),
        import_identity: retained.identity(),
        state: HoldState::Held,
        reason: "Owner original acquisition review".into(),
    };
    let preview = preview_hold(&dep, &request, &authority, &cx)?;
    commit_hold(
        &mut dep,
        &request,
        preview.record.approval(),
        &authority,
        &cx,
    )?;
    let held = plan_scope_deletion(&dep, &DeletionScope::Sensor(binding()?.sensor_id), &cx)?;
    assert!(
        held.blockers
            .iter()
            .any(|finding| finding.kind == "evidence_hold")
    );
    assert!(
        plan_deletion(&dep, retained.identity(), &cx)?
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
    let released = plan_scope_deletion(&dep, &DeletionScope::Sensor(binding()?.sensor_id), &cx)?;
    assert!(released.blockers.is_empty(), "{:?}", released.blockers);
    assert!(
        released.deleted_set().contains(
            &retained
                .native_source_digest()
                .ok_or("missing original acquisition identity")?
        )
    );
    assert!(released.deleted_set().contains(&file.source_digest()));
    Ok(())
}

#[test]
fn existing_deletion_closure_covers_native_originals_and_blocks_projected_reimport() -> Test {
    let dir = Directory::new("delete")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let native = native(true, NativeMetadataStop::TargetReached)?;
    let retained = retain_native(&mut dep, &native, binding()?, config(), &cx)?;
    let plan = plan_scope_deletion(&dep, &DeletionScope::Sensor(binding()?.sensor_id), &cx)?;
    assert_eq!(plan.imports, vec![retained.identity()]);
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(
        plan.deleted_set().contains(
            &retained
                .native_source_digest()
                .ok_or("missing native source")?
        )
    );
    assert!(plan.deleted_set().contains(&retained.source_digest()));
    commit_deletion(
        &mut dep,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &cx,
    )?;
    assert!(matches!(
        RetainedRtpMetadata::open(&dep, retained.identity(), None, &cx),
        Err(MetadataError::EvidenceDeleted { .. })
    ));
    assert!(matches!(
        retain_native(&mut dep, &native, binding()?, config(), &cx),
        Err(MetadataError::EvidenceDeleted { .. })
    ));
    assert!(matches!(
        retain(&mut dep, &native.rtpdump()?, binding()?, config(), &cx),
        Err(MetadataError::EvidenceDeleted { .. })
    ));
    Ok(())
}
