#![forbid(unsafe_code)]
//! Recorder replay through real event-linked disclosure and committed deletion.
//! The existing whole-receipt producer fixtures are reused without replacing their contracts.

mod hevc_recording_support;
mod recording_support;
#[path = "rtsp_replay_import_contract/support.rs"]
mod support;

use std::collections::BTreeMap;
use std::fs;

use fss_core::{CanonicalEncode, CaptureInterval, ContentDigest, TimestampNs};
use fss_publication::NeverCancel;
use fss_reference::ingest::rtsp_import::replay::{ADAPTER, retained_replay_receipt};
use fss_reference::ingest::rtsp_import::{RtspCaptureOrigin, RtspImportCodec};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits, VerifiedChunkCache};
use fss_reference::rtsp::client::replay::{ReplayAcceptance, ReplayWindow};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::{
    ReplayReceipt, ReplayRequest, ReplayTermination, ReplayWindowProof, publish_replay_receipt,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use support::{Fixture, SITE, Test, context};

/// Moving source used by the existing native original-media export contract. Every RTP NAL,
/// timing entry and sender EOS goes through the real HEVC recording producer before replay.
fn moving_hevc() -> Test<fss_reference::rtsp::recording::hevc::PreparedHevcRecording> {
    use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec, length_prefixed_nals};
    use fss_packet::hevc::{HevcConfiguration, HevcConfigurationLimits};
    use fss_reference::rtsp::recording::hevc::{HevcRecordingTiming, prepare_hevc_recording};

    let bytes = include_bytes!("fixtures/hevc_ingest/watch_96x48_moving.mp4");
    let movie = AvcMp4::parse(bytes, None, DemuxLimits::default())?;
    assert_eq!(movie.codec(), VideoCodec::Hevc);
    let sets = movie
        .parameter_sets()
        .iter()
        .map(|range| &bytes[range.clone()])
        .collect::<Vec<_>>();
    let parameter = |kind| {
        sets.iter()
            .copied()
            .find(|nal| (nal[0] >> 1) & 63 == kind)
            .ok_or("HEVC parameter set")
    };
    let configuration = HevcConfiguration::parse(
        parameter(32)?,
        parameter(33)?,
        parameter(34)?,
        HevcConfigurationLimits::default(),
    )?;
    let ticks = |value: i128| -> Test<i128> {
        let scaled = value.checked_mul(90_000).ok_or("timing overflow")?;
        let scale = i128::from(movie.timescale());
        if scaled % scale != 0 {
            return Err("fixture timing is not exactly representable at 90 kHz".into());
        }
        Ok(scaled / scale)
    };
    let mut packets = Vec::new();
    let mut timing = Vec::new();
    let mut sequence = 1_u64;
    let mut timestamp = 0;
    for sample in movie.samples() {
        let payload = &bytes[sample.source.clone()];
        let nals = length_prefixed_nals(payload, movie.nal_length_bytes())?;
        timestamp = u32::try_from(ticks(sample.presentation_time())?)?;
        for (index, range) in nals.iter().enumerate() {
            packets.push(hevc_recording_support::packet(
                sequence,
                timestamp,
                index + 1 == nals.len(),
                &payload[range.clone()],
            ));
            sequence += 1;
        }
        timing.push(HevcRecordingTiming {
            decode_time: u64::try_from(ticks(i128::from(sample.decode_time))?)?,
            duration: u32::try_from(ticks(i128::from(sample.duration))?)?,
            composition_offset: i32::try_from(ticks(i128::from(sample.composition_offset))?)?,
        });
    }
    packets.push(hevc_recording_support::packet(
        sequence,
        timestamp,
        true,
        &[0x48, 1, 0x80],
    ));
    assert_eq!(timing.len(), 14);
    Ok(prepare_hevc_recording(
        hevc_recording_support::scope()?,
        &configuration,
        90_000,
        &timing,
        &hevc_recording_support::borrowed(&packets),
    )?)
}

fn moving_fixture() -> Test<Fixture> {
    let mut f = Fixture::new("lifecycle-export", RtspImportCodec::Hevc, 0, false)?;
    let recording = moving_hevc()?;
    let plan = recording.publication_plan();
    let interval = ReplayWindow::from_timestamps("20261105T010000Z", "20261105T010500Z")?;
    let request = ReplayRequest::new_hevc(
        plan.summary().scope.clone(),
        ContentDigest::sha256(b"approved moving recorder route"),
        interval,
        ContentDigest::sha256(b"independent moving recorder decode clock"),
    )?;
    let scope = CatalogScope {
        recording: request.scope().clone(),
        decode_clock: request.decode_clock(),
        time_scale: 90_000,
    };
    let slot = HevcArchiveNamespace::new(scope.clone())?.window_slot(0)?;
    let source = f.source.as_mut().ok_or("source")?;
    let mut publication =
        RecordingPublication::new(plan, source, slot.clone(), plan.byte_len(), 100)?;
    for at in 0..4 {
        assert!(matches!(
            publication.step(at, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    assert!(matches!(
        publication.step(4, &NeverCancel)?,
        RecordingProgress::Published(_)
    ));
    drop(publication);
    let receipt = ReplayReceipt::prepare(
        request,
        scope.clone(),
        ContentDigest::sha256(b"approved complete moving replay capture"),
        ReplayAcceptance::new(7, interval, interval)?,
        vec![ReplayWindowProof::from_hevc(slot, &recording)?],
        ReplayTermination::InputEnded,
        false,
    )?;
    publish_replay_receipt(&receipt, source, &NeverCancel)?;
    let mut originals =
        BTreeMap::from([(plan.manifest().root(), plan.manifest().canonical_bytes())]);
    originals.extend(
        plan.children()
            .into_iter()
            .map(|(_, digest, bytes)| (digest, bytes.to_vec())),
    );
    originals.insert(receipt.root(), receipt.manifest().canonical_bytes());
    originals.insert(
        ContentDigest::sha256(receipt.metadata_bytes()),
        receipt.metadata_bytes().to_vec(),
    );
    f.media = [plan.objects().initialization, plan.objects().media].concat();
    f.frames = plan.summary().samples;
    f.packet_packs = vec![ContentDigest::sha256(plan.objects().source)];
    f.originals = originals;
    f.request.receipt_root = receipt.root();
    f.request.request_identity = receipt.request().digest();
    f.request.scope = scope;
    f.request.capture_origin = Some(RtspCaptureOrigin {
        start_ns: TimestampNs(0),
        uncertainty_ns: 0,
    });
    f.receipt = receipt;
    Ok(f)
}

fn export_authority() -> Test<fss_core::region::ContextAuthority> {
    use fss_core::region::{ContextAuthority, RootAuthoritySpec};
    use fss_core::{BudgetVector, OperationId};
    use fss_reference::evidence_export::{CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE};

    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:replay-export".into(),
        operation_id: OperationId::parse("operation:replay-export")?,
        principal: "principal:replay-import".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "CAP-READ-MEDIA-001".into(),
            CAP_EXPORT_PREPARE.into(),
            CAP_EXPORT_COMMIT.into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(131_072)
            .build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}

#[test]
fn event_linked_original_export_keeps_replay_classification_and_rechecks_cold_custody() -> Test {
    use fss_reference::evidence_export::EventExportRequest;
    use fss_reference::ingest::long_dwell::LongDwellLimits;
    use fss_reference::ingest::long_watch::LongWatchReport;
    use fss_reference::ingest::recorded_decode::ComponentInterpretation;
    use fss_reference::ingest::recorded_watch::{
        WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
    };
    use fss_reference::original_media_export::{
        OriginalMediaExportRequest, approve_original_media_export, preview_original_media_export,
        revalidate_original_media_export, verify_original_media_export,
    };
    use std::collections::BTreeSet;

    let mut f = moving_fixture()?;
    let result = f.run()?;
    let imported = result.import;
    assert_eq!(imported.frames, 14);
    f.assert_original_closure()?;
    f.offline_archive_and_reopen()?;
    let owner = export_authority()?;
    f.cx = ReplayCx::from_context_authority(&owner, f.target()?.root().to_path_buf())?;
    let plan = WatchPlan {
        import_identity: imported.import_identity,
        interpretation: ComponentInterpretation::YCbCr,
        first_segment: 0,
        segment_count: imported.frames,
        zones: vec![WatchZone {
            zone_id: "porch".into(),
            x: 0,
            y: 0,
            width: 96,
            height: 48,
        }],
        detector: WatchDetectorConfig {
            learning_rate_num: 0,
            ..WatchDetectorConfig::default()
        },
        tracker: WatchTrackerConfig::default(),
    };
    let mut report = LongWatchReport::analyze(
        f.target()?,
        &plan,
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &f.cx,
    )?;
    let candidate = report
        .candidates()
        .first()
        .ok_or("native watch candidate")?;
    let event_id = candidate.event().event_id.clone();
    let approval = candidate.proposal_digest();
    assert_eq!(
        report.publish(
            f.target.as_mut().ok_or("target")?,
            &BTreeSet::from([approval]),
            &f.cx,
        )?,
        1,
    );
    let (event, _) = f.target()?.current_event_authority(&event_id)?;
    let request = OriginalMediaExportRequest {
        event: EventExportRequest {
            event_id,
            expected_revision: event.revision_digest(),
            recipient: "recipient:replay-case".into(),
            purpose: "Review exact recorder footage and its context".into(),
            expires_at: TimestampNs(2_000_000_000_000),
        },
        import_identity: imported.import_identity,
        expected_import_root: imported.import_root,
        whole_source_authorized: true,
        destination_binding: ContentDigest::sha256(b"approved replay export destination"),
        max_source_bytes: f.media.len() as u64,
        attested_now: CaptureInterval::new(
            TimestampNs(1_000_000_000_001),
            TimestampNs(1_000_000_000_010),
        )?,
    };
    let before = f.snapshot()?;
    let anchor = f.target()?.current_anchor().clone();
    let preview = preview_original_media_export(f.target()?, &request, &owner, &f.cx)?;
    assert_eq!(preview.media_bytes(), f.media);
    assert!(preview.record_json().contains(ADAPTER));
    assert!(
        preview
            .record_json()
            .contains("\"capture_time_basis\":\"operator_assumption\"")
    );
    let prepared =
        approve_original_media_export(f.target()?, &request, preview.approval(), &owner, &f.cx)?;
    revalidate_original_media_export(f.target()?, &prepared, &owner, &f.cx)?;
    let record = verify_original_media_export(
        preview.manifest_bytes(),
        preview.record_bytes(),
        preview.media_bytes(),
        preview.root(),
    )?;
    assert_eq!(record.to_json(), preview.record_json());
    assert_eq!(f.snapshot()?, before);
    assert_eq!(f.target()?.current_anchor(), &anchor);
    fs::write(
        f.target()?.publisher().spool().object_path(imported.proof),
        b"damaged historical replay origin",
    )?;
    assert!(preview_original_media_export(f.target()?, &request, &owner, &f.cx).is_err());
    assert!(revalidate_original_media_export(f.target()?, &prepared, &owner, &f.cx).is_err());
    assert_eq!(f.snapshot()?, before);
    assert_eq!(f.target()?.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn committed_deletion_revokes_companion_cached_reads_decoding_and_exact_reimport() -> Test {
    use fss_reference::deletion::{commit_deletion, plan_deletion};
    use fss_reference::ingest::recorded_decode::ComponentInterpretation;
    use fss_reference::ingest::recorded_decode::h264::{
        DecoderLimits as AvcLimits, RecordedH264Range, RecordedH264Request,
    };
    use fss_reference::ingest::recorded_decode::h265::{
        DecoderLimits as HevcLimits, RecordedH265Range, RecordedH265Request,
    };

    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = Fixture::new("lifecycle-delete", codec, 0, true)?;
        let result = f.run()?;
        let imported = result.import;
        let retained = f.retained(imported.import_identity)?;
        let mut cache = VerifiedChunkCache::default();
        retained.read_segment_cached(
            f.target()?,
            0,
            RetainedReadLimits::default(),
            &f.cx,
            &mut cache,
        )?;
        assert!(
            retained_replay_receipt(
                f.target()?,
                imported.import_identity,
                RetainedReadLimits::default(),
                &f.cx,
            )?
            .is_some()
        );
        let plan = plan_deletion(f.target()?, imported.import_identity, &f.cx)?;
        assert!(
            plan.blockers.is_empty(),
            "deletion blockers: {:?}",
            plan.blockers
        );
        for digest in f.originals.keys().copied().chain([imported.proof]) {
            assert!(plan.deletable.iter().any(|object| object.digest == digest));
        }
        let approval = plan.approval_digest("principal:replay-import")?;
        commit_deletion(
            f.target.as_mut().ok_or("target")?,
            plan.digest()?,
            approval,
            "principal:replay-import",
            &f.cx,
        )?;
        for digest in f.originals.keys().copied().chain([imported.proof]) {
            assert!(f.target()?.publisher().spool().read(digest).is_err());
        }
        // Deleting retained custody does not claim control over the separate recorder archive.
        for (digest, bytes) in &f.originals {
            assert_eq!(
                f.source.as_ref().ok_or("source")?.spool().read(*digest)?,
                *bytes
            );
        }
        assert!(
            retained
                .read_segment_cached(
                    f.target()?,
                    0,
                    RetainedReadLimits::default(),
                    &f.cx,
                    &mut cache,
                )
                .is_err()
        );
        drop(f.target.take());
        let root = f.directory.0.join("destination");
        f.cx = context(&root)?;
        f.target = Some(ReferenceDeployment::open(&root, SITE, &f.cx)?);
        let before = f.snapshot()?;
        assert!(
            retained_replay_receipt(
                f.target()?,
                imported.import_identity,
                RetainedReadLimits::default(),
                &f.cx,
            )
            .is_err()
        );
        assert!(
            RetainedFileImport::open(
                f.target()?,
                imported.import_identity,
                RetainedReadLimits::default(),
                &f.cx,
            )
            .is_err()
        );
        match codec {
            RtspImportCodec::Avc => assert!(
                RecordedH264Range::open(
                    f.target()?,
                    RecordedH264Request {
                        import_identity: imported.import_identity,
                        first_segment: 0,
                        segment_count: imported.frames,
                        interpretation: ComponentInterpretation::YCbCr,
                        read_limits: RetainedReadLimits::default(),
                        decoder_limits: AvcLimits::default(),
                    },
                    &f.cx,
                )
                .is_err()
            ),
            RtspImportCodec::Hevc => assert!(
                RecordedH265Range::open(
                    f.target()?,
                    RecordedH265Request {
                        import_identity: imported.import_identity,
                        first_segment: 0,
                        segment_count: imported.frames,
                        interpretation: ComponentInterpretation::YCbCr,
                        read_limits: RetainedReadLimits::default(),
                        decoder_limits: HevcLimits::default(),
                    },
                    &f.cx,
                )
                .is_err()
            ),
        }
        assert!(
            f.run().is_err(),
            "deleted replay identity was resurrected from source"
        );
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}
