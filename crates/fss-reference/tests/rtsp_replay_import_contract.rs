#![forbid(unsafe_code)]
//! Recorder provenance through retained import, cold decoding, movie review and deletion.
//!
//! Synthetic native packets exercise custody and timing contracts, not camera interoperability,
//! scene coverage or trained-model accuracy. The original archive is deliberately taken offline.

mod hevc_recording_support;
mod recording_support;
#[path = "rtsp_replay_import_contract/support.rs"]
mod support;

use std::cell::Cell;
use std::fs;

use fss_container::demux::{AvcMp4, DemuxLimits, MovieSelectionLimits, VideoCodec};
use fss_core::{ContentDigest, TimestampNs};
use fss_geometry::WorkBudget;
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits as AvcLimits, RecordedH264Range, RecordedH264Request,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as HevcLimits, RecordedH265Range, RecordedH265Request,
};
use fss_reference::ingest::rtsp_import::replay::{
    ADAPTER, RtspReplayImportAuthority, RtspReplayImportRequest, import_rtsp_replay,
    retained_replay_receipt,
};
use fss_reference::ingest::rtsp_import::{RtspCaptureOrigin, RtspImportCodec, RtspImportError};
use fss_reference::ingest::{
    FileIngestAdapter, RetainedFileImport, RetainedReadLimits, VerifiedChunkCache,
};
use fss_reference::rtsp::recording_replay::ReplayTermination;

use support::{Fixture, Owner, SITE, Test, context, work};

fn decoded_samples(
    f: &Fixture,
    identity: ContentDigest,
    first: usize,
    count: usize,
) -> Test<Vec<(usize, Vec<u8>)>> {
    let mut frames = Vec::new();
    match f.request.codec {
        RtspImportCodec::Avc => {
            let mut decoder = RecordedH264Range::open(
                f.target()?,
                RecordedH264Request {
                    import_identity: identity,
                    first_segment: first,
                    segment_count: count,
                    interpretation: ComponentInterpretation::YCbCr,
                    read_limits: RetainedReadLimits::default(),
                    decoder_limits: AvcLimits::default(),
                },
                &f.cx,
            )?;
            while let Some(frame) = decoder.next_frame(f.target()?, &f.cx)? {
                assert_eq!(frame.receipt().import_identity(), identity);
                assert!(!frame.pixels().is_empty());
                frames.push((frame.segment_index() as usize, frame.pixels().to_vec()));
            }
        }
        RtspImportCodec::Hevc => {
            let mut decoder = RecordedH265Range::open(
                f.target()?,
                RecordedH265Request {
                    import_identity: identity,
                    first_segment: first,
                    segment_count: count,
                    interpretation: ComponentInterpretation::YCbCr,
                    read_limits: RetainedReadLimits::default(),
                    decoder_limits: HevcLimits::default(),
                },
                &f.cx,
            )?;
            while let Some(frame) = decoder.next_frame(f.target()?, &f.cx)? {
                assert_eq!(frame.receipt().import_identity(), identity);
                assert!(!frame.pixels().is_empty());
                frames.push((frame.segment_index() as usize, frame.pixels().to_vec()));
            }
        }
    }
    let mut observed = frames.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    observed.sort_unstable();
    assert_eq!(observed, (first..first + count).collect::<Vec<_>>());
    Ok(frames)
}

#[test]
fn avc_and_hevc_replay_imports_decode_and_select_movies_after_the_archive_is_offline() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = Fixture::new("cold", codec, 0, false)?;
        let imported = f.run()?;
        assert!(!imported.import.reused);
        assert_eq!(imported.windows, 2);
        assert_eq!(imported.import.frames, f.frames);
        assert_eq!(imported.replay_root, f.receipt.root());
        assert_eq!(imported.replay_request, f.receipt.request().digest());
        assert_eq!(imported.replay_approval, f.receipt.approval());
        assert_eq!(imported.requested_window, f.receipt.request().window());
        assert_eq!(
            imported.acknowledged_window,
            f.receipt.acceptance().acknowledged()
        );
        assert!(imported.onvif_source.is_none());
        assert_eq!(imported.termination, ReplayTermination::InputEnded);
        assert!(!imported.publication_complete);
        assert!(imported.decode_gaps.is_empty());
        assert_eq!(imported.import.capture_time_label, "unknown");
        let retained = f.retained(imported.import.import_identity)?;
        assert_eq!(retained.manifest().adapter_id, ADAPTER);
        assert!(
            retained
                .manifest()
                .adapter_generation
                .starts_with("gen:rtsp-replay-archive:v1:")
        );
        assert_eq!(
            retained.manifest().input_sha256,
            ContentDigest::sha256(&f.media)
        );
        assert!(
            retained
                .manifest()
                .validate_retained(RetainedReadLimits::default())
                .is_err()
        );
        assert!(
            FileIngestAdapter::fetch_segment_bytes(retained.manifest(), f.target()?, 0).is_err()
        );
        f.assert_original_closure()?;
        let before = decoded_samples(&f, imported.import.import_identity, 0, f.frames)?;
        f.offline_archive_and_reopen()?;
        let retained = f.retained(imported.import.import_identity)?;
        let origin = retained_replay_receipt(
            f.target()?,
            imported.import.import_identity,
            RetainedReadLimits::default(),
            &f.cx,
        )?
        .ok_or("cold replay origin")?;
        assert_eq!(origin.metadata_bytes(), f.receipt.metadata_bytes());
        assert_eq!(origin.root(), f.receipt.root());
        assert_eq!(
            retained.verify_source(f.target()?, RetainedReadLimits::default(), &f.cx)?,
            ContentDigest::sha256(&f.media)
        );
        assert_eq!(
            decoded_samples(&f, imported.import.import_identity, 0, f.frames)?,
            before
        );

        let selected = retained.select_movie_interval(
            f.target()?,
            imported.decode_interval.clone(),
            RetainedReadLimits::default(),
            MovieSelectionLimits::default(),
            &f.cx,
        )?;
        let native = AvcMp4::parse(&f.media, None, DemuxLimits::default())?;
        assert_eq!(
            selected.selection,
            native.select_movie_interval(
                imported.decode_interval.clone(),
                MovieSelectionLimits::default()
            )?
        );
        assert_eq!(selected.source_adapter_id, ADAPTER);
        assert_eq!(
            selected.source_adapter_generation,
            retained.manifest().adapter_generation
        );
        assert_eq!(selected.capture_time_label, "unknown");
        assert_eq!(selected.import_root, imported.import.import_root);
        assert_eq!(
            selected.codec,
            if codec == RtspImportCodec::Avc {
                VideoCodec::Avc
            } else {
                VideoCodec::Hevc
            }
        );
        assert!(selected.origin_read_bytes_charged > 0);
        assert!(
            retained
                .select_movie_interval_with_origin_limit(
                    f.target()?,
                    imported.decode_interval,
                    RetainedReadLimits::default(),
                    MovieSelectionLimits::default(),
                    selected.origin_read_bytes_charged - 1,
                    &f.cx,
                )
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn onvif_selection_receipt_and_packet_closure_survive_cold_import_and_deletion_planning() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = Fixture::new("onvif", codec, 0, true)?;
        assert!(f.receipt.request().onvif_source().is_some());
        let result = f.run()?;
        assert_eq!(
            result.onvif_source,
            f.receipt
                .request()
                .onvif_source()
                .map(|source| source.digest())
                .transpose()?
        );
        f.offline_archive_and_reopen()?;
        f.assert_original_closure()?;
        let origin = retained_replay_receipt(
            f.target()?,
            result.import.import_identity,
            RetainedReadLimits::default(),
            &f.cx,
        )?
        .ok_or("ONVIF replay origin")?;
        assert_eq!(
            origin.request().onvif_source(),
            f.receipt.request().onvif_source()
        );
        let retained = f.retained(result.import.import_identity)?;
        retained.verify_source(f.target()?, RetainedReadLimits::default(), &f.cx)?;
        let deletion = fss_reference::deletion::plan_deletion(
            f.target()?,
            result.import.import_identity,
            &f.cx,
        )?;
        for digest in f.originals.keys().copied().chain([result.import.proof]) {
            assert!(
                deletion
                    .deletable
                    .iter()
                    .any(|entry| entry.digest == digest),
                "replay provenance object {digest} escaped deletion closure"
            );
        }
    }
    Ok(())
}

#[test]
fn whole_request_pins_and_cumulative_limits_refuse_before_any_destination_mutation() -> Test {
    let mut f = Fixture::new("bounds", RtspImportCodec::Hevc, 0, false)?;
    let original = f.request.clone();
    let before = f.snapshot()?;
    for case in 0..12 {
        f.request = original.clone();
        match case {
            0 => f.request.codec = RtspImportCodec::Avc,
            1 => f.request.receipt_root = ContentDigest::sha256(b"other receipt"),
            2 => f.request.request_identity = ContentDigest::sha256(b"other replay request"),
            3 => f.request.scope.recording.generation += 1,
            4 => {
                f.request.scope.recording.anchor = ContentDigest::sha256(b"other source authority")
            }
            5 => {
                f.request.scope.recording.receive_clock =
                    ContentDigest::sha256(b"other receive clock")
            }
            6 => f.request.scope.decode_clock = ContentDigest::sha256(b"other decode clock"),
            7 => f.request.scope.time_scale += 1,
            8 => f.request.max_windows = 1,
            9 => f.request.max_frames = f.frames - 1,
            10 => f.request.max_original_bytes = 1,
            _ => f.request.max_media_bytes = f.media.len() as u64 - 1,
        }
        assert!(
            f.run().is_err(),
            "admitted changed binding or ceiling case {case}"
        );
        assert_eq!(
            f.snapshot()?,
            before,
            "partial publication for refusal case {case}"
        );
    }
    f.request = original;
    assert!(
        import_rtsp_replay(
            f.source.as_ref().ok_or("source")?,
            f.target.as_mut().ok_or("target")?,
            &f.request,
            &Owner(true),
            &f.cx,
            &mut WorkBudget::new(1),
        )
        .is_err()
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn request_identity_binds_replay_origin_time_assumptions_and_every_allowance() -> Test {
    let f = Fixture::new("identity", RtspImportCodec::Avc, 0, false)?;
    let baseline = f.request.digest()?;
    for case in 0..12 {
        let mut changed = f.request.clone();
        match case {
            0 => changed.receipt_root = ContentDigest::sha256(b"changed immutable receipt"),
            1 => changed.request_identity = ContentDigest::sha256(b"changed approved replay"),
            2 => changed.receive_time.0 += 1,
            3 => {
                changed.capture_origin = Some(RtspCaptureOrigin {
                    start_ns: TimestampNs(1_000_000),
                    uncertainty_ns: 1,
                })
            }
            4 => changed.preserve_decode_gaps = true,
            5 => changed.max_windows -= 1,
            6 => changed.max_frames -= 1,
            7 => changed.max_original_bytes -= 1,
            8 => changed.max_media_bytes -= 1,
            9 => changed.scope.recording.generation += 1,
            10 => changed.scope.decode_clock = ContentDigest::sha256(b"new declared decode clock"),
            _ => changed.codec = RtspImportCodec::Hevc,
        }
        assert_ne!(changed.digest()?, baseline, "unbound request field {case}");
    }
    Ok(())
}

#[test]
fn recorder_gaps_need_explicit_consent_and_remain_decoder_and_movie_boundaries() -> Test {
    let mut f = Fixture::new("gaps", RtspImportCodec::Avc, 7_200, false)?;
    let before = f.snapshot()?;
    assert!(f.run().is_err());
    assert_eq!(f.snapshot()?, before);
    f.request.preserve_decode_gaps = true;
    let result = f.run()?;
    assert_eq!(result.decode_gaps, vec![10_800..18_000]);
    let retained = f.retained(result.import.import_identity)?;
    assert_eq!(
        retained
            .manifest()
            .segment_spans
            .iter()
            .enumerate()
            .filter_map(|(index, span)| span.gap_before.then_some(index))
            .collect::<Vec<_>>(),
        vec![3]
    );
    let movie = retained.select_movie_interval(
        f.target()?,
        result.decode_interval,
        RetainedReadLimits::default(),
        MovieSelectionLimits::default(),
        &f.cx,
    )?;
    assert!(!movie.selection.gaps.is_empty());
    assert_eq!(movie.selection.decode_spans.len(), 2);
    for span in movie.selection.decode_spans {
        decoded_samples(
            &f,
            result.import.import_identity,
            span.first_sample,
            span.sample_count,
        )?;
    }
    assert!(decoded_samples(&f, result.import.import_identity, 0, f.frames).is_err());
    Ok(())
}

#[test]
fn current_masks_dominate_pixels_from_historical_hevc_replay() -> Test {
    let mut f = Fixture::new("masked", RtspImportCodec::Hevc, 0, true)?;
    let result = f.run()?;
    f.offline_archive_and_reopen()?;
    let mut decoder = RecordedH265Range::open(
        f.target()?,
        RecordedH265Request {
            import_identity: result.import.import_identity,
            first_segment: 0,
            segment_count: f.frames,
            interpretation: ComponentInterpretation::YCbCr,
            read_limits: RetainedReadLimits::default(),
            decoder_limits: HevcLimits::default(),
        },
        &f.cx,
    )?;
    let dimensions = decoder
        .next_frame(f.target()?, &f.cx)?
        .ok_or("first frame")?
        .dimensions();
    drop(decoder);
    let policy = PrivacyMaskPolicy::new(
        f.request.scope.recording.sensor.clone(),
        dimensions,
        &[[0, 0, dimensions[0], dimensions[1]]],
    )?;
    let approval = preview_mask(f.target()?, &policy)?.approval;
    declare_mask(f.target.as_mut().ok_or("target")?, &policy, approval, &f.cx)?;
    for (_, pixels) in decoded_samples(&f, result.import.import_identity, 0, f.frames)? {
        assert!(pixels.iter().all(|value| *value == MASK_FILL_LUMA));
    }
    Ok(())
}

#[test]
fn missing_receipt_or_late_original_refuses_before_copying_any_bytes() -> Test {
    let mut f = Fixture::new("missing", RtspImportCodec::Avc, 0, false)?;
    let before = f.snapshot()?;
    for digest in [
        f.receipt.root(),
        f.receipt.manifest().metadata_digest().ok_or("metadata")?,
        *f.packet_packs.last().ok_or("last original")?,
    ] {
        let path = f
            .source
            .as_ref()
            .ok_or("source")?
            .spool()
            .object_path(digest);
        let offline = path.with_extension("offline");
        fs::rename(&path, &offline)?;
        assert!(
            f.run().is_err(),
            "missing original {digest} was treated as source custody"
        );
        assert_eq!(f.snapshot()?, before);
        fs::rename(offline, path)?;
    }
    assert!(!f.run()?.import.reused);
    Ok(())
}

#[test]
fn changed_retained_replay_proof_refuses_even_with_a_warm_native_range_cache() -> Test {
    let mut f = Fixture::new("metadata-damage", RtspImportCodec::Avc, 0, true)?;
    let result = f.run()?;
    let retained = f.retained(result.import.import_identity)?;
    let mut cache = VerifiedChunkCache::default();
    retained.read_segment_cached(
        f.target()?,
        0,
        RetainedReadLimits::default(),
        &f.cx,
        &mut cache,
    )?;
    let path = f
        .target()?
        .publisher()
        .spool()
        .object_path(result.import.proof);
    fs::write(&path, b"changed historical approval and ONVIF provenance")?;
    assert!(
        RetainedFileImport::open(
            f.target()?,
            result.import.import_identity,
            RetainedReadLimits::default(),
            &f.cx
        )
        .is_err()
    );
    assert!(
        retained
            .read_segment_cached(
                f.target()?,
                1,
                RetainedReadLimits::default(),
                &f.cx,
                &mut cache
            )
            .is_err()
    );
    assert!(
        f.run().is_err(),
        "import retry silently repaired tampered retained provenance"
    );
    Ok(())
}

#[test]
fn cold_replay_inspection_requires_intact_physical_companion_metadata() -> Test {
    let mut f = Fixture::new("cold-companion", RtspImportCodec::Avc, 0, true)?;
    let result = f.run()?;
    f.offline_archive_and_reopen()?;
    let before = f.snapshot()?;
    let retained = f.retained(result.import.import_identity)?;
    for digest in [
        f.receipt.root(),
        f.receipt.manifest().metadata_digest().ok_or("metadata")?,
    ] {
        let path = f.target()?.publisher().spool().object_path(digest);
        let expected = fs::read(&path)?;
        fs::write(&path, b"corrupt retained recorder companion")?;
        assert!(
            retained_replay_receipt(
                f.target()?,
                result.import.import_identity,
                RetainedReadLimits::default(),
                &f.cx,
            )
            .is_err()
        );
        assert!(
            retained
                .verify_source(f.target()?, RetainedReadLimits::default(), &f.cx)
                .is_err()
        );
        fs::write(path, expected)?;
    }
    let origin = retained_replay_receipt(
        f.target()?,
        result.import.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?
    .ok_or("restored cold replay origin")?;
    assert_eq!(origin.metadata_bytes(), f.receipt.metadata_bytes());
    assert_eq!(
        f.snapshot()?,
        before,
        "inspection must not mutate retained authority"
    );
    Ok(())
}

#[test]
fn intact_reconstructed_movie_cannot_hide_damage_to_the_second_original_packet_pack() -> Test {
    let mut f = Fixture::new("original-damage", RtspImportCodec::Hevc, 0, false)?;
    let result = f.run()?;
    let retained = f.retained(result.import.import_identity)?;
    let packet = *f.packet_packs.last().ok_or("last packet pack")?;
    fs::write(
        f.target()?.publisher().spool().object_path(packet),
        b"damaged RTP",
    )?;
    let mut media = Vec::new();
    for digest in &retained.manifest().ordered_chunks {
        media.extend(f.target()?.publisher().spool().read(*digest)?);
    }
    assert_eq!(media, f.media);
    assert!(
        retained
            .verify_source(f.target()?, RetainedReadLimits::default(), &f.cx)
            .is_err()
    );
    assert!(
        retained
            .read_segment(
                f.target()?,
                f.frames - 1,
                RetainedReadLimits::default(),
                &f.cx
            )
            .is_err()
    );
    assert!(
        retained
            .select_movie_interval(
                f.target()?,
                0..18_000,
                RetainedReadLimits::default(),
                MovieSelectionLimits::default(),
                &f.cx
            )
            .is_err()
    );
    Ok(())
}

struct RevokedAfter(Cell<usize>);
impl RtspReplayImportAuthority for RevokedAfter {
    fn permit(&self, _: &RtspReplayImportRequest, _: &ReferenceDeployment) -> bool {
        let calls = self.0.get();
        self.0.set(calls.saturating_sub(1));
        calls > 0
    }
}

#[test]
fn authority_denial_revocation_and_pre_read_cancellation_never_complete_an_import() -> Test {
    let mut f = Fixture::new("denied", RtspImportCodec::Avc, 0, false)?;
    let before = f.snapshot()?;
    assert!(matches!(
        import_rtsp_replay(
            f.source.as_ref().ok_or("source")?,
            f.target.as_mut().ok_or("target")?,
            &f.request,
            &Owner(false),
            &f.cx,
            &mut work(),
        ),
        Err(RtspImportError::Denied)
    ));
    assert_eq!(f.snapshot()?, before);
    assert!(
        import_rtsp_replay(
            f.source.as_ref().ok_or("source")?,
            f.target.as_mut().ok_or("target")?,
            &f.request,
            &RevokedAfter(Cell::new(3)),
            &f.cx,
            &mut work(),
        )
        .is_err()
    );
    assert_eq!(f.snapshot()?, before);
    f.cx.request_cancellation();
    assert!(f.run().is_err());
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn interrupted_publication_resumes_and_completed_retry_preserves_authority_identity() -> Test {
    let mut f = Fixture::new("retry", RtspImportCodec::Avc, 0, false)?;
    f.cx.set_cancel_at_checkpoint("file_parts:root");
    assert!(f.run().is_err());
    f.cx = context(&f.directory.0.join("destination"))?;
    let result = f.run()?;
    let before = f.snapshot()?;
    let anchor = f.target()?.current_anchor().clone();
    drop(f.target.take());
    f.cx = context(&f.directory.0.join("destination"))?;
    f.target = Some(ReferenceDeployment::open(
        &f.directory.0.join("destination"),
        SITE,
        &f.cx,
    )?);
    let retried = f.run()?;
    assert!(retried.import.reused);
    assert_eq!(
        retried.import.import_identity,
        result.import.import_identity
    );
    assert_eq!(retried.import.import_root, result.import.import_root);
    assert_eq!(retried.import.proof, result.import.proof);
    assert_eq!(retried.replay_root, result.replay_root);
    assert_eq!(f.snapshot()?, before);
    assert_eq!(f.target()?.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn explicit_capture_hint_is_an_assumption_not_the_recorder_requested_or_accepted_utc() -> Test {
    let mut f = Fixture::new("assumed-time", RtspImportCodec::Avc, 0, false)?;
    let unknown = f.run()?;
    f.request.capture_origin = Some(RtspCaptureOrigin {
        start_ns: TimestampNs(1_000_000_000),
        uncertainty_ns: 25,
    });
    let assumed = f.run()?;
    assert_ne!(
        unknown.import.import_identity,
        assumed.import.import_identity
    );
    assert_ne!(unknown.import.import_root, assumed.import.import_root);
    assert_eq!(assumed.import.capture_time_label, "operator_assumption");
    let retained = f.retained(assumed.import.import_identity)?;
    for index in 0..f.frames {
        let capsule = fss_reference::ingest::recorded_decode::retained_source_capsule(
            f.target()?,
            &retained,
            index,
        )?;
        assert_eq!(
            capsule.capture.earliest.0,
            1_000_000_000 + index as i128 * 40_000_000 - 25
        );
        assert_eq!(
            capsule.capture.latest.0,
            1_000_000_000 + index as i128 * 40_000_000 + 25
        );
    }
    Ok(())
}
