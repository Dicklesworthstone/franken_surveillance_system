#![forbid(unsafe_code)]
//! Protected selection, exact original custody, independent native identities and cold replay.

use super::*;
use fss_core::PrincipalId;
use fss_object::{HostSpoolIo, RecordingSpoolIo};
use fss_reference::agent_recording_context::{RecordingContextLimits, RecordingContextRequest};
use fss_reference::agent_recordings::{RecordingQueryCodec, RecordingQueryRequest};
use fss_reference::ingest::rtsp_import::query::{
    RtspQueryImportAuthority, RtspQueryImportError, RtspQueryImportFailure, RtspQueryImportPlan,
    RtspQueryImportReceipt, RtspQueryImportSettings, STAGE_QUERY_WINDOW, import_rtsp_query,
    import_rtsp_query_existing, preview_rtsp_query_import,
};
use std::ops::Range;
use std::sync::Arc;

#[path = "query_descriptor.rs"]
mod descriptor;
#[path = "query_refusals.rs"]
mod refusals;

#[allow(dead_code)]
#[path = "../support/import_integrity.rs"]
mod integrity;

fn request(f: &Fixture, interval: Range<u64>) -> Test<RecordingContextRequest> {
    Ok(RecordingContextRequest {
        recording: RecordingQueryRequest {
            codec: match f.request.codec {
                RtspImportCodec::Avc => RecordingQueryCodec::Avc,
                RtspImportCodec::Hevc => RecordingQueryCodec::Hevc,
            },
            scope: f.request.scope.clone(),
            catalog_slot: f.request.slot.clone(),
            catalog_root: f.request.root,
            interval,
            max_windows: 32,
            max_hydration_bytes: MAX_ORIGINAL_BYTES,
        },
        principal: PrincipalId::parse("principal:rtsp-catalog-import")?,
        expected_anchor: None,
    })
}

fn settings(f: &Fixture) -> RtspQueryImportSettings {
    RtspQueryImportSettings {
        site: SITE.to_owned(),
        receive_time: f.request.receive_time,
        max_frames: MAX_FRAMES,
        max_original_bytes: MAX_ORIGINAL_BYTES,
        max_media_bytes: MAX_MEDIA_BYTES,
        max_work: 1024 * 1024 * 1024,
    }
}

fn preview(f: &Fixture, interval: Range<u64>) -> Test<RtspQueryImportPlan> {
    Ok(preview_rtsp_query_import(
        &HostSpoolIo,
        &f.directory.0.join("destination"),
        &f.directory.0.join("archive"),
        &request(f, interval)?,
        &RecordingContextLimits::default(),
        &settings(f),
        &|| false,
    )?)
}

impl RtspQueryImportAuthority for Owner {
    fn permit_open(&self, _: &RtspQueryImportPlan) -> bool {
        self.0.get()
    }

    fn permit(&self, plan: &RtspQueryImportPlan, destination: &ReferenceDeployment) -> bool {
        self.0.get()
            && destination.site_lineage() == SITE
            && destination.root() == plan.deployment_root()
    }
}

fn acquire(
    f: &mut Fixture,
    plan: &RtspQueryImportPlan,
) -> Result<RtspQueryImportReceipt, RtspQueryImportFailure> {
    import_rtsp_query(
        &HostSpoolIo,
        f.source.as_ref().expect("fixture archive"),
        f.target.as_mut().expect("fixture destination"),
        plan,
        &Owner(Cell::new(true)),
        &f.cx,
        &mut work(),
        &|| false,
    )
}

fn cold_reopen(f: &mut Fixture) -> Test {
    drop(f.source.take());
    fs::rename(
        f.directory.0.join("archive"),
        f.directory.0.join("offline-archive"),
    )?;
    drop(f.target.take());
    f.cx = context(&f.directory.0.join("destination"))?;
    f.target = Some(ReferenceDeployment::open(
        &f.directory.0.join("destination"),
        SITE,
        &f.cx,
    )?);
    Ok(())
}

fn decode_selected(f: &Fixture, identity: ContentDigest) -> Test {
    let mut indices = Vec::new();
    match f.request.codec {
        RtspImportCodec::Avc => {
            let mut decoder = RecordedH264Range::open(
                f.target()?,
                RecordedH264Request {
                    import_identity: identity,
                    first_segment: 0,
                    segment_count: 4,
                    interpretation: ComponentInterpretation::YCbCr,
                    read_limits: RetainedReadLimits::default(),
                    decoder_limits: AvcLimits::default(),
                },
                &f.cx,
            )?;
            while let Some(frame) = decoder.next_frame(f.target()?, &f.cx)? {
                assert!(!frame.pixels().is_empty());
                indices.push(frame.segment_index());
            }
        }
        RtspImportCodec::Hevc => {
            let mut decoder = RecordedH265Range::open(
                f.target()?,
                RecordedH265Request {
                    import_identity: identity,
                    first_segment: 0,
                    segment_count: 4,
                    interpretation: ComponentInterpretation::YCbCr,
                    read_limits: RetainedReadLimits::default(),
                    decoder_limits: HevcLimits::default(),
                },
                &f.cx,
            )?;
            while let Some(frame) = decoder.next_frame(f.target()?, &f.cx)? {
                assert!(!frame.pixels().is_empty());
                indices.push(frame.segment_index());
            }
        }
    }
    indices.sort_unstable();
    assert_eq!(indices, vec![0, 1, 2, 3]);
    Ok(())
}

#[test]
fn exact_selected_window_retains_closed_native_origin_and_cold_decodes_both_codecs() -> Test {
    for (mut f, interval) in [
        (Fixture::avc("query-avc", 4, 0, false)?, 14_400..14_401),
        (Fixture::hevc("query-hevc")?, 72_000..72_001),
    ] {
        let before = integrity::snapshot(&f.directory.0)?;
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let plan = preview_rtsp_query_import(
            &io,
            &f.directory.0.join("destination"),
            &f.directory.0.join("archive"),
            &request(&f, interval.clone())?,
            &RecordingContextLimits::default(),
            &settings(&f),
            &|| false,
        )?;
        assert!(io.is_read_only());
        assert_eq!(integrity::snapshot(&f.directory.0)?, before);
        assert_eq!(plan.windows().len(), 1);
        assert_eq!(plan.windows()[0].row.ordinal, 1);
        assert_eq!(plan.windows()[0].row.overlap, interval);
        assert!(plan.windows()[0].request.capture_origin.is_none());
        assert_eq!(plan.frames(), 4);
        assert_eq!(
            plan.original_bytes(),
            plan.windows()[0].row.entry.byte_len() as u64
        );

        let selected_root = plan.windows()[0].request.root;
        let original_manifest = ObjectManifest::from_canonical_bytes(
            f.originals
                .get(&selected_root)
                .ok_or("selected original root")?,
        )?;
        let result = acquire(&mut f, &plan)?;
        assert_eq!(result.imports.len(), 1);
        assert_eq!(result.plan_digest, plan.digest());
        assert_eq!(result.frames, 4);
        assert_eq!(result.original_bytes, plan.original_bytes());
        assert_eq!(result.imports[0].ordinal, 1);
        assert_eq!(result.imports[0].source_root, selected_root);
        assert_eq!(result.imports[0].import.capture_time_label, "unknown");
        assert!(result.work_used >= fss_reference::ingest::rtsp_import::MAX_ORIGINAL_BYTES);
        let spool = f.target()?.publisher().spool();
        for digest in
            std::iter::once(selected_root).chain(original_manifest.children().iter().copied())
        {
            assert_eq!(
                spool.read(digest)?,
                *f.originals.get(&digest).ok_or("original child")?
            );
        }
        assert!(!spool.digests().any(|digest| digest == f.original_packs[0]));
        assert!(!spool.digests().any(|digest| digest == f.request.root));

        let identity = result.imports[0].import.import_identity;
        cold_reopen(&mut f)?;
        let retained =
            RetainedFileImport::open(f.target()?, identity, RetainedReadLimits::default(), &f.cx)?;
        assert_eq!(
            retained.manifest().adapter_id,
            fss_reference::ingest::rtsp_import::ADAPTER
        );
        assert_eq!(retained.manifest().capture_time_label, "unknown");
        let mut expected = f.mp4[..f.initialization_bytes].to_vec();
        expected.extend_from_slice(
            f.originals
                .get(&f.original_fragments[1])
                .ok_or("fragment")?,
        );
        assert_eq!(
            retained.manifest().input_sha256,
            ContentDigest::sha256(&expected)
        );
        assert_eq!(result.media_bytes, expected.len() as u64);
        let before_decode = integrity::snapshot(&f.directory.0.join("destination"))?;
        decode_selected(&f, identity)?;
        assert_eq!(
            integrity::snapshot(&f.directory.0.join("destination"))?,
            before_decode
        );
    }
    Ok(())
}

#[test]
fn partial_success_requires_fresh_approval_and_reuses_unchanged_native_children() -> Test {
    let mut f = Fixture::avc("query-partial", 4, 0, false)?;
    let plan = preview(&f, 0..28_800)?;
    f.cx.set_cancel_at_checkpoint_occurrence(STAGE_QUERY_WINDOW, 2);
    let refusal = acquire(&mut f, &plan).expect_err("second window cancellation");
    assert_eq!(refusal.completed.len(), 1);
    assert_eq!(refusal.next_window, 1);
    assert!(!refusal.current_import_may_be_durable);
    let identity = refusal.completed[0].import.import_identity;
    f.cx = context(&f.directory.0.join("destination"))?;
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    let stale = acquire(&mut f, &plan).expect_err("old context approval");
    assert!(matches!(stale.reason, RtspQueryImportError::StalePlan));
    assert!(stale.completed.is_empty());
    assert!(!stale.current_import_may_be_durable);
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("destination"))?,
        before
    );

    let fresh = preview(&f, 0..28_800)?;
    assert_ne!(fresh.digest(), plan.digest());
    for (old, new) in plan.windows().iter().zip(fresh.windows()) {
        assert_eq!(old.request.digest()?, new.request.digest()?);
    }
    let result = acquire(&mut f, &fresh)?;
    assert_eq!(result.imports.len(), 2);
    assert!(result.imports[0].import.reused);
    assert_eq!(result.imports[0].import.import_identity, identity);
    assert!(!result.imports[1].import.reused);
    assert_eq!(result.frames, 8);
    Ok(())
}

#[test]
fn indexed_gap_is_an_explicit_empty_success_without_native_writes() -> Test {
    let mut f = Fixture::avc("query-gap", 4, 3_600, false)?;
    let plan = preview(&f, 14_400..18_000)?;
    assert!(plan.windows().is_empty());
    assert_eq!(plan.query().native.indexed_gaps, vec![14_400..18_000]);
    assert_eq!(plan.original_bytes(), 0);
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    let result = acquire(&mut f, &plan)?;
    assert!(result.imports.is_empty());
    assert_eq!(
        (
            result.frames,
            result.original_bytes,
            result.media_bytes,
            result.work_used
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("destination"))?,
        before
    );
    Ok(())
}
