#![forbid(unsafe_code)]

use super::*;
use fss_geometry::WorkBudget;
use fss_reference::deletion::{CommitOutcome, commit_deletion, plan_deletion};
use fss_reference::ingest::rtsp_import::{
    RtspImportAuthority, RtspImportCodec, RtspImportRequest, import_rtsp,
};
use fss_reference::rtsp::recording_replay::time::pinned::query_replay_time_read_only;

#[test]
fn deleted_outside_interval_original_is_denied_before_original_metadata_or_payload() -> TestResult {
    let source_fixture = stamped_avc()?;
    let mut f = Fixture::from_native(seal_avc("context-deleted-original", &source_fixture, 1, 7)?)?;
    f.request.replay.start_ns = UTC_NS + 20_000_000_000;
    f.request.replay.end_ns = UTC_NS + 30_000_000_000;
    let limits = RecordingReplayContextLimits::default();
    let source = f.native.open()?;
    let recording = source_fixture.prepare_at(0)?;
    assert_eq!(
        recording.manifest().root(),
        f.native.receipt.windows()[0].root()
    );
    let cx = f.cx()?;
    let mut deployment = ReferenceDeployment::open(&f.deployment, SITE, &cx)?;
    struct Owner(ContentDigest);
    impl RtspImportAuthority for Owner {
        fn permit(&self, request: &RtspImportRequest, destination: &ReferenceDeployment) -> bool {
            request.root == self.0 && destination.site_lineage() == SITE
        }
    }
    let imported = import_rtsp(
        &source,
        &mut deployment,
        &RtspImportRequest {
            codec: RtspImportCodec::Avc,
            slot: f.native.receipt.windows()[0].slot().clone(),
            root: recording.manifest().root(),
            source: recording.summary().scope.clone(),
            receive_time: TimestampNs(10_000_000_000),
            capture_origin: None,
            max_frames: 256,
            max_original_bytes: 32 * 1024 * 1024,
            max_media_bytes: 32 * 1024 * 1024,
        },
        &Owner(recording.manifest().root()),
        &cx,
        &mut WorkBudget::new(512 * 1024 * 1024),
    )?;
    let before = f.query(&ReadOnlyIo::default(), &limits, &|| false)?;
    assert!(before.native.report.matches.is_empty());
    assert_eq!(before.native.report.outside_samples, 1);
    let deletion = plan_deletion(&deployment, imported.import_identity, &cx)?;
    assert!(deletion.blockers.is_empty(), "{:?}", deletion.blockers);
    assert!(deletion.deletable.iter().any(|entry| {
        f.native
            .receipt
            .manifest()
            .children()
            .contains(&entry.digest)
    }));
    let committed = commit_deletion(
        &mut deployment,
        deletion.digest()?,
        deletion.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &cx,
    )?;
    assert_eq!(committed.outcome, CommitOutcome::Completed);

    // The independent archive remains natively valid. Current deployment authority must
    // still deny its deleted original even though it could produce no matching sample.
    let native = query_replay_time_read_only(
        &ReadOnlyIo::default(),
        &f.native.root,
        &f.request.replay,
        limits.replay,
        &|| false,
    )?;
    assert_eq!(native.report.digest, before.native.report.digest);
    let authority = f.authority(&limits)?;
    let now = || TimestampNs(0);
    let permit = ReplaySourceReadPermit::authorize(&authority, &f.request, limits.replay, &now)?;
    let io = ReadOnlyIo::default();
    let result = query_recordings_replay_in_deployment(
        &io,
        &f.deployment,
        &f.native.root,
        &f.request,
        &limits,
        Some(&permit),
        &|| false,
    );
    assert!(matches!(result, Err(E::AnchorChanged)), "{result:?}");
    assert!(
        io.calls.load(Ordering::SeqCst) > 0,
        "the exact receipt was read and admitted first"
    );
    for window in f.native.receipt.windows() {
        for digest in std::iter::once(window.root()).chain(window.original_leaf_digests()) {
            assert_eq!(
                io.opened_count(&source.spool().object_path(digest)),
                0,
                "deleted closure must be denied before original I/O"
            );
        }
    }
    assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
    Ok(())
}
