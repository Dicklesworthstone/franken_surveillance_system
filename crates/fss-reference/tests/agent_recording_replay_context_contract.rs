#![forbid(unsafe_code)]
//! Source-verified recorder UTC requires current exact source authority and protected context.

mod hevc_recording_support;
#[path = "rtsp_replay_time_pinned_contract/io.rs"]
mod read_io;
mod recording_support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::client::replay::{ReplayAcceptance, ReplayWindow};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::ReplayRequest;
use recording_support::{Error, fixture, scope};

type TestResult = Result<(), Error>;
static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

fn path(name: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("agent_recording_replay_context_contract")
        .join(format!(
            "{}-{}-{name}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16,
        512,
        16,
        128,
        SpoolLimits::new(128, 32 * 1024 * 1024, 8 * 1024 * 1024, 256),
    )
}

fn request() -> Result<ReplayRequest, Error> {
    Ok(ReplayRequest::new(
        scope()?,
        ContentDigest::sha256(b"approved credential-free route"),
        ReplayWindow::from_timestamps("20261105T010000Z", "20261105T010500Z")?,
        ContentDigest::sha256(b"original decode clock"),
    )?)
}

fn catalog_scope(request: &ReplayRequest) -> CatalogScope {
    CatalogScope {
        recording: request.scope().clone(),
        decode_clock: request.decode_clock(),
        time_scale: 90_000,
    }
}

fn accepted(request: &ReplayRequest) -> Result<ReplayAcceptance, Error> {
    Ok(ReplayAcceptance::new(
        7,
        request.window(),
        ReplayWindow::from_timestamps("20261105T010100Z", "20261105T010400Z")?,
    )?)
}

fn publish_window(
    publisher: &mut LocalRootPublisher,
    slot: &SlotName,
    recording: &PreparedRecording,
) -> TestResult {
    let mut job = RecordingPublication::new(
        recording,
        publisher,
        slot.clone(),
        recording.byte_len(),
        100,
    )?;
    for now in 0..4 {
        assert!(matches!(
            job.step(now, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    assert!(matches!(
        job.step(4, &NeverCancel)?,
        RecordingProgress::Published(_)
    ));
    Ok(())
}

#[path = "agent_recording_replay_context_contract/native.rs"]
mod native;
