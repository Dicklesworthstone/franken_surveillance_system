#![forbid(unsafe_code)]
//! Native verification of copied exports, without opening their original archive.

use super::*;
use fss_object::ObjectManifest;
use fss_reference::rtsp::recording::hevc::verify_hevc_recording;
use fss_reference::rtsp::recording::{RecordingObjects, verify_recording};

pub(super) mod bundle;

/// Operator result only. No source/catalog/disclosure authority is created by verification.
pub const EXPORT_VERIFICATION_SCHEMA: &str = "fss.local_archive_export_verification.v1";

struct Clock<'a, C>(&'a C);
impl<C: OperationClock> bundle::Clock for Clock<'_, C> {
    fn check(&self) -> bundle::Result<()> {
        let now = self
            .0
            .now_ns()
            .map_err(|_| ExportVerificationError::Deadline)?;
        if now >= self.0.deadline_ns() {
            return Err(ExportVerificationError::Deadline);
        }
        if self
            .0
            .cancel_requested(PublishCutPoint::AfterChildrenVerified)
        {
            let now = self
                .0
                .now_ns()
                .map_err(|_| ExportVerificationError::Deadline)?;
            return Err(if now >= self.0.deadline_ns() {
                ExportVerificationError::Deadline
            } else {
                ExportVerificationError::Cancelled
            });
        }
        Ok(())
    }
}

pub(super) fn execute(options: &ArchiveOptions, clock: &impl OperationClock) -> Result<String> {
    verify(options, clock).map_err(ArchiveCommandError::ExportVerification)
}

fn verify(options: &ArchiveOptions, clock: &impl OperationClock) -> bundle::Result<String> {
    use bundle::Clock as _;
    let clock = Clock(clock);
    clock.check()?;
    let completion = options
        .expected_completion
        .ok_or(ExportVerificationError::CompletionPinMismatch)?;
    // Codec is selected exclusively by validated caller arguments, before reading bundle bytes.
    match options.codec {
        Codec::Avc => verify_for::<AvcArchiveCodec>(options, &clock, completion),
        Codec::Hevc => verify_for::<HevcArchiveCodec>(options, &clock, completion),
    }
}

fn verify_for<C: ArchiveCodec>(
    options: &ArchiveOptions,
    clock: &impl bundle::Clock,
    completion: ContentDigest,
) -> bundle::Result<String> {
    let namespace = CodecArchiveNamespace::<C>::new(options.scope.clone())
        .map_err(|_| ExportVerificationError::ScopeMismatch)?;
    verify_with_namespace(options, clock, completion, namespace.digest())
}

fn verify_with_namespace(
    options: &ArchiveOptions,
    clock: &impl bundle::Clock,
    completion: ContentDigest,
    namespace: ContentDigest,
) -> bundle::Result<String> {
    let scope = bundle::Scope {
        codec: options.codec.name(),
        sensor: options.scope.recording.sensor.as_str().to_owned(),
        stream: options.scope.recording.stream.as_str().to_owned(),
        generation: options.scope.recording.generation,
        anchor: options.scope.recording.anchor,
        receive_clock: options.scope.recording.receive_clock,
        decode_clock: options.scope.decode_clock,
        time_scale: options.scope.time_scale,
        namespace,
    };
    let limits = bundle::Limits {
        windows: options.archive_limits.max_windows,
        files: options.storage_limits.spool.max_objects,
        file_bytes: options.storage_limits.spool.max_total_bytes,
        read_bytes: options.verify_read_budget,
        io_calls: options.verify_io_budget,
        window_bytes: MAX_RECORDING_BYTES,
    };
    let mut bundle = bundle::Bundle::open(&options.root, completion, &scope, limits, clock)?;
    while let Some(bytes) = bundle.next_window()? {
        clock.check()?;
        let manifest = ObjectManifest::from_canonical_bytes(&bytes.manifest)
            .map_err(|_| ExportVerificationError::Integrity)?;
        let objects = RecordingObjects {
            source: &bytes.source,
            initialization: &bytes.initialization,
            media: &bytes.media,
            index: &bytes.index,
        };
        let summary = match options.codec {
            Codec::Avc => verify_recording(&manifest, objects, &options.scope.recording),
            Codec::Hevc => verify_hevc_recording(&manifest, objects, &options.scope.recording)
                .map(|verified| verified.recording),
        }
        .map_err(|_| ExportVerificationError::Integrity)?;
        if summary.root != bytes.window.root
            || summary.scope != options.scope.recording
            || summary.time_scale != options.scope.time_scale
            || summary.decode_interval != bytes.window.returned
        {
            return Err(ExportVerificationError::Integrity);
        }
        clock.check()?;
    }
    let receipt = bundle.finish()?;
    clock.check()?;
    let report = format!(
        "{{\"schema\":\"{EXPORT_VERIFICATION_SCHEMA}\",\"command\":\"verify-export\",\"codec\":\"{}\",\"sensor\":{},\"stream\":{},\"generation\":{},\"anchor\":{},\"receive_clock\":{},\"decode_clock\":{},\"time_scale\":{},\"namespace\":{},\"completion_sha256\":{},\"request_sha256_observed\":{},\"request_binding\":\"semantic_consistency_only_unpinned_by_completion_v1\",\"original_snapshot_claim\":{},\"original_query\":{},\"verified_windows\":{},\"verified_recording_bytes\":{},\"bundle_files\":{},\"bundle_file_bytes\":{},\"charged_read_bytes\":{},\"io_calls\":{},\"pending_completion_copy_present\":{},\"native_source_provenance_verified\":true,\"playback_bytes_verified\":true,\"decoded_pictures_verified\":false,\"original_catalog_reconstructed\":false,\"current_archive_or_disclosure_authorized\":false,\"coverage_claim\":\"not_claimed\",\"filesystem_snapshot_atomic\":false,\"complete\":true}}\n",
        options.codec.name(),
        quoted(&scope.sensor),
        quoted(&scope.stream),
        scope.generation,
        quoted(&scope.anchor.to_text()),
        quoted(&scope.receive_clock.to_text()),
        quoted(&scope.decode_clock.to_text()),
        scope.time_scale,
        quoted(&namespace.to_text()),
        quoted(&receipt.completion.to_text()),
        quoted(&receipt.request_observation.to_text()),
        quoted(&receipt.snapshot_claim.to_text()),
        interval(&receipt.query),
        receipt.windows,
        receipt.recording_bytes,
        receipt.files,
        receipt.file_bytes,
        receipt.charged_read_bytes,
        receipt.io_calls,
        receipt.pending_copy_present,
    );
    if report.len() > MAX_REPORT_BYTES {
        return Err(ExportVerificationError::Limit("report_bytes"));
    }
    clock.check()?;
    Ok(report)
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
