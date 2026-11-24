#![forbid(unsafe_code)]
//! Explicit finite MPEG-TS import through the existing retained file owner.
//!
//! The parser and native splitter have independent finite limits. One cancellable byte-work
//! budget covers import and a reserved retained-verification pass; it is not an OS-I/O or
//! allocator meter. No report or manifest export precedes reopened source verification.

use std::io::{self, Write};
use std::path::Path;

use fss_container::demux::VideoCodec;
use fss_container::mpeg_ts::{TsFraming, TsLimits, TsSelection};
use fss_geometry::WorkBudget;
use fss_reference::ingest::mpeg_ts_import::{
    ADAPTER, MAX_BYTES, MpegTsImportReceipt, MpegTsImportRequest, import_mpeg_ts_file,
};
use fss_reference::ingest::retained::MAX_RETAINED_MANIFEST_BYTES;
use fss_reference::ingest::{FileIngestRequest, RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{ParseResult, RunResult, Values, malformed, number, source_read, text, write_new};

pub(super) const MAX_SOURCE_BYTES: u64 = MAX_BYTES;
const DEFAULT_WORK_UNITS: u64 = 1024 * 1024 * 1024;
const MAX_WORK_UNITS: u64 = 4 * 1024 * 1024 * 1024;
// Reopened manifest/revalidation plus the bounded transport-origin proof.
const VERIFICATION_METADATA_UNITS: u64 = 2 * MAX_RETAINED_MANIFEST_BYTES as u64 + 4 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct Action {
    request: MpegTsImportRequest,
    work_units: u64,
}

pub(super) fn accepts_option(command: &str, key: &str) -> bool {
    command == "import-ts"
        && matches!(
            key,
            "--input"
                | "--sensor"
                | "--stream"
                | "--receive-time-ns"
                | "--capture-start-ns"
                | "--capture-uncertainty-ns"
                | "--assumed-fps"
                | "--ts-program"
                | "--ts-framing"
                | "--ts-video-pid"
                | "--max-ts-packets"
                | "--max-ts-psi-sections"
                | "--max-ts-pes"
                | "--max-ts-pes-bytes"
                | "--max-ts-spans"
                | "--max-elementary-bytes"
                | "--work-units"
        )
}

fn decimal<T: std::str::FromStr>(values: &Values, key: &str, default: Option<T>) -> ParseResult<T> {
    if values.contains_key(key) && !text(values, key)?.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed(&format!(
            "{key} requires an unsigned decimal integer"
        )));
    }
    number(values, key, default)
}

pub(super) fn parse(file: FileIngestRequest, values: &Values) -> ParseResult<Action> {
    if !(1..=MAX_SOURCE_BYTES).contains(&file.limits.max_file_bytes) {
        return Err(malformed(
            "--max-source-bytes must be in 1..=67108864 for import-ts",
        ));
    }
    if file.format_hint.is_some() || file.rtp_binding.is_some() {
        return Err(malformed(
            "import-ts does not accept media-format or RTP binding options",
        ));
    }
    let mut request = MpegTsImportRequest::new(file);
    request.framing = if values.contains_key("--ts-framing") {
        match text(values, "--ts-framing")? {
            "ts188" => TsFraming::Ts188,
            "m2ts192" => TsFraming::M2ts192,
            "dvb204" => TsFraming::Dvb204,
            _ => return Err(malformed("--ts-framing must be ts188, m2ts192 or dvb204")),
        }
    } else {
        TsFraming::Ts188
    };
    request.selection = TsSelection {
        program: values
            .contains_key("--ts-program")
            .then(|| decimal::<u16>(values, "--ts-program", None))
            .transpose()?,
        video_pid: values
            .contains_key("--ts-video-pid")
            .then(|| decimal::<u16>(values, "--ts-video-pid", None))
            .transpose()?,
    };
    if request.selection.program == Some(0)
        || request
            .selection
            .video_pid
            .is_some_and(|pid| !(16..8191).contains(&pid))
    {
        return Err(malformed(
            "TS program must be 1..65535 and video PID 16..8190",
        ));
    }
    let defaults = request.transport_limits;
    request.transport_limits = TsLimits {
        max_input_bytes: defaults.max_input_bytes,
        max_packets: decimal(values, "--max-ts-packets", Some(defaults.max_packets))?,
        max_psi_sections: decimal(
            values,
            "--max-ts-psi-sections",
            Some(defaults.max_psi_sections),
        )?,
        max_pes: decimal(values, "--max-ts-pes", Some(defaults.max_pes))?,
        max_pes_bytes: decimal(values, "--max-ts-pes-bytes", Some(defaults.max_pes_bytes))?,
        max_payload_spans: decimal(values, "--max-ts-spans", Some(defaults.max_payload_spans))?,
        max_elementary_bytes: decimal(
            values,
            "--max-elementary-bytes",
            Some(defaults.max_elementary_bytes),
        )?,
    };
    if request.transport_limits.max_elementary_bytes as u64 > MAX_BYTES {
        return Err(malformed("--max-elementary-bytes cannot exceed 67108864"));
    }
    request.transport_limits.validate().map_err(|_| {
        malformed("TS parser limits must be positive and within the native hard ceilings")
    })?;
    // The reconstructed stream also enters the existing native Annex-B splitter under the
    // explicit elementary byte ceiling; no codec hint is inferred from a NAL prefix.
    request.file.limits.annexb_limits.max_input_bytes =
        request.transport_limits.max_elementary_bytes;
    request
        .digest()
        .map_err(|_| malformed("MPEG-TS file scope or capture assumptions refused"))?;
    let work_units = decimal(values, "--work-units", Some(DEFAULT_WORK_UNITS))?;
    if work_units > MAX_WORK_UNITS {
        return Err(malformed(
            "--work-units cannot exceed 4294967296 for import-ts",
        ));
    }
    Ok(Action {
        request,
        work_units,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    action: &Action,
    deployment: &mut ReferenceDeployment,
    limits: RetainedReadLimits,
    root: &Path,
    manifest_output: Option<&Path>,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let cancelled = || cx.is_cancelled();
    let mut work = WorkBudget::with_cancellation_probe(action.work_units, &cancelled);
    // Zero never selects unlimited work, and refuses before entering source acquisition.
    work.charge(1)?;
    let receipt = import_mpeg_ts_file(deployment, &action.request, cx, &mut work)?;
    report_verified(
        &receipt,
        deployment,
        limits,
        root,
        manifest_output,
        cx,
        &mut work,
        action.work_units,
        out,
    )
}

#[allow(clippy::too_many_arguments)]
fn report_verified(
    receipt: &MpegTsImportReceipt,
    deployment: &ReferenceDeployment,
    limits: RetainedReadLimits,
    root: &Path,
    manifest_output: Option<&Path>,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    work_limit: u64,
    out: &mut impl Write,
) -> RunResult<()> {
    if receipt.original_bytes > MAX_BYTES || receipt.elementary_bytes > MAX_BYTES {
        return Err(io::Error::other("MPEG-TS receipt exceeds the finite byte profile").into());
    }
    let verification = receipt
        .original_bytes
        .checked_add(receipt.elementary_bytes)
        .and_then(|bytes| bytes.checked_add(VERIFICATION_METADATA_UNITS))
        .ok_or_else(|| io::Error::other("MPEG-TS verification reservation overflow"))?;
    work.charge(verification)?;
    let retained = RetainedFileImport::open(deployment, receipt.import_identity, limits, cx)?;
    let manifest = retained.manifest();
    let format = match receipt.codec {
        VideoCodec::Avc => "annexb",
        VideoCodec::Hevc => "hevc",
    };
    if retained.import_root() != receipt.import_root
        || retained.manifest_digest() != receipt.manifest_digest
        || manifest.adapter_id != ADAPTER
        || manifest.format != format
        || manifest.input_bytes != receipt.elementary_bytes
        || manifest.segment_spans.len() != receipt.segments
        || manifest.capture_time_label != receipt.capture_time_label
    {
        return Err(
            io::Error::other("MPEG-TS receipt differs from reopened retained custody").into(),
        );
    }
    // This also reconstructs and verifies every original TS byte through its retained origin.
    // No successful line or exported manifest may precede this cold custody check.
    let verified = retained.verify_source(deployment, limits, cx)?;
    work.charge(0)?;

    let mut report = Vec::new();
    source_read::metadata(
        deployment,
        &retained,
        receipt.import_identity,
        "import-ts",
        &mut report,
    )?;
    writeln!(report, "transport_container=mpegts")?;
    writeln!(
        report,
        "ts_framing={}",
        match receipt.framing {
            TsFraming::Ts188 => "ts188",
            TsFraming::M2ts192 => "m2ts192",
            TsFraming::Dvb204 => "dvb204",
        }
    )?;
    if receipt.framing == TsFraming::M2ts192 {
        writeln!(report, "source_m2ts_prefix_clock=opaque_untrusted")?;
    } else if receipt.framing == TsFraming::Dvb204 {
        writeln!(report, "source_dvb_parity=unverified")?;
    }
    writeln!(report, "transport_origin_proof={}", receipt.proof)?;
    writeln!(report, "original_ts_sha256={}", receipt.original_digest)?;
    writeln!(report, "original_ts_bytes={}", receipt.original_bytes)?;
    writeln!(report, "elementary_bytes={}", receipt.elementary_bytes)?;
    writeln!(report, "verified_elementary_sha256={verified}")?;
    writeln!(
        report,
        "video_codec={}",
        match receipt.codec {
            VideoCodec::Avc => "h264",
            VideoCodec::Hevc => "h265",
        }
    )?;
    writeln!(report, "ts_program={}", receipt.program)?;
    writeln!(report, "ts_video_pid={}", receipt.video_pid)?;
    writeln!(report, "segment_unit=annexb_access_unit")?;
    writeln!(report, "clock_basis=estimated")?;
    writeln!(report, "source_pts_clock=untrusted_33bit_90khz")?;
    writeln!(report, "source_pts_is_utc=false")?;
    writeln!(report, "decoded_frames=0")?;
    writeln!(report, "reused={}", receipt.reused)?;
    writeln!(report, "import_work_units_used={}", work.used())?;
    writeln!(report, "import_work_units_limit={work_limit}")?;
    cx.checkpoint("file_cli:mpegts_verified_output")?;
    if let Some(path) = manifest_output {
        write_new(path, &manifest.canonical_bytes(), root, cx)?;
        writeln!(report, "canonical_manifest_written=true")?;
    }
    work.charge(0)?;
    out.write_all(&report)?;
    Ok(())
}

#[cfg(test)]
#[path = "mpeg_ts/tests.rs"]
mod tests;
