#![forbid(unsafe_code)]
//! `fss-lab decode`: recorded JPEG/MJPEG file -> file-ingest adapter -> every retained capsule
//! custody-verified and decoded -> `fss.lab.decode_report.v1` (fss-2h5zq.43).
//!
//! The import is the real `FileIngestAdapter` path into an empty deployment root, and every
//! capsule goes through `recorded_decode::refusal::decode_capsule`: custody is verified before
//! any codec work, a decoded frame is published with its `fss.recorded_luma_receipt.v2` receipt,
//! and a codec refusal is published with its `fss.recorded_decode_refusal.v1` receipt. Source
//! bytes that became no capsule are listed as omissions, never as decoded frames: the import's
//! omission spans, plus every input range no segment or omission span covers (a truncated last
//! frame is dropped this way). The import's retained acquisition degradation (its lost
//! dimensions, for example `truncated_frame_omitted`) is reported verbatim. Any refusal,
//! omission or source-loss dimension makes the report degraded. The report carries digests,
//! spans and counters only, never pixels. A file never certifies absence and has no live
//! continuity.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::decoder_identity;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    AcquisitionStateKind, BudgetVector, CanonicalDecode, CanonicalDecoder, ContentDigest,
    DegradationEvidence, DigestAlgorithm, OperationId, SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::file_session::{
    LOST_SEGMENT_GAP, LOST_SOURCE_BYTES_OMITTED, LOST_TRUNCATED_FRAME_OMITTED,
};
use fss_reference::ingest::recorded_decode::refusal::{CapsuleDecode, decode_capsule};
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest,
};
use fss_reference::ingest::{
    AcquisitionRetention, FileFormatHint, FileImportManifest, FileIngestAdapter, FileIngestRequest,
    RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use fss_cli::LabInterpretation;

/// Report schema identity.
pub const DECODE_REPORT_SCHEMA: &str = "fss.lab.decode_report.v1";
/// Deployment site lineage of every lab decode root (fixed, so reports are root-independent).
pub const DECODE_SITE: &str = "site:lab-decode";
/// Sensor and stream identities given to the recorded file.
pub const DECODE_SENSOR: &str = "sensor:lab-decode";
const DECODE_STREAM: &str = "stream:lab-decode";
/// Fixed ingest arrival time: file mtime is never capture time, and capture stays unknown.
const RECEIVE_TIME_NS: i128 = 1_000_000_000;
/// At most this many frame rows are listed; totals always cover every capsule.
pub const MAX_REPORTED_FRAMES: usize = 1_024;
/// Canonical codec work allowance per capsule.
const WORK_UNITS_PER_FRAME: u64 = 100_000_000;
const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;

/// One capsule's outcome row.
#[derive(Debug)]
pub struct FrameRow {
    segment: usize,
    capsule_id: String,
    source_offset: u64,
    source_bytes: u64,
    source_digest: ContentDigest,
    outcome: RowOutcome,
}

#[derive(Debug)]
enum RowOutcome {
    Decoded {
        width: u32,
        height: u32,
        tensor_digest: ContentDigest,
        receipt_digest: ContentDigest,
        work_units: u64,
    },
    Refused {
        kind: &'static str,
        error_id: &'static str,
        receipt_digest: ContentDigest,
        work_units: u64,
    },
}

/// Complete deterministic decode report of one recorded file.
#[derive(Debug)]
pub struct DecodeReport {
    input_sha256: ContentDigest,
    input_bytes: u64,
    media_format: String,
    import_identity: ContentDigest,
    import_root: ContentDigest,
    import_outcome: String,
    capture_time_class: String,
    interpretation: LabInterpretation,
    frames: Vec<FrameRow>,
    omissions: Vec<(u64, u64, String)>,
    /// Lost dimensions of the retained acquisition degradation; `None` when not recorded.
    lost_dimensions: Option<Vec<String>>,
}

/// Lost dimensions that mean source bytes did not become decodable capsules.
const SOURCE_LOSS: [&str; 3] = [
    LOST_SOURCE_BYTES_OMITTED,
    LOST_TRUNCATED_FRAME_OMITTED,
    LOST_SEGMENT_GAP,
];
/// Reason given to an input range that neither a segment nor an omission span covers.
const NOT_SEGMENTED: &str = "not_segmented";

impl DecodeReport {
    /// Number of decoded capsules.
    #[must_use]
    pub fn decoded(&self) -> usize {
        self.frames
            .iter()
            .filter(|f| matches!(f.outcome, RowOutcome::Decoded { .. }))
            .count()
    }
    /// Number of receipted refusals.
    #[must_use]
    pub fn refused(&self) -> usize {
        self.frames.len() - self.decoded()
    }
    /// Degraded when any capsule was refused, any source range became no capsule, or the
    /// retained acquisition degradation names a source loss.
    #[must_use]
    pub fn degraded(&self) -> bool {
        self.refused() != 0
            || !self.omissions.is_empty()
            || self
                .lost_dimensions
                .iter()
                .flatten()
                .any(|lost| SOURCE_LOSS.contains(&lost.as_str()))
    }

    /// `fss.lab.decode_report.v1` JSON; root paths and wall-clock time never appear.
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            "{{\"schema\":\"{DECODE_REPORT_SCHEMA}\",\"input_sha256\":\"{}\",\"input_bytes\":{},\
             \"media_format\":\"{}\",\"import_identity\":\"{}\",\"import_root\":\"{}\",\
             \"import_outcome\":\"{}\",\"capture_time_class\":\"{}\",\"absence_certifiable\":false,\
             \"continuity\":\"not_observable: file_source\",\"decoder_generation\":\"{}\",\
             \"interpretation\":\"{}\",\"mask_policy\":\"none\",\"frames\":[",
            self.input_sha256,
            self.input_bytes,
            escape(&self.media_format),
            self.import_identity,
            self.import_root,
            escape(&self.import_outcome),
            escape(&self.capture_time_class),
            ContentDigest::new(DigestAlgorithm::Sha256, decoder_identity()),
            self.interpretation.as_str(),
        );
        for (index, row) in self.frames.iter().take(MAX_REPORTED_FRAMES).enumerate() {
            if index > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"segment\":{},\"capsule_id\":\"{}\",\"source_offset\":{},\"source_bytes\":{},\
                 \"source_digest\":\"{}\",",
                row.segment,
                escape(&row.capsule_id),
                row.source_offset,
                row.source_bytes,
                row.source_digest,
            );
            match &row.outcome {
                RowOutcome::Decoded {
                    width,
                    height,
                    tensor_digest,
                    receipt_digest,
                    work_units,
                } => {
                    let _ = write!(
                        out,
                        "\"outcome\":\"decoded\",\"width\":{width},\"height\":{height},\
                         \"tensor_shape\":[{height},{width},1],\"tensor_dtype\":\"u8\",\
                         \"tensor_layout\":\"hwc_luma\",\"tensor_digest\":\"{tensor_digest}\",\
                         \"receipt_domain\":\"fss.recorded_luma_receipt.v2\",\
                         \"receipt_digest\":\"{receipt_digest}\",\"work_units\":{work_units}}}"
                    );
                }
                RowOutcome::Refused {
                    kind,
                    error_id,
                    receipt_digest,
                    work_units,
                } => {
                    let _ = write!(
                        out,
                        "\"outcome\":\"refused\",\"refusal\":\"{kind}\",\"error_id\":\"{error_id}\",\
                         \"receipt_domain\":\"fss.recorded_decode_refusal.v1\",\
                         \"receipt_digest\":\"{receipt_digest}\",\"work_units\":{work_units}}}"
                    );
                }
            }
        }
        out.push_str("],\"omissions\":[");
        for (index, (offset, len, reason)) in self.omissions.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"outcome\":\"omitted\",\"source_offset\":{offset},\"source_bytes\":{len},\
                 \"reason\":\"{}\"}}",
                escape(reason)
            );
        }
        out.push_str("],\"acquisition_lost_dimensions\":");
        match &self.lost_dimensions {
            Some(lost) => {
                out.push('[');
                for (index, dimension) in lost.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    let _ = write!(out, "\"{}\"", escape(dimension));
                }
                out.push(']');
            }
            None => out.push_str("\"not_recorded\""),
        }
        let listed = self.frames.len().min(MAX_REPORTED_FRAMES);
        let _ = write!(
            out,
            ",\"frames_listed\":{listed},\"frames_not_listed\":{},\
             \"totals\":{{\"capsules\":{},\"decoded\":{},\"refused\":{},\"omitted\":{}}},\
             \"degraded\":{},\"derived_not_evidence\":true}}",
            self.frames.len() - listed,
            self.frames.len(),
            self.decoded(),
            self.refused(),
            self.omissions.len(),
            self.degraded(),
        );
        out
    }

    /// Short human summary; the JSON report is the machine contract.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = format!(
            "fss-lab decode: {} {} bytes, import {}\n",
            self.media_format, self.input_bytes, self.import_identity
        );
        for row in self.frames.iter().take(MAX_REPORTED_FRAMES) {
            let _ = match &row.outcome {
                RowOutcome::Decoded {
                    width,
                    height,
                    tensor_digest,
                    ..
                } => writeln!(
                    out,
                    "  segment {} decoded {width}x{height} tensor {tensor_digest}",
                    row.segment
                ),
                RowOutcome::Refused { kind, error_id, .. } => {
                    writeln!(out, "  segment {} refused {kind} ({error_id})", row.segment)
                }
            };
        }
        for (offset, len, reason) in &self.omissions {
            let _ = writeln!(out, "  omitted {len} bytes at {offset}: {reason}");
        }
        let _ = write!(
            out,
            "decoded={} refused={} omitted={} degraded={} (decoded luma is derived, not evidence)",
            self.decoded(),
            self.refused(),
            self.omissions.len(),
            self.degraded()
        );
        out
    }
}

/// Every input range covered by neither a segment span nor an omission span, in file order.
fn uncovered_spans(manifest: &FileImportManifest) -> Vec<(u64, u64)> {
    let mut covered: Vec<(u64, u64)> = manifest
        .segment_spans
        .iter()
        .map(|s| (s.offset, s.offset.saturating_add(s.len)))
        .chain(
            manifest
                .omission_spans
                .iter()
                .map(|o| (o.offset, o.offset.saturating_add(o.len))),
        )
        .collect();
    covered.sort_unstable();
    let mut gaps = Vec::new();
    let mut cursor = 0_u64;
    for (start, end) in covered {
        if start > cursor {
            gaps.push((cursor, start - cursor));
        }
        cursor = cursor.max(end);
    }
    if manifest.input_bytes > cursor {
        gaps.push((cursor, manifest.input_bytes - cursor));
    }
    gaps
}

/// Lost dimensions of the import's retained `Degraded` transition witness, verified by digest.
fn retained_lost_dimensions(
    deployment: &ReferenceDeployment,
    import_identity: ContentDigest,
) -> Result<Option<Vec<String>>, String> {
    let retention = AcquisitionRetention::open(deployment, import_identity)
        .map_err(|e| format!("lab decode acquisition history: {e}"))?;
    let Some(history) = retention.history() else {
        return Ok(None);
    };
    let Some(record) = history
        .records()
        .iter()
        .find(|r| r.to == AcquisitionStateKind::Degraded)
    else {
        return Ok(Some(Vec::new()));
    };
    let bytes = deployment
        .publisher()
        .spool()
        .read(record.witness_digest)
        .map_err(|e| format!("lab decode degradation witness: {e}"))?;
    if ContentDigest::sha256(&bytes) != record.witness_digest {
        return Err("lab decode degradation witness digest mismatch".to_owned());
    }
    let refused = |e: &dyn std::fmt::Display| format!("lab decode degradation witness: {e}");
    let mut decoder = CanonicalDecoder::new(&bytes);
    if decoder.text().map_err(|e| refused(&e))? != "fss.canonical.v1"
        || decoder.text().map_err(|e| refused(&e))? != "fss.acquisition.degradation.v1"
    {
        return Err("lab decode degradation witness has an unexpected domain".to_owned());
    }
    let evidence = DegradationEvidence::decode_canonical(&mut decoder).map_err(|e| refused(&e))?;
    decoder.ensure_finished().map_err(|e| refused(&e))?;
    Ok(Some(evidence.lost_dimensions))
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn context(root: &Path) -> Result<ReplayCx, String> {
    let error = |e: &dyn std::fmt::Display| format!("lab decode authority: {e}");
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:lab:decode".to_owned(),
        operation_id: OperationId::parse("op:lab:decode").map_err(|e| error(&e))?,
        principal: "operator:lab".to_owned(),
        capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(MAX_SOURCE_BYTES)
            .storage_operations(1 << 20)
            .build()
            .map_err(|e| error(&e))?,
        privacy_scope: "privacy:local-authorized-files".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(DECODE_SITE.as_bytes()),
        generation: 1,
    })
    .map_err(|e| error(&e))?;
    authority.validate().map_err(|e| error(&e))?;
    ReplayCx::from_context_authority(&authority, root.to_path_buf()).map_err(|e| error(&e))
}

/// Runs the decode into `root` (which the caller checked is absent or empty).
pub fn run(
    input: &Path,
    root: &Path,
    interpretation: LabInterpretation,
) -> Result<DecodeReport, String> {
    let cx = context(root)?;
    let result = run_in(input, root, interpretation, &cx);
    cx.drain_and_finalize();
    result
}

fn run_in(
    input: &Path,
    root: &Path,
    interpretation: LabInterpretation,
    cx: &ReplayCx,
) -> Result<DecodeReport, String> {
    let mut deployment = ReferenceDeployment::open(root, DECODE_SITE, cx)
        .map_err(|e| format!("lab decode deployment: {e}"))?;
    let mut request = FileIngestRequest::new(
        PathBuf::from(input),
        SensorId::parse(DECODE_SENSOR).map_err(|e| e.to_string())?,
        StreamId::parse(DECODE_STREAM).map_err(|e| e.to_string())?,
    )
    .with_receive_time(TimestampNs(RECEIVE_TIME_NS));
    request.format_hint = Some(FileFormatHint::JpegStream);
    let imported = FileIngestAdapter::ingest(request, cx, &mut deployment)
        .map_err(|e| format!("lab decode import: {e}"))?;
    let read_limits = RetainedReadLimits::default();
    let retained = RetainedFileImport::open(&deployment, imported.import_identity, read_limits, cx)
        .map_err(|e| format!("lab decode retained import: {e}"))?;
    let manifest = retained.manifest().clone();
    let codec_interpretation = match interpretation {
        LabInterpretation::Gray => ComponentInterpretation::Grayscale,
        LabInterpretation::Ycbcr => ComponentInterpretation::YCbCr,
    };
    let mut frames = Vec::with_capacity(manifest.segment_spans.len());
    for span in &manifest.segment_spans {
        let request = RecordedDecodeRequest {
            import_identity: imported.import_identity,
            segment_index: span.segment_index,
            interpretation: codec_interpretation,
            read_limits,
            decode_limits: DecodeLimits::default(),
        };
        let mut budget = DecodeBudget::new(WORK_UNITS_PER_FRAME);
        let outcome = match decode_capsule(&mut deployment, &request, &mut budget, cx) {
            Ok(CapsuleDecode::Decoded(frame)) => {
                let receipt = frame.receipt();
                let [width, height] = receipt.dimensions();
                RowOutcome::Decoded {
                    width,
                    height,
                    tensor_digest: ContentDigest::new(
                        DigestAlgorithm::Sha256,
                        receipt.codec().luma_sha256,
                    ),
                    receipt_digest: receipt.digest().map_err(|e| e.to_string())?,
                    work_units: receipt.work_units(),
                }
            }
            Ok(CapsuleDecode::Refused(retained)) => {
                let refusal = retained.refusal();
                RowOutcome::Refused {
                    kind: refusal.kind().as_str(),
                    error_id: refusal.error_id(),
                    receipt_digest: refusal.digest().map_err(|e| e.to_string())?,
                    work_units: refusal.work_units(),
                }
            }
            Err(error) => {
                return Err(format!(
                    "{}: segment {}: {error}",
                    error.stable_id(),
                    span.segment_index
                ));
            }
        };
        frames.push(FrameRow {
            segment: span.segment_index,
            capsule_id: span.capsule_id.as_str().to_owned(),
            source_offset: span.offset,
            source_bytes: span.len,
            source_digest: span.segment_sha256,
            outcome,
        });
    }
    Ok(DecodeReport {
        input_sha256: manifest.input_sha256,
        input_bytes: manifest.input_bytes,
        media_format: manifest.format.clone(),
        import_identity: imported.import_identity,
        import_root: retained.import_root(),
        import_outcome: imported.outcome.as_str().to_owned(),
        capture_time_class: manifest.capture_time_label.clone(),
        interpretation,
        frames,
        omissions: {
            let mut omissions: Vec<(u64, u64, String)> = manifest
                .omission_spans
                .iter()
                .map(|o| (o.offset, o.len, o.reason.clone()))
                .chain(
                    uncovered_spans(&manifest)
                        .into_iter()
                        .map(|(offset, len)| (offset, len, NOT_SEGMENTED.to_owned())),
                )
                .collect();
            omissions.sort();
            omissions
        },
        lost_dimensions: retained_lost_dimensions(&deployment, imported.import_identity)?,
    })
}
