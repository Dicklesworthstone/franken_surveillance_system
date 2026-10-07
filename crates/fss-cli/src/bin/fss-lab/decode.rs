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
//!
//! Each capsule gets its own codec work budget, derived from the effective decode limits
//! ([`DecodeLimits::luma_work_bound`]), so every frame those limits admit (up to 4096x1024 or
//! 2048x2048 at the default ceilings) can decode. A frame that still exhausts its budget is a
//! typed per-frame `not_decoded` row (`ERR-BUDGET-EXHAUSTED-001`, never receipted: the budget
//! describes the caller, not the source); the remaining capsules are still decoded and reported.
//! Each row names the privacy mask policy its receipt binds.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::{DecodeError, decoder_identity};
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
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeError, RecordedDecodeRequest,
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
/// Registered identity of a per-frame codec budget exhaustion (registries/ERRORS.md).
const ERR_BUDGET_EXHAUSTED: &str = "ERR-BUDGET-EXHAUSTED-001";
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
        mask_policy: Option<ContentDigest>,
    },
    Refused {
        kind: &'static str,
        error_id: &'static str,
        receipt_digest: ContentDigest,
        work_units: u64,
        mask_policy: Option<ContentDigest>,
    },
    /// The per-frame codec budget ran out; nothing was decoded or receipted for this capsule.
    BudgetExhausted { work_units: u64 },
}

/// Mask binding of a receipt as report text: the policy digest, or `none` (explicit no-policy).
fn mask_text(policy: Option<ContentDigest>) -> String {
    policy.map_or_else(|| "none".to_owned(), |digest| digest.to_string())
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
        self.frames
            .iter()
            .filter(|f| matches!(f.outcome, RowOutcome::Refused { .. }))
            .count()
    }
    /// Number of capsules whose per-frame codec budget ran out (not decoded, not receipted).
    #[must_use]
    pub fn not_decoded(&self) -> usize {
        self.frames.len() - self.decoded() - self.refused()
    }
    /// Degraded when any capsule was refused or not decoded, any source range became no
    /// capsule, or the retained acquisition degradation names a source loss.
    #[must_use]
    pub fn degraded(&self) -> bool {
        self.refused() != 0
            || self.not_decoded() != 0
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
             \"interpretation\":\"{}\",\"frames\":[",
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
                    mask_policy,
                } => {
                    let _ = write!(
                        out,
                        "\"outcome\":\"decoded\",\"width\":{width},\"height\":{height},\
                         \"tensor_shape\":[{height},{width},1],\"tensor_dtype\":\"u8\",\
                         \"tensor_layout\":\"hwc_luma\",\"tensor_digest\":\"{tensor_digest}\",\
                         \"receipt_domain\":\"fss.recorded_luma_receipt.v2\",\
                         \"receipt_digest\":\"{receipt_digest}\",\"mask_policy\":\"{}\",\
                         \"work_units\":{work_units}}}",
                        mask_text(*mask_policy)
                    );
                }
                RowOutcome::Refused {
                    kind,
                    error_id,
                    receipt_digest,
                    work_units,
                    mask_policy,
                } => {
                    let _ = write!(
                        out,
                        "\"outcome\":\"refused\",\"refusal\":\"{kind}\",\"error_id\":\"{error_id}\",\
                         \"receipt_domain\":\"fss.recorded_decode_refusal.v1\",\
                         \"receipt_digest\":\"{receipt_digest}\",\"mask_policy\":\"{}\",\
                         \"work_units\":{work_units}}}",
                        mask_text(*mask_policy)
                    );
                }
                RowOutcome::BudgetExhausted { work_units } => {
                    let _ = write!(
                        out,
                        "\"outcome\":\"not_decoded\",\"reason\":\"budget_exhausted\",\
                         \"error_id\":\"{ERR_BUDGET_EXHAUSTED}\",\"receipted\":false,\
                         \"work_units\":{work_units}}}"
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
             \"totals\":{{\"capsules\":{},\"decoded\":{},\"refused\":{},\"not_decoded\":{},\
             \"omitted\":{}}},\"degraded\":{},\"derived_not_evidence\":true}}",
            self.frames.len() - listed,
            self.frames.len(),
            self.decoded(),
            self.refused(),
            self.not_decoded(),
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
                RowOutcome::BudgetExhausted { .. } => writeln!(
                    out,
                    "  segment {} not decoded: budget exhausted ({ERR_BUDGET_EXHAUSTED})",
                    row.segment
                ),
            };
        }
        for (offset, len, reason) in &self.omissions {
            let _ = writeln!(out, "  omitted {len} bytes at {offset}: {reason}");
        }
        let _ = write!(
            out,
            "decoded={} refused={} not_decoded={} omitted={} degraded={} \
             (decoded luma is derived, not evidence)",
            self.decoded(),
            self.refused(),
            self.not_decoded(),
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

/// Runs the decode into `root` (which the caller checked is absent or empty), with every
/// capsule's codec budget derived from the decode limits.
pub fn run(
    input: &Path,
    root: &Path,
    interpretation: LabInterpretation,
) -> Result<DecodeReport, String> {
    run_with_frame_budget(
        input,
        root,
        interpretation,
        DecodeLimits::default().luma_work_bound(),
    )
}

/// [`run`] with an explicit per-capsule codec work budget.
fn run_with_frame_budget(
    input: &Path,
    root: &Path,
    interpretation: LabInterpretation,
    frame_budget: u64,
) -> Result<DecodeReport, String> {
    let cx = context(root)?;
    let result = run_in(input, root, interpretation, frame_budget, &cx);
    cx.drain_and_finalize();
    result
}

fn run_in(
    input: &Path,
    root: &Path,
    interpretation: LabInterpretation,
    frame_budget: u64,
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
        let mut budget = DecodeBudget::new(frame_budget);
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
                    mask_policy: receipt.mask_policy(),
                }
            }
            Ok(CapsuleDecode::Refused(retained)) => {
                let refusal = retained.refusal();
                RowOutcome::Refused {
                    kind: refusal.kind().as_str(),
                    error_id: refusal.error_id(),
                    receipt_digest: refusal.digest().map_err(|e| e.to_string())?,
                    work_units: refusal.work_units(),
                    mask_policy: refusal.mask_policy(),
                }
            }
            Err(RecordedDecodeError::Codec(DecodeError::BudgetExhausted)) => {
                RowOutcome::BudgetExhausted {
                    work_units: budget.used(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn report(
        omissions: Vec<(u64, u64, String)>,
        lost_dimensions: Option<Vec<String>>,
    ) -> DecodeReport {
        DecodeReport {
            input_sha256: ContentDigest::sha256(b"input"),
            input_bytes: 10,
            media_format: "mjpeg".to_owned(),
            import_identity: ContentDigest::sha256(b"import"),
            import_root: ContentDigest::sha256(b"root"),
            import_outcome: "new".to_owned(),
            capture_time_class: "unknown".to_owned(),
            interpretation: LabInterpretation::Ycbcr,
            frames: Vec::new(),
            omissions,
            lost_dimensions,
        }
    }

    /// Each degradation source is sufficient on its own: an omitted range without a recorded
    /// acquisition history, and a source-loss dimension without any omitted range.
    #[test]
    fn omissions_and_source_loss_each_degrade_the_report() {
        let continuity_only = Some(vec!["continuity_not_observable".to_owned()]);
        assert!(!report(Vec::new(), continuity_only.clone()).degraded());
        assert!(!report(Vec::new(), None).degraded());
        let omitted = vec![(4, 6, NOT_SEGMENTED.to_owned())];
        assert!(report(omitted.clone(), None).degraded());
        assert!(report(omitted, continuity_only).degraded());
        let truncated = Some(vec![LOST_TRUNCATED_FRAME_OMITTED.to_owned()]);
        assert!(report(Vec::new(), truncated).degraded());
        let json = report(Vec::new(), None).render_json();
        assert!(json.contains("\"acquisition_lost_dimensions\":\"not_recorded\""));
    }

    /// fss-2h5zq.43 D1: a capsule that exhausts its per-frame budget is a typed `not_decoded`
    /// row (never receipted) and the command still reports every capsule instead of aborting.
    #[test]
    fn budget_exhaustion_is_a_typed_row_not_an_abort() -> Result<(), Box<dyn std::error::Error>> {
        let input = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/media/mjpeg/mjpeg_clean_3frames.mjpeg");
        let root =
            std::env::temp_dir().join(format!("fss-lab-decode-budget-row-{}", std::process::id()));
        let report = run_with_frame_budget(&input, &root, LabInterpretation::Ycbcr, 1_000);
        let _ = std::fs::remove_dir_all(&root);
        let report = report?;
        assert_eq!(report.frames.len(), 3);
        assert_eq!(
            (report.decoded(), report.refused(), report.not_decoded()),
            (0, 0, 3)
        );
        assert!(report.degraded());
        let json = report.render_json();
        assert_eq!(
            json.matches(
                "\"outcome\":\"not_decoded\",\"reason\":\"budget_exhausted\",\
                 \"error_id\":\"ERR-BUDGET-EXHAUSTED-001\",\"receipted\":false"
            )
            .count(),
            3
        );
        assert!(!json.contains("\"receipt_digest\""));
        assert!(json.contains(
            "\"totals\":{\"capsules\":3,\"decoded\":0,\"refused\":0,\"not_decoded\":3,\"omitted\":0}"
        ));
        assert!(report.render_text().contains("not_decoded=3"));
        Ok(())
    }

    /// Ranges covered by neither a segment nor an omission span are found, including the tail.
    #[test]
    fn uncovered_spans_include_interior_gaps_and_the_tail() -> Result<(), Box<dyn std::error::Error>>
    {
        use fss_core::CapsuleId;
        use fss_reference::ingest::SegmentSpan;
        let span = |index: usize, offset: u64, len: u64| -> Result<SegmentSpan, String> {
            Ok(SegmentSpan {
                segment_index: index,
                offset,
                len,
                segment_sha256: ContentDigest::sha256(&[index as u8]),
                capsule_id: CapsuleId::parse(format!("capsule:test-{index}"))
                    .map_err(|e| e.to_string())?,
                gap_before: false,
            })
        };
        let mut manifest = FileImportManifest {
            input_sha256: ContentDigest::sha256(b"input"),
            input_bytes: 100,
            format: "mjpeg".to_owned(),
            detector_evidence: String::new(),
            chunk_bytes: 100,
            ordered_chunks: Vec::new(),
            segment_spans: vec![span(0, 0, 10)?, span(1, 20, 10)?],
            omission_spans: Vec::new(),
            capsule_ids: Vec::new(),
            limits_digest: ContentDigest::sha256(b"limits"),
            adapter_id: String::new(),
            adapter_generation: String::new(),
            part_roots: Vec::new(),
            capture_time_label: "unknown".to_owned(),
        };
        assert_eq!(uncovered_spans(&manifest), vec![(10, 10), (30, 70)]);
        manifest.input_bytes = 30;
        assert_eq!(uncovered_spans(&manifest), vec![(10, 10)]);
        Ok(())
    }
}
