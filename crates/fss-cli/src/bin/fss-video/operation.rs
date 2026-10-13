#![forbid(unsafe_code)]
//! Composition only: existing native ranges and publication owners keep codec and custody truth.

use std::fs;
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(target_os = "linux")]
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fss_cli::agent_json::{object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits as AvcLimits, RecordedH264Frame, RecordedH264Range, RecordedH264Request,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as HevcLimits, RecordedH265Frame, RecordedH265Range, RecordedH265Request,
};
use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use fss_reference::ingest::recorded_decode::{ComponentInterpretation, RecordedDecodeError};
use fss_reference::ingest::video_publication::{
    NativeVideoFrame, PublishedVideoCodec, PublishedVideoFrame, VideoPublicationLimits,
};
use fss_reference::ingest::RetainedFileImport;
use fss_reference::{ReferenceDeployment, ReplayCx};

use crate::plan::{Codec, Command, Plan, REPORT_LIMIT, SCHEMA};
use crate::{Result, fail, write_bounded};

struct Gate<'a> { cx: &'a ReplayCx, start: Instant, timeout: Duration }
impl Gate<'_> {
    fn check(&self) -> Result<()> {
        if self.start.elapsed() >= self.timeout { return Err(fail("video operation deadline elapsed")); }
        self.cx.checkpoint("video_cli:progress").map_err(|_| fail("video operation cancelled"))?;
        Ok(())
    }
}
struct Reports<'a, W> { out: &'a mut W, sequence: usize, bytes: usize }
impl<W: Write> Reports<'_, W> {
    fn row(&mut self, kind: &str, detail: String) -> Result<()> {
        let row = object(&[("schema", string(SCHEMA)), ("sequence", self.sequence.to_string()),
                          ("kind", string(kind)), ("detail", detail)]) + "\n";
        if row.len() > REPORT_LIMIT.saturating_sub(self.bytes) { return Err(fail("video report allowance exceeded")); }
        write_bounded(self.out, row.as_bytes())?;
        self.bytes += row.len(); self.sequence += 1;
        Ok(())
    }
}

fn existing_root(path: &Path) -> Result<PathBuf> {
    if !fs::symlink_metadata(path)?.is_dir() { return Err(fail("existing real deployment directory required")); }
    let root = fs::canonicalize(path)?;
    for name in ["ledger", "effects", "objects", "objects/roots", "objects/tombstones",
                 "objects/spool", "objects/spool/objects", "objects/spool/staging", "objects/spool/verified"] {
        if !fs::symlink_metadata(root.join(name))?.is_dir() { return Err(fail("incomplete deployment layout")); }
    }
    for name in ["LAYOUT", "ledger/journal.fssj", "effects/journal.fssj", "objects/LOCK", "objects/spool/LOCK"] {
        if !fs::symlink_metadata(root.join(name))?.is_file() { return Err(fail("incomplete deployment layout")); }
    }
    Ok(root)
}

// Holding a directory descriptor prevents a renamed export parent from redirecting writes into
// another tree. The final file is create-new, never followed or overwritten. No unsafe/syscall ABI.
#[cfg(target_os = "linux")]
struct Export { parent: File, path: PathBuf, identity: (u64, u64), name: std::ffi::OsString }
#[cfg(target_os = "linux")]
impl Export {
    fn prepare(path: &Path, root: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let parent_path = fs::canonicalize(path.parent().ok_or_else(|| fail("export parent required"))?)?;
        let name = path.file_name().ok_or_else(|| fail("export name required"))?.to_owned();
        let full = parent_path.join(&name);
        if parent_path.starts_with(root) || root.starts_with(&full) { return Err(fail("export overlaps deployment")); }
        match fs::symlink_metadata(&full) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(fail("export destination must be absent")),
        }
        let parent = File::open(&parent_path)?;
        let metadata = parent.metadata()?;
        if !metadata.is_dir() { return Err(fail("real export parent required")); }
        let export = Self { parent, path: parent_path, identity: (metadata.dev(), metadata.ino()), name };
        export.check()?;
        Ok(export)
    }
    fn check(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.is_dir() || (metadata.dev(), metadata.ino()) != self.identity {
            return Err(fail("export parent changed"));
        }
        Ok(())
    }
    fn write(&self, bytes: &[u8], gate: &Gate<'_>) -> Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        gate.check()?; self.check()?;
        let destination = PathBuf::from(format!("/proc/self/fd/{}", self.parent.as_raw_fd())).join(&self.name);
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(destination)?;
        for chunk in bytes.chunks(4096) { gate.check()?; self.check()?; write_bounded(&mut file, chunk)?; }
        gate.check()?; self.check()?;
        file.sync_all()?; self.parent.sync_all()?;
        Ok(())
    }
}
#[cfg(not(target_os = "linux"))]
struct Export;
#[cfg(not(target_os = "linux"))]
impl Export {
    fn prepare(_: &Path, _: &Path) -> Result<Self> { Err(fail("pixel export requires Linux pinned-directory support")) }
    fn write(&self, _: &[u8], _: &Gate<'_>) -> Result<()> { Err(fail("pixel export unsupported")) }
}

enum Range { Avc(Box<RecordedH264Range>), Hevc(Box<RecordedH265Range>) }
enum Frame { Avc(RecordedH264Frame), Hevc(RecordedH265Frame) }
impl Range {
    fn open(plan: &Plan, first: usize, count: usize, deployment: &ReferenceDeployment,
            budget: &mut RecordedVideoDecodeBudget, cx: &ReplayCx) -> Result<Self> {
        if count == 0 || count > plan.segments { return Err(fail("requested replay range exceeds segment allowance")); }
        let range = match plan.codec {
            Codec::Avc => Self::Avc(Box::new(RecordedH264Range::open_with_budget(deployment, RecordedH264Request {
                import_identity: plan.identity, first_segment: first, segment_count: count,
                interpretation: ComponentInterpretation::YCbCr, read_limits: plan.source,
                decoder_limits: AvcLimits {
                    max_width: plan.dimension, max_height: plan.dimension,
                    max_macroblocks: u32::try_from(plan.pixels / 256)?, max_pictures: count as u64,
                    max_nal_bytes: (plan.source.max_segment_bytes as usize).min(16 * 1024 * 1024),
                    max_slices_per_picture: plan.slices, ..AvcLimits::default()
                },
            }, budget, cx)?)),
            Codec::Hevc => Self::Hevc(Box::new(RecordedH265Range::open_with_budget(deployment, RecordedH265Request {
                import_identity: plan.identity, first_segment: first, segment_count: count,
                interpretation: ComponentInterpretation::YCbCr, read_limits: plan.source,
                decoder_limits: HevcLimits {
                    max_width: plan.dimension, max_height: plan.dimension,
                    max_luma_samples: plan.pixels as u64, max_pictures: count as u64,
                    max_nal_bytes: (plan.source.max_segment_bytes as usize).min(16 * 1024 * 1024),
                    max_slices_per_picture: plan.slices, ..HevcLimits::default()
                },
            }, budget, cx)?)),
        };
        let policy = match &range {
            Self::Avc(range) => range.mask().policy_digest(), Self::Hevc(range) => range.mask().policy_digest(),
        };
        if policy != plan.privacy { return Err(fail("current privacy policy differs from approved policy")); }
        Ok(range)
    }
    fn next(&mut self, deployment: &ReferenceDeployment, budget: &mut RecordedVideoDecodeBudget,
            cx: &ReplayCx) -> Result<Option<Frame>> {
        Ok(match self {
            Self::Avc(range) => range.next_frame_with_budget(deployment, budget, cx)?.map(Frame::Avc),
            Self::Hevc(range) => range.next_frame_with_budget(deployment, budget, cx)?.map(Frame::Hevc),
        })
    }
    fn skipped(&self) -> &[usize] {
        match self { Self::Avc(_) => &[], Self::Hevc(range) => range.skipped_rasl_segments() }
    }
}
impl Frame {
    fn native(&self) -> NativeVideoFrame<'_> {
        match self { Self::Avc(f) => NativeVideoFrame::H264(f), Self::Hevc(f) => NativeVideoFrame::H265(f) }
    }
    fn output(&self) -> u64 {
        match self { Self::Avc(f) => f.output_index(), Self::Hevc(f) => f.output_index() }
    }
    fn planes(&self) -> [&[u8]; 3] {
        match self { Self::Avc(f) => [f.pixels(), f.cb(), f.cr()], Self::Hevc(f) => [f.pixels(), f.cb(), f.cr()] }
    }
    fn receipt(&self) -> Vec<u8> {
        match self { Self::Avc(f) => f.receipt().encoded(), Self::Hevc(f) => f.receipt().encoded() }
    }
    fn quote(&self) -> Result<usize> {
        self.planes().iter().try_fold(self.receipt().len() + 4096, |n, p|
            n.checked_add(p.len()).ok_or_else(|| fail("derived byte quote overflow")))
    }
    fn equals(&self, saved: &PublishedVideoFrame) -> bool {
        let planes = self.planes();
        let (segment, count) = match self {
            Self::Avc(f) => (f.segment_index(), f.range_segment_count()),
            Self::Hevc(f) => (f.segment_index(), f.range_segment_count()),
        };
        self.output() == saved.output_index() && segment == saved.segment_index()
            && count == saved.range_segment_count() && self.receipt() == saved.codec_receipt()
            && planes == [saved.pixels(), saved.cb(), saved.cr()]
    }
}

fn publication_limits(plan: &Plan) -> VideoPublicationLimits {
    VideoPublicationLimits { source: plan.source, maximum_pixels: plan.pixels }
}
fn scope(plan: &Plan, frame: &PublishedVideoFrame) -> Result<()> {
    let codec = match frame.codec() { PublishedVideoCodec::H264 => Codec::Avc, PublishedVideoCodec::H265 => Codec::Hevc };
    if frame.import_identity() != plan.identity || codec != plan.codec || frame.mask_policy() != plan.privacy {
        return Err(fail("frame import, codec or current privacy differs from approved scope"));
    }
    if frame.dimensions().iter().any(|n| *n > plan.dimension) { return Err(fail("frame dimension limit exceeded")); }
    Ok(())
}
fn frame_json(frame: &PublishedVideoFrame) -> String {
    let capsule = frame.capsule();
    object(&[
        ("frame_root", string(&frame.publication_root().to_text())),
        ("codec", string(match frame.codec() { PublishedVideoCodec::H264 => "avc", PublishedVideoCodec::H265 => "hevc" })),
        ("import_identity", string(&frame.import_identity().to_text())),
        ("segment", frame.segment_index().to_string()), ("range_start", frame.range_start().to_string()),
        ("range_segment_count", frame.range_segment_count().to_string()), ("output_index", frame.output_index().to_string()),
        ("width", frame.dimensions()[0].to_string()), ("height", frame.dimensions()[1].to_string()),
        ("receipt_digest", string(&ContentDigest::sha256(frame.codec_receipt()).to_text())),
        ("i420_digest", string(&ContentDigest::sha256(frame.i420()).to_text())),
        ("luma_digest", string(&ContentDigest::sha256(frame.pixels()).to_text())),
        ("capsule", string(capsule.capsule_id.as_str())), ("sensor", string(capsule.sensor_id.as_str())),
        ("capture_earliest_ns", string(&capsule.capture.earliest.0.to_string())),
        ("capture_latest_ns", string(&capsule.capture.latest.0.to_string())),
        ("privacy_policy", frame.mask_policy().map_or_else(|| "null".into(), |d| string(&d.to_text()))),
        ("completion_sequence", frame.authority_anchor().commit_sequence.to_string()),
        ("custody_verified", "true".into()), ("absence_certifiable", "false".into()),
    ])
}

pub(crate) fn run(plan: &Plan, out: &mut impl Write) -> Result<()> {
    let approval = plan.digest()?;
    if plan.approval != Some(approval) { return Err(fail("exact video operation approval required")); }
    // Approval and existing layout precede context construction, which must not create a store.
    let start = Instant::now();
    let root = existing_root(&plan.root)?;
    let export = plan.output.as_ref().map(|p| Export::prepare(p, &root)).transpose()?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:video-cli".into(), operation_id: OperationId::parse("operation:video-cli")?,
        principal: plan.principal.clone(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(plan.source.max_source_bytes)
            .storage_operations(65_536).build()?,
        privacy_scope: "privacy:exact-owner-video-policy".into(),
        retention_scope: "retention:explicit-native-derived-frames".into(),
        anchor_universe: ContentDigest::sha256(plan.site.as_bytes()), generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root)?;
    let gate = Gate { cx: &cx, start, timeout: Duration::from_millis(plan.timeout_ms) };
    let result = (|| -> Result<()> {
        gate.check()?;
        let mut deployment = ReferenceDeployment::open(&plan.root, &plan.site, &cx)?;
        gate.check()?;
        let mut reports = Reports { out, sequence: 0, bytes: 0 };
        reports.row("started", object(&[("approval", string(&approval.to_text())),
            ("command", string(plan.command.text())), ("network_requested", "false".into())]))?;
        let mut budget = RecordedVideoDecodeBudget::new(plan.work);
        let mut derived = 0_usize;
        let mut decoded = 0_usize;
        let skipped;
        match plan.command {
            Command::Publish => {
                let retained = RetainedFileImport::open(&deployment, plan.identity, plan.source, &cx)?;
                let admitted = match plan.codec {
                    Codec::Avc => matches!(retained.manifest().format.as_str(), "annexb" | "mp4avc" | "mkvavc"),
                    Codec::Hevc => matches!(retained.manifest().format.as_str(), "hevc" | "mp4hevc" | "mkvhevc"),
                };
                if !admitted { return Err(fail("retained media does not match approved codec")); }
                let mut range = Range::open(plan, plan.first, plan.count, &deployment, &mut budget, &cx)?;
                loop {
                    gate.check()?;
                    let Some(frame) = range.next(&deployment, &mut budget, &cx)? else { break; };
                    gate.check()?;
                    let next = derived.checked_add(frame.quote()?).filter(|n| *n <= plan.derived)
                        .ok_or_else(|| fail("cumulative derived byte allowance exceeded"))?;
                    if REPORT_LIMIT.saturating_sub(reports.bytes) < 4096 { return Err(fail("frame report reserve exhausted")); }
                    let published = PublishedVideoFrame::publish(&mut deployment, frame.native(), publication_limits(plan), &cx)?;
                    derived = next; decoded += 1;
                    scope(plan, &published)?;
                    reports.row("frame", frame_json(&published))?;
                }
                skipped = range.skipped().to_vec();
            }
            Command::Read | Command::Verify => {
                let saved = PublishedVideoFrame::open(&deployment, plan.frame.ok_or_else(|| fail("frame root required"))?,
                                                      publication_limits(plan), &cx)?;
                scope(plan, &saved)?;
                if plan.command == Command::Verify {
                    let mut range = Range::open(plan, usize::try_from(saved.range_start())?, saved.range_segment_count(),
                                                &deployment, &mut budget, &cx)?;
                    let mut matched = false;
                    loop {
                        gate.check()?;
                        let Some(frame) = range.next(&deployment, &mut budget, &cx)? else { break; };
                        decoded += 1;
                        if frame.output() == saved.output_index() {
                            if matched || !frame.equals(&saved) { return Err(RecordedDecodeError::InvalidReceipt.into()); }
                            matched = true;
                        }
                        // Never stop after finding the frame: later corruption/refusal belongs
                        // to the original requested range and must prevent a replay certificate.
                    }
                    if !matched { return Err(RecordedDecodeError::InvalidReceipt.into()); }
                    skipped = range.skipped().to_vec();
                } else { skipped = Vec::new(); }
                gate.check()?;
                if let Some(export) = &export {
                    let bytes = match plan.pixel_format.as_deref() {
                        Some("pgm") => {
                            let [w, h] = saved.dimensions();
                            let mut bytes = format!("P5\n{w} {h}\n255\n").into_bytes();
                            bytes.try_reserve_exact(saved.pixels().len())?;
                            bytes.extend_from_slice(saved.pixels()); bytes
                        }
                        Some("i420") => saved.i420().to_vec(),
                        Some("rgb") => saved.to_rgb()?, _ => return Err(fail("pixel format required")),
                    };
                    export.write(&bytes, &gate)?;
                    reports.row("export", object(&[("bytes", bytes.len().to_string()),
                        ("digest", string(&ContentDigest::sha256(&bytes).to_text())),
                        ("pixel_format", string(plan.pixel_format.as_deref().ok_or_else(|| fail("pixel format"))?))]))?;
                }
                reports.row("frame", frame_json(&saved))?;
            }
        }
        gate.check()?;
        reports.row("terminal", object(&[
            ("command", string(plan.command.text())), ("complete", "true".into()),
            ("frames_decoded", decoded.to_string()), ("decode_work_units", budget.used().to_string()),
            ("charged_derived_bytes", derived.to_string()),
            ("skipped_rasl_segments", format!("[{}]", skipped.iter().map(usize::to_string).collect::<Vec<_>>().join(","))),
            ("replay_verified", (plan.command == Command::Verify).to_string()),
            ("new_frame_publication_requested", (plan.command == Command::Publish).to_string()),
            ("network_requested", "false".into()), ("absence_certifiable", "false".into()),
        ]))?;
        Ok(())
    })();
    cx.drain_and_finalize();
    result
}
