#![forbid(unsafe_code)]
//! Pure parent approval over acquisition, generation bindings and native model execution.

use std::collections::BTreeSet;
use std::ffi::OsString;

use fss_cli::agent_json::{array, object, string};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_reference::http_reconnect_history::ReconnectHistoryPin;
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::rgb_package::MAX_RGB_PACKAGE_BYTES;

use super::analysis_plan;

pub(crate) const MAX_ARGUMENTS: usize = 272;
pub(super) const FORMAT: &str = "fss.http_capture_sentinel.v1";
const POLICY: &str = "one-owned-http-capture:typed-settled-history:explicit-generation-bindings:\
pinned-model-before-camera:whole-history-native-sentinel:root-last-retention:\
cooperative-analysis-deadline:exact-offline-continuation:no-recapture:no-effects:v1";

pub(super) const HELP: &str = "fss-capture-reconnect sentinel [ordinary reconnect capture options]\n\
  --durable-history yes --deployment-root ABSOLUTE_DEPLOYMENT --site SITE\n\
  --binding GENERATION,SENSOR,STREAM,RECEIVE_NS,CAPTURE_START_NS,UNCERTAINTY_NS,FPS\n\
  --interpretation gray|ycbcr --package ABSOLUTE_FMPK --package-digest sha256:HEX\n\
  --read-originals yes --read-model yes --execute-perception yes --retain-analysis yes\n\
  --sentinel-every-frames N --sentinel-burst-frames K --sentinel-max-inferences M\n\
  [--approve sha256:OUTER_PLAN]\n\
\n\
Preview is pure: no filesystem, clocks, model reads or camera contact. The outer approval\n\
binds the complete native capture plan and every reserved generation's explicit camera/time\n\
assumptions, destination, pinned native RGB package, sampling and resource ceilings.\n\
Supply one --binding for EVERY reserved generation, in the same order as --generations.\n\
Capture time is an operator assumption. Receive time is never used as capture time.\n\
\n\
Approved execution resolves separate archive/deployment/model paths and compiles the pinned\n\
local native model before contacting the one approved literal-IP camera route. Only a\n\
satisfied capture with a complete durable ended-history inventory advances automatically.\n\
The camera must end each selected HTTP response. --stop-after-frames and capture --decode\n\
are refused: a deliberately interrupted current prefix is not an ended HTTP history.\n\
Native reconnect policy and original capture budgets are unchanged; generations never refill\n\
the analysis inference, pixel, source or framing allowances. Current privacy applies.\n\
\n\
Analysis bounds: --analysis-timeout-ms 600000 --analysis-work 1000000000000\n\
  --analysis-framing-work 10000000000 --analysis-report-bytes 33619968\n\
  --max-frames-per-generation N --max-bytes-per-generation N must cover capture ceilings.\n\
  --max-history-reads 8192 --max-history-bytes 536870912 --archive-read-bytes 1073741824\n\
  --stream-read-bytes 536870912 --stream-pixel-budget 1073741824\n\
  --max-macs 8000000000 --max-tensor-bytes 268435456 --max-output-bytes 16777216\n\
  --sentinel-report-bytes 16777216 [--max-frame-pixels 256..9437184]\n\
  [--minimum-score-ppm N] --kernels optimized-cpu|scalar-reference --threads 1..64.\n\
Unprefixed --timeout-ms, --max-framing-work and --max-report-bytes bound acquisition only.\n\
The analysis timer starts before model preflight and continues across capture. It is checked\n\
at native phase/I/O boundaries, not inside an indivisible inference or capture operation.\n\
The native capture owner enforces its separately approved network/storage deadline.\n\
\n\
Save complete stdout JSONL. Native acquisition rows keep their original format. Parent rows\n\
include exact history pins, offline fss-sentinel-http-history argv, native analysis and\n\
retained fss-infer sentinel-replay argv. Output acceptance is not external durable storage.\n\
Any failure may leave originals/imports/analysis durable. Existing archive roots always\n\
refuse live recapture. Continue from saved exact pins; never reacquire to repair analysis.\n\
A capture request ending in failure requires separate offline approval to analyze. Earlier\n\
failed generations remain explicit when later approved retries satisfy the request.\n\
No event/alert dispatch, absence or continuous coverage is authorized.\n";

pub(super) struct Options {
    pub capture: super::super::plan::Options,
    /// Reservation template only. Its history root is a non-authoritative placeholder derived
    /// from the capture approval; it can never be sent to the native analysis owner.
    pub analysis: analysis_plan::Options,
    analysis_args: Vec<OsString>,
    pub approve: Option<ContentDigest>,
}

fn push(args: &mut Vec<OsString>, key: &str, value: impl Into<OsString>) {
    args.push(key.into());
    args.push(value.into());
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty()
            || args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err("bounded option/value pairs required");
        }
        let mut capture_args = Vec::new();
        let mut analysis_args = Vec::new();
        let mut keys = BTreeSet::new();
        let mut approval = None;
        let mut execute = false;
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if value.is_empty() || value.starts_with("--") {
                return Err("missing option value");
            }
            if key != "--binding" && !keys.insert(key) {
                return Err("duplicate option");
            }
            match key {
                "--approve" => {
                    let digest = ContentDigest::parse(value).map_err(|_| "invalid approval")?;
                    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
                        return Err("nonzero SHA-256 approval required");
                    }
                    approval = Some(digest);
                }
                "--execute-perception" if value == "yes" => execute = true,
                "--execute-perception" => return Err("explicit perception execution required"),
                "--deployment-root" => push(&mut analysis_args, "--root", &pair[1]),
                "--analysis-timeout-ms" => push(&mut analysis_args, "--timeout-ms", &pair[1]),
                "--analysis-work" => push(&mut analysis_args, "--max-work", &pair[1]),
                "--analysis-framing-work" => {
                    push(&mut analysis_args, "--max-framing-work", &pair[1]);
                }
                "--analysis-report-bytes" => {
                    push(&mut analysis_args, "--max-report-bytes", &pair[1]);
                }
                "--site"
                | "--binding"
                | "--interpretation"
                | "--package"
                | "--package-digest"
                | "--read-originals"
                | "--read-model"
                | "--retain-analysis"
                | "--minimum-score-ppm"
                | "--kernels"
                | "--threads"
                | "--sentinel-every-frames"
                | "--sentinel-burst-frames"
                | "--sentinel-max-inferences"
                | "--stream-read-bytes"
                | "--stream-pixel-budget"
                | "--max-frame-pixels"
                | "--max-macs"
                | "--max-tensor-bytes"
                | "--max-output-bytes"
                | "--sentinel-report-bytes"
                | "--max-frames-per-generation"
                | "--max-bytes-per-generation"
                | "--max-history-reads"
                | "--max-history-bytes"
                | "--archive-read-bytes" => analysis_args.extend_from_slice(pair),
                "--archive"
                | "--history-session"
                | "--history-root"
                | "--history-connections"
                | "--approve-import" => {
                    return Err("history identity comes only from this native capture");
                }
                _ => capture_args.extend_from_slice(pair),
            }
        }
        if !execute {
            return Err("--execute-perception yes required");
        }
        let capture = super::super::plan::Options::parse(&capture_args)?;
        if capture.history_work.is_none()
            || capture.stop_after.is_some()
            || capture.decode.is_some()
        {
            return Err(
                "sentinel requires durable ended history without stop-after-frames or capture decode",
            );
        }
        push(&mut analysis_args, "--archive", capture.root.as_os_str());
        push(&mut analysis_args, "--principal", &capture.principal);
        push(&mut analysis_args, "--owner-authorized", "yes");
        push(&mut analysis_args, "--retain-originals", "yes");
        let session = capture.approval().to_text();
        push(&mut analysis_args, "--history-session", &session);
        push(&mut analysis_args, "--history-root", &session);
        push(
            &mut analysis_args,
            "--history-connections",
            capture.generations.len().to_string(),
        );
        if !keys.contains("--analysis-timeout-ms") {
            push(&mut analysis_args, "--timeout-ms", "600000");
        }
        if !keys.contains("--max-frames-per-generation") {
            push(
                &mut analysis_args,
                "--max-frames-per-generation",
                capture.per_slot_frames.to_string(),
            );
        }
        if !keys.contains("--max-bytes-per-generation") {
            push(
                &mut analysis_args,
                "--max-bytes-per-generation",
                capture.archive.maximum_bytes.to_string(),
            );
        }
        let analysis = analysis_plan::Options::parse(&analysis_args)?;
        if !analysis.plan.retain {
            return Err("--retain-analysis yes required for source-closed live sentinel");
        }
        if analysis.plan.bindings.len() != capture.generations.len()
            || analysis
                .plan
                .bindings
                .iter()
                .zip(&capture.generations)
                .any(|(binding, generation)| binding.generation != *generation)
            || (analysis.limits.maximum_frames_per_generation as u64) < capture.per_slot_frames
            || analysis.limits.maximum_bytes_per_generation < capture.archive.maximum_bytes
            || analysis.limits.history.maximum_reads
                < capture.generations.len() as u64 * capture.archive.maximum_reads as u64
            || analysis.limits.history.maximum_bytes
                < capture.generations.len() as u64 * capture.archive.maximum_bytes
        {
            return Err(
                "analysis must bind every reserved generation and cover capture frame/read/byte ceilings",
            );
        }
        let result = Self {
            capture,
            analysis,
            analysis_args,
            approve: approval,
        };
        result.preview()?;
        Ok(result)
    }

    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.http_capture_sentinel_plan.v1");
        e.text(POLICY);
        e.digest(self.capture.approval());
        e.digest(self.analysis.approval()?);
        e.u64(MAX_ARGUMENTS as u64);
        e.u64(analysis_plan::MAX_PREVIEW_BYTES as u64);
        Ok(ContentDigest::sha256(
            &e.finish_checked().map_err(|_| "approval bound")?,
        ))
    }

    /// Only a typed settled receipt can supply the real history pin. Unused reserved
    /// generations are dropped; all whole-operation resource ceilings remain unchanged.
    pub fn resolve(
        &self,
        pin: ReconnectHistoryPin,
    ) -> Result<(analysis_plan::Options, Vec<String>), &'static str> {
        if pin.session != self.capture.approval()
            || pin.connections == 0
            || pin.connections as usize > self.capture.generations.len()
        {
            return Err(super::SOURCE);
        }
        let mut args = Vec::new();
        let mut binding = 0;
        for pair in self.analysis_args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or(super::PATH)?;
            match key {
                "--history-session" => push(&mut args, key, pin.session.to_text()),
                "--history-root" => push(&mut args, key, pin.root.to_text()),
                "--history-connections" => push(&mut args, key, pin.connections.to_string()),
                "--binding" => {
                    if binding < pin.connections {
                        args.extend_from_slice(pair);
                    }
                    binding += 1;
                }
                _ => args.extend_from_slice(pair),
            }
        }
        let analysis = analysis_plan::Options::parse(&args)?;
        let mut continuation = vec!["fss-sentinel-http-history".to_owned()];
        for word in args {
            continuation.push(word.into_string().map_err(|_| super::PATH)?);
        }
        Ok((analysis, continuation))
    }

    pub fn preview(&self) -> Result<String, &'static str> {
        let a = &self.analysis;
        let r = a.plan.reservation(&a.limits).map_err(|e| e.stable_id())?;
        let bindings = a
            .plan
            .bindings
            .iter()
            .map(|b| {
                object(&[
                    ("generation", b.generation.to_string()),
                    ("sensor_id", string(b.sensor.as_str())),
                    ("stream_id", string(b.stream.as_str())),
                    ("receive_time_ns", string(&b.receive_time.0.to_string())),
                    (
                        "capture_start_ns",
                        string(&b.capture_hint.start_ns.0.to_string()),
                    ),
                    (
                        "capture_uncertainty_ns",
                        b.capture_hint.uncertainty_ns.to_string(),
                    ),
                    ("assumed_fps", b.capture_hint.assumed_fps.to_string()),
                ])
            })
            .collect::<Vec<_>>();
        let output = object(&[
            ("format", string(FORMAT)),
            ("kind", string("plan")),
            ("policy", string(POLICY)),
            ("approval_digest", string(&self.approval()?.to_text())),
            ("capture", self.capture.preview()),
            (
                "analysis",
                object(&[
                    ("root", string(a.root.to_str().ok_or(super::PATH)?)),
                    ("site", string(&a.site)),
                    ("package", string(a.package.to_str().ok_or(super::PATH)?)),
                    ("package_digest", string(&a.plan.package_digest.to_text())),
                    ("template_approval", string(&a.approval()?.to_text())),
                    (
                        "history_selection",
                        string("exact_typed_settled_prefix_from_this_capture"),
                    ),
                    ("bindings", array(&bindings)),
                    ("backend", string(a.plan.backend.stable_id())),
                    (
                        "backend_generation",
                        string(&a.plan.backend.generation().to_text()),
                    ),
                    ("threads", a.thread_count.to_string()),
                    (
                        "interpretation",
                        string(match a.plan.interpretation {
                            ComponentInterpretation::Grayscale => "gray",
                            ComponentInterpretation::YCbCr => "ycbcr",
                        }),
                    ),
                    (
                        "minimum_score_ppm",
                        a.plan
                            .minimum_score_ppm
                            .map_or_else(|| "null".into(), |value| value.to_string()),
                    ),
                    (
                        "frame_pixels",
                        a.frame_pixels
                            .map_or_else(|| "null".into(), |value| value.to_string()),
                    ),
                    ("retain_analysis", "true".into()),
                    ("inferences", r.inference.inferences.to_string()),
                    (
                        "sampling",
                        object(&[
                            ("every_frames", a.plan.sampling.every_frames.to_string()),
                            ("burst_frames", a.plan.sampling.burst_frames.to_string()),
                            ("max_inferences", a.plan.sampling.max_inferences.to_string()),
                        ]),
                    ),
                    (
                        "limits",
                        object(&[
                            (
                                "maximum_frames_per_generation",
                                a.limits.maximum_frames_per_generation.to_string(),
                            ),
                            (
                                "maximum_bytes_per_generation",
                                a.limits.maximum_bytes_per_generation.to_string(),
                            ),
                            (
                                "maximum_history_reads",
                                a.limits.history.maximum_reads.to_string(),
                            ),
                            (
                                "maximum_history_bytes",
                                a.limits.history.maximum_bytes.to_string(),
                            ),
                            (
                                "maximum_archive_read_bytes",
                                a.archive_read_bytes.to_string(),
                            ),
                            (
                                "maximum_archive_operations",
                                analysis_plan::STORAGE_OPERATIONS.to_string(),
                            ),
                            ("maximum_package_bytes", MAX_RGB_PACKAGE_BYTES.to_string()),
                            (
                                "maximum_package_compile_macs",
                                analysis_plan::PACKAGE_COMPILE_MACS.to_string(),
                            ),
                            (
                                "jpeg_frame_pixels",
                                a.limits
                                    .sentinel
                                    .package
                                    .jpeg
                                    .frame
                                    .maximum_pixels
                                    .to_string(),
                            ),
                            (
                                "avc_macroblocks",
                                a.limits.sentinel.package.h264.max_macroblocks.to_string(),
                            ),
                            (
                                "hevc_luma_samples",
                                a.limits.sentinel.package.h265.max_luma_samples.to_string(),
                            ),
                            ("maximum_work", a.work.to_string()),
                            ("maximum_framing_work", a.framing.to_string()),
                            (
                                "maximum_report_bytes",
                                a.limits.maximum_report_bytes.to_string(),
                            ),
                            ("timeout_ms", a.timeout_ms.to_string()),
                            (
                                "native_limits_digest",
                                string(&a.limits.sentinel.digest().to_text()),
                            ),
                            ("execution_macs", r.inference.execution_macs.to_string()),
                            ("output_bytes", r.inference.output_bytes.to_string()),
                            (
                                "source_chunk_bytes",
                                r.inference.source_chunk_bytes.to_string(),
                            ),
                            ("pixel_samples", r.inference.pixel_samples.to_string()),
                        ]),
                    ),
                ]),
            ),
            ("writes", string("none")),
            ("network", string("none")),
            ("event_publication_authorized", "false".into()),
            ("automatic_reacquisition_authorized", "false".into()),
            ("absence_certifiable", "false".into()),
        ]);
        if output.len() >= analysis_plan::MAX_PREVIEW_BYTES {
            return Err(super::LIMIT);
        }
        Ok(output)
    }
}
