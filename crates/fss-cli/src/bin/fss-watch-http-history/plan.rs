#![forbid(unsafe_code)]
//! Pure argument admission, resource reservations, and exact original-retention approval.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId, SensorId, StreamId, TimestampNs,
};
use fss_reference::http_reconnect_history::ReconnectHistoryPin;
use fss_reference::ingest::CaptureHint;
use fss_reference::ingest::http_history_watch::{
    HttpHistoryWatchBinding, HttpHistoryWatchLimits, HttpHistoryWatchPlan,
};
use fss_reference::ingest::http_import::{MAX_BYTES, MAX_FRAMES};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchTrackerConfig, WatchZone,
};
use fss_reference::reference_deployment::validate_site_lineage;

pub(super) const MAX_ARGUMENTS: usize = 192;
pub(super) const FORMAT: &str = "fss.http_history_watch_operator.v1";

pub(super) struct Options {
    pub archive: PathBuf,
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub plan: HttpHistoryWatchPlan,
    pub limits: HttpHistoryWatchLimits,
    pub work: u64,
    pub framing: u64,
    pub timeout_ms: u64,
    pub approve: Option<ContentDigest>,
}

fn path(text: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(text);
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("non-root absolute path without dot components required");
    }
    Ok(path)
}

fn digest(text: &str) -> Result<ContentDigest, &'static str> {
    let digest = ContentDigest::parse(text).map_err(|_| "invalid digest")?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("nonzero SHA-256 digest required");
    }
    Ok(digest)
}

fn integer(text: &str) -> Result<u64, &'static str> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("unsigned decimal integer required");
    }
    text.parse().map_err(|_| "integer overflow")
}

fn binding(text: &str) -> Result<HttpHistoryWatchBinding, &'static str> {
    let parts: Vec<_> = text.split(',').collect();
    let [generation, sensor, stream, receive, start, uncertainty, fps] = parts.as_slice() else {
        return Err(
            "binding requires GENERATION,SENSOR,STREAM,RECEIVE_NS,CAPTURE_START_NS,UNCERTAINTY_NS,FPS",
        );
    };
    let timestamp = |value: &str| {
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err("nonnegative decimal timestamp required");
        }
        value
            .parse::<i128>()
            .map(TimestampNs)
            .map_err(|_| "timestamp overflow")
    };
    Ok(HttpHistoryWatchBinding {
        generation: integer(generation)?,
        sensor: SensorId::parse(*sensor).map_err(|_| "invalid binding sensor")?,
        stream: StreamId::parse(*stream).map_err(|_| "invalid binding stream")?,
        receive_time: timestamp(receive)?,
        capture_hint: CaptureHint::new(
            timestamp(start)?,
            integer(uncertainty)?,
            fps.parse().map_err(|_| "invalid frame rate")?,
        )
        .map_err(|_| "invalid explicit capture hint")?,
    })
}

fn zone(text: &str) -> Result<WatchZone, &'static str> {
    let (id, geometry) = text.split_once(':').ok_or("zone must be ID:X,Y,W,H")?;
    let parts: Vec<u32> = geometry
        .split(',')
        .map(|p| integer(p).and_then(|n| u32::try_from(n).map_err(|_| "zone coordinate overflow")))
        .collect::<Result<_, _>>()?;
    let [x, y, width, height] = parts.as_slice() else {
        return Err("zone needs four coordinates");
    };
    Ok(WatchZone {
        zone_id: id.into(),
        x: *x,
        y: *y,
        width: *width,
        height: *height,
    })
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty()
            || args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|a| a.as_encoded_bytes().len() > 4096)
        {
            return Err("argument count or byte bound");
        }
        let allowed = [
            "--archive",
            "--root",
            "--site",
            "--principal",
            "--history-session",
            "--history-root",
            "--history-connections",
            "--interpretation",
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
            "--approve-import",
            "--max-frames-per-generation",
            "--max-bytes-per-generation",
            "--max-history-reads",
            "--max-history-bytes",
            "--max-report-bytes",
            "--max-work",
            "--max-framing-work",
            "--timeout-ms",
            "--work-units",
            "--stream-read-bytes",
            "--stream-pixel-budget",
            "--stream-assignment-work",
            "--stream-trace-bytes",
            "--max-dimension",
            "--max-pixels",
            "--max-segment-bytes",
            "--pixel-threshold",
            "--threshold-sigma",
            "--learning-rate-num",
            "--learning-rate-den",
            "--min-region-pixels",
            "--confirmation-hits",
            "--maximum-missed-frames",
            "--minimum-iou-ppm",
            "--screened",
            "--tolerate-decode-refusals",
        ];
        let mut values = BTreeMap::new();
        let mut bindings = Vec::new();
        let mut zones = Vec::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if value.is_empty() || value.starts_with("--") {
                return Err("missing option value");
            }
            match key {
                "--binding" if bindings.len() < 32 => bindings.push(binding(value)?),
                "--zone" if zones.len() < 16 => zones.push(zone(value)?),
                _ if allowed.contains(&key) => {
                    if values.insert(key, value).is_some() {
                        return Err("duplicate option");
                    }
                }
                _ => return Err("unknown option or repeated collection bound exceeded"),
            }
        }
        let required = |key| values.get(key).copied().ok_or("required option missing");
        for key in [
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
        ] {
            if required(key)? != "yes" {
                return Err(
                    "explicit owner, original-read and destination-retention acknowledgements required",
                );
            }
        }
        let number = |key, default: u64, low, high| -> Result<u64, &'static str> {
            let n = values.get(key).map_or(Ok(default), |v| integer(v))?;
            if n < low || n > high {
                return Err("numeric bound exceeded");
            }
            Ok(n)
        };
        let flag = |key| -> Result<bool, &'static str> {
            match values.get(key).copied().unwrap_or("no") {
                "yes" => Ok(true),
                "no" => Ok(false),
                _ => Err("boolean option requires yes or no"),
            }
        };
        let mut limits = HttpHistoryWatchLimits::default();
        limits.maximum_frames_per_generation = number(
            "--max-frames-per-generation",
            limits.maximum_frames_per_generation as u64,
            1,
            MAX_FRAMES as u64,
        )? as usize;
        limits.maximum_bytes_per_generation = number(
            "--max-bytes-per-generation",
            limits.maximum_bytes_per_generation,
            1,
            MAX_BYTES,
        )?;
        limits.history.maximum_reads =
            number("--max-history-reads", limits.history.maximum_reads, 1, 8192)?;
        limits.history.maximum_bytes = number(
            "--max-history-bytes",
            limits.history.maximum_bytes,
            1,
            512 * 1024 * 1024,
        )?;
        limits.maximum_report_bytes = number(
            "--max-report-bytes",
            limits.maximum_report_bytes as u64,
            1,
            32 * 1024 * 1024 + 65536,
        )? as usize;
        limits.watch.decode.jpeg_work_units = number(
            "--work-units",
            limits.watch.decode.jpeg_work_units,
            1,
            1_000_000_000_000_000,
        )?;
        limits.watch.decode.read_limits.max_segment_bytes = number(
            "--max-segment-bytes",
            limits.watch.decode.read_limits.max_segment_bytes,
            1,
            16 * 1024 * 1024,
        )?;
        // Mirror fss-event watch codec admission exactly so the supplied publish reruns reproduce
        // every successful native watch identity, including otherwise unused codec ceilings.
        let dimension = number("--max-dimension", 4096, 16, 4096)? as u32;
        let pixels = number("--max-pixels", 4_194_304, 1, 4_194_304)? as usize;
        limits.watch.decode.jpeg_limits.maximum_dimension = dimension;
        limits.watch.decode.jpeg_limits.maximum_pixels = pixels;
        limits.watch.decode.h264_limits.max_width = dimension;
        limits.watch.decode.h264_limits.max_height = dimension;
        limits.watch.decode.h264_limits.max_macroblocks = pixels.div_ceil(256) as u32;
        limits.watch.decode.h265_limits.max_width = dimension;
        limits.watch.decode.h265_limits.max_height = dimension;
        limits.watch.decode.h265_limits.max_luma_samples = pixels as u64;
        limits.watch.maximum_source_chunk_bytes = number(
            "--stream-read-bytes",
            limits.watch.maximum_source_chunk_bytes,
            1,
            512 * 1024 * 1024,
        )?;
        limits.watch.maximum_pixel_samples = number(
            "--stream-pixel-budget",
            limits.watch.maximum_pixel_samples,
            1,
            u64::MAX,
        )?;
        limits.watch.maximum_assignment_work = number(
            "--stream-assignment-work",
            limits.watch.maximum_assignment_work,
            1,
            u64::MAX,
        )?;
        limits.watch.maximum_trace_bytes = number(
            "--stream-trace-bytes",
            limits.watch.maximum_trace_bytes as u64,
            1,
            8 * 1024 * 1024,
        )? as usize;
        let d = WatchDetectorConfig::default();
        let detector = WatchDetectorConfig {
            base_threshold: number(
                "--pixel-threshold",
                u64::from(d.base_threshold),
                0,
                u16::MAX as u64,
            )? as u16,
            threshold_sigma: number(
                "--threshold-sigma",
                u64::from(d.threshold_sigma),
                0,
                u16::MAX as u64,
            )? as u16,
            learning_rate_num: number(
                "--learning-rate-num",
                u64::from(d.learning_rate_num),
                0,
                u16::MAX as u64,
            )? as u16,
            learning_rate_den: number(
                "--learning-rate-den",
                u64::from(d.learning_rate_den),
                1,
                u16::MAX as u64,
            )? as u16,
            minimum_region_pixels: number(
                "--min-region-pixels",
                d.minimum_region_pixels as u64,
                1,
                4_194_304,
            )? as usize,
        };
        let t = WatchTrackerConfig::default();
        let tracker = WatchTrackerConfig {
            confirmation_hits: number(
                "--confirmation-hits",
                u64::from(t.confirmation_hits),
                1,
                u32::MAX as u64,
            )? as u32,
            maximum_missed_frames: number(
                "--maximum-missed-frames",
                u64::from(t.maximum_missed_frames),
                0,
                u32::MAX as u64,
            )? as u32,
            minimum_iou_ppm: number(
                "--minimum-iou-ppm",
                u64::from(t.minimum_iou_ppm),
                0,
                1_000_000,
            )? as u32,
        };
        let plan = HttpHistoryWatchPlan {
            history: ReconnectHistoryPin {
                session: digest(required("--history-session")?)?,
                root: digest(required("--history-root")?)?,
                connections: number("--history-connections", 0, 1, 32)? as u32,
            },
            bindings,
            interpretation: match required("--interpretation")? {
                "gray" => ComponentInterpretation::Grayscale,
                "ycbcr" => ComponentInterpretation::YCbCr,
                _ => return Err("interpretation requires gray or ycbcr"),
            },
            zones,
            detector,
            tracker,
            options: WatchOptions {
                tolerate_decode_refusals: flag("--tolerate-decode-refusals")?,
            },
            screened: flag("--screened")?,
        };
        plan.digest(&limits)
            .map_err(|_| "invalid exact history watch plan or resource reservation")?;
        let archive = path(required("--archive")?)?;
        let root = path(required("--root")?)?;
        if archive.starts_with(&root) || root.starts_with(&archive) {
            return Err("distinct non-nested stores required");
        }
        let site = required("--site")?.to_owned();
        validate_site_lineage(&site).map_err(|_| "invalid site lineage")?;
        if site.len() > 256 {
            return Err("site byte bound");
        }
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if principal.len() > 128 {
            return Err("principal byte bound");
        }
        let result = Self {
            archive,
            root,
            site,
            principal,
            plan,
            limits,
            work: number("--max-work", 1_000_000_000_000, 1, 1_000_000_000_000_000)?,
            framing: number(
                "--max-framing-work",
                10_000_000_000,
                1,
                1_000_000_000_000_000,
            )?,
            timeout_ms: number("--timeout-ms", 30_000, 1, 600_000)?,
            approve: values
                .get("--approve-import")
                .map(|s| digest(s))
                .transpose()?,
        };
        // Reserve command capacity before import. Real import digests have the same length;
        // using the maximum admitted frame count also bounds decimal segment-count bytes.
        super::rerun::preview_bound(&result)?;
        Ok(result)
    }

    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.http_history_watch_cli_plan.v1");
        e.text("exact-history:owner-original-read:source-closed-retention:native-watch:no-network:no-event-publish:v1");
        e.digest(self.plan.digest(&self.limits).map_err(|e| e.stable_id())?);
        e.text(self.archive.to_str().ok_or("UTF-8 path required")?);
        e.text(self.root.to_str().ok_or("UTF-8 path required")?);
        e.text(&self.site);
        e.text(&self.principal);
        e.u64(self.work);
        e.u64(self.framing);
        e.u64(self.timeout_ms);
        Ok(ContentDigest::sha256(&e.finish()))
    }

    pub fn preview(&self) -> Result<String, &'static str> {
        let reservation = self
            .plan
            .reservation(&self.limits)
            .map_err(|e| e.stable_id())?;
        let bindings = self
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
            .collect::<Vec<_>>()
            .join(",");
        let limits = &self.limits;
        let report = object(&[
            ("format", string(FORMAT)),
            ("kind", string("plan")),
            ("approval_digest", string(&self.approval()?.to_text())),
            (
                "plan_digest",
                string(
                    &self
                        .plan
                        .digest(limits)
                        .map_err(|e| e.stable_id())?
                        .to_text(),
                ),
            ),
            (
                "archive",
                string(self.archive.to_str().ok_or("UTF-8 path required")?),
            ),
            (
                "root",
                string(self.root.to_str().ok_or("UTF-8 path required")?),
            ),
            ("site", string(&self.site)),
            ("principal", string(&self.principal)),
            (
                "history_pin",
                object(&[
                    ("session", string(&self.plan.history.session.to_text())),
                    ("root", string(&self.plan.history.root.to_text())),
                    ("connections", self.plan.history.connections.to_string()),
                ]),
            ),
            ("bindings", format!("[{bindings}]")),
            (
                "watch_configuration",
                super::rerun::configuration_json(self),
            ),
            (
                "maximum_frames_per_generation",
                limits.maximum_frames_per_generation.to_string(),
            ),
            (
                "maximum_bytes_per_generation",
                limits.maximum_bytes_per_generation.to_string(),
            ),
            (
                "history_limits",
                object(&[
                    ("total_reads", limits.history.maximum_reads.to_string()),
                    ("total_bytes", limits.history.maximum_bytes.to_string()),
                    (
                        "per_generation_reads",
                        limits.history.archive.maximum_reads.to_string(),
                    ),
                    (
                        "per_generation_bytes",
                        limits.history.archive.maximum_bytes.to_string(),
                    ),
                    (
                        "archive_scan_roots",
                        limits.history.archive.maximum_scan_roots.to_string(),
                    ),
                    (
                        "spool_object_bytes",
                        limits
                            .history
                            .archive
                            .maximum_spool_object_bytes
                            .to_string(),
                    ),
                ]),
            ),
            (
                "reserved_whole_history",
                object(&[
                    ("connections", reservation.connections.to_string()),
                    ("frames", reservation.frames.to_string()),
                    ("original_bytes", reservation.original_bytes.to_string()),
                    (
                        "source_read_bytes",
                        reservation.source_read_bytes.to_string(),
                    ),
                    ("pixel_samples", reservation.pixel_samples.to_string()),
                    ("assignment_work", reservation.assignment_work.to_string()),
                    ("jpeg_work", reservation.jpeg_work.to_string()),
                    ("trace_bytes", reservation.trace_bytes.to_string()),
                    ("report_bytes", reservation.report_bytes.to_string()),
                ]),
            ),
            ("maximum_work", self.work.to_string()),
            ("maximum_framing_work", self.framing.to_string()),
            ("timeout_ms", self.timeout_ms.to_string()),
            (
                "maximum_report_bytes",
                limits.maximum_report_bytes.to_string(),
            ),
            (
                "capture_time_label",
                string("operator_assumptions_per_generation"),
            ),
            ("writes", string("none")),
            ("approved_writes", string("source_closed_recording_imports")),
            ("network", string("none")),
            ("event_publication", string("separate_exact_watch_approval")),
        ]);
        if report.len() > 65536 {
            return Err("ERR-HTTP-HISTORY-WATCH-LIMIT-001");
        }
        Ok(report)
    }
}
