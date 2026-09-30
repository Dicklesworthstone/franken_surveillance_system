#![forbid(unsafe_code)]
//! Pure plan construction and exact operator approval. No filesystem, network or clock reads.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Component, PathBuf};

use fss_cli::agent_json::{array, object, string};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::ingest::http_archive::HttpArchiveLimits;
use fss_reference::ingest::http_camera::HttpCameraLimits;
use fss_reference::ingest::http_reconnect::{
    HttpReconnectPolicy, HttpReconnectReservation, HttpReconnectSlot, MAX_RECONNECT_CONNECTIONS,
};
use fss_reference::ingest::http_reconnect_recording::{
    HttpReconnectRecording, HttpReconnectRecordingPlan, HttpReconnectRecordingSlot,
};
use fss_reference::ingest::http_recording::{HttpRecordingLimits, HttpRecordingRequest};
use fss_reference::ingest::http_replay::check::HttpCheckSource;

pub(super) const MAX_ARGUMENTS: usize = 80;

use super::decode;
pub(super) const RESERVE: usize = 64 * 1024;
pub(super) const FORMAT: &str = "fss.http_reconnect_capture.v1";
const DOMAIN: &str = "fss.http_reconnect_capture_plan.v1";
const POLICY: &str = "explicit-generations:fixed-slot-reservations:root-before-parse:\
verified-boundary-before-next-connect:native-retry-policy:one-deadline:framing-only:v1";
pub(super) const HELP: &str = "fss-capture-reconnect --root ABSOLUTE_ARCHIVE_DIR --peer IP:PORT\n\
  --host HOST --target /PATH --source sha256:HEX --generations N,N[,N...]\n\
  --receive-clock sha256:HEX --retention-evidence sha256:HEX\n\
  --owner-authorized yes --plaintext yes --retain-originals yes [--approve sha256:HEX]\n\
  Preview without --approve performs NO filesystem/network I/O. Repeat with its exact approval.\n\
  --generations reserves 1..32 strictly increasing, nonzero generations on ONE literal-IP route.\n\
  --initial-backoff-ms 250 --maximum-backoff-ms 5000 --after-complete no|yes (default no).\n\
  Only existing native transport/truncation failures retry. Denials, malformed data, privacy,\n\
  storage and exhausted limits never trigger a fallback, reset, or an unapproved generation.\n\
  --timeout-ms 30000 is ONE run deadline; --connect-timeout-ms 5000 caps each attempt.\n\
  Per-slot ceilings: --max-reads 512 --max-source-bytes 67108864 --max-frames 128\n\
                    --read-bytes 16384 --max-frame-bytes 16777216 --max-io-calls 1000000.\n\
  Whole-run ceilings: --max-steps 100000 --max-source-work 1000000000000\n\
                     --max-framing-work 1000000000 --max-report-bytes 8388608.\n\
  Hard aggregate reservation: 8192 reads and 512 MiB original response bytes. Slots do not refill.\n\
  --stop-after-frames N deliberately stops after N verified parts across all generations; NOT EOF.\n\
  --principal ID is an audit label, not authentication. No credentials, DNS, redirects or TLS.\n\
  Save stdout JSONL independently. Prepared pins precede disk writes; verified boundaries precede\n\
  the next connect. Output acceptance is NOT a durable external checkpoint acknowledgement.\n\
  Optional --decode grayscale|ycbcr requires --privacy-root EXISTING_DEPLOYMENT --site SITE --sensor ID.\n\
  --max-decode-work 1000000000 is shared across ALL connections; --max-dimension 4096 and\n\
  --max-pixels 4194304 bound each frame. Current privacy masks apply before pixel digests.\n\
  --recoverable yes emits a lossless recovery key before each original-read publication.\n\
  Save it independently; fss-recover-http can reconcile already-staged bytes, not resume capture.\n\
  No pixels, raw headers, capture timestamps, detection, events, alerts or absence claims.\n\
  Original source is private local UNENCRYPTED custody. This is not crash-resume or a daemon.\n";

#[derive(Debug)]
pub(super) struct Options {
    pub root: PathBuf,
    pub peer: SocketAddr,
    pub host: String,
    pub target: String,
    pub principal: String,
    pub source: ContentDigest,
    pub generations: Vec<u64>,
    pub receive_clock: ContentDigest,
    pub retention_evidence: ContentDigest,
    pub native: HttpCameraLimits,
    pub archive: HttpArchiveLimits,
    pub per_slot_frames: u64,
    pub policy: HttpReconnectPolicy,
    pub source_work: u64,
    pub maximum_steps: u64,
    pub timeout_ns: u64,
    pub report_bytes: usize,
    pub stop_after: Option<u64>,
    pub approve: Option<ContentDigest>,
    pub decode: Option<decode::Options>,
    pub recoverable: bool,
}

fn digest(text: &str) -> Result<ContentDigest, &'static str> {
    let digest = ContentDigest::parse(text).map_err(|_| "invalid SHA-256 identity")?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("nonzero SHA-256 required");
    }
    Ok(digest)
}
fn unsigned(text: &str) -> Result<u64, &'static str> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("unsigned decimal required");
    }
    text.parse().map_err(|_| "integer overflow")
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|s| s.as_encoded_bytes().len() > 4096)
        {
            return Err("argument count, UTF-8 value or byte bound");
        }
        let allowed = [
            "--root",
            "--peer",
            "--host",
            "--target",
            "--source",
            "--generations",
            "--receive-clock",
            "--retention-evidence",
            "--owner-authorized",
            "--plaintext",
            "--retain-originals",
            "--principal",
            "--approve",
            "--timeout-ms",
            "--connect-timeout-ms",
            "--max-reads",
            "--max-source-bytes",
            "--max-frames",
            "--read-bytes",
            "--max-frame-bytes",
            "--max-io-calls",
            "--max-steps",
            "--max-source-work",
            "--max-framing-work",
            "--max-report-bytes",
            "--stop-after-frames",
            "--initial-backoff-ms",
            "--maximum-backoff-ms",
            "--after-complete",
            "--recoverable",
            "--decode",
            "--privacy-root",
            "--site",
            "--sensor",
            "--max-decode-work",
            "--max-dimension",
            "--max-pixels",
        ];
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if !allowed.contains(&key) || value.is_empty() || value.starts_with("--") {
                return Err("unknown option or missing value");
            }
            if values.insert(key, value).is_some() {
                return Err("duplicate option");
            }
        }
        let required = |key: &str| values.get(key).copied().ok_or("required option missing");
        let number = |key: &str, default: u64, low: u64, high: u64| -> Result<u64, &'static str> {
            let value = values
                .get(key)
                .map_or(Ok(default), |value| unsigned(value))?;
            if !(low..=high).contains(&value) {
                return Err("numeric bound exceeded");
            }
            Ok(value)
        };
        for key in ["--owner-authorized", "--plaintext", "--retain-originals"] {
            if required(key)? != "yes" {
                return Err(
                    "explicit owner, plaintext and original-retention acknowledgements required",
                );
            }
        }
        let root = PathBuf::from(required("--root")?);
        if !root.is_absolute()
            || root.parent().is_none()
            || root
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err("non-root absolute archive path without dot components required");
        }
        let mut generations = Vec::new();
        for text in required("--generations")?.split(',') {
            if generations.len() == MAX_RECONNECT_CONNECTIONS {
                return Err("at most 32 generations");
            }
            let generation = unsigned(text)?;
            if generation == 0
                || generations
                    .last()
                    .is_some_and(|previous| *previous >= generation)
            {
                return Err("generations must be nonzero and strictly increasing");
            }
            generations.push(generation);
        }
        let per_slot_frames = number("--max-frames", 128, 1, 4096)?;
        let mut native = HttpCameraLimits::default();
        native.http.wire_bytes =
            number("--max-source-bytes", 64 * 1024 * 1024, 1, 256 * 1024 * 1024)?;
        native.http.entity_bytes = native.http.wire_bytes;
        native.read_bytes = number("--read-bytes", 16384, 1, 65536)? as usize;
        native.multipart.frame_bytes =
            number("--max-frame-bytes", 16 * 1024 * 1024, 4, 16 * 1024 * 1024)? as usize;
        native.frames = per_slot_frames + 1; // EOF lookahead, never transferred beyond the approved count.
        native.io_calls = number("--max-io-calls", 1_000_000, 1, 1_000_000)?;
        native.connect_timeout_ns = number("--connect-timeout-ms", 5000, 1, 60_000)? * 1_000_000;
        let archive = HttpArchiveLimits {
            maximum_reads: number("--max-reads", 512, 1, 4096)? as usize,
            maximum_bytes: native.http.wire_bytes,
            maximum_scan_roots: 65536,
            maximum_spool_object_bytes: 16 * 1024 * 1024,
        };
        let count = generations.len() as u64;
        if count * archive.maximum_reads as u64 > 8192
            || count * native.http.wire_bytes > 512 * 1024 * 1024
        {
            return Err("aggregate reservation exceeds 8192 reads or 512 MiB; narrow each slot");
        }
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if principal.len() > 256 {
            return Err("principal byte bound");
        }
        let after_complete = match values.get("--after-complete").copied().unwrap_or("no") {
            "yes" => true,
            "no" => false,
            _ => return Err("--after-complete requires yes or no"),
        };
        let recoverable = match values.get("--recoverable").copied().unwrap_or("no") {
            "yes" => true,
            "no" => false,
            _ => return Err("--recoverable requires yes or no"),
        };
        let decode = decode::Options::parse(&values, &root, native.multipart.frame_bytes)?;
        let options = Self {
            root,
            generations,
            principal,
            native,
            archive,
            per_slot_frames,
            decode,
            recoverable,
            peer: required("--peer")?
                .parse()
                .map_err(|_| "literal IP:PORT required")?,
            host: required("--host")?.to_owned(),
            target: required("--target")?.to_owned(),
            source: digest(required("--source")?)?,
            receive_clock: digest(required("--receive-clock")?)?,
            retention_evidence: digest(required("--retention-evidence")?)?,
            policy: HttpReconnectPolicy {
                initial_backoff_ns: number("--initial-backoff-ms", 250, 1, 60_000)? * 1_000_000,
                maximum_backoff_ns: number("--maximum-backoff-ms", 5000, 1, 60_000)? * 1_000_000,
                reconnect_after_complete: after_complete,
                framing_work: number(
                    "--max-framing-work",
                    1_000_000_000,
                    1,
                    1_000_000_000_000_000,
                )?,
            },
            source_work: number(
                "--max-source-work",
                1_000_000_000_000,
                1,
                1_000_000_000_000_000,
            )?,
            maximum_steps: number("--max-steps", 100_000, 1, 1_000_000)?,
            timeout_ns: number("--timeout-ms", 30_000, 1, 600_000)? * 1_000_000,
            report_bytes: number(
                "--max-report-bytes",
                8 * 1024 * 1024,
                (RESERVE * 2) as u64,
                32 * 1024 * 1024,
            )? as usize,
            stop_after: values
                .contains_key("--stop-after-frames")
                .then(|| number("--stop-after-frames", 0, 1, count * per_slot_frames))
                .transpose()?,
            approve: values
                .get("--approve")
                .map(|text| digest(text))
                .transpose()?,
        };
        // The actual native plan validator, not a second permissive CLI interpretation.
        options.recording()?;
        Ok(options)
    }

    pub fn source_at(&self, generation: u64) -> HttpCheckSource {
        HttpCheckSource {
            source: self.source,
            generation,
            receive_clock: self.receive_clock,
            retention_evidence: self.retention_evidence,
        }
    }
    pub fn plan(&self) -> Result<HttpReconnectRecordingPlan, &'static str> {
        let mut slots = Vec::with_capacity(self.generations.len());
        for generation in &self.generations {
            let request = HttpRecordingRequest::new(
                self.source_at(*generation),
                self.peer,
                &self.host,
                &self.target,
                HttpRecordingLimits::default(),
                self.timeout_ns,
            )
            .map_err(|_| "native route or custody scope refused")?;
            slots.push(HttpReconnectRecordingSlot {
                source: HttpReconnectSlot {
                    route: request.route,
                    limits: self.native,
                },
                scope: request.scope,
                archive: self.archive,
            });
        }
        Ok(HttpReconnectRecordingPlan {
            slots,
            policy: self.policy,
            source_work: self.source_work,
            maximum_steps: self.maximum_steps,
            deadline_ns: self.timeout_ns,
        })
    }
    pub fn recording(&self) -> Result<HttpReconnectRecording, &'static str> {
        HttpReconnectRecording::new(self.plan()?, 0).map_err(|_| "native reconnect plan refused")
    }
    // Bind all effective defaults as well as user overrides; dependency defaults cannot drift
    // silently beneath an unchanged approval. No Debug/Serde formatting defines these bytes.
    fn bound_numbers(&self) -> Vec<(&'static str, u64)> {
        let n = self.native;
        vec![
            ("http_header_bytes", n.http.header_bytes as u64),
            ("http_fragment_bytes", n.http.fragment_bytes as u64),
            ("http_chunk_bytes", n.http.chunk_bytes),
            ("http_chunks", n.http.chunks),
            ("wire_bytes_per_slot", n.http.wire_bytes),
            ("entity_bytes_per_slot", n.http.entity_bytes),
            ("multipart_header_bytes", n.multipart.header_bytes as u64),
            ("multipart_wrapper_bytes", n.multipart.wrapper_bytes as u64),
            ("frame_bytes", n.multipart.frame_bytes as u64),
            ("read_bytes", n.read_bytes as u64),
            ("frames_per_slot", self.per_slot_frames),
            ("native_frames_with_lookahead", n.frames),
            ("source_runs", n.source_runs as u64),
            ("io_calls_per_slot", n.io_calls),
            ("connect_timeout_ns", n.connect_timeout_ns),
            ("reads_per_slot", self.archive.maximum_reads as u64),
            ("scan_roots", self.archive.maximum_scan_roots as u64),
            (
                "spool_object_bytes",
                self.archive.maximum_spool_object_bytes as u64,
            ),
            ("initial_backoff_ns", self.policy.initial_backoff_ns),
            ("maximum_backoff_ns", self.policy.maximum_backoff_ns),
            ("framing_work", self.policy.framing_work),
            ("source_work", self.source_work),
            ("maximum_steps", self.maximum_steps),
            ("timeout_ns", self.timeout_ns),
            ("report_bytes", self.report_bytes as u64),
            ("stop_after_frames_or_zero", self.stop_after.unwrap_or(0)),
        ]
    }
    pub fn approval(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(if self.decode.is_some() {
            "fss.http_reconnect_capture_plan.v2"
        } else {
            DOMAIN
        });
        e.text(POLICY);
        let peer = self.peer.to_string();
        for text in [
            self.root.to_str().unwrap_or("invalid"),
            &peer,
            &self.host,
            &self.target,
            &self.principal,
        ] {
            e.text(text);
        }
        for digest in [self.source, self.receive_clock, self.retention_evidence] {
            e.digest(digest);
        }
        e.u64(self.generations.len() as u64);
        for generation in &self.generations {
            e.u64(*generation);
        }
        e.bool(self.policy.reconnect_after_complete);
        let numbers = self.bound_numbers();
        e.u64(numbers.len() as u64);
        for (name, value) in numbers {
            e.text(name);
            e.u64(value);
        }
        if let Some(decode) = &self.decode {
            decode.encode(&mut e);
        }
        let base = ContentDigest::sha256(&e.finish());
        if !self.recoverable {
            return base;
        }
        // Existing raw/v2 decode approvals are byte-identical unless explicitly opted in.
        let mut e = CanonicalEncoder::new();
        e.text("fss.http_recoverable_capture_plan.v1");
        e.digest(base);
        e.text("fss.http_wire_recovery_key.v1:preserve-before-publication:no-network-resume");
        ContentDigest::sha256(&e.finish())
    }
    pub fn preview(&self) -> String {
        let generations: Vec<_> = self
            .generations
            .iter()
            .map(|g| string(&g.to_string()))
            .collect();
        let numbers: Vec<_> = self
            .bound_numbers()
            .iter()
            .map(|(k, v)| (*k, v.to_string()))
            .collect();
        let mut fields = vec![
            ("format", string(FORMAT)),
            ("kind", string("plan")),
            ("approval_digest", string(&self.approval().to_text())),
            ("root", string(self.root.to_str().unwrap_or("invalid"))),
            ("peer", string(&self.peer.to_string())),
            ("host", string(&self.host)),
            ("target", string(&self.target)),
            ("principal", string(&self.principal)),
            ("source", string(&self.source.to_text())),
            ("generations", array(&generations)),
            ("receive_clock", string(&self.receive_clock.to_text())),
            (
                "retention_evidence",
                string(&self.retention_evidence.to_text()),
            ),
            (
                "after_complete",
                self.policy.reconnect_after_complete.to_string(),
            ),
            ("limits", object(&numbers)),
            (
                "reserved_reads",
                (self.generations.len() as u64 * self.archive.maximum_reads as u64).to_string(),
            ),
            (
                "reserved_wire_bytes",
                (self.generations.len() as u64 * self.native.http.wire_bytes).to_string(),
            ),
            (
                "reserved_frames",
                (self.generations.len() as u64 * self.per_slot_frames).to_string(),
            ),
            ("policy", string(POLICY)),
            ("writes", string("none")),
            ("network", string("none")),
            (
                "retention",
                string("original_headers_and_media_local_unencrypted"),
            ),
            ("capture_time", string("unknown_receive_clock_only")),
            ("coverage_certified", "false".into()),
        ];
        if let Some(decode) = &self.decode {
            fields.push(("native_decode", decode.to_json()));
        }
        if self.recoverable {
            fields.push(("wire_recovery", string("save_key_before_publication_no_capture_resume")));
        }
        object(&fields)
    }
}

pub(super) fn reservation_json(r: HttpReconnectReservation) -> String {
    object(&[
        ("connections", r.connections.to_string()),
        ("wire_bytes", r.wire_bytes.to_string()),
        ("entity_bytes", r.entity_bytes.to_string()),
        ("chunks", r.chunks.to_string()),
        ("io_calls", r.io_calls.to_string()),
        ("native_frames_with_lookahead", r.frames.to_string()),
        ("connect_timeout_ns_sum", r.connect_timeout_ns.to_string()),
        ("framing_work", r.framing_work.to_string()),
    ])
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "recovery_plan_tests.rs"]
mod recovery_tests;
