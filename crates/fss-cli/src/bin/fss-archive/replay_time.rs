#![forbid(unsafe_code)]
//! Bounded cold projection of source-verified recorder-reported timestamps.
//! JSON is an operator projection; the native report digest binds its interpretation.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::Path;

use fss_object::HostSpoolIo;
use fss_reference::rtsp::recording_replay::time::pinned::{
    ReplayTimeReadLimits, query_replay_time_read_only,
};
use fss_reference::rtsp::recording_replay::time::{
    REPLAY_TIME_END_EXCLUSIVE_NS, ReplayTimeLimits, ReplayTimeQuery,
};

use super::{Clock, Error, Options, Result, argument, malformed};
use fss_cli::{ERR_CLI_INVALID_UNICODE, ERR_CLI_MISSING_VALUE};

pub(super) const HELP: &str = "fss-archive query-replay-utc [options]\n\
  Required: --root EXISTING_DIR --codec avc|hevc --sensor ID --stream ID --generation N\n\
            --anchor sha256:HEX --receive-clock sha256:HEX\n\
            --decode-clock sha256:HEX --time-scale N\n\
            --expected-replay-root sha256:HEX --expected-replay-request sha256:HEX\n\
            --ntp-era N --utc-start-ns I128 --utc-end-ns I128\n\
  Query: half-open Unix-nanosecond interval [start,end), within 1970 through 9999.\n\
         NTP era is an explicit interpretation input; it is never inferred.\n\
  Work bounds: [--max-query-windows N] [--max-query-samples N]\n\
               [--max-query-packets N] [--max-query-source-bytes N]\n\
               [--max-query-results N] [--max-query-read-bytes N]\n\
               [--max-query-io-calls N]\n\
  Defaults: 64 windows, 16384 samples, 262144 packets, 268435456 reserved source\n\
            bytes and 4096 returned sample/lookahead rows. Output is at most 8 MiB.\n\
  Read bounds: 1 GiB aggregate reads and 1000000 filesystem calls by default,\n\
               including metadata, envelopes and final revalidation.\n\
  Storage: [--timeout-ms N] [--max-scan-roots N] [--max-objects N]\n\
           [--max-object-bytes N] [--max-total-bytes N]\n\
  Each window reserves 32 MiB before native source verification; the default source\n\
  allowance admits eight windows. Raise an explicit bound only after reviewing it.\n\
  Reconstructs ONVIF 0xABAC time from original AVC/HEVC packets. Missing, conflicting\n\
  or unusable timestamps stay explicit. CSeq correlation checks only its low byte.\n\
  Recorder-reported time is not calibrated capture time. No coverage or absence claim.\n\
  Read-only exact-slot verification works while the archive writer is open.\n\
  No writer lock, archive scan, recovery, repair or directory creation occurs.\n\
  No network, source payload output, publication, deletion or guessed pins.\n";

pub(super) const OPTIONS: [&str; 10] = [
    "--ntp-era",
    "--utc-start-ns",
    "--utc-end-ns",
    "--max-query-windows",
    "--max-query-samples",
    "--max-query-packets",
    "--max-query-source-bytes",
    "--max-query-results",
    "--max-query-read-bytes",
    "--max-query-io-calls",
];

pub(super) struct QueryOptions {
    ntp_era: u32,
    start_ns: i128,
    end_ns: i128,
    limits: ReplayTimeLimits,
    read_bytes: u64,
    io_calls: u64,
}

impl QueryOptions {
    pub(super) fn parse(values: &BTreeMap<&str, &OsStr>) -> Result<Self> {
        let text = |key: &str| -> Result<&str> {
            values
                .get(key)
                .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "required time option missing"))?
                .to_str()
                .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "time option must be UTF-8"))
        };
        let unsigned = |key: &str, default: Option<u64>| -> Result<u64> {
            if !values.contains_key(key) {
                return default.ok_or_else(|| {
                    argument(ERR_CLI_MISSING_VALUE, "required time option missing")
                });
            }
            let raw = text(key)?;
            if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(malformed("expected unsigned decimal time bound"));
            }
            raw.parse()
                .map_err(|_| malformed("time bound integer overflow"))
        };
        let signed = |key: &str| -> Result<i128> {
            let raw = text(key)?;
            let digits = raw.strip_prefix('-').unwrap_or(raw);
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(malformed("expected signed decimal Unix nanoseconds"));
            }
            raw.parse()
                .map_err(|_| malformed("Unix nanoseconds integer overflow"))
        };
        let size = |key: &str, default: usize| -> Result<usize> {
            usize::try_from(unsigned(key, Some(default as u64))?)
                .map_err(|_| malformed("query work bound integer overflow"))
        };
        let defaults = ReplayTimeLimits::default();
        let limits = ReplayTimeLimits {
            max_windows: size("--max-query-windows", defaults.max_windows)?,
            max_samples: size("--max-query-samples", defaults.max_samples)?,
            max_packets: size("--max-query-packets", defaults.max_packets)?,
            max_source_bytes: unsigned(
                "--max-query-source-bytes",
                Some(defaults.max_source_bytes),
            )?,
            max_results: size("--max-query-results", defaults.max_results)?,
        };
        limits
            .validate()
            .map_err(|_| malformed("query work bound outside supported limits"))?;
        let ntp_era = u32::try_from(unsigned("--ntp-era", None)?)
            .map_err(|_| malformed("NTP era must fit an unsigned 32-bit integer"))?;
        let start_ns = signed("--utc-start-ns")?;
        let end_ns = signed("--utc-end-ns")?;
        if start_ns < 0 || start_ns >= end_ns || end_ns > REPLAY_TIME_END_EXCLUSIVE_NS {
            return Err(malformed(
                "query UTC interval must be nonempty within 1970-9999",
            ));
        }
        let read_bytes = unsigned("--max-query-read-bytes", Some(1024 * 1024 * 1024))?;
        let io_calls = unsigned("--max-query-io-calls", Some(1_000_000))?;
        if !(1..=4 * 1024 * 1024 * 1024).contains(&read_bytes)
            || !(1..=4_000_000).contains(&io_calls)
        {
            return Err(malformed("query read allowance outside supported limits"));
        }
        Ok(Self {
            ntp_era,
            start_ns,
            end_ns,
            limits,
            read_bytes,
            io_calls,
        })
    }

    // Each owner receives a fixed part of the request allowance; unused metadata
    // capacity never refills original reads or vice versa. The inherited storage
    // caps apply to explicitly selected objects rather than a whole-spool scan.
    fn read_limits(&self, options: &Options) -> ReplayTimeReadLimits {
        let mut limits = ReplayTimeReadLimits::default();
        let bytes = self.read_bytes.min(options.storage.spool.max_total_bytes);
        let metadata_bytes = (bytes / 2).min(limits.metadata.max_read_bytes);
        limits.metadata.max_read_bytes = metadata_bytes;
        limits.originals.max_read_bytes = bytes - metadata_bytes;
        let metadata_calls = (self.io_calls / 2).min(limits.metadata.max_io_calls);
        limits.metadata.max_io_calls = metadata_calls;
        limits.originals.max_io_calls = self.io_calls - metadata_calls;
        let objects = options.storage.spool.max_objects;
        let metadata_objects = objects.div_ceil(3).min(limits.metadata.max_objects);
        limits.metadata.max_objects = metadata_objects;
        limits.originals.max_objects =
            (objects - metadata_objects).min(limits.originals.max_objects);
        limits.metadata.max_catalogue_entries = limits
            .metadata
            .max_catalogue_entries
            .min(options.storage.max_roots);
        limits.originals.max_catalogue_entries = limits
            .originals
            .max_catalogue_entries
            .min(options.storage.max_roots.saturating_sub(1));
        limits.metadata.max_object_bytes = limits
            .metadata
            .max_object_bytes
            .min(options.storage.spool.max_object_bytes);
        limits.originals.max_object_bytes = limits
            .originals
            .max_object_bytes
            .min(options.storage.spool.max_object_bytes);
        limits
    }
}

pub(super) fn run(
    root: &Path,
    options: &Options,
    time: &QueryOptions,
    clock: &Clock,
) -> Result<String> {
    let query = ReplayTimeQuery {
        codec: options.codec,
        scope: options.scope.clone(),
        receipt_root: options.receipt,
        request: options.request,
        ntp_era: time.ntp_era,
        start_ns: time.start_ns,
        end_ns: time.end_ns,
        limits: time.limits,
    };
    let result = query_replay_time_read_only(
        &HostSpoolIo,
        root,
        &query,
        time.read_limits(options),
        &|| clock.check().is_err(),
    )
    .map_err(|error| Error {
        code: error.code(),
        message: "recorder-time query or pinned original source verification refused",
        usage: false,
    })?;
    fss_cli::replay_time_json::render_replay_time_report(&result.report, || {
        clock
            .check()
            .map_err(|error| fss_cli::replay_time_json::ReplayTimeRenderError {
                code: error.code,
                message: error.message,
            })
    })
    .map_err(|error| Error {
        code: error.code,
        message: error.message,
        usage: false,
    })
}
