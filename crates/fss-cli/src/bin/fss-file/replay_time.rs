#![forbid(unsafe_code)]
//! Source-verified recorder UTC queries over completed retained imports.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{object, string};
use fss_cli::replay_time_json::{
    MAX_REPORT_BYTES, ReplayTimeRenderError, render_replay_time_report,
};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, OperationId, PrincipalId, SensorId, StreamId,
};
use fss_publication::{PublishCancellation, PublishCutPoint};
use fss_reference::ingest::rtsp_import::replay::query_retained_replay_time;
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::ReplayCodec;
use fss_reference::rtsp::recording_replay::time::{ReplayTimeLimits, ReplayTimeQuery};
use fss_reference::{ReferenceDeployment, ReplayCx};

pub(super) const MAX_ARGUMENTS: usize = 64;
const HELP: &str = "fss-file query-replay-utc [options]\n\
  Required: --root EXISTING_ABSOLUTE_DEPLOYMENT --site SITE --import-id sha256:HEX\n\
            --codec avc|hevc --sensor ID --stream ID --generation N\n\
            --anchor sha256:HEX --receive-clock sha256:HEX\n\
            --decode-clock sha256:HEX --time-scale N\n\
            --expected-replay-root sha256:HEX --expected-replay-request sha256:HEX\n\
            --ntp-era N --utc-start-ns I128 --utc-end-ns I128\n\
  Uses only the completed retained replay import, including every original packet.\n\
  No capture archive, recorder connection or temporary archive is needed.\n\
  UTC query is half-open [start,end), within 1970 through 9999. NTP era is explicit.\n\
  Native query, index, report and row digests match an equivalent source-archive query.\n\
  Missing, malformed or conflicting recorder assertions stay unknown, including source-only tails.\n\
  Recorder UTC is not calibrated capture time; no continuity, coverage or absence is certified.\n\
  Bounds: [--max-query-windows N] [--max-query-samples N] [--max-query-packets N]\n\
          [--max-query-source-bytes N] [--max-query-results N]\n\
  Query defaults: 64 windows, 16384 samples, 262144 packets, 268435456 source bytes,\n\
                  4096 output rows. Every original reserves 32 MiB before source verification.\n\
  Retained media: [--max-source-bytes N] (default/max 64 MiB)\n\
                  [--chunk-bytes N] [--max-segment-bytes N] (default 16 MiB, max 64 MiB)\n\
  [--principal ID] [--timeout-ms N] (default 30000, max 600000).\n\
  Whole proof and companion reads have separate fixed native ceilings. Output is at most 8 MiB.\n\
  Existing deployment open may recover journals and holds its exclusive lock. The query publishes\n\
  no new evidence, exports no original bytes, and cannot repair or resurrect deleted custody.\n\
  Deadline and cancellation are cooperative at native read and projection boundaries.\n";

#[derive(Debug)]
struct Error {
    code: &'static str,
    message: &'static str,
    usage: bool,
}
type Result<T> = std::result::Result<T, Error>;

fn malformed(message: &'static str) -> Error {
    Error {
        code: ERR_CLI_MALFORMED_VALUE,
        message,
        usage: true,
    }
}
fn runtime(message: &'static str) -> Error {
    Error {
        code: ERR_CLI_RUNTIME_FAILURE,
        message,
        usage: false,
    }
}
fn digest(value: &str) -> Result<ContentDigest> {
    let digest = ContentDigest::parse(value).map_err(|_| malformed("invalid source digest"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err(malformed("nonzero SHA-256 source digest required"));
    }
    Ok(digest)
}

struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    import_identity: ContentDigest,
    query: ReplayTimeQuery,
    retained_limits: RetainedReadLimits,
    timeout: Duration,
}

fn parse(args: &[OsString]) -> Result<Options> {
    if args.is_empty()
        || args.len() > MAX_ARGUMENTS
        || !args.len().is_multiple_of(2)
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(malformed("bounded option/value pairs required"));
    }
    let allowed = [
        "--root",
        "--site",
        "--principal",
        "--import-id",
        "--codec",
        "--sensor",
        "--stream",
        "--generation",
        "--anchor",
        "--receive-clock",
        "--decode-clock",
        "--time-scale",
        "--expected-replay-root",
        "--expected-replay-request",
        "--ntp-era",
        "--utc-start-ns",
        "--utc-end-ns",
        "--max-query-windows",
        "--max-query-samples",
        "--max-query-packets",
        "--max-query-source-bytes",
        "--max-query-results",
        "--max-source-bytes",
        "--chunk-bytes",
        "--max-segment-bytes",
        "--timeout-ms",
    ];
    let mut values = BTreeMap::new();
    for pair in args.as_chunks::<2>().0 {
        let key = pair[0]
            .to_str()
            .ok_or_else(|| malformed("UTF-8 option required"))?;
        let value = pair[1]
            .to_str()
            .ok_or_else(|| malformed("UTF-8 value required"))?;
        if !allowed.contains(&key)
            || value.is_empty()
            || value.starts_with("--")
            || values.insert(key, value).is_some()
        {
            return Err(malformed("unknown or duplicate option, or missing value"));
        }
    }
    let required = |key| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| malformed("required option missing"))
    };
    let unsigned = |key: &str, default: Option<u64>, minimum: u64, maximum: u64| -> Result<u64> {
        let value = match values.get(key) {
            None => default.ok_or_else(|| malformed("required numeric option missing"))?,
            Some(value) if value.bytes().all(|byte| byte.is_ascii_digit()) => value
                .parse()
                .map_err(|_| malformed("numeric option overflow"))?,
            Some(_) => return Err(malformed("unsigned decimal option required")),
        };
        if !(minimum..=maximum).contains(&value) {
            return Err(malformed("numeric option bound exceeded"));
        }
        Ok(value)
    };
    let timestamp = |key| -> Result<i128> {
        let value = required(key)?;
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(malformed("nonnegative Unix nanoseconds required"));
        }
        value
            .parse()
            .map_err(|_| malformed("Unix nanoseconds overflow"))
    };
    let defaults = ReplayTimeLimits::default();
    let query = ReplayTimeQuery {
        codec: match required("--codec")? {
            "avc" => ReplayCodec::Avc,
            "hevc" => ReplayCodec::Hevc,
            _ => return Err(malformed("explicit avc or hevc codec required")),
        },
        scope: CatalogScope {
            recording: RecordingScope {
                sensor: SensorId::parse(required("--sensor")?)
                    .map_err(|_| malformed("invalid sensor"))?,
                stream: StreamId::parse(required("--stream")?)
                    .map_err(|_| malformed("invalid stream"))?,
                generation: unsigned("--generation", None, 1, u64::MAX)?,
                anchor: digest(required("--anchor")?)?,
                receive_clock: digest(required("--receive-clock")?)?,
            },
            decode_clock: digest(required("--decode-clock")?)?,
            time_scale: unsigned("--time-scale", None, 1, u32::MAX as u64)? as u32,
        },
        receipt_root: digest(required("--expected-replay-root")?)?,
        request: digest(required("--expected-replay-request")?)?,
        ntp_era: unsigned("--ntp-era", None, 0, u32::MAX as u64)? as u32,
        start_ns: timestamp("--utc-start-ns")?,
        end_ns: timestamp("--utc-end-ns")?,
        limits: ReplayTimeLimits {
            max_windows: unsigned(
                "--max-query-windows",
                Some(defaults.max_windows as u64),
                1,
                64,
            )? as usize,
            max_samples: unsigned(
                "--max-query-samples",
                Some(defaults.max_samples as u64),
                1,
                16384,
            )? as usize,
            max_packets: unsigned(
                "--max-query-packets",
                Some(defaults.max_packets as u64),
                1,
                262144,
            )? as usize,
            max_source_bytes: unsigned(
                "--max-query-source-bytes",
                Some(defaults.max_source_bytes),
                1,
                2147483648,
            )?,
            max_results: unsigned(
                "--max-query-results",
                Some(defaults.max_results as u64),
                1,
                32768,
            )? as usize,
        },
    };
    query
        .validate()
        .map_err(|_| malformed("invalid query scope, UTC interval or work limits"))?;
    let root_text = required("--root")?;
    let root = PathBuf::from(root_text);
    if !root.is_absolute()
        || root.file_name().is_none()
        || root_text.split('/').any(|part| matches!(part, "." | ".."))
        || root_text.chars().any(char::is_control)
    {
        return Err(malformed(
            "non-root absolute deployment path without dot components required",
        ));
    }
    let site = required("--site")?.to_owned();
    if site.len() > 256 || site.chars().any(char::is_control) {
        return Err(malformed("invalid site lineage"));
    }
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| malformed("invalid site lineage"))?;
    let principal = values
        .get("--principal")
        .copied()
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| malformed("invalid principal"))?;
    if principal.len() > 256 {
        return Err(malformed("principal byte bound exceeded"));
    }
    Ok(Options {
        root,
        site,
        principal,
        import_identity: digest(required("--import-id")?)?,
        query,
        retained_limits: RetainedReadLimits {
            max_source_bytes: unsigned(
                "--max-source-bytes",
                Some(64 * 1024 * 1024),
                1,
                64 * 1024 * 1024,
            )?,
            max_chunk_bytes: unsigned(
                "--chunk-bytes",
                Some(16 * 1024 * 1024),
                1,
                64 * 1024 * 1024,
            )?,
            max_segment_bytes: unsigned(
                "--max-segment-bytes",
                Some(16 * 1024 * 1024),
                1,
                64 * 1024 * 1024,
            )?,
        },
        timeout: Duration::from_millis(unsigned("--timeout-ms", Some(30000), 1, 600000)?),
    })
}

struct Clock {
    start: Instant,
    timeout: Duration,
}
impl Clock {
    fn check(&self) -> Result<()> {
        if self.start.elapsed() >= self.timeout {
            return Err(Error {
                code: "ERR-REPLAY-TIME-CANCELLED-001",
                message: "retained recorder query deadline expired",
                usage: false,
            });
        }
        Ok(())
    }
}
impl PublishCancellation for Clock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.start.elapsed() >= self.timeout
    }
}

fn execute(options: &Options) -> Result<String> {
    options
        .query
        .validate()
        .map_err(|_| malformed("invalid native query"))?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-replay-time-query".into(),
        operation_id: OperationId::parse("operation:retained-replay-time-query")
            .map_err(|_| runtime("invalid query operation identity"))?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            // Native original envelope plus repeated bounded proof/companion authority reads.
            .bytes(options.query.limits.max_source_bytes + 128 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()
            .map_err(|_| runtime("query authority budget refused"))?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| runtime("query authority refused"))?;
    authority
        .validate()
        .map_err(|_| runtime("query authority validation refused"))?;
    let clock = Clock {
        start: Instant::now(),
        timeout: options.timeout,
    };
    // Refuse a missing/non-native store before ReplayCx can create destination directories.
    if !std::fs::symlink_metadata(&options.root).is_ok_and(|meta| meta.file_type().is_dir())
        || !std::fs::symlink_metadata(options.root.join("LAYOUT"))
            .is_ok_and(|meta| meta.file_type().is_file())
    {
        return Err(runtime("existing retained deployment required"));
    }
    clock.check()?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(|_| runtime("query context refused"))?;
    let result = (|| {
        clock.check()?;
        let deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)
            .map_err(|_| runtime("existing deployment open refused"))?;
        let result = query_retained_replay_time(
            &deployment,
            options.import_identity,
            &options.query,
            options.retained_limits,
            &cx,
            &clock,
        )
        .map_err(|error| Error {
            code: error.code(),
            message: "retained recorder UTC query or current source custody refused",
            usage: false,
        })?;
        let retained = RetainedFileImport::open(
            &deployment,
            options.import_identity,
            options.retained_limits,
            &cx,
        )
        .map_err(|_| runtime("retained source authority changed"))?;
        let report = render_replay_time_report(&result, || {
            clock.check().map_err(|error| ReplayTimeRenderError {
                code: error.code,
                message: error.message,
            })?;
            cx.checkpoint("file_cli:retained_replay_time_report")
                .map_err(|_| ReplayTimeRenderError {
                    code: "ERR-REPLAY-TIME-CANCELLED-001",
                    message: "query report owner cancelled",
                })
        })
        .map_err(|error| Error {
            code: error.code,
            message: error.message,
            usage: false,
        })?;
        let final_retained = RetainedFileImport::open(
            &deployment,
            options.import_identity,
            options.retained_limits,
            &cx,
        )
        .map_err(|_| runtime("retained source authority changed before report"))?;
        if final_retained != retained {
            return Err(runtime("retained source authority changed before report"));
        }
        let report = object(&[
            (
                "schema",
                string("fss.retained_replay_time_operator_report.v1"),
            ),
            ("command", string("query-replay-utc")),
            (
                "import_identity",
                string(&options.import_identity.to_text()),
            ),
            ("import_root", string(&retained.import_root().to_text())),
            ("source_archive_required", "false".into()),
            ("network", string("none")),
            ("report", report),
        ]);
        if report.len() > MAX_REPORT_BYTES {
            return Err(runtime("complete retained query report exceeds 8 MiB"));
        }
        clock.check()?;
        Ok(report)
    })();
    cx.drain_and_finalize();
    result
}

fn emit(text: &str) -> io::Result<()> {
    if text.len() > MAX_REPORT_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut out = io::stdout().lock();
    for mut bytes in [text.as_bytes(), b"\n".as_slice()] {
        let mut interruptions = 0;
        while !bytes.is_empty() {
            match out.write(&bytes[..bytes.len().min(4096)]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) if written <= bytes.len().min(4096) => {
                    bytes = &bytes[written..];
                    interruptions = 0;
                }
                Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interruptions < 7 => {
                    interruptions += 1
                }
                Err(error) => return Err(error),
            }
        }
    }
    out.flush()
}

pub(super) fn dispatch(args: &[OsString]) -> ExitCode {
    let result = if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        Ok(HELP.to_owned())
    } else {
        parse(args).and_then(|options| execute(&options))
    };
    match result {
        Ok(report) => ExitCode::from(if emit(&report).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        }),
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            ExitCode::from(if error.usage {
                ExitIdentity::MALFORMED_VALUE.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            })
        }
    }
}

#[cfg(test)]
#[path = "replay_time/tests.rs"]
mod tests;
