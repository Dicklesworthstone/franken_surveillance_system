#![forbid(unsafe_code)]
//! Local recipe operation adapter. Native replay/publication semantics live in fss-reference.
use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION, ExitIdentity,
};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, PublishCancellation, PublishCutPoint,
    PublishOutcome,
};
use fss_reference::rtsp::datagram_archive::{DatagramArchiveLimits, DatagramScope};
use fss_reference::rtsp::datagram_reconstruction::AvcReplayBounds;
use fss_reference::rtsp::recording_recipe::storage::RecipeStorageLimits;
use fss_reference::rtsp::recording_recipe::storage::operation::*;
use fss_reference::rtsp::recording_recipe::{
    MAX_RECORDING_RECIPE_BYTES, MAX_RECORDING_RECIPE_TIMINGS, RecordingRecipeLimits,
};
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

pub(super) const HELP: &str = "fss-archive <check-recipe|reconstruct-recipe> [options]\n\
  Required: --root EXISTING_DIR --recipe-id sha256:HEX --recipe-root sha256:HEX\n\
            --ingress U128 --generation N --ssrc N --peer IP:PORT --authority HOST[:PORT]\n\
            --rtp-channel N --rtcp-channel N --receive-clock sha256:HEX\n\
            --retention-evidence sha256:HEX\n\
  reconstruct-recipe additionally requires: --commit yes\n\
  Bounds: --timeout-ms --max-steps --max-work --max-datagrams --max-source-bytes\n\
          --max-recipe-bytes --max-timings --max-windows --max-output-bytes\n\
          --max-roots --max-scan-roots --max-objects --max-object-bytes --max-total-bytes\n\
  Each bound takes one unsigned decimal value. Source fields describe the original\n\
  approved plaintext capture, NOT permission to contact a camera. No network occurs.\n\
  Source bounds cover the full current chain, including verified later observations.\n\
  Replay uses only the exact historical recipe prefix; no stored source is truncated.\n\
  check-recipe executes native reconstruction but publishes no output roots.\n\
  reconstruct-recipe validates the whole program, publishes exact windows, then its\n\
  derived completion root last. Capture completeness and archive indexing are NOT claimed.\n\
  Existing locks/recovery sync apply; neither command is a forensic read-only open.\n";

pub(super) fn handles(args: &[OsString]) -> bool {
    args.first()
        .and_then(|s| s.to_str())
        .is_some_and(|s| matches!(s, "check-recipe" | "reconstruct-recipe"))
}
struct Error {
    code: &'static str,
    message: &'static str,
    usage: bool,
}
type Result<T> = std::result::Result<T, Error>;
fn argument(code: &'static str, message: &'static str) -> Error {
    Error {
        code,
        message,
        usage: true,
    }
}
fn malformed(message: &'static str) -> Error {
    argument(ERR_CLI_MALFORMED_VALUE, message)
}
fn runtime(message: &'static str) -> Error {
    Error {
        code: ERR_CLI_RUNTIME_FAILURE,
        message,
        usage: false,
    }
}
struct Options {
    root: PathBuf,
    selected: RecipeSelection,
    load: RecipeLoadLimits,
    output: ReconstructionLimits,
    storage: LocalPublicationLimits,
    timeout: Duration,
    steps: u64,
    work: u64,
    publish: bool,
}
fn parse(args: &[OsString]) -> Result<Options> {
    if args.len() > 65 || args.iter().any(|s| s.as_encoded_bytes().len() > 4096) {
        return Err(malformed("argument count or size bound exceeded"));
    }
    if !handles(args) {
        return Err(malformed("expected a recipe operation"));
    }
    let publish = args[0].as_os_str() == OsStr::new("reconstruct-recipe");
    let allowed = [
        "--root",
        "--recipe-id",
        "--recipe-root",
        "--ingress",
        "--generation",
        "--ssrc",
        "--peer",
        "--authority",
        "--rtp-channel",
        "--rtcp-channel",
        "--receive-clock",
        "--retention-evidence",
        "--timeout-ms",
        "--max-steps",
        "--max-work",
        "--max-datagrams",
        "--max-source-bytes",
        "--max-recipe-bytes",
        "--max-timings",
        "--max-windows",
        "--max-output-bytes",
        "--max-roots",
        "--max-scan-roots",
        "--max-objects",
        "--max-object-bytes",
        "--max-total-bytes",
    ];
    let mut values: BTreeMap<&str, &OsStr> = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0]
            .to_str()
            .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "option name must be UTF-8"))?;
        if !allowed.contains(&key) && !(publish && key == "--commit") {
            return Err(argument(
                ERR_CLI_UNKNOWN_OPTION,
                "unknown or inapplicable option",
            ));
        }
        if values.contains_key(key) {
            return Err(argument(ERR_CLI_DUPLICATE_OPTION, "duplicate option"));
        }
        let value = pair
            .get(1)
            .filter(|v| !v.is_empty() && !v.to_str().is_some_and(|s| s.starts_with("--")))
            .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "missing option value"))?;
        values.insert(key, value.as_os_str());
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "required option missing"))
    };
    let text = |key: &str| {
        required(key)?
            .to_str()
            .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "identity must be UTF-8"))
    };
    let number = |key: &str, default: u64, minimum: u64, maximum: u64| -> Result<u64> {
        let n = if values.contains_key(key) {
            let raw = text(key)?;
            if !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(malformed("expected unsigned decimal integer"));
            }
            raw.parse::<u64>()
                .map_err(|_| malformed("integer overflow"))?
        } else {
            default
        };
        if !(minimum..=maximum).contains(&n) {
            return Err(malformed("numeric bound exceeded"));
        }
        Ok(n)
    };
    let digest = |key: &str| -> Result<ContentDigest> {
        let d = ContentDigest::parse(text(key)?).map_err(|_| malformed("invalid digest"))?;
        if d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32] {
            return Err(malformed("nonzero SHA-256 required"));
        }
        Ok(d)
    };
    if publish && text("--commit")? != "yes" {
        return Err(malformed(
            "publication requires explicit commit acknowledgement",
        ));
    }
    for name in ["--generation", "--ssrc", "--rtp-channel", "--rtcp-channel"] {
        let _ = required(name)?;
    }
    let ingress = text("--ingress")?;
    if !ingress.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed("invalid source ingress"));
    }
    let key = StreamKey {
        ingress: ingress
            .parse::<u128>()
            .map_err(|_| malformed("invalid source ingress"))?,
        generation: number("--generation", 0, 1, u64::MAX)?,
        ssrc: number("--ssrc", 0, 0, u32::MAX as u64)? as u32,
    };
    let peer = text("--peer")?
        .parse()
        .map_err(|_| malformed("expected a literal source IP and port"))?;
    let binding = TcpBinding::new(
        key,
        peer,
        text("--authority")?,
        TcpSecurityPolicy::OwnerApprovedPlaintext,
    )
    .map_err(|_| malformed("invalid original source binding"))?;
    let scope = DatagramScope {
        binding,
        channels: (
            number("--rtp-channel", 0, 0, 255)? as u8,
            number("--rtcp-channel", 1, 0, 255)? as u8,
        ),
        receive_clock: digest("--receive-clock")?,
        retention_evidence: digest("--retention-evidence")?,
    };
    scope
        .digest()
        .map_err(|_| malformed("invalid original source scope"))?;
    let object_bytes = number(
        "--max-object-bytes",
        32 * 1024 * 1024,
        1024,
        32 * 1024 * 1024,
    )? as usize;
    let roots = number("--max-roots", 16_384, 1, 65_536)? as usize;
    let scan = number("--max-scan-roots", 65_536, roots as u64, 262_144)? as usize;
    let objects = number("--max-objects", 65_536, 1, 131_072)? as usize;
    let storage = LocalPublicationLimits::new(
        roots,
        MAX_MANIFEST_CHILDREN,
        roots,
        scan,
        SpoolLimits::new(
            objects,
            number(
                "--max-total-bytes",
                1024 * 1024 * 1024,
                1,
                1024 * 1024 * 1024 * 1024,
            )?,
            object_bytes,
            objects,
        ),
    );
    storage
        .validate()
        .map_err(|_| malformed("inconsistent storage ceilings"))?;
    // Current namespace bounds include verified descendants outside the selected recipe.
    let datagrams = number("--max-datagrams", 8192, 1, 65_536)? as usize;
    let load = RecipeLoadLimits {
        source: DatagramArchiveLimits {
            max_datagrams: datagrams,
            max_payload_bytes: number(
                "--max-source-bytes",
                256 * 1024 * 1024,
                1,
                1024 * 1024 * 1024,
            )?,
            max_scan_roots: scan,
            max_spool_object_bytes: object_bytes,
        },
        recipe: RecordingRecipeLimits {
            max_bytes: number(
                "--max-recipe-bytes",
                MAX_RECORDING_RECIPE_BYTES as u64,
                1,
                MAX_RECORDING_RECIPE_BYTES as u64,
            )? as usize,
            max_timings: number(
                "--max-timings",
                MAX_RECORDING_RECIPE_TIMINGS as u64,
                0,
                MAX_RECORDING_RECIPE_TIMINGS as u64,
            )? as usize,
            ..RecordingRecipeLimits::default()
        },
        storage: RecipeStorageLimits {
            max_source_roots: datagrams.min(MAX_MANIFEST_CHILDREN - 1),
            max_spool_object_bytes: object_bytes,
        },
    };
    Ok(Options {
        root: PathBuf::from(required("--root")?),
        selected: RecipeSelection {
            recipe: digest("--recipe-id")?,
            root: digest("--recipe-root")?,
            scope,
        },
        load,
        output: ReconstructionLimits {
            max_windows: number("--max-windows", 64, 1, 1024)? as usize,
            max_output_bytes: number(
                "--max-output-bytes",
                64 * 1024 * 1024,
                1,
                1024 * 1024 * 1024,
            )?,
            max_scan_roots: scan,
        },
        storage,
        timeout: Duration::from_millis(number("--timeout-ms", 30_000, 1, 3_600_000)?),
        steps: number("--max-steps", 65_536, 1, 1_000_000)?,
        work: number("--max-work", 1_000_000_000_000, 1, 1_000_000_000_000_000)?,
        publish,
    })
}
struct Clock {
    start: Instant,
    deadline: u64,
}
impl ReconstructionClock for Clock {
    fn now_ns(&self) -> Option<u64> {
        u64::try_from(self.start.elapsed().as_nanos()).ok()
    }
}
impl PublishCancellation for Clock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.now_ns().is_none_or(|n| n >= self.deadline)
    }
}
fn existing(path: &Path) -> Result<PathBuf> {
    let directory = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    let file = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file());
    if !directory(path) {
        return Err(runtime("expected an existing non-symlink archive"));
    }
    let root =
        std::fs::canonicalize(path).map_err(|_| runtime("archive path resolution failed"))?;
    for name in [
        "roots",
        "tombstones",
        "spool",
        "spool/objects",
        "spool/staging",
        "spool/verified",
    ] {
        if !directory(&root.join(name)) {
            return Err(runtime("existing archive layout is required"));
        }
    }
    for name in ["LOCK", "spool/LOCK"] {
        if !file(&root.join(name)) {
            return Err(runtime("existing archive lock layout is required"));
        }
    }
    Ok(root)
}
fn run(options: Options) -> Result<String> {
    let clock = Clock {
        start: Instant::now(),
        deadline: u64::try_from(options.timeout.as_nanos())
            .map_err(|_| runtime("operation deadline overflow"))?,
    };
    let root = existing(&options.root)?;
    if clock.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
        return Err(runtime("operation deadline expired"));
    }
    let mut p = LocalRootPublisher::open(root, options.storage)
        .map_err(|_| runtime("archive open or exclusive ownership refused"))?;
    let mut work = WorkBudget::new(options.work);
    let loaded = LoadedRecordingRecipe::load(&p, options.selected, options.load, &clock, &mut work)
        .map_err(|_| runtime("selected recipe or original source verification failed"))?;
    let bounds = AvcReplayBounds {
        max_source_bytes: options.load.source.max_payload_bytes,
        max_steps: options.steps,
        deadline_ns: clock.deadline,
    };
    let plan = PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds,
        options.output,
        &clock,
        &clock,
        &mut work,
    )
    .map_err(|_| {
        runtime("complete native reconstruction refused; no output was published by preparation")
    })?;
    // Every printed field is fixed vocabulary, bounded integer or canonical digest/slot. Reserve
    // the whole output buffer BEFORE any possibly committing publication.
    let mut report = String::new();
    report
        .try_reserve_exact(8192)
        .map_err(|_| runtime("report capacity exhausted"))?;
    let (status, published, reused) = if options.publish {
        let outcome = plan.publish(&mut p, clock.deadline, &clock, &clock, &mut work)
            .map_err(|_| runtime("publication stopped; exact windows or completion root may already have committed"))?;
        let new = outcome
            .windows
            .iter()
            .filter(|r| r.outcome == PublishOutcome::Published)
            .count();
        (
            if outcome.completion.outcome == PublishOutcome::AlreadyPublished {
                "already_durable"
            } else {
                "published"
            },
            new,
            outcome.windows.len() - new,
        )
    } else {
        ("not_requested", 0, 0)
    };
    let s = plan.summary();
    let source = loaded.pin().source;
    let observed = loaded.observed_source_head();
    writeln!(&mut report,
        "{{\"schema\":\"fss.local_reconstruction_operator.v1\",\"command\":\"{}\",\"recipe\":\"{}\",\"recipe_root\":\"{}\",\"source_scope\":\"{}\",\"source_head\":\"{}\",\"source_datagrams\":{},\"source_bytes\":{},\"observed_source_head_at_load\":\"{}\",\"observed_source_datagrams_at_load\":{},\"interpretation\":\"{}\",\"result_slot\":\"{}\",\"result_root\":\"{}\",\"result_status\":\"{}\",\"publication_requested\":{},\"windows\":{},\"output_bytes\":{},\"new_windows\":{},\"reused_windows\":{},\"rtp_observations\":{},\"rtcp_observations\":{},\"invalid_rtcp\":{},\"timings_applied\":{},\"unselected_pictures\":{},\"unselected_packets\":{},\"unsealed_packets\":{},\"queued_packets\":{},\"fragment_bytes\":{},\"queued_nals\":{},\"incomplete_picture\":{},\"capture_complete\":false,\"archive_index_published\":false,\"source_bytes_emitted\":false,\"operation_complete\":true}}",
        if options.publish { "reconstruct-recipe" } else { "check-recipe" }, loaded.pin().recipe,
        loaded.pin().root, source.scope, source.head, source.datagrams, source.payload_bytes,
        observed.head, observed.datagrams,
        loaded.recipe().interpretation(), plan.pin().slot, plan.pin().root, status, options.publish,
        s.windows, s.output_bytes, published, reused, s.rtp_observations, s.rtcp_observations, s.invalid_rtcp,
        s.timings_applied, s.unselected_pictures, s.unselected_packets, s.unsealed_packets, s.queued_packets,
        s.fragment_bytes, s.queued_nals, s.incomplete_picture).map_err(|_| runtime("report formatting failed"))?;
    if report.len() > 8192 {
        return Err(runtime("report bound exceeded"));
    }
    Ok(report)
}
pub(super) fn dispatch(args: &[OsString]) -> ExitCode {
    let result = if args.len() == 2 && args[1].as_os_str() == OsStr::new("--help") {
        Ok(HELP.to_owned())
    } else {
        parse(args).and_then(run)
    };
    match result {
        Ok(report) => match super::emit(&mut std::io::stdout().lock(), report.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            eprintln!(
                "No complete report was emitted. Retain the original recipe pin and storage; reconcile uncertain roots before exact retry. No operator cleanup, source deletion, camera connection or archive indexing was requested."
            );
            ExitCode::from(if error.usage {
                ExitIdentity::MALFORMED_VALUE.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            })
        }
    }
}
