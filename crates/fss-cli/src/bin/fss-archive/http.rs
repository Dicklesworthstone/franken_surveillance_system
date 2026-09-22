#![forbid(unsafe_code)]
//! Local operator adapter over the reference native recording checker, not fss/1.
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use fss_cli::{ExitIdentity, ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE,
    ERR_CLI_MALFORMED_VALUE, ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_object::{SpoolLimits, MAX_MANIFEST_CHILDREN};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, PublishCancellation, PublishCutPoint};
use fss_reference::ingest::http_replay::check::*;

pub(super) const HELP: &str = "fss-archive check-http [options]\n\
  Required: --root EXISTING_DIR --source sha256:HEX --generation N\n\
            --receive-clock sha256:HEX --retention-evidence sha256:HEX\n\
            --head sha256:HEX --reads N --bytes N --read-originals yes\n\
            --decode none|grayscale|ycbcr\n\
  Optional: --completion-root sha256:HEX (exact independently retained terminal root)\n\
  Bounds: --timeout-ms --max-reads --max-source-bytes --max-frames --max-steps\n\
          --read-bytes --max-object-bytes --max-roots --max-scan-roots --max-objects\n\
          --max-total-bytes --max-source-work --max-framing-work --max-decode-work\n\
          --max-frame-bytes --max-dimension --max-pixels --max-report-bytes\n\
  Bounds take unsigned decimal values. Checks ALL selected frames, not a sample.\n\
  No network, repair, new evidence root, raw-media export or inferred capture time.\n\
  Existing publisher locks/recovery sync apply; this is not forensic read-only open.\n\
  A partial prefix emits a typed report with nonzero exit, never a clean-EOF claim.\n";

pub(super) fn handles(args: &[OsString]) -> bool {
    args.first().is_some_and(|s| s.as_os_str() == OsStr::new("check-http"))
}
#[derive(Debug)]
struct Error { code: &'static str, message: &'static str, usage: bool }
type Result<T> = std::result::Result<T, Error>;
fn argument(code: &'static str, message: &'static str) -> Error { Error { code, message, usage: true } }
fn malformed(message: &'static str) -> Error { argument(ERR_CLI_MALFORMED_VALUE, message) }
fn runtime(message: &'static str) -> Error { Error { code: ERR_CLI_RUNTIME_FAILURE, message, usage: false } }
struct Options {
    root: PathBuf, request: HttpCheckRequest, limits: HttpCheckLimits,
    storage: LocalPublicationLimits, timeout: Duration, report_bytes: usize,
}
fn parse(args: &[OsString]) -> Result<Options> {
    if !handles(args) || args.len() > 65 || args.iter().any(|s| s.as_encoded_bytes().len() > 4096) {
        return Err(malformed("invalid command or argument bounds"));
    }
    let allowed = ["--root", "--source", "--generation", "--receive-clock", "--retention-evidence",
        "--head", "--reads", "--bytes", "--read-originals", "--decode", "--completion-root", "--timeout-ms",
        "--max-reads", "--max-source-bytes", "--max-frames", "--max-steps", "--read-bytes",
        "--max-object-bytes", "--max-roots", "--max-scan-roots", "--max-objects", "--max-total-bytes",
        "--max-source-work", "--max-framing-work", "--max-decode-work", "--max-frame-bytes",
        "--max-dimension", "--max-pixels", "--max-report-bytes"];
    let mut values: BTreeMap<&str, &OsStr> = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "option name must be UTF-8"))?;
        if !allowed.contains(&key) { return Err(argument(ERR_CLI_UNKNOWN_OPTION, "unknown option")); }
        if values.contains_key(key) { return Err(argument(ERR_CLI_DUPLICATE_OPTION, "duplicate option")); }
        let value = pair.get(1).filter(|s| !s.is_empty() && !s.to_str().is_some_and(|s| s.starts_with("--")))
            .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "missing option value"))?;
        values.insert(key, value.as_os_str());
    }
    let required = |key: &str| values.get(key).copied()
        .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "required option missing"));
    let text = |key: &str| required(key)?.to_str()
        .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "identity must be UTF-8"));
    let number = |key: &str, default: u64, min: u64, max: u64| -> Result<u64> {
        let n = if values.contains_key(key) {
            let raw = text(key)?;
            if !raw.bytes().all(|b| b.is_ascii_digit()) { return Err(malformed("expected unsigned decimal integer")); }
            raw.parse::<u64>().map_err(|_| malformed("integer overflow"))?
        } else { default };
        if !(min..=max).contains(&n) { return Err(malformed("numeric bound exceeded")); }
        Ok(n)
    };
    let digest = |key: &str| -> Result<ContentDigest> {
        let d = ContentDigest::parse(text(key)?).map_err(|_| malformed("invalid digest"))?;
        if d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32] { return Err(malformed("nonzero SHA-256 required")); }
        Ok(d)
    };
    if text("--read-originals")? != "yes" { return Err(malformed("explicit original-media read acknowledgement is required")); }
    for key in ["--generation", "--reads", "--bytes"] { let _ = required(key)?; }
    let decode = match text("--decode")? {
        "none" => HttpCheckDecode::None, "grayscale" => HttpCheckDecode::Grayscale, "ycbcr" => HttpCheckDecode::YCbCr,
        _ => return Err(malformed("select none, grayscale or ycbcr explicitly")),
    };
    let request = HttpCheckRequest { source: HttpCheckSource { source: digest("--source")?,
            generation: number("--generation", 0, 1, u64::MAX)?, receive_clock: digest("--receive-clock")?,
            retention_evidence: digest("--retention-evidence")? },
        head: digest("--head")?, reads: number("--reads", 0, 0, 4096)?, bytes: number("--bytes", 0, 0, 256 * 1024 * 1024)?,
        completion: values.contains_key("--completion-root").then(|| digest("--completion-root")).transpose()?, decode };
    request.pin().map_err(|_| malformed("invalid original source selection"))?;
    let defaults = HttpCheckLimits::default();
    let roots = number("--max-roots", 16384, 1, 65536)? as usize;
    let scan = number("--max-scan-roots", 65536, roots as u64, 65536)? as usize;
    let objects = number("--max-objects", 65536, 1, 131072)? as usize;
    let object_bytes = number("--max-object-bytes", defaults.maximum_spool_object_bytes as u64, 1024, 16 * 1024 * 1024)? as usize;
    let limits = HttpCheckLimits { maximum_reads: number("--max-reads", defaults.maximum_reads as u64, 1, 4096)? as usize,
        maximum_source_bytes: number("--max-source-bytes", defaults.maximum_source_bytes, 1, 256 * 1024 * 1024)?,
        maximum_scan_roots: scan, maximum_spool_object_bytes: object_bytes,
        maximum_frames: number("--max-frames", defaults.maximum_frames as u64, 1, 4096)? as usize,
        maximum_steps: number("--max-steps", defaults.maximum_steps, 1, 1_000_000)?,
        read_bytes: number("--read-bytes", defaults.read_bytes as u64, 1, 65536)? as usize,
        maximum_frame_bytes: number("--max-frame-bytes", defaults.maximum_frame_bytes as u64, 4, 16 * 1024 * 1024)? as usize,
        maximum_dimension: number("--max-dimension", defaults.maximum_dimension as u64, 1, 4096)? as u32,
        maximum_pixels: number("--max-pixels", defaults.maximum_pixels as u64, 1, 4_194_304)? as usize,
        source_work: number("--max-source-work", defaults.source_work, 0, 1_000_000_000_000_000)?,
        framing_work: number("--max-framing-work", defaults.framing_work, 0, 1_000_000_000_000_000)?,
        decode_work: number("--max-decode-work", defaults.decode_work, 0, 1_000_000_000_000_000)? };
    limits.validate().map_err(|_| malformed("inconsistent check bounds"))?;
    let storage = LocalPublicationLimits::new(roots, MAX_MANIFEST_CHILDREN, roots, scan,
        SpoolLimits::new(objects, number("--max-total-bytes", 1024 * 1024 * 1024, 1, 1024 * 1024 * 1024 * 1024)?, object_bytes, objects));
    storage.validate().map_err(|_| malformed("inconsistent storage bounds"))?;
    Ok(Options { root: PathBuf::from(required("--root")?), request, limits, storage,
        timeout: Duration::from_millis(number("--timeout-ms", 30000, 1, 3600000)?),
        report_bytes: number("--max-report-bytes", 4 * 1024 * 1024, 1024, 16 * 1024 * 1024)? as usize })
}
struct Clock { start: Instant, timeout: Duration }
impl PublishCancellation for Clock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool { self.start.elapsed() >= self.timeout }
}
fn existing(path: &Path) -> Result<PathBuf> {
    let directory = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    let file = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file());
    if !directory(path) { return Err(runtime("expected an existing non-symlink archive")); }
    let root = std::fs::canonicalize(path).map_err(|_| runtime("archive path resolution failed"))?;
    for name in ["roots", "tombstones", "spool", "spool/objects", "spool/staging", "spool/verified"] {
        if !directory(&root.join(name)) { return Err(runtime("existing archive layout is required")); }
    }
    for name in ["LOCK", "spool/LOCK"] {
        if !file(&root.join(name)) { return Err(runtime("existing archive lock layout is required")); }
    }
    Ok(root)
}
struct Json { text: String, maximum: usize }
impl std::fmt::Write for Json {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        if self.text.len().checked_add(s.len()).is_none_or(|n| n > self.maximum) { return Err(std::fmt::Error); }
        self.text.push_str(s); Ok(())
    }
}
fn render(r: &HttpCheckReport, maximum: usize) -> Result<String> {
    let mut out = Json { text: String::new(), maximum };
    out.text.try_reserve_exact(maximum).map_err(|_| runtime("report allocation refused"))?;
    let encode = |out: &mut Json| -> std::fmt::Result {
        let status = match r.status { HttpCheckStatus::Complete => "complete", HttpCheckStatus::PrefixExhausted => "prefix_exhausted", HttpCheckStatus::Refused => "refused" };
        let decode = match r.decode { HttpCheckDecode::None => "none", HttpCheckDecode::Grayscale => "grayscale", HttpCheckDecode::YCbCr => "ycbcr" };
        write!(out, "{{\"schema\":\"fss.local_http_check.v1\",\"command\":\"check-http\",\"status\":\"{status}\",\"source_scope\":\"{}\",\"source_head\":\"{}\",\"source_reads\":{},\"source_bytes\":{},\"completion_root\":",
            r.pin.scope, r.pin.head, r.pin.reads, r.pin.bytes)?;
        match r.completion_root { Some(d) => write!(out, "\"{d}\"")?, None => write!(out, "null")? }
        write!(out, ",\"decode\":\"{decode}\",\"decoder\":")?;
        match r.decoder { Some(d) => write!(out, "\"{d}\"")?, None => write!(out, "null")? }
        write!(out, ",\"termination\":")?;
        match r.termination_name() { Some(t) => write!(out, "\"{t}\"")?, None => write!(out, "null")? }
        write!(out, ",\"error\":")?;
        // All variants contain only typed numeric/enum fields, never source text.
        match r.error { Some(e) => write!(out, "\"{e:?}\"")?, None => write!(out, "null")? }
        write!(out, ",\"checked_frames\":{},\"frame_chain\":\"{}\",\"loaded_bytes\":{},\"parsed_bytes\":{},\"parsed_frames\":{},\"transferred_frames\":{},\"steps\":{},\"source_work\":{},\"framing_work\":{},\"decode_work\":{},\"source_bytes_emitted\":false,\"new_roots_published\":false,\"physical_coverage_claimed\":false,\"frames\":[",
            r.frames.len(), r.frame_chain, r.position.loaded_bytes, r.position.parsed_bytes, r.position.frames,
            r.position.transferred_frames, r.steps, r.source_work, r.framing_work, r.decode_work)?;
        for (i, frame) in r.frames.iter().enumerate() {
            if i != 0 { write!(out, ",")?; }
            write!(out, "{{\"ordinal\":{},\"encoded\":\"{}\",\"exposure\":\"{}\",\"bytes\":{},\"source_runs\":{},\"dimensions\":",
                frame.ordinal, frame.encoded, frame.exposure, frame.bytes, frame.source_runs)?;
            match frame.dimensions { Some([w, h]) => write!(out, "[{w},{h}]")?, None => write!(out, "null")? }
            write!(out, ",\"luma\":")?;
            match frame.luma { Some(d) => write!(out, "\"{d}\"")?, None => write!(out, "null")? }
            write!(out, "}}")?;
        }
        write!(out, "]}}\n")
    };
    encode(&mut out).map_err(|_| runtime("complete report exceeds selected output bound; no report emitted"))?;
    Ok(out.text)
}
fn run(o: Options) -> Result<(String, bool)> {
    let clock = Clock { start: Instant::now(), timeout: o.timeout };
    let root = existing(&o.root)?;
    if clock.cancel_requested(PublishCutPoint::AfterChildrenVerified) { return Err(runtime("operation deadline expired")); }
    let publisher = LocalRootPublisher::open(root, o.storage).map_err(|_| runtime("archive open or exclusive ownership refused"))?;
    let report = check_http_recording(&publisher, o.request, o.limits, &clock)
        .map_err(|_| runtime("original source or completion verification refused before frame checking"))?;
    let success = report.status == HttpCheckStatus::Complete;
    Ok((render(&report, o.report_bytes)?, success))
}
pub(super) fn dispatch(args: &[OsString]) -> ExitCode {
    match parse(args).and_then(run) {
        Ok((report, complete)) => {
            if super::emit(&mut std::io::stdout().lock(), report.as_bytes()).is_err() {
                return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
            }
            ExitCode::from(if complete { ExitIdentity::SUCCESS.code } else { ExitIdentity::RUNTIME_FAILURE.code })
        }
        Err(e) => {
            eprintln!("{}: {}. No raw media was emitted, new evidence roots published, or camera contacted. Use fss-archive help.", e.code, e.message);
            ExitCode::from(if e.usage { ExitIdentity::MALFORMED_VALUE.code } else { ExitIdentity::RUNTIME_FAILURE.code })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<OsString> {
        let d = fss_core::ContentDigest::sha256(b"fixture").to_string();
        ["check-http", "--root", "not-opened", "--source", &d, "--generation", "1", "--receive-clock", &d,
            "--retention-evidence", &d, "--head", &d, "--reads", "1", "--bytes", "100",
            "--read-originals", "yes", "--decode", "none"].into_iter().map(OsString::from).collect()
    }
    #[test]
    fn parses_exact_source_without_accessing_the_path() {
        let o = parse(&args()).expect("pure parse"); assert_eq!(o.request.reads, 1); assert_eq!(o.request.bytes, 100);
        assert_eq!(o.request.decode, HttpCheckDecode::None); assert!(o.request.completion.is_none());
    }
    #[test]
    fn original_access_and_component_interpretation_are_explicit() {
        for key in ["--read-originals", "--decode"] {
            let mut a = args(); let i = a.iter().position(|v| v.as_os_str() == OsStr::new(key)).expect("flag");
            a.remove(i); a.remove(i); assert!(parse(&a).is_err());
        }
        for (key, value) in [("--read-originals", "no"), ("--decode", "auto"), ("--generation", "0"), ("--bytes", "-1")] {
            let mut a = args(); let i = a.iter().position(|v| v.as_os_str() == OsStr::new(key)).expect("flag");
            a[i + 1] = value.into(); assert!(parse(&a).is_err());
        }
    }
    #[test]
    fn duplicate_unknown_overflow_and_out_of_range_options_are_refused() {
        for pair in [["--head", "secret-not-echoed"], ["--unexpected", "secret-not-echoed"],
            ["--max-frames", "4097"], ["--max-steps", "18446744073709551616"], ["--read-bytes", "0"]] {
            let mut a = args(); a.extend(pair.map(OsString::from)); assert!(parse(&a).is_err());
        }
    }
}
