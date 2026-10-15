#![forbid(unsafe_code)]
//! Read-only, loopback-only operator visualization of retained deployment metadata.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[path = "fss-dashboard/server.rs"]
mod server;
#[path = "fss-dashboard/snapshot.rs"]
mod snapshot;

const HELP: &str = "FSS Observatory — local, read-only evidence dashboard\n\n\
  fss-dashboard --root /absolute/deployment --site SITE --allow-local-metadata yes\n\
  fss-dashboard --demo\n\n\
  Optional: --port 7474 (0 selects a free port); --serve-seconds 28800 (1..86400).\n\
  --snapshot prints the same bounded metadata projection without opening a socket.\n\n\
  Open the printed http://127.0.0.1:PORT address. No installation, CDN or cloud account.\n\
  The selected site is checked against retained LAYOUT. This view discloses local event\n\
  metadata without a privacy transform to browsers and other processes on this machine.\n\
  It is not an evidence export, a live camera viewer, an agent envelope or effect authority.\n\
  No source media, credentials, camera connections, repairs or deployment writes.\n\
  Never reverse-proxy or forward this listener. Ctrl-C stops it; its finite lease also expires.\n\
  Demo is explicitly synthetic and never reads a deployment. Real reads never fall back to demo.\n\
  Read bounds: 256 events, 64 revisions/event, 16 MiB/journal, 2 MiB/object, 4 MiB/report.\n\
  An oversized or damaged deployment refuses, rather than truncating important facts.\n\
  The 5-second read deadline is cooperative around the bounded native snapshot reader.\n";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Options {
    root: Option<PathBuf>,
    site: Option<String>,
    demo: bool,
    snapshot: bool,
    port: u16,
    seconds: u64,
}

impl Options {
    fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > 14 || args.iter().any(|s| s.as_encoded_bytes().len() > 4096) {
            return Err("argument bound exceeded");
        }
        let mut result = Self { root: None, site: None, demo: false, snapshot: false, port: 7474, seconds: 28_800 };
        let mut seen = BTreeSet::new();
        let mut authorized = false;
        let mut i = 0;
        while i < args.len() {
            let key = args[i].to_str().ok_or("option is not UTF-8")?;
            if !seen.insert(key) { return Err("duplicate option"); }
            i += 1;
            match key {
                "--demo" => result.demo = true,
                "--snapshot" => result.snapshot = true,
                "--root" | "--site" | "--allow-local-metadata" | "--port" | "--serve-seconds" => {
                    let value = args.get(i).ok_or("missing option value")?;
                    i += 1;
                    if value.is_empty() { return Err("empty option value"); }
                    if key == "--root" { result.root = Some(PathBuf::from(value)); continue; }
                    let value = value.to_str().ok_or("value is not UTF-8")?;
                    match key {
                        "--site" => {
                            if value.len() > 256 || fss_reference::reference_deployment::validate_site_lineage(value).is_err() {
                                return Err("invalid site lineage");
                            }
                            result.site = Some(value.to_owned());
                        }
                        "--allow-local-metadata" => {
                            if value != "yes" { return Err("metadata acknowledgement must be yes"); }
                            authorized = true;
                        }
                        _ => {
                            if !value.bytes().all(|b| b.is_ascii_digit()) { return Err("expected unsigned decimal integer"); }
                            let n: u64 = value.parse().map_err(|_| "integer overflow")?;
                            if key == "--port" {
                                result.port = u16::try_from(n).map_err(|_| "port out of range")?;
                            } else {
                                if !(1..=86_400).contains(&n) { return Err("lease out of range"); }
                                result.seconds = n;
                            }
                        }
                    }
                }
                _ => return Err("unknown option"),
            }
        }
        if result.demo {
            if result.root.is_some() || result.site.is_some() || authorized { return Err("demo cannot select or authorize a deployment"); }
        } else if !authorized || result.site.is_none() || result.root.as_ref().is_none_or(|p| !p.is_absolute()) {
            return Err("require absolute --root, --site and --allow-local-metadata yes");
        }
        if result.snapshot && (seen.contains("--port") || seen.contains("--serve-seconds")) {
            return Err("snapshot mode does not accept listener options");
        }
        Ok(result)
    }
}

// All time, source reads and listener work belong to this explicit, finite owner.
struct Lease { deadline: Instant }
impl Lease {
    fn new(seconds: u64) -> Self { Self { deadline: Instant::now() + Duration::from_secs(seconds) } }
    fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline { Err(io::ErrorKind::TimedOut.into()) } else { Ok(()) }
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(15).collect();
    if args.is_empty() || (args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h" | "help"))) {
        return match io::stdout().lock().write_all(HELP.as_bytes()) { Ok(()) => ExitCode::SUCCESS, Err(_) => ExitCode::FAILURE };
    }
    let options = match Options::parse(&args) {
        Ok(value) => value,
        Err(reason) => { eprintln!("ERR-CLI-MALFORMED-VALUE-001: {reason}. Use --help."); return ExitCode::from(2); }
    };
    let lease = Lease::new(if options.snapshot { 5 } else { options.seconds });
    let result = if options.snapshot {
        snapshot::read(&options, &lease).and_then(|body| {
            let mut out = io::stdout().lock();
            out.write_all(body.as_bytes())?;
            out.write_all(b"\n")
        })
    } else { server::run(&options, &lease) };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => { eprintln!("ERR-CLI-RUNTIME-FAILURE-001: dashboard stopped or selected deployment could not be read within its bounds; no deployment writes were requested."); ExitCode::FAILURE }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<Options, &'static str> { Options::parse(&args.iter().map(OsString::from).collect::<Vec<_>>()) }
    #[test]
    fn demo_and_snapshot_are_explicit_and_pure() {
        assert!(parse(&["--demo", "--snapshot"]).unwrap().snapshot);
        assert_eq!(parse(&["--demo", "--port", "0"]).unwrap().port, 0);
        assert!(parse(&["--demo", "--root", "/abs"]).is_err());
        assert!(parse(&["--demo", "--allow-local-metadata", "yes"]).is_err());
        assert!(parse(&["--demo", "--snapshot", "--port", "0"]).is_err());
    }
    #[test]
    fn unbounded_ambiguous_or_missing_authority_refuses() {
        for args in [vec![], vec!["--demo", "--demo"], vec!["--demo", "--host", "0.0.0.0"], vec!["--demo", "--port", "65536"], vec!["--demo", "--serve-seconds", "0"], vec!["--demo", "--port", "-1"], vec!["--root", "/abs", "--site", "site:test"]] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }
}
