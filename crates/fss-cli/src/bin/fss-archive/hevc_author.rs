#![forbid(unsafe_code)]
//! Bounded explicit-timing authoring for the existing portable HEVC recipe, never a camera adapter.
use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION, ExitIdentity,
};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::WorkBudget;
use fss_publication::{PublishCancellation, PublishCutPoint};
use std::ffi::{OsStr, OsString};
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[path = "hevc_author/input.rs"]
mod input;
#[path = "hevc_author/run.rs"]
mod run;

pub(super) const HELP: &str = "fss-archive author-hevc-recipe --root EXISTING_DIR --draft FILE --draft-id sha256:HEX\n\
  The bounded fss.hevc_recipe_draft.v1 JSON supplies the exact source prefix, original\n\
  VPS/SPS/PPS, source/clock evidence and a complete explicit per-picture timing schedule.\n\
  Default: verify and author in memory; no recipe or recording is published. This opens\n\
  the existing store with its normal lock/recovery synchronization, not forensic read-only.\n\
  Publication additionally requires: --commit yes --approve-recipe sha256:PREVIEW_RECIPE_ID\n\
  Bounds: --timeout-ms --max-steps --max-work --max-draft-bytes --max-timings\n\
          --max-datagrams --max-source-bytes --max-windows --max-output-bytes\n\
          --max-roots --max-scan-roots --max-objects --max-object-bytes --max-total-bytes\n\
  Every numeric bound takes one unsigned decimal value. No networking, inferred cadence,\n\
  guessed timing or codec EOF. All input keys are required; unknown/duplicate keys refuse.\n\
  Draft files must be regular non-symlink files; Linux x86_64/aarch64 reader only.\n";

pub(super) fn handles(args: &[OsString]) -> bool {
    args.first().is_some_and(|s| s == "author-hevc-recipe")
}
#[derive(Debug)]
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
fn digest(text: &str) -> Result<ContentDigest> {
    let d = ContentDigest::parse(text).map_err(|_| malformed("invalid digest"))?;
    if d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32] {
        return Err(malformed("nonzero SHA-256 required"));
    }
    Ok(d)
}
struct Clock {
    start: Instant,
    timeout: Duration,
}
impl Clock {
    fn deadline(&self) -> Result<u64> {
        u64::try_from(self.timeout.as_nanos()).map_err(|_| runtime("deadline overflow"))
    }
    fn now(&self) -> Result<u64> {
        let now = u64::try_from(self.start.elapsed().as_nanos())
            .map_err(|_| runtime("current clock unavailable"))?;
        if now >= self.deadline()? {
            return Err(runtime("authoring deadline expired"));
        }
        Ok(now)
    }
    fn check(&self) -> Result<()> {
        self.now().map(|_| ())
    }
}
impl PublishCancellation for Clock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.check().is_err()
    }
}
pub(super) fn dispatch(args: &[OsString]) -> ExitCode {
    let result = input::options(args).and_then(run::execute);
    match result {
        Ok(report) => match super::emit(&mut std::io::stdout().lock(), report.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => {
                eprintln!(
                    "{ERR_CLI_RUNTIME_FAILURE}: report delivery failed; recipe publication may have committed; reconcile the approved identity before retrying"
                );
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            if !error.usage {
                eprintln!(
                    "No complete report. Existing source is never deleted or repaired. A requested recipe publication may have committed; retry only the exact approved identity. No recording was published by this command."
                );
            }
            ExitCode::from(if error.usage {
                ExitIdentity::MALFORMED_VALUE.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            })
        }
    }
}
