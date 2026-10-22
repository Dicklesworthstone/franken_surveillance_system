#![forbid(unsafe_code)]
//! Exact retained RTSP campaign → native motion-independent trained detector bursts.

#[path = "fss-watch-rtsp-campaign/admission.rs"]
mod admission;
#[path = "fss-watch-rtsp-campaign/archive_open.rs"]
mod archive_open;
#[path = "fss-sentinel-rtsp-campaign/driver.rs"]
mod driver;
#[path = "fss-import-rtsp/plan.rs"]
mod import_plan;
#[path = "fss-sentinel-rtsp-campaign/model.rs"]
mod model;
#[path = "fss-sentinel-rtsp-campaign/plan.rs"]
mod plan;
#[path = "fss-watch-rtsp-campaign/preflight.rs"]
mod preflight;
#[cfg(test)]
#[path = "fss-sentinel-rtsp-campaign/tests.rs"]
mod tests;

use fss_cli::ExitIdentity;
use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

const HELP: &str = "fss-sentinel-rtsp-campaign\n\
  --history-root EXISTING_ABSOLUTE_HISTORY --history-approval sha256:HEX\n\
  --history-plan sha256:HEX --history-root-digest sha256:HEX --history-records N\n\
  --root ABSOLUTE_DEPLOYMENT --site SITE [--principal principal:local-operator]\n\
  --requests JSON --interpretation ycbcr\n\
  --package ABSOLUTE_FMPK --package-digest sha256:HEX --read-model yes\n\
  --sentinel-every-frames N --sentinel-burst-frames K --sentinel-max-inferences M\n\
  --retain-analysis yes|no\n\
  --owner-authorized yes --read-originals yes --retain-originals yes\n\
  [--approve-import sha256:PLAN]\n\
\n\
Uses all four independently saved CampaignPin coordinates. --requests has one ordered\n\
{\"ordinal\":1,\"request\":[native fss-import-rtsp options]} or request:null row per selected start.\n\
Every catalogued attempt names its exact archive and COMPLETE saved catalog/page list, original\n\
codec/sensor/stream/anchor/generation/clocks and explicit capture-time assumptions. Child\n\
root/site/principal must equal the outer values. Child approval/work/deadline are forbidden.\n\
Null rows preserve start-only, unavailable, empty and unindexed-picture observations.\n\
\n\
Sampling is independent of foreground or motion. Complete bursts are allocated round-robin\n\
across actual verified attempt recordings. Period 1..65536, burst 1..8 and <=period; M is ONE\n\
campaign allowance 1..1024, at most 64 inferences per attempt. Only whole bursts run. Short,\n\
budget-skipped and unsampled ranges remain explicit; no tracking bridges attempts or bursts.\n\
Native AVC/HEVC decode the complete strict range, including unsampled video. A missing frame,\n\
source gap or decode refusal fails computation. Current destination privacy masks apply.\n\
\n\
Without approval: pure preview, no filesystem, clock, model read, camera or network. Review\n\
the exact history/package/requests, resource reservations and retention choice, then repeat\n\
with the returned approval_digest. Approved execution validates all history/scope/path bindings,\n\
loads the pinned local native RGB detector, imports all originals, then runs native sentinel.\n\
No model download or activation occurs. No foreground scan or zone configuration is required.\n\
\n\
Shared campaign pools: --stream-read-bytes 536870912 --stream-pixel-budget 1073741824.\n\
Per-inference: --max-macs 8000000000 --max-tensor-bytes 268435456\n\
  --max-output-bytes 16777216; aggregate reserved model output must fit 1 GiB.\n\
  --max-frame-pixels N only narrows native coded capacity; AVC floors whole macroblocks.\n\
  --minimum-score-ppm N explicitly overrides the package threshold (uncalibrated output).\n\
  --kernels optimized-cpu|scalar-reference --threads N (numeric 1..64; default 1).\n\
Whole operation: --max-work 1000000000000 --archive-read-bytes 1073741824\n\
  --timeout-ms 30000 --max-report-bytes 16842752 --sentinel-report-bytes 16777216.\n\
Source open/recovery and all subsequent archive reads share the same byte and 1m operation\n\
allowances. History bounds match fss-watch-rtsp-campaign. Timers are cooperative at model/archive\n\
I/O and native operation boundaries; they do not preempt a native decode/inference/retention\n\
operation. Destination opening/import metadata/publication use existing native limits; the\n\
retention read reservation is conservative admission, not a runtime destination-I/O meter.\n\
\n\
--retain-analysis yes retains native aggregate reports, exact package and recipes as cognition,\n\
with fss-infer sentinel-replay hints that need only destination custody after source/model\n\
files go offline. --retain-analysis no creates no report retention or claimed rerun handle.\n\
Imports/retention are incremental; a later refusal can leave earlier work durable. Preserve\n\
stores and retry the exact approved plan. Source owners may finish existing archive recovery.\n\
No event/alert/capture-resume authority, continuous coverage, absence or quality is claimed.\n";

fn emit(text: &str, maximum: usize) -> io::Result<()> {
    if text.len() > maximum {
        return Err(io::Error::other("complete campaign output bound"));
    }
    let mut output = io::stdout().lock();
    let mut bytes = text.as_bytes();
    let mut interrupted = 0;
    while !bytes.is_empty() {
        match output.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => {
                bytes = &bytes[count..];
                interrupted = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 7 => {
                interrupted += 1;
            }
            Err(error) => return Err(error),
        }
    }
    output.flush()
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os()
        .skip(1)
        .take(plan::MAX_ARGUMENTS + 1)
        .collect();
    if args.len() == 1 && args[0] == "--help" {
        return ExitCode::from(if emit(HELP, plan::MAX_PREVIEW_BYTES).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        });
    }
    let options = match plan::Options::parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!(
                "ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-sentinel-rtsp-campaign --help."
            );
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let approved = options.input.approve.is_some();
    let result = if approved {
        driver::execute(&options)
    } else {
        options.preview()
    };
    match result {
        Ok(mut report) => {
            report.push('\n');
            let maximum = if approved {
                options.limits.maximum_report_bytes
            } else {
                plan::MAX_PREVIEW_BYTES
            };
            if emit(&report, maximum).is_ok() {
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "ERR-CLI-RUNTIME-FAILURE-001: output failed; imports/analysis may be durable; retain stores and retry the exact plan"
                );
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        }
        Err(reason) => {
            eprintln!(
                "{reason}: campaign sentinel not confirmed; earlier imports/analysis may remain durable; retry the same approved plan"
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
