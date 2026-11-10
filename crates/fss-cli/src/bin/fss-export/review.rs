#![forbid(unsafe_code)]
//! Retained screened review media with explicit grants, revocation and local disclosure.

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};

#[path = "review/delivery.rs"]
mod delivery;
#[path = "review/destination.rs"]
mod destination;
#[path = "review/execute.rs"]
mod execute;
#[path = "review/options.rs"]
mod options;
#[cfg(all(test, target_os = "linux"))]
#[path = "review/runtime_tests.rs"]
mod runtime_tests;
#[cfg(test)]
#[path = "review/tests.rs"]
mod tests;

pub(super) const HELP: &str = "fss-export review --root DIR --site SITE\n\
  --import-identity sha256:HEX --expected-import-root sha256:HEX --sensor ID\n\
  --movie-start-tick U64 --movie-end-tick U64 --privacy-digest sha256:HEX\n\
  --recipient PRINCIPAL_ID --purpose TEXT --issued-at-ns I128 --expires-at-ns I128\n\
  --max-media-bytes U64 [--principal ID] [--approve sha256:HEX]\n\
Prepares a bounded grayscale Matroska review derivative from an exact retained AVC/HEVC movie.\n\
The selected interval uses movie presentation ticks. Current privacy masks are applied before\n\
encoding. No audio or unscreened original is disclosed. Default native decode/resource bounds\n\
apply; media is limited to 64 MiB. Preparation renders and verifies without publishing.\n\
Repeat the exact request with approval_digest to publish media, lineage and the recipient grant.\n\
The owner principal is an audit label supplied by the local operator, not authentication.\n\
\n\
fss-export review-show --root DIR --site SITE --review-root sha256:HEX [--principal ID]\n\
Verifies retained review metadata and custody. It returns no media bytes.\n\
\n\
fss-export review-read --root DIR --site SITE --review-root sha256:HEX\n\
  --principal RECIPIENT_ID --attested-now-ns EARLIEST:LATEST --out FILE\n\
  [--approve sha256:EXACT_FILE_APPROVAL]\n\
Checks the exact recipient, current privacy/source state, revocation and supplied time interval.\n\
Both interval bounds must fall inside the grant. The clock is caller-attested, never trusted UTC.\n\
Without --approve, returns a destination-bound approval without creating a file. Approved reads\n\
write a new private file outside the deployment; existing files are never overwritten.\n\
The destination parent must exist and forbid group/world writes. Linux with /proc is required.\n\
Delivery records an intent before creating the file, then verifies its complete readback.\n\
Repeat an approved request to verify a complete prior file; missing or partial files refuse.\n\
No retry overwrites an existing file or creates a second copy for the same delivery identity.\n\
Revocation or expiry cannot erase delivered copies.\n\
\n\
fss-export review-delivery-show --root DIR --site SITE --delivery-id sha256:HEX\n\
  --principal RECIPIENT_ID\n\
Reads durable delivery metadata even after grant expiry or revocation. It neither reads the\n\
external file nor grants media access; Started means the outcome requires reconciliation.\n\
\n\
fss-export review-revoke --root DIR --site SITE --review-root sha256:HEX\n\
  [--principal ID] [--approve sha256:HEX]\n\
Preview then commit permanent local revocation of this exact review grant. No network listener,\n\
external transfer, remote authentication, FLDT rights decision or automatic expiry deletion exists.\n";

pub(super) fn main(args: &[OsString]) -> ExitCode {
    let options = match options::parse(args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-export --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match execute::run(&options) {
        Ok(report) => match writeln!(io::stdout().lock(), "{report}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => {
                eprintln!(
                    "{ERR_CLI_RUNTIME_FAILURE}: review response lost; inspect retained custody and private output before retrying"
                );
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(error) => {
            eprintln!(
                "{ERR_CLI_RUNTIME_FAILURE}: {error}; publication or private output may require inspection"
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
