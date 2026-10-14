#![forbid(unsafe_code)]
//! Optional early-stop policy over the unchanged native single-capture plan.
//!
//! The enclosing approval binds both the native plan and the shared progress observer.
//! Delegation happens only after exact approval. There is no retry, path rewriting,
//! alternate media receiver or secret lookup. Parsing is pure. Explicit recovery preview
//! delegates protected metadata inspection to the existing storage-only recovery owner.

use std::ffi::OsString;

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest};

use super::driver::{self, Supervision};
use super::plan::{self, Options};
use super::reconnect::recovery::{self, RecoveryPlan};

const POLICY: &str = "single-capture:owner-progress-supervision:no-reconnect:v1";
pub(super) const HELP: &str = "\nOptional recording watchdog: --progress-timeout-ms 1..600000\n\
Starts at Playing; only collected pictures renew it. Uses the same native observer\n\
as reconnect mode, excluding storage pauses without extending native deadlines.\n\
Its new outer approval binds the complete nested capture plan and timeout.\n\
A stalled source closes and drains only its complete prefix, then exits unsuccessfully.\n\
There is no retry or destination suffix; --root and --pins retain their exact paths.\n\
Omitting the option preserves the ordinary plan, approval and execution unchanged.\n\
\n\
Recover an interrupted single capture: repeat its ORIGINAL options with --recover yes.\n\
Keep the original --root and --pins paths; do not add attempt suffixes or change epochs.\n\
Remove the capture approval. Preview reads protected journal metadata, NOT media or secrets.\n\
Repeat with the recovery preview's separate --approve digest to restore original pending work.\n\
--recovery-timeout-ms 1..3600000 (default 30000) bounds the entire recovery operation.\n\
No camera connection, credential lease, new directory, generation or implicit recapture occurs.\n\
Preserve both stores on failure; re-preview current pins before retrying original slots.\n\
Work restoration is not capture completion, loss concealment or an absence certificate.\n\
\n\
After work settles, --recover index previews source-verified catalog completion.\n\
It needs its OWN new approval, not the capture approval or the --recover yes approval.\n\
Index preview reads original media but publishes nothing. Approved execution uses the\n\
same journal/work/confirmation/catalog barriers as reconnect recovery. It never records\n\
new pictures or invents a complete capture. No-op retries report the original catalog pins.\n";

pub(super) struct SinglePlan {
    capture: Options,
    timeout_ns: Option<u64>,
    approval: Option<ContentDigest>,
    recovery_timeout_ns: Option<u64>,
    index_catalogs: bool,
}

impl SinglePlan {
    pub(super) fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > plan::MAX_ARGUMENTS + 6
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err("single-capture argument bound exceeded");
        }
        let mut native = Vec::with_capacity(args.len());
        let mut timeout_ns = None;
        let mut recover = false;
        let mut index_catalogs = false;
        let mut recovery_timeout_ns = None;
        for pair in args.chunks_exact(2) {
            if pair[0] == "--recover" {
                if recover {
                    return Err("duplicate recovery mode");
                }
                index_catalogs = match pair[1].to_str() {
                    Some("yes") => false,
                    Some("index") => true,
                    _ => return Err("offline recovery requires --recover yes or --recover index"),
                };
                recover = true;
                continue;
            }
            if pair[0] == "--recovery-timeout-ms" {
                if recovery_timeout_ns.is_some() {
                    return Err("duplicate recovery timeout");
                }
                let value = pair[1].to_str().ok_or("UTF-8 recovery timeout required")?;
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err("unsigned recovery timeout required");
                }
                let milliseconds = value
                    .parse::<u64>()
                    .ok()
                    .filter(|value| (1..=3_600_000).contains(value))
                    .ok_or("recovery timeout must be in 1..=3600000 milliseconds")?;
                recovery_timeout_ns = Some(milliseconds * 1_000_000);
                continue;
            }
            if pair[0] != "--progress-timeout-ms" {
                native.extend_from_slice(pair);
                continue;
            }
            if timeout_ns.is_some() {
                return Err("duplicate progress timeout");
            }
            let value = pair[1].to_str().ok_or("UTF-8 progress timeout required")?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("unsigned progress timeout required");
            }
            let milliseconds = value
                .parse::<u64>()
                .ok()
                .filter(|value| (1..=600_000).contains(value))
                .ok_or("progress timeout must be in 1..=600000 milliseconds")?;
            timeout_ns = Some(milliseconds * 1_000_000);
        }
        if !recover && recovery_timeout_ns.is_some() {
            return Err("recovery timeout requires --recover yes or --recover index");
        }
        let recovery_timeout_ns = recover.then_some(recovery_timeout_ns.unwrap_or(30_000_000_000));
        let capture = Options::parse(&native)?;
        let approval = capture.approve;
        Ok(Self {
            capture,
            timeout_ns,
            approval,
            recovery_timeout_ns,
            index_catalogs,
        })
    }

    fn digest(&self) -> Result<ContentDigest, &'static str> {
        let Some(timeout) = self.timeout_ns else {
            return self.capture.digest();
        };
        let mut e = CanonicalEncoder::new();
        // A distinct policy tag in the existing capture-plan domain cannot collide
        // with any ordinary AVC/HEVC plan. The complete native approval is a child.
        e.text("fss.rtsp_capture_cli_plan.v1");
        e.text(POLICY);
        e.text(Supervision::POLICY);
        e.u64(timeout);
        e.digest(self.capture.digest()?);
        Ok(ContentDigest::sha256(
            &e.finish_checked()
                .map_err(|_| "supervised capture plan refused")?,
        ))
    }

    pub(super) fn preview(&self) -> Result<String, &'static str> {
        if let Some(timeout) = self.recovery_timeout_ns {
            return recovery::preview(self, timeout);
        }
        let Some(timeout) = self.timeout_ns else {
            return self.capture.preview();
        };
        Ok(object(&[
            ("schema", string("fss.rtsp_supervised_capture_cli.v1")),
            ("phase", string("planned")),
            ("approval", string(&self.digest()?.to_text())),
            ("policy", string(POLICY)),
            ("progress_policy", string(Supervision::POLICY)),
            ("progress_timeout_ns", timeout.to_string()),
            ("capture", self.capture.preview()?),
            ("maximum_attempts", "1".into()),
            ("automatic_reconnect", "false".into()),
            ("destination_rewriting", "false".into()),
            ("effects", string("none-until-exact-outer-approval")),
        ]))
    }

    pub(super) fn approved(&self) -> bool {
        self.approval.is_some()
    }

    fn admit(&mut self) -> Result<Option<Supervision>, &'static str> {
        // A recovery request can never delegate its approval to a live capture, even
        // when a caller supplies the old capture approval instead of the recovery one.
        if self.recovery_timeout_ns.is_some() {
            return Err("ERR-CAPTURE-RTSP-STATE-001");
        }
        let approval = self.digest()?;
        if self.approval != Some(approval) {
            return Err("ERR-CAPTURE-RTSP-APPROVAL-001");
        }
        let supervision = self
            .timeout_ns
            .map(|timeout| Supervision::new(timeout, approval))
            .transpose()?;
        // The caller authorized this exact native plan as part of the outer plan.
        // Never set the child approval before the outer check has succeeded.
        self.capture.approve = Some(self.capture.digest()?);
        Ok(supervision)
    }

    pub(super) fn execute(&mut self) -> Result<(), &'static str> {
        if let Some(timeout) = self.recovery_timeout_ns {
            return recovery::execute(self, timeout);
        }
        match self.admit()? {
            None => driver::execute(&self.capture),
            Some(supervision) => {
                driver::execute_supervised_attempt(&self.capture, Some(supervision))?.result
            }
        }
    }
}

impl RecoveryPlan for SinglePlan {
    fn attempts(&self) -> &[Options] {
        std::slice::from_ref(&self.capture)
    }
    fn capture_digest(&self) -> Result<ContentDigest, &'static str> {
        // Preserve the exact original single-capture identity, including supervision.
        // Recovery mode/deadline are bound separately by the shared recovery owner.
        self.digest()
    }
    fn recovery_approval(&self) -> Option<ContentDigest> {
        self.approval
    }
    fn index_catalogs(&self) -> bool {
        self.index_catalogs
    }
    fn maximum_storage_bytes(&self) -> u64 {
        self.capture.publication_limits().spool.max_total_bytes
    }
}

#[cfg(test)]
#[path = "single_recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
#[path = "single_tests.rs"]
mod tests;
