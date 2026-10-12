#![forbid(unsafe_code)]
//! Optional early-stop policy over the unchanged native single-capture plan.
//!
//! The enclosing approval binds both the native plan and the shared progress observer.
//! Delegation happens only after exact approval. There is no retry, path rewriting,
//! alternate media receiver, secret lookup or I/O in this planner.

use std::ffi::OsString;

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest};

use super::driver::{self, Supervision};
use super::plan::{self, Options};

const POLICY: &str = "single-capture:owner-progress-supervision:no-reconnect:v1";
pub(super) const HELP: &str = "\nOptional recording watchdog: --progress-timeout-ms 1..600000\n\
Starts at Playing; only collected pictures renew it. Uses the same native observer\n\
as reconnect mode, excluding storage pauses without extending native deadlines.\n\
Its new outer approval binds the complete nested capture plan and timeout.\n\
A stalled source closes and drains only its complete prefix, then exits unsuccessfully.\n\
There is no retry or destination suffix; --root and --pins retain their exact paths.\n\
Omitting the option preserves the ordinary plan, approval and execution unchanged.\n";

pub(super) struct SinglePlan {
    capture: Options,
    timeout_ns: Option<u64>,
    approval: Option<ContentDigest>,
}

impl SinglePlan {
    pub(super) fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > plan::MAX_ARGUMENTS + 2
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err("single-capture argument bound exceeded");
        }
        let mut native = Vec::with_capacity(args.len());
        let mut timeout_ns = None;
        for pair in args.chunks_exact(2) {
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
        let capture = Options::parse(&native)?;
        let approval = capture.approve;
        Ok(Self {
            capture,
            timeout_ns,
            approval,
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
        match self.admit()? {
            None => driver::execute(&self.capture),
            Some(supervision) => {
                driver::execute_supervised_attempt(&self.capture, Some(supervision))?.result
            }
        }
    }
}

#[cfg(test)]
#[path = "single_tests.rs"]
mod tests;
