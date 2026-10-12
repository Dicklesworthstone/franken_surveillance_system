#![forbid(unsafe_code)]
//! Finite, explicitly approved reconnects through the unchanged native capture owners.
//! No archive is overwritten or automatically recovered; every retry starts a new epoch.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::time::Duration;

use fss_cli::agent_json::{object, string};
use fss_core::{BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};

use super::driver::{self, AttemptOutcome};
use super::plan::{self, Options};

pub(super) const MAX_ARGUMENTS: usize = plan::MAX_ARGUMENTS + 6;
const FORMAT: &str = "fss.rtsp_reconnect_cli.v1";
const MAX_CONTROL_REPORT_BYTES: usize = 262_144;
const POLICY: &str = "bounded-owner-approved-attempts:literal-peer-only:fresh-generation-and-clocks:\
new-independent-destinations:retry-typed-connect-io-or-drained-eof-only:\
no-auth-protocol-budget-authority-or-storage-retry:no-automatic-recovery:v1";
pub(super) const HELP: &str = "fss-capture-rtsp reconnect [ordinary capture options]\n\
  --max-attempts 3 --retry-delay-ms 250 --retry-max-delay-ms 5000\n\
\n\
Without --approve: pure JSON preview of EVERY possible attempt and aggregate ceilings.\n\
Approve the outer plan, not an individual attempt. The ordinary single-attempt mode is unchanged.\n\
Retries use exactly the same peer, codec, SSRC, media selection, timing evidence and auth policy.\n\
Each starts generation + attempt_index with fresh receive/decode clocks and journal identity.\n\
--root and --pins are path prefixes: actual new sibling directories are PREFIX.attempt-0001,\n\
PREFIX.attempt-0002, etc. Their parents must exist. All prior directories are preserved.\n\
\n\
Only a typed transient connect failure or real EOF after settled archival work can retry.\n\
Authentication, credentials, revocation, cancellation, timing/protocol faults, exhausted\n\
budgets, output failure, and incomplete archive work STOP the run. Recovery remains explicit.\n\
A successful attempt stops the run. --stop-after-pictures is a PER-ATTEMPT target; earlier\n\
partial captures are reported separately, never joined into a continuous recording.\n\
Between attempts, exponential backoff is capped by --retry-max-delay-ms. At most 16 attempts.\n\
Per-attempt resource ceilings are not silently widened; the outer preview prices their sum.\n\
Credentials, when explicitly configured, are loaded into a fresh private lease per attempt.\n\
Preserve all native terminal JSONL rows: they retain omissions, pins and recovery witnesses.\n\
Reconnect is not crash resume, loss concealment, scene coverage or an absence certificate.\n";

pub(super) struct ReconnectPlan {
    attempts: Vec<Options>,
    retry_delay_ms: u64,
    retry_max_delay_ms: u64,
    approve: Option<ContentDigest>,
    maximum_source_bytes: u64,
    maximum_storage_bytes: u64,
    maximum_report_bytes: u64,
    maximum_capture_ns: u64,
    maximum_backoff_ms: u64,
}

fn positive(text: &str, low: u64, high: u64) -> Result<u64, &'static str> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("bounded unsigned decimal required");
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| (low..=high).contains(value))
        .ok_or("reconnect numeric bound exceeded")
}

fn epoch_digest(domain: &str, base: ContentDigest, ordinal: u64, generation: u64) -> Result<ContentDigest, &'static str> {
    let mut e = CanonicalEncoder::new();
    e.text(domain);
    e.digest(base);
    e.u64(ordinal);
    e.u64(generation);
    Ok(ContentDigest::sha256(&e.finish_checked().map_err(|_| "reconnect identity refused")?))
}

fn arguments(values: &BTreeMap<String, String>) -> Vec<OsString> {
    values.iter().flat_map(|(key, value)| [OsString::from(key), OsString::from(value)]).collect()
}

impl ReconnectPlan {
    pub(super) fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > MAX_ARGUMENTS || !args.len().is_multiple_of(2) {
            return Err("reconnect argument count exceeded");
        }
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if key.len() > 4096 || value.len() > 4096 || value.is_empty() || value.starts_with("--") {
                return Err("bounded nonempty value required");
            }
            if values.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err("duplicate option");
            }
        }
        let count = positive(&values.remove("--max-attempts").unwrap_or_else(|| "3".into()), 1, 16)?;
        let retry_delay_ms = positive(&values.remove("--retry-delay-ms").unwrap_or_else(|| "250".into()), 1, 60_000)?;
        let retry_max_delay_ms = positive(&values.remove("--retry-max-delay-ms").unwrap_or_else(|| "5000".into()), 1, 60_000)?;
        if retry_delay_ms > retry_max_delay_ms {
            return Err("initial retry delay exceeds its ceiling");
        }
        let approve = values.remove("--approve")
            .map(|s| ContentDigest::parse(&s).map_err(|_| "invalid reconnect approval"))
            .transpose()?;
        // Reuse every native codec, route, credentials and resource check before deriving any
        // attempt. The extra mode does not maintain a second version of those contracts.
        let base = Options::parse(&arguments(&values))?;
        let first_generation = base.recording_config().scope.generation;
        first_generation.checked_add(count - 1).ok_or("reconnect generation overflow")?;
        let root = base.root.to_str().ok_or("UTF-8 archive prefix required")?;
        let pins = base.pins.to_str().ok_or("UTF-8 journal prefix required")?;
        let receive_clock = base.recording_config().scope.receive_clock;
        let journal = base.pin_scope().journal_id;
        let mut attempts = Vec::new();
        let mut maximum_source_bytes = 0_u64;
        let mut maximum_storage_bytes = 0_u64;
        let mut maximum_report_bytes = 0_u64;
        let mut maximum_capture_ns = 0_u64;
        for index in 0..count {
            let generation = first_generation + index;
            let mut child = values.clone();
            child.insert("--root".into(), format!("{root}.attempt-{:04}", index + 1));
            child.insert("--pins".into(), format!("{pins}.attempt-{:04}", index + 1));
            child.insert("--generation".into(), generation.to_string());
            child.insert("--receive-clock".into(), epoch_digest("fss.rtsp_reconnect_receive_clock.v1", receive_clock, index, generation)?.to_text());
            child.insert("--journal-id".into(), epoch_digest("fss.rtsp_reconnect_journal.v1", journal, index, generation)?.to_text());
            let attempt = Options::parse(&arguments(&child))?;
            maximum_source_bytes = maximum_source_bytes.checked_add(attempt.max_received_bytes()).ok_or("source budget overflow")?;
            maximum_storage_bytes = maximum_storage_bytes.checked_add(attempt.publication_limits().spool.max_total_bytes).ok_or("storage budget overflow")?;
            maximum_report_bytes = maximum_report_bytes.checked_add(attempt.max_report_bytes as u64).ok_or("report budget overflow")?;
            maximum_capture_ns = maximum_capture_ns.checked_add(attempt.timeout_ns).and_then(|n| n.checked_add(attempt.drain_timeout_ns)).ok_or("capture lifetime overflow")?;
            attempts.push(attempt);
        }
        let mut out = Self {
            attempts,
            retry_delay_ms,
            retry_max_delay_ms,
            approve,
            maximum_source_bytes,
            maximum_storage_bytes,
            maximum_report_bytes,
            maximum_capture_ns,
            maximum_backoff_ms: 0,
        };
        out.maximum_backoff_ms = (0..out.attempts.len().saturating_sub(1))
            .map(|index| out.delay_ms(index)).sum();
        Ok(out)
    }

    fn delay_ms(&self, completed_index: usize) -> u64 {
        self.retry_delay_ms.saturating_mul(1_u64 << completed_index.min(15)).min(self.retry_max_delay_ms)
    }

    fn digest(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_reconnect_cli_plan.v1");
        e.text(POLICY);
        e.u64(MAX_CONTROL_REPORT_BYTES as u64);
        e.u64(self.retry_delay_ms);
        e.u64(self.retry_max_delay_ms);
        e.u64(self.attempts.len() as u64);
        for attempt in &self.attempts {
            e.digest(attempt.digest()?);
        }
        Ok(ContentDigest::sha256(&e.finish_checked().map_err(|_| "reconnect plan encoding refused")?))
    }

    pub(super) fn preview(&self) -> Result<String, &'static str> {
        let children = self.attempts.iter().map(Options::preview).collect::<Result<Vec<_>, _>>()?;
        Ok(object(&[
            ("schema", string(FORMAT)),
            ("phase", string("planned")),
            ("approval", string(&self.digest()?.to_text())),
            ("policy", string(POLICY)),
            ("max_attempts", self.attempts.len().to_string()),
            ("retry_delay_ms", self.retry_delay_ms.to_string()),
            ("retry_max_delay_ms", self.retry_max_delay_ms.to_string()),
            ("maximum_capture_and_drain_ns", self.maximum_capture_ns.to_string()),
            ("maximum_backoff_ms", self.maximum_backoff_ms.to_string()),
            ("maximum_source_bytes", self.maximum_source_bytes.to_string()),
            ("maximum_archive_spool_bytes", self.maximum_storage_bytes.to_string()),
            ("maximum_native_report_bytes", self.maximum_report_bytes.to_string()),
            ("maximum_control_report_bytes", MAX_CONTROL_REPORT_BYTES.to_string()),
            ("target_scope", string("per_attempt_until_one_succeeds")),
            ("continuity_across_attempts", "false".into()),
            ("automatic_recovery", "false".into()),
            ("attempts", format!("[{}]", children.join(","))),
            ("effects", string("none-until-exact-outer-approval")),
        ]))
    }

    pub(super) fn approved(&self) -> bool {
        self.approve.is_some()
    }
}

/// The controller can be driven under deterministic test effects. Production delegates only
/// to the native, synchronous single-attempt owner: no subprocess or alternate codec path.
trait Effects {
    fn checkpoint(&mut self) -> Result<(), &'static str>;
    fn emit(&mut self, kind: &str, detail: String) -> Result<(), &'static str>;
    fn capture(&mut self, options: &Options) -> Result<AttemptOutcome, &'static str>;
    fn pause(&mut self, milliseconds: u64) -> Result<(), &'static str>;
}

fn run(plan: &ReconnectPlan, effects: &mut impl Effects) -> Result<(), &'static str> {
    let approval = plan.digest()?;
    if plan.approve != Some(approval) {
        return Err("ERR-CAPTURE-RTSP-APPROVAL-001");
    }
    effects.checkpoint()?;
    let mut durable = 0_u64;
    for (index, options) in plan.attempts.iter().enumerate() {
        effects.checkpoint()?;
        let child_approval = options.digest()?;
        effects.emit("attempt_started", object(&[
            ("approval", string(&approval.to_text())),
            ("attempt", (index + 1).to_string()),
            ("attempt_approval", string(&child_approval.to_text())),
            ("generation", options.recording_config().scope.generation.to_string()),
            ("root", string(options.root.to_str().ok_or("UTF-8 archive path required")?)),
            ("pins", string(options.pins.to_str().ok_or("UTF-8 journal path required")?)),
            ("continuity_from_previous_attempt", "false".into()),
        ]))?;
        effects.checkpoint()?;
        let outcome = effects.capture(options)?;
        durable = durable.checked_add(outcome.durable_pictures).ok_or("ERR-CAPTURE-RTSP-STATE-001")?;
        let retrying = outcome.result.is_err() && !outcome.recovery_required && outcome.retry.is_some() && index + 1 < plan.attempts.len();
        effects.emit("attempt_finished", object(&[
            ("approval", string(&approval.to_text())),
            ("attempt", (index + 1).to_string()),
            ("attempt_approval", string(&child_approval.to_text())),
            ("complete", outcome.result.is_ok().to_string()),
            ("error_id", outcome.result.err().map_or_else(|| "null".into(), string)),
            ("retry_reason", outcome.retry.map_or_else(|| "null".into(), |r| string(r.as_str()))),
            ("retrying", retrying.to_string()),
            ("recovery_required", outcome.recovery_required.to_string()),
            ("durable_pictures_this_attempt", outcome.durable_pictures.to_string()),
            ("durable_pictures_all_attempts", durable.to_string()),
            ("continuity_across_attempts", "false".into()),
        ]))?;
        if !retrying {
            effects.emit("reconnect_terminal", object(&[
                ("approval", string(&approval.to_text())),
                ("attempts_used", (index + 1).to_string()),
                ("complete", outcome.result.is_ok().to_string()),
                ("attempt_limit_reached", (outcome.result.is_err() && outcome.retry.is_some() && index + 1 == plan.attempts.len()).to_string()),
                ("recovery_required", outcome.recovery_required.to_string()),
                ("durable_pictures_all_attempts", durable.to_string()),
                ("continuity_across_attempts", "false".into()),
                ("absence_certifiable", "false".into()),
            ]))?;
            return outcome.result;
        }
        let delay = plan.delay_ms(index);
        effects.emit("backoff", object(&[
            ("next_attempt", (index + 2).to_string()),
            ("delay_ms", delay.to_string()),
        ]))?;
        effects.checkpoint()?;
        effects.pause(delay)?;
        effects.checkpoint()?;
    }
    Err("ERR-CAPTURE-RTSP-STATE-001")
}

struct NativeEffects {
    authority: ContextAuthority,
    sequence: u64,
    report_bytes: usize,
}
impl Effects for NativeEffects {
    fn checkpoint(&mut self) -> Result<(), &'static str> {
        self.authority.validate().map_err(|_| "ERR-CAPTURE-RTSP-AUTHORITY-001")?;
        if self.authority.cancellation_reason.is_some() || !self.authority.has_capability("CAP-ADAPTER-NET-001") {
            return Err("ERR-CAPTURE-RTSP-AUTHORITY-001");
        }
        Ok(())
    }
    fn emit(&mut self, kind: &str, detail: String) -> Result<(), &'static str> {
        let row = object(&[
            ("schema", string(FORMAT)),
            ("sequence", self.sequence.to_string()),
            ("kind", string(kind)),
            ("detail", detail),
        ]) + "\n";
        // Separate from each native attempt's already-approved report ceiling.
        if row.len() > MAX_CONTROL_REPORT_BYTES.saturating_sub(self.report_bytes) {
            return Err("ERR-CAPTURE-RTSP-OUTPUT-001");
        }
        self.report_bytes += row.len();
        super::write_bounded(row.as_bytes())?;
        self.sequence += 1;
        Ok(())
    }
    fn capture(&mut self, options: &Options) -> Result<AttemptOutcome, &'static str> {
        self.checkpoint()?;
        driver::execute_attempt(options)
    }
    fn pause(&mut self, milliseconds: u64) -> Result<(), &'static str> {
        // At most 600 bounded waits per backoff. Every wait has an explicit owner check;
        // it does not create a worker or let a camera operation run during backoff.
        let mut remaining = milliseconds;
        while remaining != 0 {
            self.checkpoint()?;
            let step = remaining.min(100);
            std::thread::sleep(Duration::from_millis(step));
            remaining -= step;
        }
        self.checkpoint()
    }
}

pub(super) fn execute(plan: &mut ReconnectPlan) -> Result<(), &'static str> {
    let approval = plan.digest()?;
    if plan.approve != Some(approval) {
        return Err("ERR-CAPTURE-RTSP-APPROVAL-001");
    }
    // These are exactly the child plans enumerated by the approved outer digest. Setting
    // their approval only after verifying that digest delegates no unplanned route or budget.
    for attempt in &mut plan.attempts {
        attempt.approve = Some(attempt.digest()?);
    }
    let first = plan.attempts.first().ok_or("ERR-CAPTURE-RTSP-CONFIG-001")?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-reconnect".into(),
        operation_id: OperationId::parse("operation:rtsp-reconnect").map_err(|_| "ERR-CAPTURE-RTSP-CONFIG-001")?,
        principal: first.principal.clone(),
        capabilities: vec!["CAP-ADAPTER-NET-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:owner-original-rtsp-custody".into(),
        retention_scope: "retention:explicit-original-rtsp-scope".into(),
        anchor_universe: approval,
        generation: first.recording_config().scope.generation,
    }).map_err(|_| "ERR-CAPTURE-RTSP-CONFIG-001")?;
    let mut effects = NativeEffects { authority, sequence: 0, report_bytes: 0 };
    run(plan, &mut effects)
}

#[cfg(test)]
#[path = "reconnect_tests.rs"]
mod tests;
