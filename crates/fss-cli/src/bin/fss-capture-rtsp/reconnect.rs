#![forbid(unsafe_code)]
//! Finite, explicitly approved reconnects through the native capture owners.
//! No archive is overwritten or automatically recovered; every retry starts a new epoch.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use fss_cli::agent_json::{object, string};
use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
};

use super::driver::{self, AttemptOutcome};
use super::plan::{self, Options};
use super::source_mode::SourceConfig;

#[path = "reconnect_source.rs"]
mod retained;

#[path = "recovery.rs"]
pub(super) mod recovery;

pub(super) const MAX_ARGUMENTS: usize = plan::MAX_ARGUMENTS + 32;
const FORMAT: &str = "fss.rtsp_reconnect_cli.v1";
const MAX_CONTROL_REPORT_BYTES: usize = 262_144;
const POLICY: &str = "bounded-owner-approved-attempts:literal-peer-only:fresh-generation-and-clocks:\
new-independent-destinations:retry-typed-connect-io-or-drained-eof-only:\
no-auth-protocol-budget-authority-or-storage-retry:no-automatic-recovery:v1";
const SUPERVISED_POLICY: &str = "bounded-owner-approved-attempts:literal-peer-only:fresh-generation-and-clocks:\
new-independent-destinations:retry-typed-connect-io-drained-eof-or-supervised-stall:\
no-auth-protocol-budget-authority-or-storage-retry:no-automatic-recovery:v2";
// A new outer grant, never an enlargement of any child capture's authority.
const INTERRUPTION_POLICY: &str = "fss.rtsp_interrupted_prefix_retry.v1:\
read-reset-aborted-broken-pipe-unexpected-eof-not-connected-only:\
nonempty-source-verified-prefix:closed-presentation-timing:normal-archive-finish:\
no-pending-custody-or-control:original-failure-retained:no-continuity-claim";
// This opt-in adds possible successful sessions, not authority to widen any child plan.
// The conditional encoding below leaves all pre-existing reconnect approvals unchanged.
const CAMPAIGN_POLICY: &str = "fss.rtsp_capture_campaign.v1:continue-after-settled-success:\
every-approved-attempt-is-independent:all-attempts-must-settle-for-completion";
pub(super) const HELP: &str = "fss-capture-rtsp reconnect [ordinary capture options]\n\
  --max-attempts 3 --retry-delay-ms 250 --retry-max-delay-ms 5000\n\
  [--progress-timeout-ms 5000] [--capture-duration-ms 10000]\n\
  [--continue-after-success yes] [--retry-interrupted yes]\n\
  [--source-root NEW_PREFIX --source-retention-evidence sha256:HEX]\n\
  [--max-datagrams 8192 --source-storage-bytes 268435456 --source-work 1000000000]\n\
\n\
Without --approve: pure JSON preview of EVERY possible attempt and aggregate ceilings.\n\
Approve the outer plan, not an individual attempt. The ordinary single-attempt mode is unchanged.\n\
Retries use exactly the same peer, codec, SSRC, media selection, timing evidence and auth policy.\n\
Each starts generation + attempt_index with fresh receive/decode clocks and journal identity.\n\
--root and --pins are path prefixes: actual new sibling directories are PREFIX.attempt-0001,\n\
PREFIX.attempt-0002, etc. Their parents must exist. All prior directories are preserved.\n\
\n\
By default only typed transient connect I/O or real source end after settled work can retry.\n\
Opt-in progress supervision detects no collected pictures while acquisition is active.\n\
It starts at PLAY, excludes storage pauses, and ignores keepalive/RTCP/duplicate traffic.\n\
Expiry stops intake, attempts to seal/drain the collected prefix, then permits bounded retry\n\
only after normal archive completion. It asserts neither camera outage nor source EOF.\n\
Use --max-attempts 1 to supervise without reconnecting. Omit the option for legacy behavior.\n\
Authentication, credentials, revocation, cancellation, timing/protocol faults, exhausted\n\
budgets, output failure, and incomplete archive work STOP the run. Recovery remains explicit.\n\
\n\
--retry-interrupted yes separately authorizes a successor after a typed abrupt READ failure\n\
(reset, aborted connection, broken pipe, not connected, or unexpected EOF) ONLY after the\n\
native owner verifies, seals and fully publishes a nonempty collected prefix and its catalog.\n\
Pending custody, untimed/unsealed pictures, unresolved display timing, pending control,\n\
authentication, authority, deadlines, output failure and write/protocol failures still STOP.\n\
The interrupted attempt stays a failure, not a successful duration or a source EOF. Original\n\
receiver/wire remainders stay explicit; they are not reconstructed or claimed as durable media.\n\
The next attempt has independent clocks, generation and stores. No continuity is asserted.\n\
This does not add attempts or replenish any child budget. A legacy approval cannot enable it.\n\
Repeat the option unchanged when previewing offline recovery. Omit it for legacy retry rules.\n\
\n\
--capture-duration-ms optionally stops each attempt after owner-clock elapsed time from PLAY.\n\
It includes storage pauses and is NOT renewed by pictures. --stop-after-pictures becomes an\n\
alternate successful stop and a hard picture ceiling. Whichever approved boundary occurs first\n\
stops intake, seals only the already-collected prefix, and drains the archive normally.\n\
Success requires nonempty durable pictures, a complete catalog and settled publication work.\n\
A duration with no collected pictures fails; it is not EOF, absence or permission to retry.\n\
An earlier progress timeout (including a tie) remains a failure, never timed success.\n\
Duration is bounded to 1..600000 ms and must be LESS than --timeout-ms. Leave room for\n\
negotiation and sealing: the original hard network deadline and drain allowance still apply.\n\
This is not an exact camera-time slice or a guarantee of continuous scene coverage.\n\
Use --max-attempts 1 for one timed session, or --continue-after-success yes for a finite campaign.\n\
Repeat the duration option unchanged when previewing offline recovery of its stores.\n\
\n\
By default a successful attempt stops the run. Without a duration, --stop-after-pictures is a\n\
PER-ATTEMPT target; partial captures are reported separately, never joined into a continuous recording.\n\
--continue-after-success yes explicitly approves a finite campaign through every planned attempt.\n\
Each settled success permits another independent session, still subject to the attempt limit,\n\
backoff, owner checkpoints and all original child ceilings. Failure retry rules do not change.\n\
A campaign is complete only when EVERY planned attempt settles successfully. A later success\n\
cannot erase an earlier shortfall: partial campaigns return an original failure and retain per-attempt reports.\n\
This is bounded repeated capture, NOT gap-free recording or an always-on daemon.\n\
Repeat this option unchanged when previewing offline recovery of a campaign.\n\
Between attempts, exponential backoff is capped by --retry-max-delay-ms. At most 16 attempts.\n\
Per-attempt resource ceilings are not silently widened; the outer preview prices their sum.\n\
Credentials, when explicitly configured, are loaded into a fresh private lease per attempt.\n\
Preserve all native terminal JSONL rows: they retain omissions, pins and recovery witnesses.\n\
Reconnect is not crash resume, loss concealment, scene coverage or an absence certificate.\n\
\n\
Explicit offline recovery: repeat the ORIGINAL reconnect options with --recover yes.\n\
Remove the capture --approve value. The returned recovery preview reads protected journal\n\
metadata; source-retained plans also reverify their complete original datagram chains.\n\
It reads no recording or credential files and opens NO camera connection.\n\
Repeat with its separate --approve digest to verify all selected work before restoring\n\
any original pending window/catalog. --recovery-timeout-ms 30000 bounds the ENTIRE operation.\n\
The recovery approval binds all observed journal tips, directory identities, scopes and limits.\n\
A changed tip, a capture approval, a replaced directory, a partial layout or corrupt candidate\n\
refuses; a bad candidate never falls back to older work. Both missing stores remain UNKNOWN,\n\
not evidence that an attempt never ran. With no work pin, archive custody remains unchecked.\n\
Recovery creates no directories, new epochs, extra catalog pages, camera traffic or secret leases.\n\
Native per-attempt ceilings are preserved; all journals and selected archives stay locked.\n\
Restoration is incremental. On failure or lost output, keep every store, preview again,\n\
and approve the current state: original slots retry idempotently, without duplicate ordinals.\n\
Recovered work does NOT establish capture completion, cross-attempt continuity or absence.\n\
\n\
Complete discovery after restoration: --recover index requests a SEPARATE source-reading preview.\n\
It verifies every observed archive and prices the exact next catalog before any publication.\n\
Approve that index preview (not a capture or recovery approval) to publish the recovered tail\n\
through independent journal/work barriers. Unsettled work must first use --recover yes.\n\
Original windows never change; all catalog slots/roots are reported again on no-op retries.\n\
A failed index may leave work to restore. Preserve both stores and preview again; no automatic\n\
repair, new camera input, archive deletion or cross-epoch merge occurs.\n\
\n\
Optional independent rollback fences for either recovery mode:\n\
  --minimum-pin-anchors 1:SEQUENCE:sha256:HEX,2:SEQUENCE:sha256:HEX\n\
Supply journal anchors saved independently for the ORIGINAL one-based attempt ordinals.\n\
Every listed journal prefix must pass before any source read/publication.\n\
Missing listed stores refuse; unlisted attempts do not acquire an independent guarantee.\n\
The bounded map changes recovery approval only, never original capture epochs or paths.\n\
\n\
Optional source-first custody: --source-root PREFIX and --source-retention-evidence sha256:HEX.\n\
These explicitly grant UNENCRYPTED complete RTP/RTCP retention, including malformed input,\n\
before subsequent media progress. Each attempt uses NEW PREFIX.attempt-NNNN alongside its\n\
separate recording archive and journal. Sources, generations and clocks are never reused.\n\
Datagram/spool/work ceilings are PER ATTEMPT; the outer preview prices their sums.\n\
Every child source grant is bound to the outer approval; old or child approvals refuse.\n\
Source storage/work/output failure or uncertainty STOPS, without retry or replenishment.\n\
Progress/duration/retry/campaign rules still apply; all native deadlines remain unchanged.\n\
This adds neither retention by default, new retry causes, automatic source recovery nor\n\
continuous coverage. Preserve the preview, every datagram_durable receipt and all stores.\n\
\n\
Source-retained offline recovery supports --recover yes and --recover index with ALL original\n\
source options. It binds all three stores, holds source/journal owners and verifies source chains,\n\
and requires every original recording RTP packet with its unchanged receive time before writing.\n\
Source stores are never created, appended, reconstructed or resumed by recovery. Any missing,\n\
corrupt, stale or replaced source refuses; all three absent stores remain UNKNOWN.\n\
Optional --minimum-source-pins 1:DATAGRAMS:PAYLOAD_BYTES:sha256:HEAD binds independently saved\n\
datagram_durable coordinates for original attempt ordinals. Each exact prefix must occur in\n\
the complete current chain; damaged newer source is never replaced by an older prefix.\n\
Repeated native source checks share one original --source-work allowance per attempt.\n";

pub(super) struct ReconnectPlan {
    attempts: Vec<Options>,
    sources: Option<retained::SourcePlans>,
    retry_delay_ms: u64,
    retry_max_delay_ms: u64,
    progress_timeout_ns: Option<u64>,
    capture_duration_ns: Option<u64>,
    continue_after_success: bool,
    retry_interrupted: bool,
    recovery_timeout_ns: Option<u64>,
    index_catalogs: bool,
    minimum_pins: Option<recovery::MinimumPins>,
    minimum_sources: Option<recovery::MinimumSourcePins>,
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

fn epoch_digest(
    domain: &str,
    base: ContentDigest,
    ordinal: u64,
    generation: u64,
) -> Result<ContentDigest, &'static str> {
    let mut e = CanonicalEncoder::new();
    e.text(domain);
    e.digest(base);
    e.u64(ordinal);
    e.u64(generation);
    Ok(ContentDigest::sha256(
        &e.finish_checked()
            .map_err(|_| "reconnect identity refused")?,
    ))
}

fn arguments(values: &BTreeMap<String, String>) -> Vec<OsString> {
    values
        .iter()
        .flat_map(|(key, value)| [OsString::from(key), OsString::from(value)])
        .collect()
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
            if key.len() > 4096 || value.len() > 4096 || value.is_empty() || value.starts_with("--")
            {
                return Err("bounded nonempty value required");
            }
            if values.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err("duplicate option");
            }
        }
        let (recover, index_catalogs) = match values.remove("--recover").as_deref() {
            None => (false, false),
            Some("yes") => (true, false),
            Some("index") => (true, true),
            Some(_) => return Err("offline recovery requires --recover yes or --recover index"),
        };
        let continue_after_success = match values.remove("--continue-after-success").as_deref() {
            None => false,
            Some("yes") => true,
            Some(_) => {
                return Err("continuing after success requires --continue-after-success yes");
            }
        };
        let retry_interrupted = match values.remove("--retry-interrupted").as_deref() {
            None => false,
            Some("yes") => true,
            Some(_) => return Err("interruption retries require --retry-interrupted yes"),
        };
        let minimum_pins = values
            .remove("--minimum-pin-anchors")
            .map(|text| recovery::MinimumPins::parse(&text))
            .transpose()?;
        if !recover && minimum_pins.is_some() {
            return Err("minimum pin anchors require --recover yes or --recover index");
        }
        let minimum_sources = values
            .remove("--minimum-source-pins")
            .map(|text| recovery::MinimumSourcePins::parse(&text))
            .transpose()?;
        if !recover && minimum_sources.is_some() {
            return Err("minimum source pins require --recover yes or --recover index");
        }
        let recovery_timeout = values.remove("--recovery-timeout-ms");
        if !recover && recovery_timeout.is_some() {
            return Err("recovery timeout requires --recover yes or --recover index");
        }
        let recovery_timeout_ns = if recover {
            Some(
                positive(recovery_timeout.as_deref().unwrap_or("30000"), 1, 3_600_000)? * 1_000_000,
            )
        } else {
            None
        };
        let count = positive(
            &values
                .remove("--max-attempts")
                .unwrap_or_else(|| "3".into()),
            1,
            16,
        )?;
        let retry_delay_ms = positive(
            &values
                .remove("--retry-delay-ms")
                .unwrap_or_else(|| "250".into()),
            1,
            60_000,
        )?;
        let retry_max_delay_ms = positive(
            &values
                .remove("--retry-max-delay-ms")
                .unwrap_or_else(|| "5000".into()),
            1,
            60_000,
        )?;
        if retry_delay_ms > retry_max_delay_ms {
            return Err("initial retry delay exceeds its ceiling");
        }
        let progress_timeout_ns = values
            .remove("--progress-timeout-ms")
            .map(|text| positive(&text, 1, 600_000).map(|ms| ms * 1_000_000))
            .transpose()?;
        let capture_duration_ns = values
            .remove("--capture-duration-ms")
            .map(|text| positive(&text, 1, 600_000).map(|ms| ms * 1_000_000))
            .transpose()?;
        let approve = values
            .remove("--approve")
            .map(|s| ContentDigest::parse(&s).map_err(|_| "invalid reconnect approval"))
            .transpose()?;
        // Reuse every native codec, route, credentials and resource check before deriving any
        // attempt. The extra mode does not maintain a second version of those contracts.
        let source_arguments = retained::SourceArguments::take(&mut values);
        if minimum_sources.is_some() && source_arguments.is_none() {
            return Err("minimum source pins require the original source-retention options");
        }
        let base = Options::parse(&arguments(&values))?;
        if let Some(source) = &source_arguments {
            source.validate(&values)?;
        }
        if capture_duration_ns.is_some_and(|duration| duration >= base.timeout_ns) {
            return Err("capture duration must be less than the native attempt timeout");
        }
        let first_generation = base.recording_config().scope.generation;
        first_generation
            .checked_add(count - 1)
            .ok_or("reconnect generation overflow")?;
        let root = base.root.to_str().ok_or("UTF-8 archive prefix required")?;
        let pins = base.pins.to_str().ok_or("UTF-8 journal prefix required")?;
        let receive_clock = base.recording_config().scope.receive_clock;
        let journal = base.pin_scope().journal_id;
        let mut attempts = Vec::new();
        let mut sources = source_arguments
            .as_ref()
            .map(|_| retained::SourcePlans::new());
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
            child.insert(
                "--receive-clock".into(),
                epoch_digest(
                    "fss.rtsp_reconnect_receive_clock.v1",
                    receive_clock,
                    index,
                    generation,
                )?
                .to_text(),
            );
            child.insert(
                "--journal-id".into(),
                epoch_digest("fss.rtsp_reconnect_journal.v1", journal, index, generation)?
                    .to_text(),
            );
            let attempt = if let Some(source) = &source_arguments {
                let retained = source.attempt(&child, index as usize)?;
                sources
                    .as_mut()
                    .ok_or("source plan state")?
                    .push(retained.source)?;
                retained.capture
            } else {
                Options::parse(&arguments(&child))?
            };
            maximum_source_bytes = maximum_source_bytes
                .checked_add(attempt.max_received_bytes())
                .ok_or("source budget overflow")?;
            maximum_storage_bytes = maximum_storage_bytes
                .checked_add(attempt.publication_limits().spool.max_total_bytes)
                .ok_or("storage budget overflow")?;
            maximum_report_bytes = maximum_report_bytes
                .checked_add(attempt.max_report_bytes as u64)
                .ok_or("report budget overflow")?;
            maximum_capture_ns = maximum_capture_ns
                .checked_add(attempt.timeout_ns)
                .and_then(|n| n.checked_add(attempt.drain_timeout_ns))
                .ok_or("capture lifetime overflow")?;
            attempts.push(attempt);
        }
        if let Some(minimum) = &minimum_pins {
            minimum.validate(&attempts)?;
        }
        let mut out = Self {
            attempts,
            sources,
            retry_delay_ms,
            retry_max_delay_ms,
            progress_timeout_ns,
            capture_duration_ns,
            continue_after_success,
            retry_interrupted,
            recovery_timeout_ns,
            index_catalogs,
            minimum_pins,
            minimum_sources,
            approve,
            maximum_source_bytes,
            maximum_storage_bytes,
            maximum_report_bytes,
            maximum_capture_ns,
            maximum_backoff_ms: 0,
        };
        out.maximum_backoff_ms = (0..out.attempts.len().saturating_sub(1))
            .map(|index| out.delay_ms(index))
            .sum();
        if let Some(minimum) = &out.minimum_sources {
            minimum.validate(&out)?;
        }
        Ok(out)
    }

    fn child_approval(&self, index: usize) -> Result<ContentDigest, &'static str> {
        let attempt = self
            .attempts
            .get(index)
            .ok_or("ERR-CAPTURE-RTSP-STATE-001")?;
        match &self.sources {
            Some(sources) => sources.get(index)?.digest(attempt),
            None => attempt.digest(),
        }
    }

    fn delay_ms(&self, completed_index: usize) -> u64 {
        self.retry_delay_ms
            .saturating_mul(1_u64 << completed_index.min(15))
            .min(self.retry_max_delay_ms)
    }

    fn policy(&self) -> &'static str {
        if self.progress_timeout_ns.is_some() {
            SUPERVISED_POLICY
        } else {
            POLICY
        }
    }

    fn supervision(
        &self,
        approval: ContentDigest,
    ) -> Result<Option<driver::Supervision>, &'static str> {
        match (self.progress_timeout_ns, self.capture_duration_ns) {
            (None, None) => Ok(None),
            (Some(timeout), None) => driver::Supervision::new(timeout, approval).map(Some),
            (timeout, Some(duration)) => {
                driver::Supervision::with_limits(timeout, Some(duration), approval).map(Some)
            }
        }
    }

    fn valid_picture_total(&self, options: &Options, pictures: u64) -> bool {
        if self.capture_duration_ns.is_some() {
            pictures != 0 && pictures <= options.stop_after_pictures
        } else {
            pictures == options.stop_after_pictures
        }
    }

    // Original capture identity. Recovery binds this under its own domain plus observed stores;
    // this digest alone can never authorize a recovery operation or vice versa.
    fn digest(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_reconnect_cli_plan.v1");
        e.text(self.policy());
        if self.continue_after_success {
            e.text(CAMPAIGN_POLICY);
        }
        if let Some(timeout) = self.progress_timeout_ns {
            e.text(driver::Supervision::POLICY);
            e.u64(timeout);
        }
        // Omission preserves the historical byte encoding, not just its policy label.
        // A duration changes only the outer delegation; it never widens a child budget.
        if let Some(duration) = self.capture_duration_ns {
            e.text(driver::Supervision::TIMED_POLICY);
            e.u64(duration);
        }
        // No bytes are added for the legacy policy. Old approvals cannot authorize
        // interruption retries, and changing this policy invalidates its own approvals.
        if self.retry_interrupted {
            e.text(INTERRUPTION_POLICY);
        }
        if let Some(sources) = &self.sources {
            sources.encode(&self.attempts, &mut e)?;
        }
        e.u64(MAX_CONTROL_REPORT_BYTES as u64);
        e.u64(self.retry_delay_ms);
        e.u64(self.retry_max_delay_ms);
        e.u64(self.attempts.len() as u64);
        for attempt in &self.attempts {
            e.digest(attempt.digest()?);
        }
        Ok(ContentDigest::sha256(
            &e.finish_checked()
                .map_err(|_| "reconnect plan encoding refused")?,
        ))
    }

    pub(super) fn preview(&self) -> Result<String, &'static str> {
        self.prepared_preview(false).map(|(_, report)| report)
    }

    /// A protected metadata owner must redact even query-free private URIs in every
    /// possible attempt. The returned digest belongs to this exact capture or the
    /// freshly observed recovery/index plan, never to a parsed rendering.
    pub(super) fn private_prepared_preview(&self) -> Result<(ContentDigest, String), &'static str> {
        self.prepared_preview(true)
    }

    fn prepared_preview(&self, private: bool) -> Result<(ContentDigest, String), &'static str> {
        if let Some(timeout) = self.recovery_timeout_ns {
            return recovery::prepared_preview(self, timeout);
        }
        let approval = self.digest()?;
        let children = self
            .attempts
            .iter()
            .map(|attempt| {
                if private {
                    attempt.private_uri_preview()
                } else {
                    attempt.preview()
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut fields = vec![
            ("schema", string(FORMAT)),
            ("phase", string("planned")),
            ("approval", string(&approval.to_text())),
            ("policy", string(self.policy())),
            ("max_attempts", self.attempts.len().to_string()),
            ("retry_delay_ms", self.retry_delay_ms.to_string()),
            ("retry_max_delay_ms", self.retry_max_delay_ms.to_string()),
            (
                "maximum_capture_and_drain_ns",
                self.maximum_capture_ns.to_string(),
            ),
            ("maximum_backoff_ms", self.maximum_backoff_ms.to_string()),
            (
                "maximum_source_bytes",
                self.maximum_source_bytes.to_string(),
            ),
            (
                "maximum_archive_spool_bytes",
                self.maximum_storage_bytes.to_string(),
            ),
            (
                "maximum_native_report_bytes",
                self.maximum_report_bytes.to_string(),
            ),
            (
                "maximum_control_report_bytes",
                MAX_CONTROL_REPORT_BYTES.to_string(),
            ),
            (
                "target_scope",
                string(if self.continue_after_success {
                    "every_approved_attempt_independent"
                } else {
                    "per_attempt_until_one_succeeds"
                }),
            ),
            ("continuity_across_attempts", "false".into()),
            ("automatic_recovery", "false".into()),
            ("attempts", format!("[{}]", children.join(","))),
            ("effects", string("none-until-exact-outer-approval")),
        ];
        if let Some(sources) = &self.sources {
            fields.push(("datagram_source_custody", sources.report(&self.attempts)?));
        }
        if let Some(timeout) = self.progress_timeout_ns {
            fields.push(("progress_timeout_ns", timeout.to_string()));
        }
        if self.progress_timeout_ns.is_some() || self.capture_duration_ns.is_some() {
            fields.push((
                "supervision_policy",
                string(if self.capture_duration_ns.is_some() {
                    driver::Supervision::TIMED_POLICY
                } else {
                    driver::Supervision::POLICY
                }),
            ));
        }
        if let Some(duration) = self.capture_duration_ns {
            fields.push(("capture_duration_ns", duration.to_string()));
            fields.push(("duration_starts_at", string("accepted_play_owner_clock")));
            fields.push(("duration_includes_storage_pause", "true".into()));
            fields.push(("picture_target_is_ceiling", "true".into()));
            fields.push(("nonempty_durable_prefix_required", "true".into()));
            fields.push(("camera_time_asserted", "false".into()));
        }
        if self.retry_interrupted {
            fields.push(("retry_interrupted", "true".into()));
            fields.push(("interruption_retry_policy", string(INTERRUPTION_POLICY)));
            fields.push(("interrupted_attempt_is_success", "false".into()));
        }
        if self.continue_after_success {
            fields.push(("continue_after_success", "true".into()));
            fields.push(("campaign_policy", string(CAMPAIGN_POLICY)));
            fields.push((
                "completion_scope",
                string("all_planned_attempts_settled_successfully"),
            ));
        }
        Ok((approval, object(&fields)))
    }

    /// Exact derived destinations, including all optional source stores. Enclosing
    /// private input owners use these before any recovery read or capture mutation.
    pub(super) fn output_paths(&self) -> Result<Vec<&Path>, &'static str> {
        let mut paths = Vec::with_capacity(self.attempts.len() * 3);
        for (index, attempt) in self.attempts.iter().enumerate() {
            paths.push(attempt.root.as_path());
            paths.push(attempt.pins.as_path());
            if let Some(sources) = &self.sources {
                paths.push(sources.get(index)?.root.as_path());
            }
        }
        Ok(paths)
    }

    pub(super) fn operation_kind(&self) -> &'static str {
        if self.recovery_timeout_ns.is_none() {
            "capture"
        } else if self.index_catalogs {
            "index"
        } else {
            "recover"
        }
    }

    /// Validate a containing plan at this owner's exact approval gate. Recovery
    /// passes its locked observed digest to the callback in its sole execution
    /// scan, preserving the original operation clock and cumulative work budgets.
    pub(super) fn execute_validated(
        &mut self,
        validate_approval: &impl Fn(ContentDigest) -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        if let Some(timeout) = self.recovery_timeout_ns {
            return recovery::execute_validated(self, timeout, validate_approval);
        }
        let approval = self.digest()?;
        validate_approval(approval)?;
        self.approve = Some(approval);
        execute(self)
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
    // An implementation that cannot honor source custody must refuse; it must
    // never fall through to ordinary capture and silently omit approved evidence.
    fn capture_retained(
        &mut self,
        _options: &Options,
        _source: &SourceConfig,
    ) -> Result<AttemptOutcome, &'static str> {
        Err("ERR-CAPTURE-RTSP-STATE-001")
    }
    fn pause(&mut self, milliseconds: u64) -> Result<(), &'static str>;
}

fn run(plan: &ReconnectPlan, effects: &mut impl Effects) -> Result<(), &'static str> {
    if plan.recovery_timeout_ns.is_some() {
        return Err("ERR-CAPTURE-RTSP-STATE-001");
    }
    let approval = plan.digest()?;
    if plan.approve != Some(approval) {
        return Err("ERR-CAPTURE-RTSP-APPROVAL-001");
    }
    effects.checkpoint()?;
    let mut durable = 0_u64;
    let mut successful_attempts = 0_usize;
    let mut first_failure: Option<(usize, &'static str)> = None;
    for (index, options) in plan.attempts.iter().enumerate() {
        effects.checkpoint()?;
        let child_approval = plan.child_approval(index)?;
        effects.emit(
            "attempt_started",
            object(&[
                ("approval", string(&approval.to_text())),
                ("attempt", (index + 1).to_string()),
                ("attempt_approval", string(&child_approval.to_text())),
                (
                    "generation",
                    options.recording_config().scope.generation.to_string(),
                ),
                (
                    "root",
                    string(options.root.to_str().ok_or("UTF-8 archive path required")?),
                ),
                (
                    "pins",
                    string(options.pins.to_str().ok_or("UTF-8 journal path required")?),
                ),
                ("continuity_from_previous_attempt", "false".into()),
            ]),
        )?;
        effects.checkpoint()?;
        let outcome = match &plan.sources {
            Some(sources) => effects.capture_retained(options, sources.get(index)?),
            None => effects.capture(options),
        }?;
        // The native owner proves the actual stop and publication barriers. The controller
        // independently checks the approved picture rule: exact count in legacy mode,
        // or a nonempty prefix no larger than the ceiling under explicit duration approval.
        let picture_total_valid = plan.valid_picture_total(options, outcome.durable_pictures);
        let settled_success = outcome.result.is_ok()
            && !outcome.recovery_required
            && outcome.retry == Some(driver::RetryReason::SettledSuccess)
            && picture_total_valid;
        let continuation_blocked =
            plan.continue_after_success && outcome.result.is_ok() && !settled_success;
        // Pending remote control can block a successor independently of media completion.
        // Neither mode may hide unresolved archive work or an invalid picture total.
        let completion_invalid =
            outcome.result.is_ok() && (outcome.recovery_required || !picture_total_valid);
        let capture_result = if completion_invalid {
            Err("ERR-CAPTURE-RTSP-STATE-001")
        } else {
            outcome.result
        };
        let attempt_result = if continuation_blocked {
            Err("ERR-CAPTURE-RTSP-STATE-001")
        } else {
            capture_result
        };
        match attempt_result {
            Ok(()) => successful_attempts += 1,
            Err(error) => {
                first_failure.get_or_insert((index + 1, error));
            }
        }
        durable = durable
            .checked_add(outcome.durable_pictures)
            .ok_or("ERR-CAPTURE-RTSP-STATE-001")?;
        let retry_admitted = matches!(
            outcome.retry,
            Some(driver::RetryReason::ConnectionUnavailable | driver::RetryReason::SourceEnded)
        ) || (outcome.retry == Some(driver::RetryReason::ProgressStalled)
            && plan.progress_timeout_ns.is_some())
            || (plan.retry_interrupted
                && outcome.retry == Some(driver::RetryReason::ReadInterrupted)
                && outcome.result == Err("ERR-CAPTURE-RTSP-SOURCE-001")
                && outcome.durable_pictures != 0
                && outcome.durable_pictures <= options.stop_after_pictures);
        let retrying = outcome.result.is_err()
            && !outcome.recovery_required
            && retry_admitted
            && index + 1 < plan.attempts.len();
        let continuing_after_success =
            plan.continue_after_success && settled_success && index + 1 < plan.attempts.len();
        let mut finished_fields = vec![
            ("approval", string(&approval.to_text())),
            ("attempt", (index + 1).to_string()),
            ("attempt_approval", string(&child_approval.to_text())),
            ("complete", capture_result.is_ok().to_string()),
            (
                "error_id",
                capture_result.err().map_or_else(|| "null".into(), string),
            ),
            (
                "retry_reason",
                outcome
                    .retry
                    .filter(|reason| {
                        *reason != driver::RetryReason::SettledSuccess
                            && (*reason != driver::RetryReason::ReadInterrupted
                                || plan.retry_interrupted)
                    })
                    .map_or_else(|| "null".into(), |r| string(r.as_str())),
            ),
            ("retrying", retrying.to_string()),
            ("recovery_required", outcome.recovery_required.to_string()),
            (
                "durable_pictures_this_attempt",
                outcome.durable_pictures.to_string(),
            ),
            ("durable_pictures_all_attempts", durable.to_string()),
            ("continuity_across_attempts", "false".into()),
        ];
        if let Some(duration) = plan.capture_duration_ns {
            finished_fields.push(("capture_duration_ns", duration.to_string()));
            finished_fields.push(("picture_ceiling", options.stop_after_pictures.to_string()));
            finished_fields.push((
                "picture_ceiling_reached",
                (outcome.durable_pictures == options.stop_after_pictures).to_string(),
            ));
            finished_fields.push(("camera_time_asserted", "false".into()));
        }
        if capture_result != outcome.result {
            finished_fields.push(("native_complete", outcome.result.is_ok().to_string()));
            finished_fields.push((
                "native_error_id",
                outcome.result.err().map_or_else(|| "null".into(), string),
            ));
        }
        if plan.continue_after_success {
            finished_fields.push(("settled_success", settled_success.to_string()));
            finished_fields.push(("continuation_blocked", continuation_blocked.to_string()));
            finished_fields.push((
                "continuing_after_success",
                continuing_after_success.to_string(),
            ));
            finished_fields.push((
                "next_attempt_planned",
                (retrying || continuing_after_success).to_string(),
            ));
        }
        effects.emit("attempt_finished", object(&finished_fields))?;
        if !retrying && !continuing_after_success {
            // Legacy reconnect succeeds as soon as a later attempt succeeds. A campaign has
            // the stronger, explicitly approved contract: every planned session must succeed.
            // Prefer a current terminal failure; otherwise retain the first earlier shortfall.
            let terminal_result = if plan.continue_after_success {
                attempt_result.and(first_failure.map_or(Ok(()), |(_, error)| Err(error)))
            } else {
                attempt_result
            };
            let mut terminal_fields = vec![
                ("approval", string(&approval.to_text())),
                ("attempts_used", (index + 1).to_string()),
                ("complete", terminal_result.is_ok().to_string()),
                (
                    "attempt_limit_reached",
                    (index + 1 == plan.attempts.len()
                        && (plan.continue_after_success
                            || (outcome.result.is_err() && retry_admitted)))
                        .to_string(),
                ),
                ("recovery_required", outcome.recovery_required.to_string()),
                ("durable_pictures_all_attempts", durable.to_string()),
                ("continuity_across_attempts", "false".into()),
                ("absence_certifiable", "false".into()),
            ];
            if plan.continue_after_success {
                terminal_fields.extend([
                    (
                        "completion_scope",
                        string("all_planned_attempts_settled_successfully"),
                    ),
                    ("planned_attempts", plan.attempts.len().to_string()),
                    ("successful_attempts", successful_attempts.to_string()),
                    (
                        "unsuccessful_attempts",
                        (index + 1 - successful_attempts).to_string(),
                    ),
                    (
                        "first_failed_attempt",
                        first_failure
                            .map_or_else(|| "null".into(), |(ordinal, _)| ordinal.to_string()),
                    ),
                    (
                        "first_error_id",
                        first_failure.map_or_else(|| "null".into(), |(_, error)| string(error)),
                    ),
                ]);
            }
            terminal_fields.push((
                "error_id",
                terminal_result.err().map_or_else(|| "null".into(), string),
            ));
            effects.emit("reconnect_terminal", object(&terminal_fields))?;
            return terminal_result;
        }
        let delay = plan.delay_ms(index);
        let mut backoff_fields = vec![
            ("next_attempt", (index + 2).to_string()),
            ("delay_ms", delay.to_string()),
        ];
        if plan.continue_after_success {
            backoff_fields.push((
                "reason",
                string(if continuing_after_success {
                    "next_independent_session"
                } else {
                    "retry_after_failure"
                }),
            ));
        }
        effects.emit("backoff", object(&backoff_fields))?;
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
    supervision: Option<driver::Supervision>,
}
impl Effects for NativeEffects {
    fn checkpoint(&mut self) -> Result<(), &'static str> {
        self.authority
            .validate()
            .map_err(|_| "ERR-CAPTURE-RTSP-AUTHORITY-001")?;
        if self.authority.cancellation_reason.is_some()
            || !self.authority.has_capability("CAP-ADAPTER-NET-001")
        {
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
        driver::execute_supervised_attempt(options, self.supervision)
    }
    fn capture_retained(
        &mut self,
        options: &Options,
        source: &SourceConfig,
    ) -> Result<AttemptOutcome, &'static str> {
        self.checkpoint()?;
        source.execute_supervised_capture(options, self.supervision)
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
    if let Some(timeout) = plan.recovery_timeout_ns {
        return recovery::execute(plan, timeout);
    }
    let approval = plan.digest()?;
    if plan.approve != Some(approval) {
        return Err("ERR-CAPTURE-RTSP-APPROVAL-001");
    }
    // These are exactly the child plans enumerated by the approved outer digest. Setting
    // their approval only after verifying that digest delegates no unplanned route or budget.
    for index in 0..plan.attempts.len() {
        let child_approval = plan.child_approval(index)?;
        plan.attempts[index].approve = Some(child_approval);
    }
    let first = plan.attempts.first().ok_or("ERR-CAPTURE-RTSP-CONFIG-001")?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-reconnect".into(),
        operation_id: OperationId::parse("operation:rtsp-reconnect")
            .map_err(|_| "ERR-CAPTURE-RTSP-CONFIG-001")?,
        principal: first.principal.clone(),
        capabilities: vec!["CAP-ADAPTER-NET-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:owner-original-rtsp-custody".into(),
        retention_scope: "retention:explicit-original-rtsp-scope".into(),
        anchor_universe: approval,
        generation: first.recording_config().scope.generation,
    })
    .map_err(|_| "ERR-CAPTURE-RTSP-CONFIG-001")?;
    let supervision = plan.supervision(approval)?;
    let mut effects = NativeEffects {
        authority,
        sequence: 0,
        report_bytes: 0,
        supervision,
    };
    run(plan, &mut effects)
}

#[cfg(test)]
#[path = "reconnect_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "reconnect_supervision_tests.rs"]
mod supervision_tests;

#[cfg(test)]
#[path = "reconnect_interruption_tests.rs"]
mod interruption_tests;

#[cfg(test)]
#[path = "reconnect_campaign_tests.rs"]
mod campaign_tests;

#[cfg(test)]
mod custody_tests {
    use super::*;

    fn plan_arguments(campaign: bool) -> Vec<OsString> {
        let mut args: Vec<OsString> = [
            ("--root", "/owner/private/archive"),
            ("--pins", "/owner/private/pins"),
            ("--peer", "127.0.0.1:8554"),
            ("--authority", "camera.test:8554"),
            ("--presentation", "/camera/main"),
            ("--control-root", "/camera"),
            ("--sensor-id", "sensor:camera"),
            ("--stream-id", "stream:main"),
            ("--generation", "1"),
            ("--ingress", "1"),
            ("--ssrc", "7"),
            ("--frame-duration-ticks", "3600"),
            ("--stop-after-pictures", "2"),
            ("--max-attempts", "2"),
            ("--owner-authorized", "yes"),
            ("--plaintext", "yes"),
            ("--retain-originals", "yes"),
        ]
        .into_iter()
        .flat_map(|(key, value)| [OsString::from(key), OsString::from(value)])
        .collect();
        for (key, digit) in [
            ("--anchor", "1"),
            ("--receive-clock", "2"),
            ("--timing-evidence", "3"),
            ("--journal-id", "4"),
        ] {
            args.extend([
                OsString::from(key),
                OsString::from(format!("sha256:{}", digit.repeat(64))),
            ]);
        }
        if campaign {
            args.extend([
                OsString::from("--continue-after-success"),
                OsString::from("yes"),
            ]);
        }
        args
    }

    fn approved_plan(campaign: bool) -> ReconnectPlan {
        let mut plan =
            ReconnectPlan::parse(&plan_arguments(campaign)).expect("valid pure reconnect plan");
        plan.approve = Some(plan.digest().expect("outer approval"));
        for attempt in &mut plan.attempts {
            attempt.approve = Some(attempt.digest().expect("child approval"));
        }
        plan
    }

    struct SingleOutcome {
        outcome: Option<AttemptOutcome>,
        captures: usize,
        rows: Vec<(String, String)>,
    }

    impl SingleOutcome {
        fn new(outcome: AttemptOutcome) -> Self {
            Self {
                outcome: Some(outcome),
                captures: 0,
                rows: Vec::new(),
            }
        }

        fn row(&self, kind: &str) -> &str {
            let mut rows = self.rows.iter().filter(|(actual, _)| actual == kind);
            let (_, detail) = rows.next().expect("required control report");
            assert!(rows.next().is_none(), "duplicate {kind}");
            detail
        }
    }

    impl Effects for SingleOutcome {
        fn checkpoint(&mut self) -> Result<(), &'static str> {
            Ok(())
        }

        fn emit(&mut self, kind: &str, detail: String) -> Result<(), &'static str> {
            self.rows.push((kind.into(), detail));
            Ok(())
        }

        fn capture(&mut self, options: &Options) -> Result<AttemptOutcome, &'static str> {
            assert_eq!(
                options.approve,
                Some(options.digest().expect("child approval"))
            );
            self.captures += 1;
            Ok(self.outcome.take().expect("no successor capture may run"))
        }

        fn pause(&mut self, _milliseconds: u64) -> Result<(), &'static str> {
            panic!("unsettled custody must not enter backoff")
        }
    }

    #[test]
    fn reconnect_rejects_invalid_native_success_in_both_modes() {
        for campaign in [false, true] {
            let plan = approved_plan(campaign);
            for (recovery_required, durable_pictures) in [
                (true, 2),
                (false, 0),
                (false, 1),
                (false, 3),
                (false, u64::MAX),
            ] {
                let mut effects = SingleOutcome::new(AttemptOutcome {
                    result: Ok(()),
                    retry: Some(driver::RetryReason::SettledSuccess),
                    recovery_required,
                    durable_pictures,
                });
                assert_eq!(run(&plan, &mut effects), Err("ERR-CAPTURE-RTSP-STATE-001"));
                assert_eq!(effects.captures, 1);
                let finished = effects.row("attempt_finished");
                assert!(finished.contains("\"complete\":false"));
                assert!(finished.contains("\"native_complete\":true"));
                assert!(finished.contains("\"native_error_id\":null"));
                assert!(finished.contains("\"retrying\":false"));
                assert!(finished.contains("\"error_id\":\"ERR-CAPTURE-RTSP-STATE-001\""));
                let terminal = effects.row("reconnect_terminal");
                assert!(terminal.contains("\"complete\":false"));
                assert!(terminal.contains("\"error_id\":\"ERR-CAPTURE-RTSP-STATE-001\""));
                assert!(terminal.contains(&format!("\"recovery_required\":{recovery_required}")));
                if campaign {
                    assert!(terminal.contains("\"successful_attempts\":0"));
                }
            }
        }
    }

    #[test]
    fn native_storage_failure_is_not_replaced_by_a_controller_error() {
        for campaign in [false, true] {
            let plan = approved_plan(campaign);
            let mut effects = SingleOutcome::new(AttemptOutcome {
                result: Err("ERR-CAPTURE-RTSP-STORAGE-001"),
                retry: Some(driver::RetryReason::SourceEnded),
                recovery_required: true,
                durable_pictures: 1,
            });
            assert_eq!(
                run(&plan, &mut effects),
                Err("ERR-CAPTURE-RTSP-STORAGE-001")
            );
            assert_eq!(effects.captures, 1);
            assert!(
                effects
                    .row("attempt_finished")
                    .contains("\"error_id\":\"ERR-CAPTURE-RTSP-STORAGE-001\"")
            );
            assert!(
                effects
                    .row("reconnect_terminal")
                    .contains("\"error_id\":\"ERR-CAPTURE-RTSP-STORAGE-001\"")
            );
        }
    }

    #[test]
    fn media_completion_does_not_imply_campaign_continuation_authority() {
        for campaign in [false, true] {
            let plan = approved_plan(campaign);
            let mut effects = SingleOutcome::new(AttemptOutcome {
                result: Ok(()),
                retry: None,
                recovery_required: false,
                durable_pictures: 2,
            });
            let expected = if campaign {
                Err("ERR-CAPTURE-RTSP-STATE-001")
            } else {
                Ok(())
            };
            assert_eq!(run(&plan, &mut effects), expected);
            assert_eq!(effects.captures, 1);
            let finished = effects.row("attempt_finished");
            assert!(finished.contains("\"complete\":true"));
            assert!(finished.contains("\"error_id\":null"));
            let terminal = effects.row("reconnect_terminal");
            assert!(terminal.contains(&format!("\"complete\":{}", !campaign)));
            if campaign {
                assert!(finished.contains("\"continuation_blocked\":true"));
                assert!(terminal.contains("\"error_id\":\"ERR-CAPTURE-RTSP-STATE-001\""));
            } else {
                assert!(terminal.contains("\"error_id\":null"));
            }
        }
    }

    #[test]
    fn duration_is_bound_to_outer_approval_without_widening_native_attempts() {
        let args = plan_arguments(false);
        let legacy = ReconnectPlan::parse(&args).unwrap();
        let mut timed_args = args.clone();
        timed_args.extend([
            OsString::from("--capture-duration-ms"),
            OsString::from("1000"),
        ]);
        let timed = ReconnectPlan::parse(&timed_args).unwrap();
        assert_eq!(timed.capture_duration_ns, Some(1_000_000_000));
        assert_ne!(legacy.digest().unwrap(), timed.digest().unwrap());
        assert!(
            legacy
                .supervision(legacy.digest().unwrap())
                .unwrap()
                .is_none()
        );
        assert!(
            timed
                .supervision(timed.digest().unwrap())
                .unwrap()
                .is_some()
        );
        assert_eq!(legacy.maximum_capture_ns, timed.maximum_capture_ns);
        assert_eq!(legacy.maximum_source_bytes, timed.maximum_source_bytes);
        assert_eq!(legacy.maximum_storage_bytes, timed.maximum_storage_bytes);
        for (before, after) in legacy.attempts.iter().zip(&timed.attempts) {
            assert_eq!(before.digest().unwrap(), after.digest().unwrap());
        }
        let preview = timed.preview().unwrap();
        for expected in [
            "\"capture_duration_ns\":1000000000",
            "\"duration_includes_storage_pause\":true",
            "\"picture_target_is_ceiling\":true",
            "\"nonempty_durable_prefix_required\":true",
            "\"camera_time_asserted\":false",
        ] {
            assert!(preview.contains(expected), "missing {expected}");
        }
        *timed_args.last_mut().unwrap() = OsString::from("1001");
        assert_ne!(
            timed.digest().unwrap(),
            ReconnectPlan::parse(&timed_args).unwrap().digest().unwrap()
        );
        timed_args.extend([
            OsString::from("--progress-timeout-ms"),
            OsString::from("100"),
        ]);
        let combined = ReconnectPlan::parse(&timed_args).unwrap();
        assert!(
            combined
                .supervision(combined.digest().unwrap())
                .unwrap()
                .is_some()
        );
        assert!(
            combined
                .preview()
                .unwrap()
                .contains(driver::Supervision::TIMED_POLICY)
        );
    }

    #[test]
    fn invalid_or_unreachable_duration_is_refused_before_effects() {
        for value in ["0", "-1", "1.5", "600001", "18446744073709551615", "bad"] {
            let mut args = plan_arguments(false);
            args.extend([
                OsString::from("--capture-duration-ms"),
                OsString::from(value),
            ]);
            assert!(ReconnectPlan::parse(&args).is_err(), "accepted {value}");
        }
        for duration in ["1000", "1001"] {
            let mut args = plan_arguments(false);
            args.extend([
                OsString::from("--timeout-ms"),
                OsString::from("1000"),
                OsString::from("--capture-duration-ms"),
                OsString::from(duration),
            ]);
            assert!(ReconnectPlan::parse(&args).is_err());
        }
        let mut duplicate = plan_arguments(false);
        duplicate.extend([
            OsString::from("--capture-duration-ms"),
            OsString::from("1"),
            OsString::from("--capture-duration-ms"),
            OsString::from("2"),
        ]);
        assert!(ReconnectPlan::parse(&duplicate).is_err());
    }

    #[test]
    fn a_legacy_approval_cannot_authorize_an_early_duration_success() {
        let mut plan = approved_plan(false);
        plan.capture_duration_ns = Some(1_000_000_000);
        let mut effects = SingleOutcome::new(AttemptOutcome {
            result: Ok(()),
            retry: Some(driver::RetryReason::SettledSuccess),
            recovery_required: false,
            durable_pictures: 1,
        });
        assert_eq!(
            run(&plan, &mut effects),
            Err("ERR-CAPTURE-RTSP-APPROVAL-001")
        );
        assert_eq!(effects.captures, 0);
        assert!(effects.rows.is_empty());
        plan.approve = Some(plan.digest().unwrap());
        assert_eq!(run(&plan, &mut effects), Ok(()));
        assert_eq!(effects.captures, 1);
        assert!(
            effects
                .row("attempt_finished")
                .contains("\"picture_ceiling_reached\":false")
        );
    }

    #[test]
    fn timed_controller_refuses_empty_oversized_and_unsettled_successes() {
        for campaign in [false, true] {
            let mut plan = approved_plan(campaign);
            plan.capture_duration_ns = Some(1_000_000_000);
            plan.approve = Some(plan.digest().unwrap());
            for (pictures, recovery_required) in [(0, false), (3, false), (1, true)] {
                let mut effects = SingleOutcome::new(AttemptOutcome {
                    result: Ok(()),
                    retry: Some(driver::RetryReason::SettledSuccess),
                    recovery_required,
                    durable_pictures: pictures,
                });
                assert_eq!(run(&plan, &mut effects), Err("ERR-CAPTURE-RTSP-STATE-001"));
                assert_eq!(effects.captures, 1);
            }
            let mut empty = SingleOutcome::new(AttemptOutcome {
                result: Err("ERR-CAPTURE-RTSP-EMPTY-DURATION-001"),
                retry: None,
                recovery_required: false,
                durable_pictures: 0,
            });
            assert_eq!(
                run(&plan, &mut empty),
                Err("ERR-CAPTURE-RTSP-EMPTY-DURATION-001")
            );
            assert_eq!(empty.captures, 1);
        }
    }

    #[test]
    fn offline_recovery_retains_original_timed_capture_identity() {
        let mut args = plan_arguments(true);
        args.extend([
            OsString::from("--capture-duration-ms"),
            OsString::from("1000"),
        ]);
        let original = ReconnectPlan::parse(&args).unwrap();
        for mode in ["yes", "index"] {
            let mut recovery_args = args.clone();
            recovery_args.extend([OsString::from("--recover"), OsString::from(mode)]);
            let recovery = ReconnectPlan::parse(&recovery_args).unwrap();
            assert_eq!(original.digest().unwrap(), recovery.digest().unwrap());
            assert_eq!(recovery.capture_duration_ns, original.capture_duration_ns);
            for (before, after) in original.attempts.iter().zip(&recovery.attempts) {
                assert_eq!(before.root, after.root);
                assert_eq!(before.pins, after.pins);
                assert_eq!(before.digest().unwrap(), after.digest().unwrap());
            }
        }
    }
}

#[cfg(test)]
#[path = "reconnect_source_tests.rs"]
mod retained_tests;
