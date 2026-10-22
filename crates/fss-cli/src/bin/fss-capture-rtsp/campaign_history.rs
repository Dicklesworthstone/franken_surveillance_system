#![forbid(unsafe_code)]
//! Explicit campaign metadata custody and exact, storage-only inspection.
//! A selected prefix records observations, never camera coverage or cross-epoch continuity.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, OperationId, PrincipalId,
    RootAuthoritySpec,
};
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher};
use fss_reference::ReplayCx;
use fss_reference::rtsp::campaign_history::{
    CampaignAttempt, CampaignAuthority, CampaignFinish, CampaignHistoryLimits, CampaignOperation,
    CampaignPin, CampaignPlan, CampaignSourceBinding, CampaignTerminal, CampaignWriter,
    NativeAttemptObservation, VerifiedCampaignHistory,
};

use super::{ReconnectPlan, positive};

const ERROR: &str = "ERR-CAPTURE-RTSP-HISTORY-001";
const ROOT: &str = "ERR-CAPTURE-RTSP-ROOT-001";
const AUTHORITY: &str = "ERR-CAPTURE-RTSP-AUTHORITY-001";
const OUTPUT: &str = "ERR-CAPTURE-RTSP-OUTPUT-001";
const FORMAT: &str = "fss.rtsp_campaign_history_cli.v1";
const POLICY: &str = "fss.rtsp_campaign_history_cli.v1:explicit-metadata-retention:\
root-last-immutable-observations:start-before-camera:finish-before-successor:\
separate-terminal:exact-independent-pin:no-resume:no-continuity:no-current-media-custody";
const MAX_STORAGE: u64 = 33_554_432;
const MAX_WORK: u64 = 10_000_000_000;
const MAX_REPORT: usize = 1_048_576;
const KEYS: [&str; 7] = [
    "--history-root",
    "--history-max-records",
    "--history-object-bytes",
    "--history-max-scan-entries",
    "--history-metadata-bytes",
    "--history-storage-bytes",
    "--history-work",
];

pub(crate) const HELP: &str = "fss-capture-rtsp campaign-inspect\n\
  --history-root ABSOLUTE_DIRECTORY --principal principal:local-operator\n\
  --approval sha256:HEX --plan-digest sha256:HEX --root-digest sha256:HEX --records N\n\
  [--history-max-records 33 --history-object-bytes 262144]\n\
  [--history-max-scan-entries 4096 --history-metadata-bytes 16777216]\n\
  [--history-storage-bytes 33554432 --history-work 10000000000 --max-report-bytes 1048576]\n\
\n\
Supply ALL four pin coordinates saved independently from history_durable JSONL receipts.\n\
This reads the EXACT selected immutable prefix. It never selects a latest root or falls back.\n\
Current read ceilings may be smaller than the original grant; insufficient bounds refuse.\n\
No camera, credentials, media archive, lock creation, directory creation, repair or publication.\n\
Metadata is reverified read-only; durability is not freshly fsynced and media custody is unchecked.\n\
A started-only attempt has UNKNOWN completion. An unobserved planned attempt is not proven absent.\n\
An older valid prefix does not prove no later attempt occurred. No capture resume is authorized.\n\
Native catalog, journal and source coordinates are retained observations, not current custody proofs.\n";

#[derive(Clone, Debug)]
pub(super) struct Config {
    pub(super) root: PathBuf,
    limits: CampaignHistoryLimits,
    storage_bytes: u64,
    work: u64,
}

fn path(text: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(text);
    if text.len() > 4096
        || !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || text.split('/').any(|part| part == "." || part == "..")
    {
        return Err("history requires a non-root absolute path without dot components");
    }
    Ok(path)
}

fn separate(left: &Path, right: &Path) -> bool {
    !left.starts_with(right) && !right.starts_with(left)
}

impl Config {
    pub(super) fn take(
        values: &mut BTreeMap<String, String>,
    ) -> Result<Option<Self>, &'static str> {
        if !KEYS.iter().any(|key| values.contains_key(*key)) {
            return Ok(None);
        }
        let root = path(
            &values
                .remove("--history-root")
                .ok_or("--history-root required")?,
        )?;
        let defaults = CampaignHistoryLimits::default();
        let mut bounded = |key: &str, default: u64, maximum: u64| {
            values
                .remove(key)
                .map_or(Ok(default), |text| positive(&text, 1, maximum))
        };
        let limits = CampaignHistoryLimits {
            maximum_records: bounded("--history-max-records", 33, 33)? as u32,
            maximum_spool_object_bytes: bounded(
                "--history-object-bytes",
                defaults.maximum_spool_object_bytes as u64,
                defaults.maximum_spool_object_bytes as u64,
            )? as usize,
            maximum_scan_roots: bounded(
                "--history-max-scan-entries",
                defaults.maximum_scan_roots as u64,
                defaults.maximum_scan_roots as u64,
            )? as usize,
            maximum_metadata_bytes: bounded(
                "--history-metadata-bytes",
                defaults.maximum_metadata_bytes,
                defaults.maximum_metadata_bytes,
            )?,
        };
        let result = Self {
            root,
            limits,
            storage_bytes: bounded("--history-storage-bytes", MAX_STORAGE, MAX_STORAGE)?,
            work: bounded("--history-work", MAX_WORK, MAX_WORK)?,
        };
        result
            .limits
            .validate()
            .map_err(|_| "history limits refused")?;
        result
            .storage()
            .validate()
            .map_err(|_| "history storage limits refused")?;
        Ok(Some(result))
    }

    fn storage(&self) -> LocalPublicationLimits {
        LocalPublicationLimits::new(
            self.limits.maximum_records as usize,
            4,
            1,
            self.limits.maximum_scan_roots,
            SpoolLimits::new(
                self.limits.maximum_scan_roots,
                self.storage_bytes,
                self.limits.maximum_spool_object_bytes,
                self.limits.maximum_scan_roots,
            ),
        )
    }

    pub(super) fn validate(&self, plan: &ReconnectPlan) -> Result<(), &'static str> {
        if self.limits.maximum_records < (plan.attempts.len() * 2 + 1) as u32 {
            return Err(
                "history record ceiling must admit every approved start, finish and terminal",
            );
        }
        for (index, attempt) in plan.attempts.iter().enumerate() {
            for output in [&attempt.root, &attempt.pins] {
                if !separate(&self.root, output) {
                    return Err(
                        "history and all attempt stores must be separate, nonnested directories",
                    );
                }
            }
            if let Some(source) = &plan.sources
                && !separate(&self.root, &source.get(index)?.root)
            {
                return Err("history and source stores must be separate, nonnested directories");
            }
            if let Some(auth) = &attempt.authentication
                && !separate(&self.root, &auth.credential_file)
            {
                return Err("credential file must be outside the campaign history directory");
            }
        }
        Ok(())
    }

    pub(super) fn encode(&self, encoder: &mut CanonicalEncoder) -> Result<(), &'static str> {
        encoder.text(POLICY);
        encoder.text(self.root.to_str().ok_or(ERROR)?);
        encoder.digest(self.limits.digest().map_err(|_| ERROR)?);
        encoder.u64(self.storage_bytes);
        encoder.u64(self.work);
        Ok(())
    }

    pub(super) fn campaign(&self, plan: &ReconnectPlan) -> Result<CampaignPlan, &'static str> {
        let attempts = plan
            .attempts
            .iter()
            .enumerate()
            .map(|(index, options)| {
                let source = plan
                    .sources
                    .as_ref()
                    .map(|sources| {
                        let source = sources.get(index)?;
                        Ok(CampaignSourceBinding {
                            path: source.root.to_str().ok_or(ERROR)?.to_owned(),
                            scope: source.scope.digest().map_err(|_| ERROR)?,
                        })
                    })
                    .transpose()?;
                Ok(CampaignAttempt {
                    ordinal: (index + 1) as u32,
                    child_approval: plan.child_approval(index)?,
                    generation: options.recording_config().scope.generation,
                    archive_namespace: options.pin_scope().archive_namespace,
                    journal_id: options.pin_scope().journal_id,
                    receive_clock: options.recording_config().scope.receive_clock,
                    decode_clock: options.catalog_scope().decode_clock,
                    archive_path: options.root.to_str().ok_or(ERROR)?.to_owned(),
                    pins_path: options.pins.to_str().ok_or(ERROR)?.to_owned(),
                    source,
                    picture_ceiling: options.stop_after_pictures,
                })
            })
            .collect::<Result<Vec<_>, &'static str>>()?;
        let campaign = CampaignPlan {
            approval: plan.digest()?,
            principal: plan.attempts.first().ok_or(ERROR)?.principal.clone(),
            history_path: self.root.to_str().ok_or(ERROR)?.to_owned(),
            continue_after_success: plan.continue_after_success,
            retry_interrupted: plan.retry_interrupted,
            progress_supervised: plan.progress_timeout_ns.is_some(),
            duration_limited: plan.capture_duration_ns.is_some(),
            attempts,
        };
        campaign.validate().map_err(|_| ERROR)?;
        Ok(campaign)
    }

    pub(super) fn report(&self, plan: &ReconnectPlan) -> Result<String, &'static str> {
        Ok(object(&[
            ("policy", string(POLICY)),
            ("root", string(self.root.to_str().ok_or(ERROR)?)),
            (
                "plan_digest",
                string(&self.campaign(plan)?.digest().map_err(|_| ERROR)?.to_text()),
            ),
            ("maximum_records", self.limits.maximum_records.to_string()),
            (
                "maximum_object_bytes",
                self.limits.maximum_spool_object_bytes.to_string(),
            ),
            (
                "maximum_scan_entries",
                self.limits.maximum_scan_roots.to_string(),
            ),
            (
                "maximum_metadata_bytes",
                self.limits.maximum_metadata_bytes.to_string(),
            ),
            ("maximum_storage_bytes", self.storage_bytes.to_string()),
            ("maximum_work", self.work.to_string()),
            ("native_limits_unchanged", "true".into()),
            ("history_contains_original_media", "false".into()),
            ("save_each_pin_independently", "true".into()),
        ]))
    }
}

struct Authority {
    context: ContextAuthority,
    root: PathBuf,
    recorded_path: PathBuf,
    plan: ContentDigest,
    expected: Option<CampaignPin>,
    retain: bool,
}

impl Authority {
    fn new(
        principal: &str,
        approval: ContentDigest,
        plan: ContentDigest,
        root: PathBuf,
        recorded_path: PathBuf,
        expected: Option<CampaignPin>,
        retain: bool,
    ) -> Result<Self, &'static str> {
        let mut capabilities = vec!["ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into()];
        if retain {
            capabilities.extend([
                "CAP-OBJECT-STAGE-001".into(),
                "CAP-OBJECT-PUBLISH-001".into(),
                "CAP-RETENTION-COMMIT-001".into(),
            ]);
        }
        Ok(Self {
            context: ContextAuthority::new_root(RootAuthoritySpec {
                trace_id: "trace:rtsp-campaign-history".into(),
                operation_id: OperationId::parse("operation:rtsp-campaign-history")
                    .map_err(|_| AUTHORITY)?,
                principal: principal.to_owned(),
                capabilities,
                deadline: None,
                priority: 10,
                budgets: BudgetVector::default(),
                privacy_scope: "privacy:owner-rtsp-campaign-metadata".into(),
                retention_scope: "retention:explicit-rtsp-campaign-history".into(),
                anchor_universe: approval,
                generation: 1,
            })
            .map_err(|_| AUTHORITY)?,
            root,
            recorded_path,
            plan,
            expected,
            retain,
        })
    }

    fn check(&self) -> Result<(), &'static str> {
        self.context.validate().map_err(|_| AUTHORITY)?;
        if self.context.cancellation_reason.is_some()
            || !self.context.has_capability("CAP-READ-MEDIA-001")
            || (self.retain
                && ![
                    "CAP-OBJECT-STAGE-001",
                    "CAP-OBJECT-PUBLISH-001",
                    "CAP-RETENTION-COMMIT-001",
                ]
                .iter()
                .all(|cap| self.context.has_capability(cap)))
        {
            return Err(AUTHORITY);
        }
        Ok(())
    }
}

impl CampaignAuthority for Authority {
    fn permit(&self, operation: CampaignOperation, plan: &CampaignPlan) -> bool {
        self.check().is_ok()
            && (operation == CampaignOperation::Read || self.retain)
            && self.context.principal == plan.principal
            && self.context.anchor_universe == plan.approval
            && Path::new(&plan.history_path) == self.recorded_path
            && plan.digest().ok() == Some(self.plan)
    }

    fn permit_read(&self, expected: CampaignPin, root: &Path, principal: &str) -> bool {
        self.check().is_ok()
            && self.expected == Some(expected)
            && self.context.principal == principal
            && self.context.anchor_universe == expected.approval
            && expected.plan == self.plan
            && root == self.root
    }
}

fn resolved(path: &Path, authority: &Authority) -> Result<PathBuf, &'static str> {
    authority.check()?;
    let parent = fs::canonicalize(path.parent().ok_or(ROOT)?).map_err(|_| ROOT)?;
    authority.check()?;
    if !fs::metadata(&parent).map_err(|_| ROOT)?.is_dir() {
        return Err(ROOT);
    }
    Ok(parent.join(path.file_name().ok_or(ROOT)?))
}

pub(super) struct Recorder {
    writer: CampaignWriter,
    publisher: LocalRootPublisher,
    authority: Authority,
    cx: ReplayCx,
    work: WorkBudget<'static>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ContinuationSeed {
    pub(super) next_index: usize,
    pub(super) durable_pictures: u64,
    pub(super) successful_attempts: usize,
}

impl Recorder {
    pub(super) fn new(config: &Config, plan: &ReconnectPlan) -> Result<Self, &'static str> {
        config.validate(plan)?;
        let campaign = config.campaign(plan)?;
        let writer = CampaignWriter::new(campaign.clone(), config.limits).map_err(|_| ERROR)?;
        let mut authority = Authority::new(
            &campaign.principal,
            campaign.approval,
            campaign.digest().map_err(|_| ERROR)?,
            config.root.clone(),
            config.root.clone(),
            None,
            true,
        )?;
        let root = resolved(&config.root, &authority)?;
        // The canonical history graph binds the exact approved path. Refuse a
        // symlinked ancestor before creating anything rather than rebinding it.
        if root != config.root {
            return Err(ROOT);
        }
        for output in plan.output_paths()? {
            if output != config.root && !separate(&root, &resolved(output, &authority)?) {
                return Err(ROOT);
            }
        }
        for attempt in &plan.attempts {
            if let Some(auth) = &attempt.authentication
                && !separate(&root, &resolved(&auth.credential_file, &authority)?)
            {
                return Err(ROOT);
            }
        }
        authority.root = root.clone();
        authority.check()?;
        let mut directory = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        // Exclusive new directory; no adoption, reuse, recovery or mutable resume pointer.
        directory.create(&root).map_err(|_| ROOT)?;
        authority.check()?;
        fs::File::open(root.parent().ok_or(ROOT)?)
            .and_then(|parent| parent.sync_all())
            .map_err(|_| ROOT)?;
        authority.check()?;
        let cx =
            ReplayCx::from_context_authority(&authority.context, &root).map_err(|_| AUTHORITY)?;
        let publisher = LocalRootPublisher::open(&root, config.storage()).map_err(|_| ERROR)?;
        authority.check()?;
        Ok(Self {
            writer,
            publisher,
            authority,
            cx,
            work: WorkBudget::new(config.work),
        })
    }

    /// Reopen one exact independently saved successful campaign prefix under fresh current
    /// authority and a fresh history-work account. Only settled-success prefixes are exposed
    /// through the live reconnect CLI in this first continuation mode; retry-after-failure
    /// continuation remains explicit future work rather than silently rewriting terminal counts.
    pub(super) fn resume(
        config: &Config,
        plan: &ReconnectPlan,
        expected: CampaignPin,
    ) -> Result<(Self, ContinuationSeed), &'static str> {
        config.validate(plan)?;
        let campaign = config.campaign(plan)?;
        if !campaign.continue_after_success {
            return Err(ERROR);
        }
        let mut authority = Authority::new(
            &campaign.principal,
            campaign.approval,
            campaign.digest().map_err(|_| ERROR)?,
            config.root.clone(),
            config.root.clone(),
            Some(expected),
            true,
        )?;
        let root = resolved(&config.root, &authority)?;
        if root != config.root {
            return Err(ROOT);
        }
        for output in plan.output_paths()? {
            if output != config.root && !separate(&root, &resolved(output, &authority)?) {
                return Err(ROOT);
            }
        }
        for attempt in &plan.attempts {
            if let Some(auth) = &attempt.authentication
                && !separate(&root, &resolved(&auth.credential_file, &authority)?)
            {
                return Err(ROOT);
            }
        }
        authority.root = root.clone();
        authority.check()?;
        let cx =
            ReplayCx::from_context_authority(&authority.context, &root).map_err(|_| AUTHORITY)?;
        let publisher = LocalRootPublisher::open(&root, config.storage()).map_err(|_| ERROR)?;
        authority.check()?;
        let mut work = WorkBudget::new(config.work);
        let verified = VerifiedCampaignHistory::load(
            &publisher,
            expected,
            config.limits,
            &authority,
            &cx,
            &mut work,
        )
        .map_err(|_| ERROR)?;
        if verified.plan() != &campaign
            || verified.writer_limits() != config.limits
            || verified.terminal().is_some()
            || verified.attempts().is_empty()
            || verified.attempts().iter().any(|attempt| {
                attempt
                    .finish
                    .as_ref()
                    .is_none_or(|finish| !finish.settled_success)
            })
            || verified
                .attempts()
                .last()
                .and_then(|attempt| attempt.finish.as_ref())
                .is_none_or(|finish| !finish.next_attempt_planned)
        {
            return Err(ERROR);
        }
        let next_index = verified.attempts().len();
        if next_index >= campaign.attempts.len() {
            return Err(ERROR);
        }
        let durable_pictures = verified.attempts().iter().try_fold(0_u64, |sum, attempt| {
            let pictures = attempt
                .finish
                .as_ref()
                .and_then(|finish| finish.native.as_ref())
                .map(|native| native.durable_pictures)
                .ok_or(ERROR)?;
            sum.checked_add(pictures).ok_or(ERROR)
        })?;
        let successful_attempts = next_index;
        let writer = CampaignWriter::resume_from_prefix(
            &publisher,
            campaign,
            expected,
            config.limits,
            &authority,
            &cx,
            &mut work,
        )
        .map_err(|_| ERROR)?;
        Ok((
            Self {
                writer,
                publisher,
                authority,
                cx,
                work,
            },
            ContinuationSeed {
                next_index,
                durable_pictures,
                successful_attempts,
            },
        ))
    }

    pub(super) fn start(&mut self, ordinal: u32) -> Result<CampaignPin, &'static str> {
        self.authority.check()?;
        self.writer
            .start_attempt(
                &mut self.publisher,
                ordinal,
                &self.authority,
                &self.cx,
                &mut self.work,
            )
            .map_err(|_| ERROR)
    }

    pub(super) fn finish(
        &mut self,
        ordinal: u32,
        finish: CampaignFinish,
    ) -> Result<CampaignPin, &'static str> {
        self.authority.check()?;
        self.writer
            .finish_attempt(
                &mut self.publisher,
                ordinal,
                finish,
                &self.authority,
                &self.cx,
                &mut self.work,
            )
            .map_err(|_| ERROR)
    }

    pub(super) fn terminal(
        &mut self,
        result: Result<(), &'static str>,
    ) -> Result<CampaignPin, &'static str> {
        self.authority.check()?;
        self.writer
            .finish_campaign(
                &mut self.publisher,
                CampaignTerminal {
                    complete: result.is_ok(),
                    error_id: result.err().map(str::to_owned),
                },
                &self.authority,
                &self.cx,
                &mut self.work,
            )
            .map_err(|_| ERROR)
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
    }
}

pub(super) fn pin_json(pin: CampaignPin) -> String {
    object(&[
        ("approval", string(&pin.approval.to_text())),
        ("plan", string(&pin.plan.to_text())),
        ("root", string(&pin.root.to_text())),
        ("records", pin.records.to_string()),
    ])
}

fn native_json(native: &NativeAttemptObservation) -> String {
    let bindings = &native.bindings;
    let catalogs = bindings
        .catalogs
        .iter()
        .map(|catalog| {
            object(&[
                ("slot", string(&catalog.slot)),
                ("root", string(&catalog.root.to_text())),
            ])
        })
        .collect::<Vec<_>>();
    object(&[
        ("complete", native.complete.to_string()),
        ("error_id", native.error_id.as_deref().map_or_else(|| "null".into(), string)),
        ("retry", native.retry.map_or_else(|| "null".into(), |reason| string(match reason {
            fss_reference::rtsp::campaign_history::CampaignRetryReason::ConnectionUnavailable => "connection_unavailable",
            fss_reference::rtsp::campaign_history::CampaignRetryReason::SourceEnded => "source_ended",
            fss_reference::rtsp::campaign_history::CampaignRetryReason::ProgressStalled => "recording_progress_stalled",
            fss_reference::rtsp::campaign_history::CampaignRetryReason::ReadInterrupted => "read_interrupted_after_verified_drain",
            fss_reference::rtsp::campaign_history::CampaignRetryReason::SettledSuccess => "settled_success",
        }))),
        ("durable_pictures", native.durable_pictures.to_string()),
        ("recovery_required", native.recovery_required.to_string()),
        ("snapshot_digest", bindings.snapshot_digest.map_or_else(|| "null".into(), |digest| string(&digest.to_text()))),
        ("journal_anchor", bindings.journal_anchor.map_or_else(|| "null".into(), |anchor| object(&[
            ("sequence", anchor.sequence.to_string()), ("root", string(&anchor.root.to_text())),
        ]))),
        ("catalogs", format!("[{}]", catalogs.join(","))),
        ("source_pin", bindings.source_pin.as_ref().map_or_else(|| "null".into(), |pin| object(&[
            ("scope", string(&pin.scope.to_text())), ("head", string(&pin.head.to_text())),
            ("datagrams", pin.datagrams.to_string()), ("bytes", pin.bytes.to_string()),
        ]))),
        ("custody", string("recorded_native_observation_current_media_unchecked")),
    ])
}

pub(crate) struct Inspection {
    config: Config,
    principal: String,
    pin: CampaignPin,
    maximum_report: usize,
}

impl Inspection {
    pub(crate) fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > 32 || !args.len().is_multiple_of(2) {
            return Err("bounded inspection arguments required");
        }
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or(ERROR)?;
            let value = pair[1].to_str().ok_or(ERROR)?;
            if key.len() > 4096
                || value.is_empty()
                || value.len() > 4096
                || value.starts_with("--")
                || values.insert(key.to_owned(), value.to_owned()).is_some()
            {
                return Err("duplicate or invalid history inspection option");
            }
        }
        let config = Config::take(&mut values)?.ok_or("--history-root required")?;
        let principal = values
            .remove("--principal")
            .unwrap_or_else(|| "principal:local-operator".into());
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if principal.len() > 256 {
            return Err("principal too long");
        }
        let mut digest = |key: &str| {
            ContentDigest::parse(
                &values
                    .remove(key)
                    .ok_or("all four independently saved pin coordinates required")?,
            )
            .map_err(|_| "invalid history pin digest")
        };
        let approval = digest("--approval")?;
        let plan = digest("--plan-digest")?;
        let root = digest("--root-digest")?;
        let records = positive(
            &values.remove("--records").ok_or("--records required")?,
            1,
            33,
        )? as u32;
        let pin = CampaignPin {
            approval,
            plan,
            root,
            records,
        };
        pin.validate().map_err(|_| "invalid campaign pin")?;
        let maximum_report = values
            .remove("--max-report-bytes")
            .map_or(Ok(MAX_REPORT as u64), |value| {
                positive(&value, 1, MAX_REPORT as u64)
            })? as usize;
        if !values.is_empty() {
            return Err("unknown history inspection option");
        }
        Ok(Self {
            config,
            principal,
            pin,
            maximum_report,
        })
    }

    pub(crate) fn execute(&self) -> Result<(), &'static str> {
        let authority = Authority::new(
            &self.principal,
            self.pin.approval,
            self.pin.plan,
            self.config.root.clone(),
            self.config.root.clone(),
            Some(self.pin),
            false,
        )?;
        authority.check()?;
        let cx = ReplayCx::from_context_authority_read_only(&authority.context, &self.config.root)
            .map_err(|_| AUTHORITY)?;
        let mut work = WorkBudget::new(self.config.work);
        let result = (|| {
            let history = VerifiedCampaignHistory::inspect(
                &self.config.root,
                self.pin,
                self.config.limits,
                self.config.storage(),
                &authority,
                &cx,
                &mut work,
            )
            .map_err(|_| ERROR)?;
            let attempts = history
                .attempts()
                .iter()
                .map(|entry| {
                    let attempt = &entry.attempt;
                    object(&[
                        ("ordinal", attempt.ordinal.to_string()),
                        ("child_approval", string(&attempt.child_approval.to_text())),
                        ("generation", attempt.generation.to_string()),
                        (
                            "archive_namespace",
                            string(&attempt.archive_namespace.to_text()),
                        ),
                        ("archive_path", string(&attempt.archive_path)),
                        ("pins_path", string(&attempt.pins_path)),
                        ("journal_id", string(&attempt.journal_id.to_text())),
                        ("receive_clock", string(&attempt.receive_clock.to_text())),
                        ("decode_clock", string(&attempt.decode_clock.to_text())),
                        ("picture_ceiling", attempt.picture_ceiling.to_string()),
                        (
                            "source",
                            attempt.source.as_ref().map_or_else(
                                || "null".into(),
                                |source| {
                                    object(&[
                                        ("path", string(&source.path)),
                                        ("scope", string(&source.scope.to_text())),
                                    ])
                                },
                            ),
                        ),
                        ("start_pin", pin_json(entry.start)),
                        (
                            "finish_pin",
                            entry.finish_pin.map_or_else(|| "null".into(), pin_json),
                        ),
                        (
                            "state",
                            string(if entry.finish.is_some() {
                                "finished_observation"
                            } else {
                                "started_completion_unknown"
                            }),
                        ),
                        (
                            "finish",
                            entry.finish.as_ref().map_or_else(
                                || "null".into(),
                                |finish| {
                                    object(&[
                                        (
                                            "native_observation",
                                            string(if finish.native.is_some() {
                                                "available"
                                            } else {
                                                "unavailable"
                                            }),
                                        ),
                                        (
                                            "native",
                                            finish
                                                .native
                                                .as_ref()
                                                .map_or_else(|| "null".into(), native_json),
                                        ),
                                        (
                                            "controller_error",
                                            finish
                                                .controller_error
                                                .as_deref()
                                                .map_or_else(|| "null".into(), string),
                                        ),
                                        ("settled_success", finish.settled_success.to_string()),
                                        (
                                            "next_attempt_planned",
                                            finish.next_attempt_planned.to_string(),
                                        ),
                                    ])
                                },
                            ),
                        ),
                    ])
                })
                .collect::<Vec<_>>();
            let terminal = history.terminal();
            let mut report = object(&[
                ("schema", string(FORMAT)),
                ("phase", string("inspected")),
                ("pin", pin_json(history.pin())),
                ("principal", string(&history.plan().principal)),
                ("selection", string("exact_independently_saved_prefix")),
                (
                    "planned_attempts",
                    history.plan().attempts.len().to_string(),
                ),
                (
                    "observed_started_attempts",
                    history.attempts().len().to_string(),
                ),
                (
                    "observed_finished_attempts",
                    history
                        .attempts()
                        .iter()
                        .filter(|entry| entry.finish.is_some())
                        .count()
                        .to_string(),
                ),
                (
                    "campaign_completion",
                    string(match terminal {
                        Some(value) if value.complete => "observed_complete",
                        Some(_) => "observed_failed",
                        None => "unknown",
                    }),
                ),
                (
                    "terminal",
                    terminal.map_or_else(
                        || "null".into(),
                        |terminal| {
                            object(&[
                                ("complete", terminal.complete.to_string()),
                                (
                                    "error_id",
                                    terminal
                                        .error_id
                                        .as_deref()
                                        .map_or_else(|| "null".into(), string),
                                ),
                            ])
                        },
                    ),
                ),
                ("attempts", format!("[{}]", attempts.join(","))),
                (
                    "durability_resynced",
                    history.durability_resynced().to_string(),
                ),
                ("possibly_stale", history.possibly_stale().to_string()),
                ("work_used", work.used().to_string()),
                ("work_remaining", work.remaining().to_string()),
                ("later_records", string("not_asserted")),
                ("unobserved_attempts", string("unknown_not_proven_absent")),
                ("current_media_custody", string("unchecked")),
                ("camera_opened", "false".into()),
                ("capture_resume_authorized", "false".into()),
                ("continuity_across_attempts", "false".into()),
                ("absence_certifiable", "false".into()),
            ]);
            report.push('\n');
            if report.len() > self.maximum_report {
                return Err(OUTPUT);
            }
            authority.check()?;
            crate::write_bounded(report.as_bytes())
        })();
        cx.drain_and_finalize();
        result
    }
}
