#![forbid(unsafe_code)]
//! Pure exact-prefix admission and one approved resource envelope before filesystem access.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_cli::agent_json::{array, object, string};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::ingest::rtsp_campaign_watch::{RtspCampaignWatchLimits, RtspCampaignWatchPlan};
use fss_reference::ingest::rtsp_selected_watch::{RtspSelectedWatchLimits, RtspSelectedWatchPlan};
use fss_reference::rtsp::campaign_history::CampaignPin;

use super::{import_plan, watch};

pub(super) const MAX_ARGUMENTS: usize = 160;
pub(super) const MAX_REQUEST_BYTES: usize = 96 * 1024;
pub(super) const MAX_PREVIEW_BYTES: usize = 256 * 1024;
pub(super) const STORAGE_OPERATIONS: u64 = 1_000_000;
pub(super) const FORMAT: &str = "fss.rtsp_campaign_watch_operator.v1";
const POLICY: &str = "exact-saved-campaign-prefix:complete-ordered-catalog-bindings:independent-archives:\
explicit-unknown-empty-failed-attempts:source-closed-native-imports:all-imports-before-analysis:\
shared-history-and-import-work:aggregate-native-watch-reservations:bounded-native-source-io:\
current-privacy:no-camera:no-event-publish:no-cross-attempt-continuity:no-absence:v1";

pub(super) struct Options {
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub plan: RtspCampaignWatchPlan,
    pub limits: RtspCampaignWatchLimits,
    pub children: Vec<Option<import_plan::Options>>,
    pub work: u64,
    pub archive_read_bytes: u64,
    pub timeout_ms: u64,
    pub approve: Option<ContentDigest>,
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty() || args.len() > MAX_ARGUMENTS || !args.len().is_multiple_of(2) {
            return Err("argument count bound exceeded");
        }
        let mut values = BTreeMap::new();
        let mut zones = Vec::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            let maximum = if key == "--requests" {
                MAX_REQUEST_BYTES
            } else {
                4096
            };
            if key.len() > 4096
                || value.is_empty()
                || value.len() > maximum
                || value.starts_with("--")
            {
                return Err("missing or oversized option value");
            }
            if key == "--zone" && zones.len() < 16 {
                zones.push(watch::zone(value)?);
            } else if watch::ALLOWED.contains(&key)
                || [
                    "--history-root",
                    "--history-approval",
                    "--history-plan",
                    "--history-root-digest",
                    "--history-records",
                    "--history-max-records",
                    "--history-object-bytes",
                    "--history-max-scan-entries",
                    "--history-metadata-bytes",
                    "--history-storage-bytes",
                    "--root",
                    "--site",
                    "--principal",
                    "--requests",
                    "--owner-authorized",
                    "--read-originals",
                    "--retain-originals",
                    "--approve-import",
                    "--max-work",
                    "--timeout-ms",
                    "--max-report-bytes",
                    "--archive-read-bytes",
                ]
                .contains(&key)
            {
                if values.insert(key, value).is_some() {
                    return Err("duplicate option");
                }
            } else {
                return Err("unknown option or collection bound exceeded");
            }
        }
        let input = super::admission::Inputs::parse(&values)?;
        let selections = input
            .bindings
            .iter()
            .filter_map(|binding| binding.selection.clone())
            .collect::<Vec<_>>();
        let (configuration, native_limits) = if selections.is_empty() {
            watch::configure_unselected(&values, zones)?
        } else {
            watch::configure(&values, zones, selections)?
        };
        let options = Self {
            root: input.root,
            site: input.site,
            principal: input.principal,
            children: input.children,
            plan: RtspCampaignWatchPlan {
                history: input.history,
                history_root: input.history_root,
                bindings: input.bindings,
                interpretation: configuration.interpretation,
                zones: configuration.zones,
                detector: configuration.detector,
                tracker: configuration.tracker,
                options: configuration.options,
                screened: configuration.screened,
            },
            limits: RtspCampaignWatchLimits {
                history: input.history_limits,
                history_publication: input.history_publication,
                watch: native_limits.watch,
                maximum_report_bytes: native_limits.maximum_report_bytes,
            },
            work: input.work,
            archive_read_bytes: input.archive_read_bytes,
            timeout_ms: input.timeout_ms,
            approve: input.approve,
        };
        options
            .plan
            .reservation(&options.limits)
            .map_err(|error| error.stable_id())?;
        super::rerun::preview_bound(&options)?;
        options.preview()?;
        Ok(options)
    }

    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut encoded = CanonicalEncoder::new();
        encoded.text("fss.rtsp_campaign_watch_cli_plan.v1");
        encoded.text(POLICY);
        encoded.digest(
            self.plan
                .digest(&self.limits)
                .map_err(|error| error.stable_id())?,
        );
        encoded.text(self.root.to_str().ok_or("UTF-8 path required")?);
        encoded.text(&self.site);
        encoded.text(&self.principal);
        encoded.u64(self.work);
        encoded.u64(self.archive_read_bytes);
        encoded.u64(self.timeout_ms);
        encoded.u64(MAX_REQUEST_BYTES as u64);
        encoded.u64(MAX_PREVIEW_BYTES as u64);
        encoded.u64(STORAGE_OPERATIONS);
        encoded.u64(self.authority_byte_budget()?);
        encoded.u64(self.children.len() as u64);
        for child in &self.children {
            encoded.bool(child.is_some());
            if let Some(child) = child {
                encoded.digest(child.approval()?);
            }
        }
        Ok(ContentDigest::sha256(
            &encoded.finish_checked().map_err(|_| "plan byte bound")?,
        ))
    }

    pub fn authority_byte_budget(&self) -> Result<u64, &'static str> {
        let reservation = self
            .plan
            .reservation(&self.limits)
            .map_err(|error| error.stable_id())?;
        // The CLI adds an initial cold history admission before the core's own history checks.
        // All native source-owner reads have a separately enforced aggregate byte allowance.
        [
            reservation.original_verification_bytes,
            reservation.analysis.media_bytes,
            reservation.analysis.source_read_bytes,
            reservation.analysis.trace_bytes,
            reservation.analysis.report_bytes,
            reservation.history_metadata_bytes,
            self.limits.history.maximum_metadata_bytes,
            self.archive_read_bytes,
        ]
        .into_iter()
        .try_fold(1024 * 1024 * 1024, |sum: u64, value| {
            sum.checked_add(value)
                .ok_or("aggregate custody byte budget overflow")
        })
    }

    pub fn configuration_json(&self) -> String {
        let plan = RtspSelectedWatchPlan {
            selections: Vec::new(),
            interpretation: self.plan.interpretation,
            zones: self.plan.zones.clone(),
            detector: self.plan.detector,
            tracker: self.plan.tracker,
            options: self.plan.options,
            screened: self.plan.screened,
        };
        watch::configuration_json(
            &plan,
            &RtspSelectedWatchLimits {
                watch: self.limits.watch,
                maximum_report_bytes: self.limits.maximum_report_bytes,
            },
        )
    }

    pub fn preview(&self) -> Result<String, &'static str> {
        let campaign = self
            .plan
            .reservation(&self.limits)
            .map_err(|error| error.stable_id())?;
        let r = campaign.analysis;
        let rows = self
            .children
            .iter()
            .enumerate()
            .map(|(index, child)| {
                Ok(object(&[
                    ("ordinal", (index + 1).to_string()),
                    (
                        "native_import_plan",
                        child
                            .as_ref()
                            .map(import_plan::Options::preview)
                            .transpose()?
                            .unwrap_or_else(|| "null".into()),
                    ),
                ]))
            })
            .collect::<Result<Vec<_>, &'static str>>()?;
        let json = object(&[
            ("format", string(FORMAT)),
            ("kind", string("plan")),
            ("approval_digest", string(&self.approval()?.to_text())),
            (
                "plan_digest",
                string(
                    &self
                        .plan
                        .digest(&self.limits)
                        .map_err(|error| error.stable_id())?
                        .to_text(),
                ),
            ),
            ("policy", string(POLICY)),
            (
                "history_root",
                string(
                    self.plan
                        .history_root
                        .to_str()
                        .ok_or("UTF-8 path required")?,
                ),
            ),
            ("history_pin", pin_json(self.plan.history)),
            (
                "root",
                string(self.root.to_str().ok_or("UTF-8 path required")?),
            ),
            ("site", string(&self.site)),
            ("principal", string(&self.principal)),
            ("attempts", array(&rows)),
            ("watch_configuration", self.configuration_json()),
            (
                "reserved_whole_campaign",
                object(&[
                    ("attempts", campaign.attempts.to_string()),
                    ("selected_recordings", r.selections.to_string()),
                    ("frames", r.frames.to_string()),
                    ("original_bytes", r.original_bytes.to_string()),
                    ("media_bytes", r.media_bytes.to_string()),
                    (
                        "source_verification_passes",
                        campaign.source_verification_passes.to_string(),
                    ),
                    (
                        "original_verification_bytes",
                        campaign.original_verification_bytes.to_string(),
                    ),
                    ("source_read_bytes", r.source_read_bytes.to_string()),
                    ("pixel_samples", r.pixel_samples.to_string()),
                    (
                        "screening_pixel_samples",
                        r.screening_pixel_samples.to_string(),
                    ),
                    ("assignment_work", r.assignment_work.to_string()),
                    ("jpeg_work", r.jpeg_work.to_string()),
                    ("trace_bytes", r.trace_bytes.to_string()),
                    ("report_bytes", r.report_bytes.to_string()),
                ]),
            ),
            (
                "history_limits",
                object(&[
                    (
                        "maximum_records",
                        self.limits.history.maximum_records.to_string(),
                    ),
                    (
                        "maximum_object_bytes",
                        self.limits.history.maximum_spool_object_bytes.to_string(),
                    ),
                    (
                        "maximum_scan_entries",
                        self.limits.history.maximum_scan_roots.to_string(),
                    ),
                    (
                        "maximum_metadata_bytes_per_inspection",
                        self.limits.history.maximum_metadata_bytes.to_string(),
                    ),
                    (
                        "maximum_storage_bytes",
                        self.limits
                            .history_publication
                            .spool
                            .max_total_bytes
                            .to_string(),
                    ),
                    ("inspections", "3".into()),
                ]),
            ),
            ("maximum_history_and_import_work", self.work.to_string()),
            (
                "maximum_archive_read_bytes",
                self.archive_read_bytes.to_string(),
            ),
            (
                "maximum_archive_io_operations",
                STORAGE_OPERATIONS.to_string(),
            ),
            ("timeout_ms", self.timeout_ms.to_string()),
            (
                "timeout_scope",
                string("cooperative_at_native_io_and_analysis_boundaries"),
            ),
            ("authority_bytes", self.authority_byte_budget()?.to_string()),
            (
                "authority_storage_operations",
                STORAGE_OPERATIONS.to_string(),
            ),
            (
                "maximum_report_bytes",
                self.limits.maximum_report_bytes.to_string(),
            ),
            (
                "history_selection",
                string("exact_independently_saved_prefix"),
            ),
            ("later_records", string("not_asserted")),
            (
                "capture_time_label",
                string("operator_assumptions_per_attempt"),
            ),
            ("tracking_between_attempts", "false".into()),
            ("continuity_between_attempts", "false".into()),
            ("absence_certifiable", "false".into()),
            ("network", string("none")),
            ("writes", string("none_until_exact_outer_approval")),
            (
                "approved_writes",
                string("native_source_open_recovery_and_source_closed_destination_imports"),
            ),
            ("event_publication", "false".into()),
            ("atomic", "false".into()),
        ]);
        if json.len() >= MAX_PREVIEW_BYTES {
            return Err("ERR-RTSP-CAMPAIGN-WATCH-LIMIT-001");
        }
        Ok(json)
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
