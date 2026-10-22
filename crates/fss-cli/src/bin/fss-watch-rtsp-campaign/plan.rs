#![forbid(unsafe_code)]
//! Pure exact-prefix admission and one approved resource envelope before filesystem access.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_cli::agent_json::{array, object, string};
use fss_cli::json_input::{self, Value};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId};
use fss_object::SpoolLimits;
use fss_publication::LocalPublicationLimits;
use fss_reference::ingest::rtsp_campaign_watch::{
    RtspCampaignWatchBinding, RtspCampaignWatchLimits, RtspCampaignWatchPlan,
};
use fss_reference::ingest::rtsp_selected_watch::{
    RtspSelectedWatchLimits, RtspSelectedWatchPlan, RtspWatchSelection,
};
use fss_reference::rtsp::campaign_history::{CampaignHistoryLimits, CampaignPin};

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

fn path(text: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(text);
    if text.len() > 2048
        || !path.is_absolute()
        || path.file_name().is_none()
        || text.split('/').any(|part| matches!(part, "." | ".."))
        || text.chars().any(char::is_control)
    {
        return Err("non-root absolute path without dot components required");
    }
    Ok(path)
}

fn digest(text: &str) -> Result<ContentDigest, &'static str> {
    let value = ContentDigest::parse(text).map_err(|_| "invalid digest")?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err("nonzero SHA-256 digest required");
    }
    Ok(value)
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
        let required = |key| values.get(key).copied().ok_or("required option missing");
        for key in [
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
        ] {
            if required(key)? != "yes" {
                return Err(
                    "explicit owner, original-read and retention acknowledgements required",
                );
            }
        }
        let root = path(required("--root")?)?;
        let history_root = path(required("--history-root")?)?;
        if root.starts_with(&history_root) || history_root.starts_with(&root) {
            return Err("history and destination must be distinct non-nested stores");
        }
        let site = required("--site")?.to_owned();
        if site.len() > 256 || site.chars().any(char::is_control) {
            return Err("invalid site");
        }
        fss_reference::reference_deployment::validate_site_lineage(&site)
            .map_err(|_| "invalid site lineage")?;
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if principal.len() > 256 {
            return Err("principal byte bound exceeded");
        }
        let history = CampaignPin {
            approval: digest(required("--history-approval")?)?,
            plan: digest(required("--history-plan")?)?,
            root: digest(required("--history-root-digest")?)?,
            records: watch::number(&values, "--history-records", 0, 1, 33)? as u32,
        };
        history.validate().map_err(|_| "invalid campaign pin")?;
        let document = json_input::parse(required("--requests")?)
            .map_err(|_| "invalid bounded request JSON")?;
        let rows = document.array().ok_or("requests must be an array")?;
        if !(1..=16).contains(&rows.len()) {
            return Err("one through sixteen ordered attempt rows required");
        }
        let mut bindings = Vec::with_capacity(rows.len());
        let mut children = Vec::with_capacity(rows.len());
        for (index, row) in rows.iter().enumerate() {
            let row = row.object().ok_or("attempt row must be an object")?;
            if row.len() != 2
                || row.get("ordinal").and_then(Value::integer) != Some(index as i128 + 1)
            {
                return Err(
                    "attempt rows need exact consecutive one-based ordinal and request fields",
                );
            }
            let request = row.get("request").ok_or("attempt request required")?;
            let child = if request == &Value::Null {
                None
            } else {
                let arguments = request
                    .array()
                    .ok_or("request must be a native option array or null")?;
                if arguments.len() > import_plan::MAX_ARGUMENTS {
                    return Err("child argument count exceeded");
                }
                let arguments = arguments
                    .iter()
                    .map(|value| {
                        value
                            .text()
                            .map(OsString::from)
                            .ok_or("child options must be strings")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                for pair in arguments.as_chunks::<2>().0 {
                    if matches!(
                        pair[0].to_str(),
                        Some("--approve" | "--max-work" | "--timeout-ms")
                    ) {
                        return Err("child approval/work/timeout forbidden; use the outer owner");
                    }
                }
                let child = import_plan::Options::parse(&arguments)?;
                if child.root != root || child.site != site || child.principal != principal {
                    return Err("every child must use the exact outer root, site and principal");
                }
                if child.request.capture_origin.is_none() {
                    return Err("every recording requires explicit capture origin and uncertainty");
                }
                if child.catalog.is_none() && child.pages.is_none() {
                    return Err(
                        "campaign attempts require a complete catalog or complete page list",
                    );
                }
                if child.archive.starts_with(&history_root)
                    || history_root.starts_with(&child.archive)
                {
                    return Err(
                        "history and recording archives must be distinct non-nested stores",
                    );
                }
                Some(child)
            };
            let selection = child.as_ref().map(|child| {
                    if let Some(pages) = &child.pages {
                        Ok(RtspWatchSelection::Pages(pages.clone()))
                    } else {
                        child.catalog.clone().map(RtspWatchSelection::Catalog)
                            .ok_or("campaign attempts require a complete catalog or complete page list")
                    }
                }).transpose()?;
            bindings.push(RtspCampaignWatchBinding {
                ordinal: (index + 1) as u32,
                selection,
            });
            children.push(child);
        }
        let selections = bindings
            .iter()
            .filter_map(|binding| binding.selection.clone())
            .collect::<Vec<_>>();
        let (configuration, native_limits) = if selections.is_empty() {
            watch::configure_unselected(&values, zones)?
        } else {
            watch::configure(&values, zones, selections)?
        };
        let default_history = CampaignHistoryLimits::default();
        let n = |key, default, low, high| watch::number(&values, key, default, low, high);
        let history_limits = CampaignHistoryLimits {
            maximum_records: n("--history-max-records", 33, 1, 33)? as u32,
            maximum_spool_object_bytes: n(
                "--history-object-bytes",
                default_history.maximum_spool_object_bytes as u64,
                4096,
                1024 * 1024,
            )? as usize,
            maximum_scan_roots: n(
                "--history-max-scan-entries",
                default_history.maximum_scan_roots as u64,
                1,
                65536,
            )? as usize,
            maximum_metadata_bytes: n(
                "--history-metadata-bytes",
                default_history.maximum_metadata_bytes,
                4096,
                256 * 1024 * 1024,
            )?,
        };
        let history_storage = n(
            "--history-storage-bytes",
            32 * 1024 * 1024,
            1,
            256 * 1024 * 1024,
        )?;
        let options = Self {
            root,
            site,
            principal,
            children,
            plan: RtspCampaignWatchPlan {
                history,
                history_root,
                bindings,
                interpretation: configuration.interpretation,
                zones: configuration.zones,
                detector: configuration.detector,
                tracker: configuration.tracker,
                options: configuration.options,
                screened: configuration.screened,
            },
            limits: RtspCampaignWatchLimits {
                history: history_limits,
                history_publication: LocalPublicationLimits::new(
                    history_limits.maximum_records as usize,
                    4,
                    1,
                    history_limits.maximum_scan_roots,
                    SpoolLimits::new(
                        history_limits.maximum_scan_roots,
                        history_storage,
                        history_limits.maximum_spool_object_bytes,
                        history_limits.maximum_scan_roots,
                    ),
                ),
                watch: native_limits.watch,
                maximum_report_bytes: native_limits.maximum_report_bytes,
            },
            work: n("--max-work", 1_000_000_000_000, 1, 1_000_000_000_000_000)?,
            archive_read_bytes: n(
                "--archive-read-bytes",
                1024 * 1024 * 1024,
                1,
                16 * 1024 * 1024 * 1024,
            )?,
            timeout_ms: n("--timeout-ms", 30_000, 1, 600_000)?,
            approve: values
                .get("--approve-import")
                .map(|value| digest(value))
                .transpose()?,
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
