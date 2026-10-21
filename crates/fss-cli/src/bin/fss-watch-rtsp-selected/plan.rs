#![forbid(unsafe_code)]
//! Pure ordered source admission and exact approval before any path or clock is opened.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_cli::agent_json::{array, object, string};
use fss_cli::json_input;
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_reference::ingest::rtsp_selected_watch::{
    RtspSelectedWatchLimits, RtspSelectedWatchPlan, RtspWatchSelection,
};

use super::{import_plan, watch};

pub(super) const MAX_ARGUMENTS: usize = 128;
pub(super) const MAX_REQUEST_BYTES: usize = 48 * 1024;
pub(super) const MAX_PREVIEW_BYTES: usize = 128 * 1024;
pub(super) const STORAGE_OPERATIONS: u64 = 1_000_000;
const CUSTODY_OVERHEAD_BYTES: u64 = 1024 * 1024 * 1024;
const FORMAT: &str = "fss.rtsp_selected_watch_operator.v1";
const POLICY: &str = "finite-ordered-native-rtsp-selections:owner-original-read:source-closed-retention:\
all-imports-before-independent-whole-recording-watch:one-shared-import-work-and-deadline:\
aggregate-watch-reservations:no-network:no-event-publish:no-complete-history-claim:v1";

pub(super) struct Options {
    pub archive: PathBuf,
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub plan: RtspSelectedWatchPlan,
    pub limits: RtspSelectedWatchLimits,
    pub work: u64,
    pub timeout_ms: u64,
    pub approve: Option<ContentDigest>,
    pub children: Vec<import_plan::Options>,
}

fn digest(text: &str) -> Result<ContentDigest, &'static str> {
    let digest = ContentDigest::parse(text).map_err(|_| "invalid digest")?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("nonzero SHA-256 digest required");
    }
    Ok(digest)
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
            let limit = if key == "--requests" {
                MAX_REQUEST_BYTES
            } else {
                4096
            };
            if key.len() > 4096
                || value.is_empty()
                || value.len() > limit
                || value.starts_with("--")
            {
                return Err("missing or oversized option value");
            }
            if key == "--zone" && zones.len() < 16 {
                zones.push(watch::zone(value)?);
            } else if watch::ALLOWED.contains(&key)
                || [
                    "--requests",
                    "--approve-import",
                    "--max-work",
                    "--timeout-ms",
                    "--max-report-bytes",
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
        let document = json_input::parse(values.get("--requests").ok_or("--requests required")?)
            .map_err(|_| "invalid bounded request JSON")?;
        let requests = document.array().ok_or("requests must be an array")?;
        if !(1..=16).contains(&requests.len()) {
            return Err("1..16 ordered selections required");
        }
        let mut children: Vec<import_plan::Options> = Vec::with_capacity(requests.len());
        let mut selections = Vec::with_capacity(requests.len());
        for request in requests {
            let request = request
                .array()
                .ok_or("each request must be an option array")?;
            if request.len() > import_plan::MAX_ARGUMENTS {
                return Err("child argument count bound exceeded");
            }
            let args = request
                .iter()
                .map(|value| {
                    value
                        .text()
                        .map(OsString::from)
                        .ok_or("child options must be strings")
                })
                .collect::<Result<Vec<_>, _>>()?;
            for pair in args.as_chunks::<2>().0 {
                if matches!(
                    pair[0].to_str(),
                    Some("--approve" | "--max-work" | "--timeout-ms")
                ) {
                    return Err(
                        "child approval/work/timeout options are forbidden; use outer controls",
                    );
                }
            }
            let child = import_plan::Options::parse(&args)?;
            if child.request.capture_origin.is_none() {
                return Err("every selection requires an explicit capture origin and uncertainty");
            }
            if let Some(first) = children.first()
                && (child.archive != first.archive
                    || child.root != first.root
                    || child.site != first.site
                    || child.principal != first.principal)
            {
                return Err("all selections must share archive, deployment, site and principal");
            }
            selections.push(if let Some(pages) = &child.pages {
                RtspWatchSelection::Pages(pages.clone())
            } else if let Some(catalog) = &child.catalog {
                RtspWatchSelection::Catalog(catalog.clone())
            } else {
                RtspWatchSelection::Window(child.request.clone())
            });
            children.push(child);
        }
        let (plan, limits) = watch::configure(&values, zones, selections)?;
        let first = children.first().ok_or("empty selection")?;
        let options = Self {
            archive: first.archive.clone(),
            root: first.root.clone(),
            site: first.site.clone(),
            principal: first.principal.clone(),
            plan,
            limits,
            work: watch::number(
                &values,
                "--max-work",
                1_000_000_000_000,
                1,
                1_000_000_000_000_000,
            )?,
            timeout_ms: watch::number(&values, "--timeout-ms", 30_000, 1, 600_000)?,
            approve: values
                .get("--approve-import")
                .map(|text| digest(text))
                .transpose()?,
            children,
        };
        // Output capacity and the complete reservation must be admissible even on an approved run.
        options.preview()?;
        Ok(options)
    }

    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut encoded = CanonicalEncoder::new();
        encoded.text("fss.rtsp_selected_watch_cli_plan.v1");
        encoded.text(POLICY);
        encoded.digest(
            self.plan
                .digest(&self.limits)
                .map_err(|error| error.stable_id())?,
        );
        encoded.text(self.archive.to_str().ok_or("UTF-8 path required")?);
        encoded.text(self.root.to_str().ok_or("UTF-8 path required")?);
        encoded.text(&self.site);
        encoded.text(&self.principal);
        encoded.u64(self.work);
        encoded.u64(self.timeout_ms);
        encoded.u64(MAX_REQUEST_BYTES as u64);
        encoded.u64(MAX_PREVIEW_BYTES as u64);
        encoded.u64(STORAGE_OPERATIONS);
        encoded.u64(self.authority_byte_budget()?);
        // Retain exact native source-plan references in the approved preview; execution uses
        // the typed selections and the outer shared work/deadline, never child drivers.
        encoded.u64(self.children.len() as u64);
        for child in &self.children {
            encoded.digest(child.approval()?);
        }
        Ok(ContentDigest::sha256(
            &encoded.finish_checked().map_err(|_| "plan byte bound")?,
        ))
    }

    pub fn preview(&self) -> Result<String, &'static str> {
        let reserve = self
            .plan
            .reservation(&self.limits)
            .map_err(|error| error.stable_id())?;
        let children = self
            .children
            .iter()
            .map(import_plan::Options::preview)
            .collect::<Result<Vec<_>, _>>()?;
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
                "archive",
                string(self.archive.to_str().ok_or("UTF-8 path required")?),
            ),
            (
                "root",
                string(self.root.to_str().ok_or("UTF-8 path required")?),
            ),
            ("site", string(&self.site)),
            ("principal", string(&self.principal)),
            ("native_import_plans", array(&children)),
            (
                "native_plan_budget_scope",
                string("reference_only_outer_work_and_deadline_govern_this_execution"),
            ),
            (
                "watch_configuration",
                watch::configuration_json(&self.plan, &self.limits),
            ),
            (
                "reserved_whole_selection",
                object(&[
                    ("selections", reserve.selections.to_string()),
                    ("frames", reserve.frames.to_string()),
                    ("original_bytes", reserve.original_bytes.to_string()),
                    ("media_bytes", reserve.media_bytes.to_string()),
                    ("source_read_bytes", reserve.source_read_bytes.to_string()),
                    ("pixel_samples", reserve.pixel_samples.to_string()),
                    (
                        "screening_pixel_samples",
                        reserve.screening_pixel_samples.to_string(),
                    ),
                    ("assignment_work", reserve.assignment_work.to_string()),
                    ("jpeg_work", reserve.jpeg_work.to_string()),
                    ("trace_bytes", reserve.trace_bytes.to_string()),
                    ("report_bytes", reserve.report_bytes.to_string()),
                ]),
            ),
            ("maximum_import_work", self.work.to_string()),
            ("timeout_ms", self.timeout_ms.to_string()),
            ("authority_bytes", self.authority_byte_budget()?.to_string()),
            (
                "authority_storage_operations",
                STORAGE_OPERATIONS.to_string(),
            ),
            (
                "timeout_scope",
                string("whole_operation_cooperative_at_custody_and_analysis_boundaries"),
            ),
            (
                "maximum_report_bytes",
                self.limits.maximum_report_bytes.to_string(),
            ),
            ("tracking_between_selections", "false".into()),
            ("complete_history_claim", "false".into()),
            ("continuity_between_selections", "false".into()),
            ("absence_certifiable", "false".into()),
            (
                "capture_time_label",
                string("operator_assumptions_per_selection"),
            ),
            ("network", string("none")),
            ("writes", string("none_until_exact_outer_approval")),
            (
                "approved_writes",
                string("source_closed_native_recording_imports"),
            ),
            ("event_publication", "false".into()),
            ("atomic", "false".into()),
        ]);
        if json.len() > MAX_PREVIEW_BYTES {
            return Err("ERR-RTSP-SELECTED-WATCH-LIMIT-001");
        }
        Ok(json)
    }

    pub fn authority_byte_budget(&self) -> Result<u64, &'static str> {
        let reserve = self
            .plan
            .reservation(&self.limits)
            .map_err(|error| error.stable_id())?;
        [
            reserve.original_bytes,
            reserve.media_bytes,
            reserve.source_read_bytes,
            reserve.trace_bytes,
            reserve.report_bytes,
        ]
        .into_iter()
        .try_fold(CUSTODY_OVERHEAD_BYTES, |sum, bytes| {
            sum.checked_add(bytes)
                .ok_or("aggregate custody byte budget overflow")
        })
    }
}
