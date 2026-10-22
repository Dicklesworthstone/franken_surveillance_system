#![forbid(unsafe_code)]
//! Shared pure history/native-import admission. Analysis modes own their own exact policy.

use super::import_plan;
use fss_cli::json_input::{self, Value};
use fss_core::{ContentDigest, DigestAlgorithm, PrincipalId};
use fss_object::SpoolLimits;
use fss_publication::LocalPublicationLimits;
use fss_reference::ingest::rtsp_campaign_watch::RtspCampaignWatchBinding;
use fss_reference::ingest::rtsp_selected_watch::RtspWatchSelection;
use fss_reference::rtsp::campaign_history::{CampaignHistoryLimits, CampaignPin};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

pub(super) struct Inputs {
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub history_root: PathBuf,
    pub history: CampaignPin,
    pub bindings: Vec<RtspCampaignWatchBinding>,
    pub children: Vec<Option<import_plan::Options>>,
    pub history_limits: CampaignHistoryLimits,
    pub history_publication: LocalPublicationLimits,
    pub work: u64,
    pub archive_read_bytes: u64,
    pub timeout_ms: u64,
    pub approve: Option<ContentDigest>,
}

pub(super) fn path(text: &str) -> Result<PathBuf, &'static str> {
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

pub(super) fn digest(text: &str) -> Result<ContentDigest, &'static str> {
    let value = ContentDigest::parse(text).map_err(|_| "invalid digest")?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err("nonzero SHA-256 digest required");
    }
    Ok(value)
}

pub(super) fn number(
    values: &BTreeMap<&str, &str>,
    key: &str,
    default: u64,
    low: u64,
    high: u64,
) -> Result<u64, &'static str> {
    let n = match values.get(key).copied() {
        None => default,
        Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            text.parse().map_err(|_| "integer overflow")?
        }
        Some(_) => return Err("unsigned decimal integer required"),
    };
    if !(low..=high).contains(&n) {
        return Err("numeric bound exceeded");
    }
    Ok(n)
}

impl Inputs {
    pub fn parse(values: &BTreeMap<&str, &str>) -> Result<Self, &'static str> {
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
            records: number(values, "--history-records", 0, 1, 33)? as u32,
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
        let default_history = CampaignHistoryLimits::default();
        let n = |key, default, low, high| number(values, key, default, low, high);
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
        Ok(Self {
            root,
            site,
            principal,
            history_root,
            history,
            bindings,
            children,
            history_limits,
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
        })
    }
}
