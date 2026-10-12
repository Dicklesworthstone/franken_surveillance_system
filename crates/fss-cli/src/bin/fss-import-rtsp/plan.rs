#![forbid(unsafe_code)]
//! Pure exact-selection and original-retention approval planning.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_cli::agent_json::{array, object, string};
use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId, SensorId, StreamId, TimestampNs,
};
use fss_publication::{MAX_SLOT_NAME_BYTES, SlotName};
use fss_reference::ingest::rtsp_import::catalog::{self, RtspCatalogImportRequest};
use fss_reference::ingest::rtsp_import::pages::{
    self, RtspCatalogPage, RtspCatalogPagesImportRequest,
};
use fss_reference::ingest::rtsp_import::{
    MAX_FRAMES, MAX_MEDIA_BYTES, MAX_ORIGINAL_BYTES, RtspCaptureOrigin, RtspImportCodec,
    RtspImportRequest,
};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording_catalog::CatalogScope;

pub(super) const FORMAT: &str = "fss.rtsp_recording_import_operator.v1";
pub(super) const CATALOG_FORMAT: &str = "fss.rtsp_catalog_import_operator.v1";
pub(super) const PAGES_FORMAT: &str = "fss.rtsp_catalog_pages_import_operator.v1";
pub(super) const MAX_ARGUMENTS: usize = 64;
// SlotName excludes '@' and ','. Every admitted list fits one bounded argv value, including
// 64 maximum-length slots, full SHA-256 roots and separators (12,863 ASCII bytes).
pub(super) const MAX_PAGE_ARGUMENT_BYTES: usize =
    pages::MAX_PAGES * (MAX_SLOT_NAME_BYTES + 1 + 71 + 1) - 1;
pub(super) const CAPS: [&str; 4] = [
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
];

pub(super) struct Options {
    pub archive: PathBuf,
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub request: RtspImportRequest,
    pub catalog: Option<RtspCatalogImportRequest>,
    pub pages: Option<RtspCatalogPagesImportRequest>,
    pub work: u64,
    pub timeout_ms: u64,
    pub approve: Option<ContentDigest>,
}

fn path(text: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(text);
    if !path.is_absolute()
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

fn timestamp(text: &str) -> Result<TimestampNs, &'static str> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("nonnegative decimal timestamp required");
    }
    Ok(TimestampNs(text.parse().map_err(|_| "timestamp overflow")?))
}

fn catalog_pages(value: &str) -> Result<Vec<RtspCatalogPage>, &'static str> {
    if value.len() > MAX_PAGE_ARGUMENT_BYTES || value.split(',').count() > pages::MAX_PAGES {
        return Err("catalog page list bound exceeded");
    }
    value
        .split(',')
        .map(|entry| {
            let (slot, root) = entry
                .split_once('@')
                .ok_or("catalog page must be SLOT@sha256:HEX")?;
            Ok(RtspCatalogPage {
                slot: SlotName::parse(slot).map_err(|_| "invalid catalog page slot")?,
                root: digest(root)?,
            })
        })
        .collect()
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty() || args.len() > MAX_ARGUMENTS || !args.len().is_multiple_of(2) {
            return Err("argument count or byte bound exceeded");
        }
        let allowed = [
            "--archive",
            "--root",
            "--site",
            "--principal",
            "--window-slot",
            "--window-root",
            "--catalog-slot",
            "--catalog-root",
            "--catalog-pages",
            "--decode-clock",
            "--time-scale",
            "--max-windows",
            "--max-pages",
            "--codec",
            "--sensor-id",
            "--stream-id",
            "--generation",
            "--anchor",
            "--receive-clock",
            "--receive-time-ns",
            "--capture-start-ns",
            "--capture-uncertainty-ns",
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
            "--approve",
            "--max-frames",
            "--max-original-bytes",
            "--max-media-bytes",
            "--max-work",
            "--timeout-ms",
        ];
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            let maximum = if key == "--catalog-pages" {
                MAX_PAGE_ARGUMENT_BYTES
            } else {
                4096
            };
            if key.len() > 4096 || value.len() > maximum {
                return Err("argument byte bound exceeded");
            }
            if !allowed.contains(&key) || value.is_empty() || value.starts_with("--") {
                return Err("unknown option or missing value");
            }
            if values.insert(key, value).is_some() {
                return Err("duplicate option");
            }
        }
        let required = |key: &str| values.get(key).copied().ok_or("required option missing");
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
        let number = |key: &str, default: u64, maximum: u64| -> Result<u64, &'static str> {
            let value = match values.get(key) {
                None => default,
                Some(text) if text.bytes().all(|byte| byte.is_ascii_digit()) => {
                    text.parse().map_err(|_| "integer overflow")?
                }
                Some(_) => return Err("unsigned decimal integer required"),
            };
            if value == 0 || value > maximum {
                return Err("numeric bound exceeded");
            }
            Ok(value)
        };
        let capture_origin = if ["--capture-start-ns", "--capture-uncertainty-ns"]
            .iter()
            .any(|key| values.contains_key(key))
        {
            let uncertainty = required("--capture-uncertainty-ns")?;
            if !uncertainty.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("unsigned capture uncertainty required");
            }
            Some(RtspCaptureOrigin {
                start_ns: timestamp(required("--capture-start-ns")?)?,
                uncertainty_ns: uncertainty
                    .parse()
                    .map_err(|_| "capture uncertainty overflow")?,
            })
        } else {
            None
        };
        let _ = required("--generation")?;
        let page_list = values
            .get("--catalog-pages")
            .map(|value| catalog_pages(value))
            .transpose()?;
        if (page_list.is_some()
            && ["--catalog-slot", "--catalog-root"]
                .iter()
                .any(|key| values.contains_key(key)))
            || (page_list.is_none() && values.contains_key("--max-pages"))
        {
            return Err("page lists require their own exact selector and page bound");
        }
        let catalog_selected = [
            "--catalog-slot",
            "--catalog-root",
            "--catalog-pages",
            "--decode-clock",
            "--time-scale",
            "--max-windows",
        ]
        .iter()
        .any(|key| values.contains_key(key));
        if catalog_selected
            && ["--window-slot", "--window-root"]
                .iter()
                .any(|key| values.contains_key(key))
        {
            return Err("select one window, one catalog or one exact page list");
        }
        let (slot_key, root_key, frame_max, original_max, media_max) = if catalog_selected {
            (
                "--catalog-slot",
                "--catalog-root",
                catalog::MAX_FRAMES,
                catalog::MAX_ORIGINAL_BYTES,
                catalog::MAX_MEDIA_BYTES,
            )
        } else {
            (
                "--window-slot",
                "--window-root",
                MAX_FRAMES,
                MAX_ORIGINAL_BYTES,
                MAX_MEDIA_BYTES,
            )
        };
        let (slot, root) = match &page_list {
            Some(pages) => {
                let first = pages.first().ok_or("empty catalog page list")?;
                (first.slot.clone(), first.root)
            }
            None => (
                SlotName::parse(required(slot_key)?).map_err(|_| "invalid source slot")?,
                digest(required(root_key)?)?,
            ),
        };
        let request = RtspImportRequest {
            codec: match required("--codec")? {
                "avc" => RtspImportCodec::Avc,
                "hevc" => RtspImportCodec::Hevc,
                _ => return Err("codec must be avc or hevc"),
            },
            slot,
            root,
            source: RecordingScope {
                sensor: SensorId::parse(required("--sensor-id")?).map_err(|_| "invalid sensor")?,
                stream: StreamId::parse(required("--stream-id")?).map_err(|_| "invalid stream")?,
                generation: number("--generation", 0, u64::MAX)?,
                anchor: digest(required("--anchor")?)?,
                receive_clock: digest(required("--receive-clock")?)?,
            },
            receive_time: timestamp(required("--receive-time-ns")?)?,
            capture_origin,
            max_frames: number("--max-frames", frame_max as u64, frame_max as u64)? as usize,
            max_original_bytes: number("--max-original-bytes", original_max, original_max)?,
            max_media_bytes: number("--max-media-bytes", media_max, media_max)?,
        };
        let mut catalog = if catalog_selected {
            let _ = required("--time-scale")?;
            let selected = RtspCatalogImportRequest {
                codec: request.codec,
                slot: request.slot.clone(),
                root: request.root,
                scope: CatalogScope {
                    recording: request.source.clone(),
                    decode_clock: digest(required("--decode-clock")?)?,
                    time_scale: number("--time-scale", 0, u32::MAX as u64)? as u32,
                },
                receive_time: request.receive_time,
                capture_origin: request.capture_origin,
                max_windows: number(
                    "--max-windows",
                    catalog::MAX_WINDOWS as u64,
                    catalog::MAX_WINDOWS as u64,
                )? as usize,
                max_frames: request.max_frames,
                max_original_bytes: request.max_original_bytes,
                max_media_bytes: request.max_media_bytes,
            };
            selected.digest().map_err(|_| "invalid catalog request")?;
            Some(selected)
        } else {
            request.digest().map_err(|_| "invalid recording request")?;
            None
        };
        let pages = if let Some(pages) = page_list {
            let common = catalog.take().ok_or("catalog page scope required")?;
            let selected = RtspCatalogPagesImportRequest {
                codec: common.codec,
                pages,
                scope: common.scope,
                receive_time: common.receive_time,
                capture_origin: common.capture_origin,
                max_pages: number(
                    "--max-pages",
                    pages::MAX_PAGES as u64,
                    pages::MAX_PAGES as u64,
                )? as usize,
                max_windows: common.max_windows,
                max_frames: common.max_frames,
                max_original_bytes: common.max_original_bytes,
                max_media_bytes: common.max_media_bytes,
            };
            selected
                .digest()
                .map_err(|_| "invalid catalog page selection")?;
            Some(selected)
        } else {
            None
        };
        let archive = path(required("--archive")?)?;
        let root = path(required("--root")?)?;
        if archive.starts_with(&root) || root.starts_with(&archive) {
            return Err("distinct non-nested stores required");
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
        Ok(Self {
            archive,
            root,
            site,
            principal,
            request,
            catalog,
            pages,
            work: number("--max-work", 1_000_000_000_000, 1_000_000_000_000_000)?,
            timeout_ms: number("--timeout-ms", 30_000, 600_000)?,
            approve: values
                .get("--approve")
                .map(|text| digest(text))
                .transpose()?,
        })
    }

    pub fn request_digest(&self) -> Result<ContentDigest, &'static str> {
        if let Some(request) = &self.pages {
            return request
                .digest()
                .map_err(|_| "invalid catalog page selection");
        }
        match &self.catalog {
            Some(request) => request.digest().map_err(|_| "invalid catalog request"),
            None => self
                .request
                .digest()
                .map_err(|_| "invalid recording request"),
        }
    }

    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut encoded = CanonicalEncoder::new();
        encoded.text(if self.pages.is_some() {
            "fss.rtsp_catalog_pages_import_cli_plan.v1"
        } else if self.catalog.is_some() {
            "fss.rtsp_catalog_import_cli_plan.v1"
        } else {
            "fss.rtsp_recording_import_cli_plan.v1"
        });
        encoded.text("original-read:source-closed-destination-retention:no-network:v1");
        encoded.digest(self.request_digest()?);
        encoded.text(self.archive.to_str().ok_or("UTF-8 path required")?);
        encoded.text(self.root.to_str().ok_or("UTF-8 path required")?);
        encoded.text(&self.site);
        encoded.text(&self.principal);
        encoded.u64(self.work);
        encoded.u64(self.timeout_ms);
        Ok(ContentDigest::sha256(&encoded.finish()))
    }

    pub fn preview(&self) -> Result<String, &'static str> {
        let request = &self.request;
        let mut fields = vec![
            (
                "format",
                string(if self.pages.is_some() {
                    PAGES_FORMAT
                } else if self.catalog.is_some() {
                    CATALOG_FORMAT
                } else {
                    FORMAT
                }),
            ),
            ("kind", string("plan")),
            ("approval_digest", string(&self.approval()?.to_text())),
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
            ("request_digest", string(&self.request_digest()?.to_text())),
            ("codec", string(request.codec.as_str())),
            (
                if self.pages.is_some() {
                    "first_catalog_slot"
                } else if self.catalog.is_some() {
                    "catalog_slot"
                } else {
                    "window_slot"
                },
                string(request.slot.as_str()),
            ),
            (
                if self.pages.is_some() {
                    "first_catalog_root"
                } else if self.catalog.is_some() {
                    "catalog_root"
                } else {
                    "window_root"
                },
                string(&request.root.to_text()),
            ),
            ("sensor_id", string(request.source.sensor.as_str())),
            ("stream_id", string(request.source.stream.as_str())),
            ("generation", request.source.generation.to_string()),
            ("source_anchor", string(&request.source.anchor.to_text())),
            (
                "receive_clock",
                string(&request.source.receive_clock.to_text()),
            ),
            (
                "receive_time_ns",
                string(&request.receive_time.0.to_string()),
            ),
            (
                "capture_time_label",
                string(if request.capture_origin.is_some() {
                    "operator_assumption"
                } else {
                    "unknown"
                }),
            ),
            (
                "capture_origin",
                request.capture_origin.map_or_else(
                    || "null".into(),
                    |origin| {
                        object(&[
                            ("start_ns", string(&origin.start_ns.0.to_string())),
                            ("uncertainty_ns", origin.uncertainty_ns.to_string()),
                        ])
                    },
                ),
            ),
            (
                "sample_timing",
                string("retained_mp4_presentation_timestamps"),
            ),
            ("maximum_frames", request.max_frames.to_string()),
            (
                "maximum_original_bytes",
                request.max_original_bytes.to_string(),
            ),
            ("maximum_media_bytes", request.max_media_bytes.to_string()),
            ("maximum_work", self.work.to_string()),
            ("timeout_ms", self.timeout_ms.to_string()),
            ("writes", string("none")),
            ("network", string("none")),
            (
                "retention",
                string(if self.pages.is_some() {
                    "every_selected_catalog_and_every_original_window_rtp_index_initialization_and_fragment_in_destination"
                } else if self.catalog.is_some() {
                    "complete_catalog_and_every_original_window_rtp_index_initialization_and_fragment_in_destination"
                } else {
                    "original_recording_root_rtp_index_initialization_and_fragment_in_destination"
                }),
            ),
        ];
        if let Some(catalog) = &self.catalog {
            fields.extend([
                (
                    "decode_clock",
                    string(&catalog.scope.decode_clock.to_text()),
                ),
                ("time_scale", catalog.scope.time_scale.to_string()),
                ("maximum_windows", catalog.max_windows.to_string()),
                ("selection", string("complete_catalog_page")),
                (
                    "composition",
                    string("adjacent_decode_intervals_identical_initialization"),
                ),
            ]);
        }
        if let Some(pages) = &self.pages {
            fields.extend([
                ("catalog_pages", page_selection_json(pages)),
                ("pages", pages.pages.len().to_string()),
                ("maximum_pages", pages.max_pages.to_string()),
                ("decode_clock", string(&pages.scope.decode_clock.to_text())),
                ("time_scale", pages.scope.time_scale.to_string()),
                ("maximum_windows", pages.max_windows.to_string()),
                ("selection", string("complete_ordered_catalog_pages")),
                (
                    "composition",
                    string("adjacent_decode_intervals_identical_initialization"),
                ),
            ]);
        }
        Ok(object(&fields))
    }
}

pub(super) fn page_selection_json(request: &RtspCatalogPagesImportRequest) -> String {
    array(
        &request
            .pages
            .iter()
            .map(|page| {
                object(&[
                    ("slot", string(page.slot.as_str())),
                    ("root", string(&page.root.to_text())),
                ])
            })
            .collect::<Vec<_>>(),
    )
}
