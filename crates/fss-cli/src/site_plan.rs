#![forbid(unsafe_code)]
//! Pure, atomic compilation of one site into existing native RTSP capture plans.
//!
//! A site digest is an inspectable planning result. This module does not validate
//! signed rights leases, grant capture authority, read credentials or execute plans.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use fss_core::{CanonicalEncoder, ContentDigest, PrincipalId};
use fss_reference::site::{ProbeCodec, SiteManifest, SiteProbeReceipt, SourceKind};

use crate::capture_plan::{prepare_jpeg, prepare_rtsp};
use crate::json_output::{array, object, string, strings};

/// Versioned site plan report schema.
pub const SITE_PLAN_SCHEMA: &str = "fss.site_capture_plan.v1";
/// Maximum complete report. Over-bound sites are refused, never truncated.
pub const MAX_SITE_PLAN_BYTES: usize = 2 * 1024 * 1024;
/// Stable refusal identity; `reason` and `source_index` locate the failed contract.
pub const ERR_SITE_PLAN: &str = "ERR-SITE-PLAN-001";

const POLICY: &str = "site-capture-plan:v1:manifest-and-probe-pinned:all-sources-or-none:\
existing-native-avc-hevc-planner:exact-ssrc-and-cadence:no-executor:no-rights-grant";
const JPEG_POLICY: &str = "site-capture-plan:v1:manifest-and-probe-pinned:all-sources-or-none:\
existing-native-avc-hevc-jpeg-planners:exact-ssrc:receipt-bound-cadence:receipt-bound-jpeg-retention:\
reserved-journal-parent-bound:no-executor:no-rights-grant";

/// Explicit operation coordinates supplied separately from the site manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SitePlanOptions {
    /// New nonzero capture-operation epoch; not a claim that the probe is still live.
    pub epoch: u64,
    /// Existing absolute parent for new per-source archive directories.
    pub archive_root: PathBuf,
    /// Independent existing absolute parent for new per-source pin journals.
    pub pins_root: PathBuf,
    /// Audit principal label; not authentication or a capability grant.
    pub principal: String,
    /// Bounded requested picture count per source.
    pub stop_after_pictures: u64,
}

/// A refusal that never includes an input URI, credential, private path or raw JSON.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SitePlanError {
    /// Stable machine identity.
    pub code: &'static str,
    /// Zero-based manifest source ordinal, when one source caused the refusal.
    pub source_index: Option<usize>,
    /// Static reason describing the unmet contract.
    pub reason: &'static str,
}

impl std::fmt::Display for SitePlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.reason)?;
        if let Some(index) = self.source_index {
            write!(formatter, " (source index {index})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SitePlanError {}

fn refused(reason: &'static str) -> SitePlanError {
    SitePlanError {
        code: ERR_SITE_PLAN,
        source_index: None,
        reason,
    }
}

fn source_refused(index: usize, reason: &'static str) -> SitePlanError {
    SitePlanError {
        code: ERR_SITE_PLAN,
        source_index: Some(index),
        reason,
    }
}

/// One unapproved, bounded native operation. Values contain no inline credentials.
/// Exact arguments are private operator material; diagnostic formatting omits them.
#[derive(Clone, Eq, PartialEq)]
pub struct SiteSourcePlan {
    source_index: usize,
    source_id: String,
    probe_digest: ContentDigest,
    argv: Vec<String>,
    native_approval: ContentDigest,
    native_preview: String,
}

impl std::fmt::Debug for SiteSourcePlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SiteSourcePlan")
            .field("source_index", &self.source_index)
            .field("source_id", &self.source_id)
            .field("probe_digest", &self.probe_digest)
            .field("native_approval", &self.native_approval)
            .field("argument_count", &self.argv.len())
            .finish_non_exhaustive()
    }
}

impl SiteSourcePlan {
    /// Zero-based source position in the original manifest.
    #[must_use]
    pub const fn source_index(&self) -> usize {
        self.source_index
    }
    /// Manifest source identity.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    /// Exact canonical receipt used to produce this operation.
    #[must_use]
    pub const fn probe_digest(&self) -> ContentDigest {
        self.probe_digest
    }
    /// Arguments to the existing `fss-capture-rtsp` binary, without `--approve`.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }
    /// Native operation digest, distinct from the enclosing site digest.
    #[must_use]
    pub const fn native_approval(&self) -> ContentDigest {
        self.native_approval
    }
    /// Exact native CLI plan for these arguments.
    #[must_use]
    pub fn native_preview(&self) -> &str {
        &self.native_preview
    }
}

/// An immutable complete site preview. Construction succeeds only for the whole site.
#[derive(Clone, Eq, PartialEq)]
pub struct SitePlan {
    approval: ContentDigest,
    sources: Vec<SiteSourcePlan>,
    report: String,
}

impl std::fmt::Debug for SitePlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SitePlan")
            .field("approval", &self.approval)
            .field("sources", &self.sources)
            .field("report_bytes", &self.report.len())
            .finish_non_exhaustive()
    }
}

impl SitePlan {
    /// Digest binding the full manifest, receipts, operation epoch and every native plan.
    #[must_use]
    pub const fn approval(&self) -> ContentDigest {
        self.approval
    }
    /// Complete manifest-order list of compiled source plans.
    #[must_use]
    pub fn sources(&self) -> &[SiteSourcePlan] {
        &self.sources
    }
    /// Complete bounded JSON report, including private operator path/route references.
    /// This report grants no effect authority; it is not a public diagnostic record.
    #[must_use]
    pub fn render_json(&self) -> String {
        self.report.clone()
    }
}

fn checked_base(path: &Path) -> Result<&str, SitePlanError> {
    let text = path
        .to_str()
        .ok_or_else(|| refused("UTF-8 output parent required"))?;
    if text.len() > 1024
        || !path.is_absolute()
        || path.file_name().is_none()
        || text.chars().any(char::is_control)
        || text.contains("//")
        || text
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(refused(
            "bounded absolute output parents without dot components required",
        ));
    }
    Ok(text)
}

fn validate_options(options: &SitePlanOptions) -> Result<(), SitePlanError> {
    checked_base(&options.archive_root)?;
    checked_base(&options.pins_root)?;
    if options.archive_root.starts_with(&options.pins_root)
        || options.pins_root.starts_with(&options.archive_root)
    {
        return Err(refused(
            "archive and independent journal parents must be separate and nonnested",
        ));
    }
    if options.epoch == 0 || !(1..=4096).contains(&options.stop_after_pictures) {
        return Err(refused(
            "nonzero epoch and picture count within the native reservation required",
        ));
    }
    if options.principal.len() > 256 || PrincipalId::parse(&options.principal).is_err() {
        return Err(refused("bounded audit principal required"));
    }
    Ok(())
}

fn identity(
    purpose: &str,
    site_id: &str,
    source_id: &str,
    manifest: ContentDigest,
    epoch: u64,
) -> Result<ContentDigest, SitePlanError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.site_capture_identity.v1");
    encoder.text(purpose);
    encoder.text(site_id);
    encoder.text(source_id);
    encoder.digest(manifest);
    encoder.u64(epoch);
    Ok(ContentDigest::sha256(
        &encoder
            .finish_checked()
            .map_err(|_| refused("identity encoding refused"))?,
    ))
}

fn add(argv: &mut Vec<String>, key: &str, value: impl ToString) {
    argv.extend([key.to_owned(), value.to_string()]);
}

fn stable_source_identity(
    purpose: &str,
    site: &str,
    source: &str,
) -> Result<ContentDigest, SitePlanError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.site_source_identity.v1");
    encoder.text(purpose);
    encoder.text(site);
    encoder.text(source);
    Ok(ContentDigest::sha256(&encoder.finish_checked().map_err(
        |_| refused("source identity encoding refused"),
    )?))
}

fn hex(digest: ContentDigest) -> String {
    // ContentDigest::to_text is the registered algorithm:hex spelling.
    digest.to_text()["sha256:".len()..].to_owned()
}

fn capture_timeout(pictures: u64, cadence: u32) -> Result<u64, SitePlanError> {
    let duration_ticks = pictures
        .checked_mul(u64::from(cadence))
        .ok_or_else(|| refused("capture duration overflow"))?;
    let duration_ms = duration_ticks
        .checked_mul(1000)
        .ok_or_else(|| refused("capture duration overflow"))?
        .div_ceil(90_000);
    let timeout = duration_ms
        .checked_add(15_000)
        .ok_or_else(|| refused("capture duration overflow"))?
        .max(30_000);
    if timeout > 600_000 {
        return Err(refused(
            "requested pictures and observed cadence exceed the native deadline ceiling",
        ));
    }
    Ok(timeout)
}

/// Compile an entire validated site into native AVC/HEVC/JPEG capture previews.
///
/// Manifest and receipt validation is repeated for typed callers. Receipts must form an
/// exact one-to-one inventory of the manifest, with the same site, manifest generation,
/// source generation and route. Receipt ordering is immaterial; output follows manifest
/// order. Any refusal discards the complete result, including already-prepared sources.
///
/// The supplied receipt is historical evidence, not authentication or current liveness.
/// Source permission declarations must be explicit; signed FLDT verdict verification and
/// site execution remain unavailable. Original-byte recording cannot apply payment masks,
/// so payment-zone sources are refused before constructing a permitted native request.
pub fn compile(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
) -> Result<SitePlan, SitePlanError> {
    validate_options(options)?;
    manifest
        .validate()
        .map_err(|_| refused("site manifest contract refused"))?;
    let manifest_digest = manifest
        .digest()
        .map_err(|_| refused("site manifest identity refused"))?;

    let mut indices = BTreeMap::new();
    for (index, source) in manifest.sources.iter().enumerate() {
        if indices.insert(source.source_id.as_str(), index).is_some() {
            return Err(source_refused(index, "duplicate source identity"));
        }
        if !matches!(source.kind, SourceKind::Rtsp | SourceKind::NvrChannel) {
            return Err(source_refused(
                index,
                "source kind requires an onboarding path not supported by this compiler",
            ));
        }
        if !source.owner_authorized || !source.plaintext || !source.retain_originals {
            return Err(source_refused(
                index,
                "owner, plaintext and original-retention declarations must all be explicit",
            ));
        }
        if !source.payment_masks.is_empty()
            || source.zones.iter().any(|zone| {
                matches!(
                    zone.kind.as_str(),
                    "payment" | "payment_terminal" | "lane_pay"
                )
            })
        {
            return Err(source_refused(
                index,
                "payment-zone source requires masking before original retention; this capture path cannot enforce it",
            ));
        }
        if let Some(authentication) = &source.authentication {
            // Reserve the whole parent namespace: another source or future epoch must
            // never turn a credential file into a capture output or journal descendant.
            if [&options.archive_root, &options.pins_root]
                .iter()
                .any(|base| {
                    authentication.credential_file.starts_with(base)
                        || base.starts_with(&authentication.credential_file)
                })
            {
                return Err(source_refused(
                    index,
                    "credential references must be outside all archive and journal output namespaces",
                ));
            }
        }
    }

    if receipts.len() > manifest.sources.len() {
        return Err(refused(
            "probe inventory contains extra or duplicate source receipts",
        ));
    }
    let mut probes = BTreeMap::new();
    for receipt in receipts {
        let index = *indices
            .get(receipt.source_id.as_str())
            .ok_or_else(|| refused("probe inventory contains a foreign source"))?;
        receipt
            .validate()
            .map_err(|_| source_refused(index, "probe evidence contract refused"))?;
        if receipt.site_id != manifest.site_id {
            return Err(source_refused(index, "probe belongs to a different site"));
        }
        if receipt.manifest_digest != manifest_digest {
            return Err(source_refused(
                index,
                "probe does not bind the exact current manifest",
            ));
        }
        if receipt.source_generation != manifest.sources[index].generation {
            return Err(source_refused(
                index,
                "probe source generation is stale or foreign",
            ));
        }
        receipt.validate_for(manifest).map_err(|_| {
            source_refused(
                index,
                "probe route or source binding differs from the manifest",
            )
        })?;
        if probes.insert(index, receipt).is_some() {
            return Err(source_refused(index, "duplicate probe receipt for source"));
        }
    }
    for index in 0..manifest.sources.len() {
        if !probes.contains_key(&index) {
            return Err(source_refused(index, "source has no exact probe receipt"));
        }
    }

    // Keep existing AVC/HEVC approvals byte-for-byte stable. JPEG source capture
    // has a different custody format and no pin-journal argument, so its site
    // policy explicitly binds the still-reserved independent journal parent.
    let includes_jpeg = probes.values().any(|probe| probe.codec == ProbeCodec::Jpeg);
    let policy = if includes_jpeg { JPEG_POLICY } else { POLICY };
    let mut sources = Vec::with_capacity(manifest.sources.len());
    let mut source_reports = Vec::with_capacity(manifest.sources.len());
    let mut ingress_ids = BTreeSet::new();
    let mut output_scopes = BTreeSet::new();
    let mut report_bytes = 0usize;
    let mut approval = CanonicalEncoder::new();
    approval.text(SITE_PLAN_SCHEMA);
    approval.text(policy);
    approval.digest(manifest_digest);
    approval.u64(options.epoch);
    approval.u64(manifest.sources.len() as u64);
    if includes_jpeg {
        approval.text(checked_base(&options.pins_root)?);
    }

    for (index, source) in manifest.sources.iter().enumerate() {
        let probe = probes
            .get(&index)
            .ok_or_else(|| source_refused(index, "source has no exact probe receipt"))?;
        let is_jpeg = probe.codec == ProbeCodec::Jpeg;
        if probe.rtp_channel.checked_add(1) != Some(probe.rtcp_channel) {
            return Err(source_refused(
                index,
                "native capture requires adjacent RTP and RTCP channels",
            ));
        }
        let probe_digest = probe
            .digest()
            .map_err(|_| source_refused(index, "probe identity refused"))?;
        let scope = identity(
            "output-scope",
            &manifest.site_id,
            &source.source_id,
            manifest_digest,
            options.epoch,
        )?;
        if !output_scopes.insert(scope) {
            return Err(source_refused(index, "source output identity collision"));
        }
        let sensor = stable_source_identity("sensor", &manifest.site_id, &source.source_id)?;
        let stream = stable_source_identity("stream", &manifest.site_id, &source.source_id)?;
        let mut ingress_bytes = [0_u8; 16];
        ingress_bytes.copy_from_slice(&stream.bytes()[..16]);
        let ingress = u128::from_be_bytes(ingress_bytes);
        if ingress == 0 || !ingress_ids.insert(ingress) {
            return Err(source_refused(index, "source ingress identity collision"));
        }
        let coordinate = |purpose| {
            identity(
                purpose,
                &manifest.site_id,
                &source.source_id,
                manifest_digest,
                options.epoch,
            )
        };
        // The JPEG retention reference binds this declared source scope and exact
        // receipt. It is evidence identity only, never a verified rights verdict.
        let mut evidence = CanonicalEncoder::new();
        evidence.text(if is_jpeg {
            "fss.site_probe_retention.v1"
        } else {
            "fss.site_probe_timing.v1"
        });
        evidence.digest(coordinate(if is_jpeg {
            "retention-evidence"
        } else {
            "timing-evidence"
        })?);
        evidence.digest(probe_digest);
        let evidence = ContentDigest::sha256(&evidence.finish_checked().map_err(|_| {
            source_refused(
                index,
                if is_jpeg {
                    "retention evidence encoding refused"
                } else {
                    "timing evidence encoding refused"
                },
            )
        })?);
        let archive = options.archive_root.join(hex(scope));
        let pins = options.pins_root.join(hex(scope));
        let timeout = capture_timeout(options.stop_after_pictures, probe.frame_duration_ticks)
            .map_err(|error| source_refused(index, error.reason))?;

        let mut argv = Vec::with_capacity(64);
        if is_jpeg {
            argv.push("jpeg".to_owned());
        }
        add(
            &mut argv,
            "--root",
            archive
                .to_str()
                .ok_or_else(|| source_refused(index, "UTF-8 archive path required"))?,
        );
        if !is_jpeg {
            add(
                &mut argv,
                "--pins",
                pins.to_str()
                    .ok_or_else(|| source_refused(index, "UTF-8 journal path required"))?,
            );
        }
        add(&mut argv, "--peer", source.peer);
        add(&mut argv, "--authority", &source.authority);
        add(
            &mut argv,
            "--presentation",
            source
                .presentation
                .as_deref()
                .ok_or_else(|| source_refused(index, "source presentation path missing"))?,
        );
        add(
            &mut argv,
            "--control-root",
            source
                .control_root
                .as_deref()
                .ok_or_else(|| source_refused(index, "source control subtree missing"))?,
        );
        add(
            &mut argv,
            "--sensor-id",
            format!("sensor:site-{}", hex(sensor)),
        );
        add(
            &mut argv,
            "--stream-id",
            format!("stream:site-{}", hex(stream)),
        );
        add(&mut argv, "--generation", options.epoch);
        add(&mut argv, "--ingress", ingress);
        add(&mut argv, "--ssrc", probe.ssrc);
        add(
            &mut argv,
            "--anchor",
            coordinate("authority-anchor")?.to_text(),
        );
        add(
            &mut argv,
            "--receive-clock",
            coordinate("receive-clock")?.to_text(),
        );
        if is_jpeg {
            add(&mut argv, "--retention-evidence", evidence.to_text());
        } else {
            add(&mut argv, "--timing-evidence", evidence.to_text());
            add(&mut argv, "--journal-id", coordinate("journal")?.to_text());
            add(&mut argv, "--codec", probe.codec.as_str());
        }
        add(&mut argv, "--payload-type", probe.payload_type);
        add(&mut argv, "--media-index", probe.media_index);
        add(&mut argv, "--rtp-channel", probe.rtp_channel);
        if !is_jpeg {
            add(
                &mut argv,
                "--frame-duration-ticks",
                probe.frame_duration_ticks,
            );
        }
        add(
            &mut argv,
            "--stop-after-pictures",
            options.stop_after_pictures,
        );
        add(&mut argv, "--timeout-ms", timeout);
        add(&mut argv, "--principal", &options.principal);
        add(&mut argv, "--owner-authorized", "yes");
        add(&mut argv, "--plaintext", "yes");
        add(&mut argv, "--retain-originals", "yes");
        if let Some(authentication) = &source.authentication {
            add(
                &mut argv,
                "--credential-file",
                authentication
                    .credential_file
                    .to_str()
                    .ok_or_else(|| source_refused(index, "UTF-8 credential reference required"))?,
            );
            add(&mut argv, "--auth-realm", &authentication.realm);
            if authentication.legacy_md5 {
                add(&mut argv, "--legacy-md5", "yes");
            }
            if authentication.legacy_no_qop {
                add(&mut argv, "--legacy-no-qop", "yes");
            }
        }
        let os_args: Vec<OsString> = argv
            .iter()
            .skip(if is_jpeg { 1 } else { 0 })
            .map(OsString::from)
            .collect();
        let native = if is_jpeg {
            prepare_jpeg(&os_args)
        } else {
            prepare_rtsp(&os_args)
        }
        .map_err(|reason| source_refused(index, reason))?;
        approval.u64(index as u64);
        approval.text(&source.source_id);
        approval.digest(probe_digest);
        approval.digest(native.approval);

        let source_report = object(&[
            ("source_index", index.to_string()),
            ("source_id", string(&source.source_id)),
            ("source_generation", source.generation.to_string()),
            ("kind", string(source.kind.as_str())),
            ("stream_role", string(source.stream_role.as_str())),
            ("retention_class", string(&source.retention_class)),
            ("probe_digest", string(&probe_digest.to_text())),
            ("command", string("fss-capture-rtsp")),
            ("argv", strings(&argv)),
            ("native_approval", string(&native.approval.to_text())),
            ("native_plan", native.preview.clone()),
        ]);
        report_bytes = report_bytes
            .checked_add(source_report.len())
            .ok_or_else(|| refused("complete site report exceeds its bound"))?;
        if report_bytes > MAX_SITE_PLAN_BYTES {
            return Err(refused("complete site report exceeds its bound"));
        }
        source_reports.push(source_report);
        sources.push(SiteSourcePlan {
            source_index: index,
            source_id: source.source_id.clone(),
            probe_digest,
            argv,
            native_approval: native.approval,
            native_preview: native.preview,
        });
    }

    let approval = ContentDigest::sha256(
        &approval
            .finish_checked()
            .map_err(|_| refused("site approval encoding refused"))?,
    );
    let mut report_fields = vec![
        ("schema", string(SITE_PLAN_SCHEMA)),
        ("phase", string("planned")),
        ("policy", string(policy)),
        ("site_id", string(&manifest.site_id)),
        ("manifest_generation", manifest.generation.to_string()),
        ("manifest_digest", string(&manifest_digest.to_text())),
        ("epoch", options.epoch.to_string()),
        ("approval", string(&approval.to_text())),
        ("source_count", sources.len().to_string()),
        ("sources", array(&source_reports)),
        ("effects_started", "false".to_owned()),
        ("device_contacted", "false".to_owned()),
        ("credentials_read", "false".to_owned()),
        ("executor_available", "false".to_owned()),
        ("rights_leases_verified", "false".to_owned()),
        ("capture_authorized", "false".to_owned()),
        ("probe_liveness_verified", "false".to_owned()),
    ];
    if includes_jpeg {
        report_fields.push((
            "reserved_pins_root",
            string(checked_base(&options.pins_root)?),
        ));
    }
    let report = object(&report_fields);
    if report.len() > MAX_SITE_PLAN_BYTES {
        return Err(refused("complete site report exceeds its bound"));
    }
    Ok(SitePlan {
        approval,
        sources,
        report,
    })
}
