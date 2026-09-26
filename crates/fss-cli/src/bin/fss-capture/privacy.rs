#![forbid(unsafe_code)]
//! The existing retained mask authority for optional full native recording decode.
use std::collections::BTreeMap;
use std::path::{Component, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CanonicalEncoder, ContentDigest, OperationId, SensorId};
use fss_reference::ingest::http_replay::check::HttpCheckDecode;
use fss_reference::ingest::privacy_mask::live::{MaskedLuma, SensorMask};
use fss_reference::{ReferenceDeployment, ReplayCx};

#[derive(Debug)]
pub(super) struct Options {
    root: PathBuf,
    site: String,
    sensor: SensorId,
}
impl Options {
    pub(super) fn parse(values: &BTreeMap<&str, &str>, decode: HttpCheckDecode, archive: &std::path::Path) -> Result<Option<Self>, &'static str> {
        let keys = ["--privacy-root", "--site", "--sensor"];
        let supplied = keys.iter().filter(|k| values.contains_key(**k)).count();
        if decode == HttpCheckDecode::None {
            if supplied != 0 { return Err("privacy options require an explicit decode mode"); }
            return Ok(None);
        }
        if supplied != keys.len() { return Err("decoded capture requires --privacy-root, --site and --sensor"); }
        let get = |k: &str| values.get(k).copied().ok_or("missing privacy option");
        let root = PathBuf::from(get("--privacy-root")?);
        if !root.is_absolute() || root.parent().is_none()
            || root.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || root.starts_with(archive) || archive.starts_with(&root)
        { return Err("privacy and archive roots must be separate absolute non-nested paths"); }
        let site = get("--site")?.to_owned();
        fss_reference::reference_deployment::validate_site_lineage(&site).map_err(|_| "invalid privacy site")?;
        if site.len() > 256 { return Err("privacy site byte bound"); }
        let sensor = SensorId::parse(get("--sensor")?).map_err(|_| "invalid privacy sensor")?;
        Ok(Some(Self { root, site, sensor }))
    }
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(self.root.to_str().unwrap_or("invalid-non-utf8-privacy-root"));
        e.text(&self.site); e.text(self.sensor.as_str());
        e.text("sensor-current-retained-mask-before-pixel-digest:no-raw-export:v1");
    }
    pub(super) fn to_json(&self) -> String {
        object(&[("root", string(self.root.to_str().unwrap_or(""))), ("site", string(&self.site)),
            ("sensor", string(self.sensor.as_str())), ("policy", string("current_retained_binding_resolved_at_execution"))])
    }
    pub(super) fn open(&self, principal: &str) -> Result<Context, &'static str> {
        // Do not let the ReplayCx constructor create a replacement privacy deployment.
        if !std::fs::symlink_metadata(&self.root).is_ok_and(|m| m.file_type().is_dir())
            || !std::fs::symlink_metadata(self.root.join("LAYOUT")).is_ok_and(|m| m.file_type().is_file())
        { return Err("ERR-CAPTURE-PRIVACY-001"); }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:http-capture-privacy".into(),
            operation_id: OperationId::parse("operation:http-capture-privacy").map_err(|_| "ERR-CAPTURE-PRIVACY-001")?,
            principal: principal.to_owned(), capabilities: vec!["ADP-REPLAY-001".into(), "CAP-MEDIA-DECODE-001".into()],
            deadline: None, priority: 10,
            budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).storage_operations(8192).build().map_err(|_| "ERR-CAPTURE-PRIVACY-001")?,
            privacy_scope: "privacy:owner-named-recording-sensor".into(), retention_scope: "retention:existing-deployment-policy".into(),
            anchor_universe: ContentDigest::sha256(self.site.as_bytes()), generation: 1,
        }).map_err(|_| "ERR-CAPTURE-PRIVACY-001")?;
        authority.validate().map_err(|_| "ERR-CAPTURE-PRIVACY-001")?;
        let cx = ReplayCx::from_context_authority(&authority, self.root.clone()).map_err(|_| "ERR-CAPTURE-PRIVACY-001")?;
        let deployment = match ReferenceDeployment::reopen(&self.root, &self.site, &cx) {
            Ok(d) => d,
            Err(_) => { cx.drain_and_finalize(); return Err("ERR-CAPTURE-PRIVACY-001"); },
        };
        let context = Context { deployment, cx, sensor: self.sensor.clone() };
        // Reject damaged retained policy before the native connection is attempted.
        context.sensor().resolve().map_err(|_| "ERR-CAPTURE-PRIVACY-001")?;
        Ok(context)
    }
}

pub(super) struct Context { deployment: ReferenceDeployment, cx: ReplayCx, sensor: SensorId }
impl Context {
    pub(super) fn sensor(&self) -> SensorMask<'_> { SensorMask::new(&self.deployment, &self.sensor) }
}
impl Drop for Context {
    fn drop(&mut self) { self.cx.drain_and_finalize(); }
}

pub(super) fn label(mode: HttpCheckDecode) -> &'static str {
    match mode { HttpCheckDecode::None => "none", HttpCheckDecode::Grayscale => "grayscale", HttpCheckDecode::YCbCr => "ycbcr" }
}
pub(super) fn frame_json(decoded: Option<&MaskedLuma>) -> String {
    decoded.map_or_else(|| object(&[("state", string("not_requested"))]), |d| {
        let [width, height] = d.dimensions();
        object(&[("state", string("native_luma_verified")), ("width", width.to_string()), ("height", height.to_string()),
            ("luma_digest", string(&super::byte_digest(d.receipt().luma_sha256))),
            ("privacy", string(if d.mask_policy().is_some() { "retained_policy_applied" } else { "explicit_no_policy" })),
            ("policy_digest", d.mask_policy().map_or_else(|| "null".into(), |p| string(&p.to_text()))),
            ("policy_generation", super::optional_number(d.mask_generation())), ("pixels_emitted", "false".into())])
    })
}
