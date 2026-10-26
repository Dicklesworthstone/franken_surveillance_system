#![forbid(unsafe_code)]
//! Complete session-owned recovery metadata; no recipe file or remembered label is required.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fss_cli::agent_json::{array, evidence_anchor, object, string, supervision_inventory_entry};
use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, DigestAlgorithm, OperationId,
    PrincipalId, RootAuthoritySpec, SessionId,
};
use fss_reference::ReplayCx;
use fss_reference::agent_orient::OrientLimits;
use fss_reference::deployment_session::supervision::{
    SupervisionAdapterError, SupervisionInventoryBinding, SupervisionInventoryBoundary,
    SupervisionInventoryControl, SupervisionInventoryDelivery, SupervisionInventoryRequest,
    list_supervision,
};

use super::{Failure, Result, text};

const MAX_INVENTORY_BYTES: usize = 128 * 1024;

struct Control<'a> {
    root: &'a Path,
    principal: &'a PrincipalId,
    request: &'a SupervisionInventoryRequest,
    limits: OrientLimits,
    cx: &'a ReplayCx,
    boundaries: u32,
}

fn denied(reason: impl std::fmt::Display) -> SupervisionAdapterError {
    SupervisionAdapterError {
        identity: fss_cli::ERR_CLI_RUNTIME_FAILURE,
        reason: reason.to_string(),
    }
}

impl SupervisionInventoryControl for Control<'_> {
    fn admit_inventory(
        &mut self,
        binding: &SupervisionInventoryBinding<'_>,
        _: SupervisionInventoryBoundary,
    ) -> std::result::Result<(), SupervisionAdapterError> {
        if binding.root() != self.root
            || binding.principal() != self.principal
            || binding.request() != self.request
            || binding.limits() != &self.limits
            || self.cx.root_dir() != self.root
        {
            return Err(denied("supervision inventory binding differs"));
        }
        self.boundaries = self
            .boundaries
            .checked_add(1)
            .ok_or_else(|| denied("supervision inventory boundary budget exhausted"))?;
        if self.boundaries > 16 {
            return Err(denied("supervision inventory boundary budget exhausted"));
        }
        self.cx
            .checkpoint("retained_supervisor_session:inventory")
            .map_err(denied)
    }
}

fn render(delivery: &SupervisionInventoryDelivery) -> Result<String> {
    let mut fields = vec![
        ("schema", string("fss.retained_supervisor_inventory.v1")),
        ("session_id", string(delivery.session.session_id.as_str())),
        ("current_anchor", evidence_anchor(&delivery.head.anchor)),
        (
            "current_authority_root",
            string(&delivery.head.anchor.state_root.to_text()),
        ),
        (
            "current_ledger_root",
            string(&delivery.head.ledger_root.to_text()),
        ),
        (
            "current_effect_root",
            string(&delivery.head.effect_root.to_text()),
        ),
        ("journal_root", string(&delivery.journal_root.to_text())),
        (
            "subscriptions",
            array(
                &delivery
                    .subscriptions
                    .iter()
                    .map(supervision_inventory_entry)
                    .collect::<Vec<_>>(),
            ),
        ),
        ("complete", "true".to_owned()),
        ("native_attempts_reserved_by_listing", "0".to_owned()),
        ("sources_revalidated", "false".to_owned()),
        ("effects_authorized", "false".to_owned()),
        ("supports_absence_claim", "false".to_owned()),
    ];
    let unsigned = object(&fields);
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.retained_supervisor_inventory_receipt.v1");
    encoder.bytes(unsigned.as_bytes());
    let receipt = ContentDigest::sha256(&encoder.finish_checked().map_err(Failure::runtime)?);
    fields.push(("receipt_digest", string(&receipt.to_text())));
    let rendered = format!("{}\n", object(&fields));
    if rendered.len() > MAX_INVENTORY_BYTES {
        return Err(Failure::runtime(
            "complete supervision inventory exceeds output bound",
        ));
    }
    Ok(rendered)
}

pub(super) fn run(values: &BTreeMap<String, OsString>) -> Result<()> {
    if text(values, "--list")? != "yes"
        || values.keys().any(|key| {
            !matches!(
                key.as_str(),
                "--list"
                    | "--root"
                    | "--site"
                    | "--principal"
                    | "--session"
                    | "--authority-root"
                    | "--report-out"
            )
        })
    {
        return Err(Failure::malformed(
            "--list yes accepts only --root, --site, --principal, --session, --authority-root and --report-out",
        ));
    }
    let root = PathBuf::from(
        values
            .get("--root")
            .ok_or_else(|| Failure::malformed("required --root"))?,
    );
    let site = text(values, "--site")?;
    if site.is_empty() || site.len() > 256 || site.chars().any(char::is_control) {
        return Err(Failure::malformed("invalid --site"));
    }
    let principal = PrincipalId::parse(
        values
            .get("--principal")
            .map_or(Some("principal:local-operator"), |value| value.to_str())
            .ok_or_else(|| Failure::malformed("--principal requires UTF-8"))?,
    )
    .map_err(Failure::malformed)?;
    let expected_authority_root =
        ContentDigest::parse(text(values, "--authority-root")?).map_err(Failure::malformed)?;
    if expected_authority_root.algorithm() != DigestAlgorithm::Sha256
        || expected_authority_root.bytes() == [0; 32]
    {
        return Err(Failure::malformed(
            "--authority-root requires a nonzero SHA-256 digest",
        ));
    }
    let request = SupervisionInventoryRequest {
        session_id: SessionId::parse(text(values, "--session")?).map_err(Failure::malformed)?,
        expected_authority_root,
    };
    // ReplayCx may create a namespace; admit only an existing deployment before creating it.
    if !fs::symlink_metadata(&root).is_ok_and(|metadata| metadata.file_type().is_dir())
        || !fs::symlink_metadata(root.join("LAYOUT"))
            .is_ok_and(|metadata| metadata.file_type().is_file())
    {
        return Err(Failure::runtime("existing non-symlink deployment required"));
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-supervise-inventory".into(),
        operation_id: OperationId::parse("operation:event-supervise-inventory")
            .map_err(Failure::runtime)?,
        principal: principal.as_str().to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .build()
            .map_err(Failure::runtime)?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    })
    .map_err(Failure::runtime)?;
    let cx =
        ReplayCx::from_context_authority(&authority, root.clone()).map_err(Failure::runtime)?;
    let result =
        (|| {
            let limits = OrientLimits {
                max_journal_bytes: 32 * 1024 * 1024,
                ..OrientLimits::default()
            };
            let mut control = Control {
                root: &root,
                principal: &principal,
                request: &request,
                limits,
                cx: &cx,
                boundaries: 0,
            };
            let delivery = list_supervision(&root, &principal, &request, &limits, &mut control)
            .map_err(|error| Failure::runtime(format!(
                "{error}; journal_may_have_changed=true; native_attempts_reserved_by_listing=0",
            )))?;
            if delivery.head.anchor.site_lineage != site {
                return Err(Failure::malformed(
                    "deployment site_lineage does not match --site",
                ));
            }
            let rendered = render(&delivery)?;
            cx.checkpoint("retained_supervisor_inventory:output")
                .map_err(Failure::runtime)?;
            if let Some(path) = values.get("--report-out") {
                super::super::super::export(Path::new(path), rendered.as_bytes(), &root, &cx)
                    .map_err(Failure::runtime)?;
            }
            io::stdout()
                .lock()
                .write_all(rendered.as_bytes())
                .map_err(Failure::runtime)
        })();
    cx.drain_and_finalize();
    result
}
