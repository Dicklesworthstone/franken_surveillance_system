#![forbid(unsafe_code)]
//! Local operator authority, exact publication and separately approved private delivery.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use fss_cli::agent_json::{evidence_anchor, object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_reference::deletion::DeletionIndex;
use fss_reference::evidence_export::{CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE};
use fss_reference::review_media::{
    CAP_REVIEW_MEDIA_READ, ReviewMediaRecord, commit_review_media, inspect_review_media,
    prepare_review_media, review_grant_revoked, revocation_approval, revoke_review_media,
};
use fss_reference::{DeploymentLayout, ReferenceDeployment, ReplayCx};

use super::super::RunResult;
use super::options::{Action, Options};

const MAX_REPORT_BYTES: usize = 512 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;

fn refused(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn preflight(root: &Path, site: &str, cx: &ReplayCx) -> RunResult<PathBuf> {
    cx.checkpoint("review_cli:preflight")?;
    if !fs::symlink_metadata(root)?.file_type().is_dir() {
        return Err(refused("existing non-symlink deployment required").into());
    }
    let root = fs::canonicalize(root)?;
    let path = root.join("LAYOUT");
    let before = fs::symlink_metadata(&path)?;
    if !before.file_type().is_file() || before.len() > 4096 {
        return Err(refused("regular bounded existing deployment layout required").into());
    }
    let mut opening = OpenOptions::new();
    opening.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opening.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = opening.open(&path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > 4096 {
        return Err(refused("deployment layout changed").into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(refused("deployment layout identity changed").into());
        }
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(refused("deployment layout exceeds bound").into());
    }
    let layout = DeploymentLayout::parse_canonical_text(std::str::from_utf8(&bytes)?)?;
    if layout.site_lineage != site {
        return Err(refused("deployment site mismatch").into());
    }
    for relative in [layout.ledger_relpath, layout.effects_relpath] {
        cx.checkpoint("review_cli:journal_preflight")?;
        let metadata = fs::symlink_metadata(root.join(relative))?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_JOURNAL_BYTES {
            return Err(refused("regular bounded existing journal required").into());
        }
    }
    Ok(root)
}

fn bounded(report: String) -> RunResult<String> {
    if report.len() > MAX_REPORT_BYTES {
        return Err(refused("review report exceeds byte bound").into());
    }
    Ok(report)
}

fn report(
    options: &Options,
    status: &str,
    record: &ReviewMediaRecord,
    approval: Option<ContentDigest>,
    published: bool,
    anchor: &fss_core::LedgerAnchor,
    revoked: Option<bool>,
) -> RunResult<String> {
    bounded(object(&[
        ("format", string("fss.review_media_cli.v1")),
        ("site", string(&options.site)),
        ("status", string(status)),
        ("published", published.to_string()),
        (
            "grant_revoked",
            revoked.map_or_else(|| "null".into(), |value| value.to_string()),
        ),
        ("review_root", string(&record.root().to_text())),
        ("record_digest", string(&record.digest().to_text())),
        (
            "approval_digest",
            approval.map_or_else(|| "null".into(), |digest| string(&digest.to_text())),
        ),
        ("authority_anchor", evidence_anchor(anchor)),
        ("record", record.to_json()),
        ("external_transport_performed", "false".into()),
        ("recipient_authenticated", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ]))
}

pub(super) fn run(options: &Options) -> RunResult<String> {
    let mut capabilities = vec!["ADP-REPLAY-001".to_owned()];
    match &options.action {
        Action::Read { approval, .. } => {
            capabilities.push(CAP_REVIEW_MEDIA_READ.into());
            if approval.is_some() {
                capabilities.push(CAP_EXPORT_COMMIT.into());
            }
        }
        Action::DeliveryShow { .. } => capabilities.push(CAP_REVIEW_MEDIA_READ.into()),
        Action::Publish { approval, .. } => {
            capabilities.push(CAP_EXPORT_PREPARE.into());
            capabilities.push(CAP_REVIEW_MEDIA_READ.into());
            if approval.is_some() {
                capabilities.push(CAP_EXPORT_COMMIT.into());
            }
        }
        Action::Show { .. } => capabilities.push(CAP_EXPORT_PREPARE.into()),
        Action::Revoke { approval, .. } => {
            capabilities.push(CAP_EXPORT_PREPARE.into());
            if approval.is_some() {
                capabilities.push(CAP_EXPORT_COMMIT.into());
            }
        }
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:review-media-cli".into(),
        operation_id: OperationId::parse("operation:review-media-cli")?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(2 * 1024 * 1024 * 1024)
            .storage_operations(262_144)
            .build()?,
        privacy_scope: "privacy:screened-review-media-v1".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    // Canonicalization admits only an existing root. The inspection constructor itself creates
    // nothing, so a misspelled root never bootstraps a new deployment during preview or read.
    let canonical_root = fs::canonicalize(&options.root)?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, canonical_root)?;
    let result = (|| -> RunResult<String> {
        let root = preflight(&options.root, &options.site, &cx)?;
        let mut deployment = ReferenceDeployment::open(&root, &options.site, &cx)?;
        match &options.action {
            Action::Publish {
                request,
                approval: None,
            } => {
                let preview = prepare_review_media(&deployment, request, &authority, &cx)?;
                report(
                    options,
                    if preview.already_committed() {
                        "already_published"
                    } else {
                        "awaiting_publication_approval"
                    },
                    preview.record(),
                    Some(preview.approval()),
                    false,
                    deployment.current_anchor(),
                    None,
                )
            }
            Action::Publish {
                request,
                approval: Some(approval),
            } => {
                let receipt =
                    commit_review_media(&mut deployment, request, *approval, &authority, &cx)?;
                let record = inspect_review_media(&deployment, receipt.root, &authority, &cx)?;
                report(
                    options,
                    if receipt.published {
                        "published"
                    } else {
                        "already_published"
                    },
                    &record,
                    Some(*approval),
                    receipt.published,
                    &receipt.anchor,
                    Some(false),
                )
            }
            Action::Show { root } => {
                let record = inspect_review_media(&deployment, *root, &authority, &cx)?;
                let revoked = review_grant_revoked(&deployment, *root, &authority, &cx)?;
                let deletions = DeletionIndex::read(&deployment)?;
                if let Some(entry) = deletions.review(*root) {
                    return bounded(object(&[
                        ("format", string("fss.review_media_deleted.v1")),
                        ("site", string(&options.site)),
                        ("status", string("deleted_review_metadata")),
                        ("review_root", string(&root.to_text())),
                        ("record_digest", string(&record.digest().to_text())),
                        ("record", record.to_json()),
                        ("media_access", string("denied")),
                        ("grant_revoked", revoked.to_string()),
                        ("deletion_plan_digest", string(&entry.plan_digest.to_text())),
                        ("deletion_complete", entry.is_complete().to_string()),
                        (
                            "completion_digest",
                            entry
                                .completion_digest
                                .map_or_else(|| "null".into(), |digest| string(&digest.to_text())),
                        ),
                        (
                            "authority_anchor",
                            evidence_anchor(deployment.current_anchor()),
                        ),
                        ("existing_copies_recalled", "false".into()),
                        ("external_transport_performed", "false".into()),
                        ("qualification", string("implemented_not_qualified")),
                    ]));
                }
                report(
                    options,
                    "verified_retained_review",
                    &record,
                    None,
                    false,
                    deployment.current_anchor(),
                    Some(revoked),
                )
            }
            Action::Read { .. } => super::delivery::run(options, &mut deployment, &authority, &cx),
            Action::DeliveryShow { identity } => {
                super::delivery::show(options, &deployment, *identity, &authority, &cx)
            }
            Action::Revoke {
                root,
                approval: None,
            } => {
                let approval = revocation_approval(&deployment, *root, &authority, &cx)?;
                let record = inspect_review_media(&deployment, *root, &authority, &cx)?;
                let revoked = review_grant_revoked(&deployment, *root, &authority, &cx)?;
                report(
                    options,
                    "awaiting_revocation_approval",
                    &record,
                    Some(approval),
                    false,
                    deployment.current_anchor(),
                    Some(revoked),
                )
            }
            Action::Revoke {
                root,
                approval: Some(approval),
            } => {
                let receipt =
                    revoke_review_media(&mut deployment, *root, *approval, &authority, &cx)?;
                bounded(object(&[
                    ("format", string("fss.review_media_cli.v1")),
                    ("site", string(&options.site)),
                    (
                        "status",
                        string(if receipt.published {
                            "revoked"
                        } else {
                            "already_revoked"
                        }),
                    ),
                    ("review_root", string(&receipt.root.to_text())),
                    ("published", receipt.published.to_string()),
                    ("approval_digest", string(&approval.to_text())),
                    ("authority_anchor", evidence_anchor(&receipt.anchor)),
                    ("existing_copies_recalled", "false".into()),
                    ("external_transport_performed", "false".into()),
                    ("qualification", string("implemented_not_qualified")),
                ]))
            }
        }
    })();
    cx.drain_and_finalize();
    result
}
