#![forbid(unsafe_code)]
//! Local operator authority, exact publication and separately approved private delivery.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use fss_cli::agent_json::{evidence_anchor, object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CanonicalEncoder, CaptureInterval, ContentDigest, OperationId};
use fss_reference::evidence_export::{CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE};
use fss_reference::review_media::{
    CAP_REVIEW_MEDIA_READ, ReviewMediaRecord, ReviewedMedia, commit_review_media,
    inspect_review_media, prepare_review_media, read_review_media, revalidate_review_media,
    review_grant_revoked, revocation_approval, revoke_review_media,
};
use fss_reference::{DeploymentLayout, ReferenceDeployment, ReplayCx};

use super::super::RunResult;
use super::options::{Action, Options};
use super::private_output::PrivateOutputPath;

const MAX_REPORT_BYTES: usize = 512 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const IO_CHUNK_BYTES: usize = 64 * 1024;

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

/// The held directory and canonical pathname jointly bind approval. No ambient pathname can
/// select a replacement directory after preparation, and creation is always exclusive.
struct Destination {
    output: PrivateOutputPath,
    binding: ContentDigest,
    #[cfg(unix)]
    identity: (u64, u64),
}

impl Destination {
    fn prepare(path: &Path, root: &Path, cx: &ReplayCx) -> RunResult<Self> {
        if !cfg!(target_os = "linux") {
            return Err(refused("private review delivery requires Linux directory handles").into());
        }
        let output = PrivateOutputPath::prepare(path, root, cx)?;
        let destination = output.destination();
        let parent = destination
            .parent()
            .ok_or_else(|| refused("review destination requires a parent directory"))?;
        let metadata = fs::symlink_metadata(parent)?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.review_media_cli_destination.v1");
        encoder.bytes(destination.as_os_str().as_encoded_bytes());
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
                return Err(
                    refused("review output parent must forbid group and world writes").into(),
                );
            }
            encoder.u64(metadata.dev());
            encoder.u64(metadata.ino());
            (metadata.dev(), metadata.ino())
        };
        #[cfg(not(unix))]
        let _ = metadata;
        let value = Self {
            output,
            binding: ContentDigest::sha256(&encoder.finish_checked()?),
            #[cfg(unix)]
            identity,
        };
        value.check(cx)?;
        Ok(value)
    }

    fn check(&self, cx: &ReplayCx) -> RunResult<()> {
        self.output.check(cx)?;
        let path = self.output.destination();
        let parent = path
            .parent()
            .ok_or_else(|| refused("review output parent changed"))?;
        let metadata = fs::symlink_metadata(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !metadata.is_dir()
                || metadata.mode() & 0o022 != 0
                || (metadata.dev(), metadata.ino()) != self.identity
            {
                return Err(refused("review output parent identity or protection changed").into());
            }
        }
        #[cfg(not(unix))]
        let _ = metadata;
        Ok(())
    }
}

fn delivery_approval(
    options: &Options,
    media: &ReviewedMedia,
    now: CaptureInterval,
    target: &Destination,
) -> RunResult<ContentDigest> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.review_media_cli_delivery_approval.v1");
    encoder.text(&options.site);
    encoder.text(&options.principal);
    encoder.digest(media.root());
    encoder.digest(media.record().digest());
    encoder.digest(media.media_digest());
    encoder.u64(media.bytes().len() as u64);
    encoder.i128(now.earliest.0);
    encoder.i128(now.latest.0);
    encoder.digest(target.binding);
    Ok(ContentDigest::sha256(&encoder.finish_checked()?))
}

fn delivery_report(
    options: &Options,
    media: &ReviewedMedia,
    now: CaptureInterval,
    target: &Destination,
    approval: ContentDigest,
    written: bool,
) -> RunResult<String> {
    bounded(object(&[
        ("format", string("fss.review_media_cli.v1")),
        ("site", string(&options.site)),
        (
            "status",
            string(if written {
                "private_file_written"
            } else {
                "awaiting_file_approval"
            }),
        ),
        ("review_root", string(&media.root().to_text())),
        ("record_digest", string(&media.record().digest().to_text())),
        ("media_digest", string(&media.media_digest().to_text())),
        ("media_bytes", media.bytes().len().to_string()),
        ("media_type", string("video/x-matroska")),
        ("approval_digest", string(&approval.to_text())),
        ("destination_binding", string(&target.binding.to_text())),
        ("recipient", string(&options.principal)),
        (
            "attested_now_ns",
            object(&[
                ("earliest", string(&now.earliest.0.to_string())),
                ("latest", string(&now.latest.0.to_string())),
            ]),
        ),
        ("file_written", written.to_string()),
        ("recipient_authenticated", "false".into()),
        ("trusted_clock_used", "false".into()),
        ("external_transport_performed", "false".into()),
        ("delivery_receipt_in_deployment", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ]))
}

fn read_to_file(
    options: &Options,
    deployment: &ReferenceDeployment,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> RunResult<String> {
    let Action::Read {
        root,
        attested_now,
        output,
        approval,
    } = &options.action
    else {
        return Err(refused("review delivery requires explicit read action").into());
    };
    let target = Destination::prepare(output, &options.root, cx)?;
    let media = read_review_media(deployment, *root, *attested_now, authority, cx)?;
    let expected = delivery_approval(options, &media, *attested_now, &target)?;
    let Some(approval) = approval else {
        return delivery_report(options, &media, *attested_now, &target, expected, false);
    };
    if *approval != expected {
        return Err(
            refused("review file approval does not match exact destination and grant").into(),
        );
    }
    // Finish bounded metadata before creating an output; no serialization failure can turn a
    // successful copy into a fabricated complete response.
    let report = delivery_report(options, &media, *attested_now, &target, expected, true)?;
    target.check(cx)?;
    revalidate_review_media(deployment, &media, *attested_now, authority, cx)?;
    let mut file = target.output.create(cx)?;
    for chunk in media.bytes().chunks(IO_CHUNK_BYTES) {
        cx.checkpoint("review_cli:write_screened_media")?;
        target.check(cx)?;
        file.write_all(chunk)?;
    }
    target.output.sync(&file, cx)?;
    target.check(cx)?;
    revalidate_review_media(deployment, &media, *attested_now, authority, cx)?;
    Ok(report)
}

pub(super) fn run(options: &Options) -> RunResult<String> {
    let mut capabilities = vec!["ADP-REPLAY-001".to_owned()];
    match &options.action {
        Action::Read { .. } => capabilities.push(CAP_REVIEW_MEDIA_READ.into()),
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
            Action::Read { .. } => read_to_file(options, &deployment, &authority, &cx),
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
