#![forbid(unsafe_code)]
//! Restart recovery exercises the real guarded attempt, held output and CLI owner.

use std::io::Write;
use std::os::unix::fs::MetadataExt;

use fss_reference::evidence_export::CAP_EXPORT_COMMIT;
use fss_reference::review_media::delivery::begin_review_delivery;
use fss_reference::review_media::{CAP_REVIEW_MEDIA_READ, read_review_media};

use super::*;

fn published(directory: &Directory) -> Test<(PathBuf, String)> {
    let (root, request) = imported(directory)?;
    let preview = run(&request)?;
    let review_root = text(&preview, "review_root")?.to_owned();
    run(&approved(request, &preview)?)?;
    Ok((root, review_root))
}

/// Stop at a real durable cut point: begun, partially written, or synced without a receipt.
fn interrupted(read: &[OsString], complete: Option<bool>) -> Test<ContentDigest> {
    let preview = run(read)?;
    let options = super::super::options::parse(read).map_err(io::Error::other)?;
    let super::super::options::Action::Read {
        root,
        attested_now,
        output,
        ..
    } = &options.action
    else {
        return Err(io::Error::other("test requires a delivery request").into());
    };
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:review-media-cli".into(),
        operation_id: OperationId::parse("operation:review-media-cli")?,
        principal: options.principal.clone(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            CAP_REVIEW_MEDIA_READ.into(),
            CAP_EXPORT_COMMIT.into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(2 * 1024 * 1024 * 1024)
            .storage_operations(262_144)
            .build()?,
        privacy_scope: "privacy:screened-review-media-v1".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, options.root.clone())?;
    let mut deployment = ReferenceDeployment::open(&options.root, SITE, &cx)?;
    let target = super::super::destination::Destination::prepare(output, &options.root, &cx)?;
    let progress = begin_review_delivery(
        &mut deployment,
        *root,
        target.binding(),
        *attested_now,
        ContentDigest::parse(text(&preview, "approval_digest")?)?,
        &authority,
        &cx,
    )?;
    assert!(progress.started);
    if let Some(complete) = complete {
        let media = read_review_media(&deployment, *root, *attested_now, &authority, &cx)?;
        let mut file = target.create(&cx)?;
        let count = if complete {
            media.bytes().len()
        } else {
            media.bytes().len() / 2
        };
        file.write_all(&media.bytes()[..count])?;
        target.sync(&file, &cx)?;
    }
    let identity = progress.record.identity();
    drop(deployment);
    cx.drain_and_finalize();
    Ok(identity)
}

fn show(root: &Path, identity: ContentDigest, principal: &str) -> Vec<OsString> {
    args(
        root,
        "review-delivery-show",
        &[
            "--delivery-id",
            &identity.to_text(),
            "--principal",
            principal,
        ],
    )
}

#[test]
fn synced_output_without_receipt_reconciles_after_restart_without_rewriting() -> Test {
    let directory = Directory::new()?;
    let (root, review) = published(&directory)?;
    let output = directory.0.join("interrupted-complete.mkv");
    let read = delivery(&root, &review, &output, "principal:reviewer", "20:30");
    let identity = interrupted(&read, Some(true))?;
    let before = fs::read(&output)?;
    let inode = fs::metadata(&output)?.ino();
    let metadata = show(&root, identity, "principal:reviewer");
    let state = run(&metadata)?;
    assert_eq!(
        text(&state, "delivery_state")?,
        "started_outcome_indeterminate"
    );
    assert_eq!(
        json_field(&state, "current_destination_verified")?.boolean(),
        Some(false)
    );

    // A new current-time attestation gets fresh approval without changing the attempt.
    let retry = delivery(&root, &review, &output, "principal:reviewer", "40:50");
    let preview = run(&retry)?;
    assert_eq!(text(&preview, "delivery_id")?, identity.to_text());
    let retry = approved(retry, &preview)?;
    let result = run(&retry)?;
    assert_eq!(text(&result, "status")?, "private_file_reconciled");
    assert_eq!(text(&result, "delivery_state")?, "verified_local_file");
    assert_eq!(json_field(&result, "file_written")?.boolean(), Some(false));
    assert_eq!(fs::metadata(&output)?.ino(), inode);
    assert_eq!(fs::read(&output)?, before);
    let again = run(&retry)?;
    assert_eq!(text(&again, "status")?, "private_file_verified");
    assert_eq!(
        text(&again, "delivery_record_digest")?,
        text(&result, "delivery_record_digest")?
    );
    assert!(run(&show(&root, identity, "principal:other")).is_err());
    assert_eq!(
        text(&run(&metadata)?, "delivery_state")?,
        "verified_local_file"
    );
    Ok(())
}

#[test]
fn missing_or_partial_attempt_never_creates_overwrites_or_claims_completion() -> Test {
    let directory = Directory::new()?;
    let (root, review) = published(&directory)?;
    for (name, content) in [("missing", None), ("partial", Some(false))] {
        let output = directory.0.join(format!("{name}.mkv"));
        let read = delivery(&root, &review, &output, "principal:reviewer", "20:30");
        let identity = interrupted(&read, content)?;
        let before = fs::read(&output).ok();
        let preview = run(&read)?;
        assert!(run(&approved(read, &preview)?).is_err());
        assert_eq!(fs::read(&output).ok(), before);
        let status = run(&show(&root, identity, "principal:reviewer"))?;
        assert_eq!(
            text(&status, "delivery_state")?,
            "started_outcome_indeterminate"
        );
        assert_eq!(
            json_field(&status, "delivery_receipt_in_deployment")?.boolean(),
            Some(false)
        );
    }
    Ok(())
}

#[test]
fn unrecorded_replaced_linked_and_public_outputs_are_never_adopted() -> Test {
    let directory = Directory::new()?;
    let (root, review) = published(&directory)?;
    let unrelated = directory.0.join("unrecorded.mkv");
    fs::write(&unrelated, b"private but unrelated file")?;
    fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o600))?;
    assert!(
        run(&delivery(
            &root,
            &review,
            &unrelated,
            "principal:reviewer",
            "20:30"
        ))
        .is_err()
    );
    assert_eq!(fs::read(&unrelated)?, b"private but unrelated file");

    let output = directory.0.join("verified.mkv");
    let read = delivery(&root, &review, &output, "principal:reviewer", "20:30");
    let preview = run(&read)?;
    let approved_read = approved(read.clone(), &preview)?;
    run(&approved_read)?;
    let bytes = fs::read(&output)?;
    let saved = directory.0.join("original.mkv");
    fs::rename(&output, &saved)?;
    fs::write(&output, &bytes)?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o600))?;
    assert!(
        run(&approved_read).is_err(),
        "replacement inode was adopted"
    );
    fs::remove_file(&output)?;
    fs::rename(&saved, &output)?;

    let alias = directory.0.join("linked.mkv");
    fs::hard_link(&output, &alias)?;
    assert!(
        run(&read).is_err(),
        "multiply-linked private file was admitted"
    );
    fs::remove_file(&alias)?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o644))?;
    assert!(run(&read).is_err(), "public file was admitted");
    fs::set_permissions(&output, fs::Permissions::from_mode(0o600))?;
    fs::remove_file(&output)?;
    symlink(&unrelated, &output)?;
    assert!(run(&approved_read).is_err(), "symlink was followed");
    assert_eq!(fs::read(&unrelated)?, b"private but unrelated file");
    Ok(())
}

#[test]
fn expired_or_revoked_pending_delivery_remains_inspectable_without_disclosure() -> Test {
    let directory = Directory::new()?;
    let (root, review) = published(&directory)?;
    let output = directory.0.join("pending.mkv");
    let read = delivery(&root, &review, &output, "principal:reviewer", "20:30");
    let identity = interrupted(&read, Some(true))?;
    let before = fs::read(&output)?;
    assert!(
        run(&delivery(
            &root,
            &review,
            &output,
            "principal:reviewer",
            "100:110"
        ))
        .is_err()
    );
    let revoke = args(&root, "review-revoke", &["--review-root", &review]);
    let preview = run(&revoke)?;
    run(&approved(revoke, &preview)?)?;
    assert!(run(&read).is_err());
    let state = run(&show(&root, identity, "principal:reviewer"))?;
    assert_eq!(
        text(&state, "delivery_state")?,
        "started_outcome_indeterminate"
    );
    assert_eq!(fs::read(&output)?, before);
    Ok(())
}
