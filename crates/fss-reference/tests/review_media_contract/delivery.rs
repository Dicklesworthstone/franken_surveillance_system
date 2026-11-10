#![forbid(unsafe_code)]
//! Native ledger + retained media + actual held-file delivery, including cold reconciliation.

use super::*;
use std::fs::{File, FileTimes, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use fss_reference::review_media::delivery::{
    DELIVERY_OBJECT_PREFIX, FAMILY_REVIEW_DELIVERY_STARTED, FAMILY_REVIEW_DELIVERY_VERIFIED,
    ReviewDeliveryProgress, ReviewDeliveryRecord, ReviewDeliveryState, STAGE_DELIVERY_BEGIN,
    STAGE_DELIVERY_READBACK, STAGE_DELIVERY_STARTED, STAGE_DELIVERY_VERIFIED,
    STAGE_DELIVERY_VERIFY, begin_review_delivery, inspect_review_delivery, prepare_review_delivery,
    verify_review_delivery,
};

fn delivery_actor(f: &Fixture) -> TestResult<(ContextAuthority, ReplayCx)> {
    let a = authority(
        READER,
        &[CAP_REVIEW_MEDIA_READ, CAP_EXPORT_COMMIT],
        MEDIA_BOUND,
    )?;
    let cx = ReplayCx::from_context_authority_read_only(&a, f.root.clone())?;
    Ok((a, cx))
}

fn target() -> ContentDigest {
    ContentDigest::sha256(b"test protected parent identity and exact output leaf")
}

fn start(
    f: &mut Fixture,
    review: &ReviewMediaRecord,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> TestResult<ReviewDeliveryProgress> {
    let preview =
        prepare_review_delivery(&f.deployment, review.root(), target(), now(20, 30)?, a, cx)?;
    Ok(begin_review_delivery(
        &mut f.deployment,
        review.root(),
        target(),
        now(20, 30)?,
        preview.approval(),
        a,
        cx,
    )?)
}

fn private_output(
    f: &Fixture,
    review: &ReviewMediaRecord,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> TestResult<(PathBuf, File, Vec<u8>)> {
    let bytes = read_review_media(&f.deployment, review.root(), now(20, 30)?, a, cx)?
        .bytes()
        .to_vec();
    let path = f._directory.0.join("delivery.mkv");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok((path, file, bytes))
}

fn assert_started(
    f: &Fixture,
    identity: ContentDigest,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> TestResult {
    assert_eq!(
        inspect_review_delivery(&f.deployment, identity, a, cx)?
            .ok_or("missing durable start")?
            .state(),
        ReviewDeliveryState::Started
    );
    Ok(())
}

#[test]
fn read_only_preview_approval_starts_once_and_cold_completed_retry_rechecks_file() -> TestResult {
    let mut f = Fixture::new("delivery-cold", "indexed_avc.mp4")?;
    let (_, review) = f.publish()?;
    let (reader, reader_cx) = f.reader(READER, MEDIA_BOUND)?;
    let before = snapshot(&f.root)?;
    let preview = prepare_review_delivery(
        &f.deployment,
        review.root(),
        target(),
        now(20, 30)?,
        &reader,
        &reader_cx,
    )?;
    assert_eq!(preview.state(), None);
    assert_eq!(snapshot(&f.root)?, before);
    assert!(matches!(
        begin_review_delivery(
            &mut f.deployment,
            review.root(),
            target(),
            now(20, 30)?,
            preview.approval(),
            &reader,
            &reader_cx
        ),
        Err(ReviewMediaError::Unauthorized)
    ));
    let (a, cx) = delivery_actor(&f)?;
    let mut changed = a.clone();
    changed.privacy_scope = "privacy:different".into();
    let changed_cx = ReplayCx::from_context_authority_read_only(&changed, f.root.clone())?;
    assert!(matches!(
        begin_review_delivery(
            &mut f.deployment,
            review.root(),
            target(),
            now(20, 30)?,
            preview.approval(),
            &changed,
            &changed_cx
        ),
        Err(ReviewMediaError::StaleApproval)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    // Adding the separately required commit capability must not stale the reviewed approval.
    let started = begin_review_delivery(
        &mut f.deployment,
        review.root(),
        target(),
        now(20, 30)?,
        preview.approval(),
        &a,
        &cx,
    )?;
    assert!(started.started);
    assert_eq!(started.record.identity(), preview.identity());
    assert_started(&f, preview.identity(), &reader, &reader_cx)?;
    let (path, mut file, _) = private_output(&f, &review, &a, &cx)?;
    assert!(matches!(
        prepare_review_delivery(
            &f.deployment,
            review.root(),
            target(),
            now(40, 50)?,
            &changed,
            &changed_cx
        ),
        Err(ReviewMediaError::StaleApproval)
    ));
    assert!(matches!(
        verify_review_delivery(
            &mut f.deployment,
            preview.identity(),
            target(),
            now(40, 50)?,
            &mut file,
            &mut |_| Ok(()),
            &changed,
            &changed_cx
        ),
        Err(ReviewMediaError::StaleApproval)
    ));
    let mut checks = 0;
    let receipt = verify_review_delivery(
        &mut f.deployment,
        preview.identity(),
        target(),
        now(40, 50)?,
        &mut file,
        &mut |held| {
            checks += 1;
            let named = fs::metadata(&path).map_err(|_| ReviewMediaError::CustodyMismatch)?;
            let held = held
                .metadata()
                .map_err(|_| ReviewMediaError::CustodyMismatch)?;
            if (named.dev(), named.ino()) != (held.dev(), held.ino()) {
                return Err(ReviewMediaError::CustodyMismatch);
            }
            Ok(())
        },
        &a,
        &cx,
    )?;
    assert_eq!(checks, 2);
    assert!(receipt.published);
    assert_eq!(receipt.record.state(), ReviewDeliveryState::Verified);
    assert_eq!(
        ReviewDeliveryRecord::from_bytes(receipt.record.to_bytes(), receipt.record.digest())?,
        receipt.record
    );
    f = f.cold_reopen()?;
    let (a, cx) = delivery_actor(&f)?;
    let before = snapshot(&f.root)?;
    let retried = prepare_review_delivery(
        &f.deployment,
        review.root(),
        target(),
        now(60, 70)?,
        &a,
        &cx,
    )?;
    assert_eq!(retried.identity(), preview.identity());
    assert_ne!(retried.approval(), preview.approval());
    assert_eq!(retried.state(), Some(ReviewDeliveryState::Verified));
    let replayed = begin_review_delivery(
        &mut f.deployment,
        review.root(),
        target(),
        now(60, 70)?,
        retried.approval(),
        &a,
        &cx,
    )?;
    assert!(!replayed.started);
    let mut read_only = File::open(path)?;
    let replayed = verify_review_delivery(
        &mut f.deployment,
        preview.identity(),
        target(),
        now(60, 70)?,
        &mut read_only,
        &mut |_| Ok(()),
        &a,
        &cx,
    )?;
    assert!(!replayed.published);
    assert_eq!(replayed.record, receipt.record);
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn partial_changed_extended_public_linked_and_replaced_files_cannot_be_verified() -> TestResult {
    let mut f = Fixture::new("delivery-bad-files", "indexed_avc.mp4")?;
    let (_, review) = f.publish()?;
    let (a, cx) = delivery_actor(&f)?;
    let progress = start(&mut f, &review, &a, &cx)?;
    let identity = progress.record.identity();
    let (path, mut file, bytes) = private_output(&f, &review, &a, &cx)?;
    let before = snapshot(&f.root)?;
    for damage in ["partial", "changed", "extended", "public", "linked"] {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.set_len(bytes.len() as u64)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let extra_link = f._directory.0.join("delivery-hardlink");
        match damage {
            "partial" => file.set_len(bytes.len() as u64 - 1)?,
            "changed" => {
                file.seek(SeekFrom::Start(0))?;
                file.write_all(&[bytes[0] ^ 1])?;
            }
            "extended" => {
                file.seek(SeekFrom::End(0))?;
                file.write_all(b"extra")?;
            }
            "public" => fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?,
            "linked" => fs::hard_link(&path, &extra_link)?,
            _ => return Err("unexpected damage fixture".into()),
        }
        assert!(
            matches!(
                verify_review_delivery(
                    &mut f.deployment,
                    identity,
                    target(),
                    now(40, 50)?,
                    &mut file,
                    &mut |_| Ok(()),
                    &a,
                    &cx
                ),
                Err(ReviewMediaError::CustodyMismatch)
            ),
            "{damage}"
        );
        assert_started(&f, identity, &a, &cx)?;
        assert_eq!(snapshot(&f.root)?, before);
        if damage == "linked" {
            fs::remove_file(extra_link)?;
        }
    }
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    file.set_len(bytes.len() as u64)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let receipt = verify_review_delivery(
        &mut f.deployment,
        identity,
        target(),
        now(40, 50)?,
        &mut file,
        &mut |_| Ok(()),
        &a,
        &cx,
    )?;
    assert!(receipt.published);
    // Exact bytes and the same inode do not erase a later rewrite or metadata change.
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    file.set_times(FileTimes::new().set_modified(std::time::UNIX_EPOCH))?;
    assert_eq!(
        file.metadata()?.ino(),
        receipt
            .record
            .verified_file()
            .ok_or("missing file identity")?
            .inode
    );
    let before_rewrite_retry = snapshot(&f.root)?;
    assert!(matches!(
        verify_review_delivery(
            &mut f.deployment,
            identity,
            target(),
            now(60, 70)?,
            &mut file,
            &mut |_| Ok(()),
            &a,
            &cx
        ),
        Err(ReviewMediaError::CustodyMismatch)
    ));
    assert_eq!(snapshot(&f.root)?, before_rewrite_retry);
    // Keep the original descriptor open so the replacement cannot reuse its inode.
    fs::remove_file(&path)?;
    let (_, mut replacement, _) = private_output(&f, &review, &a, &cx)?;
    assert_ne!(file.metadata()?.ino(), replacement.metadata()?.ino());
    let before = snapshot(&f.root)?;
    assert!(matches!(
        verify_review_delivery(
            &mut f.deployment,
            identity,
            target(),
            now(60, 70)?,
            &mut replacement,
            &mut |_| Ok(()),
            &a,
            &cx
        ),
        Err(ReviewMediaError::CustodyMismatch)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn cancellation_preserves_durable_start_and_terminal_receipt_across_cold_reopen() -> TestResult {
    let mut f = Fixture::new("delivery-cancellation", "indexed_avc.mp4")?;
    let (_, review) = f.publish()?;
    let (a, cx) = delivery_actor(&f)?;
    let preview = prepare_review_delivery(
        &f.deployment,
        review.root(),
        target(),
        now(20, 30)?,
        &a,
        &cx,
    )?;
    let before = snapshot(&f.root)?;
    let stop = ReplayCx::from_context_authority_read_only(&a, f.root.clone())?;
    stop.set_cancel_at_checkpoint(STAGE_DELIVERY_BEGIN);
    assert!(matches!(
        begin_review_delivery(
            &mut f.deployment,
            review.root(),
            target(),
            now(20, 30)?,
            preview.approval(),
            &a,
            &stop
        ),
        Err(ReviewMediaError::Cancelled)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    let stop = ReplayCx::from_context_authority_read_only(&a, f.root.clone())?;
    stop.set_cancel_at_checkpoint(STAGE_DELIVERY_STARTED);
    let started = begin_review_delivery(
        &mut f.deployment,
        review.root(),
        target(),
        now(20, 30)?,
        preview.approval(),
        &a,
        &stop,
    )?;
    assert!(started.started);
    assert!(stop.is_cancelled());
    f = f.cold_reopen()?;
    assert_started(&f, preview.identity(), &a, &cx)?;
    let retry = start(&mut f, &review, &a, &cx)?;
    assert!(!retry.started);
    assert!(!f._directory.0.join("delivery.mkv").exists());
    let (_, mut file, _) = private_output(&f, &review, &a, &cx)?;
    for stage in [STAGE_DELIVERY_READBACK, STAGE_DELIVERY_VERIFY] {
        let before = snapshot(&f.root)?;
        let stop = ReplayCx::from_context_authority_read_only(&a, f.root.clone())?;
        stop.set_cancel_at_checkpoint(stage);
        assert!(matches!(
            verify_review_delivery(
                &mut f.deployment,
                preview.identity(),
                target(),
                now(40, 50)?,
                &mut file,
                &mut |_| Ok(()),
                &a,
                &stop
            ),
            Err(ReviewMediaError::Cancelled)
        ));
        assert_started(&f, preview.identity(), &a, &cx)?;
        assert_eq!(snapshot(&f.root)?, before);
    }
    let stop = ReplayCx::from_context_authority_read_only(&a, f.root.clone())?;
    stop.set_cancel_at_checkpoint(STAGE_DELIVERY_VERIFIED);
    let receipt = verify_review_delivery(
        &mut f.deployment,
        preview.identity(),
        target(),
        now(40, 50)?,
        &mut file,
        &mut |_| Ok(()),
        &a,
        &stop,
    )?;
    assert!(receipt.published);
    assert!(stop.is_cancelled());
    f = f.cold_reopen()?;
    assert_eq!(
        inspect_review_delivery(&f.deployment, preview.identity(), &a, &cx)?
            .ok_or("missing durable receipt")?,
        receipt.record
    );
    assert!(
        !verify_review_delivery(
            &mut f.deployment,
            preview.identity(),
            target(),
            now(60, 70)?,
            &mut file,
            &mut |_| Ok(()),
            &a,
            &cx
        )?
        .published
    );
    Ok(())
}

#[test]
fn final_destination_check_and_new_time_attestation_cannot_be_bypassed_by_readback() -> TestResult {
    let mut f = Fixture::new("delivery-final-check", "indexed_avc.mp4")?;
    let (_, review) = f.publish()?;
    let (a, cx) = delivery_actor(&f)?;
    let progress = start(&mut f, &review, &a, &cx)?;
    let identity = progress.record.identity();
    let (_, mut file, _) = private_output(&f, &review, &a, &cx)?;
    let before = snapshot(&f.root)?;
    let mut checks = 0;
    assert!(matches!(
        verify_review_delivery(
            &mut f.deployment,
            identity,
            target(),
            now(40, 50)?,
            &mut file,
            &mut |held| {
                checks += 1;
                if checks == 2 {
                    held.set_len(1)
                        .map_err(|_| ReviewMediaError::CustodyMismatch)?;
                }
                Ok(())
            },
            &a,
            &cx
        ),
        Err(ReviewMediaError::CustodyMismatch)
    ));
    assert_eq!(checks, 2);
    assert_started(&f, identity, &a, &cx)?;
    assert!(matches!(
        verify_review_delivery(
            &mut f.deployment,
            identity,
            ContentDigest::sha256(b"other destination"),
            now(40, 50)?,
            &mut file,
            &mut |_| Ok(()),
            &a,
            &cx
        ),
        Err(ReviewMediaError::StaleApproval)
    ));
    assert!(matches!(
        verify_review_delivery(
            &mut f.deployment,
            identity,
            target(),
            now(19, 50)?,
            &mut file,
            &mut |_| Ok(()),
            &a,
            &cx
        ),
        Err(ReviewMediaError::InvalidRequest)
    ));
    assert!(matches!(
        verify_review_delivery(
            &mut f.deployment,
            identity,
            target(),
            now(100, 101)?,
            &mut file,
            &mut |_| Ok(()),
            &a,
            &cx
        ),
        Err(ReviewMediaError::Grant(GrantError::Expired))
    ));
    let (other, other_cx) = f.reader("principal:other", MEDIA_BOUND)?;
    assert!(matches!(
        inspect_review_delivery(&f.deployment, identity, &other, &other_cx),
        Err(ReviewMediaError::Unauthorized)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    let approval = revocation_approval(&f.deployment, review.root(), &f.owner, &f.cx)?;
    revoke_review_media(&mut f.deployment, review.root(), approval, &f.owner, &f.cx)?;
    f = f.cold_reopen()?;
    assert_started(&f, identity, &a, &cx)?;
    assert!(matches!(
        verify_review_delivery(
            &mut f.deployment,
            identity,
            target(),
            now(40, 50)?,
            &mut file,
            &mut |_| Ok(()),
            &a,
            &cx
        ),
        Err(ReviewMediaError::Revoked)
    ));
    Ok(())
}

#[test]
fn source_deletion_keeps_delivery_audit_without_pinning_review_pixels() -> TestResult {
    let mut f = Fixture::new("delivery-deletion", "indexed_avc.mp4")?;
    let (_, review) = f.publish()?;
    let (a, cx) = delivery_actor(&f)?;
    let progress = start(&mut f, &review, &a, &cx)?;
    let identity = progress.record.identity();
    let (_, mut file, _) = private_output(&f, &review, &a, &cx)?;
    let receipt = verify_review_delivery(
        &mut f.deployment,
        identity,
        target(),
        now(40, 50)?,
        &mut file,
        &mut |_| Ok(()),
        &a,
        &cx,
    )?;
    let plan = plan_deletion(&f.deployment, f.source.import_identity, &f.cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for digest in [
        review.root(),
        review.digest(),
        review.media_digest(),
        review.render_receipt_digest(),
    ] {
        assert!(
            plan.deletable.iter().any(|object| object.digest == digest),
            "delivery audit must not retain media: {digest}"
        );
    }
    for digest in [progress.record.digest(), receipt.record.digest()] {
        assert!(!plan.deletable.iter().any(|object| object.digest == digest));
        assert!(plan.retained.iter().any(|object| object.digest == digest));
    }
    commit_deletion(
        &mut f.deployment,
        plan.digest()?,
        plan.approval_digest(OWNER)?,
        OWNER,
        &f.cx,
    )?;
    f = f.cold_reopen()?;
    assert!(
        !f.deployment
            .publisher()
            .spool()
            .object_path(review.media_digest())
            .exists()
    );
    assert_eq!(
        inspect_review_delivery(&f.deployment, identity, &a, &cx)?
            .ok_or("missing deletion audit")?,
        receipt.record
    );
    assert!(matches!(
        verify_review_delivery(
            &mut f.deployment,
            identity,
            target(),
            now(60, 70)?,
            &mut file,
            &mut |_| Ok(()),
            &a,
            &cx
        ),
        Err(ReviewMediaError::Deleted)
    ));
    // The output is an already delivered local copy. Source deletion does not claim to recall it.
    assert_eq!(file.metadata()?.len(), review.media_bytes());
    Ok(())
}

#[test]
fn generic_authority_append_cannot_forge_delivery_state_or_shadow_its_namespace() -> TestResult {
    let mut f = Fixture::new("delivery-forged-authority", "indexed_avc.mp4")?;
    let before = snapshot(&f.root)?;
    for (family, object) in [
        (FAMILY_REVIEW_DELIVERY_STARTED, "object:any".to_owned()),
        (FAMILY_REVIEW_DELIVERY_VERIFIED, "object:any".to_owned()),
        ("other_family", format!("{DELIVERY_OBJECT_PREFIX}forged")),
    ] {
        let digest = ContentDigest::sha256(b"forged delivery authority");
        assert!(matches!(
            f.deployment.append_batch(
                BatchId::parse("batch:forged-delivery")?,
                vec![EvidenceDelta {
                    delta_id: "delta:forged-delivery".into(),
                    family: family.into(),
                    object_id: ObjectId::parse(object)?,
                    prior_generation: None,
                    new_generation: 1,
                    validity: now(20, 30)?,
                    plane: Plane::Authority,
                    payload_digest: digest,
                    witness_digest: None,
                    operation_id: None
                }],
                vec![digest],
                &f.cx,
            ),
            Err(ReferenceError::ReservedDeltaFamily { .. })
        ));
    }
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}
