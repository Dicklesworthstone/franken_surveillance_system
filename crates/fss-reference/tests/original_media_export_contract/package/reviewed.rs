#![forbid(unsafe_code)]
//! Current reviewed package events retain native uncertainty and exact source/review custody.

use super::*;
use fss_core::CanonicalEncode;
use fss_publication::SlotName;
use fss_reference::event_review::{ReviewError, ReviewReceipt};
use fss_reference::ingest::package_event::PackageEventError;
use fss_reference::original_media_export::{
    REVIEWED_PACKAGE_ORIGINAL_MEDIA_EXPORT_DOMAIN, REVIEWED_PACKAGE_ORIGINAL_MEDIA_EXPORT_PROFILE,
};
use fss_reference::{ReferencePolicyAction, ReferencePolicyDecision};

const REVIEWER: &str = "principal:private-package-reviewer";
const REASON: &str = "Private operator rationale is not a detector assertion";

pub(super) fn review(f: &mut Fixture, disposition: ReviewDisposition) -> Test<ReviewReceipt> {
    let mut authority = f.authority.clone();
    authority.principal = REVIEWER.into();
    let cx = ReplayCx::from_context_authority(&authority, f.deployment.root().to_path_buf())?;
    let request = ReviewRequest {
        event_id: f.request.event.event_id.clone(),
        expected_revision: f.request.event.expected_revision,
        disposition,
        reason: REASON.into(),
    };
    let preview = preview_review(&f.deployment, &request, &authority, &cx)?;
    let receipt = commit_review(
        &mut f.deployment,
        &request,
        preview.approval(),
        &authority,
        &cx,
    )?;
    f.request.event.expected_revision = receipt.review.event().revision_digest();
    Ok(receipt)
}

#[test]
fn current_reviewed_package_cold_export_preserves_native_origin_and_every_operator_assertion()
-> Test {
    let mut f = fixture("package-review-cold")?;
    let original_request = f.request.clone();
    let native = PackageEvent::open(&f.deployment, &f.request.event.event_id, &f.cx)?;
    let original = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    let mut reviews = Vec::new();
    for disposition in [
        ReviewDisposition::Investigate,
        ReviewDisposition::Investigate,
        ReviewDisposition::Resolve,
    ] {
        reviews.push(review(&mut f, disposition)?);
    }
    assert!(matches!(
        preview_original_media_export(&f.deployment, &original_request, &f.authority, &f.cx),
        Err(OriginalMediaExportError::Event(_))
    ));
    assert!(matches!(
        approve_original_media_export(
            &f.deployment,
            &f.request,
            original.approval(),
            &f.authority,
            &f.cx
        ),
        Err(OriginalMediaExportError::StaleApproval)
    ));
    // The public native owner must not present a reviewed successor as its earlier candidate.
    assert!(matches!(
        PackageEvent::open(&f.deployment, &f.request.event.event_id, &f.cx),
        Err(PackageEventError::Conflict)
    ));
    let before = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let preview = preview_original_media_export(&reopened, &f.request, &f.authority, &f.cx)?;
    assert_eq!(
        preview.profile(),
        REVIEWED_PACKAGE_ORIGINAL_MEDIA_EXPORT_PROFILE
    );
    assert_eq!(preview.media_bytes(), original.media_bytes());
    assert_eq!(preview.media_bytes(), f.source);
    assert_ne!(preview.approval(), original.approval());
    assert_ne!(preview.root(), original.root());
    let json = preview.record_json();
    for field in [
        "\"schema\":\"fss.original_media_export.v4\"".to_owned(),
        "\"event_profile\":\"package_track\"".to_owned(),
        "\"state\":\"resolved\"".to_owned(),
        "\"kind\":\"unclassified\"".to_owned(),
        "\"native_origin_state\":\"indeterminate\"".to_owned(),
        "\"native_origin_kind\":\"unclassified\"".to_owned(),
        "\"native_origin_calibrated\":false".to_owned(),
        "\"review_count\":3".to_owned(),
        "\"review_reasons_included\":false".to_owned(),
        "\"reviewer_identity_included\":false".to_owned(),
        "\"review_is_sensor_recomputation\":false".to_owned(),
        "\"native_perception_reexecuted\":false".to_owned(),
        "\"event_source_count\":1".to_owned(),
        "\"source_segments\":3".to_owned(),
        format!(
            "\"event_provenance_root\":\"{}\"",
            native.event().decision_path.fingerprint
        ),
        format!(
            "\"analysis_roots\":[\"{}\"]",
            native.report().retained().root()
        ),
        format!(
            "\"native_origin_revision\":\"{}\"",
            native.event().revision_digest()
        ),
        format!("\"native_origin_event_root\":\"{}\"", native.root()),
        format!(
            "\"native_origin_authority_sequence\":{}",
            native.authority_anchor().commit_sequence
        ),
    ] {
        assert!(json.contains(&field), "missing {field}: {json}");
    }
    assert!(!json.contains(REVIEWER));
    assert!(!json.contains(REASON));
    let mut previous = 0;
    for receipt in &reviews {
        let marker = format!(
            "\"revision\":{},\"event_revision\":\"{}\"",
            receipt.review.event().revision,
            receipt.review.event().revision_digest()
        );
        let position = json.find(&marker).ok_or("missing ordered review")?;
        assert!(position > previous);
        previous = position;
        for digest in [
            receipt.authority.event_root,
            receipt.review.record().digest(),
            receipt.review.provenance_root(),
        ] {
            assert!(json.contains(&digest.to_text()));
        }
    }
    assert_eq!(json.matches("\"assertion_class\":\"operator\"").count(), 3);
    assert_eq!(json.matches("\"sensor_support_added\":false").count(), 3);
    let mut decoder = CanonicalDecoder::new(preview.record_bytes());
    assert_eq!(decoder.bytes()?, b"FSSEXM01");
    assert_eq!(decoder.u32()?, 4);
    assert_eq!(
        decoder.text()?,
        REVIEWED_PACKAGE_ORIGINAL_MEDIA_EXPORT_DOMAIN
    );
    let prepared = approve_original_media_export(
        &reopened,
        &f.request,
        preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    revalidate_original_media_export(&reopened, &prepared, &f.authority, &f.cx)?;
    let retry = preview_original_media_export(&reopened, &f.request, &f.authority, &f.cx)?;
    assert_eq!(retry.record_bytes(), preview.record_bytes());
    assert_eq!(retry.root(), preview.root());
    assert_eq!(retry.approval(), preview.approval());
    for change in ["source", "import-root", "destination", "revision"] {
        let mut request = f.request.clone();
        let alien = ContentDigest::sha256(b"different exact disclosure");
        match change {
            "source" => request.import_identity = alien,
            "import-root" => request.expected_import_root = alien,
            "destination" => request.destination_binding = alien,
            "revision" => request.event.expected_revision = alien,
            _ => unreachable!(),
        }
        assert!(
            approve_original_media_export(
                &reopened,
                &request,
                preview.approval(),
                &f.authority,
                &f.cx
            )
            .is_err()
        );
    }
    assert_eq!(*reopened.current_anchor(), before.0);
    assert_eq!(reopened.effects().last_root(), before.1);
    assert_eq!(reopened.publisher().spool().object_count(), before.2);
    drop(reopened);
    let verified = verify_original_media_export(
        preview.manifest_bytes(),
        preview.record_bytes(),
        preview.media_bytes(),
        preview.root(),
    )?;
    assert_eq!(verified.to_bytes(), preview.record_bytes());
    assert_eq!(verified.to_json(), json);
    let wrong_profile = fss_object::ObjectManifest::new(
        PACKAGE_ORIGINAL_MEDIA_EXPORT_PROFILE,
        [preview.media_digest()],
        Some(ContentDigest::sha256(preview.record_bytes())),
    )?;
    assert!(
        verify_original_media_export(
            &wrong_profile.canonical_bytes(),
            preview.record_bytes(),
            preview.media_bytes(),
            wrong_profile.root()
        )
        .is_err()
    );

    // Independent record verification also rejects cross-profile interpretations, truncation,
    // a missing chain, and a last review that disagrees with the exact current summary.
    let mut prefix = CanonicalEncoder::new();
    prefix.bytes(b"FSSEXM01");
    let position = prefix.finish().len();
    for version in [1_u32, 2, 3, 5] {
        let mut changed = preview.record_bytes().to_vec();
        changed[position..position + 4].copy_from_slice(&version.to_be_bytes());
        assert!(OriginalMediaExportRecord::from_bytes(&changed).is_err());
    }
    let current = f.request.event.expected_revision.bytes();
    let position = preview
        .record_bytes()
        .windows(current.len())
        .rposition(|bytes| bytes == current)
        .ok_or("missing final review")?;
    let mut changed = preview.record_bytes().to_vec();
    changed[position] ^= 1;
    assert!(OriginalMediaExportRecord::from_bytes(&changed).is_err());
    let mut prefix = CanonicalEncoder::new();
    prefix.digest(native.event().revision_digest());
    prefix.digest(native.root());
    native.authority_anchor().encode_canonical(&mut prefix);
    let prefix = prefix.finish();
    let count_position = preview
        .record_bytes()
        .windows(prefix.len())
        .position(|bytes| bytes == prefix)
        .ok_or("missing origin pins")?
        + prefix.len();
    for count in [0_u32, fss_core::event::MAX_LINEAGE_DEPTH as u32] {
        let mut changed = preview.record_bytes().to_vec();
        changed[count_position..count_position + 4].copy_from_slice(&count.to_be_bytes());
        assert!(OriginalMediaExportRecord::from_bytes(&changed).is_err());
    }
    assert!(
        OriginalMediaExportRecord::from_bytes(&preview.record_bytes()[..count_position]).is_err()
    );
    Ok(())
}

#[test]
fn reviewed_package_rechecks_native_source_analysis_and_intermediate_operator_custody() -> Test {
    let mut f = fixture("package-review-custody")?;
    let native = PackageEvent::open(&f.deployment, &f.request.event.event_id, &f.cx)?;
    let middle = review(&mut f, ReviewDisposition::Investigate)?;
    review(&mut f, ReviewDisposition::Resolve)?;
    let preview = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    let prepared = approve_original_media_export(
        &f.deployment,
        &f.request,
        preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    let source = RetainedFileImport::open(
        &f.deployment,
        f.request.import_identity,
        Default::default(),
        &f.cx,
    )?;
    let chunk = *source
        .manifest()
        .ordered_chunks
        .first()
        .ok_or("source chunk missing")?;
    for digest in [
        chunk,
        native.root(),
        native.event().decision_path.fingerprint,
        native.report().digest(),
        native.report().retained().record_digest(),
        middle.review.record().digest(),
        middle.review.provenance_root(),
    ] {
        let path = f.deployment.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        fs::write(
            &path,
            b"damaged original package or intermediate operator proof",
        )?;
        let before = f.snapshot();
        assert!(
            preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx).is_err()
        );
        assert!(
            revalidate_original_media_export(&f.deployment, &prepared, &f.authority, &f.cx)
                .is_err()
        );
        assert_eq!(f.snapshot(), before);
        assert_eq!(
            fs::read(&path)?,
            b"damaged original package or intermediate operator proof"
        );
        fs::write(path, bytes)?;
    }
    revalidate_original_media_export(&f.deployment, &prepared, &f.authority, &f.cx)?;
    let before = f.snapshot();
    f.cx.set_cancel_at_checkpoint_occurrence("event_review:lineage_link", 2);
    assert!(preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx).is_err());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn package_review_cannot_rewrite_native_probability_even_with_retained_statement_and_event_roots()
-> Test {
    let mut f = fixture("package-forged-review")?;
    let (_, original) = f
        .deployment
        .current_event_authority(&f.request.event.event_id)?;
    let request = ReviewRequest {
        event_id: f.request.event.event_id.clone(),
        expected_revision: f.request.event.expected_revision,
        disposition: ReviewDisposition::Investigate,
        reason: REASON.into(),
    };
    let review = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
    let statement = review.record().to_bytes();
    let previous = f.deployment.publisher().spool().read(original.event_root)?;
    let slot = SlotName::parse(&format!(
        "review-{}",
        review
            .record()
            .digest()
            .to_text()
            .strip_prefix("sha256:")
            .ok_or("hash format")?
    ))?;
    let staged = f
        .deployment
        .stage_and_publish(&slot, &[&statement, &previous], &f.cx)?;
    assert_eq!(staged.root, review.provenance_root());
    f.deployment
        .publish_and_commit(&slot, &staged.manifest, review.event().interval, &f.cx)?;
    let mut forged = review.event().clone();
    forged.probability.lower = 0.125;
    forged.probability.upper = 0.875;
    f.deployment.publish_event(
        &ReferencePolicyDecision {
            event: forged.clone(),
            action: ReferencePolicyAction::Hold,
        },
        &f.cx,
    )?;
    f.request.event.expected_revision = forged.revision_digest();
    let before = f.snapshot();
    let result = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx);
    assert!(
        matches!(result, Err(OriginalMediaExportError::Review(ref error)) if matches!(error.as_ref(), ReviewError::CustodyMismatch)),
        "{result:?}"
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}
