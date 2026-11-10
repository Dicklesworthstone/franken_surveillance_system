#![forbid(unsafe_code)]
//! Scope, expiry, capability and canonical corruption contracts for local review grants.

use super::*;
use fss_core::region::RootAuthoritySpec;
use fss_core::{BudgetVector, OperationId};

type Test = Result<(), Box<dyn std::error::Error>>;
const SITE: &str = "site:review-test";

fn request() -> Result<ReviewAccessRequest, ContractError> {
    Ok(ReviewAccessRequest {
        import_identity: ContentDigest::sha256(b"import"),
        import_root: ContentDigest::sha256(b"retained root"),
        sensor: SensorId::parse("sensor:front")?,
        movie_start_tick: 100,
        movie_end_tick: 200,
        expected_privacy: ContentDigest::sha256(b"current complete mask binding"),
        recipient: PrincipalId::parse("principal:reviewer")?,
        purpose: "Inspect one selected interval".to_owned(),
        issued_at: TimestampNs(10),
        expires_at: TimestampNs(100),
        maximum_media_bytes: 1024,
    })
}

fn authority(principal: &str, cap: &str) -> Result<ContextAuthority, Box<dyn std::error::Error>> {
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:review".to_owned(),
        operation_id: OperationId::parse("operation:review")?,
        principal: principal.to_owned(),
        capabilities: vec![cap.to_owned()],
        deadline: None,
        priority: 0,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:local".to_owned(),
        retention_scope: "retention:local".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}

fn grant() -> Result<ReviewGrant, Box<dyn std::error::Error>> {
    Ok(ReviewGrant::prepare(
        request()?,
        &authority("principal:owner", CAP_EXPORT_PREPARE)?,
        SITE,
        ContentDigest::sha256(b"render receipt"),
    )?)
}

fn admit(grant: &ReviewGrant, earliest: i128, latest: i128) -> Result<(), GrantError> {
    let reader = authority("principal:reviewer", CAP_READ_REVIEW_MEDIA)
        .map_err(|_| GrantError::Unauthorized)?;
    grant.authorize_reader(
        &reader,
        SITE,
        grant.render_receipt(),
        grant.request().expected_privacy,
        CaptureInterval {
            earliest: TimestampNs(earliest),
            latest: TimestampNs(latest),
        },
        false,
    )
}

#[test]
fn canonical_scope_and_grant_round_trip_with_no_implicit_authority() -> Test {
    let req = request()?;
    assert_eq!(
        ReviewAccessRequest::from_bytes(&req.to_bytes()?, req.digest()?)?,
        req
    );
    let prepared = grant()?;
    let read = ReviewGrant::from_bytes(&prepared.to_bytes()?, prepared.digest()?)?;
    assert_eq!(prepared, read);
    assert_eq!(read.owner().as_str(), "principal:owner");
    assert_eq!(read.site(), SITE);
    assert_eq!(read.request(), &req);
    let wrong_reader = authority("principal:owner", CAP_READ_REVIEW_MEDIA)?;
    assert_eq!(
        read.authorize_reader(
            &wrong_reader,
            SITE,
            read.render_receipt(),
            req.expected_privacy,
            CaptureInterval::new(TimestampNs(11), TimestampNs(12))?,
            false,
        ),
        Err(GrantError::ScopeMismatch)
    );
    Ok(())
}

#[test]
fn every_source_privacy_recipient_time_and_byte_field_changes_request_identity() -> Test {
    let req = request()?;
    let mut variants = Vec::new();
    let mut changed = req.clone();
    changed.import_identity = ContentDigest::sha256(b"other import");
    variants.push(changed);
    let mut changed = req.clone();
    changed.import_root = ContentDigest::sha256(b"other root");
    variants.push(changed);
    let mut changed = req.clone();
    changed.sensor = SensorId::parse("sensor:other")?;
    variants.push(changed);
    let mut changed = req.clone();
    changed.movie_start_tick += 1;
    variants.push(changed);
    let mut changed = req.clone();
    changed.movie_end_tick += 1;
    variants.push(changed);
    let mut changed = req.clone();
    changed.expected_privacy = ContentDigest::sha256(b"other mask");
    variants.push(changed);
    let mut changed = req.clone();
    changed.recipient = PrincipalId::parse("principal:other")?;
    variants.push(changed);
    let mut changed = req.clone();
    changed.purpose.push('.');
    variants.push(changed);
    let mut changed = req.clone();
    changed.issued_at = TimestampNs(11);
    variants.push(changed);
    let mut changed = req.clone();
    changed.expires_at = TimestampNs(101);
    variants.push(changed);
    let mut changed = req.clone();
    changed.maximum_media_bytes += 1;
    variants.push(changed);
    for changed in variants {
        assert_ne!(req.digest()?, changed.digest()?);
    }
    Ok(())
}

#[test]
fn conservative_lifetime_refuses_uncertain_issuance_and_expiry() -> Test {
    let g = grant()?;
    assert_eq!(admit(&g, 10, 99), Ok(()));
    assert_eq!(admit(&g, 9, 11), Err(GrantError::NotYetValid));
    assert_eq!(admit(&g, 99, 100), Err(GrantError::ExpiryUncertain));
    assert_eq!(admit(&g, 100, 100), Err(GrantError::Expired));
    assert_eq!(admit(&g, 20, 19), Err(GrantError::InvalidRequest));
    Ok(())
}

#[test]
fn current_authority_revocation_privacy_and_exact_receipt_are_required() -> Test {
    let g = grant()?;
    let reader = authority("principal:reviewer", CAP_READ_REVIEW_MEDIA)?;
    let now = CaptureInterval::new(TimestampNs(11), TimestampNs(12))?;
    let check = |a: &ContextAuthority, site: &str, receipt, privacy, revoked| {
        g.authorize_reader(a, site, receipt, privacy, now, revoked)
    };
    assert_eq!(
        check(
            &reader,
            SITE,
            g.render_receipt(),
            g.request().expected_privacy,
            false
        ),
        Ok(())
    );
    assert_eq!(
        check(
            &reader,
            SITE,
            g.render_receipt(),
            g.request().expected_privacy,
            true
        ),
        Err(GrantError::Revoked)
    );
    assert_eq!(
        check(
            &reader,
            SITE,
            g.render_receipt(),
            ContentDigest::sha256(b"changed privacy"),
            false
        ),
        Err(GrantError::PrivacyChanged)
    );
    assert_eq!(
        check(
            &reader,
            SITE,
            ContentDigest::sha256(b"changed receipt"),
            g.request().expected_privacy,
            false
        ),
        Err(GrantError::ScopeMismatch)
    );
    assert_eq!(
        check(
            &reader,
            "site:other",
            g.render_receipt(),
            g.request().expected_privacy,
            false
        ),
        Err(GrantError::Unauthorized)
    );
    let observer = authority("principal:reviewer", CAP_EXPORT_PREPARE)?;
    assert_eq!(
        check(
            &observer,
            SITE,
            g.render_receipt(),
            g.request().expected_privacy,
            false
        ),
        Err(GrantError::Unauthorized)
    );
    let mut expired = reader.clone();
    expired.deadline = Some(TimestampNs(12));
    assert_eq!(
        check(
            &expired,
            SITE,
            g.render_receipt(),
            g.request().expected_privacy,
            false
        ),
        Err(GrantError::Unauthorized)
    );
    let mut cancelled = reader;
    cancelled.cancellation_reason = Some("stop".to_owned());
    assert_eq!(
        check(
            &cancelled,
            SITE,
            g.render_receipt(),
            g.request().expected_privacy,
            false
        ),
        Err(GrantError::Cancelled)
    );
    Ok(())
}

#[test]
fn preparation_is_capability_scoped_and_immutable_render_bound() -> Test {
    let reader = authority("principal:reviewer", CAP_READ_REVIEW_MEDIA)?;
    assert_eq!(
        ReviewGrant::prepare(request()?, &reader, SITE, ContentDigest::sha256(b"render")),
        Err(GrantError::Unauthorized)
    );
    let owner = authority("principal:owner", CAP_EXPORT_PREPARE)?;
    let a = grant()?;
    let b = ReviewGrant::prepare(
        request()?,
        &owner,
        SITE,
        ContentDigest::sha256(b"different rendered pixels"),
    )?;
    assert_ne!(a.digest()?, b.digest()?);
    let mut expired_owner = owner;
    expired_owner.deadline = Some(TimestampNs(10));
    assert_eq!(
        ReviewGrant::prepare(request()?, &expired_owner, SITE, a.render_receipt()),
        Err(GrantError::Unauthorized)
    );
    Ok(())
}

#[test]
fn malformed_scope_refuses_before_encoding() -> Test {
    let req = request()?;
    let mut changed = req.clone();
    changed.maximum_media_bytes = MAX_REVIEW_MEDIA_BYTES + 1;
    assert_eq!(changed.to_bytes(), Err(GrantError::InvalidRequest));
    changed = req.clone();
    changed.maximum_media_bytes = 0;
    assert_eq!(changed.validate(), Err(GrantError::InvalidRequest));
    changed = req.clone();
    changed.purpose = "bad\nlabel".to_owned();
    assert_eq!(changed.validate(), Err(GrantError::InvalidRequest));
    changed = req.clone();
    changed.purpose = "a".repeat(MAX_PURPOSE_BYTES + 1);
    assert_eq!(changed.validate(), Err(GrantError::InvalidRequest));
    changed = req.clone();
    changed.expires_at = changed.issued_at;
    assert_eq!(changed.validate(), Err(GrantError::InvalidRequest));
    changed = req;
    changed.movie_end_tick = changed.movie_start_tick;
    assert_eq!(changed.validate(), Err(GrantError::InvalidRequest));
    Ok(())
}

#[test]
fn checksum_truncation_trailing_and_oversized_records_fail_closed() -> Test {
    let g = grant()?;
    let bytes = g.to_bytes()?;
    for length in 0..bytes.len() {
        let cut = &bytes[..length];
        assert_eq!(
            ReviewGrant::from_bytes(cut, ContentDigest::sha256(cut)),
            Err(GrantError::InvalidRecord)
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        ReviewGrant::from_bytes(&trailing, ContentDigest::sha256(&trailing)),
        Err(GrantError::InvalidRecord)
    );
    let mut tampered = bytes;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        ReviewGrant::from_bytes(&tampered, g.digest()?),
        Err(GrantError::InvalidRecord)
    );
    let oversized = vec![0; MAX_REVIEW_GRANT_BYTES + 1];
    assert_eq!(
        ReviewGrant::from_bytes(&oversized, ContentDigest::sha256(&oversized)),
        Err(GrantError::InvalidRecord)
    );
    Ok(())
}
