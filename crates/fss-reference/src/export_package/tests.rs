#![forbid(unsafe_code)]
//! Real export authority plus independent envelope tampering; no live devices or providers.

use std::fs;
use std::path::PathBuf;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, DecisionPath, EventEvidence, EventHypothesis,
    EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, OperationId,
    ProbabilityInterval, TimestampNs,
};

use super::*;
use crate::evidence_export::{EventExportRequest, commit_export, preview_export};
use crate::{ReferencePolicyAction, ReferencePolicyDecision};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:portable-export";
const ACTOR: &str = "principal:portable-export";
const RECIPIENT: &str = "recipient:case-7";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-portable-export-{label}-{}-{n}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    deployment: ReferenceDeployment,
    auth: ContextAuthority,
    cx: ReplayCx,
    request: EventExportRequest,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, expiry: i128) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let auth = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:portable-export".into(),
            operation_id: OperationId::parse("operation:portable-export")?,
            principal: ACTOR.into(),
            capabilities: vec![
                "ADP-REPLAY-001".into(),
                CAP_EXPORT_PREPARE.into(),
                CAP_EXPORT_COMMIT.into(),
            ],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:redacted-export-test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&auth, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.into(),
            event_id: EventId::parse("event:portable-export")?,
            revision: 1,
            supersedes: None,
            state: EventState::Indeterminate,
            kind: EventKind::Unclassified,
            interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            uncertainty_reason: Some("Synthetic unresolved observation".into()),
            zone_ids: vec!["private-zone-name".into()],
            track_ids: vec!["private-track-name".into()],
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: vec![EventEvidence {
                digest: ContentDigest::sha256(b"private raw payload sentinel"),
                class: EvidenceClass::Assertion,
                failure_domain: "sensor:private-front-door".into(),
                supports: false,
                relation: EvidenceEdgeRelation::DerivedFrom,
                capsule_digest: None,
                identity_digest: Some(ContentDigest::sha256(b"private identity")),
            }],
            model_receipts: vec![ContentDigest::sha256(b"private model payload sentinel")],
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"policy"),
                fingerprint: ContentDigest::sha256(b"decision"),
                abstained: true,
                abstention_reason: Some("synthetic".into()),
            },
        };
        deployment.stage_payload(b"private raw payload sentinel")?;
        deployment.stage_payload(b"private model payload sentinel")?;
        deployment.publish_event(
            &ReferencePolicyDecision {
                event: event.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        let request = EventExportRequest {
            event_id: event.event_id.clone(),
            expected_revision: event.revision_digest(),
            recipient: RECIPIENT.into(),
            purpose: "Owner review".into(),
            expires_at: TimestampNs(expiry),
        };
        Ok(Self {
            deployment,
            auth,
            cx,
            request,
            _directory: directory,
        })
    }

    fn commit(&mut self) -> Test<ContentDigest> {
        let preview = preview_export(&self.deployment, &self.request, &self.auth, &self.cx)?;
        commit_export(
            &mut self.deployment,
            &self.request,
            preview.approval(),
            &self.auth,
            &self.cx,
        )?;
        Ok(preview.root())
    }

    fn package(&self, root: ContentDigest) -> Test<PreparedPackage> {
        Ok(prepare_package(
            &self.deployment,
            root,
            &scope(30, 40)?,
            &self.auth,
            &self.cx,
        )?)
    }

    fn snapshot(&self) -> Test<(Vec<u8>, Vec<u8>, Vec<ContentDigest>)> {
        Ok((
            fs::read(self.deployment.root().join("ledger/journal.fssj"))?,
            fs::read(self.deployment.root().join("effects/journal.fssj"))?,
            self.deployment.publisher().spool().digests().collect(),
        ))
    }
}

fn scope(earliest: i128, latest: i128) -> Test<PackageScope> {
    Ok(PackageScope {
        recipient: RECIPIENT.into(),
        attested_now: CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest))?,
    })
}

fn reseal(bytes: &mut [u8]) {
    let end = bytes.len() - PACKAGE_TRAILER_BYTES;
    let checksum = ContentDigest::sha256(&bytes[..end]);
    bytes[end..].copy_from_slice(&checksum.bytes());
}

#[test]
fn committed_package_is_exact_deterministic_redacted_and_independently_readable() -> Test {
    let mut fixture = Fixture::new("roundtrip", 100)?;
    let root = fixture.commit()?;
    let before = fixture.snapshot()?;
    let package = fixture.package(root)?;
    assert_eq!(fixture.package(root)?.bytes(), package.bytes());
    assert_eq!(
        fixture.snapshot()?,
        before,
        "preparation writes no authority or objects"
    );
    let verified = verify_package(package.bytes(), root, &scope(30, 40)?)?;
    assert_eq!(verified, *package.verified());
    assert_eq!(verified.root(), root);
    assert_eq!(
        verified.package_digest(),
        ContentDigest::sha256(package.bytes())
    );
    assert_eq!(
        verified.record().manifest()?.children(),
        &[verified.record().digest()]
    );
    let json = verified.record().to_redacted_json();
    assert!(json.contains("\"state\":\"indeterminate\""));
    assert!(json.contains("\"raw_media_included\":false"));
    for forbidden in [
        "private-zone-name",
        "private-track-name",
        "sensor:private-front-door",
        "private raw payload sentinel",
        "private model payload sentinel",
    ] {
        assert!(!json.contains(forbidden));
        assert!(
            !package
                .bytes()
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes())
        );
    }
    drop(fixture);
    assert_eq!(
        verify_package(package.bytes(), root, &scope(30, 40)?)?,
        verified
    );
    Ok(())
}

#[test]
fn preview_and_root_only_publication_are_not_committed_export_authority() -> Test {
    let mut fixture = Fixture::new("uncommitted", 100)?;
    let preview = preview_export(
        &fixture.deployment,
        &fixture.request,
        &fixture.auth,
        &fixture.cx,
    )?;
    assert!(fixture.package(preview.root()).is_err());
    let record = preview.record();
    let manifest = record.manifest()?;
    let slot = record.slot()?;
    fixture
        .deployment
        .publisher_mut()
        .stage_object(&record.to_bytes())?;
    fixture
        .deployment
        .publisher_mut()
        .stage_manifest(&slot, &manifest)?;
    fixture.deployment.publish_and_commit(
        &slot,
        &manifest,
        CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        &fixture.cx,
    )?;
    let before = fixture.snapshot()?;
    assert!(matches!(
        prepare_package(
            &fixture.deployment,
            preview.root(),
            &scope(30, 40)?,
            &fixture.auth,
            &fixture.cx
        ),
        Err(PackageError::Export(ExportError::CustodyMismatch))
    ));
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[test]
fn all_truncations_trailing_bytes_and_header_or_payload_corruption_are_refused() -> Test {
    let mut fixture = Fixture::new("corrupt", 100)?;
    let root = fixture.commit()?;
    let package = fixture.package(root)?;
    let bytes = package.bytes();
    let admitted = scope(30, 40)?;
    for end in 0..bytes.len() {
        assert!(
            verify_package(&bytes[..end], root, &admitted).is_err(),
            "prefix {end}"
        );
    }
    for index in [0, 8, 12, 44, PACKAGE_HEADER_BYTES, bytes.len() - 1] {
        let mut corrupted = bytes.to_vec();
        corrupted[index] ^= 1;
        assert!(
            verify_package(&corrupted, root, &admitted).is_err(),
            "byte {index}"
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(verify_package(&trailing, root, &admitted).is_err());
    Ok(())
}

#[test]
fn recomputing_a_checksum_cannot_replace_the_independent_trust_root() -> Test {
    let mut fixture = Fixture::new("forgery", 100)?;
    let root = fixture.commit()?;
    let package = fixture.package(root)?;
    let mut forged = package.bytes().to_vec();
    let index = forged
        .windows(b"Owner review".len())
        .position(|w| w == b"Owner review")
        .ok_or("fixture purpose absent")?;
    forged[index] = b'P';
    reseal(&mut forged);
    assert!(matches!(
        verify_package(&forged, root, &scope(30, 40)?),
        Err(PackageError::RootMismatch)
    ));
    let end = forged.len() - PACKAGE_TRAILER_BYTES;
    let payload = &forged[PACKAGE_HEADER_BYTES..end];
    let replacement = EventExportRecord::from_bytes(payload, ContentDigest::sha256(payload))?;
    forged[12..44].copy_from_slice(&replacement.manifest()?.root().bytes());
    reseal(&mut forged);
    assert!(matches!(
        verify_package(&forged, root, &scope(30, 40)?),
        Err(PackageError::RootMismatch)
    ));
    assert!(matches!(
        verify_package(
            package.bytes(),
            ContentDigest::sha256(b"another root"),
            &scope(30, 40)?
        ),
        Err(PackageError::RootMismatch)
    ));
    Ok(())
}

#[test]
fn recipient_and_exclusive_expiry_are_enforced_without_time_midpoints() -> Test {
    let mut fixture = Fixture::new("scope", 100)?;
    let root = fixture.commit()?;
    let package = fixture.package(root)?;
    let mut other = scope(30, 40)?;
    other.recipient = "recipient:other".into();
    assert!(matches!(
        verify_package(package.bytes(), root, &other),
        Err(PackageError::RecipientMismatch)
    ));
    assert!(verify_package(package.bytes(), root, &scope(99, 99)?).is_ok());
    assert!(matches!(
        verify_package(package.bytes(), root, &scope(90, 100)?),
        Err(PackageError::ExpiryUncertain)
    ));
    assert!(matches!(
        verify_package(package.bytes(), root, &scope(100, 100)?),
        Err(PackageError::Expired)
    ));
    assert!(matches!(
        verify_package(package.bytes(), root, &scope(101, 200)?),
        Err(PackageError::Expired)
    ));
    assert!(matches!(
        verify_package(package.bytes(), root, &scope(i128::MIN, i128::MAX)?),
        Err(PackageError::ExpiryUncertain)
    ));
    Ok(())
}

#[test]
fn signed_extremes_and_invalid_scope_never_overflow_or_read_a_package() -> Test {
    let mut fixture = Fixture::new("extremes", i128::MAX)?;
    let root = fixture.commit()?;
    let package = fixture.package(root)?;
    assert!(verify_package(package.bytes(), root, &scope(i128::MIN, i128::MAX - 1)?).is_ok());
    assert!(matches!(
        verify_package(package.bytes(), root, &scope(i128::MAX, i128::MAX)?),
        Err(PackageError::Expired)
    ));
    let mut invalid = scope(30, 40)?;
    invalid.attested_now.earliest = TimestampNs(50);
    assert!(matches!(
        verify_package(&[], root, &invalid),
        Err(PackageError::InvalidScope)
    ));
    invalid = scope(30, 40)?;
    invalid.recipient = "x".repeat(MAX_RECIPIENT_BYTES + 1);
    assert!(matches!(
        verify_package(&[], root, &invalid),
        Err(PackageError::InvalidScope)
    ));
    Ok(())
}

#[test]
fn format_bound_and_untrusted_lengths_are_checked_before_record_decode() -> Test {
    let root = ContentDigest::sha256(b"root");
    let admitted = scope(30, 40)?;
    assert!(matches!(
        verify_package(&vec![0; MAX_PACKAGE_BYTES + 1], root, &admitted),
        Err(PackageError::Limit)
    ));
    assert!(matches!(
        verify_package(&vec![0; MAX_PACKAGE_BYTES], root, &admitted),
        Err(PackageError::Malformed)
    ));
    let mut fixture = Fixture::new("length", 100)?;
    let root = fixture.commit()?;
    let package = fixture.package(root)?;
    for length in [0, u32::MAX, MAX_EXPORT_RECORD_BYTES as u32 + 1] {
        let mut bytes = package.bytes().to_vec();
        bytes[44..48].copy_from_slice(&length.to_be_bytes());
        reseal(&mut bytes);
        assert!(matches!(
            verify_package(&bytes, root, &admitted),
            Err(PackageError::Malformed)
        ));
    }
    let mut bytes = package.bytes().to_vec();
    bytes[8..12].copy_from_slice(&2_u32.to_be_bytes());
    reseal(&mut bytes);
    assert!(matches!(
        verify_package(&bytes, root, &admitted),
        Err(PackageError::Malformed)
    ));
    Ok(())
}

#[test]
fn both_capabilities_original_actor_and_context_scope_are_required() -> Test {
    let mut fixture = Fixture::new("authority", 100)?;
    let root = fixture.commit()?;
    let before = fixture.snapshot()?;
    for cap in [CAP_EXPORT_PREPARE, CAP_EXPORT_COMMIT] {
        let mut denied = fixture.auth.clone();
        denied.capabilities.retain(|c| c != cap);
        assert!(matches!(
            prepare_package(
                &fixture.deployment,
                root,
                &scope(30, 40)?,
                &denied,
                &fixture.cx
            ),
            Err(PackageError::Unauthorized)
        ));
    }
    let mut other = fixture.auth.clone();
    other.principal = "principal:other".into();
    assert!(matches!(
        prepare_package(
            &fixture.deployment,
            root,
            &scope(30, 40)?,
            &other,
            &fixture.cx
        ),
        Err(PackageError::Unauthorized)
    ));
    other = fixture.auth.clone();
    other.anchor_universe = ContentDigest::sha256(b"another site");
    assert!(matches!(
        prepare_package(
            &fixture.deployment,
            root,
            &scope(30, 40)?,
            &other,
            &fixture.cx
        ),
        Err(PackageError::Unauthorized)
    ));
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[test]
fn cancellation_at_each_package_boundary_returns_no_package_and_writes_nothing() -> Test {
    for (index, stage) in ["export_package:read", "export_package:ready"]
        .iter()
        .enumerate()
    {
        let mut fixture = Fixture::new(&format!("cancel-{index}"), 100)?;
        let root = fixture.commit()?;
        let before = fixture.snapshot()?;
        fixture.cx.set_cancel_at_checkpoint(stage);
        assert!(matches!(
            prepare_package(
                &fixture.deployment,
                root,
                &scope(30, 40)?,
                &fixture.auth,
                &fixture.cx
            ),
            Err(PackageError::Cancelled)
        ));
        assert_eq!(fixture.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn cold_read_recreates_identical_package_without_the_original_request() -> Test {
    let mut fixture = Fixture::new("cold", 100)?;
    let root = fixture.commit()?;
    let bytes = fixture.package(root)?.bytes().to_vec();
    let path = fixture.deployment.root().to_path_buf();
    drop(fixture.deployment);
    let reopened = ReferenceDeployment::open(&path, SITE, &fixture.cx)?;
    let recovered = prepare_package(&reopened, root, &scope(30, 40)?, &fixture.auth, &fixture.cx)?;
    assert_eq!(recovered.bytes(), bytes);
    Ok(())
}
