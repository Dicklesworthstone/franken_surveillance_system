#![forbid(unsafe_code)]
use super::*;
use fss_core::DigestAlgorithm;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Frozen v1 record from the original layout, independently encoded from its declared fields.
// The domain's final byte is at 34; the route ends at 271. Neither offset depends on the new
// writer, so the migration cannot bless its own reordered or enlarged legacy representation.
const LEGACY_HEX: &str = concat!(
    "000000000000001b6673732e7265666572656e63655f6167656e745f706c616e2e76310000000000000007706c616e3a",
    "3030000000000000000973657373696f6e3a6100000000000000096d697373696f6e3a6100000000000000187072696e",
    "636970616c3a6c6f63616c2d6f70657261746f720000000000000008616e63686f723a780000000000000005616c6572",
    "7400000000000000076576656e743a61012b214ddf3326016519afcb268f63623b80b91a65265277668e4d020d87dd90",
    "78000000000000000b3132372e302e302e313a39000000000000000a2f6673732f616c657274019deb65b8788f41ff94",
    "a217842017db2f843954fc0eb46110835903908e5a265f000000000000138800000000000000116f7065726174696f6e",
    "3a616c6572743a7800000000000000126f626c69676174696f6e3a616c6572743a780164879f7d6b960a01909762d911",
    "a32d4582c20010c5641ee90278b644a9e3b52501512d0f29088c76daad57b9c3569733021775483b2ca319fa56c99a07",
    "dd996d4e010000000000000006636173653a6101bbfcd4160a1e8674dac62292ae48be4785262ad7078f9ec11b74a254",
    "ce70fa0600000000000000000000000000000007",
);
const DOMAIN_VERSION_OFFSET: usize = 34;
const DISCLOSURE_OFFSET: usize = 271;

fn legacy_bytes() -> Test<Vec<u8>> {
    (0..LEGACY_HEX.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&LEGACY_HEX[index..index + 2], 16)?))
        .collect()
}

fn record() -> Result<PlanRecord, ContractError> {
    Ok(PlanRecord {
        plan_id: "plan:00".to_owned(),
        session_id: SessionId::parse("session:a")?,
        mission_id: MissionId::parse("mission:a")?,
        principal: PrincipalId::parse("principal:local-operator")?,
        anchor_token: "anchor:x".to_owned(),
        intent: "alert".to_owned(),
        event_id: "event:a".to_owned(),
        event_revision: ContentDigest::sha256(b"revision"),
        route: AlertRoute {
            relay: "127.0.0.1:9".to_owned(),
            path: "/fss/alert".to_owned(),
            plaintext_approval: ContentDigest::sha256(b"approval"),
            deadline_ms: 5_000,
            disclosure_profile: WebhookDisclosureProfile::ReferencesV1,
            metadata_approval: None,
        },
        operation_id: "operation:alert:x".to_owned(),
        obligation_id: "obligation:alert:x".to_owned(),
        plan_approval: ContentDigest::sha256(b"plan"),
        control_plan_digest: ContentDigest::sha256(b"dag"),
        case: Some(("case:a".to_owned(), ContentDigest::sha256(b"case"))),
        created_at: TimestampNs(7),
    })
}

#[test]
fn plan_records_round_trip_exactly_and_refuse_any_other_bytes() -> Result<(), ContractError> {
    let record = record()?;
    let bytes = record.to_bytes();
    assert_eq!(PlanRecord::from_bytes(&bytes)?, record);
    let mut without_case = record.clone();
    without_case.case = None;
    assert_eq!(
        PlanRecord::from_bytes(&without_case.to_bytes())?,
        without_case
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(PlanRecord::from_bytes(&trailing).is_err());
    assert!(PlanRecord::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    Ok(())
}

#[test]
fn plan_identity_binds_session_anchor_and_approval() -> Result<(), ContractError> {
    let session = SessionId::parse("session:a")?;
    let approval = ContentDigest::sha256(b"plan");
    let base = PlanRecord::identity(&session, "anchor:x", approval);
    assert_eq!(base, "plan:b5a4aeb63d5dbb6d3e243b15d0aa8126");
    assert_eq!(base, PlanRecord::identity(&session, "anchor:x", approval));
    assert_ne!(base, PlanRecord::identity(&session, "anchor:y", approval));
    assert_ne!(
        base,
        PlanRecord::identity(&session, "anchor:x", ContentDigest::sha256(b"other"))
    );
    assert_ne!(
        base,
        PlanRecord::identity(&SessionId::parse("session:b")?, "anchor:x", approval)
    );
    Ok(())
}

fn metadata_record() -> Test<PlanRecord> {
    let mut record = record()?;
    record.route.disclosure_profile = WebhookDisclosureProfile::EventMetadataV1;
    record.route.metadata_approval = Some(ContentDigest::sha256(b"event metadata approval"));
    Ok(record)
}

#[test]
fn reference_record_retains_frozen_v1_bytes_and_never_infers_metadata_approval() -> Test {
    let golden = legacy_bytes()?;
    assert_eq!(golden.len(), 452);
    assert_eq!(
        ContentDigest::sha256(&golden).to_text(),
        "sha256:89131d38a73e78c45c1b0f862949c931024af67740b975ba223b22182bbca257"
    );
    assert_eq!(record()?.to_bytes(), golden);
    let decoded = PlanRecord::from_bytes(&golden)?;
    assert_eq!(decoded, record()?);
    assert_eq!(
        decoded.route.disclosure_profile,
        WebhookDisclosureProfile::ReferencesV1
    );
    assert_eq!(decoded.route.metadata_approval, None);
    assert_eq!(decoded.to_bytes(), golden);
    Ok(())
}

#[test]
fn rich_record_roundtrip_retains_exact_profile_approval_and_versioned_field_order() -> Test {
    let original = metadata_record()?;
    let bytes = original.to_bytes();
    let mut expected = legacy_bytes()?;
    expected[DOMAIN_VERSION_OFFSET] = b'2';
    let mut extension = vec![2, 1, 1]; // Profile, presence, SHA-256 algorithm.
    extension.extend_from_slice(&ContentDigest::sha256(b"event metadata approval").bytes());
    expected.splice(DISCLOSURE_OFFSET..DISCLOSURE_OFFSET, extension);
    assert_eq!(bytes, expected);
    assert_eq!(PlanRecord::from_bytes(&bytes)?, original);
    assert_eq!(PlanRecord::from_bytes(&bytes)?.to_bytes(), bytes);
    let mut without_case = original.clone();
    without_case.case = None;
    assert_eq!(
        PlanRecord::from_bytes(&without_case.to_bytes())?,
        without_case
    );
    let mut changed = original;
    changed.route.metadata_approval = Some(ContentDigest::sha256(b"new metadata approval"));
    assert_ne!(
        ContentDigest::sha256(&changed.to_bytes()),
        ContentDigest::sha256(&bytes)
    );
    assert_eq!(PlanRecord::from_bytes(&changed.to_bytes())?, changed);
    Ok(())
}

#[test]
fn missing_zero_and_non_sha256_metadata_approvals_are_refused() -> Test {
    for approval in [
        None,
        Some(ContentDigest::new(DigestAlgorithm::Sha256, [0; 32])),
        Some(ContentDigest::new(DigestAlgorithm::Blake3, [7; 32])),
    ] {
        let mut record = metadata_record()?;
        record.route.metadata_approval = approval;
        assert_eq!(
            record.route.validate_disclosure(),
            Err(ContractError::InvalidIdentifier)
        );
        assert_eq!(
            PlanRecord::from_bytes(&record.to_bytes()),
            Err(ContractError::InvalidIdentifier)
        );
    }
    Ok(())
}

#[test]
fn reference_record_cannot_smuggle_or_silently_discard_an_inapplicable_approval() -> Test {
    let mut record = record()?;
    record.route.metadata_approval = Some(ContentDigest::sha256(b"stray approval"));
    assert_eq!(
        record.route.validate_disclosure(),
        Err(ContractError::InvalidIdentifier)
    );
    let bytes = record.to_bytes();
    assert_ne!(bytes, legacy_bytes()?);
    assert_eq!(bytes[DOMAIN_VERSION_OFFSET], b'2');
    assert_eq!(bytes[DISCLOSURE_OFFSET..DISCLOSURE_OFFSET + 3], [1, 1, 1]);
    assert_eq!(
        PlanRecord::from_bytes(&bytes),
        Err(ContractError::InvalidIdentifier)
    );
    Ok(())
}

#[test]
fn rich_record_refuses_unknown_profile_tag_and_noncanonical_approval_boolean() -> Test {
    let original = metadata_record()?.to_bytes();
    for tag in [0, 3, 255] {
        let mut bytes = original.clone();
        bytes[DISCLOSURE_OFFSET] = tag;
        assert_eq!(
            PlanRecord::from_bytes(&bytes),
            Err(ContractError::UnknownEntryTag(tag))
        );
    }
    let mut bytes = original;
    bytes[DISCLOSURE_OFFSET + 1] = 2;
    assert_eq!(
        PlanRecord::from_bytes(&bytes),
        Err(ContractError::InvalidIdentifier)
    );
    Ok(())
}

#[test]
fn reference_only_v2_and_version_retagging_never_change_old_disclosure() -> Test {
    let mut bytes = metadata_record()?.to_bytes();
    bytes[DISCLOSURE_OFFSET] = 1;
    bytes[DISCLOSURE_OFFSET + 1] = 0;
    bytes.drain(DISCLOSURE_OFFSET + 2..DISCLOSURE_OFFSET + 35);
    assert_eq!(
        PlanRecord::from_bytes(&bytes),
        Err(ContractError::InvalidIdentifier)
    );

    // A version change alone cannot reinterpret a retained approval as metadata approval.
    let mut old = legacy_bytes()?;
    old[DOMAIN_VERSION_OFFSET] = b'2';
    assert!(PlanRecord::from_bytes(&old).is_err());
    let mut rich = metadata_record()?.to_bytes();
    rich[DOMAIN_VERSION_OFFSET] = b'1';
    assert!(PlanRecord::from_bytes(&rich).is_err());
    rich[DOMAIN_VERSION_OFFSET] = b'3';
    assert_eq!(
        PlanRecord::from_bytes(&rich),
        Err(ContractError::DigestMismatch)
    );
    Ok(())
}

#[test]
fn every_truncated_prefix_trailing_bytes_and_oversized_record_are_refused() -> Test {
    for bytes in [legacy_bytes()?, metadata_record()?.to_bytes()] {
        for end in 0..bytes.len() {
            assert!(
                PlanRecord::from_bytes(&bytes[..end]).is_err(),
                "accepted prefix {end}"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PlanRecord::from_bytes(&trailing).is_err());
    }
    assert_eq!(
        PlanRecord::from_bytes(&vec![0; MAX_PLAN_RECORD_BYTES + 1]),
        Err(ContractError::CountBoundExceeded)
    );
    Ok(())
}
