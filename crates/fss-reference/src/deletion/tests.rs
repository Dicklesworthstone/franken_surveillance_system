#![forbid(unsafe_code)]

use fss_core::{CaptureInterval, ContentDigest, LedgerAnchor, Plane, TimestampNs};

use super::plan::{
    ClosureUnit, DeletableObject, DeletionCompletion, DeletionPlan, EventReference, Finding,
    ObjectTombstone, RetainedObject, RootRetraction, Unattributed, approval_digest,
};
use super::{DELETION_CUT_POINTS, DeletionError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn plan() -> Result<DeletionPlan, DeletionError> {
    let validity = CaptureInterval::new(TimestampNs(10), TimestampNs(20))?;
    Ok(DeletionPlan {
        site_lineage: "site:deletion-unit".to_owned(),
        import_identity: ContentDigest::sha256(b"import"),
        basis_anchor: LedgerAnchor {
            site_lineage: "site:deletion-unit".to_owned(),
            ledger_epoch: 1,
            commit_sequence: 7,
            adapter_registry_epoch: 1,
            schema_epoch: 1,
            policy_epoch: 1,
            privacy_epoch: 1,
            state_root: ContentDigest::sha256(b"state"),
        },
        effect_journal_root: ContentDigest::sha256(b"effects"),
        validity,
        scanned_objects: 3,
        scanned_bytes: 300,
        units: vec![ClosureUnit {
            id: "batch:file-import:aa:c0".to_owned(),
            kind: "import_custody".to_owned(),
            class: "deletable_content".to_owned(),
            via: ContentDigest::sha256(b"import"),
        }],
        deletable: vec![DeletableObject {
            digest: ContentDigest::sha256(b"chunk"),
            bytes: 100,
        }],
        retained: vec![RetainedObject {
            digest: ContentDigest::sha256(b"shared"),
            reason: "shared_with_retained_authority".to_owned(),
        }],
        tombstones: vec![ObjectTombstone {
            object_id: "object:file-import:aa".to_owned(),
            prior_generation: 2,
            plane: Plane::Authority,
            validity,
        }],
        retractions: vec![RootRetraction {
            slot: "fi-aa".to_owned(),
            root: ContentDigest::sha256(b"root"),
            prior_generation: Some(1),
            validity,
        }],
        events: vec![EventReference {
            object_id: "object:event:e".to_owned(),
            latest_revision: 1,
        }],
        blockers: Vec::new(),
        unknown_copies: vec![Finding {
            kind: "original_input_file".to_owned(),
            subject: "import".to_owned(),
            detail: "outside".to_owned(),
        }],
        unattributed: Unattributed::default(),
    })
}

#[test]
fn plan_bytes_round_trip_exactly_and_bind_their_digest() -> TestResult {
    let plan = plan()?;
    let bytes = plan.canonical_bytes()?;
    let digest = ContentDigest::sha256(&bytes);
    assert_eq!(plan.digest()?, digest);
    assert!(DeletionPlan::is_plan_bytes(&bytes));
    assert!(!DeletionCompletion::is_completion_bytes(&bytes));
    assert_eq!(DeletionPlan::decode(&bytes, digest)?, plan);
    // A different expected digest, a trailing byte and a truncation all fail closed.
    assert!(DeletionPlan::decode(&bytes, ContentDigest::sha256(b"other")).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(DeletionPlan::decode(&longer, ContentDigest::sha256(&longer)).is_err());
    let shorter = &bytes[..bytes.len() - 1];
    assert!(DeletionPlan::decode(shorter, ContentDigest::sha256(shorter)).is_err());
    Ok(())
}

#[test]
fn unsorted_lists_are_not_canonical() -> TestResult {
    let mut plan = plan()?;
    plan.deletable.push(DeletableObject {
        digest: ContentDigest::sha256(b"another"),
        bytes: 1,
    });
    plan.deletable.reverse();
    if plan.deletable[0].digest < plan.deletable[1].digest {
        plan.deletable.reverse();
    }
    let bytes = plan.canonical_bytes()?;
    assert!(DeletionPlan::decode(&bytes, ContentDigest::sha256(&bytes)).is_err());
    Ok(())
}

#[test]
fn approval_binds_plan_site_and_principal() -> TestResult {
    let digest = plan()?.digest()?;
    let approval = approval_digest(digest, "site:deletion-unit", "principal:a")?;
    assert_ne!(
        approval,
        approval_digest(digest, "site:deletion-unit", "principal:b")?
    );
    assert_ne!(
        approval,
        approval_digest(digest, "site:other", "principal:a")?
    );
    assert_ne!(
        approval,
        approval_digest(
            ContentDigest::sha256(b"x"),
            "site:deletion-unit",
            "principal:a"
        )?
    );
    Ok(())
}

#[test]
fn completion_states_unlinking_not_erasure_and_round_trips() -> TestResult {
    let plan = plan()?;
    let completion = DeletionCompletion::of(&plan)?;
    assert_eq!(completion.objects_unlinked, 1);
    assert_eq!(completion.bytes_unlinked, 100);
    assert_eq!(completion.not_proven, plan.unknown_copies);
    let bytes = completion.canonical_bytes()?;
    assert!(DeletionCompletion::is_completion_bytes(&bytes));
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("filesystem_unlink"));
    assert!(text.contains("cryptographic_erasure:spool_not_encrypted"));
    assert!(text.contains("filesystem_level_recovery"));
    assert_eq!(
        DeletionCompletion::decode(&bytes, ContentDigest::sha256(&bytes))?,
        completion
    );
    Ok(())
}

#[test]
fn cut_points_are_distinct_and_named() {
    let unique: std::collections::BTreeSet<_> = DELETION_CUT_POINTS.iter().collect();
    assert_eq!(unique.len(), DELETION_CUT_POINTS.len());
    assert!(
        DELETION_CUT_POINTS
            .iter()
            .all(|stage| stage.starts_with("deletion:"))
    );
}

#[test]
fn stable_ids_are_registered_spellings() {
    let digest = ContentDigest::sha256(b"x");
    assert_eq!(
        DeletionError::Blocked(Vec::new()).stable_id(),
        "ERR-DELETION-BLOCKED-001"
    );
    assert_eq!(
        DeletionError::StalePlan(digest).stable_id(),
        "ERR-DELETION-PLAN-STALE-001"
    );
    assert_eq!(
        DeletionError::EvidenceDeleted {
            import: digest,
            plan: digest
        }
        .stable_id(),
        "ERR-EVIDENCE-DELETED-001"
    );
}

#[test]
fn embedded_references_are_found_raw_and_hex_and_only_in_the_universe() {
    let wanted = ContentDigest::sha256(b"wanted");
    let other = ContentDigest::sha256(b"not in the universe");
    let universe: std::collections::HashSet<[u8; 32]> = [wanted.bytes()].into_iter().collect();
    let mut prefix = vec![0_u64; (1 << 24) / 64];
    let key = (usize::from(wanted.bytes()[0]) << 16)
        | (usize::from(wanted.bytes()[1]) << 8)
        | usize::from(wanted.bytes()[2]);
    prefix[key >> 6] |= 1_u64 << (key & 63);
    let hex: String = wanted.bytes().iter().map(|b| format!("{b:02x}")).collect();
    let cases: Vec<Vec<u8>> = vec![
        [b"prefix\x01".as_slice(), &wanted.bytes(), b"suffix"].concat(),
        format!("{{\"digest\":\"sha256:{hex}\"}}").into_bytes(),
        format!("capsule:{hex}:0").into_bytes(),
    ];
    for bytes in cases {
        let mut found = std::collections::BTreeSet::new();
        super::walk::embedded(&bytes, &universe, &prefix, &mut found);
        assert_eq!(found, std::collections::BTreeSet::from([wanted]));
    }
    let mut found = std::collections::BTreeSet::new();
    super::walk::embedded(&other.bytes(), &universe, &prefix, &mut found);
    assert!(found.is_empty());
    // A hex run of 63 digits is not a digest.
    let mut found = std::collections::BTreeSet::new();
    super::walk::embedded(&hex.as_bytes()[..63], &universe, &prefix, &mut found);
    assert!(found.is_empty());
}
