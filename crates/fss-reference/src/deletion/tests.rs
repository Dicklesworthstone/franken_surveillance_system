#![forbid(unsafe_code)]

use fss_core::{CaptureInterval, ContentDigest, LedgerAnchor, Plane, TimestampNs};

use super::plan::{
    ClosureUnit, DeletableObject, DeletionCompletion, DeletionPlan, EventReference, Finding,
    ObjectTombstone, RetainedObject, RootRetraction, Unattributed, approval_digest,
};
use super::{DELETION_CUT_POINTS, DeletionError, DeletionScope};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn plan() -> Result<DeletionPlan, DeletionError> {
    let validity = CaptureInterval::new(TimestampNs(10), TimestampNs(20))?;
    Ok(DeletionPlan {
        site_lineage: "site:deletion-unit".to_owned(),
        scope: DeletionScope::Import(ContentDigest::sha256(b"import")),
        imports: vec![ContentDigest::sha256(b"import")],
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

fn scoped(scope: DeletionScope) -> Result<DeletionPlan, DeletionError> {
    let mut plan = plan()?;
    let mut imports = vec![ContentDigest::sha256(b"a"), ContentDigest::sha256(b"b")];
    imports.sort();
    plan.scope = scope;
    plan.imports = imports;
    Ok(plan)
}

/// The v1 plan layout exactly as it was before scopes existed, encoded independently.
fn legacy_v1_bytes(plan: &DeletionPlan) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use fss_core::{CanonicalEncode, CanonicalEncoder};
    let mut e = CanonicalEncoder::new();
    e.text("fss.canonical.v1");
    e.text("fss.deletion_plan.v1");
    e.text(&plan.site_lineage);
    e.digest(plan.imports[0]);
    plan.basis_anchor.encode_canonical(&mut e);
    e.digest(plan.effect_journal_root);
    plan.validity.encode_canonical(&mut e);
    e.u64(plan.scanned_objects);
    e.u64(plan.scanned_bytes);
    e.u64(plan.units.len() as u64);
    for u in &plan.units {
        e.text(&u.id);
        e.text(&u.kind);
        e.text(&u.class);
        e.digest(u.via);
    }
    e.u64(plan.deletable.len() as u64);
    for o in &plan.deletable {
        e.digest(o.digest);
        e.u64(o.bytes);
    }
    e.u64(plan.retained.len() as u64);
    for o in &plan.retained {
        e.digest(o.digest);
        e.text(&o.reason);
    }
    e.u64(plan.tombstones.len() as u64);
    for t in &plan.tombstones {
        e.text(&t.object_id);
        e.u64(t.prior_generation);
        e.text(t.plane.as_str());
        t.validity.encode_canonical(&mut e);
    }
    e.u64(plan.retractions.len() as u64);
    for r in &plan.retractions {
        e.text(&r.slot);
        e.digest(r.root);
        match r.prior_generation {
            Some(generation) => {
                e.bool(true);
                e.u64(generation);
            }
            None => e.bool(false),
        }
        r.validity.encode_canonical(&mut e);
    }
    e.u64(plan.events.len() as u64);
    for ev in &plan.events {
        e.text(&ev.object_id);
        e.u64(ev.latest_revision);
    }
    for findings in [&plan.blockers, &plan.unknown_copies] {
        e.u64(findings.len() as u64);
        for f in findings {
            e.text(&f.kind);
            e.text(&f.subject);
            e.text(&f.detail);
        }
    }
    e.u64(plan.unattributed.staging_files);
    e.u64(plan.unattributed.staging_bytes);
    e.u64(plan.unattributed.objects);
    e.u64(plan.unattributed.object_bytes);
    e.text("filesystem_unlink");
    Ok(e.finish_checked()?)
}

#[test]
fn import_scope_plans_keep_their_exact_v1_bytes_and_digest() -> TestResult {
    let plan = plan()?;
    let bytes = plan.canonical_bytes()?;
    assert_eq!(bytes, legacy_v1_bytes(&plan)?, "import plans are unchanged");
    assert_eq!(plan.domain(), super::DELETION_PLAN_DOMAIN);
    assert_eq!(
        plan.record_object_id_of(plan.digest()?),
        DeletionPlan::record_object_id(plan.imports[0])
    );
    // An import scope whose member list is not exactly its import has no encoding.
    let mut wrong = plan.clone();
    wrong.imports.push(ContentDigest::sha256(b"zzz"));
    assert!(wrong.canonical_bytes().is_err());
    Ok(())
}

#[test]
fn scoped_plans_bind_scope_kind_and_id_and_round_trip() -> TestResult {
    let sensor = scoped(DeletionScope::Sensor(fss_core::SensorId::parse(
        "sensor:alpha",
    )?))?;
    let other = scoped(DeletionScope::Sensor(fss_core::SensorId::parse(
        "sensor:gamma",
    )?))?;
    let event = scoped(DeletionScope::Event(fss_core::EventId::parse(
        "sensor:alpha",
    )?))?;
    let bytes = sensor.canonical_bytes()?;
    assert!(DeletionPlan::is_plan_bytes(&bytes));
    assert_eq!(sensor.domain(), super::DELETION_SCOPE_PLAN_DOMAIN);
    assert_eq!(DeletionPlan::decode(&bytes, sensor.digest()?)?, sensor);
    // Same members and closure, different scope id or kind: different sealed plans.
    let digests: std::collections::BTreeSet<ContentDigest> = [&sensor, &other, &event]
        .iter()
        .map(|p| p.digest())
        .collect::<Result<_, _>>()?;
    assert_eq!(digests.len(), 3);
    assert_ne!(
        sensor.record_object_id_of(sensor.digest()?),
        other.record_object_id_of(other.digest()?)
    );
    // Tampering with the scope id breaks the sealed digest.
    let at = bytes
        .windows(12)
        .position(|w| w == b"sensor:alpha")
        .ok_or("scope id")?;
    let mut tampered = bytes.clone();
    tampered[at..at + 12].copy_from_slice(b"sensor:gamma");
    assert!(DeletionPlan::decode(&tampered, sensor.digest()?).is_err());
    assert_eq!(
        DeletionPlan::decode(&tampered, ContentDigest::sha256(&tampered))?,
        other
    );
    // Unsorted or empty member lists are not canonical.
    let mut unsorted = sensor.clone();
    unsorted.imports.reverse();
    let b = unsorted.canonical_bytes()?;
    assert!(DeletionPlan::decode(&b, ContentDigest::sha256(&b)).is_err());
    let mut empty = sensor.clone();
    empty.imports.clear();
    let b = empty.canonical_bytes()?;
    assert!(DeletionPlan::decode(&b, ContentDigest::sha256(&b)).is_err());
    // The completion record carries the scope and round trips under v2.
    let completion = DeletionCompletion::of(&sensor)?;
    let c = completion.canonical_bytes()?;
    assert!(DeletionCompletion::is_completion_bytes(&c));
    assert_eq!(
        DeletionCompletion::decode(&c, ContentDigest::sha256(&c))?,
        completion
    );
    assert_eq!(completion.imports, sensor.imports);
    Ok(())
}
