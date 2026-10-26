#![forbid(unsafe_code)]
//! Metadata-owner regressions; the native CLI suite separately creates real retained findings.

use super::*;
use crate::{ReferencePolicyAction, policy_decision_path};
use fss_core::{
    BatchId, CaptureInterval, EventId, EventKind, EventState, EvidenceClass, EvidenceDelta,
    ProbabilityInterval, TimestampNs,
};
use fss_ledger::IncompleteTailPolicy;
use std::cell::Cell;
use std::fs;
use std::path::PathBuf;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-alert-source-health-{label}-{}-{attempt}",
                std::process::id(),
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

fn reader<F>(read: F, width: usize) -> Reader<F> {
    Reader {
        read,
        reads: 0,
        bytes: 0,
        history: 0,
        comparisons: 0,
        width,
        deletions: DeletionIndex::default(),
    }
}

fn sensor() -> Test<SensorId> {
    Ok(SensorId::parse("sensor:alert-health-lineage")?)
}

fn edge(label: &[u8]) -> Test<EventEvidence> {
    Ok(EventEvidence {
        digest: ContentDigest::sha256(label),
        class: EvidenceClass::Derived,
        failure_domain: "domain:alert-health-lineage".into(),
        supports: true,
        relation: EvidenceEdgeRelation::Supports,
        capsule_digest: Some(ContentDigest::sha256(b"one-capsule-two-interpretations")),
        identity_digest: Some(ContentDigest::sha256(sensor()?.as_str().as_bytes())),
    })
}

fn event(edges: Vec<EventEvidence>, prior: Option<&EventHypothesis>) -> Test<EventHypothesis> {
    let event_id = EventId::parse("event:alert-health-lineage")?;
    let state = EventState::Witnessed;
    let value = EventHypothesis {
        schema: EventHypothesis::SCHEMA.into(),
        event_id: event_id.clone(),
        revision: prior.map_or(1, |prior| prior.revision + 1),
        supersedes: prior.map(EventHypothesis::revision_digest),
        state,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        uncertainty_reason: None,
        zone_ids: Vec::new(),
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        decision_path: policy_decision_path(&event_id, &edges, state, ReferencePolicyAction::Hold),
        evidence: edges,
        model_receipts: Vec::new(),
    };
    value.verify()?;
    Ok(value)
}

fn append_event(
    ledger: &mut DurableReferenceLedger,
    payloads: &mut BTreeMap<ContentDigest, Vec<u8>>,
    event: &EventHypothesis,
) -> Test {
    let bytes = event.canonical_bytes();
    let payload = ContentDigest::sha256(&bytes);
    payloads.insert(payload, bytes);
    let root = ObjectManifest::new("event-revision", Vec::new(), Some(payload))?;
    payloads.insert(root.root(), root.canonical_bytes());
    let delta = EvidenceDelta {
        delta_id: format!("delta:test-event:{}", event.revision),
        family: "event_revision".into(),
        object_id: ObjectId::parse(format!("object:event:{}", event.event_id.as_str()))?,
        prior_generation: (event.revision > 1).then_some(event.revision - 1),
        new_generation: event.revision,
        validity: event.interval,
        plane: Plane::Authority,
        payload_digest: root.root(),
        witness_digest: Some(event.revision_digest()),
        operation_id: None,
    };
    let batch = ledger.prepare_batch(
        BatchId::parse(format!("batch:test-event:{}", event.revision))?,
        vec![delta],
        [root.root()],
    )?;
    ledger.append(batch)?;
    Ok(())
}

fn append_policy(
    ledger: &mut DurableReferenceLedger,
    payloads: &mut BTreeMap<ContentDigest, Vec<u8>>,
    policy: &PrivacyMaskPolicy,
    generation: u64,
) -> Test {
    payloads.insert(policy.digest(), policy.to_bytes());
    let delta = EvidenceDelta {
        delta_id: format!("delta:test-mask:{generation}"),
        family: FAMILY_PRIVACY_MASK_POLICY.into(),
        object_id: mask_object_id(policy.sensor_id())?,
        prior_generation: (generation > 1).then_some(generation - 1),
        new_generation: generation,
        validity: CaptureInterval::new(TimestampNs(0), TimestampNs(100))?,
        plane: Plane::Authority,
        payload_digest: policy.digest(),
        witness_digest: None,
        operation_id: None,
    };
    let batch = ledger.prepare_batch(
        BatchId::parse(format!("batch:test-mask:{generation}"))?,
        vec![delta],
        [policy.digest()],
    )?;
    ledger.append(batch)?;
    Ok(())
}

#[test]
fn carried_edges_keep_original_privacy_and_each_new_edge_uses_its_own_prefix() -> Test {
    let directory = Directory::new("privacy")?;
    let mut ledger = DurableReferenceLedger::open(
        directory.0.join("ledger"),
        "site:alert-health",
        IncompleteTailPolicy::Reject,
    )?;
    let mut payloads = BTreeMap::new();
    let a = edge(b"unmasked-native-entry")?;
    let first = event(vec![a.clone()], None)?;
    append_event(&mut ledger, &mut payloads, &first)?;
    let policy_one = PrivacyMaskPolicy::new(sensor()?, [32, 32], &[[0, 0, 2, 2]])?;
    append_policy(&mut ledger, &mut payloads, &policy_one, 1)?;
    let b = edge(b"new-entry-under-first-mask")?;
    let second = event(vec![a.clone(), b.clone()], Some(&first))?;
    append_event(&mut ledger, &mut payloads, &second)?;
    let policy_two = PrivacyMaskPolicy::new(sensor()?, [32, 32], &[[1, 1, 2, 2]])?;
    append_policy(&mut ledger, &mut payloads, &policy_two, 2)?;
    let third = event(vec![a.clone(), b.clone()], Some(&second))?;
    append_event(&mut ledger, &mut payloads, &third)?;
    let mut metadata = reader(
        |digest| {
            payloads
                .get(&digest)
                .cloned()
                .ok_or(refusal("test_missing"))
        },
        32,
    );
    let supports = [
        (
            a.capsule_digest.ok_or("capsule")?,
            a.identity_digest.ok_or("identity")?,
            &a,
        ),
        (
            b.capsule_digest.ok_or("capsule")?,
            b.identity_digest.ok_or("identity")?,
            &b,
        ),
    ];
    let origins = support_origins(&ledger, &third, &supports, &mut metadata)?;
    assert_eq!(
        origins,
        [0, 2],
        "same capsule does not merge distinct evidence interpretations"
    );
    assert_eq!(
        historical_privacy(&ledger.batches()[..=origins[0]], &sensor()?, &mut metadata)?,
        (None, None)
    );
    assert_eq!(
        historical_privacy(&ledger.batches()[..=origins[1]], &sensor()?, &mut metadata)?,
        (Some(policy_one.digest()), Some(1))
    );
    assert_eq!(
        historical_privacy(ledger.batches(), &sensor()?, &mut metadata)?,
        (Some(policy_two.digest()), Some(2))
    );
    // Corrupt original lineage bytes cannot make carried evidence appear freshly interpreted.
    let first_root = ledger.batches()[0].deltas[0].payload_digest;
    let mut broken = reader(
        |digest| -> Result<Vec<u8>> {
            if digest == first_root {
                Ok(b"changed earlier event root".to_vec())
            } else {
                payloads
                    .get(&digest)
                    .cloned()
                    .ok_or(refusal("test_missing"))
            }
        },
        32,
    );
    assert!(matches!(
        support_origins(&ledger, &third, &supports, &mut broken),
        Err(ReferenceError::AlertSourceHealth("invalid_record"))
    ));
    Ok(())
}

#[test]
fn current_policy_cannot_repair_a_broken_historical_generation_chain() -> Test {
    let directory = Directory::new("privacy-chain")?;
    let mut ledger = DurableReferenceLedger::open(
        directory.0.join("ledger"),
        "site:alert-health",
        IncompleteTailPolicy::Reject,
    )?;
    let mut payloads = BTreeMap::new();
    let policy = PrivacyMaskPolicy::new(sensor()?, [32, 32], &[[0, 0, 2, 2]])?;
    append_policy(&mut ledger, &mut payloads, &policy, 1)?;
    let mut prefix = ledger.batches().to_vec();
    prefix[0].deltas[0].prior_generation = Some(u64::MAX);
    let calls = Cell::new(0);
    let mut metadata = reader(
        |digest| {
            calls.set(calls.get() + 1);
            payloads
                .get(&digest)
                .cloned()
                .ok_or(refusal("test_missing"))
        },
        4,
    );
    assert!(matches!(
        historical_privacy(&prefix, &sensor()?, &mut metadata),
        Err(ReferenceError::AlertSourceHealth("invalid_privacy_binding"))
    ));
    assert_eq!(
        calls.get(),
        0,
        "invalid lineage is refused before opening a policy"
    );
    Ok(())
}

#[test]
fn shared_metadata_allowances_admit_work_before_the_read_and_do_not_refill() {
    let calls = Cell::new(0);
    let mut metadata = reader(
        |_| -> Result<Vec<u8>> {
            calls.set(calls.get() + 1);
            Err(ReferenceError::InvalidSpec("test_unavailable"))
        },
        4,
    );
    metadata.reads = MAX_READS - 1;
    let digest = ContentDigest::sha256(b"unavailable");
    assert!(matches!(
        metadata.read(digest, 64),
        Err(ReferenceError::AlertSourceHealth("metadata_unavailable"))
    ));
    assert!(matches!(
        metadata.read(digest, 64),
        Err(ReferenceError::AlertSourceHealth("bound_exceeded"))
    ));
    assert_eq!(
        calls.get(),
        1,
        "failed attempts spend the operation's shared read allowance"
    );
    let calls = Cell::new(0);
    let mut metadata = reader(
        |_| -> Result<Vec<u8>> {
            calls.set(calls.get() + 1);
            Ok(Vec::new())
        },
        4,
    );
    metadata.bytes = MAX_METADATA_BYTES;
    assert!(matches!(
        metadata.read(digest, 64),
        Err(ReferenceError::AlertSourceHealth("bound_exceeded"))
    ));
    assert_eq!(calls.get(), 0);
    metadata.comparisons = MAX_MATCH_WORK;
    assert!(matches!(
        metadata.compare(1),
        Err(ReferenceError::AlertSourceHealth("bound_exceeded"))
    ));
    metadata.history = MAX_HISTORY_WORK;
    assert!(matches!(
        metadata.history(1),
        Err(ReferenceError::AlertSourceHealth("bound_exceeded"))
    ));
}

#[test]
fn absent_diagnostics_and_legacy_edges_require_no_metadata_reads() -> Test {
    let directory = Directory::new("no-diagnostic")?;
    let mut ledger = DurableReferenceLedger::open(
        directory.0.join("ledger"),
        "site:alert-health",
        IncompleteTailPolicy::Reject,
    )?;
    let mut payloads = BTreeMap::new();
    let native = event(vec![edge(b"native-entry")?], None)?;
    append_event(&mut ledger, &mut payloads, &native)?;
    let calls = Cell::new(0);
    check_alert_historical_health(&ledger, &native, |_| -> Result<Vec<u8>> {
        calls.set(calls.get() + 1);
        Err(refusal("unexpected_read"))
    })?;
    let mut legacy = native.clone();
    for edge in &mut legacy.evidence {
        edge.capsule_digest = None;
        edge.identity_digest = None;
    }
    check_alert_historical_health(&ledger, &legacy, |_| -> Result<Vec<u8>> {
        calls.set(calls.get() + 1);
        Err(refusal("unexpected_read"))
    })?;
    // Capsule admission counts distinct source objects; edge count and comparisons have
    // separate shared bounds. Many evidence edges can legitimately name the same capsule.
    let edges = (0..=MAX_CAPSULES)
        .map(|index| edge(format!("shared-capsule-entry:{index}").as_bytes()))
        .collect::<Test<Vec<_>>>()?;
    let shared = event(edges, Some(&native))?;
    append_event(&mut ledger, &mut payloads, &shared)?;
    check_alert_historical_health(&ledger, &shared, |_| -> Result<Vec<u8>> {
        calls.set(calls.get() + 1);
        Err(refusal("unexpected_read"))
    })?;
    let unique_edges = shared
        .evidence
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, mut edge)| {
            edge.capsule_digest = Some(ContentDigest::sha256(
                format!("unique-capsule:{index}").as_bytes(),
            ));
            edge
        })
        .collect();
    let unique = event(unique_edges, Some(&shared))?;
    append_event(&mut ledger, &mut payloads, &unique)?;
    assert!(matches!(
        check_alert_historical_health(&ledger, &unique, |_| -> Result<Vec<u8>> {
            calls.set(calls.get() + 1);
            Err(refusal("unexpected_read"))
        }),
        Err(ReferenceError::AlertSourceHealth("bound_exceeded"))
    ));
    assert_eq!(
        calls.get(),
        0,
        "unknown health and capsule admission require no payload reads"
    );
    Ok(())
}
