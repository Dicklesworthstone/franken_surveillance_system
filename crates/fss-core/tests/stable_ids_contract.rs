//! Tests for FSS-001 stable ID and generation newtypes.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    AdapterEpoch, AdapterGeneration, AffordanceId, BatchId, CANONICAL_FORMAT_MAGIC,
    CANONICAL_VERSION_1, CalibrationGeneration, CanonicalDecode, CanonicalDecoder, CanonicalEncode,
    CanonicalEncoder, CanonicalVersionEnvelope, CapsuleId, CaptureInterval, CaseId, ContentDigest,
    ContextPackId, ContractError, DeviceGeneration, DeviceId, EpisodeId, Epoch, EventId, FindingId,
    Generation, GraphGeneration, HandoffId, HypothesisId, IdempotencyKey, IdentityLifecycleState,
    LedgerEpoch, MAX_CANONICAL_BYTES_LEN, MAX_CANONICAL_TEXT_BYTES, MissionId, ModelGeneration,
    ObjectId, ObligationId, OntologyGeneration, OperationId, PlanId, PolicyEpoch, PolicyGeneration,
    PolicyId, PrincipalId, PrivacyEpoch, PrivacyGeneration, PropertyId, SchemaEpoch, SchemaId,
    SearchGeneration, SensorId, SessionId, StreamGeneration, StreamId, TimestampNs, TombstoneId,
    TombstoneReason, TombstoneRecord, TombstoneRegistry, TrackId, WorkspaceId,
};

#[test]
fn stable_id_all_types_valid_parse() -> Result<(), ContractError> {
    let sensor = SensorId::parse("sensor-front-01")?;
    let stream = StreamId::parse("stream:h264:1080p")?;
    let capsule = CapsuleId::parse("capsule_2026_09_10_0001")?;
    let batch = BatchId::parse("batch.001.genesis")?;
    let event = EventId::parse("event-lineage-42")?;
    let op = OperationId::parse("op:alert:deliver:1")?;
    let idem = IdempotencyKey::parse("idem_key_abcdef1234")?;
    let oblig = ObligationId::parse("oblig-drain-999")?;
    let principal = PrincipalId::parse("principal:operator:alice")?;
    let session = SessionId::parse("session:agent:crimson-willow")?;
    let mission = MissionId::parse("mission:perimeter-patrol")?;
    let handoff = HandoffId::parse("handoff:root:001")?;
    let object = ObjectId::parse("object:source-segment:777")?;
    let device = DeviceId::parse("device:insta360-link-1")?;
    let track = TrackId::parse("track:person:042")?;
    let case = CaseId::parse("case:investigation:101")?;
    let hypothesis = HypothesisId::parse("hypo:intruder:alpha")?;
    let plan = PlanId::parse("plan:contingent:ptz-track")?;
    let episode = EpisodeId::parse("episode:2026-09-10-run1")?;
    let finding = FindingId::parse("finding:blind-spot:north-gate")?;
    let pack = ContextPackId::parse("pack:context:pulse-view")?;
    let workspace = WorkspaceId::parse("ws:operator-console")?;
    let affordance = AffordanceId::parse("affordance:zoom-view")?;
    let property = PropertyId::parse("property:site-main-compound")?;
    let tombstone_id = TombstoneId::parse("tombstone:record:99")?;
    let schema_id = SchemaId::parse("schema:fss.evidence_anchor.v1")?;
    let policy_id = PolicyId::parse("policy:alert:threshold:v2")?;

    assert_eq!(sensor.as_str(), "sensor-front-01");
    assert_eq!(stream.as_str(), "stream:h264:1080p");
    assert_eq!(capsule.as_str(), "capsule_2026_09_10_0001");
    assert_eq!(batch.as_str(), "batch.001.genesis");
    assert_eq!(event.as_str(), "event-lineage-42");
    assert_eq!(op.as_str(), "op:alert:deliver:1");
    assert_eq!(idem.as_str(), "idem_key_abcdef1234");
    assert_eq!(oblig.as_str(), "oblig-drain-999");
    assert_eq!(principal.as_str(), "principal:operator:alice");
    assert_eq!(session.as_str(), "session:agent:crimson-willow");
    assert_eq!(mission.as_str(), "mission:perimeter-patrol");
    assert_eq!(handoff.as_str(), "handoff:root:001");
    assert_eq!(object.as_str(), "object:source-segment:777");
    assert_eq!(device.as_str(), "device:insta360-link-1");
    assert_eq!(track.as_str(), "track:person:042");
    assert_eq!(case.as_str(), "case:investigation:101");
    assert_eq!(hypothesis.as_str(), "hypo:intruder:alpha");
    assert_eq!(plan.as_str(), "plan:contingent:ptz-track");
    assert_eq!(episode.as_str(), "episode:2026-09-10-run1");
    assert_eq!(finding.as_str(), "finding:blind-spot:north-gate");
    assert_eq!(pack.as_str(), "pack:context:pulse-view");
    assert_eq!(workspace.as_str(), "ws:operator-console");
    assert_eq!(affordance.as_str(), "affordance:zoom-view");
    assert_eq!(property.as_str(), "property:site-main-compound");
    assert_eq!(tombstone_id.as_str(), "tombstone:record:99");
    assert_eq!(schema_id.as_str(), "schema:fss.evidence_anchor.v1");
    assert_eq!(policy_id.as_str(), "policy:alert:threshold:v2");
    Ok(())
}

#[test]
fn stable_id_hard_bounds_and_rejected_characters() {
    // Empty string rejected
    assert_eq!(SensorId::parse(""), Err(ContractError::InvalidIdentifier));

    // Exactly 1 char accepted (minimum bound)
    assert!(SensorId::parse("a").is_ok());

    // Exactly 128 chars accepted (maximum bound)
    let max_len_str = "a".repeat(128);
    assert!(SensorId::parse(&max_len_str).is_ok());

    // 129 chars rejected (exceeds bound)
    let oversized = "a".repeat(129);
    assert_eq!(
        SensorId::parse(&oversized),
        Err(ContractError::InvalidIdentifier)
    );

    // Spaces forbidden
    assert_eq!(
        SensorId::parse("id with spaces"),
        Err(ContractError::InvalidIdentifier)
    );

    // Control characters forbidden
    assert_eq!(
        SensorId::parse("id\twith\ttab"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SensorId::parse("id\nwith\nnewline"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SensorId::parse("id\0with\0null"),
        Err(ContractError::InvalidIdentifier)
    );

    // Slash and backslash forbidden
    assert_eq!(
        SensorId::parse("path/traversal"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SensorId::parse("path\\traversal"),
        Err(ContractError::InvalidIdentifier)
    );

    // Quotes and brackets forbidden
    assert_eq!(
        SensorId::parse("\"quoted\""),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SensorId::parse("<xml>"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SensorId::parse("{json:true}"),
        Err(ContractError::InvalidIdentifier)
    );

    // Non-ASCII unicode forbidden
    assert_eq!(
        SensorId::parse("sensor-カメラ"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SensorId::parse("sensor-🚀"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SensorId::parse("café"),
        Err(ContractError::InvalidIdentifier)
    );
}

#[test]
fn stable_id_canonical_ordering_is_lexicographical() -> Result<(), ContractError> {
    let id_a = SensorId::parse("cam-01")?;
    let id_b = SensorId::parse("cam-02")?;
    let id_c = SensorId::parse("cam-10")?;

    assert!(id_a < id_b);
    assert!(id_b < id_c);
    assert!(id_a < id_c);

    let mut set = BTreeSet::new();
    set.insert(id_c.clone());
    set.insert(id_a.clone());
    set.insert(id_b.clone());

    let ordered: Vec<_> = set.into_iter().collect();
    assert_eq!(ordered, vec![id_a, id_b, id_c]);
    Ok(())
}

#[test]
fn stable_id_canonical_encoding_distinct_from_json() -> Result<(), ContractError> {
    let sensor = SensorId::parse("cam-front-01")?;
    let canonical_bytes = sensor.canonical_bytes();

    // Canonical encoding starts with 64-bit big-endian length prefix (8 bytes)
    assert_eq!(canonical_bytes.len(), 8 + "cam-front-01".len());
    let len_prefix = u64::from_be_bytes(
        canonical_bytes[..8]
            .try_into()
            .map_err(|_| ContractError::InvalidDigest)?,
    );
    assert_eq!(len_prefix, "cam-front-01".len() as u64);
    assert_eq!(&canonical_bytes[8..], b"cam-front-01");

    // Must not be JSON: no quotes, no curly braces
    assert!(!canonical_bytes.starts_with(b"\""));
    assert!(!canonical_bytes.starts_with(b"{"));

    // Round-trip decoding
    let decoded = SensorId::from_canonical_bytes(&canonical_bytes)?;
    assert_eq!(decoded, sensor);
    Ok(())
}

#[test]
fn subsystem_generations_conformance() -> Result<(), ContractError> {
    let dev = DeviceGeneration::parse("insta360:v1.0")?;
    let stream = StreamGeneration::parse("stream:rtsp:main")?;
    let model = ModelGeneration::parse("model:yolo26:fp16:v1")?;
    let calib = CalibrationGeneration::parse("calib:shuttle:202609")?;
    let graph = GraphGeneration::parse("graph:projection:v1")?;
    let search = SearchGeneration::parse("search:delta:seal:1")?;
    let policy = PolicyGeneration::parse("policy:threat:matrix:1")?;
    let adapter = AdapterGeneration::parse("adapter:wyze:v4:001")?;
    let ontology = OntologyGeneration::parse("ontology:reference:v1")?;
    let privacy = PrivacyGeneration::parse("privacy:mask:zone:01")?;

    assert_eq!(dev.as_str(), "insta360:v1.0");
    assert_eq!(stream.as_str(), "stream:rtsp:main");
    assert_eq!(model.as_str(), "model:yolo26:fp16:v1");
    assert_eq!(calib.as_str(), "calib:shuttle:202609");
    assert_eq!(graph.as_str(), "graph:projection:v1");
    assert_eq!(search.as_str(), "search:delta:seal:1");
    assert_eq!(policy.as_str(), "policy:threat:matrix:1");
    assert_eq!(adapter.as_str(), "adapter:wyze:v4:001");
    assert_eq!(ontology.as_str(), "ontology:reference:v1");
    assert_eq!(privacy.as_str(), "privacy:mask:zone:01");

    // Bounds: minimum 8 chars
    assert!(DeviceGeneration::parse("12345678").is_ok());
    assert_eq!(
        DeviceGeneration::parse("1234567"),
        Err(ContractError::InvalidIdentifier)
    );

    // Bounds: maximum 256 chars
    let max_gen = format!("g{}", "a".repeat(255));
    assert_eq!(max_gen.len(), 256);
    assert!(DeviceGeneration::parse(&max_gen).is_ok());

    let over_gen = format!("g{}", "a".repeat(256));
    assert_eq!(over_gen.len(), 257);
    assert_eq!(
        DeviceGeneration::parse(&over_gen),
        Err(ContractError::InvalidIdentifier)
    );

    // Must start with lowercase alphanumeric
    assert_eq!(
        DeviceGeneration::parse(":invalid:start"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        DeviceGeneration::parse("-invalid:start"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        DeviceGeneration::parse("+invalid:start"),
        Err(ContractError::InvalidIdentifier)
    );

    // Uppercase is strictly forbidden in subsystem generations
    assert_eq!(
        DeviceGeneration::parse("Device:v1.0.0"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ModelGeneration::parse("Model:Yolo:FP16"),
        Err(ContractError::InvalidIdentifier)
    );

    // Canonical round-trip
    let model_bytes = model.canonical_bytes();
    let decoded_model = ModelGeneration::from_canonical_bytes(&model_bytes)?;
    assert_eq!(decoded_model, model);
    Ok(())
}

#[test]
fn generation_numeric_monotone_contract() -> Result<(), ContractError> {
    let genesis = Generation::GENESIS;
    assert_eq!(genesis.get(), 1);
    assert_eq!(genesis, Generation(1));

    // Genesis is successor of nothing, creation requires None
    assert!(Generation::validate_transition(None, genesis).is_ok());
    assert_eq!(
        Generation::validate_transition(None, Generation(2)),
        Err(ContractError::GenerationConflict)
    );

    // Monotonic succession
    let gen2 = genesis.next()?;
    assert_eq!(gen2.get(), 2);
    assert!(gen2.is_successor_of(genesis));
    assert!(!genesis.is_successor_of(gen2));
    assert!(Generation::validate_transition(Some(genesis), gen2).is_ok());

    // Skipping a generation is rejected
    let gen4 = Generation(4);
    assert_eq!(
        Generation::validate_transition(Some(gen2), gen4),
        Err(ContractError::GenerationConflict)
    );

    // Going backwards is rejected
    assert_eq!(
        Generation::validate_transition(Some(gen2), genesis),
        Err(ContractError::GenerationConflict)
    );

    // Same generation is rejected (no progress / duplicate)
    assert_eq!(
        Generation::validate_transition(Some(gen2), gen2),
        Err(ContractError::GenerationConflict)
    );

    // Zero parsing is rejected for positive generations
    assert_eq!(
        Generation::parse_positive(0),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(Generation::parse_positive(1)?.get(), 1);

    // Overflow check on next()
    let max_gen = Generation(u64::MAX);
    assert_eq!(max_gen.next(), Err(ContractError::GenerationConflict));

    // Canonical encoding and decoding
    let bytes = gen2.canonical_bytes();
    assert_eq!(bytes.len(), 8);
    assert_eq!(bytes, 2_u64.to_be_bytes());
    let decoded = Generation::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, gen2);

    // Canonical ordering: numerical
    assert!(Generation(2) < Generation(10));
    assert!(Generation(10) < Generation(100));
    Ok(())
}

#[test]
fn epoch_newtypes_monotone_contract() -> Result<(), ContractError> {
    let epoch1 = SchemaEpoch::from_u64(1);
    let epoch2 = epoch1.next()?;
    assert_eq!(epoch2.get(), 2);

    assert!(epoch2.validate_monotonic(epoch1).is_ok());
    assert!(epoch1.validate_monotonic(epoch1).is_ok()); // Same epoch allowed
    assert_eq!(
        epoch1.validate_monotonic(epoch2),
        Err(ContractError::InvalidAnchorSuccessor)
    );

    // Round-trip encoding
    let bytes = epoch2.canonical_bytes();
    let decoded = SchemaEpoch::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, epoch2);

    // Generic Epoch and other epoch types
    let policy_ep = PolicyEpoch::from_u64(5);
    let adapter_ep = AdapterEpoch::from_u64(3);
    let privacy_ep = PrivacyEpoch::from_u64(2);
    let ledger_ep = LedgerEpoch::from_u64(100);

    assert_eq!(policy_ep.get(), 5);
    assert_eq!(adapter_ep.get(), 3);
    assert_eq!(privacy_ep.get(), 2);
    assert_eq!(ledger_ep.get(), 100);
    Ok(())
}

#[test]
fn tombstone_rules_and_lifecycle_state_machine() -> Result<(), ContractError> {
    let mut registry = TombstoneRegistry::new();
    let obj_id = ObjectId::parse("obj-evidence-segment-400")?;

    // Rule 1: Creation starts at Generation 1
    let g1 = registry.register_active(obj_id.clone())?;
    assert_eq!(g1, Generation::GENESIS);
    assert!(!registry.is_tombstoned(&obj_id));

    // Rule 2: Active mutation strictly advances generation
    let g2 = registry.mutate(&obj_id, g1)?;
    assert_eq!(g2.get(), 2);

    let g3 = registry.mutate(&obj_id, g2)?;
    assert_eq!(g3.get(), 3);

    // Stale mutation is rejected with GenerationConflict
    assert_eq!(
        registry.mutate(&obj_id, g1),
        Err(ContractError::GenerationConflict)
    );
    assert_eq!(
        registry.mutate(&obj_id, g2),
        Err(ContractError::GenerationConflict)
    );

    // Rule 3: Tombstone transition captures prior and advances generation
    let witness = Some(ContentDigest::sha256(
        b"deletion authorization witness root",
    ));
    let payload = ContentDigest::sha256(b"manifest of deleted resources");

    let tombstone =
        registry.tombstone(obj_id.clone(), TombstoneReason::Deleted, witness, payload)?;

    assert_eq!(tombstone.prior_generation, g3);
    assert_eq!(tombstone.tombstone_generation.get(), 4);
    assert_eq!(tombstone.reason, TombstoneReason::Deleted);
    assert!(registry.is_tombstoned(&obj_id));

    // Rule 4: A tombstoned ID can NEVER be mutated
    assert_eq!(
        registry.mutate(&obj_id, g3),
        Err(ContractError::GenerationConflict)
    );
    assert_eq!(
        registry.mutate(&obj_id, tombstone.tombstone_generation),
        Err(ContractError::GenerationConflict)
    );

    // Rule 5: A tombstoned ID cannot be re-tombstoned
    assert_eq!(
        registry.tombstone(obj_id.clone(), TombstoneReason::Revoked, None, payload,),
        Err(ContractError::GenerationConflict)
    );

    // Rule 6: A tombstoned ID cannot be re-registered as active (no ID reuse)
    assert_eq!(
        registry.register_active(obj_id.clone()),
        Err(ContractError::GenerationConflict)
    );

    // Retained tombstone proof inspection
    let retrieved = registry
        .get_tombstone(&obj_id)
        .ok_or(ContractError::NotFound)?;
    assert_eq!(retrieved, &tombstone);
    assert_eq!(retrieved.witness_digest, witness);
    assert_eq!(retrieved.payload_digest, payload);

    // Canonical digest of tombstone
    let tomb_digest = tombstone.canonical_digest();
    assert_eq!(tomb_digest.algorithm(), fss_core::DigestAlgorithm::Sha256);
    Ok(())
}

#[test]
fn tombstone_record_invalid_generations_rejected() -> Result<(), ContractError> {
    let obj_id = ObjectId::parse("obj-bad-gen")?;
    let payload = ContentDigest::sha256(b"tombstone");

    // tombstone_gen == prior_gen rejected
    let res_equal = TombstoneRecord::new(
        obj_id.clone(),
        Generation(5),
        Generation(5),
        TombstoneReason::Superseded,
        None,
        payload,
    );
    assert_eq!(res_equal, Err(ContractError::GenerationConflict));

    // tombstone_gen < prior_gen rejected
    let res_less = TombstoneRecord::new(
        obj_id.clone(),
        Generation(4),
        Generation(5),
        TombstoneReason::Superseded,
        None,
        payload,
    );
    assert_eq!(res_less, Err(ContractError::GenerationConflict));

    // tombstone_gen > prior_gen + 1 (skipped) rejected
    let res_skipped = TombstoneRecord::new(
        obj_id,
        Generation(7),
        Generation(5),
        TombstoneReason::Superseded,
        None,
        payload,
    );
    assert_eq!(res_skipped, Err(ContractError::GenerationConflict));
    Ok(())
}

#[test]
fn tombstone_reason_forward_compatibility_unknown_tags() -> Result<(), ContractError> {
    // Known reasons
    assert_eq!(TombstoneReason::Deleted.tag(), 1);
    assert_eq!(TombstoneReason::Superseded.tag(), 2);
    assert_eq!(TombstoneReason::Revoked.tag(), 3);
    assert_eq!(TombstoneReason::Invalidated.tag(), 4);
    assert_eq!(TombstoneReason::Expired.tag(), 5);

    assert_eq!(TombstoneReason::from_tag(1), TombstoneReason::Deleted);
    assert_eq!(TombstoneReason::from_tag(2), TombstoneReason::Superseded);
    assert_eq!(TombstoneReason::from_tag(3), TombstoneReason::Revoked);
    assert_eq!(TombstoneReason::from_tag(4), TombstoneReason::Invalidated);
    assert_eq!(TombstoneReason::from_tag(5), TombstoneReason::Expired);

    // Forward compatibility: unknown tags preserved as Unknown(tag)
    let unknown_reason = TombstoneReason::from_tag(42);
    assert_eq!(unknown_reason, TombstoneReason::Unknown(42));
    assert_eq!(unknown_reason.tag(), 42);
    assert_eq!(unknown_reason.as_str(), "unknown");

    // Canonical round-trip of unknown reason
    let bytes = unknown_reason.canonical_bytes();
    let decoded = TombstoneReason::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, TombstoneReason::Unknown(42));

    // String parsing
    assert_eq!(TombstoneReason::parse("deleted")?, TombstoneReason::Deleted);
    assert_eq!(
        TombstoneReason::parse("superseded")?,
        TombstoneReason::Superseded
    );
    assert_eq!(TombstoneReason::parse("revoked")?, TombstoneReason::Revoked);
    assert_eq!(
        TombstoneReason::parse("invalidated")?,
        TombstoneReason::Invalidated
    );
    assert_eq!(TombstoneReason::parse("expired")?, TombstoneReason::Expired);
    assert_eq!(
        TombstoneReason::parse("invalid"),
        Err(ContractError::InvalidIdentifier)
    );
    Ok(())
}

#[test]
fn time_interval_bounds_and_uncertainty_contract() -> Result<(), ContractError> {
    let t10 = TimestampNs(10);
    let t25 = TimestampNs(25);
    let t40 = TimestampNs(40);

    // Valid interval
    let interval = CaptureInterval::new(t10, t40)?;
    assert_eq!(interval.uncertainty_ns(), 30);
    assert!(interval.contains_timestamp(t10));
    assert!(interval.contains_timestamp(t25));
    assert!(interval.contains_timestamp(t40));
    assert!(!interval.contains_timestamp(TimestampNs(9)));
    assert!(!interval.contains_timestamp(TimestampNs(41)));

    // Point interval (zero uncertainty)
    let pt = CaptureInterval::point(t25);
    assert_eq!(pt.uncertainty_ns(), 0);
    assert!(interval.contains(pt));

    // Inverted interval rejected on constructor
    assert_eq!(
        CaptureInterval::new(t40, t10),
        Err(ContractError::InvertedTimeInterval)
    );

    // Overlap and containment
    let i_sub = CaptureInterval::new(TimestampNs(15), TimestampNs(30))?;
    let i_overlap = CaptureInterval::new(TimestampNs(35), TimestampNs(50))?;
    let i_disjoint = CaptureInterval::new(TimestampNs(60), TimestampNs(80))?;

    assert!(interval.contains(i_sub));
    assert!(!interval.contains(i_overlap));
    assert!(interval.overlaps(i_overlap));
    assert!(!interval.overlaps(i_disjoint));

    // Intersection
    let isect = interval.intersection(i_overlap);
    assert_eq!(
        isect,
        Some(CaptureInterval::new(TimestampNs(35), TimestampNs(40))?)
    );
    assert_eq!(interval.intersection(i_disjoint), None);

    // Bounding hull
    let hull = interval.hull(i_disjoint);
    assert_eq!(
        hull,
        CaptureInterval::new(TimestampNs(10), TimestampNs(80))?
    );

    // Checked shift (rigid translation)
    let shifted = interval.checked_shift(5)?;
    assert_eq!(
        shifted,
        CaptureInterval::new(TimestampNs(15), TimestampNs(45))?
    );

    // Checked shift causing arithmetic overflow fails closed
    assert_eq!(
        interval.checked_shift(i128::MAX),
        Err(ContractError::ArithmeticOverflow)
    );

    // Canonical ordering: sorted by earliest, then latest
    let a = CaptureInterval::new(TimestampNs(10), TimestampNs(20))?;
    let b = CaptureInterval::new(TimestampNs(10), TimestampNs(30))?;
    let c = CaptureInterval::new(TimestampNs(15), TimestampNs(20))?;

    assert!(a < b);
    assert!(b < c);
    assert!(a < c);

    // Decode rejects inverted interval in binary payload
    let mut encoder = CanonicalEncoder::new();
    TimestampNs(100).encode_canonical(&mut encoder);
    TimestampNs(50).encode_canonical(&mut encoder);
    let bad_bytes = encoder.finish();
    assert_eq!(
        CaptureInterval::from_canonical_bytes(&bad_bytes),
        Err(ContractError::InvertedTimeInterval)
    );
    Ok(())
}

#[test]
fn timestamp_checked_arithmetic() -> Result<(), ContractError> {
    let t = TimestampNs(1_000_000);
    assert_eq!(t.checked_add_ns(500_000)?, TimestampNs(1_500_000));
    assert_eq!(t.checked_sub_ns(300_000)?, TimestampNs(700_000));
    assert_eq!(t.checked_duration_since(TimestampNs(400_000))?, 600_000);
    assert_eq!(
        t.checked_duration_since(TimestampNs(2_000_000)),
        Err(ContractError::InvertedTimeInterval)
    );
    assert_eq!(t.abs_diff(TimestampNs(2_000_000)), 1_000_000);
    Ok(())
}

#[test]
fn version_envelope_fail_closed_unknown_version() -> Result<(), ContractError> {
    let envelope_v1 = CanonicalVersionEnvelope::new(ObjectId::parse("obj-envelope-01")?);
    assert_eq!(envelope_v1.version, CANONICAL_VERSION_1);

    let bytes = envelope_v1.canonical_bytes();

    // Decoding supported version succeeds
    let decoded = CanonicalVersionEnvelope::<ObjectId>::from_canonical_bytes_bounded(
        &bytes,
        CANONICAL_VERSION_1,
        CANONICAL_VERSION_1,
    )?;
    assert_eq!(decoded.version, CANONICAL_VERSION_1);
    assert_eq!(decoded.payload.as_str(), "obj-envelope-01");

    // Envelope with future unknown version (e.g. 2)
    let envelope_v2 =
        CanonicalVersionEnvelope::with_version(2, ObjectId::parse("obj-envelope-02")?);
    let bytes_v2 = envelope_v2.canonical_bytes();

    // Fails closed when expected version is only 1
    let err_v2 = CanonicalVersionEnvelope::<ObjectId>::from_canonical_bytes_bounded(
        &bytes_v2,
        CANONICAL_VERSION_1,
        CANONICAL_VERSION_1,
    );
    assert_eq!(err_v2, Err(ContractError::InvalidAnchorSuccessor));

    // Corrupt magic header fails closed
    let mut corrupt_bytes = bytes.clone();
    corrupt_bytes[8] = b'X'; // Corrupt magic
    let err_magic = CanonicalVersionEnvelope::<ObjectId>::from_canonical_bytes_bounded(
        &corrupt_bytes,
        CANONICAL_VERSION_1,
        CANONICAL_VERSION_1,
    );
    assert_eq!(err_magic, Err(ContractError::InvalidDigest));
    Ok(())
}

#[test]
fn decoder_fault_matrix() -> Result<(), ContractError> {
    // 1. Truncated EOF on u32
    let short_bytes = [1_u8, 2_u8];
    let mut decoder = CanonicalDecoder::new(&short_bytes);
    assert_eq!(decoder.read_u32(), Err(ContractError::InvalidDigest));

    // 2. Truncated EOF on u64
    let mut decoder = CanonicalDecoder::new(&short_bytes);
    assert_eq!(decoder.u64(), Err(ContractError::InvalidDigest));

    // 3. Truncated EOF on i128
    let mut decoder = CanonicalDecoder::new(&short_bytes);
    assert_eq!(decoder.i128(), Err(ContractError::InvalidDigest));

    // 4. Invalid boolean byte (> 1)
    let bad_bool = [255_u8];
    let mut decoder = CanonicalDecoder::new(&bad_bool);
    assert_eq!(decoder.bool(), Err(ContractError::InvalidIdentifier));

    // 5. Invalid digest algorithm tag (> 2)
    let bad_algo = [3_u8; 33];
    let mut decoder = CanonicalDecoder::new(&bad_algo);
    assert_eq!(
        decoder.digest(),
        Err(ContractError::UnsupportedDigestAlgorithm)
    );

    // 6. Trailing unconsumed bytes in ensure_finished
    let trailing = [0_u8, 1_u8];
    let mut decoder = CanonicalDecoder::new(&trailing);
    assert_eq!(decoder.u8()?, 0);
    assert_eq!(
        decoder.ensure_finished(),
        Err(ContractError::NonCanonicalOrdering)
    );

    // 7. Non-UTF8 string rejected
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(&[0xFF, 0xFE, 0xFD]);
    let non_utf8_bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&non_utf8_bytes);
    assert_eq!(decoder.text(), Err(ContractError::InvalidIdentifier));

    // 8. Text exceeding MAX_CANONICAL_TEXT_BYTES rejected
    let mut over_encoder = CanonicalEncoder::new();
    over_encoder.u64((MAX_CANONICAL_TEXT_BYTES + 1) as u64);
    let over_bytes = over_encoder.finish();
    let mut over_decoder = CanonicalDecoder::new(&over_bytes);
    assert_eq!(over_decoder.text(), Err(ContractError::InvalidDigest));

    // 9. Bytes exceeding MAX_CANONICAL_BYTES_LEN rejected
    let mut big_encoder = CanonicalEncoder::new();
    big_encoder.u64((MAX_CANONICAL_BYTES_LEN + 1) as u64);
    let big_bytes = big_encoder.finish();
    let mut big_decoder = CanonicalDecoder::new(&big_bytes);
    assert_eq!(big_decoder.bytes(), Err(ContractError::InvalidDigest));
    Ok(())
}

#[test]
fn constants_and_lifecycle_state_direct_coverage() -> Result<(), ContractError> {
    assert_eq!(CANONICAL_FORMAT_MAGIC, *b"FSSC");

    // Epoch generic newtype
    let ep = Epoch::from_u64(42);
    assert_eq!(ep.get(), 42);
    assert_eq!(ep.next()?.get(), 43);

    // IdentityLifecycleState direct inspection
    let mut lifecycle = IdentityLifecycleState::create();
    assert!(lifecycle.is_active());
    assert!(!lifecycle.is_tombstoned());
    assert_eq!(lifecycle.generation(), Generation::GENESIS);

    let next_gen = lifecycle.mutate(Generation::GENESIS)?;
    assert_eq!(next_gen.get(), 2);
    assert_eq!(lifecycle.generation().get(), 2);

    let obj = ObjectId::parse("obj:lifecycle:test")?;
    let payload = ContentDigest::sha256(b"lifecycle tombstone");
    let tombstone = lifecycle.tombstone(obj.clone(), TombstoneReason::Expired, None, payload)?;
    assert!(lifecycle.is_tombstoned());
    assert_eq!(tombstone.tombstone_generation.get(), 3);
    assert_eq!(lifecycle.generation().get(), 3);

    // BTreeMap indexing by ObjectId
    let mut map = BTreeMap::new();
    map.insert(obj.clone(), lifecycle);
    assert!(map.contains_key(&obj));
    Ok(())
}

#[test]
fn finding_1_and_2_tombstone_reason_tags_and_ordering() -> Result<(), ContractError> {
    // Finding 1: overlapping tags must be rejected on construction
    assert_eq!(
        TombstoneReason::unknown(1),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        TombstoneReason::unknown(5),
        Err(ContractError::InvalidIdentifier)
    );
    let unk6 = TombstoneReason::unknown(6)?;
    assert_eq!(unk6.tag(), 6);
    let unk0 = TombstoneReason::unknown(0)?;
    assert_eq!(unk0.tag(), 0);

    // from_tag maps known tags to known variants, not Unknown
    assert_eq!(TombstoneReason::from_tag(1), TombstoneReason::Deleted);
    assert_eq!(TombstoneReason::from_tag(5), TombstoneReason::Expired);
    assert_eq!(TombstoneReason::from_tag(6), unk6);

    // Finding 2: Ord must agree with canonical tag order
    assert!(unk0 < TombstoneReason::Deleted);
    assert!(TombstoneReason::Deleted < TombstoneReason::Superseded);
    assert!(TombstoneReason::Superseded < TombstoneReason::Revoked);
    assert!(TombstoneReason::Revoked < TombstoneReason::Invalidated);
    assert!(TombstoneReason::Invalidated < TombstoneReason::Expired);
    assert!(TombstoneReason::Expired < unk6);

    let unk255 = TombstoneReason::unknown(255)?;
    assert!(unk6 < unk255);
    assert_eq!(unk0.cmp(&TombstoneReason::Deleted), 0.cmp(&1));
    Ok(())
}

#[test]
fn finding_4_tombstone_record_canonical_digest_delegation() -> Result<(), ContractError> {
    let obj = ObjectId::parse("obj-tombstone-digest-01")?;
    let payload = ContentDigest::sha256(b"deletion manifest");
    let record = TombstoneRecord::new(
        obj,
        Generation(2),
        Generation(1),
        TombstoneReason::Deleted,
        None,
        payload,
    )?;

    // Must delegate to CanonicalEncode::canonical_digest with domain "fss.tombstone.v1"
    let direct_digest = record.canonical_digest();
    let trait_digest = CanonicalEncode::canonical_digest(&record, "fss.tombstone.v1");
    assert_eq!(direct_digest, trait_digest);
    Ok(())
}

#[test]
fn finding_5_canonical_decoder_u32_no_phantom_param() -> Result<(), ContractError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(0x12345678);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    // u32 must not take a phantom parameter
    let val = decoder.u32()?;
    assert_eq!(val, 0x12345678);
    decoder.ensure_finished()?;
    Ok(())
}

#[test]
fn finding_6_and_7_encoder_fail_closed_and_real_text_bound() -> Result<(), ContractError> {
    // Finding 6: Encoder fails closed on over-bound text/bytes
    let mut enc_over_text = CanonicalEncoder::new();
    let huge_str = "a".repeat(MAX_CANONICAL_TEXT_BYTES + 1);
    enc_over_text.text(&huge_str);
    assert!(enc_over_text.has_error());
    assert_eq!(
        enc_over_text.finish_checked(),
        Err(ContractError::InvalidIdentifier)
    );

    let mut enc_over_bytes = CanonicalEncoder::new();
    // try_bytes over limit
    assert_eq!(
        enc_over_bytes.try_bytes(&vec![0u8; MAX_CANONICAL_BYTES_LEN + 1]),
        Err(ContractError::InvalidDigest)
    );

    // Finding 7: Fix the tautological text-bound test so it exercises text() with a real over-bound payload
    let mut raw_buf = Vec::new();
    // 8-byte big-endian length prefix = MAX_CANONICAL_TEXT_BYTES + 1
    raw_buf.extend_from_slice(&((MAX_CANONICAL_TEXT_BYTES + 1) as u64).to_be_bytes());
    // Actual payload of MAX_CANONICAL_TEXT_BYTES + 1 valid ASCII bytes
    raw_buf.extend(std::iter::repeat_n(b'x', MAX_CANONICAL_TEXT_BYTES + 1));

    let mut dec = CanonicalDecoder::new(&raw_buf);
    // Must return InvalidIdentifier because length exceeds MAX_CANONICAL_TEXT_BYTES,
    // NOT InvalidDigest from EOF truncation!
    assert_eq!(dec.text(), Err(ContractError::InvalidIdentifier));
    Ok(())
}

#[test]
fn finding_8_reject_generation_0_as_prior() -> Result<(), ContractError> {
    // Generation 0 cannot be prior in validate_transition
    assert_eq!(
        Generation::validate_transition(Some(Generation(0)), Generation(1)),
        Err(ContractError::GenerationConflict)
    );
    assert_eq!(
        Generation::validate_transition(Some(Generation::UNVERSIONED), Generation::GENESIS),
        Err(ContractError::GenerationConflict)
    );

    // Generation 1 is not a valid successor of Generation 0
    assert!(!Generation(1).is_successor_of(Generation(0)));
    assert!(!Generation::GENESIS.is_successor_of(Generation::UNVERSIONED));

    // TombstoneRecord::new rejects prior_generation == 0
    let obj = ObjectId::parse("obj-tombstone-gen0")?;
    let payload = ContentDigest::sha256(b"payload");
    assert_eq!(
        TombstoneRecord::new(
            obj,
            Generation(1),
            Generation(0),
            TombstoneReason::Deleted,
            None,
            payload
        ),
        Err(ContractError::GenerationConflict)
    );
    Ok(())
}

#[test]
fn finding_3_signed_i128_byte_order_property_pinned() {
    let mut enc_neg = CanonicalEncoder::new();
    enc_neg.i128(-1);
    let bytes_neg = enc_neg.finish();

    let mut enc_pos = CanonicalEncoder::new();
    enc_pos.i128(1);
    let bytes_pos = enc_pos.finish();

    // Pin the property: two's complement -1 has leading 0xFF bytes,
    // so in lexicographical byte comparison bytes_neg > bytes_pos.
    // Callers MUST sort using typed i128 / TimestampNs rather than raw canonical bytes.
    assert!(bytes_neg > bytes_pos);
}
