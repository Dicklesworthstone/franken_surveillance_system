#![forbid(unsafe_code)]
//! Differential oracle, incremental catch-up, corrupt-file quarantine/rebuild, unified 4-adapter
//! footage indexing, ALG-ZSET-001 bridge, and `DoctorScrubReceipt` persistence tests.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EffectState, EventId, EventKind, EventState,
    EvidenceDelta, EvidenceDeltaBatch, LedgerAnchor, ObjectId, ObligationId, ObligationState, OperationId, Plane,
    SensorId, StreamId, TimestampNs,
};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::zset::zset_incremental_maintenance;
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{DurabilityMode, PACK_KIND_METADATA, PackConfig, PackObjectInput, PackStore};
use fss_projection_store::{
    CanonicalBatchSource, CoverageStatus, CoverageWitnessPayload, DeletionTarget,
    DeletionTombstonePayload, DoctorScrubReceipt, EffectOutcomePayload, EventQueryFilter,
    EventRevisionPayload, EvidenceHoldPayload, FAMILY_ALERT_EFFECT_OUTCOME,
    FAMILY_COVERAGE_WITNESS, FAMILY_DELETION_TOMBSTONE, FAMILY_EVENT_REVISION,
    FAMILY_EVIDENCE_HOLD, FAMILY_FOOTAGE_IMPORT, FAMILY_GRAPH_EDGE, FAMILY_OBLIGATION,
    FAMILY_PRIVACY_MASK_POLICY, FAMILY_SENSOR_LIVENESS, FAMILY_SENSOR_TAMPER_STATUS,
    FootageAdapterKind, FootageImportPayload, FootageQueryFilter, GraphEdgeDeltaPayload,
    GraphEdgeKey, HistoryChainMode, MvccProjectionStore, ObligationPayload,
    PROJECTION_SCRUB_RECEIPT_DOMAIN, PackStorePayloadResolver, PrivacyMaskPayload,
    ProjectionAnchor, ProjectionError, ProjectionRebuildReason, ProjectionRecordPayload, ProjectionRecoveryMode, ProjectionStore,
    ProjectionStoreConfig, SNAPSHOT_FILENAME, ScrubVerdict, SensorLivenessPayload,
    SensorLivenessStatus, SensorTamperPayload, WAL_FILENAME, replay_from_batches,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempWorkspace {
    root: PathBuf,
}

impl TempWorkspace {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("fss-proj-diff-{label}-{}-{id}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct ScenarioHarness {
    ledger: MerkleEpochLedger,
    packs: PackStore,
    gens: BTreeMap<ObjectId, u64>,
    rev_digests: BTreeMap<String, ContentDigest>,
    created_imports: Vec<(ObjectId, ContentDigest)>,
}

struct DeltaSpec<'a> {
    seq_tag: u64,
    family: &'a str,
    object_id: ObjectId,
    plane: Plane,
    interval: CaptureInterval,
}

impl ScenarioHarness {
    fn commit(
        &mut self,
        proj: Option<&MvccProjectionStore>,
        spec: DeltaSpec<'_>,
        payload: &ProjectionRecordPayload,
    ) -> Result<EvidenceDeltaBatch, Box<dyn std::error::Error>> {
        let raw = payload.encode_bytes()?;
        let digest = ContentDigest::sha256(&raw);
        let _ = self.packs.append_batch(&[PackObjectInput::with_digest(
            PACK_KIND_METADATA,
            0,
            &raw,
            digest,
        )])?;
        let prior = self.gens.get(&spec.object_id).copied();
        let next_gen = prior.map_or(1, |g| g + 1);
        self.gens.insert(spec.object_id.clone(), next_gen);

        let delta = EvidenceDelta {
            delta_id: format!("delta-{:06}", spec.seq_tag),
            family: spec.family.to_owned(),
            object_id: spec.object_id,
            prior_generation: prior,
            new_generation: next_gen,
            validity: spec.interval,
            plane: spec.plane,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        };
        let batch = self.ledger.prepare_batch(
            BatchId::parse(format!("batch-{:06}", spec.seq_tag))?,
            vec![delta],
            [digest],
        )?;
        let _ = self.ledger.append_batch(batch.clone())?;
        if let Some(store) = proj {
            let resolver = PackStorePayloadResolver::new(&self.packs);
            let _ = store.apply_delta_batch(&batch, &resolver)?;
        }
        Ok(batch)
    }

    fn run_step(
        &mut self,
        store: &MvccProjectionStore,
        step: u64,
    ) -> Result<EvidenceDeltaBatch, Box<dyn std::error::Error>> {
        let adapters = [
            FootageAdapterKind::Rtsp,
            FootageAdapterKind::Http,
            FootageAdapterKind::File,
            FootageAdapterKind::Tutk,
        ];
        let cam_idx = step % 8;
        let zone_idx = step % 4;
        let sensor = SensorId::parse(format!("cam-{cam_idx:02}"))?;
        let zone = format!("zone-{zone_idx:02}");
        let start = TimestampNs((step as i128) * 1_000_000);
        let end = TimestampNs((step as i128) * 1_000_000 + 500_000);
        let interval = CaptureInterval::new(start, end)?;

        match step % 10 {
            1 | 2 => {
                let ev_idx = step % 20;
                let ev_key = format!("ev-{ev_idx:03}");
                let obj_id = ObjectId::parse(format!("obj:ev:{ev_idx:03}"))?;
                let prior_rev = self.rev_digests.get(&ev_key).copied();
                let rev_num = self.gens.get(&obj_id).copied().map_or(1, |g| g + 1);
                let state = match rev_num {
                    1 => EventState::Witnessed,
                    2 => EventState::Corroborated,
                    3 => EventState::Adjudicated,
                    _ => EventState::Resolved,
                };
                let kind = if ev_idx.is_multiple_of(2) {
                    EventKind::PerimeterBreach
                } else {
                    EventKind::UnknownPresence
                };
                let payload = ProjectionRecordPayload::EventRevision(EventRevisionPayload {
                    event_id: EventId::parse(&ev_key)?,
                    revision: rev_num,
                    state,
                    kind,
                    zones: vec![zone, format!("zone-{:02}", (zone_idx + 1) % 4)],
                    sensor_ids: vec![sensor],
                    interval,
                    event_root: ContentDigest::sha256(format!("ev-root-{step}").as_bytes()),
                    supersedes: prior_rev,
                    corroborated: rev_num >= 2,
                    tamper_open: false,
                });
                let spec = DeltaSpec {
                    seq_tag: step,
                    family: FAMILY_EVENT_REVISION,
                    object_id: obj_id,
                    plane: Plane::Cognition,
                    interval,
                };
                let b = self.commit(Some(store), spec, &payload)?;
                self.rev_digests.insert(ev_key, b.deltas[0].payload_digest);
                Ok(b)
            }
            3 => {
                let status = match (step / 10) % 3 {
                    0 => CoverageStatus::Covered,
                    1 => CoverageStatus::Stale,
                    _ => CoverageStatus::NotObservable,
                };
                let payload = ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
                    sensor_id: sensor,
                    zone_id: zone,
                    window: interval,
                    status,
                    active_gaps: u32::from(status == CoverageStatus::NotObservable),
                    health_conflicts: u32::from(status == CoverageStatus::Stale),
                });
                let spec = DeltaSpec {
                    seq_tag: step,
                    family: FAMILY_COVERAGE_WITNESS,
                    object_id: ObjectId::parse(format!("obj:cov:{cam_idx:02}:{zone_idx:02}"))?,
                    plane: Plane::Authority,
                    interval,
                };
                self.commit(Some(store), spec, &payload)
            }
            4 => {
                let adapter_kind = adapters[((step / 10) as usize) % adapters.len()];
                let import_id = ContentDigest::sha256(format!("import-{step}").as_bytes());
                let obj_id = ObjectId::parse(format!("obj:imp:{step:04}"))?;
                self.created_imports.push((obj_id.clone(), import_id));
                let payload = ProjectionRecordPayload::FootageImport(FootageImportPayload {
                    import_id,
                    adapter_kind,
                    sensor_id: sensor,
                    stream_id: StreamId::parse(format!("stream-{cam_idx:02}"))?,
                    capture_interval: interval,
                    manifest_digest: ContentDigest::sha256(format!("manifest-{step}").as_bytes()),
                    capsule_count: 16,
                    total_bytes: 65_536 * step,
                    adapter_id: format!("adp-{}", adapter_kind.as_str()),
                    adapter_generation: format!("gen-{}-v1", adapter_kind.as_str()),
                    completed: !step.is_multiple_of(8),
                });
                let spec = DeltaSpec {
                    seq_tag: step,
                    family: FAMILY_FOOTAGE_IMPORT,
                    object_id: obj_id,
                    plane: Plane::Authority,
                    interval,
                };
                self.commit(Some(store), spec, &payload)
            }
            5 => {
                let hold_idx = step % 5;
                let payload = ProjectionRecordPayload::EvidenceHold(EvidenceHoldPayload {
                    hold_id: format!("hold-{hold_idx}"),
                    scope: format!("scope-{zone}"),
                    target_digest: ContentDigest::sha256(format!("target-{hold_idx}").as_bytes()),
                    active: step < 140,
                });
                let spec = DeltaSpec {
                    seq_tag: step,
                    family: FAMILY_EVIDENCE_HOLD,
                    object_id: ObjectId::parse(format!("obj:hold:{hold_idx}"))?,
                    plane: Plane::Authority,
                    interval,
                };
                self.commit(Some(store), spec, &payload)
            }
            6 => {
                let payload = ProjectionRecordPayload::PrivacyMask(PrivacyMaskPayload {
                    sensor_id: sensor,
                    policy_digest: ContentDigest::sha256(format!("mask-pol-{step}").as_bytes()),
                });
                let spec = DeltaSpec {
                    seq_tag: step,
                    family: FAMILY_PRIVACY_MASK_POLICY,
                    object_id: ObjectId::parse(format!("obj:mask:{cam_idx:02}"))?,
                    plane: Plane::Authority,
                    interval,
                };
                self.commit(Some(store), spec, &payload)
            }
            7 => {
                let ob_idx = step % 6;
                let state = if step > 130 && ob_idx < 3 {
                    ObligationState::Verified
                } else {
                    ObligationState::Pending
                };
                let payload = ProjectionRecordPayload::Obligation(ObligationPayload {
                    obligation_id: ObligationId::parse(format!("ob-{ob_idx:02}"))?,
                    operation_id: OperationId::parse(format!("op-{ob_idx:02}"))?,
                    terminal_predicate: "provider_receipt_verified".to_owned(),
                    state,
                    proof_digest: (state == ObligationState::Verified)
                        .then(|| ContentDigest::sha256(format!("proof-{step}").as_bytes())),
                });
                let spec = DeltaSpec {
                    seq_tag: step,
                    family: FAMILY_OBLIGATION,
                    object_id: ObjectId::parse(format!("obj:ob:{ob_idx:02}"))?,
                    plane: Plane::Effect,
                    interval,
                };
                self.commit(Some(store), spec, &payload)
            }
            8 => {
                let op_idx = step % 4;
                let effect_state = if step > 150 && op_idx == 0 {
                    EffectState::Verified
                } else {
                    EffectState::Indeterminate
                };
                let payload = ProjectionRecordPayload::EffectOutcome(EffectOutcomePayload {
                    operation_id: OperationId::parse(format!("op-eff-{op_idx:02}"))?,
                    obligation_id: Some(ObligationId::parse(format!("ob-{op_idx:02}"))?),
                    effect_state,
                    reason: "gateway_ack_timeout".to_owned(),
                });
                let spec = DeltaSpec {
                    seq_tag: step,
                    family: FAMILY_ALERT_EFFECT_OUTCOME,
                    object_id: ObjectId::parse(format!("obj:eff:{op_idx:02}"))?,
                    plane: Plane::Effect,
                    interval,
                };
                self.commit(Some(store), spec, &payload)
            }
            9 => {
                let state = match (step / 10) % 4 {
                    0 => SensorLivenessStatus::Online,
                    1 => SensorLivenessStatus::Degraded,
                    2 => SensorLivenessStatus::Offline,
                    _ => SensorLivenessStatus::Unknown,
                };
                let payload = ProjectionRecordPayload::SensorLiveness(SensorLivenessPayload {
                    sensor_id: sensor,
                    state,
                    last_seen_ns: start,
                    observed_at_ns: end,
                });
                let spec = DeltaSpec {
                    seq_tag: step,
                    family: FAMILY_SENSOR_LIVENESS,
                    object_id: ObjectId::parse(format!("obj:live:{cam_idx:02}"))?,
                    plane: Plane::Authority,
                    interval,
                };
                self.commit(Some(store), spec, &payload)
            }
            _ => {
                if step == 100 || step == 160 {
                    let target = if step == 100 && !self.created_imports.is_empty() {
                        DeletionTarget::Object(self.created_imports[0].0.clone())
                    } else {
                        DeletionTarget::Event(EventId::parse("ev-001")?)
                    };
                    let payload =
                        ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
                            target,
                        });
                    let spec = DeltaSpec {
                        seq_tag: step,
                        family: FAMILY_DELETION_TOMBSTONE,
                        object_id: ObjectId::parse(format!("obj:tomb:{step:04}"))?,
                        plane: Plane::Authority,
                        interval,
                    };
                    self.commit(Some(store), spec, &payload)
                } else if step == 120 {
                    let payload = ProjectionRecordPayload::SensorTamper(SensorTamperPayload {
                        event_id: EventId::parse("ev-002")?,
                        tamper_open: true,
                    });
                    let spec = DeltaSpec {
                        seq_tag: step,
                        family: FAMILY_SENSOR_TAMPER_STATUS,
                        object_id: ObjectId::parse("obj:tamper:002")?,
                        plane: Plane::Authority,
                        interval,
                    };
                    self.commit(Some(store), spec, &payload)
                } else {
                    let payload = ProjectionRecordPayload::GraphEdgeDelta(GraphEdgeDeltaPayload {
                        edge_deltas: vec![(
                            GraphEdgeKey::new("handover_link", sensor.as_str(), zone.as_str()),
                            1,
                        )],
                    });
                    let spec = DeltaSpec {
                        seq_tag: step,
                        family: FAMILY_GRAPH_EDGE,
                        object_id: ObjectId::parse(format!("obj:edge:{step:04}"))?,
                        plane: Plane::Cognition,
                        interval,
                    };
                    self.commit(Some(store), spec, &payload)
                }
            }
        }
    }
}

/// Recovery must consume the cursor even when a backend cannot materialize an entire range.
struct StreamingHistory<'a>(&'a MerkleEpochLedger);

impl CanonicalBatchSource for StreamingHistory<'_> {
    fn history_mode(&self) -> HistoryChainMode {
        self.0.history_mode()
    }

    fn genesis_anchor(&self) -> LedgerAnchor {
        self.0.genesis_anchor().clone()
    }

    fn head_ledger_anchor(&self) -> LedgerAnchor {
        self.0.head_ledger_anchor()
    }

    fn head_history_root(&self) -> ContentDigest {
        self.0.head_history_root()
    }

    fn matches_anchor(&self, anchor: &ProjectionAnchor) -> Result<bool, ProjectionError> {
        self.0.matches_anchor(anchor)
    }

    fn read_batches_range(
        &self,
        _: u64,
        _: u64,
    ) -> Result<Vec<EvidenceDeltaBatch>, ProjectionError> {
        Err(ProjectionError::InvalidRequest("bulk read during recovery"))
    }

    fn visit_batches_range(
        &self,
        from_seq: u64,
        to_seq: u64,
        visit: &mut dyn FnMut(&EvidenceDeltaBatch) -> Result<(), ProjectionError>,
    ) -> Result<(), ProjectionError> {
        self.0.visit_batches_range(from_seq, to_seq, visit)
    }
}

#[test]
fn differential_200_scenarios_rebuild_and_oracle_exactness() -> TestResult {
    let ws = TempWorkspace::new("diff200")?;
    let proj_dir = ws.root.join("projection");
    let ledger = MerkleEpochLedger::open(
        ws.root.join("ledger"),
        "site:diff-200",
        EpochLedgerConfig {
            max_batches_per_epoch: 64,
            checkpoint_stride: 50,
            ..EpochLedgerConfig::default()
        },
        IncompleteTailPolicy::Reject,
    )?;
    let packs = PackStore::open(
        ws.root.join("packs"),
        PackConfig {
            durability: DurabilityMode::Fsync,
            ..PackConfig::default()
        },
    )?;
    let store = MvccProjectionStore::open_empty(
        &proj_dir,
        ledger.genesis_anchor(),
        ProjectionStoreConfig {
            snapshot_stride: 75,
            max_retained_snapshots: 64,
            ..ProjectionStoreConfig::default()
        },
    )?;
    assert!(store.latest_scrub_receipt().is_none());
    assert!(
        store
            .snapshot_latest()
            .orient_summary()
            .scrub_receipt
            .is_none()
    );

    let mut harness = ScenarioHarness {
        ledger,
        packs,
        gens: BTreeMap::new(),
        rev_digests: BTreeMap::new(),
        created_imports: Vec::new(),
    };
    let mut all_batches = Vec::with_capacity(205);
    for step in 1_u64..=200 {
        all_batches.push(harness.run_step(&store, step)?);
    }

    let inc_snap = store.snapshot_latest();
    assert_eq!(inc_snap.anchor().commit_sequence, 200);
    for adapter in [
        FootageAdapterKind::Rtsp,
        FootageAdapterKind::Http,
        FootageAdapterKind::File,
        FootageAdapterKind::Tutk,
    ] {
        let page = store.query_footage(
            &inc_snap,
            &FootageQueryFilter {
                adapter_kind: Some(adapter),
                ..FootageQueryFilter::default()
            },
            64,
        );
        assert!(!page.entries.is_empty(), "missing adapter {adapter:?}");
    }

    // Verify ALG-ZSET-001 bridge directly over exported Z-set state + follow commit delta.
    let zset_state = inc_snap.to_zset_graph_state()?;
    let tail = store.follow_since(195, 10)?;
    assert_eq!(tail.commits.len(), 5);
    let cert = zset_incremental_maintenance(
        &zset_state,
        &tail.commits[4].to_zset_delta_batch(),
        Budget::new(100_000, 100_000),
    )?;
    assert_eq!(cert.identity.algorithm_id, "ALG-ZSET-001");

    // (b) Delete projection directory completely and rebuild from canonical ledger + packs.
    drop(store);
    fs::remove_dir_all(&proj_dir)?;
    let resolver = PackStorePayloadResolver::new(&harness.packs);
    let recovery_config = ProjectionStoreConfig {
        max_retained_snapshots: 3,
        ..ProjectionStoreConfig::default()
    };
    let rebuilt = MvccProjectionStore::open_or_rebuild_with_config(
        &proj_dir,
        &StreamingHistory(&harness.ledger),
        &resolver,
        recovery_config,
    )?;
    assert!(matches!(
        rebuilt.snapshot_at(197),
        Err(ProjectionError::SnapshotEvicted { .. })
    ));
    assert_eq!(rebuilt.snapshot_at(198)?.anchor().commit_sequence, 198);
    assert_eq!(
        rebuilt.recovery_report().mode,
        ProjectionRecoveryMode::RebuiltFromGenesis
    );
    assert_eq!(
        rebuilt.recovery_report().rebuild_reason,
        Some(ProjectionRebuildReason::Missing)
    );
    assert_eq!(rebuilt.recovery_report().replayed_ledger_batches, 200);
    let reb_snap = rebuilt.snapshot_latest();

    // (c) Independent full-history replay oracle.
    let ora_snap = replay_from_batches(
        harness.ledger.genesis_anchor(),
        HistoryChainMode::V2MerkleEpoch,
        &all_batches,
        &resolver,
    )?;

    // Bit-exact equivalence across (a) incremental, (b) rebuilt, and (c) replay oracle.
    assert_eq!(inc_snap.state_digest(), reb_snap.state_digest());
    assert_eq!(inc_snap.state_digest(), ora_snap.state_digest());
    assert_eq!(inc_snap.orient_summary(), reb_snap.orient_summary());
    assert_eq!(inc_snap.orient_summary(), ora_snap.orient_summary());
    let ev_filter = EventQueryFilter {
        zone: Some("zone-01".to_owned()),
        ..EventQueryFilter::default()
    };
    assert_eq!(
        rebuilt.query_events(&inc_snap, &ev_filter, 50),
        rebuilt.query_events(&reb_snap, &ev_filter, 50)
    );
    assert_eq!(
        rebuilt.query_events(&inc_snap, &ev_filter, 50),
        ora_snap.query_events(&ev_filter, 50)
    );
    let foot_filter = FootageQueryFilter {
        completed_only: true,
        ..FootageQueryFilter::default()
    };
    assert_eq!(
        rebuilt.query_footage(&inc_snap, &foot_filter, 50),
        rebuilt.query_footage(&reb_snap, &foot_filter, 50)
    );
    assert_eq!(
        rebuilt.query_footage(&inc_snap, &foot_filter, 50),
        ora_snap.query_footage(&foot_filter, 50)
    );
    assert_eq!(
        rebuilt.query_coverage(&inc_snap, None, None),
        rebuilt.query_coverage(&reb_snap, None, None)
    );
    assert_eq!(
        rebuilt.query_coverage(&inc_snap, None, None),
        ora_snap.query_coverage(None, None)
    );
    assert_eq!(
        inc_snap.follow_since(0, 250)?,
        rebuilt.follow_since(0, 250)?
    );
    assert_eq!(
        inc_snap.follow_since(0, 250)?,
        ora_snap.follow_since(0, 250)?
    );

    // Incremental catch-up (high_water + 1 ..= ledger_head).
    drop(rebuilt);
    for step in 201_u64..=205 {
        let interval = CaptureInterval::new(
            TimestampNs(step as i128 * 100),
            TimestampNs(step as i128 * 100 + 50),
        )?;
        let payload = ProjectionRecordPayload::SensorLiveness(SensorLivenessPayload {
            sensor_id: SensorId::parse("cam-00")?,
            state: SensorLivenessStatus::Online,
            last_seen_ns: interval.earliest,
            observed_at_ns: interval.latest,
        });
        let b = harness.commit(
            None,
            DeltaSpec {
                seq_tag: step,
                family: FAMILY_SENSOR_LIVENESS,
                object_id: ObjectId::parse("obj:live:00")?,
                plane: Plane::Authority,
                interval,
            },
            &payload,
        )?;
        all_batches.push(b);
    }

    let resolver = PackStorePayloadResolver::new(&harness.packs);
    let caught_up = MvccProjectionStore::open_or_rebuild_with_config(
        &proj_dir,
        &StreamingHistory(&harness.ledger),
        &resolver,
        recovery_config,
    )?;
    assert!(matches!(
        caught_up.snapshot_at(202),
        Err(ProjectionError::SnapshotEvicted { .. })
    ));
    assert_eq!(caught_up.snapshot_at(203)?.anchor().commit_sequence, 203);
    assert_eq!(
        caught_up.recovery_report().mode,
        ProjectionRecoveryMode::CaughtUpFromSnapshot
    );
    assert_eq!(caught_up.recovery_report().replayed_ledger_batches, 5);
    let ora_205 = replay_from_batches(
        harness.ledger.genesis_anchor(),
        HistoryChainMode::V2MerkleEpoch,
        &all_batches,
        &resolver,
    )?;
    assert_eq!(
        caught_up.snapshot_latest().state_digest(),
        ora_205.state_digest()
    );

    // DoctorScrubReceipt: strictly None until recorded, domain digest check, persists on reopen.
    assert!(caught_up.latest_scrub_receipt().is_none());
    let receipt = DoctorScrubReceipt {
        scrubbed_at_ns: TimestampNs(1_700_000_000_000_000_000),
        anchor: caught_up.head_anchor(),
        first_seq: 1,
        last_seq: 205,
        verified_objects: 205,
        verified_packs: 1,
        verified_fraction_ppm: 1_000_000,
        verdict: ScrubVerdict::Clean,
    };
    assert_eq!(
        receipt.receipt_digest(),
        fss_core::CanonicalEncode::canonical_digest(&receipt, PROJECTION_SCRUB_RECEIPT_DOMAIN)
    );
    caught_up.record_scrub_receipt(receipt.clone())?;
    drop(caught_up);

    let reopened = MvccProjectionStore::open_or_rebuild(&proj_dir, &harness.ledger, &resolver)?;
    assert_eq!(
        reopened.recovery_report().mode,
        ProjectionRecoveryMode::LoadedCurrent
    );
    assert_eq!(reopened.latest_scrub_receipt(), Some(receipt));
    assert_eq!(
        reopened.snapshot_latest().state_digest(),
        ora_205.state_digest()
    );
    drop(reopened);

    // Corrupt mvcc.snap -> automatic quarantine + deterministic rebuild (scrub resets to None).
    let snap_path = proj_dir.join(SNAPSHOT_FILENAME);
    let mut snap_bytes = fs::read(&snap_path)?;
    let mid = snap_bytes.len() / 2;
    snap_bytes[mid] ^= 0xAA;
    fs::write(&snap_path, &snap_bytes)?;
    let repaired_snap =
        MvccProjectionStore::open_or_rebuild(&proj_dir, &harness.ledger, &resolver)?;
    assert_eq!(
        repaired_snap.recovery_report().rebuild_reason,
        Some(ProjectionRebuildReason::CorruptSnapshot)
    );
    assert!(!repaired_snap.recovery_report().quarantined_files.is_empty());
    assert!(repaired_snap.latest_scrub_receipt().is_none());
    assert_eq!(
        repaired_snap.snapshot_latest().state_digest(),
        ora_205.state_digest()
    );
    drop(repaired_snap);

    // Corrupt mvcc.wal -> automatic quarantine + deterministic rebuild.
    fs::write(
        proj_dir.join(WAL_FILENAME),
        b"FMVW\x00\x01corrupted-wal-garbage",
    )?;
    let repaired_wal = MvccProjectionStore::open_or_rebuild(&proj_dir, &harness.ledger, &resolver)?;
    assert_eq!(
        repaired_wal.recovery_report().rebuild_reason,
        Some(ProjectionRebuildReason::CorruptWal)
    );
    assert!(!repaired_wal.recovery_report().quarantined_files.is_empty());
    assert_eq!(
        repaired_wal.snapshot_latest().state_digest(),
        ora_205.state_digest()
    );
    assert_eq!(harness.ledger.read_batches_range(1, 205)?.len(), 205);
    Ok(())
}

#[test]
fn epoch_visitor_stops_before_later_corruption() -> TestResult {
    use std::io::{Seek, SeekFrom, Write};

    let ws = TempWorkspace::new("visit-epoch")?;
    let ledger = MerkleEpochLedger::open(
        ws.root.join("ledger"),
        "site:visit-epoch",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    let store = MvccProjectionStore::open_empty(
        ws.root.join("projection"),
        ledger.genesis_anchor(),
        ProjectionStoreConfig::default(),
    )?;
    let mut harness = ScenarioHarness {
        ledger,
        packs: PackStore::open(ws.root.join("packs"), PackConfig::default())?,
        gens: BTreeMap::new(),
        rev_digests: BTreeMap::new(),
        created_imports: Vec::new(),
    };
    harness.run_step(&store, 1)?;
    harness.run_step(&store, 2)?;

    let path = fss_ledger::epoch_file_path(&ws.root.join("ledger/epochs"), 0);
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::End(-1))?;
    let mut last_byte = [0_u8];
    std::io::Read::read_exact(&mut file, &mut last_byte)?;
    file.seek(SeekFrom::End(-1))?;
    file.write_all(&[last_byte[0] ^ 1])?;
    drop(file);

    let mut visited = Vec::new();
    let stopped = harness.ledger.visit_batches_range(1, 2, &mut |batch| {
        visited.push(batch.new_anchor.commit_sequence);
        Err(ProjectionError::InvalidRequest("stop"))
    });
    assert!(matches!(
        stopped,
        Err(ProjectionError::InvalidRequest("stop"))
    ));
    assert_eq!(visited, [1]);

    let mut verified = Vec::new();
    let corrupt = harness.ledger.visit_batches_range(1, 2, &mut |batch| {
        verified.push(batch.new_anchor.commit_sequence);
        Ok(())
    });
    assert!(matches!(
        corrupt,
        Err(ProjectionError::CorruptDerivedStore { .. })
    ));
    assert_eq!(verified, [1]);
    Ok(())
}
