#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
//! Live contract & adversarial verification suite for `DOC-050` (`fss-x4a.5.50`,
//! import `IMP-AS-SUBJECT-001`, admission gate `INT-AS-001`):
//! Route internal work through typed semantic subjects with separate packet,
//! authority, and reasoning service classes.

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    BudgetVector, ContentDigest, IdempotencyKey, OperationId, RegionId, RegionKind, RegionTree,
    ResourcePressure, RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::grant::GrantSet;
use fss_runtime::lease::LeaseRegistry;
use fss_runtime::obligation::ObligationTerminal;
use fss_runtime::semantic_subject::{
    AtpObjectGraphManifest, AuthoritySubmission, DataLocality, DeploymentProfile,
    DispatchedMessage, DurableAckOutcome, FabricPlane, FairnessWeights, LabFabricHarness,
    PacketSubmission, PrivacyZone, QueueBounds, ReasoningSubmission, RouteCompiler, RouteContext,
    RouteDisposition, SemanticSubjectFabric, ServiceClass, SubjectError, SubjectFamily,
    SubjectName, SubjectSchema, SubjectSchemaRegistry, SubjectSchemaStatus,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn all_reference_caps() -> Vec<String> {
    [
        RuntimeGrant::ObserveStatus,
        RuntimeGrant::ObserveEvent,
        RuntimeGrant::LedgerAppend,
        RuntimeGrant::ObjectStage,
        RuntimeGrant::ObjectPublish,
        RuntimeGrant::AgentQuery,
        RuntimeGrant::ModelInfer,
        RuntimeGrant::Calibrate,
        RuntimeGrant::AgentExplain,
        RuntimeGrant::AlertCommit,
        RuntimeGrant::AgentPlanPrepare,
        RuntimeGrant::AdapterNet,
    ]
    .into_iter()
    .map(|g| g.as_str().to_owned())
    .collect()
}

fn open_root_authority(
    region: &str,
    caps: Vec<String>,
) -> TestResult<(AuthorityCx, RegionTree, LeaseRegistry)> {
    let budget = BudgetVector::builder()
        .bytes(4 * 1024 * 1024)
        .cpu_millis(60_000)
        .storage_operations(50_000)
        .network_bytes(4 * 1024 * 1024)
        .build()?;
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:doc050:{region}"),
        operation_id: OperationId::parse(format!("op:doc050:{region}"))?,
        principal: "principal:doc050-owner".to_owned(),
        capabilities: caps,
        deadline: None,
        priority: 10,
        budgets: budget,
        privacy_scope: "private:property".to_owned(),
        retention_scope: "retention:standard".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:home"),
        generation: 1,
    };
    let (cx, tree) = AuthorityCx::root(
        spec,
        RegionId::new(region)?,
        RegionKind::Process,
        budget,
        TimestampNs(1_000),
    )?;
    Ok((cx, tree, LeaseRegistry::new()))
}

fn route_context(
    grants: &GrantSet,
    pressure: ResourcePressure,
    locality: DataLocality,
    profile: DeploymentProfile,
) -> RouteContext {
    RouteContext {
        grants: grants.clone(),
        allowed_sites: BTreeSet::from(["home".to_owned()]),
        allowed_sensors: Some(BTreeSet::from(["cam1".to_owned(), "cam2".to_owned()])),
        allowed_privacy_zones: BTreeSet::from([
            PrivacyZone::Metadata,
            PrivacyZone::ExteriorProperty,
            PrivacyZone::InteriorPrivate,
            PrivacyZone::RestrictedCustody,
        ]),
        target_locality: locality,
        pressure,
        profile,
    }
}

#[test]
fn doc_050_all_six_families_five_service_classes_and_three_planes_contract() -> TestResult {
    let (mut cx, mut tree, mut leases) =
        open_root_authority("region:doc050:all-planes", all_reference_caps())?;
    let reg = SubjectSchemaRegistry::reference_fss_v1()?;
    let routes = RouteCompiler::compile(
        &reg,
        &route_context(
            cx.grants(),
            ResourcePressure::Nominal,
            DataLocality::SiteHub,
            DeploymentProfile::MultiSiteHub,
        ),
    );
    assert!(!routes.receipt().grants_effect_authority);

    let mut fabric = SemanticSubjectFabric::open(
        &cx,
        &tree,
        reg,
        routes,
        QueueBounds {
            max_durable_attempts: 2,
            ..QueueBounds::default()
        },
        FairnessWeights::default(),
    )?;

    // SUBJ-001 Packet / EphemeralLatest (supersede receipt)
    let thumb_subj = SubjectName::parse("fss.site.home.sensor.cam1.thumbnail.g1")?;
    let t1 = fabric.publish_packet(
        PacketSubmission {
            subject: thumb_subj.clone(),
            source_key: "cam1:thumb".to_owned(),
            sequence: 10,
            object_digests: vec![ContentDigest::sha256(b"thumb-10")],
            provenance: "source:sensor-thumb".to_owned(),
            budget: BudgetVector::ZERO,
            created_at: TimestampNs(2_000),
            deadline: None,
            atp_manifest: None,
        },
        TimestampNs(2_000),
    )?;
    assert!(!t1.grants_effect_authority);
    let t2 = fabric.publish_packet(
        PacketSubmission {
            subject: thumb_subj,
            source_key: "cam1:thumb".to_owned(),
            sequence: 11,
            object_digests: vec![ContentDigest::sha256(b"thumb-11")],
            provenance: "source:sensor-thumb".to_owned(),
            budget: BudgetVector::ZERO,
            created_at: TimestampNs(2_010),
            deadline: None,
            atp_manifest: None,
        },
        TimestampNs(2_010),
    )?;
    assert_eq!(t2.superseded.as_ref().map(|s| s.superseded_seq), Some(10));

    // SUBJ-001 Packet / OrderedTelemetry (in-order, gap, and out-of-order receipts)
    let health_subj = SubjectName::parse("fss.site.home.sensor.cam1.health")?;
    for (seq, expect_gap, expect_ooo) in [(1, false, false), (4, true, false), (2, true, true)] {
        let rcpt = fabric.publish_packet(
            PacketSubmission {
                subject: health_subj.clone(),
                source_key: "cam1:health".to_owned(),
                sequence: seq,
                object_digests: vec![ContentDigest::sha256(format!("h-{seq}").as_bytes())],
                provenance: "source:sensor-health".to_owned(),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(2_020 + i128::from(seq)),
                deadline: None,
                atp_manifest: None,
            },
            TimestampNs(2_020 + i128::from(seq)),
        )?;
        assert_eq!(rcpt.telemetry_gap.is_some(), expect_gap);
        if let Some(gap) = rcpt.telemetry_gap {
            assert_eq!(gap.out_of_order, expect_ooo);
        }
    }

    // SUBJ-002 Packet / VerifiedObjectGraph (ATP immutable object graph)
    let atp_manifest = AtpObjectGraphManifest::new(
        ContentDigest::sha256(b"atp-manifest-1"),
        ContentDigest::sha256(b"atp-root-1"),
        vec![
            ContentDigest::sha256(b"chunk-1"),
            ContentDigest::sha256(b"chunk-2"),
        ],
        8,
        true,
        true,
    )?;
    assert!(!atp_manifest.grants_effect_authority());
    let atp_rcpt = fabric.publish_packet(
        PacketSubmission {
            subject: SubjectName::parse("fss.site.home.archive.root1.graph")?,
            source_key: "archive:hub".to_owned(),
            sequence: 1,
            object_digests: vec![ContentDigest::sha256(b"atp-root-1")],
            provenance: "custody:atp-graph".to_owned(),
            budget: BudgetVector::ZERO,
            created_at: TimestampNs(2_100),
            deadline: None,
            atp_manifest: Some(atp_manifest),
        },
        TimestampNs(2_100),
    )?;
    assert_eq!(atp_rcpt.service_class, ServiceClass::VerifiedObjectGraph);
    assert!(!atp_rcpt.grants_effect_authority);

    // SUBJ-003 & SUBJ-004 Reasoning / DurableAtLeastOnce (graph delta + decision card)
    let graph_rcpt = fabric.publish_reasoning(
        ReasoningSubmission {
            subject: SubjectName::parse("fss.site.home.graph.coverage.delta")?,
            delivery_key: "del:graph:1".to_owned(),
            evidence_anchor_root: ContentDigest::sha256(b"anchor:root:1"),
            generation_id: "graph-gen:v1".to_owned(),
            payload_digest: ContentDigest::sha256(b"graph-delta-1"),
            budget: BudgetVector::ZERO,
            created_at: TimestampNs(2_200),
            deadline: None,
        },
        TimestampNs(2_200),
    )?;
    assert_eq!(graph_rcpt.plane, FabricPlane::Reasoning);
    assert!(!graph_rcpt.grants_effect_authority);

    let dec_rcpt = fabric.publish_reasoning(
        ReasoningSubmission {
            subject: SubjectName::parse("fss.evidence.decision.dec-001")?,
            delivery_key: "del:decision:1".to_owned(),
            evidence_anchor_root: ContentDigest::sha256(b"anchor:root:1"),
            generation_id: "policy-gen:v1".to_owned(),
            payload_digest: ContentDigest::sha256(b"decision-card-1"),
            budget: BudgetVector::ZERO,
            created_at: TimestampNs(2_210),
            deadline: None,
        },
        TimestampNs(2_210),
    )?;
    assert_eq!(dec_rcpt.plane, FabricPlane::Reasoning);

    // SUBJ-005 Authority / ObligatedExactlyEffectOnce + SUBJ-006 Proof / DurableAtLeastOnce
    let lease = leases.acquire(
        "alert:primary",
        cx.region().as_str(),
        Some(50_000),
        TimestampNs(2_000),
    )?;
    let alert_rcpt = fabric.publish_authority(
        &mut cx,
        &mut tree,
        &mut leases,
        AuthoritySubmission {
            subject: SubjectName::parse("fss.site.home.incident.inc42.obligation")?,
            operation_id: OperationId::parse("op:alert:inc42")?,
            idempotency_key: IdempotencyKey::parse("idem:alert:inc42")?,
            resource: "alert:primary".to_owned(),
            fence: lease.fence,
            terminal_predicate: "alert webhook verified or explicitly reconciled".to_owned(),
            payload_digest: ContentDigest::sha256(b"alert-inc42"),
            budget: BudgetVector::builder().bytes(512).build()?,
            created_at: TimestampNs(2_300),
            deadline: None,
        },
        TimestampNs(2_300),
    )?;
    assert!(alert_rcpt.obligation_id.is_some());

    let proof_rcpt = fabric.publish_authority(
        &mut cx,
        &mut tree,
        &mut leases,
        AuthoritySubmission {
            subject: SubjectName::parse("fss.site.home.proof.bundle1.publish")?,
            operation_id: OperationId::parse("op:proof:bundle1")?,
            idempotency_key: IdempotencyKey::parse("idem:proof:bundle1")?,
            resource: "proof:bundle1".to_owned(),
            fence: 0,
            terminal_predicate: "proof bundle published".to_owned(),
            payload_digest: ContentDigest::sha256(b"proof-bundle-1"),
            budget: BudgetVector::builder().storage_operations(2).build()?,
            created_at: TimestampNs(2_310),
            deadline: None,
        },
        TimestampNs(2_310),
    )?;
    assert!(proof_rcpt.obligation_id.is_none());

    // Drain all messages, testing durable nack -> redelivery -> dead-letter on decision card,
    // durable ack on graph/proof, and Indeterminate-with-reconciliation-note on alert obligation!
    let mut now_ns = 3_000_i128;
    let mut seen_planes = BTreeSet::new();
    let mut saw_redelivery = false;
    while let Some(msg) = fabric.dequeue_next(TimestampNs(now_ns)) {
        now_ns += 10;
        seen_planes.insert(msg.plane());
        match msg {
            DispatchedMessage::Packet {
                grants_effect_authority,
                ..
            } => {
                assert!(!grants_effect_authority);
            }
            DispatchedMessage::Reasoning {
                fabric_seq,
                schema_id,
                attempt,
                is_authoritative_truth,
                grants_effect_authority,
                ..
            } => {
                assert!(!is_authoritative_truth);
                assert!(!grants_effect_authority);
                if schema_id == "SUBJ-004.evidence.decision.v1" {
                    let outcome = fabric.nack_durable(fabric_seq)?;
                    if attempt == 1 {
                        assert_eq!(outcome, DurableAckOutcome::Redelivered { next_attempt: 2 });
                        saw_redelivery = true;
                    } else {
                        assert_eq!(outcome, DurableAckOutcome::DeadLettered { attempts: 2 });
                    }
                } else {
                    assert_eq!(
                        fabric.ack_durable(fabric_seq)?,
                        DurableAckOutcome::Acknowledged
                    );
                }
            }
            DispatchedMessage::Authority {
                fabric_seq,
                obligation_id,
                ..
            } => {
                if let Some(ob_id) = obligation_id {
                    // Indeterminate WITHOUT reconciliation note must fail closed!
                    let bad_ind = fabric.settle_authority_obligation(
                        &cx,
                        &mut tree,
                        fabric_seq,
                        &ob_id,
                        ObligationTerminal::Indeterminate,
                        None,
                        None,
                    );
                    assert!(bad_ind.is_err());
                    // Indeterminate WITH explicit reconciliation note succeeds!
                    fabric.settle_authority_obligation(
                        &cx,
                        &mut tree,
                        fabric_seq,
                        &ob_id,
                        ObligationTerminal::Indeterminate,
                        None,
                        Some("webhook peer closed before ACK; operator reconciliation queued"),
                    )?;
                } else {
                    assert_eq!(
                        fabric.ack_durable(fabric_seq)?,
                        DurableAckOutcome::Acknowledged
                    );
                }
            }
        }
    }
    assert!(saw_redelivery);
    assert_eq!(fabric.dead_letters().len(), 1);
    assert_eq!(seen_planes.len(), 3);

    fabric.request_drain(&cx, &mut tree, TimestampNs(now_ns + 10))?;
    let receipt = fabric.finalize(&cx, &mut tree, TimestampNs(now_ns + 20))?;
    assert_eq!(receipt.remaining_queued, 0);
    assert_eq!(receipt.remaining_in_flight, 0);
    assert_eq!(receipt.total_telemetry_gaps, 2);
    Ok(())
}

#[test]
fn doc_050_packet_flood_fairness_pressure_shed_and_packet_batch_authority_isolation() -> TestResult
{
    let (mut cx, mut tree, mut leases) =
        open_root_authority("region:doc050:fairness", all_reference_caps())?;
    let reg = SubjectSchemaRegistry::reference_fss_v1()?;
    let nominal_routes = RouteCompiler::compile(
        &reg,
        &route_context(
            cx.grants(),
            ResourcePressure::Nominal,
            DataLocality::SiteHub,
            DeploymentProfile::EdgeMinimal,
        ),
    );
    let mut fabric = SemanticSubjectFabric::open(
        &cx,
        &tree,
        reg.clone(),
        nominal_routes,
        QueueBounds {
            ephemeral_latest: 8,
            ordered_telemetry: 16,
            verified_object_graph: 4,
            reasoning_durable: 8,
            authority_durable: 8,
            authority_obligated: 8,
            max_durable_attempts: 2,
        },
        FairnessWeights {
            authority_weight: 4,
            reasoning_weight: 2,
            packet_weight: 1,
        },
    )?;

    // 1. Flood packet plane with 16 OrderedTelemetry + 4 EphemeralLatest items (hits exact backpressure at 17th!).
    for idx in 1..=16_u64 {
        fabric.publish_packet(
            PacketSubmission {
                subject: SubjectName::parse("fss.site.home.sensor.cam1.health")?,
                source_key: "cam1:flood".to_owned(),
                sequence: idx,
                object_digests: vec![ContentDigest::sha256(format!("pkt-{idx}").as_bytes())],
                provenance: "source:sensor-health".to_owned(),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(1_500 + i128::from(idx)),
                deadline: None,
                atp_manifest: None,
            },
            TimestampNs(1_500 + i128::from(idx)),
        )?;
    }
    let bp = fabric.publish_packet(
        PacketSubmission {
            subject: SubjectName::parse("fss.site.home.sensor.cam1.health")?,
            source_key: "cam1:flood".to_owned(),
            sequence: 17,
            object_digests: vec![ContentDigest::sha256(b"pkt-17")],
            provenance: "source:sensor-health".to_owned(),
            budget: BudgetVector::ZERO,
            created_at: TimestampNs(1_600),
            deadline: None,
            atp_manifest: None,
        },
        TimestampNs(1_600),
    );
    assert!(matches!(
        bp,
        Err(SubjectError::BackpressureQueueFull {
            service_class: ServiceClass::OrderedTelemetry,
            capacity: 16,
        })
    ));

    for idx in 1..=4_u64 {
        fabric.publish_packet(
            PacketSubmission {
                subject: SubjectName::parse("fss.site.home.sensor.cam1.thumbnail.g1")?,
                source_key: format!("cam1:thumb:{idx}"),
                sequence: 1,
                object_digests: vec![ContentDigest::sha256(format!("t-{idx}").as_bytes())],
                provenance: "source:sensor-thumb".to_owned(),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(1_610),
                deadline: None,
                atp_manifest: None,
            },
            TimestampNs(1_610),
        )?;
    }

    // 2. Submit 4 Authority items alongside the packet flood.
    let lease = leases.acquire(
        "alert:primary",
        cx.region().as_str(),
        Some(100_000),
        TimestampNs(1_000),
    )?;
    for idx in 1..=4_u64 {
        fabric.publish_authority(
            &mut cx,
            &mut tree,
            &mut leases,
            AuthoritySubmission {
                subject: SubjectName::parse(format!("fss.site.home.incident.inc{idx}.obligation"))?,
                operation_id: OperationId::parse(format!("op:fair:{idx}"))?,
                idempotency_key: IdempotencyKey::parse(format!("idem:fair:{idx}"))?,
                resource: "alert:primary".to_owned(),
                fence: lease.fence,
                terminal_predicate: "authority priority proof".to_owned(),
                payload_digest: ContentDigest::sha256(format!("auth-{idx}").as_bytes()),
                budget: BudgetVector::builder().bytes(64).build()?,
                created_at: TimestampNs(1_700 + i128::from(idx)),
                deadline: None,
            },
            TimestampNs(1_700 + i128::from(idx)),
        )?;
    }

    // 3. Packet batch drain on EphemeralLatest leaves Authority high-water completely untouched!
    let hw_before = fabric.authority_order_high_water();
    let (batch, batch_rcpt) =
        fabric.drain_packet_batch(ServiceClass::EphemeralLatest, 8, TimestampNs(1_800))?;
    assert_eq!(batch.len(), 4);
    assert!(!batch_rcpt.grants_effect_authority);
    assert_eq!(batch_rcpt.authority_order_high_water, hw_before);
    // Attempting packet batching on OrderedTelemetry or Authority service classes fails closed!
    assert!(matches!(
        fabric.drain_packet_batch(ServiceClass::OrderedTelemetry, 4, TimestampNs(1_800)),
        Err(SubjectError::PlaneServiceClassMismatch { .. })
    ));

    // 4. First 4 weighted-fairness dequeues MUST be the 4 Authority items in strict order 1..=4!
    let mut auth_orders = Vec::new();
    for step in 0..4_u64 {
        let msg = fabric
            .dequeue_next(TimestampNs(1_900 + i128::from(step)))
            .ok_or("expected authority message")?;
        match msg {
            DispatchedMessage::Authority {
                fabric_seq,
                authority_order_seq,
                obligation_id,
                submission,
                ..
            } => {
                auth_orders.push(authority_order_seq);
                if let Some(ob_id) = obligation_id {
                    fabric.settle_authority_obligation(
                        &cx,
                        &mut tree,
                        fabric_seq,
                        &ob_id,
                        ObligationTerminal::Completed,
                        Some(submission.payload_digest),
                        None,
                    )?;
                }
            }
            other => {
                return Err(
                    format!("expected Authority before packet flood, got {other:?}").into(),
                );
            }
        }
    }
    assert_eq!(auth_orders, vec![1, 2, 3, 4]);

    // 5. Switch compiled routes to Critical resource pressure:
    //    EphemeralLatest & non-critical Reasoning are shed, while Authority stays admitted!
    let critical_routes = RouteCompiler::compile(
        &reg,
        &route_context(
            cx.grants(),
            ResourcePressure::Critical,
            DataLocality::SiteHub,
            DeploymentProfile::EdgeMinimal,
        ),
    );
    assert!(matches!(
        critical_routes
            .route_for("SUBJ-001.sensor.thumbnail.v1")
            .map(|r| &r.disposition),
        Some(RouteDisposition::PressureShed {
            pressure: ResourcePressure::Critical,
            ..
        })
    ));
    assert!(matches!(
        critical_routes
            .route_for("SUBJ-003.model.infer.v1")
            .map(|r| &r.disposition),
        Some(RouteDisposition::PressureShed {
            pressure: ResourcePressure::Critical,
            ..
        })
    ));
    assert!(matches!(
        critical_routes
            .route_for("SUBJ-005.incident.obligation.v1")
            .map(|r| &r.disposition),
        Some(RouteDisposition::Admitted { .. })
    ));
    fabric.update_routes(critical_routes);

    let shed_err = fabric.publish_packet(
        PacketSubmission {
            subject: SubjectName::parse("fss.site.home.sensor.cam1.thumbnail.g1")?,
            source_key: "cam1:shed".to_owned(),
            sequence: 1,
            object_digests: vec![ContentDigest::sha256(b"shed-thumb")],
            provenance: "source:sensor-thumb".to_owned(),
            budget: BudgetVector::ZERO,
            created_at: TimestampNs(2_000),
            deadline: None,
            atp_manifest: None,
        },
        TimestampNs(2_000),
    );
    assert!(matches!(
        shed_err,
        Err(SubjectError::PressureShed {
            pressure: ResourcePressure::Critical,
            ..
        })
    ));

    // Drain remaining packets and close cleanly.
    fabric.request_drain(&cx, &mut tree, TimestampNs(2_100))?;
    let (_drained, cert) = fabric.step_drain(64, TimestampNs(2_150))?;
    assert_eq!(cert.remaining_after, 0);
    let _quiescence = fabric.finalize(&cx, &mut tree, TimestampNs(2_200))?;
    Ok(())
}

#[test]
fn doc_050_adversarial_authority_boundaries_tombstones_deadlines_and_leak_refusal() -> TestResult {
    let (mut cx, mut tree, mut leases) =
        open_root_authority("region:doc050:adv", all_reference_caps())?;
    let mut reg = SubjectSchemaRegistry::reference_fss_v1()?;
    // Register & tombstone a custom version dynamically to verify non-renumbering tombstone retention.
    reg.register(SubjectSchema {
        schema_id: "SUBJ-006.custom.legacy.v1".to_owned(),
        family: SubjectFamily::Proof,
        version: 1,
        pattern: SubjectSchema::parse_pattern("fss.site.<site>.custom_legacy.<id>")?,
        plane: FabricPlane::Authority,
        service_class: ServiceClass::DurableAtLeastOnce,
        required_grant: RuntimeGrant::ObjectPublish,
        privacy_zone: PrivacyZone::Metadata,
        requires_lease_fence: false,
        terminal_or_coverage_critical: true,
        allows_archive_locality: false,
        status: SubjectSchemaStatus::Active,
    })?;
    reg.tombstone_version(
        "SUBJ-006.custom.legacy.v1",
        2,
        "migrated to v2 proof schema",
    )?;

    // Compile routes with FULL grants, then narrow AuthorityCx grants to REMOVE AlertCommit!
    // Proves routing table can NEVER substitute for explicit AuthorityCx verification!
    let routes = RouteCompiler::compile(
        &reg,
        &route_context(
            cx.grants(),
            ResourcePressure::Nominal,
            DataLocality::SiteHub,
            DeploymentProfile::HomeSingleHost,
        ),
    );
    let mut fabric = SemanticSubjectFabric::open(
        &cx,
        &tree,
        reg,
        routes,
        QueueBounds::default(),
        FairnessWeights::default(),
    )?;

    // 1. Cross-plane smuggling attempts fail closed!
    let smuggle_auth_in_packet = fabric.publish_packet(
        PacketSubmission {
            subject: SubjectName::parse("fss.site.home.incident.inc1.obligation")?,
            source_key: "spoof".to_owned(),
            sequence: 1,
            object_digests: vec![ContentDigest::sha256(b"spoof")],
            provenance: "untrusted".to_owned(),
            budget: BudgetVector::ZERO,
            created_at: TimestampNs(2_000),
            deadline: None,
            atp_manifest: None,
        },
        TimestampNs(2_000),
    );
    assert!(matches!(
        smuggle_auth_in_packet,
        Err(SubjectError::WrongPlaneBoundary {
            expected: FabricPlane::Authority,
            attempted: FabricPlane::Packet,
        })
    ));

    let smuggle_packet_in_reasoning = fabric.publish_reasoning(
        ReasoningSubmission {
            subject: SubjectName::parse("fss.site.home.sensor.cam1.health")?,
            delivery_key: "spoof".to_owned(),
            evidence_anchor_root: ContentDigest::sha256(b"a"),
            generation_id: "gen:v1".to_owned(),
            payload_digest: ContentDigest::sha256(b"p"),
            budget: BudgetVector::ZERO,
            created_at: TimestampNs(2_000),
            deadline: None,
        },
        TimestampNs(2_000),
    );
    assert!(matches!(
        smuggle_packet_in_reasoning,
        Err(SubjectError::WrongPlaneBoundary {
            expected: FabricPlane::Packet,
            attempted: FabricPlane::Reasoning,
        })
    ));

    // 2. Lease fence enforcement + IdempotencyConflict detection + narrowed AuthorityCx refusal!
    let lease = leases.acquire(
        "alert:primary",
        cx.region().as_str(),
        Some(5_000),
        TimestampNs(2_000),
    )?;
    let good_sub = AuthoritySubmission {
        subject: SubjectName::parse("fss.site.home.incident.inc7.obligation")?,
        operation_id: OperationId::parse("op:adv:inc7")?,
        idempotency_key: IdempotencyKey::parse("idem:adv:inc7")?,
        resource: "alert:primary".to_owned(),
        fence: lease.fence,
        terminal_predicate: "inc7 obligation terminal".to_owned(),
        payload_digest: ContentDigest::sha256(b"payload-A"),
        budget: BudgetVector::builder().bytes(128).build()?,
        created_at: TimestampNs(2_100),
        deadline: None,
    };
    let ok_rcpt = fabric.publish_authority(
        &mut cx,
        &mut tree,
        &mut leases,
        good_sub.clone(),
        TimestampNs(2_100),
    )?;
    let ob_id = ok_rcpt.obligation_id.ok_or("expected obligation")?;

    // Reusing same idempotency key with DIFFERENT payload fails closed (`IdempotencyConflict`)!
    let mut conflict_sub = good_sub.clone();
    conflict_sub.payload_digest = ContentDigest::sha256(b"payload-TAMPERED");
    assert!(matches!(
        fabric.publish_authority(
            &mut cx,
            &mut tree,
            &mut leases,
            conflict_sub,
            TimestampNs(2_150)
        ),
        Err(SubjectError::IdempotencyConflict { .. })
    ));

    // Narrow AuthorityCx grants to drop AlertCommit: even though compiled route is Admitted,
    // explicit AuthorityCx check MUST deny!
    let narrowed = GrantSet::empty();
    cx.narrow_grants(narrowed)?;
    let mut post_narrow = good_sub;
    post_narrow.idempotency_key = IdempotencyKey::parse("idem:adv:inc8")?;
    post_narrow.operation_id = OperationId::parse("op:adv:inc8")?;
    assert!(matches!(
        fabric.publish_authority(
            &mut cx,
            &mut tree,
            &mut leases,
            post_narrow,
            TimestampNs(2_200)
        ),
        Err(SubjectError::AuthorityDenied { .. })
    ));

    // 3. Deadlines: already-expired admission refuses; mid-queue expiry emits explicit receipt!
    assert!(matches!(
        fabric.publish_packet(
            PacketSubmission {
                subject: SubjectName::parse("fss.site.home.sensor.cam1.health")?,
                source_key: "cam1:dl".to_owned(),
                sequence: 1,
                object_digests: vec![ContentDigest::sha256(b"late")],
                provenance: "source:sensor-health".to_owned(),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(2_500),
                deadline: Some(TimestampNs(2_400)),
                atp_manifest: None,
            },
            TimestampNs(2_500),
        ),
        Err(SubjectError::AlreadyExpired { .. })
    ));
    fabric.publish_packet(
        PacketSubmission {
            subject: SubjectName::parse("fss.site.home.sensor.cam1.health")?,
            source_key: "cam1:dl".to_owned(),
            sequence: 2,
            object_digests: vec![ContentDigest::sha256(b"expiring")],
            provenance: "source:sensor-health".to_owned(),
            budget: BudgetVector::ZERO,
            created_at: TimestampNs(2_500),
            deadline: Some(TimestampNs(2_600)),
            atp_manifest: None,
        },
        TimestampNs(2_500),
    )?;
    // Dequeue at 2_700 expires the packet with explicit receipt, while Authority item stays valid!
    let dispatched = fabric
        .dequeue_next(TimestampNs(2_700))
        .ok_or("expected authority item")?;
    assert_eq!(dispatched.plane(), FabricPlane::Authority);
    assert_eq!(fabric.expired_receipts().len(), 1);

    // 4. Attempting finalize while obligation is still pending fails closed naming the leak!
    let leaked_now = cx.leaked_obligations(&tree)?;
    assert_eq!(leaked_now.len(), 1);
    assert_eq!(leaked_now[0].id, ob_id.as_str());

    // Settle obligation cleanly, drain, and finalize!
    fabric.settle_authority_obligation(
        &cx,
        &mut tree,
        ok_rcpt.fabric_seq,
        &ob_id,
        ObligationTerminal::Drained,
        None,
        None,
    )?;
    fabric.request_drain(&cx, &mut tree, TimestampNs(2_800))?;
    let receipt = fabric.finalize(&cx, &mut tree, TimestampNs(2_900))?;
    assert_eq!(receipt.total_expired, 1);
    assert_eq!(receipt.remaining_queued, 0);
    assert_eq!(receipt.remaining_in_flight, 0);
    Ok(())
}

#[test]
fn doc_050_production_vs_lab_equivalence_and_multi_seed_authority_invariance() -> TestResult {
    type LabRunSummary = (
        ContentDigest,
        ContentDigest,
        Vec<(String, u64, ContentDigest)>,
    );
    let run_lab = |seed: u64| -> TestResult<LabRunSummary> {
        let (mut cx, mut tree, mut leases) =
            open_root_authority(&format!("region:doc050:lab-{seed}"), all_reference_caps())?;
        let reg = SubjectSchemaRegistry::reference_fss_v1()?;
        let routes = RouteCompiler::compile(
            &reg,
            &route_context(
                cx.grants(),
                ResourcePressure::Nominal,
                DataLocality::LocalProcess,
                DeploymentProfile::LabDeterministic,
            ),
        );
        let mut fabric = SemanticSubjectFabric::open(
            &cx,
            &tree,
            reg,
            routes,
            QueueBounds::default(),
            FairnessWeights::default(),
        )?;
        let lease = leases.acquire(
            "alert:lab",
            cx.region().as_str(),
            Some(500_000),
            TimestampNs(1_000),
        )?;

        // Seed mixed workload across all 3 planes & all 5 service classes.
        for idx in 1..=5_u64 {
            fabric.publish_packet(
                PacketSubmission {
                    subject: SubjectName::parse("fss.site.home.sensor.cam1.thumbnail.g1")?,
                    source_key: format!("thumb:{idx}"),
                    sequence: 1,
                    object_digests: vec![ContentDigest::sha256(format!("th-{idx}").as_bytes())],
                    provenance: "source:thumb".to_owned(),
                    budget: BudgetVector::ZERO,
                    created_at: TimestampNs(1_100 + i128::from(idx)),
                    deadline: None,
                    atp_manifest: None,
                },
                TimestampNs(1_100 + i128::from(idx)),
            )?;
            let atp = AtpObjectGraphManifest::new(
                ContentDigest::sha256(format!("m-{idx}").as_bytes()),
                ContentDigest::sha256(format!("r-{idx}").as_bytes()),
                vec![ContentDigest::sha256(format!("c-{idx}").as_bytes())],
                2,
                true,
                true,
            )?;
            fabric.publish_packet(
                PacketSubmission {
                    subject: SubjectName::parse(format!("fss.site.home.archive.r{idx}.graph"))?,
                    source_key: format!("atp:{idx}"),
                    sequence: idx,
                    object_digests: vec![ContentDigest::sha256(format!("r-{idx}").as_bytes())],
                    provenance: "custody:atp".to_owned(),
                    budget: BudgetVector::ZERO,
                    created_at: TimestampNs(1_200 + i128::from(idx)),
                    deadline: None,
                    atp_manifest: Some(atp),
                },
                TimestampNs(1_200 + i128::from(idx)),
            )?;
            fabric.publish_reasoning(
                ReasoningSubmission {
                    subject: SubjectName::parse("fss.site.home.graph.cov.delta")?,
                    delivery_key: format!("r:{idx}"),
                    evidence_anchor_root: ContentDigest::sha256(b"anchor:lab"),
                    generation_id: "graph-gen:lab-v1".to_owned(),
                    payload_digest: ContentDigest::sha256(format!("g-{idx}").as_bytes()),
                    budget: BudgetVector::ZERO,
                    created_at: TimestampNs(1_300 + i128::from(idx)),
                    deadline: None,
                },
                TimestampNs(1_300 + i128::from(idx)),
            )?;
        }
        for idx in 1..=4_u64 {
            fabric.publish_authority(
                &mut cx,
                &mut tree,
                &mut leases,
                AuthoritySubmission {
                    subject: SubjectName::parse(format!(
                        "fss.site.home.incident.lab{idx}.obligation"
                    ))?,
                    operation_id: OperationId::parse(format!("op:lab:{idx}"))?,
                    idempotency_key: IdempotencyKey::parse(format!("idem:lab:{idx}"))?,
                    resource: "alert:lab".to_owned(),
                    fence: lease.fence,
                    terminal_predicate: "lab authority settlement".to_owned(),
                    payload_digest: ContentDigest::sha256(format!("auth-lab-{idx}").as_bytes()),
                    budget: BudgetVector::builder().bytes(128).build()?,
                    created_at: TimestampNs(1_400 + i128::from(idx)),
                    deadline: None,
                },
                TimestampNs(1_400 + i128::from(idx)),
            )?;
        }

        let mut harness = LabFabricHarness::new(seed, TimestampNs(2_000), 1_000);
        let transcript = harness.run_to_empty(&mut fabric, &cx, &mut tree)?;
        fabric.request_drain(&cx, &mut tree, harness.now())?;
        let quiescence = fabric.finalize(&cx, &mut tree, TimestampNs(harness.now().0 + 1_000))?;
        assert_eq!(quiescence.remaining_queued, 0);
        assert_eq!(quiescence.remaining_in_flight, 0);
        assert_eq!(quiescence.total_authority_dispatched, 4);
        Ok((
            transcript.transcript_digest,
            transcript.authority_outcome_digest,
            transcript.authority_commit_sequence,
        ))
    };

    // 1. Same seed reproduces byte-identical full transcript!
    let (full_42_a, auth_42_a, seq_42_a) = run_lab(42)?;
    let (full_42_b, auth_42_b, seq_42_b) = run_lab(42)?;
    assert_eq!(full_42_a, full_42_b);
    assert_eq!(auth_42_a, auth_42_b);
    assert_eq!(seq_42_a, seq_42_b);

    // 2. Five distinct packet-interleaving seeds produce 100% IDENTICAL Authority commit sequence & digest!
    for other_seed in [1_u64, 7, 2026, 0xDEAD_BEEF] {
        let (_full_other, auth_other, seq_other) = run_lab(other_seed)?;
        assert_eq!(seq_other, seq_42_a);
        assert_eq!(auth_other, auth_42_a);
    }
    Ok(())
}
