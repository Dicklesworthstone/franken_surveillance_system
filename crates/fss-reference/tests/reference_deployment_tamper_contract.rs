#![forbid(unsafe_code)]
//! Sticky sensor tamper through [`ReferenceDeployment`] (fss-2uftm), ported from the r9e review
//! probe: `publish_event` refuses a revision that drops an unretired tamper and a restoration
//! with no open tamper; a stale alert plan is refused after a tamper revision; an idempotent
//! retry is exact; and the public `append_batch` refuses the reserved families that would let a
//! caller bypass those checks.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::event::EventSupersedeParams;
use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, CapsuleId, CaptureInterval, ContentDigest,
    ContractError, EffectJournal, EffectState, EventHypothesis, EventId, EventKind, EventState,
    EvidenceDelta, IdempotencyKey, LedgerAnchor, ObjectId, ObligationId, OperationId,
    OperationReceipt, Plane, ProbabilityInterval, SensorId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};
use fss_reference::{
    DeliveryPlan, DurableEffectError, MockModelScript, MockModelSpec, MockSemanticLabel,
    PrepareAlertParams, ReferenceAlertPlan, ReferenceDeployment, ReferenceError,
    ReferenceEventReceipt, ReferenceModelObservation, ReferencePolicyAction,
    ReferencePolicyDecision, ReferenceProviderBehavior, ReplayCx, VirtualCameraSpec,
    evaluate_unknown_presence, execute_mock_model, prepare_reference_alert, run_reference_capture,
};

type R = Result<(), Box<dyn Error>>;

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = fss_core::RootAuthoritySpec {
        trace_id: format!("trace:refdep-tamper-{label}"),
        operation_id: OperationId::parse(format!("operation:refdep-tamper-{label}"))?,
        principal: format!("operator:refdep-tamper-{label}"),
        capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"refdep-tamper-anchor-universe"),
        generation: 1,
    };
    let root_auth = fss_core::ContextAuthority::new_root(spec)?;
    let scratch =
        std::env::temp_dir().join(format!("refdep-tamper-cx-{label}-{}", std::process::id()));
    let io = fss_reference::ReplayIoAuthority::from_context_authority(&root_auth, scratch)?;
    Ok(ReplayCx::new(io))
}

fn revision_encoding(event: &EventHypothesis) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text("fss.event_hypothesis.v1");
    event.encode_canonical(&mut encoder);
    encoder.finish()
}

fn supersede(
    prior: &EventHypothesis,
    c: EventHypothesis,
) -> Result<EventHypothesis, Box<dyn Error>> {
    Ok(prior.supersede(
        EventSupersedeParams {
            state: c.state,
            kind: c.kind,
            interval: c.interval,
            uncertainty_reason: c.uncertainty_reason,
            zone_ids: c.zone_ids,
            track_ids: c.track_ids,
            probability: c.probability,
            evidence: c.evidence,
            model_receipts: c.model_receipts,
            decision_path: c.decision_path,
        },
        std::slice::from_ref(prior),
    )?)
}

/// A hand-built Corroborated successor that drops the predecessor's unretired tamper.
fn corroborated_dropping_tamper(
    prior: &EventHypothesis,
    c: EventHypothesis,
) -> Result<EventHypothesis, Box<dyn Error>> {
    let rev = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: prior.event_id.clone(),
        revision: prior.revision + 1,
        supersedes: Some(prior.revision_digest()),
        state: EventState::Corroborated,
        kind: EventKind::UnknownPresence,
        interval: c.interval,
        uncertainty_reason: None,
        zone_ids: Vec::new(),
        track_ids: Vec::new(),
        probability: c.probability,
        evidence: c.evidence,
        model_receipts: c.model_receipts,
        decision_path: c.decision_path,
    };
    rev.validate()?;
    Ok(rev)
}

/// A deployment plus an independent capture ledger and object store for the virtual cameras.
struct Harness {
    dir: PathBuf,
    objects: InMemoryObjectStore,
    captures: DurableReferenceLedger,
    dep: ReferenceDeployment,
    cx: ReplayCx,
}

impl Harness {
    fn new(tag: &str) -> Result<Self, Box<dyn Error>> {
        let dir =
            std::env::temp_dir().join(format!("fss-refdep-tamper-{tag}-{}", std::process::id()));
        let _stale = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let captures = DurableReferenceLedger::open(
            dir.join("captures.journal"),
            format!("site:refdep-tamper-captures:{tag}"),
            IncompleteTailPolicy::Reject,
        )?;
        let cx = test_cx(tag)?;
        let dep = ReferenceDeployment::open(
            &dir.join("deployment"),
            &format!("site:refdep-tamper:{tag}"),
            &cx,
        )?;
        Ok(Self {
            dir,
            objects: InMemoryObjectStore::new(ObjectLimits::new(2048, 32 * 1024 * 1024)),
            captures,
            dep,
            cx,
        })
    }

    fn journal(&self) -> PathBuf {
        self.dep.root().join("ledger/journal.fssj")
    }

    fn observe(
        &mut self,
        tag: &str,
        lane: &str,
        seed: u64,
        domain: &str,
        label: MockSemanticLabel,
    ) -> Result<ReferenceModelObservation, Box<dyn Error>> {
        let spec = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:refdep:{tag}:{lane}:{seed}"))?,
            sensor_id: SensorId::parse(format!("sensor:refdep:{tag}:{lane}"))?,
            seed,
            packet_count: 3,
            packet_bytes: 32,
            start_ns: i128::from(seed) * 10_000,
            period_ns: 1_000_000,
            uncertainty_ns: 100,
        };
        let capture = run_reference_capture(
            &spec,
            &DeliveryPlan::identity(spec.packet_count)?,
            &mut self.objects,
            &mut self.captures,
        )?;
        let model = MockModelSpec::new(
            format!("mock:refdep:{tag}:{lane}:v1"),
            MockModelScript::Fixed {
                label,
                probability: ProbabilityInterval::new(0.9, 1.0)?,
            },
        )?;
        let result = execute_mock_model(&model, &capture, &mut self.objects)?;
        let first = capture.source_packets.first().ok_or("no packets")?;
        let last = capture.source_packets.last().ok_or("no packets")?;
        Ok(ReferenceModelObservation::new(
            result,
            domain,
            CaptureInterval::new(first.capture.earliest, last.capture.latest)?,
        )?)
    }

    /// Copies the model receipts a decision cites into the deployment spool.
    fn mirror(&mut self, d: &ReferencePolicyDecision) -> R {
        for digest in &d.event.model_receipts {
            let bytes = self.objects.read_verified(*digest)?.to_vec();
            if self.dep.stage_payload(&bytes)? != *digest {
                return Err("mirrored receipt digest differs".into());
            }
        }
        Ok(())
    }

    fn publish(
        &mut self,
        d: &ReferencePolicyDecision,
    ) -> Result<Result<ReferenceEventReceipt, ReferenceError>, Box<dyn Error>> {
        self.mirror(d)?;
        Ok(self.dep.publish_event(d, &self.cx))
    }

    /// Offers `d` straight to the public `append_batch` as an `event_revision` delta, with or
    /// without its `sensor_tamper_status` witness, the way the review probe forced it.
    fn bypass(
        &mut self,
        d: &ReferencePolicyDecision,
        prior: &[EventHypothesis],
        with_witness: bool,
    ) -> Result<Result<LedgerAnchor, ReferenceError>, Box<dyn Error>> {
        self.mirror(d)?;
        let event_object_digest = self.dep.stage_payload(&d.event.canonical_bytes())?;
        let event_revision_digest = self.dep.stage_payload(&revision_encoding(&d.event))?;
        let manifest = ObjectManifest::new(
            "event-revision",
            d.event.model_receipts.iter().copied(),
            Some(event_object_digest),
        )?;
        let event_root = self.dep.stage_payload(&manifest.canonical_bytes())?;
        let status = fss_core::event::compute_sensor_tamper_status(
            prior.iter().chain(std::iter::once(&d.event)),
            None,
        );
        let name = d.event.event_id.as_str();
        let prior_generation = prior.last().map(|p| p.revision);
        let mut deltas = vec![EvidenceDelta {
            delta_id: format!("delta:event:{name}:{}", d.event.revision),
            family: "event_revision".to_owned(),
            object_id: ObjectId::parse(format!("object:event:{name}"))?,
            prior_generation,
            new_generation: d.event.revision,
            validity: d.event.interval,
            plane: Plane::Authority,
            payload_digest: event_root,
            witness_digest: Some(event_revision_digest),
            operation_id: None,
        }];
        if with_witness {
            deltas.push(EvidenceDelta {
                delta_id: format!("delta:event:{name}:tamper:{}", d.event.revision),
                family: "sensor_tamper_status".to_owned(),
                object_id: ObjectId::parse(format!("object:event:{name}:tamper"))?,
                prior_generation,
                new_generation: d.event.revision,
                validity: d.event.interval,
                plane: Plane::Authority,
                payload_digest: event_root,
                witness_digest: Some(status.canonical_digest()),
                operation_id: None,
            });
        }
        Ok(self.dep.append_batch(
            BatchId::parse(format!("batch:event:{name}:{}", d.event.revision))?,
            deltas,
            vec![event_root],
            &self.cx,
        ))
    }

    fn prepare(
        &self,
        d: &ReferencePolicyDecision,
        r: &ReferenceEventReceipt,
        tag: &str,
    ) -> Result<Result<ReferenceAlertPlan, ReferenceError>, Box<dyn Error>> {
        let mut journal = EffectJournal::new();
        Ok(prepare_reference_alert(
            PrepareAlertParams {
                decision: d,
                event_receipt: r,
                authority: self.dep.ledger(),
                operation_id: OperationId::parse(format!("op:refdep:{tag}").as_str())?,
                idempotency_key: IdempotencyKey::parse(format!("idemp-refdep-{tag}").as_str())?,
                obligation_id: ObligationId::parse(format!("obligation:refdep:{tag}").as_str())?,
                channel: "security-ops".to_owned(),
                now: TimestampNs(3_000),
            },
            &mut journal,
        ))
    }

    fn cleanup(self) {
        let dir = self.dir.clone();
        drop(self);
        let _removed = fs::remove_dir_all(dir);
    }
}

/// rev1 carries a tamper on gamma and is published through the deployment; rev2 is a
/// Corroborated revision that drops that unretired tamper.
fn tamper_then_drop(
    h: &mut Harness,
    tag: &str,
) -> Result<
    (
        ReferencePolicyDecision,
        ReferenceEventReceipt,
        ReferencePolicyDecision,
    ),
    Box<dyn Error>,
> {
    let eid = format!("event:refdep:{tag}");
    let tamper = h.observe(
        tag,
        "lane2",
        52,
        "power:gamma",
        MockSemanticLabel::TamperLike,
    )?;
    let d1 = evaluate_unknown_presence(EventId::parse(eid.as_str())?, vec![tamper])?;
    let r1 = h.publish(&d1)??;
    let alpha = h.observe(
        tag,
        "lane0",
        50,
        "power:alpha",
        MockSemanticLabel::PersonLike,
    )?;
    let beta = h.observe(
        tag,
        "lane1",
        51,
        "power:beta",
        MockSemanticLabel::PersonLike,
    )?;
    let candidate = evaluate_unknown_presence(EventId::parse(eid.as_str())?, vec![alpha, beta])?;
    let d2 = ReferencePolicyDecision {
        event: corroborated_dropping_tamper(&d1.event, candidate.event)?,
        action: ReferencePolicyAction::PrepareAlert,
    };
    Ok((d1, r1, d2))
}

#[test]
fn publish_event_refuses_a_revision_that_drops_an_unretired_tamper() -> R {
    let mut h = Harness::new("p1")?;
    let (_d1, r1, d2) = tamper_then_drop(&mut h, "p1")?;
    assert!(r1.lineage_tamper_status.has_open_tamper());
    let batches = h.dep.ledger().batches().len();
    let journal = fs::read(h.journal())?;
    let res = h.publish(&d2)?;
    assert!(
        matches!(
            res,
            Err(ReferenceError::Contract(ContractError::SensorIntegrityRisk))
        ),
        "{res:?}"
    );
    assert_eq!(h.dep.ledger().batches().len(), batches);
    assert_eq!(fs::read(h.journal())?, journal);
    h.cleanup();
    Ok(())
}

/// The review probe's p2/p3 bypass: the tamper-dropping revision offered to the public
/// `append_batch` with and without its witness is refused, and the journal is untouched.
#[test]
fn append_batch_refuses_a_forced_event_revision_with_or_without_its_witness() -> R {
    for with_witness in [true, false] {
        let tag = if with_witness { "p2" } else { "p3" };
        let mut h = Harness::new(tag)?;
        let (d1, _r1, d2) = tamper_then_drop(&mut h, tag)?;
        let batches = h.dep.ledger().batches().len();
        let journal = fs::read(h.journal())?;
        match h.bypass(&d2, std::slice::from_ref(&d1.event), with_witness)? {
            Err(ReferenceError::ReservedDeltaFamily {
                family,
                entry_point,
            }) => {
                assert_eq!(family, "event_revision", "{tag}");
                assert_eq!(entry_point, "publish_event", "{tag}");
            }
            other => {
                return Err(format!("{tag}: expected ReservedDeltaFamily, got {other:?}").into());
            }
        }
        assert_eq!(h.dep.ledger().batches().len(), batches, "{tag}");
        assert_eq!(fs::read(h.journal())?, journal, "{tag}");
        h.cleanup();
    }
    Ok(())
}

/// Every reserved family is refused by the public `append_batch`, naming its entry point, before
/// any journal I/O.
#[test]
fn append_batch_refuses_every_reserved_delta_family() -> R {
    let h = Harness::new("reserved")?;
    let mut h = h;
    let payload = h.dep.stage_payload(b"reserved-family-payload")?;
    let journal = fs::read(h.journal())?;
    for (family, entry_point) in [
        ("event_revision", "publish_event"),
        ("sensor_tamper_status", "publish_event"),
        ("local_root_reachability", "publish_and_commit"),
        // Only a durable deletion record may tombstone, retract or complete (fss-x4a.9.7).
        ("deletion_record", "deletion::commit_deletion"),
        ("deletion_tombstone", "deletion::commit_deletion"),
        ("deletion_completion", "deletion::commit_deletion"),
        ("local_root_retraction", "deletion::commit_deletion"),
    ] {
        let slug = family.replace('_', "-");
        let delta = EvidenceDelta {
            delta_id: format!("delta:reserved:{slug}"),
            family: family.to_owned(),
            object_id: ObjectId::parse(format!("object:reserved:{slug}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(1), TimestampNs(2))?,
            plane: Plane::Authority,
            payload_digest: payload,
            witness_digest: None,
            operation_id: None,
        };
        match h.dep.append_batch(
            BatchId::parse(format!("batch:reserved:{slug}"))?,
            vec![delta],
            vec![payload],
            &h.cx,
        ) {
            Err(ReferenceError::ReservedDeltaFamily {
                family: refused,
                entry_point: named,
            }) => {
                assert_eq!(refused, family);
                assert_eq!(named, entry_point);
            }
            other => {
                return Err(
                    format!("{family}: expected ReservedDeltaFamily, got {other:?}").into(),
                );
            }
        }
        assert_eq!(fs::read(h.journal())?, journal, "{family}");
    }
    assert!(h.dep.ledger().batches().is_empty());
    h.cleanup();
    Ok(())
}

#[test]
fn publish_event_refuses_a_restoration_with_no_open_tamper() -> R {
    let mut h = Harness::new("p4")?;
    let eid = "event:refdep:p4";
    let person = h.observe(
        "p4",
        "lane0",
        40,
        "power:alpha",
        MockSemanticLabel::PersonLike,
    )?;
    let d1 = evaluate_unknown_presence(EventId::parse(eid)?, vec![person])?;
    let _r1 = h.publish(&d1)??;
    let restored = h.observe(
        "p4",
        "lane0",
        241,
        "power:alpha",
        MockSemanticLabel::IntegrityRestored,
    )?;
    let candidate = evaluate_unknown_presence(EventId::parse(eid)?, vec![restored])?;
    let d2 = ReferencePolicyDecision {
        event: supersede(&d1.event, candidate.event)?,
        action: candidate.action,
    };
    let batches = h.dep.ledger().batches().len();
    let res = h.publish(&d2)?;
    assert!(
        matches!(
            res,
            Err(ReferenceError::Contract(ContractError::EvidenceRequired))
        ),
        "{res:?}"
    );
    assert_eq!(h.dep.ledger().batches().len(), batches);
    h.cleanup();
    Ok(())
}

/// Publishes a clean corroborated rev1, prepares its alert, optionally publishes a tamper
/// revision, then dispatches the rev1 plan. Returns the dispatch result and the provider's
/// message count.
fn dispatch_case(
    tag: &str,
    add_tamper: bool,
) -> Result<(Result<OperationReceipt, ReferenceError>, usize), Box<dyn Error>> {
    let mut h = Harness::new(tag)?;
    let eid = format!("event:refdep:{tag}");
    let alpha = h.observe(
        tag,
        "lane0",
        70,
        "power:alpha",
        MockSemanticLabel::PersonLike,
    )?;
    let beta = h.observe(
        tag,
        "lane1",
        71,
        "power:beta",
        MockSemanticLabel::PersonLike,
    )?;
    let d1 = evaluate_unknown_presence(EventId::parse(eid.as_str())?, vec![alpha, beta])?;
    let r1 = h.publish(&d1)??;
    let plan = h.prepare(&d1, &r1, tag)??;
    h.dep.effects_mut().prepare(
        plan.intent.clone(),
        plan.obligation_id.clone(),
        "provider delivery is independently reconciled",
        TimestampNs(3_000),
    )?;
    if add_tamper {
        let tamper = h.observe(
            tag,
            "lane2",
            72,
            "power:gamma",
            MockSemanticLabel::TamperLike,
        )?;
        let candidate = evaluate_unknown_presence(EventId::parse(eid.as_str())?, vec![tamper])?;
        let d2 = ReferencePolicyDecision {
            event: supersede(&d1.event, candidate.event)?,
            action: ReferencePolicyAction::Hold,
        };
        let r2 = h.publish(&d2)??;
        assert!(r2.lineage_tamper_status.has_open_tamper());
    }
    let res = h.dep.dispatch_alert(
        &plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(3_001),
        TimestampNs(3_002),
        &h.cx,
    );
    let sent = h.dep.alert_provider().message_count();
    h.cleanup();
    Ok((res, sent))
}

#[test]
fn a_stale_alert_plan_is_refused_after_a_tamper_revision() -> R {
    let (control, sent) = dispatch_case("p5c", false)?;
    match control {
        Ok(receipt) => assert_eq!(receipt.state, EffectState::AdapterAccepted),
        Err(error) => return Err(format!("the control plan must dispatch: {error:?}").into()),
    }
    assert_eq!(sent, 1);
    let (stale, sent) = dispatch_case("p5t", true)?;
    match stale {
        Err(ReferenceError::DurableEffect(boxed)) => assert!(
            matches!(
                *boxed,
                DurableEffectError::Reference(ReferenceError::StaleEventAuthority)
            ),
            "{boxed:?}"
        ),
        other => return Err(format!("expected a stale-authority refusal, got {other:?}").into()),
    }
    assert_eq!(sent, 0, "a refused dispatch never reaches the provider");
    Ok(())
}

#[test]
fn an_idempotent_retry_returns_the_identical_receipt_and_prepares() -> R {
    let mut h = Harness::new("p6")?;
    let eid = "event:refdep:p6";
    let person = h.observe(
        "p6",
        "lane0",
        79,
        "power:alpha",
        MockSemanticLabel::PersonLike,
    )?;
    let d1 = evaluate_unknown_presence(EventId::parse(eid)?, vec![person])?;
    let _r1 = h.publish(&d1)??;
    let alpha = h.observe(
        "p6",
        "lane0",
        80,
        "power:alpha",
        MockSemanticLabel::PersonLike,
    )?;
    let beta = h.observe(
        "p6",
        "lane1",
        81,
        "power:beta",
        MockSemanticLabel::PersonLike,
    )?;
    let candidate = evaluate_unknown_presence(EventId::parse(eid)?, vec![alpha, beta])?;
    let d2 = ReferencePolicyDecision {
        event: supersede(&d1.event, candidate.event)?,
        action: ReferencePolicyAction::PrepareAlert,
    };
    let r2 = h.publish(&d2)??;
    let batches = h.dep.ledger().batches().len();
    let retry = h.publish(&d2)??;
    assert_eq!(retry, r2);
    assert_eq!(r2.prior_revision_encodings.len(), 1);
    assert_eq!(r2.prior_revision_encodings[0], revision_encoding(&d1.event));
    assert_eq!(
        h.dep.ledger().batches().len(),
        batches,
        "a retry appends nothing"
    );
    let plan = h.prepare(&d2, &retry, "p6r")??;
    assert_eq!(
        plan.prior_revision_encodings,
        retry.prior_revision_encodings
    );
    h.cleanup();
    Ok(())
}
