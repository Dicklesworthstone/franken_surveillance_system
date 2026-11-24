#![forbid(unsafe_code)]
//! Attention frontier, epistemic debt, listed affordances, objective contract, and validity
//! builders for [`super`].

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, CanonicalEncode, ContentDigest, ContractError,
    EventState, ObjectiveContract, ObjectiveContractParams, ObjectiveScope, OperationReceipt,
    SituationCapsule,
};

use super::coverage::{CoverageAssessment, ZoneCoverageState};
use super::events::PlannedEvent;
use super::mission;
use super::types::{
    AFFORDANCE_CLAIM_PREFIX, AFFORDANCE_DOCTOR, AFFORDANCE_EXPLAIN_PREFIX,
    AFFORDANCE_FINDING_PREFIX, AFFORDANCE_FOLLOW, AFFORDANCE_INVESTIGATE_PREFIX, AFFORDANCE_PLAN,
    AFFORDANCE_PLAN_PREFIX, AFFORDANCE_RECONCILE_PREFIX, AFFORDANCE_REORIENT, AttentionItem,
    CAPABILITY_CASE_WRITE, CAPABILITY_DOCTOR, CAPABILITY_EXPLAIN, CAPABILITY_PLAN_COMMIT,
    CAPABILITY_PLAN_PREPARE, CAPABILITY_SITUATION_READ, CAPABILITY_WORK_CLAIM, DeploymentSnapshot,
    EpistemicDebtItem, ORIENT_DATA_CLASSES, OrientCaseBrief, OrientClaimBrief, OrientFindingBrief,
    OrientPlanBrief, OrientRequest, OrientSessionBinding, OrientValidity, RetainedEvent, digest_of,
    obligation_state_str, plural, read_cost,
};

/// One listed (never executed) affordance of the orientation frontier.
pub(super) struct ListedAffordance<'a> {
    pub(super) affordance_id: String,
    pub(super) operation: &'a str,
    pub(super) target: String,
    pub(super) rationale: String,
    pub(super) class: AffordanceClass,
    pub(super) supported_worlds: BTreeSet<String>,
    pub(super) required_capability: &'a str,
    pub(super) cost: BudgetVector,
}

impl ListedAffordance<'_> {
    pub(super) fn build(self) -> ActionAffordance {
        ActionAffordance {
            affordance_id: self.affordance_id,
            operation: self.operation.to_owned(),
            target: self.target,
            rationale: self.rationale,
            class: self.class,
            supported_worlds: self.supported_worlds,
            unsafe_worlds: BTreeSet::new(),
            required_capabilities: BTreeSet::from([self.required_capability.to_owned()]),
            cost: self.cost,
            reversible: true,
            branch_predicate: None,
        }
    }
}

/// Listed (never executed) explanation of one event.
pub(super) fn explain_affordance(
    retained: &RetainedEvent,
    supported_worlds: BTreeSet<String>,
    cost: BudgetVector,
) -> ActionAffordance {
    let event = retained.event.event_id.as_str();
    ListedAffordance {
        affordance_id: format!("{AFFORDANCE_EXPLAIN_PREFIX}{event}"),
        operation: "explain",
        target: format!("fss://event/{event}"),
        rationale: "Explain this event (`fss explain`).".to_owned(),
        class: AffordanceClass::Probe,
        supported_worlds,
        required_capability: CAPABILITY_EXPLAIN,
        cost,
    }
    .build()
}

/// Ranked attention frontier: open obligations and indeterminate effects, the coverage gap, and
/// the highest-consequence unresolved event.
pub(super) fn attention_frontier(
    snapshot: &DeploymentSnapshot,
    planned: &[PlannedEvent<'_>],
    deployment_handle: &str,
    coverage: Option<&CoverageAssessment>,
) -> Vec<AttentionItem> {
    let mut items = Vec::new();
    for operation in snapshot.indeterminate_operations() {
        let id = operation.intent.operation_id.as_str();
        items.push(AttentionItem {
            item_id: format!("attention:effect:{id}"),
            kind: "indeterminate_effect",
            priority_class: "critical",
            mission_relevance: 1.0,
            decision_impact: 5.0,
            reason: format!("Operation {id} may have occurred; reconcile before any resend."),
            handle: format!("fss://operation/{id}"),
        });
    }
    for obligation in snapshot.open_obligations() {
        let id = obligation.obligation_id.as_str();
        items.push(AttentionItem {
            item_id: format!("attention:obligation:{id}"),
            kind: "obligation",
            priority_class: "critical",
            mission_relevance: 1.0,
            decision_impact: 5.0,
            reason: format!(
                "Obligation {id} is {}.",
                obligation_state_str(obligation.state)
            ),
            handle: format!("fss://obligation/{id}"),
        });
    }
    if let Some(top) = planned.first() {
        let severity = top.section.protected_severity();
        items.push(AttentionItem {
            item_id: format!("attention:event:{}", top.id()),
            kind: "event",
            priority_class: if top.retained.tamper.has_open_tamper() {
                "critical"
            } else if severity >= 4 {
                "high"
            } else {
                "normal"
            },
            mission_relevance: 1.0,
            decision_impact: f64::from(severity),
            reason: format!(
                "Highest-consequence published event: state {}, physical presence {}, {}.",
                top.retained.event.state.as_str(),
                top.section.physical_state.as_str(),
                if top.retained.corroborated() {
                    "corroborated"
                } else {
                    "not corroborated"
                }
            ),
            handle: format!("fss://event/{}", top.id()),
        });
    }
    let reason = match coverage {
        None => Some("No CoverageWitness is retained; absence cannot be certified.".to_owned()),
        Some(assessment) if !assessment.complete() => {
            let gaps: Vec<String> = assessment
                .zones
                .iter()
                .filter(|zone| zone.state != ZoneCoverageState::Covered)
                .map(|zone| format!("{} is {}", zone.label(), zone.state.as_str()))
                .collect();
            if gaps.len() > 3 {
                Some(format!(
                    "Absence cannot be certified: {} of {} zones uncovered ({}; +{} more).",
                    gaps.len(),
                    assessment.zones.len(),
                    gaps[..2].join("; "),
                    gaps.len() - 2
                ))
            } else {
                Some(format!("Absence cannot be certified: {}.", gaps.join("; ")))
            }
        }
        Some(_) => None,
    };
    if let Some(reason) = reason {
        items.push(AttentionItem {
            item_id: "attention:coverage:site".to_owned(),
            kind: "coverage_gap",
            priority_class: "high",
            mission_relevance: 1.0,
            decision_impact: 4.0,
            reason,
            handle: format!("{deployment_handle}/coverage"),
        });
    }
    // The schema bounds the frontier; everything past the head stays in obligations and
    // indeterminateEffects, which are never truncated.
    items.truncate(128);
    items
}

/// Assumptions this orientation rests on.
pub(super) fn epistemic_debt(
    snapshot: &DeploymentSnapshot,
    planned: &[PlannedEvent<'_>],
    coverage: Option<&CoverageAssessment>,
) -> Vec<EpistemicDebtItem> {
    let mut debt = vec![EpistemicDebtItem {
        debt_id: "debt:coverage:uncertified".to_owned(),
        assumption: "Absence is never inferred: every interval without a CoverageWitness is \
                     treated as unobserved."
            .to_owned(),
        deferred_reason: match coverage {
            None => "No producer in this deployment retains CoverageWitness records.".to_owned(),
            Some(assessment) => format!(
                "{} retained coverage record(s) certify only their declared zones, windows and \
                 pipeline generations; everything else stays unobserved.",
                assessment.record_count
            ),
        },
        dependent_decisions: vec!["any absence or all-clear conclusion".to_owned()],
        consequence_if_wrong: "Treating unobserved time as clear would hide real activity."
            .to_owned(),
        cheapest_test: "Retain a continuous CoverageWitness over the zone and re-orient."
            .to_owned(),
        review_trigger: "A coverage witness is committed to the ledger.".to_owned(),
    }];
    let uncorroborated = planned
        .iter()
        .filter(|event| !event.retained.corroborated())
        .count();
    if uncorroborated > 0 {
        debt.push(EpistemicDebtItem {
            debt_id: "debt:events:failure-domain-independence".to_owned(),
            assumption: "Failure domains are independent only when their names differ.".to_owned(),
            deferred_reason: "No shared-failure-domain registry is retained.".to_owned(),
            dependent_decisions: vec![format!(
                "corroboration of {}",
                plural(uncorroborated, "published event", "published events")
            )],
            consequence_if_wrong:
                "Two sources sharing an unnamed failure could be miscounted as corroboration."
                    .to_owned(),
            cheapest_test: "Register each contributing sensor's failure domains.".to_owned(),
            review_trigger: "Supporting evidence from a second failure domain is committed."
                .to_owned(),
        });
    }
    if snapshot.ledger_tail_uncommitted || snapshot.effect_tail_uncommitted {
        debt.push(EpistemicDebtItem {
            debt_id: "debt:journal:uncommitted-tail".to_owned(),
            assumption: "Only the committed journal prefix is authority; tail bytes are ignored."
                .to_owned(),
            deferred_reason: "orient is read-only and never repairs a journal.".to_owned(),
            dependent_decisions: vec!["every conclusion of this orientation".to_owned()],
            consequence_if_wrong: "A torn tail could hide a committed record.".to_owned(),
            cheapest_test: "Run `fss doctor --json --root <dir>`.".to_owned(),
            review_trigger: "The doctor verdict changes.".to_owned(),
        });
    }
    debt
}

/// The probe-class affordance listing one open investigation case.
fn case_affordance(case: &OrientCaseBrief) -> Result<ActionAffordance, ContractError> {
    let rationale = if case.rebase_required {
        format!(
            "Case {} ({}, revision {}) was opened at an earlier anchor: rebase it before any \
             change (`fss investigate --transition rebase`).",
            case.case_id, case.state, case.revision
        )
    } else if case.live_hypotheses.is_empty() {
        format!(
            "Case {} ({}, revision {}) has no live hypothesis: conclude it against a declared \
             stop rule or record why it stays open.",
            case.case_id, case.state, case.revision
        )
    } else {
        let mut live = case.live_hypotheses.clone();
        let shown = live.len().min(8);
        let more = live.len() - shown;
        live.truncate(shown);
        format!(
            "Case {} ({}, revision {}) still discriminates {} live hypotheses ({}{}): cite \
             evidence, assess, or conclude (`fss investigate`).",
            case.case_id,
            case.state,
            case.revision,
            case.live_hypotheses.len(),
            live.join(", "),
            if more > 0 {
                format!(", +{more} more")
            } else {
                String::new()
            }
        )
    };
    Ok(ListedAffordance {
        affordance_id: format!("{AFFORDANCE_INVESTIGATE_PREFIX}{}", case.case_id),
        operation: "investigate",
        target: format!("fss://case/{}", case.case_id),
        rationale,
        class: AffordanceClass::Probe,
        supported_worlds: BTreeSet::new(),
        required_capability: CAPABILITY_CASE_WRITE,
        cost: read_cost(0, 0)?,
    }
    .build())
}

/// The probe listing one active finding under explicit disagreement: the conflict stays visible
/// (never ranked away) until a supersession or withdrawal ends it.
fn finding_affordance(finding: &OrientFindingBrief) -> Result<ActionAffordance, ContractError> {
    Ok(ListedAffordance {
        affordance_id: format!("{AFFORDANCE_FINDING_PREFIX}{}", finding.finding_id),
        operation: "investigate",
        target: format!("fss://case/{}", finding.case_id),
        rationale: format!(
            "Finding {} on case {} is disputed by {}: discriminate with evidence (`fss \
             investigate --transition cite|assess`), then supersede or withdraw the finding that \
             does not hold (`--transition finding --supersedes` or `finding-withdraw`).",
            finding.finding_id,
            finding.case_id,
            finding.disputed_by.join(", ")
        ),
        class: AffordanceClass::Probe,
        supported_worlds: BTreeSet::new(),
        required_capability: CAPABILITY_CASE_WRITE,
        cost: read_cost(0, 0)?,
    }
    .build())
}

/// The affordance listing one non-terminal work claim: the holder's next coordination step, an
/// explicit expire/reclaim once the lease lapsed, or a blocked entry for work another session
/// holds (so the same work is never duplicated).
fn claim_affordance(claim: &OrientClaimBrief) -> Result<ActionAffordance, ContractError> {
    let (rationale, class) = if !claim.lease_live {
        (
            format!(
                "Claim {} on case {} ({}) lapsed at {} ns on the evidence clock: record its \
                 expiry or reclaim it (`fss investigate --transition claim-expire|claim-reclaim`).",
                claim.claim_id, claim.case_id, claim.state, claim.expires_at.0
            ),
            AffordanceClass::Probe,
        )
    } else if claim.held_here {
        (
            format!(
                "This session holds claim {} on case {} ({}) until {} ns: activate, record \
                 progress, complete, renew, or release it (`fss investigate --transition \
                 claim-...`). It coordinates cognition only and confers no effect authority.",
                claim.claim_id, claim.case_id, claim.state, claim.expires_at.0
            ),
            AffordanceClass::Probe,
        )
    } else {
        (
            format!(
                "Session {} holds claim {} on case {} ({}) until {} ns: do not duplicate this \
                 work; a transfer comes only from its holder.",
                claim.owner_session, claim.claim_id, claim.case_id, claim.state, claim.expires_at.0
            ),
            AffordanceClass::Blocked,
        )
    };
    Ok(ListedAffordance {
        affordance_id: format!("{AFFORDANCE_CLAIM_PREFIX}{}", claim.claim_id),
        operation: "investigate",
        target: format!("fss://case/{}", claim.case_id),
        rationale,
        class,
        supported_worlds: BTreeSet::new(),
        required_capability: CAPABILITY_WORK_CLAIM,
        cost: read_cost(0, 0)?,
    }
    .build())
}

/// The affordance listing one active plan: the exact owner step it awaits (blocked), or, once
/// its operation is terminal, the agent's own close (`plan --close`, a probe).
fn plan_affordance(plan: &OrientPlanBrief) -> Result<ActionAffordance, ContractError> {
    let (operation, rationale) = match plan.state.as_deref() {
        None => (
            "plan",
            format!(
                "Plan {} is compiled but not prepared: it awaits the operator's exact plan \
                 approval (`fss plan ... --approve <plan approval>`), or withdraw it (`fss plan \
                 --close {}`).",
                plan.plan_id, plan.plan_id
            ),
        ),
        Some("prepared") => (
            "commit",
            format!(
                "Plan {} prepared {}: it awaits the operator's exact dispatch approval (`fss \
                 commit --plan {} --approve <dispatch approval>`); `fss cancel` retires it.",
                plan.plan_id, plan.operation_id, plan.plan_id
            ),
        ),
        Some(state @ ("verified" | "failed" | "cancelled")) => {
            // Terminal but not closed: the next move is the agent's own, a cognition write.
            return Ok(ListedAffordance {
                affordance_id: format!("{AFFORDANCE_PLAN_PREFIX}{}", plan.plan_id),
                operation: "plan",
                target: format!("fss://plan/{}", plan.plan_id),
                rationale: format!(
                    "Plan {}'s operation {} is {state}: close the plan by recording its \
                     immutable execution episode (`fss plan --close {}`).",
                    plan.plan_id, plan.operation_id, plan.plan_id
                ),
                class: AffordanceClass::Probe,
                supported_worlds: BTreeSet::new(),
                required_capability: CAPABILITY_PLAN_PREPARE,
                cost: read_cost(0, 0)?,
            }
            .build());
        }
        Some(state) => (
            "commit",
            format!(
                "Plan {}'s operation {} is {state}: its obligation stays open until the owner \
                 reconciles it (`fss commit --reconcile ...`); never resend.",
                plan.plan_id, plan.operation_id
            ),
        ),
    };
    Ok(ListedAffordance {
        affordance_id: format!("{AFFORDANCE_PLAN_PREFIX}{}", plan.plan_id),
        operation,
        target: format!("fss://plan/{}", plan.plan_id),
        rationale,
        class: AffordanceClass::Blocked,
        supported_worlds: BTreeSet::new(),
        required_capability: CAPABILITY_PLAN_COMMIT,
        cost: read_cost(0, 0)?,
    }
    .build())
}

/// Inputs for assembling the sorted affordance frontier of one compiled capsule.
pub(super) struct AffordanceAssembly<'a> {
    pub(super) heartbeat: bool,
    pub(super) deployment_handle: &'a str,
    pub(super) deployment_read: BudgetVector,
    pub(super) all_worlds: BTreeSet<String>,
    pub(super) planned: &'a [PlannedEvent<'a>],
    pub(super) memberships: &'a BTreeMap<String, BTreeSet<String>>,
    pub(super) cases: &'a [OrientCaseBrief],
    pub(super) plans: &'a [OrientPlanBrief],
    pub(super) claims: &'a [OrientClaimBrief],
    pub(super) findings: &'a [OrientFindingBrief],
    pub(super) indeterminate: &'a [&'a OperationReceipt],
    pub(super) supervision_affordances: Vec<ActionAffordance>,
}

/// Sorted affordances, actionable next-affordance IDs, and optional heartbeat degradation note.
pub(super) type CapsuleAffordances = (Vec<ActionAffordance>, Vec<String>, Option<String>);

/// Builds the sorted affordance list, actionable next-affordance IDs, and any heartbeat degradation.
pub(super) fn build_capsule_affordances(
    input: AffordanceAssembly<'_>,
) -> Result<CapsuleAffordances, ContractError> {
    let mut affordances = vec![
        ListedAffordance {
            affordance_id: AFFORDANCE_REORIENT.to_owned(),
            operation: "session.orient",
            target: input.deployment_handle.to_owned(),
            rationale: if input.heartbeat {
                "Re-orient when ledger advances.".to_owned()
            } else {
                "Re-orient once the ledger head advances past this capsule's anchor.".to_owned()
            },
            class: AffordanceClass::Wait,
            supported_worlds: input.all_worlds.clone(),
            required_capability: CAPABILITY_SITUATION_READ,
            cost: input.deployment_read,
        }
        .build(),
    ];
    let heartbeat_degradation = if input.heartbeat {
        Some(
            if input.supervision_affordances.is_empty() {
                "The pulse view lists only the re-orient heartbeat affordance; `--view brief` lists the complete affordance frontier."
            } else {
                "The pulse view preserves the re-orient heartbeat and durable-work recovery; `--view brief` lists the complete affordance frontier."
            }
            .to_owned(),
        )
    } else {
        for (rank, event) in input.planned.iter().enumerate() {
            if !event.inline && rank > 0 {
                continue;
            }
            affordances.push(explain_affordance(
                event.retained,
                input
                    .memberships
                    .get(event.id())
                    .cloned()
                    .unwrap_or_default(),
                input.deployment_read,
            ));
        }
        affordances.push(
            ListedAffordance {
                affordance_id: AFFORDANCE_DOCTOR.to_owned(),
                operation: "doctor",
                target: format!("{}/doctor", input.deployment_handle),
                rationale: "Diagnose the root read-only (`fss doctor`).".to_owned(),
                class: AffordanceClass::Probe,
                supported_worlds: BTreeSet::new(),
                required_capability: CAPABILITY_DOCTOR,
                cost: input.deployment_read,
            }
            .build(),
        );
        affordances.push(
            ListedAffordance {
                affordance_id: AFFORDANCE_FOLLOW.to_owned(),
                operation: "session.follow",
                // Anchor-invariant (`affordance_cost_repricing` compares targets): the anchor followed from is
                // this capsule's own, named by its anchor token in the answer's proof pointers
                // and by the affordance's basis anchor.
                target: format!("{}/follow", input.deployment_handle),
                rationale: "Follow deltas since this capsule's anchor (its anchor token is the answer's `anchor:` proof pointer)."
                    .to_owned(),
                class: AffordanceClass::Wait,
                supported_worlds: input.all_worlds.clone(),
                required_capability: CAPABILITY_SITUATION_READ,
                cost: input.deployment_read,
            }
            .build(),
        );
        affordances.push(orient_plan_affordance(&input)?);
        for case in input.cases {
            affordances.push(case_affordance(case)?);
        }
        for plan in input.plans {
            affordances.push(plan_affordance(plan)?);
        }
        for claim in input.claims {
            affordances.push(claim_affordance(claim)?);
        }
        for finding in input
            .findings
            .iter()
            .filter(|finding| !finding.disputed_by.is_empty())
        {
            affordances.push(finding_affordance(finding)?);
        }
        None
    };
    for operation in input.indeterminate {
        affordances.push(
            ListedAffordance {
                affordance_id: format!(
                    "{AFFORDANCE_RECONCILE_PREFIX}{}",
                    operation.intent.operation_id
                ),
                operation: "commit",
                target: format!("fss://operation/{}", operation.intent.operation_id),
                rationale: "Never resend. Only the owner can reconcile this operation, by \
                            attesting delivery or non-delivery with evidence: `fss commit \
                            --reconcile delivered|not_delivered --operation <id> --evidence \
                            <sha256> --statement <text>`, previewed then exactly approved."
                    .to_owned(),
                class: AffordanceClass::Blocked,
                supported_worlds: BTreeSet::new(),
                required_capability: CAPABILITY_PLAN_COMMIT,
                cost: read_cost(0, 0)?,
            }
            .build(),
        );
    }
    affordances.extend(input.supervision_affordances);
    affordances.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
    let next: Vec<String> = affordances
        .iter()
        .filter(|candidate| {
            !matches!(
                candidate.class,
                AffordanceClass::Blocked | AffordanceClass::Unavailable
            )
        })
        .map(|candidate| candidate.affordance_id.clone())
        .collect();
    Ok((affordances, next, heartbeat_degradation))
}

/// Dynamically classifies `affordance:orient:plan` against the exact retained events,
/// corroboration/tamper eligibility (`verify_event_alert_eligibility`), and world envelope.
///
/// - Empty deployment: preserves [`AffordanceClass::Unavailable`].
/// - Corroborated, alert-eligible event(s) with >= 2 independent supporting failure domains and no
///   open tamper: exposes [`AffordanceClass::Robust`] when all worlds agree with no open
///   contradictions, tamper, indeterminate operations, or uncorroborated active events; otherwise
///   [`AffordanceClass::Conditional`] with explicit supported/unsafe worlds and branch predicate.
///   Planning remains cognition-only and never grants effect authority without owner approval.
/// - Single-camera, shared-failure-domain, uncorroborated, or tampered events only: classifies
///   honestly as [`AffordanceClass::Blocked`] explaining what evidence is missing.
fn orient_plan_affordance(
    input: &AffordanceAssembly<'_>,
) -> Result<ActionAffordance, ContractError> {
    if input.planned.is_empty() {
        return Ok(ListedAffordance {
            affordance_id: AFFORDANCE_PLAN.to_owned(),
            operation: "plan",
            target: input.deployment_handle.to_owned(),
            rationale: "Not exposed; no policy grants effect authority.".to_owned(),
            class: AffordanceClass::Unavailable,
            supported_worlds: BTreeSet::new(),
            required_capability: CAPABILITY_PLAN_PREPARE,
            cost: read_cost(0, 0)?,
        }
        .build());
    }

    let mut eligible: Vec<&PlannedEvent<'_>> = Vec::new();
    let mut tampered_corroborated: Vec<&str> = Vec::new();
    for event in input.planned {
        let retained = event.retained;
        let supporting_domains: BTreeSet<&str> = retained
            .event
            .evidence
            .iter()
            .filter(|edge| edge.counts_as_support() && !edge.failure_domain.is_empty())
            .map(|edge| edge.failure_domain.as_str())
            .collect();
        let eligibility_ok = crate::alert::verify_event_alert_eligibility(
            retained.event.state,
            crate::policy::ReferencePolicyAction::PrepareAlert,
            &retained.event.evidence,
        )
        .is_ok();
        if retained.event.state == EventState::Corroborated
            && eligibility_ok
            && !retained.tamper.has_open_tamper()
            && supporting_domains.len() >= 2
        {
            eligible.push(event);
        } else if retained.event.state == EventState::Corroborated
            && (retained.tamper.has_open_tamper() || !eligibility_ok)
        {
            tampered_corroborated.push(event.id());
        }
    }

    if let Some(primary) = eligible.first() {
        if !input.indeterminate.is_empty() {
            return Ok(ActionAffordance {
                affordance_id: AFFORDANCE_PLAN.to_owned(),
                operation: "plan".to_owned(),
                target: input.deployment_handle.to_owned(),
                rationale: "Blocked: reconcile indeterminate operation first.".to_owned(),
                class: AffordanceClass::Blocked,
                supported_worlds: BTreeSet::new(),
                unsafe_worlds: BTreeSet::new(),
                required_capabilities: BTreeSet::from([CAPABILITY_PLAN_PREPARE.to_owned()]),
                cost: read_cost(0, 0)?,
                reversible: true,
                branch_predicate: None,
            });
        }
        let shown: Vec<&str> = eligible.iter().take(8).map(|event| event.id()).collect();
        let more = eligible.len().saturating_sub(shown.len());
        let id_list = if more > 0 {
            format!("{}, +{more} more", shown.join(", "))
        } else {
            shown.join(", ")
        };
        let has_contradiction = input.planned.iter().any(|event| event.section.contradicted);
        let has_open_tamper = input
            .planned
            .iter()
            .any(|event| event.retained.tamper.has_open_tamper());
        let has_uncorroborated_active = input.planned.iter().any(|event| {
            !event.retained.corroborated()
                && !matches!(
                    event.retained.event.state,
                    EventState::Rejected | EventState::Resolved
                )
        });
        let all_worlds_clean = !has_contradiction && !has_open_tamper && !has_uncorroborated_active;

        let (class, supported_worlds, unsafe_worlds, branch_predicate) = if all_worlds_clean {
            (
                AffordanceClass::Robust,
                input.all_worlds.clone(),
                BTreeSet::new(),
                None,
            )
        } else {
            let mut unsafe_worlds = BTreeSet::new();
            for candidate in [
                "world:events:common-mode-error",
                "world:events:sensor-tamper",
                "world:events:artifact-live",
            ] {
                if input.all_worlds.contains(candidate) {
                    unsafe_worlds.insert(candidate.to_owned());
                }
            }
            let mut supported_worlds: BTreeSet<String> = input
                .memberships
                .get(primary.id())
                .into_iter()
                .flat_map(|worlds| worlds.iter())
                .filter(|world| {
                    input.all_worlds.contains(*world) && !unsafe_worlds.contains(*world)
                })
                .cloned()
                .collect();
            if input.all_worlds.contains("world:events:present")
                && !unsafe_worlds.contains("world:events:present")
            {
                supported_worlds.insert("world:events:present".to_owned());
            }
            let predicate = format!(
                "explicit_owner_approval_required;verify_no_contradiction_or_tamper_for:[{}]",
                shown.join(",")
            );
            (
                AffordanceClass::Conditional,
                supported_worlds,
                unsafe_worlds,
                Some(predicate),
            )
        };

        return Ok(ActionAffordance {
            affordance_id: AFFORDANCE_PLAN.to_owned(),
            operation: "plan".to_owned(),
            target: format!("fss://event/{}", primary.id()),
            rationale: format!(
                "Prepare alert plan for [{id_list}] (cognition-only; never grants effect authority; approval required)."
            ),
            class,
            supported_worlds,
            unsafe_worlds,
            required_capabilities: BTreeSet::from([CAPABILITY_PLAN_PREPARE.to_owned()]),
            cost: input.deployment_read,
            reversible: true,
            branch_predicate,
        });
    }

    let rationale = if !tampered_corroborated.is_empty() {
        "Blocked: open tamper; resolve integrity.".to_owned()
    } else {
        "Blocked: needs independent corroboration.".to_owned()
    };
    Ok(ActionAffordance {
        affordance_id: AFFORDANCE_PLAN.to_owned(),
        operation: "plan".to_owned(),
        target: input.deployment_handle.to_owned(),
        rationale,
        class: AffordanceClass::Blocked,
        supported_worlds: BTreeSet::new(),
        unsafe_worlds: BTreeSet::new(),
        required_capabilities: BTreeSet::from([CAPABILITY_PLAN_PREPARE.to_owned()]),
        cost: read_cost(0, 0)?,
        reversible: true,
        branch_predicate: None,
    })
}

/// The admitted mission outcome, or the read-only query objective for an unbound request.
pub(super) fn orientation_objective(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    capsule: &SituationCapsule,
    request_digest: ContentDigest,
    requested: BudgetVector,
    coverage: Option<&CoverageAssessment>,
    session: Option<&OrientSessionBinding>,
) -> Result<ObjectiveContract, ContractError> {
    let anchor = &capsule.anchor;
    let mut zones: Vec<String> = snapshot
        .events
        .iter()
        .flat_map(|retained| retained.event.zone_ids.iter().cloned())
        .chain(
            coverage
                .into_iter()
                .flat_map(|assessment| assessment.zones.iter().map(|zone| zone.zone_id.clone())),
        )
        .collect();
    zones.sort();
    zones.dedup();
    let decision = digest_of("fss.reference_orient_objective.v1", |encoder| {
        encoder.digest(request_digest);
        anchor.encode_canonical(encoder);
        encoder.text(request.view.id());
        if let Some(mission) = session.and_then(|binding| binding.mission.as_ref()) {
            encoder.digest(mission.record_digest);
        }
        if let Some(progress) = session.and_then(|binding| binding.mission_progress.as_ref()) {
            encoder.digest(progress.revision.digest());
            encoder.bool(progress.current);
        }
    });
    mission::objective(
        ObjectiveContractParams {
            objective_id: capsule.frame.objective_id.clone(),
            source_principal: request.principal.as_str().to_owned(),
            source_request_digest: request_digest.to_text(),
            desired_outcome: format!(
                "A read-only {} orientation of deployment {} pinned to commit {}.",
                request.view.name(),
                snapshot.site_lineage,
                anchor.commit_sequence
            ),
            success_predicates: vec![
                "Every protected world is inline or hydratable through a receipted handle."
                    .to_owned(),
                "The context pack is admitted within the view's registered token budget."
                    .to_owned(),
            ],
            failure_predicates: vec![
                "The critical context does not fit the admitted budget \
             (ERR-AGENT-CONTEXT-INCOMPLETE-001)."
                    .to_owned(),
            ],
            stop_conditions: vec!["The committed ledger prefix has been read once.".to_owned()],
            hard_constraints: vec![
                if session.is_some() {
                    "Situation compilation does not create, write, or repair deployment files. The enclosing session operation may hold a temporary journal lock."
                } else {
                    "Read-only: nothing under the root is created, written, locked, or repaired."
                }
                .to_owned(),
                "No listed affordance is executed.".to_owned(),
            ],
            soft_preferences: Vec::new(),
            scope: ObjectiveScope {
                deployments: vec![snapshot.site_lineage.clone()],
                zones,
                subjects: Vec::new(),
                devices: Vec::new(),
                time_intervals: Vec::new(),
                data_classes: ORIENT_DATA_CLASSES
                    .iter()
                    .map(|&class| class.to_owned())
                    .collect(),
            },
            budgets: requested,
            allowed_actions: vec!["session.orient".to_owned()],
            required_approvals: Vec::new(),
            terminal_proof: vec![format!("fss://proof/{}", snapshot.ledger_root)],
            decision_digest: decision.to_text(),
        },
        session,
    )
}

pub(super) fn orientation_validity(snapshot: &DeploymentSnapshot) -> OrientValidity {
    OrientValidity {
        valid_until: snapshot.latest_evidence_time,
        invalidators: vec![
            format!(
                "The authority ledger commits past sequence {}.",
                snapshot.anchor.commit_sequence
            ),
            format!(
                "The durable effect journal changes from {}.",
                snapshot.effect_journal_digest
            ),
            "A schema, policy, privacy, or adapter-registry epoch changes.".to_owned(),
        ],
        reanchor_required_on: vec![
            "ledger_head_advance".to_owned(),
            "effect_journal_change".to_owned(),
            "epoch_change".to_owned(),
        ],
    }
}
