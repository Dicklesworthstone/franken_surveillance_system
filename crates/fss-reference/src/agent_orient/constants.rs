#![forbid(unsafe_code)]
//! Registered capability IDs, stable claim/world/affordance identifiers, and orientation limits
//! for [`super`].

/// Capability registry row that admits a situation read (AOP-003, AOP-004, AOP-009).
pub const CAPABILITY_SITUATION_READ: &str = "CAP-AGENT-SITUATION-READ-001";
/// Capability registry row that admits an explanation (AOP-011).
pub const CAPABILITY_EXPLAIN: &str = "CAP-AGENT-EXPLAIN-001";
/// Capability registry row that admits a diagnosis (AOP-014).
pub const CAPABILITY_DOCTOR: &str = "CAP-REPAIR-PREPARE-001";
/// Capability registry row that admits plan preparation (AOP-007).
pub const CAPABILITY_PLAN_PREPARE: &str = "CAP-AGENT-PLAN-PREPARE-001";
/// Capability registry row that admits an effect commit (AOP-008).
pub const CAPABILITY_PLAN_COMMIT: &str = "CAP-AGENT-PLAN-COMMIT-001";
/// Capability every listed investigation-case affordance requires (the AOP-006 registry row).
pub const CAPABILITY_CASE_WRITE: &str = "CAP-AGENT-CASE-WRITE-001";
/// Registered coordination grant a work-claim affordance requires (never an effect grant).
pub const CAPABILITY_WORK_CLAIM: &str = "CAP-AGENT-WORK-CLAIM-001";
/// Prefix of the affordance a session-bound orientation lists for each open investigation case.
pub const AFFORDANCE_INVESTIGATE_PREFIX: &str = "affordance:investigate:";

/// Stable claim identity of the ledger-head cell: the registered anchor-position claim
/// (`anchor_position_restatement` of `meaningfulDeltaComparison`, architecture/agent_contracts.json)
/// whose statement and evidence restate the committed position and are not compared by follow.
pub const CLAIM_LEDGER_HEAD: &str = "claim:deployment:ledger-head";
/// Stable claim identity of the retained-import cell.
pub const CLAIM_IMPORTS: &str = "claim:deployment:imports";
/// Stable claim identity of the durable effect journal cell.
pub const CLAIM_EFFECT_JOURNAL: &str = "claim:deployment:effect-journal";
/// Stable claim identity of the site coverage cell.
pub const CLAIM_COVERAGE: &str = "claim:coverage:site";
/// Stable identity of the protected world that no retained evidence covers.
pub const WORLD_UNOBSERVED_ACTIVITY: &str = "world:site:unobserved-activity";
/// Affordance identity of re-orienting after the ledger head advances.
pub const AFFORDANCE_REORIENT: &str = "affordance:orient:reorient";
/// Affordance identity of the read-only deployment diagnosis.
pub const AFFORDANCE_DOCTOR: &str = "affordance:orient:doctor";
/// Affordance identity of the follow stream since this orientation's anchor (`fss follow`).
pub const AFFORDANCE_FOLLOW: &str = "affordance:orient:follow";
/// Affordance identity of the unexposed plan/commit path.
pub const AFFORDANCE_PLAN: &str = "affordance:orient:plan";
/// Affordance-identity prefix of one event explanation.
pub const AFFORDANCE_EXPLAIN_PREFIX: &str = "affordance:explain:";
/// Affordance-identity prefix of one unexposed effect reconciliation.
pub const AFFORDANCE_RECONCILE_PREFIX: &str = "affordance:reconcile:";
/// Prefix of the affordance a session-bound orientation lists for each disputed finding.
pub const AFFORDANCE_FINDING_PREFIX: &str = "affordance:finding:";
/// Prefix of the affordance a session-bound orientation lists for each non-terminal work claim.
pub const AFFORDANCE_CLAIM_PREFIX: &str = "affordance:claim:";
/// Prefix of the affordance a session-bound orientation lists for each active plan.
pub const AFFORDANCE_PLAN_PREFIX: &str = "affordance:plan:";
/// Stable claim identity of the published-event summary cell.
pub const CLAIM_EVENTS: &str = "claim:deployment:events";
/// World-identity prefix of one per-kind aggregate of per-event worlds.
pub const WORLD_EVENTS_PREFIX: &str = "world:events:";
/// The single protected world the pulse heartbeat folds every protected world into.
pub const WORLD_PROTECTED_SUMMARY: &str = "world:site:protected-worlds";
/// Source-omission class of per-event knowledge cells summarized out of a view.
pub const SOURCE_CLASS_EVENT_DETAIL: &str = "event_detail";
/// Source-omission class of per-event worlds represented by per-kind aggregates.
pub const SOURCE_CLASS_WORLD_DETAIL: &str = "protected_world_detail";
/// Largest complete retained-event catalogue admitted by the deployment reader and projection.
pub const MAX_DEPLOYMENT_EVENTS: usize = 4096;
/// Legacy per-event expansion profile. Its bytes and identities remain unchanged through 128
/// events; larger catalogues use an exact-anchor metadata inventory.
pub const DIRECT_EVENT_EXPANSION_LIMIT: usize = 128;
/// Data classes an orientation reads (every other class is outside its projection).
pub const ORIENT_DATA_CLASSES: [&str; 4] = [
    "authority-ledger",
    "effect-journal",
    "event-revisions",
    "deployment-layout",
];
/// Degradation every orientation not bound to a durable session carries.
pub const UNBOUND_SESSION_DEGRADATION: &str = "No durable agent session is bound: this capsule \
    carries a deterministic read-only session identity and persists nothing (`fss session open` \
    opens a durable one).";
