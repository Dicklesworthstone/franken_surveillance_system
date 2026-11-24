#![forbid(unsafe_code)]
//! Read-only deployment orientation (AOP-003 `session.orient`) and event explanation
//! (AOP-011 `explain`) over an existing reference deployment root.
//!
//! [`read_deployment`] never writes, creates, locks, truncates, renames, fsyncs, or repairs
//! anything under the root. It classifies the root with the read-only [`crate::doctor`], parses
//! `LAYOUT` with a bound, replays the committed authority ledger prefix through
//! [`fss_ledger::inspect_durable`], reads the durable effect journal once with a bound and replays
//! its committed records, and reads each published event revision back from the object spool
//! through [`fss_publication::read_verified`], which rehashes every payload.
//!
//! Both journals are append-only, so [`DeploymentHistory::snapshot_at`] also compiles the snapshot
//! of any earlier committed [`HistoryPosition`] (an "as of anchor" read) from the records inside
//! that position alone; [`read_deployment`] is the snapshot at the head. `session.follow`
//! ([`crate::agent_follow`]) compares the orientation at an earlier position with the head's.
//!
//! [`orient_deployment`] compiles one anchor-pinned [`SituationCapsule`] from that snapshot and
//! projects it through the same [`project_reference_situation`] selector every reference
//! publication uses, so the resource state, categorized control envelope, bounded context pack,
//! and semantic compression receipt are the verified reference sections. Nothing is invented:
//! an empty deployment yields `not_observable`/`unknown` cells and no event facts, and a published
//! watch candidate stays exactly as indeterminate, single-sensor, and uncorroborated as its
//! committed revision says. Affordances are listed with their operation, class, capability, and
//! cost; none is ever executed here.
//!
//! Views scale by compact encoding, never by truncation: events are ranked by consequence, a view
//! carries the per-event cells of its top-ranked events (and of every contradicted or tampered
//! event) inline and summarizes the rest in [`CLAIM_EVENTS`], and every per-event world is
//! aggregated into one world per kind that keeps the kind's maximum severity and protection
//! (pulse folds them further into [`WORLD_PROTECTED_SUMMARY`]). Through 128 events, each event
//! keeps its original stable, priced H1 expansion slot. Larger bounded catalogues retain direct
//! slots for inline and headline events and one exact-anchor, paginated metadata-query expansion
//! for every event identity and H0 proof root. That inventory is not source or H1 hydration;
//! subsequent explanations must still match its basis anchor.
//!
//! Every output is a pure function of the committed bytes: the capsule time is the latest
//! committed evidence time, not the wall clock, so the same root yields identical output.
//!
//! Coverage comes only from retained `coverage_witness` records ([`coverage`]): each objective
//! zone is `covered`, `not_observable`, or `stale`, and the capsule is `complete` only when every
//! objective zone is covered over its declared window. Without any retained record the site stays
//! `not_observable` and the capsule `partial`, exactly as before.

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[cfg(test)]
use fss_core::AgentView;
use fss_core::{
    ActionAffordance, AffordanceClass, CanonicalEncode, ContentDigest, ContractError,
    KnowledgeCell, KnowledgeCellParams, KnowledgeState, LedgerAnchor, MissionId, ObjectiveContract,
    ObjectiveContractParams, PrincipalId, ProvenanceClass, SessionId, TimestampNs,
};

use crate::agent_session::checkpoint::journal::supervision::SupervisionInventoryEntry;
use crate::deployment_session::trauma_guard::AntiPatternWarning;
#[cfg(test)]
use crate::doctor::DoctorVerdict;

mod capsule;
mod constants;
pub mod coverage;
mod coverage_cells;
mod events;
mod explain;
mod frontier;
pub mod historical_health;
mod io_budget;
mod learning;
pub mod liveness;
mod mission;
mod project;
pub mod projection_bridge;
mod pulse_rollup;
mod reader;
mod snapshot;
mod supervision;
mod trauma_guard;
mod types;

#[cfg(test)]
use capsule::compile_capsule;
pub use coverage::{
    CoverageAssessment, CoverageHealthConflict, MAX_COVERAGE_CAPSULE_READS,
    RECORDED_COVERAGE_PROVENANCE, RetainedCoverage, RetainedSourceCoverage,
    SOURCE_COVERAGE_PROVENANCE, ZoneAssessment, ZoneCoverageState,
};
#[cfg(test)]
use coverage_cells::zone_coverage_cell;
#[cfg(test)]
use events::planned_events;
pub use explain::{explain_event, explain_event_with_question};
use frontier::ListedAffordance;
pub use historical_health::{
    CLAIM_HISTORICAL_HEALTH_PREFIX, HistoricalHealthDeletion, HistoricalHealthMetadata,
    MAX_HISTORICAL_HEALTH_METADATA_BYTES, MAX_HISTORICAL_HEALTH_READS_PER_RECORD,
    MAX_HISTORICAL_HEALTH_RECORDS, RetainedHistoricalHealth, SOURCE_CLASS_HISTORICAL_HEALTH_DETAIL,
};
pub use learning::OrientLearningBrief;
pub use mission::{OrientMissionBrief, OrientMissionProgress};
pub use project::{orient_deployment, orient_deployment_for, orient_deployment_with_advisories};
pub(crate) use project::{orient_deployment_for_probe, orient_deployment_for_workspace};
pub(crate) use reader::MetadataReadBudget;
#[cfg(test)]
use reader::{CancellableHistoryJournal, Reader};
pub use reader::{DeploymentHistory, read_deployment, read_deployment_cancellable};
#[cfg(test)]
use types::ProjectionPurpose;
pub use types::{
    AFFORDANCE_CLAIM_PREFIX, AFFORDANCE_DOCTOR, AFFORDANCE_EXPLAIN_PREFIX,
    AFFORDANCE_FINDING_PREFIX, AFFORDANCE_FOLLOW, AFFORDANCE_INVESTIGATE_PREFIX, AFFORDANCE_PLAN,
    AFFORDANCE_PLAN_PREFIX, AFFORDANCE_RECONCILE_PREFIX, AFFORDANCE_REORIENT, AttentionItem,
    CAPABILITY_CASE_WRITE, CAPABILITY_DOCTOR, CAPABILITY_EXPLAIN, CAPABILITY_PLAN_COMMIT,
    CAPABILITY_PLAN_PREPARE, CAPABILITY_SITUATION_READ, CAPABILITY_WORK_CLAIM, CLAIM_COVERAGE,
    CLAIM_EFFECT_JOURNAL, CLAIM_EVENTS, CLAIM_IMPORTS, CLAIM_LEDGER_HEAD,
    DIRECT_EVENT_EXPANSION_LIMIT, DeploymentOrientation, DeploymentReadError, DeploymentSnapshot,
    EpistemicDebtItem, EventExplanation, EventHydration, HistoryPosition, MAX_DEPLOYMENT_EVENTS,
    ORIENT_DATA_CLASSES, OrientCaseBrief, OrientClaimBrief, OrientError, OrientFindingBrief,
    OrientLimits, OrientPlanBrief, OrientRequest, OrientSessionBinding, OrientValidity,
    RetainedEvent, SOURCE_CLASS_EVENT_DETAIL, SOURCE_CLASS_WORLD_DETAIL,
    UNBOUND_SESSION_DEGRADATION, WORLD_EVENTS_PREFIX, WORLD_PROTECTED_SUMMARY,
    WORLD_UNOBSERVED_ACTIVITY, inline_event_budget, obligation_state_str,
};
use types::{cell, corrupt, digest_of, read_cost, short_identity};

#[cfg(test)]
mod tests;
