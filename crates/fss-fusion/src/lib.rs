#![forbid(unsafe_code)]
//! Deterministic calibrated sequential evidence fusion (`fss-fusion`, plan §16.10, §17.5–17.8).
//!
//! The reference fusion layer answers one question about one event hypothesis — what should
//! happen next given the evidence so far — without ever turning an uncalibrated score, a
//! duplicated observation, or a coverage gap into belief:
//!
//! * **Exact belief.** Every calibrated observation carries a log-likelihood-ratio *interval* in
//!   integer millibans (thousandths of a ban, `log10` odds) from its calibration generation; the
//!   prior is an interval too. Posterior log-odds are exact integer interval sums. No float,
//!   transcendental function or rounding ever reaches a decision; the probability interval
//!   attached for display is outward-rounded from literal tables ([`probability`]).
//! * **No double counting (common cause).** Observations that share *any* declared failure
//!   domain — sensor, clock, model family, preprocessing, network, power, annotator — form one
//!   dependency cluster, whose likelihood interval is the hull of its members': redundant copies
//!   count once and, because the hull's lower bound never exceeds any member's, dependent evidence
//!   can never raise the robust lower bound. Two sizes of one model on one camera are one cluster.
//! * **Missing data is not evidence.** Not-observable, redacted and stale observations and
//!   uncalibrated scores are listed with their reasons and contribute nothing. A coverage gap
//!   never lets a low posterior become a rejection.
//! * **Sequential decision.** The decision is one of the plan's seven outcomes (alert, alert
//!   with degraded coverage, single-domain unconfirmed alert under a registered urgent
//!   exception, bounded wait for imminent independent corroboration, request a better
//!   observation, ask the operator, retain silently, reject) or an explicit indeterminate hold.
//!   Every wait has a deadline and a value bound; the alert threshold rises with the number of
//!   looks at the same hypothesis (optional-stopping correction).
//! * **Score calibration.** [`calibration`] turns labelled outcomes (an event-level
//!   evaluation's true and false positives) into per-score-bin likelihood intervals with exact
//!   integer Wilson bounds, so a detector score reaches fusion only through a measured,
//!   digest-bound calibration generation.
//! * **Counterfactual explanation.** The answer recomputes the decision with each dependency
//!   cluster removed and states the exact additional independent support that would alert and
//!   the reduction that would retain.
//!
//! Nothing here reads a clock, the filesystem or the network; the caller supplies `now`. A
//! decision is derived cognition: it grants no effect authority.

pub mod calibration;
pub mod probability;

mod decide;
mod log_table;
mod model;

pub use calibration::{ScoreBin, ScoreCalibration};
pub use decide::fuse;
pub use model::{
    Calibration, Cluster, ClusterDirection, Counterfactual, Coverage, Decision, EvidenceItem,
    FusionError, FusionOutcome, FusionPolicy, FusionQuery, LlrInterval, MAX_ABS_LLR,
    MAX_DOMAINS_PER_ITEM, MAX_EVIDENCE, MAX_OPPORTUNITIES, MAX_PROBES, Observability, Opportunity,
    Probe, Reason, Severity,
};

/// Fusion query digest domain (`SCHEMA-DOMAIN-FUSION-QUERY-001`).
pub const FUSION_QUERY_DOMAIN: &str = "fss.fusion.query.v1";
/// Fusion decision digest domain (`SCHEMA-DOMAIN-FUSION-DECISION-001`).
pub const FUSION_DECISION_DOMAIN: &str = "fss.fusion.decision.v1";
/// Implementation generation of the reference fusion rule.
pub const IMPLEMENTATION_ID: &str = "fss-fusion:reference:hull-cluster-interval-sum:sequential-v1";
