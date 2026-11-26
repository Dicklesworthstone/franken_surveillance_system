#![forbid(unsafe_code)]
//! Durable retention-policy and legal-hold obligation tables (`FSS-036`, `fss-x4a.9.6`).
//!
//! Enforces the conservative FSS retention lattice over canonical custody objects:
//!
//! - **Active holds ALWAYS dominate retention expiry:** if any active, unexpired
//!   [`HoldObligation`] covers an object (either by exact `ObjectId` or scope prefix),
//!   [`RetentionHoldTable::evaluate_disposition`] returns
//!   [`RetentionDisposition::BlockedByActiveHold`].
//! - **Released holds remain tombstoned:** releasing a hold requires explicit authority plus a
//!   `release_approval_digest`; released records are never silently deleted from the table.
//! - **Expiry never grants deletion authority:** [`RetentionDisposition::EligibleForDeletionPlan`]
//!   merely certifies that retention has expired with zero active holds (`grants_deletion_authority() == false`);
//!   actual deletion still requires an explicit `FSS-037` reachability closure plan and owner approval.
//! - **Uncovered/unknown timestamps fail closed:** missing matching rules or invalid timestamps
//!   yield [`RetentionDisposition::IndeterminateUncovered`] — NEVER silently treated as deletable.
//! - **Crash-safe durable wire persistence (`FSSRHT01` v1):** sealed under
//!   `fss.ledger_retention_hold_table.v1`, persisted via temp file + `sync_all()` + atomic rename +
//!   parent directory sync.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    CanonicalDecoder, CanonicalEncoder, ContentDigest, ObjectId, Plane, Sha256Hasher, TimestampNs,
};

use crate::storage_adapter::{MAX_STORAGE_LABEL_BYTES, StorageAuthorityScope};

/// Registered digest domain for [`RetentionHoldTable`] snapshots (`FSS-036`).
pub const LEDGER_RETENTION_HOLD_TABLE_DOMAIN: &str = "fss.ledger_retention_hold_table.v1";
/// Binary wire magic header for [`RetentionHoldTable`] durable snapshots.
pub const RETENTION_HOLD_WIRE_MAGIC: [u8; 8] = *b"FSSRHT01";
/// Current wire format version for [`RetentionHoldTable`].
pub const RETENTION_HOLD_WIRE_VERSION: u32 = 1;
/// Hard ceiling on retention rules in one table.
pub const MAX_RETENTION_RULES: usize = 1_024;
/// Hard ceiling on hold obligations (active + tombstoned released) in one table.
pub const MAX_HOLD_OBLIGATIONS: usize = 4_096;
/// Hard ceiling on serialized wire length for [`RetentionHoldTable`] (2 MiB).
pub const MAX_RETENTION_HOLD_WIRE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum UTF-8 bytes in a hold/release rationale string.
pub const MAX_RETENTION_REASON_BYTES: usize = 256;

const WIRE_HEADER_BYTES: usize = 16;
const WIRE_CHECKSUM_BYTES: usize = 32;
static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(1);

/// Retention data class governed by the FSS retention lattice (`FSS-036`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RetentionClass {
    /// Immutable owner-authorized raw sensor source bytes and capsules.
    SourceCustody = 1,
    /// Derived cognitive events, tracks, and hypotheses.
    DerivedEvent = 2,
    /// Redacted portable evidence exports.
    RedactedExport = 3,
    /// Audit, compliance, and diagnostic receipts.
    DiagnosticAudit = 4,
    /// Immutable model packages and calibration artifacts.
    ModelArtifact = 5,
}

impl RetentionClass {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceCustody => "source_custody",
            Self::DerivedEvent => "derived_event",
            Self::RedactedExport => "redacted_export",
            Self::DiagnosticAudit => "diagnostic_audit",
            Self::ModelArtifact => "model_artifact",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, RetentionHoldError> {
        match tag {
            1 => Ok(Self::SourceCustody),
            2 => Ok(Self::DerivedEvent),
            3 => Ok(Self::RedactedExport),
            4 => Ok(Self::DiagnosticAudit),
            5 => Ok(Self::ModelArtifact),
            other => Err(RetentionHoldError::MalformedWire(format!(
                "unknown RetentionClass tag {other}"
            ))),
        }
    }
}

/// Non-collapsed lifecycle state of a [`HoldObligation`] (released holds stay tombstoned).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HoldState {
    /// Hold is active and blocks deletion unless `expires_at` has strictly passed.
    Active,
    /// Hold was explicitly released under verified authority; preserved as an immutable tombstone.
    Released {
        /// Virtual timestamp when release was committed.
        released_at: TimestampNs,
        /// Explicit owner/operator approval commitment authorizing release.
        release_approval_digest: ContentDigest,
        /// Authority generation active at release time.
        release_authority_generation: u64,
        /// Secret-free bounded release rationale.
        release_reason: String,
    },
}

/// Target scope covered by a [`HoldObligation`].
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HoldTarget {
    /// Hold pinned to one exact [`ObjectId`].
    ExactObject(ObjectId),
    /// Hold pinned to all objects whose canonical string ID starts with `prefix`.
    ObjectPrefix(String),
}

impl HoldTarget {
    /// Returns true iff this hold target covers `object_id`.
    #[must_use]
    pub fn matches(&self, object_id: &ObjectId) -> bool {
        match self {
            Self::ExactObject(id) => id == object_id,
            Self::ObjectPrefix(prefix) => object_id.as_str().starts_with(prefix.as_str()),
        }
    }
}

/// Immutable retention window rule for a `(site_lineage, object_prefix, class)` scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionRule {
    /// Stable never-renumbered retention rule identifier.
    pub rule_id: String,
    /// Exact object ID prefix matched by this rule (e.g. `"obj:cam:front:"` or `"obj:"`).
    pub object_prefix: String,
    /// Data class governed by this rule.
    pub class: RetentionClass,
    /// Minimum retention duration in nanoseconds (`> 0`, `<= max_retain_ns`).
    pub min_retain_ns: u64,
    /// Maximum retention duration in nanoseconds (`>= min_retain_ns`); after expiry without hold,
    /// object becomes eligible for a separately approved deletion plan.
    pub max_retain_ns: u64,
    /// Authority generation pinned when this rule was adopted.
    pub authority_generation: u64,
    /// Policy epoch pinned when this rule was adopted.
    pub policy_epoch: u64,
    /// Explicit owner approval digest authorizing this retention rule.
    pub approval_digest: ContentDigest,
}

/// Legal, incident, or evidentiary hold obligation pinned inside [`RetentionHoldTable`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldObligation {
    /// Stable never-renumbered hold identifier.
    pub hold_id: String,
    /// Target object or prefix protected by this hold.
    pub target: HoldTarget,
    /// Secret-free bounded reason for the hold.
    pub reason: String,
    /// Virtual timestamp when hold was placed.
    pub placed_at: TimestampNs,
    /// Optional explicit expiration timestamp (`None` = indefinite until explicitly released).
    pub expires_at: Option<TimestampNs>,
    /// Authority generation active when the hold was placed.
    pub authority_generation: u64,
    /// Explicit approval digest authorizing the hold.
    pub approval_digest: ContentDigest,
    /// Non-collapsed lifecycle state (`Active` or tombstoned `Released`).
    pub state: HoldState,
}

impl HoldObligation {
    /// True iff this hold actively blocks deletion at `now`.
    #[must_use]
    pub fn is_blocking_at(&self, now: TimestampNs) -> bool {
        match self.state {
            HoldState::Released { .. } => false,
            HoldState::Active => match self.expires_at {
                None => true,
                Some(exp) => now.0 < exp.0,
            },
        }
    }
}

/// Result of inserting a rule or hold (distinguishes new insertion from idempotent replay).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableMutationOutcome {
    /// Entry was newly inserted and committed into the table.
    Inserted,
    /// Identical entry already existed; idempotent no-op.
    AlreadyPresent,
    /// Existing active hold transitioned cleanly to tombstoned `Released`.
    Released,
    /// Hold was already released with identical approval metadata; idempotent no-op.
    AlreadyReleased,
}

/// Non-collapsed conservative retention lattice disposition (`FSS-036`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetentionDisposition {
    /// One or more active holds block deletion regardless of retention expiry.
    BlockedByActiveHold {
        /// Canonically sorted active hold IDs blocking deletion.
        hold_ids: Vec<String>,
    },
    /// No active hold, and the most conservative matching rule still retains the object.
    RetainedWithinWindow {
        /// Controlling retention rule ID with the latest required retention boundary.
        rule_id: String,
        /// Inclusive earliest timestamp (`created_at + max_retain_ns`) when eligibility may begin.
        retain_until: TimestampNs,
    },
    /// Retention window expired AND zero active holds apply.
    ///
    /// **NOTE:** Never grants deletion authority; callers MUST construct an explicit `FSS-037`
    /// deletion reachability closure plan and obtain owner approval.
    EligibleForDeletionPlan {
        /// Controlling retention rule ID whose window expired.
        rule_id: String,
        /// Timestamp when the retention window expired.
        expired_at: TimestampNs,
    },
    /// No matching retention rule exists or timestamp bounds overflowed; fail closed (NOT deletable!).
    IndeterminateUncovered {
        /// Secret-free diagnostic reason why eligibility could not be certified.
        reason: String,
    },
}

impl RetentionDisposition {
    /// Retention evaluation is derived policy accounting and NEVER grants deletion/effect authority.
    #[must_use]
    pub const fn grants_deletion_authority(&self) -> bool {
        false
    }

    /// True iff the object may enter a separately approved deletion planning workflow.
    #[must_use]
    pub const fn is_eligible_for_deletion_plan(&self) -> bool {
        matches!(self, Self::EligibleForDeletionPlan { .. })
    }
}

/// Safe recovery guidance for a refused retention/hold table operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionHoldGuidance {
    /// Re-authorize with active `Plane::Authority` capability and current authority generation.
    ReauthorizeAuthority,
    /// Repair invalid durations, prefixes, timestamps, or conflicting stable IDs.
    RepairRuleOrHoldSpec,
    /// Cooperative cancellation observed cleanly; safe to retry without state drift.
    RetryCleanly,
    /// Reject corrupt durable snapshot bytes and recover from canonical custody ledger.
    RejectCorruptSnapshot,
}

/// Typed fail-closed error emitted by [`RetentionHoldTable`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetentionHoldError {
    /// Caller lacked active authority, privacy, `Plane::Authority`, or current generation.
    AuthorityRefused(String),
    /// Invalid rule/hold bounds, durations, prefix, or timestamp ordering.
    InvalidInput(String),
    /// Attempted to reuse an existing `rule_id` or `hold_id` with conflicting semantics.
    IdConflict {
        /// Conflicting identifier.
        id: String,
    },
    /// Target hold ID was not found for release.
    UnknownHold {
        /// Missing hold ID.
        hold_id: String,
    },
    /// Table capacity or wire ceiling exceeded.
    BoundsExceeded {
        /// Observed count or bytes.
        observed: usize,
        /// Hard maximum allowed.
        maximum: usize,
    },
    /// Cooperative cancellation observed cleanly with zero state mutation.
    Cancelled,
    /// Filesystem I/O error during atomic persistence or reload.
    Io(String),
    /// Binary snapshot lacked [`RETENTION_HOLD_WIRE_MAGIC`].
    InvalidMagic,
    /// Binary snapshot declared an unsupported version.
    UnsupportedVersion {
        /// Unsupported version tag observed.
        version: u32,
    },
    /// Trailing SHA-256 checksum or table digest verification failed.
    ChecksumMismatch,
    /// Binary snapshot truncated or structurally malformed.
    MalformedWire(String),
}

impl RetentionHoldError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AuthorityRefused(_) => "ERR-LEDGER-RETENTION-AUTH-001",
            Self::InvalidInput(_) => "ERR-LEDGER-RETENTION-INPUT-001",
            Self::IdConflict { .. } => "ERR-LEDGER-RETENTION-CONFLICT-001",
            Self::UnknownHold { .. } => "ERR-LEDGER-RETENTION-UNKNOWN-HOLD-001",
            Self::BoundsExceeded { .. } => "ERR-LEDGER-RETENTION-BOUNDS-001",
            Self::Cancelled => "ERR-LEDGER-RETENTION-CANCELLED-001",
            Self::Io(_) => "ERR-LEDGER-RETENTION-IO-001",
            Self::InvalidMagic | Self::UnsupportedVersion { .. } => "ERR-SCHEMA-UNSUPPORTED-001",
            Self::ChecksumMismatch => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::MalformedWire(_) => "ERR-LEDGER-RETENTION-MALFORMED-WIRE-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> RetentionHoldGuidance {
        match self {
            Self::AuthorityRefused(_) => RetentionHoldGuidance::ReauthorizeAuthority,
            Self::InvalidInput(_)
            | Self::IdConflict { .. }
            | Self::UnknownHold { .. }
            | Self::BoundsExceeded { .. } => RetentionHoldGuidance::RepairRuleOrHoldSpec,
            Self::Cancelled => RetentionHoldGuidance::RetryCleanly,
            Self::Io(_)
            | Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::ChecksumMismatch
            | Self::MalformedWire(_) => RetentionHoldGuidance::RejectCorruptSnapshot,
        }
    }
}

impl fmt::Display for RetentionHoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code(), self)
    }
}

impl Error for RetentionHoldError {}

/// Durable retention-policy and legal-hold obligation table (`FSS-036`, `FSSRHT01` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionHoldTable {
    format_version: u32,
    site_lineage: String,
    rules: BTreeMap<String, RetentionRule>,
    holds: BTreeMap<String, HoldObligation>,
    table_digest: ContentDigest,
}

impl RetentionHoldTable {
    /// Creates an empty retention/hold table pinned to `site_lineage`.
    pub fn new(site_lineage: &str) -> Result<Self, RetentionHoldError> {
        validate_text(site_lineage, MAX_STORAGE_LABEL_BYTES, "site_lineage")?;
        let mut table = Self {
            format_version: RETENTION_HOLD_WIRE_VERSION,
            site_lineage: site_lineage.to_owned(),
            rules: BTreeMap::new(),
            holds: BTreeMap::new(),
            table_digest: ContentDigest::sha256(b"unsealed-retention-table"),
        };
        table.table_digest = table.compute_digest()?;
        Ok(table)
    }

    /// Site lineage pinned by this table.
    #[must_use]
    pub fn site_lineage(&self) -> &str {
        &self.site_lineage
    }

    /// Canonical SHA-256 commitment digest under [`LEDGER_RETENTION_HOLD_TABLE_DOMAIN`].
    #[must_use]
    pub const fn table_digest(&self) -> ContentDigest {
        self.table_digest
    }

    /// Immutable view of registered retention rules keyed by `rule_id`.
    #[must_use]
    pub fn rules(&self) -> &BTreeMap<String, RetentionRule> {
        &self.rules
    }

    /// Immutable view of all holds (active AND tombstoned released) keyed by `hold_id`.
    #[must_use]
    pub fn holds(&self) -> &BTreeMap<String, HoldObligation> {
        &self.holds
    }

    /// Count of currently active (non-released) holds at `now`.
    #[must_use]
    pub fn active_hold_count(&self, now: TimestampNs) -> usize {
        self.holds
            .values()
            .filter(|h| h.is_blocking_at(now))
            .count()
    }

    /// Adopts an immutable [`RetentionRule`] under explicit `Plane::Authority` scope.
    ///
    /// Idempotent when an identical rule already exists under `rule.rule_id`; fails closed with
    /// [`RetentionHoldError::IdConflict`] if a differing rule attempts to overwrite the same ID.
    pub fn adopt_rule(
        &mut self,
        authority: &StorageAuthorityScope,
        rule: RetentionRule,
        cancelled: bool,
    ) -> Result<TableMutationOutcome, RetentionHoldError> {
        if cancelled {
            return Err(RetentionHoldError::Cancelled);
        }
        validate_authority(authority, Plane::Authority)?;
        validate_rule(&rule)?;
        if rule.authority_generation != authority.authority_generation {
            return Err(RetentionHoldError::AuthorityRefused(
                "rule authority_generation disagrees with active authority scope".to_owned(),
            ));
        }
        if let Some(existing) = self.rules.get(&rule.rule_id) {
            if existing == &rule {
                return Ok(TableMutationOutcome::AlreadyPresent);
            }
            return Err(RetentionHoldError::IdConflict { id: rule.rule_id });
        }
        if self.rules.len() >= MAX_RETENTION_RULES {
            return Err(RetentionHoldError::BoundsExceeded {
                observed: self.rules.len() + 1,
                maximum: MAX_RETENTION_RULES,
            });
        }
        self.rules.insert(rule.rule_id.clone(), rule);
        self.table_digest = self.compute_digest()?;
        Ok(TableMutationOutcome::Inserted)
    }

    /// Places a [`HoldObligation`] under explicit `Plane::Authority` scope.
    ///
    /// Idempotent on identical re-submission; refuses conflicting specs under an existing `hold_id`
    /// or attempts to place an already-released hold directly.
    pub fn place_hold(
        &mut self,
        authority: &StorageAuthorityScope,
        hold: HoldObligation,
        cancelled: bool,
    ) -> Result<TableMutationOutcome, RetentionHoldError> {
        if cancelled {
            return Err(RetentionHoldError::Cancelled);
        }
        validate_authority(authority, Plane::Authority)?;
        validate_hold(&hold)?;
        if hold.state != HoldState::Active {
            return Err(RetentionHoldError::InvalidInput(
                "newly placed hold must begin in HoldState::Active".to_owned(),
            ));
        }
        if hold.authority_generation != authority.authority_generation {
            return Err(RetentionHoldError::AuthorityRefused(
                "hold authority_generation disagrees with active authority scope".to_owned(),
            ));
        }
        if let Some(existing) = self.holds.get(&hold.hold_id) {
            if existing == &hold {
                return Ok(TableMutationOutcome::AlreadyPresent);
            }
            return Err(RetentionHoldError::IdConflict { id: hold.hold_id });
        }
        if self.holds.len() >= MAX_HOLD_OBLIGATIONS {
            return Err(RetentionHoldError::BoundsExceeded {
                observed: self.holds.len() + 1,
                maximum: MAX_HOLD_OBLIGATIONS,
            });
        }
        self.holds.insert(hold.hold_id.clone(), hold);
        self.table_digest = self.compute_digest()?;
        Ok(TableMutationOutcome::Inserted)
    }

    /// Explicitly releases an active hold, preserving it as a tombstoned [`HoldState::Released`]
    /// audit record rather than erasing it.
    pub fn release_hold(
        &mut self,
        authority: &StorageAuthorityScope,
        hold_id: &str,
        released_at: TimestampNs,
        release_approval_digest: ContentDigest,
        release_reason: &str,
        cancelled: bool,
    ) -> Result<TableMutationOutcome, RetentionHoldError> {
        if cancelled {
            return Err(RetentionHoldError::Cancelled);
        }
        validate_authority(authority, Plane::Authority)?;
        validate_text(hold_id, MAX_STORAGE_LABEL_BYTES, "hold_id")?;
        validate_text(release_reason, MAX_RETENTION_REASON_BYTES, "release_reason")?;
        let Some(hold) = self.holds.get_mut(hold_id) else {
            return Err(RetentionHoldError::UnknownHold {
                hold_id: hold_id.to_owned(),
            });
        };
        if released_at.0 < hold.placed_at.0 {
            return Err(RetentionHoldError::InvalidInput(
                "released_at cannot precede hold placed_at".to_owned(),
            ));
        }
        let target_state = HoldState::Released {
            released_at,
            release_approval_digest,
            release_authority_generation: authority.authority_generation,
            release_reason: release_reason.to_owned(),
        };
        match &hold.state {
            HoldState::Active => {
                hold.state = target_state;
                self.table_digest = self.compute_digest()?;
                Ok(TableMutationOutcome::Released)
            }
            existing @ HoldState::Released { .. } => {
                if existing == &target_state {
                    Ok(TableMutationOutcome::AlreadyReleased)
                } else {
                    Err(RetentionHoldError::IdConflict {
                        id: hold_id.to_owned(),
                    })
                }
            }
        }
    }

    /// Evaluates the conservative retention/hold lattice for `(object_id, class, created_at)` at `now`.
    ///
    /// Rules:
    /// 1. ANY active unexpired hold matching `object_id` IMMEDIATELY returns `BlockedByActiveHold`.
    /// 2. Among all matching retention rules for `(object_id, class)`, the **most conservative
    ///    (longest) retention boundary** governs (conservative lattice join!): an object is
    ///    `EligibleForDeletionPlan` ONLY if EVERY matching rule has expired AND at least one
    ///    matching rule exists!
    /// 3. Missing matching rules or `now < created_at` fail closed with `IndeterminateUncovered`.
    pub fn evaluate_disposition(
        &self,
        authority: &StorageAuthorityScope,
        object_id: &ObjectId,
        class: RetentionClass,
        created_at: TimestampNs,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<RetentionDisposition, RetentionHoldError> {
        if cancelled {
            return Err(RetentionHoldError::Cancelled);
        }
        authority
            .validate()
            .map_err(|e| RetentionHoldError::AuthorityRefused(e.to_string()))?;
        if now.0 < created_at.0 {
            return Ok(RetentionDisposition::IndeterminateUncovered {
                reason: "evaluation timestamp precedes object creation timestamp".to_owned(),
            });
        }

        let mut blocking_holds: Vec<String> = self
            .holds
            .values()
            .filter(|h| h.is_blocking_at(now) && h.target.matches(object_id))
            .map(|h| h.hold_id.clone())
            .collect();
        blocking_holds.sort();
        if !blocking_holds.is_empty() {
            return Ok(RetentionDisposition::BlockedByActiveHold {
                hold_ids: blocking_holds,
            });
        }

        // Conservative lattice join: pick the matching rule with the LATEST retain_until timestamp
        // (tie-break: lexicographically smallest rule_id for deterministic CGSE identity).
        let mut controlling: Option<(&str, i128)> = None;
        for rule in self.rules.values() {
            if rule.class != class || !object_id.as_str().starts_with(rule.object_prefix.as_str()) {
                continue;
            }
            let Some(expiry) = created_at.0.checked_add(i128::from(rule.max_retain_ns)) else {
                return Ok(RetentionDisposition::IndeterminateUncovered {
                    reason: "retention window timestamp overflow".to_owned(),
                });
            };
            match controlling {
                None => controlling = Some((rule.rule_id.as_str(), expiry)),
                Some((prev_id, prev_exp)) => {
                    if expiry > prev_exp || (expiry == prev_exp && rule.rule_id.as_str() < prev_id)
                    {
                        controlling = Some((rule.rule_id.as_str(), expiry));
                    }
                }
            }
        }

        let Some((rule_id, retain_until_ns)) = controlling else {
            return Ok(RetentionDisposition::IndeterminateUncovered {
                reason: "no matching retention rule covers object scope and class".to_owned(),
            });
        };

        if now.0 < retain_until_ns {
            Ok(RetentionDisposition::RetainedWithinWindow {
                rule_id: rule_id.to_owned(),
                retain_until: TimestampNs(retain_until_ns),
            })
        } else {
            Ok(RetentionDisposition::EligibleForDeletionPlan {
                rule_id: rule_id.to_owned(),
                expired_at: TimestampNs(retain_until_ns),
            })
        }
    }

    /// Independent naive reference oracle evaluating disposition directly over raw slices
    /// (`rules_slice`, `holds_slice`) to certify [`Self::evaluate_disposition`] differentially.
    #[must_use]
    pub fn oracle_evaluate_disposition(
        rules: &[RetentionRule],
        holds: &[HoldObligation],
        object_id: &ObjectId,
        class: RetentionClass,
        created_at: TimestampNs,
        now: TimestampNs,
    ) -> RetentionDisposition {
        if now.0 < created_at.0 {
            return RetentionDisposition::IndeterminateUncovered {
                reason: "evaluation timestamp precedes object creation timestamp".to_owned(),
            };
        }
        let mut hold_ids: BTreeSet<String> = BTreeSet::new();
        for h in holds {
            if matches!(h.state, HoldState::Active)
                && h.expires_at.is_none_or(|exp| now.0 < exp.0)
                && h.target.matches(object_id)
            {
                hold_ids.insert(h.hold_id.clone());
            }
        }
        if !hold_ids.is_empty() {
            return RetentionDisposition::BlockedByActiveHold {
                hold_ids: hold_ids.into_iter().collect(),
            };
        }
        let mut best: Option<(i128, &str)> = None;
        for r in rules {
            if r.class == class && object_id.as_str().starts_with(r.object_prefix.as_str()) {
                let Some(exp) = created_at.0.checked_add(i128::from(r.max_retain_ns)) else {
                    return RetentionDisposition::IndeterminateUncovered {
                        reason: "retention window timestamp overflow".to_owned(),
                    };
                };
                match best {
                    None => best = Some((exp, r.rule_id.as_str())),
                    Some((b_exp, b_id))
                        if exp > b_exp || (exp == b_exp && r.rule_id.as_str() < b_id) =>
                    {
                        best = Some((exp, r.rule_id.as_str()));
                    }
                    _ => {}
                }
            }
        }
        match best {
            None => RetentionDisposition::IndeterminateUncovered {
                reason: "no matching retention rule covers object scope and class".to_owned(),
            },
            Some((exp, rid)) if now.0 < exp => RetentionDisposition::RetainedWithinWindow {
                rule_id: rid.to_owned(),
                retain_until: TimestampNs(exp),
            },
            Some((exp, rid)) => RetentionDisposition::EligibleForDeletionPlan {
                rule_id: rid.to_owned(),
                expired_at: TimestampNs(exp),
            },
        }
    }

    /// Computes canonical SHA-256 commitment digest under [`LEDGER_RETENTION_HOLD_TABLE_DOMAIN`].
    pub fn compute_digest(&self) -> Result<ContentDigest, RetentionHoldError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_RETENTION_HOLD_TABLE_DOMAIN);
        self.encode_fields(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_fields(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(&self.site_lineage);
        enc.u32(self.rules.len() as u32);
        for rule in self.rules.values() {
            enc.text(&rule.rule_id);
            enc.text(&rule.object_prefix);
            enc.u8(rule.class.tag());
            enc.u64(rule.min_retain_ns);
            enc.u64(rule.max_retain_ns);
            enc.u64(rule.authority_generation);
            enc.u64(rule.policy_epoch);
            enc.digest(rule.approval_digest);
        }
        enc.u32(self.holds.len() as u32);
        for hold in self.holds.values() {
            enc.text(&hold.hold_id);
            match &hold.target {
                HoldTarget::ExactObject(oid) => {
                    enc.u8(1);
                    enc.text(oid.as_str());
                }
                HoldTarget::ObjectPrefix(prefix) => {
                    enc.u8(2);
                    enc.text(prefix);
                }
            }
            enc.text(&hold.reason);
            enc.i128(hold.placed_at.0);
            match hold.expires_at {
                None => enc.u8(0),
                Some(exp) => {
                    enc.u8(1);
                    enc.i128(exp.0);
                }
            }
            enc.u64(hold.authority_generation);
            enc.digest(hold.approval_digest);
            match &hold.state {
                HoldState::Active => enc.u8(1),
                HoldState::Released {
                    released_at,
                    release_approval_digest,
                    release_authority_generation,
                    release_reason,
                } => {
                    enc.u8(2);
                    enc.i128(released_at.0);
                    enc.digest(*release_approval_digest);
                    enc.u64(*release_authority_generation);
                    enc.text(release_reason);
                }
            }
        }
    }

    /// Validates all structural invariants and verifies canonical digest integrity.
    pub fn verify_self(&self) -> Result<(), RetentionHoldError> {
        if self.format_version != RETENTION_HOLD_WIRE_VERSION {
            return Err(RetentionHoldError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_text(&self.site_lineage, MAX_STORAGE_LABEL_BYTES, "site_lineage")?;
        if self.rules.len() > MAX_RETENTION_RULES {
            return Err(RetentionHoldError::BoundsExceeded {
                observed: self.rules.len(),
                maximum: MAX_RETENTION_RULES,
            });
        }
        if self.holds.len() > MAX_HOLD_OBLIGATIONS {
            return Err(RetentionHoldError::BoundsExceeded {
                observed: self.holds.len(),
                maximum: MAX_HOLD_OBLIGATIONS,
            });
        }
        for (key, rule) in &self.rules {
            if key != &rule.rule_id {
                return Err(RetentionHoldError::MalformedWire(
                    "rule map key disagrees with rule_id".to_owned(),
                ));
            }
            validate_rule(rule)?;
        }
        for (key, hold) in &self.holds {
            if key != &hold.hold_id {
                return Err(RetentionHoldError::MalformedWire(
                    "hold map key disagrees with hold_id".to_owned(),
                ));
            }
            validate_hold(hold)?;
        }
        if self.compute_digest()? != self.table_digest {
            return Err(RetentionHoldError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Encodes this table into its versioned, checksummed `FSSRHT01` v1 binary wire envelope.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, RetentionHoldError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_fields(&mut enc);
        enc.digest(self.table_digest);
        let payload = enc
            .finish_checked()
            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
        let total = WIRE_HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or(RetentionHoldError::BoundsExceeded {
                observed: usize::MAX,
                maximum: MAX_RETENTION_HOLD_WIRE_BYTES,
            })?;
        if total > MAX_RETENTION_HOLD_WIRE_BYTES {
            return Err(RetentionHoldError::BoundsExceeded {
                observed: total,
                maximum: MAX_RETENTION_HOLD_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&RETENTION_HOLD_WIRE_MAGIC);
        out.extend_from_slice(&RETENTION_HOLD_WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        let mut hasher = Sha256Hasher::new();
        hasher.update(LEDGER_RETENTION_HOLD_TABLE_DOMAIN.as_bytes());
        hasher.update(&out);
        let checksum = hasher
            .finalize()
            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Strictly decodes an `FSSRHT01` v1 binary wire envelope, failing closed on tamper or drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RetentionHoldError> {
        let min_len = WIRE_HEADER_BYTES + WIRE_CHECKSUM_BYTES;
        if bytes.len() < min_len {
            return Err(RetentionHoldError::MalformedWire(format!(
                "wire length {} below minimum {min_len}",
                bytes.len()
            )));
        }
        if bytes.len() > MAX_RETENTION_HOLD_WIRE_BYTES {
            return Err(RetentionHoldError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_RETENTION_HOLD_WIRE_BYTES,
            });
        }
        if bytes[..8] != RETENTION_HOLD_WIRE_MAGIC {
            return Err(RetentionHoldError::InvalidMagic);
        }
        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != RETENTION_HOLD_WIRE_VERSION {
            return Err(RetentionHoldError::UnsupportedVersion { version });
        }
        let declared_len =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let expected_total = WIRE_HEADER_BYTES
            .checked_add(declared_len)
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| {
                RetentionHoldError::MalformedWire("declared payload length overflow".to_owned())
            })?;
        if bytes.len() != expected_total {
            return Err(RetentionHoldError::MalformedWire(format!(
                "wire length {} disagrees with declared payload length {declared_len}",
                bytes.len()
            )));
        }
        let split_at = bytes.len() - WIRE_CHECKSUM_BYTES;
        let (body, trailer) = bytes.split_at(split_at);
        let mut hasher = Sha256Hasher::new();
        hasher.update(LEDGER_RETENTION_HOLD_TABLE_DOMAIN.as_bytes());
        hasher.update(body);
        let computed = hasher
            .finalize()
            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
        if computed.as_slice() != trailer {
            return Err(RetentionHoldError::ChecksumMismatch);
        }

        let mut dec = CanonicalDecoder::new(&body[WIRE_HEADER_BYTES..]);
        let format_version = dec
            .u32()
            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
        let site_lineage = dec
            .text()
            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
            .to_owned();

        let rule_count = dec
            .u32()
            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
            as usize;
        if rule_count > MAX_RETENTION_RULES {
            return Err(RetentionHoldError::BoundsExceeded {
                observed: rule_count,
                maximum: MAX_RETENTION_RULES,
            });
        }
        let mut rules = BTreeMap::new();
        let mut prev_rule_id: Option<String> = None;
        for _ in 0..rule_count {
            let rule_id = dec
                .text()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
                .to_owned();
            if let Some(ref prev) = prev_rule_id
                && rule_id <= *prev
            {
                return Err(RetentionHoldError::MalformedWire(
                    "retention rules not strictly sorted by rule_id".to_owned(),
                ));
            }
            prev_rule_id = Some(rule_id.clone());
            let object_prefix = dec
                .text()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
                .to_owned();
            let class = RetentionClass::from_tag(
                dec.u8()
                    .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?,
            )?;
            let min_retain_ns = dec
                .u64()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
            let max_retain_ns = dec
                .u64()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
            let authority_generation = dec
                .u64()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
            let policy_epoch = dec
                .u64()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
            let approval_digest = dec
                .digest()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
            rules.insert(
                rule_id.clone(),
                RetentionRule {
                    rule_id,
                    object_prefix,
                    class,
                    min_retain_ns,
                    max_retain_ns,
                    authority_generation,
                    policy_epoch,
                    approval_digest,
                },
            );
        }

        let hold_count = dec
            .u32()
            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
            as usize;
        if hold_count > MAX_HOLD_OBLIGATIONS {
            return Err(RetentionHoldError::BoundsExceeded {
                observed: hold_count,
                maximum: MAX_HOLD_OBLIGATIONS,
            });
        }
        let mut holds = BTreeMap::new();
        let mut prev_hold_id: Option<String> = None;
        for _ in 0..hold_count {
            let hold_id = dec
                .text()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
                .to_owned();
            if let Some(ref prev) = prev_hold_id
                && hold_id <= *prev
            {
                return Err(RetentionHoldError::MalformedWire(
                    "hold obligations not strictly sorted by hold_id".to_owned(),
                ));
            }
            prev_hold_id = Some(hold_id.clone());
            let target = match dec
                .u8()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
            {
                1 => {
                    let s = dec
                        .text()
                        .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
                    let oid = ObjectId::parse(s)
                        .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
                    HoldTarget::ExactObject(oid)
                }
                2 => {
                    let s = dec
                        .text()
                        .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
                        .to_owned();
                    HoldTarget::ObjectPrefix(s)
                }
                other => {
                    return Err(RetentionHoldError::MalformedWire(format!(
                        "unknown HoldTarget tag {other}"
                    )));
                }
            };
            let reason = dec
                .text()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
                .to_owned();
            let placed_at = TimestampNs(
                dec.i128()
                    .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?,
            );
            let expires_at = match dec
                .u8()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
            {
                0 => None,
                1 => {
                    Some(TimestampNs(dec.i128().map_err(|e| {
                        RetentionHoldError::MalformedWire(e.to_string())
                    })?))
                }
                other => {
                    return Err(RetentionHoldError::MalformedWire(format!(
                        "unknown expires_at option tag {other}"
                    )));
                }
            };
            let authority_generation = dec
                .u64()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
            let approval_digest = dec
                .digest()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
            let state = match dec
                .u8()
                .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
            {
                1 => HoldState::Active,
                2 => {
                    let released_at = TimestampNs(
                        dec.i128()
                            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?,
                    );
                    let release_approval_digest = dec
                        .digest()
                        .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
                    let release_authority_generation = dec
                        .u64()
                        .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
                    let release_reason = dec
                        .text()
                        .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?
                        .to_owned();
                    HoldState::Released {
                        released_at,
                        release_approval_digest,
                        release_authority_generation,
                        release_reason,
                    }
                }
                other => {
                    return Err(RetentionHoldError::MalformedWire(format!(
                        "unknown HoldState tag {other}"
                    )));
                }
            };
            holds.insert(
                hold_id.clone(),
                HoldObligation {
                    hold_id,
                    target,
                    reason,
                    placed_at,
                    expires_at,
                    authority_generation,
                    approval_digest,
                    state,
                },
            );
        }

        let table_digest = dec
            .digest()
            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;
        dec.ensure_finished()
            .map_err(|e| RetentionHoldError::MalformedWire(e.to_string()))?;

        let table = Self {
            format_version,
            site_lineage,
            rules,
            holds,
            table_digest,
        };
        table.verify_self()?;
        Ok(table)
    }

    /// Atomically persists the verified `FSSRHT01` snapshot to `path` via temp file + `sync_all()`
    /// + rename + parent directory sync.
    pub fn save_atomic(&self, path: &Path) -> Result<(), RetentionHoldError> {
        let bytes = self.to_canonical_bytes()?;
        let parent = path.parent().ok_or_else(|| {
            RetentionHoldError::InvalidInput("snapshot path has no parent directory".to_owned())
        })?;
        fs::create_dir_all(parent).map_err(|e| RetentionHoldError::Io(e.to_string()))?;
        let name = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
            RetentionHoldError::InvalidInput("invalid snapshot filename".to_owned())
        })?;
        let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(".{name}.tmp.{}.{seq}", std::process::id()));
        if let Err(err) = fs::write(&tmp, &bytes)
            .and_then(|()| fs::File::open(&tmp).and_then(|file| file.sync_all()))
        {
            let _ = fs::remove_file(&tmp);
            return Err(RetentionHoldError::Io(err.to_string()));
        }
        if let Err(err) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(RetentionHoldError::Io(err.to_string()));
        }
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Loads and cryptographically verifies a durable `FSSRHT01` snapshot from `path`.
    pub fn load_verified(path: &Path) -> Result<Self, RetentionHoldError> {
        let bytes = fs::read(path).map_err(|e| RetentionHoldError::Io(e.to_string()))?;
        Self::from_canonical_bytes(&bytes)
    }
}

fn validate_authority(
    authority: &StorageAuthorityScope,
    required_plane: Plane,
) -> Result<(), RetentionHoldError> {
    authority
        .validate()
        .map_err(|e| RetentionHoldError::AuthorityRefused(e.to_string()))?;
    if !authority.allowed_planes.contains(&required_plane) {
        return Err(RetentionHoldError::AuthorityRefused(format!(
            "operation requires {required_plane:?} plane authority"
        )));
    }
    Ok(())
}

fn validate_rule(rule: &RetentionRule) -> Result<(), RetentionHoldError> {
    validate_text(&rule.rule_id, MAX_STORAGE_LABEL_BYTES, "rule_id")?;
    validate_text(
        &rule.object_prefix,
        MAX_STORAGE_LABEL_BYTES,
        "object_prefix",
    )?;
    if rule.min_retain_ns == 0 || rule.max_retain_ns < rule.min_retain_ns {
        return Err(RetentionHoldError::InvalidInput(format!(
            "invalid retention durations min={} max={}",
            rule.min_retain_ns, rule.max_retain_ns
        )));
    }
    if rule.authority_generation == 0 || rule.policy_epoch == 0 {
        return Err(RetentionHoldError::InvalidInput(
            "rule authority_generation and policy_epoch must be non-zero".to_owned(),
        ));
    }
    Ok(())
}

fn validate_hold(hold: &HoldObligation) -> Result<(), RetentionHoldError> {
    validate_text(&hold.hold_id, MAX_STORAGE_LABEL_BYTES, "hold_id")?;
    validate_text(&hold.reason, MAX_RETENTION_REASON_BYTES, "hold.reason")?;
    if let HoldTarget::ObjectPrefix(ref prefix) = hold.target {
        validate_text(prefix, MAX_STORAGE_LABEL_BYTES, "hold.target.prefix")?;
    }
    if let Some(exp) = hold.expires_at
        && exp.0 <= hold.placed_at.0
    {
        return Err(RetentionHoldError::InvalidInput(
            "hold expires_at must be strictly greater than placed_at".to_owned(),
        ));
    }
    if hold.authority_generation == 0 {
        return Err(RetentionHoldError::InvalidInput(
            "hold authority_generation must be non-zero".to_owned(),
        ));
    }
    if let HoldState::Released {
        released_at,
        release_authority_generation,
        ref release_reason,
        ..
    } = hold.state
    {
        if released_at.0 < hold.placed_at.0 || release_authority_generation == 0 {
            return Err(RetentionHoldError::InvalidInput(
                "invalid released hold timestamp or authority generation".to_owned(),
            ));
        }
        validate_text(release_reason, MAX_RETENTION_REASON_BYTES, "release_reason")?;
    }
    Ok(())
}

fn validate_text(value: &str, max_len: usize, label: &str) -> Result<(), RetentionHoldError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(RetentionHoldError::InvalidInput(format!(
            "{label} invalid length or contains control characters"
        )));
    }
    Ok(())
}
