#![forbid(unsafe_code)]
//! Deterministic seeded fault schedules, recovery guidance, and adversarial modes (FSS-132).
//!
//! All randomness uses an explicit self-contained 64-bit SplitMix PRNG over integer
//! parts-per-million rates (`0..=1_000_000`), avoiding floating-point drift and external
//! crate dependencies. Every schedule hashes into a canonical digest so fault campaigns
//! and reproducers are bit-identical across runs.

use fss_core::{CanonicalEncoder, ContentDigest};

/// Canonical digest domain for remote provider fault schedules.
pub const REMOTE_FAULT_SCHEDULE_DOMAIN: &str = "fss.remote_provider_fault_schedule.v1";

/// Maximum explicit fault rules allowed in one schedule.
pub const MAX_FAULT_RULES: usize = 256;

/// Maximum adversarial misbehavior entries allowed in one schedule.
pub const MAX_ADVERSARIAL_RULES: usize = 64;

/// Maximum per-operation wire framing charge admitted by a simulator schedule.
pub const MAX_FRAMING_BYTES_PER_OP: u64 = 64 * 1024;

/// Maximum parts-per-million value (100%).
pub const PPM_SCALE: u32 = 1_000_000;

/// Deterministic 64-bit SplitMix PRNG for reproducible fault campaigns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicPrng {
    state: u64,
}

impl DeterministicPrng {
    /// Seeds a deterministic generator.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Advances and returns the next 64-bit pseudo-random word.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Returns true with exact integer probability `rate_ppm / 1_000_000`.
    pub fn hit_ppm(&mut self, rate_ppm: u32) -> bool {
        if rate_ppm == 0 {
            return false;
        }
        if rate_ppm >= PPM_SCALE {
            return true;
        }
        (self.next_u64() % u64::from(PPM_SCALE)) < u64::from(rate_ppm)
    }

    /// Returns a deterministic index in `0..upper` (`0` when `upper == 0`).
    pub fn next_index(&mut self, upper: usize) -> usize {
        if upper == 0 {
            return 0;
        }
        (self.next_u64() % (upper as u64)) as usize
    }
}

/// Operation class that a fault rule or trace entry targets.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FaultOperation {
    /// `ObjectStoreProvider::stage`.
    Stage,
    /// `ObjectStoreProvider::advance`.
    Advance,
    /// `ObjectStoreProvider::activate_root`.
    ActivateRoot,
    /// `ObjectStoreProvider::deactivate_root`.
    DeactivateRoot,
    /// `ObjectStoreProvider::retire`.
    Retire,
    /// `ObjectStoreProvider::verify_retrievable`.
    VerifyRetrievable,
    /// `ObjectStoreProvider::state`.
    State,
    /// `MultipartTransport::initiate`.
    Initiate,
    /// `MultipartTransport::upload_part`.
    UploadPart,
    /// `MultipartTransport::complete`.
    Complete,
    /// `MultipartTransport::abort`.
    Abort,
    /// `MultipartTransport::reconcile`.
    Reconcile,
    /// `RemoteProviderSimulator::list_objects`.
    ListObjects,
    /// `RemoteProviderSimulator::list_multipart_parts`.
    ListMultipartParts,
    /// `RemoteProviderSimulator::put_object_conditional`.
    PutConditional,
    /// `RemoteProviderSimulator::head_object`.
    HeadObject,
    /// `RemoteProviderSimulator::get_object_verified`.
    GetObject,
    /// `RemoteProviderSimulator::delete_object_key`.
    DeleteObject,
}

impl FaultOperation {
    /// Stable lowercase spelling for logs and digests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Advance => "advance",
            Self::ActivateRoot => "activate_root",
            Self::DeactivateRoot => "deactivate_root",
            Self::Retire => "retire",
            Self::VerifyRetrievable => "verify_retrievable",
            Self::State => "state",
            Self::Initiate => "initiate",
            Self::UploadPart => "upload_part",
            Self::Complete => "complete",
            Self::Abort => "abort",
            Self::Reconcile => "reconcile",
            Self::ListObjects => "list_objects",
            Self::ListMultipartParts => "list_multipart_parts",
            Self::PutConditional => "put_conditional",
            Self::HeadObject => "head_object",
            Self::GetObject => "get_object",
            Self::DeleteObject => "delete_object",
        }
    }

    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Stage => 1,
            Self::Advance => 2,
            Self::ActivateRoot => 3,
            Self::DeactivateRoot => 4,
            Self::Retire => 5,
            Self::VerifyRetrievable => 6,
            Self::State => 7,
            Self::Initiate => 8,
            Self::UploadPart => 9,
            Self::Complete => 10,
            Self::Abort => 11,
            Self::Reconcile => 12,
            Self::ListObjects => 13,
            Self::ListMultipartParts => 14,
            Self::PutConditional => 15,
            Self::HeadObject => 16,
            Self::GetObject => 17,
            Self::DeleteObject => 18,
        }
    }
}

/// Fault behavior injected at a targeted simulator boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultKind {
    /// Fails before mutating remote state (transient network/service outage).
    FailBeforeEffect,
    /// Commits the mutation on the authoritative backend, then drops the acknowledgement.
    LostAckAfterEffect,
    /// Refuses before mutating with a rate-limit / service-pressure signal (429/503).
    ThrottleRateLimit,
    /// Refuses before mutating as if remote quota/capacity were exhausted.
    QuotaExceeded,
    /// Overrides visibility lag for this mutation (`visible_at_epoch = commit_epoch + lag_steps`).
    EventualVisibilityLag {
        /// Logical epochs before readers/listers observe the committed mutation.
        lag_steps: u64,
    },
    /// Omits up to `omit_count` entries from a list page to model partial eventual listings.
    PartialListOmission {
        /// Maximum entries omitted from the matching list page.
        omit_count: usize,
    },
    /// Forces a smaller page ceiling on list pagination to test continuation traversal.
    TruncateListPage {
        /// Maximum entries emitted on this page (`>= 1`).
        forced_max_keys: usize,
    },
    /// Rejects the next paginated list call as an expired/invalid continuation token.
    CorruptContinuationToken,
    /// Flips a deterministic bit on readback to prove digest verification rejects corruption.
    CorruptReadback,
    /// Advances the admitted `TransportCx` clock by `delta_ns` before executing the call.
    ClockStepOnCheckpoint {
        /// Signed nanosecond offset applied during `TransportCx::checkpoint`.
        delta_ns: i128,
    },
}

impl FaultKind {
    /// Stable lowercase spelling for structured trace logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailBeforeEffect => "fail_before_effect",
            Self::LostAckAfterEffect => "lost_ack_after_effect",
            Self::ThrottleRateLimit => "throttle_rate_limit",
            Self::QuotaExceeded => "quota_exceeded",
            Self::EventualVisibilityLag { .. } => "eventual_visibility_lag",
            Self::PartialListOmission { .. } => "partial_list_omission",
            Self::TruncateListPage { .. } => "truncate_list_page",
            Self::CorruptContinuationToken => "corrupt_continuation_token",
            Self::CorruptReadback => "corrupt_readback",
            Self::ClockStepOnCheckpoint { .. } => "clock_step_on_checkpoint",
        }
    }

    pub(crate) fn encode_canonical(self, enc: &mut CanonicalEncoder) {
        match self {
            Self::FailBeforeEffect => enc.u8(1),
            Self::LostAckAfterEffect => enc.u8(2),
            Self::ThrottleRateLimit => enc.u8(3),
            Self::QuotaExceeded => enc.u8(4),
            Self::EventualVisibilityLag { lag_steps } => {
                enc.u8(5);
                enc.u64(lag_steps);
            }
            Self::PartialListOmission { omit_count } => {
                enc.u8(6);
                enc.u64(omit_count as u64);
            }
            Self::TruncateListPage { forced_max_keys } => {
                enc.u8(7);
                enc.u64(forced_max_keys as u64);
            }
            Self::CorruptContinuationToken => enc.u8(8),
            Self::CorruptReadback => enc.u8(9),
            Self::ClockStepOnCheckpoint { delta_ns } => {
                enc.u8(10);
                enc.bool(delta_ns < 0);
                let mag = delta_ns.unsigned_abs();
                enc.u64((mag >> 64) as u64);
                enc.u64(mag as u64);
            }
        }
    }
}

/// Explicit opt-in adversarial remote provider misbehavior for negative-control testing.
///
/// Honest providers never emit these responses; enabling one tests that `MultipartSession`
/// and `StagedUpload` refuse forged or inconsistent provider observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdversarialMisbehavior {
    /// Returns a corrupted part checksum once on `upload_part`.
    WrongPartChecksumOnce,
    /// Returns a mismatched `intent_digest` once on `reconcile`.
    WrongIntentDigestOnReconcileOnce,
    /// Claims `Completed` on `reconcile` even though `complete` was never dispatched.
    ForgedCompletedWithoutCompleteOnce,
    /// Omits an already acknowledged part from an `Active` inventory once on `reconcile`.
    OmitAcknowledgedPartInActiveReconcileOnce,
    /// Returns a mismatched `UploadId` once on `reconcile`.
    UnexpectedUploadIdOnReconcileOnce,
}

impl AdversarialMisbehavior {
    /// Stable spelling for trace output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongPartChecksumOnce => "wrong_part_checksum_once",
            Self::WrongIntentDigestOnReconcileOnce => "wrong_intent_digest_on_reconcile_once",
            Self::ForgedCompletedWithoutCompleteOnce => "forged_completed_without_complete_once",
            Self::OmitAcknowledgedPartInActiveReconcileOnce => {
                "omit_acknowledged_part_in_active_reconcile_once"
            }
            Self::UnexpectedUploadIdOnReconcileOnce => "unexpected_upload_id_on_reconcile_once",
        }
    }

    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::WrongPartChecksumOnce => 1,
            Self::WrongIntentDigestOnReconcileOnce => 2,
            Self::ForgedCompletedWithoutCompleteOnce => 3,
            Self::OmitAcknowledgedPartInActiveReconcileOnce => 4,
            Self::UnexpectedUploadIdOnReconcileOnce => 5,
        }
    }
}

/// One deterministic targeted fault rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRule {
    /// Operation class matched by this rule.
    pub operation: FaultOperation,
    /// Optional 1-based per-operation call ordinal; `None` matches every occurrence.
    pub occurrence: Option<u64>,
    /// Optional content or intent digest filter; `None` matches any target.
    pub target_digest: Option<ContentDigest>,
    /// Fault injected when matched.
    pub kind: FaultKind,
}

impl FaultRule {
    /// Convenience constructor matching the `nth` (1-based) invocation of `operation`.
    #[must_use]
    pub const fn on_nth(operation: FaultOperation, nth: u64, kind: FaultKind) -> Self {
        Self {
            operation,
            occurrence: Some(nth),
            target_digest: None,
            kind,
        }
    }

    /// Convenience constructor matching every invocation of `operation`.
    #[must_use]
    pub const fn always(operation: FaultOperation, kind: FaultKind) -> Self {
        Self {
            operation,
            occurrence: None,
            target_digest: None,
            kind,
        }
    }

    /// Restricts this rule to one exact content or intent digest.
    #[must_use]
    pub const fn for_digest(mut self, digest: ContentDigest) -> Self {
        self.target_digest = Some(digest);
        self
    }

    pub(crate) fn matches(
        &self,
        operation: FaultOperation,
        ordinal: u64,
        target: Option<ContentDigest>,
    ) -> bool {
        if self.operation != operation {
            return false;
        }
        if let Some(expected) = self.occurrence
            && expected != ordinal
        {
            return false;
        }
        if let Some(expected_digest) = self.target_digest
            && target != Some(expected_digest)
        {
            return false;
        }
        true
    }
}

/// Seeded integer parts-per-million (`0..=1_000_000`) fault rates for property/fuzz campaigns.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FaultRatesPpm {
    /// Probability of failing before committing an effect.
    pub fail_before_effect_ppm: u32,
    /// Probability of committing an effect then dropping its acknowledgement.
    pub lost_ack_ppm: u32,
    /// Probability of rate-limit throttling before effect.
    pub throttle_ppm: u32,
    /// Probability of omitting at least one entry from a list page.
    pub partial_list_omission_ppm: u32,
    /// Probability of forcing early page truncation on list calls.
    pub truncate_list_ppm: u32,
}

impl FaultRatesPpm {
    /// Validates every rate is within `0..=1_000_000`.
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("fail_before_effect_ppm", self.fail_before_effect_ppm),
            ("lost_ack_ppm", self.lost_ack_ppm),
            ("throttle_ppm", self.throttle_ppm),
            ("partial_list_omission_ppm", self.partial_list_omission_ppm),
            ("truncate_list_ppm", self.truncate_list_ppm),
        ] {
            if value > PPM_SCALE {
                return Err(format!("{name} ({value}) exceeds {PPM_SCALE}"));
            }
        }
        Ok(())
    }

    pub(crate) fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.fail_before_effect_ppm);
        enc.u32(self.lost_ack_ppm);
        enc.u32(self.throttle_ppm);
        enc.u32(self.partial_list_omission_ppm);
        enc.u32(self.truncate_list_ppm);
    }
}

/// Complete, canonicalizable fault schedule for [`super::RemoteProviderSimulator`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteFaultSchedule {
    /// Deterministic PRNG seed.
    pub seed: u64,
    /// Default logical epochs before newly committed writes appear in read/list views.
    pub default_visibility_lag: u64,
    /// Logical epochs retired/deleted keys linger as stale ghost entries in `LIST`.
    pub ghost_retention_steps: u64,
    /// Simulated wire-framing byte overhead charged through `TransportCx::charge_io`.
    pub framing_bytes_per_op: u64,
    /// Ordered targeted deterministic rules.
    pub rules: Vec<FaultRule>,
    /// Optional seeded probabilistic campaign rates.
    pub rates: FaultRatesPpm,
    /// Explicit opt-in adversarial misbehaviors (empty for honest providers).
    pub adversarial: Vec<AdversarialMisbehavior>,
}

impl RemoteFaultSchedule {
    /// Zero-fault, zero-lag schedule that preserves exact reference provider parity.
    #[must_use]
    pub fn clean(seed: u64) -> Self {
        Self {
            seed,
            default_visibility_lag: 0,
            ghost_retention_steps: 0,
            framing_bytes_per_op: 0,
            rules: Vec::new(),
            rates: FaultRatesPpm::default(),
            adversarial: Vec::new(),
        }
    }

    /// Builder helper setting default eventual-visibility lag.
    #[must_use]
    pub const fn with_visibility_lag(mut self, lag_steps: u64) -> Self {
        self.default_visibility_lag = lag_steps;
        self
    }

    /// Builder helper setting post-retirement/delete stale ghost retention in `LIST`.
    #[must_use]
    pub const fn with_ghost_retention(mut self, steps: u64) -> Self {
        self.ghost_retention_steps = steps;
        self
    }

    /// Builder helper setting wire-framing byte charge per multipart transport call.
    #[must_use]
    pub const fn with_framing_bytes(mut self, bytes: u64) -> Self {
        self.framing_bytes_per_op = bytes;
        self
    }

    /// Builder helper appending one targeted fault rule.
    #[must_use]
    pub fn with_rule(mut self, rule: FaultRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Builder helper setting integer parts-per-million fault rates.
    #[must_use]
    pub const fn with_rates(mut self, rates: FaultRatesPpm) -> Self {
        self.rates = rates;
        self
    }

    /// Builder helper appending one opt-in adversarial misbehavior.
    #[must_use]
    pub fn with_adversarial(mut self, mode: AdversarialMisbehavior) -> Self {
        self.adversarial.push(mode);
        self
    }

    /// Validates all bounds before constructing a simulator.
    pub fn validate(&self) -> Result<(), String> {
        if self.rules.len() > MAX_FAULT_RULES {
            return Err(format!(
                "fault rules ({}) exceed ceiling {MAX_FAULT_RULES}",
                self.rules.len()
            ));
        }
        if self.adversarial.len() > MAX_ADVERSARIAL_RULES {
            return Err(format!(
                "adversarial rules ({}) exceed ceiling {MAX_ADVERSARIAL_RULES}",
                self.adversarial.len()
            ));
        }
        if self.framing_bytes_per_op > MAX_FRAMING_BYTES_PER_OP {
            return Err(format!(
                "framing_bytes_per_op ({}) exceeds ceiling {MAX_FRAMING_BYTES_PER_OP}",
                self.framing_bytes_per_op
            ));
        }
        for rule in &self.rules {
            if let Some(0) = rule.occurrence {
                return Err("fault rule occurrence is 1-based and must be >= 1".to_owned());
            }
            if let FaultKind::TruncateListPage { forced_max_keys: 0 } = rule.kind {
                return Err("TruncateListPage forced_max_keys must be >= 1".to_owned());
            }
        }
        self.rates.validate()
    }

    /// Canonical SHA-256 identity of this exact fault schedule.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(REMOTE_FAULT_SCHEDULE_DOMAIN);
        enc.u64(self.seed);
        enc.u64(self.default_visibility_lag);
        enc.u64(self.ghost_retention_steps);
        enc.u64(self.framing_bytes_per_op);
        enc.u64(self.rules.len() as u64);
        for rule in &self.rules {
            enc.u8(rule.operation.tag());
            enc.bool(rule.occurrence.is_some());
            if let Some(n) = rule.occurrence {
                enc.u64(n);
            }
            enc.bool(rule.target_digest.is_some());
            if let Some(d) = rule.target_digest {
                enc.digest(d);
            }
            rule.kind.encode_canonical(&mut enc);
        }
        self.rates.encode_canonical(&mut enc);
        enc.u64(self.adversarial.len() as u64);
        for mode in &self.adversarial {
            enc.u8(mode.tag());
        }
        ContentDigest::sha256(&enc.finish())
    }
}

/// Safe operator/agent recovery action paired with every simulator refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryGuidance {
    /// Safe to retry the exact same immutable intent without changing identity.
    RetrySameIntent,
    /// Effect outcome is uncertain; reconcile by exact intent before any retry or abort.
    ReconcileBeforeRetry,
    /// Authoritative write is lagging on the read/list view; wait/advance visibility and re-probe.
    WaitVisibilityAndRetry,
    /// Continuation cursor is invalid or expired; restart pagination from the beginning.
    ResetPaginationFromStart,
    /// Readback digest mismatch detected; quarantine replica and repair from verified manifest.
    QuarantineAndRepairFromManifest,
    /// Backpressure or quota refusal; respect backoff/budget or settle indeterminate locally.
    BackoffOrSettleIndeterminate,
    /// Conditional precondition failed; reload current remote state and revalidate plan.
    RevalidateConditionalPrecondition,
    /// Caller request, bounds, or authority is invalid; fix inputs before retrying.
    FixRequestOrAuthority,
}

impl RecoveryGuidance {
    /// Stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetrySameIntent => "retry_same_intent",
            Self::ReconcileBeforeRetry => "reconcile_before_retry",
            Self::WaitVisibilityAndRetry => "wait_visibility_and_retry",
            Self::ResetPaginationFromStart => "reset_pagination_from_start",
            Self::QuarantineAndRepairFromManifest => "quarantine_and_repair_from_manifest",
            Self::BackoffOrSettleIndeterminate => "backoff_or_settle_indeterminate",
            Self::RevalidateConditionalPrecondition => "revalidate_conditional_precondition",
            Self::FixRequestOrAuthority => "fix_request_or_authority",
        }
    }
}
