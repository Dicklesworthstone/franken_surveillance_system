#![forbid(unsafe_code)]
//! Direct Rust API, CLI, and MCP transcript-equivalence harness (`FSS-235`).
//!
//! Semantic plane: `"cognition"` (pure deterministic projection, normalization,
//! comparison, and cryptographic receipt generation over surface transcripts;
//! this module never executes external effects and never grants effect
//! authority — `grants_effect_authority` is always `false`).
//!
//! # Guarantees
//! - Every surface response (`RustApi`, `Cli`, `Mcp`) is strictly parsed with
//!   `fss_core::json_input::parse_mcp_reply` under bounded byte ceilings
//!   (`MAX_SURFACE_OUTPUT_BYTES = 4 MiB`).
//! - Task-critical semantic coordinates — `schema`, `operationId`, `outcome`,
//!   `errorId`, `epistemicState`, `completeness`, `principalId`,
//!   `effectiveViewId`, `effectiveCapabilities`, `payloadSchema`,
//!   `contractBasis`, `worldEnvelope` digest, `affordances` (control-envelope
//!   robustness classes), `warnings`, `contradictions`, `degradation`,
//!   `recoveryClass`, `safeRetry`, `resnapshotRequired`, `doctor` verdict, and
//!   `activePolicyMutation` — are **protected** and can never be stripped by
//!   any [`NormalizationPolicy`].
//! - Under [`NormalizationPolicy::exact`], **zero** keys are ignored: all three
//!   surfaces must match bit-for-bit on canonical sorted JSON as well as on
//!   `payloadDigest` and `decisionFingerprint`.
//! - Under [`NormalizationPolicy::stateful_clone`], wall-clock timestamps and
//!   instance-scoped identifiers produced by three independent deployment
//!   clones may be normalized while preserving every semantic invariant,
//!   epistemic cell, contradiction, warning, coverage boundary, execution
//!   boundary, and control-envelope classification.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::time::Instant;

use fss_core::json_input::{Value, parse_mcp_reply};
use fss_core::{CanonicalEncoder, ContentDigest};

use crate::agent_json::{array, object, optional_string, string, strings};
use crate::diagnostic::escape_json_str;
use crate::error::ExitIdentity;
use crate::fss_cmd::{execute_live_fss_with_exit, parse_fss_args};

/// Maximum number of transcript steps admitted into one equivalence report.
pub const MAX_TRANSCRIPT_STEPS: usize = 256;
/// Maximum UTF-8 byte length admitted for a single surface response (4 MiB).
pub const MAX_SURFACE_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of volatile keys in a custom normalization policy.
pub const MAX_IGNORED_KEYS: usize = 128;
/// Maximum number of literal string substitutions per surface.
pub const MAX_TOKEN_SUBSTITUTIONS: usize = 32;

// Non-wire internal domain tags (intentionally not registered `fss.*.v1` wire schemas).
const CANONICAL_JSON_HASH_TAG: &str = "transcript-equivalence-canonical-json-v1";
const CONTRACT_BASIS_HASH_TAG: &str = "transcript-equivalence-contract-basis-v1";
const STEP_RECEIPT_HASH_TAG: &str = "transcript-equivalence-step-v1";
const REPORT_RECEIPT_HASH_TAG: &str = "transcript-equivalence-report-v1";

/// Keys that carry epistemic, authority, safety, outcome, or control-envelope
/// meaning and therefore **cannot** be stripped by any [`NormalizationPolicy`].
pub const PROTECTED_SEMANTIC_KEYS: &[&str] = &[
    "schema",
    "operationId",
    "outcome",
    "errorId",
    "epistemicState",
    "completeness",
    "principalId",
    "effectiveViewId",
    "effectiveCapabilities",
    "effectivePrivacyProjection",
    "payloadSchema",
    "contractBasis",
    "warnings",
    "contradictions",
    "degradation",
    "affordances",
    "recoveryClass",
    "safeRetry",
    "resnapshotRequired",
    "verdict",
    "possibly_stale",
    "state",
    "activePolicyMutation",
    "knowledgeState",
    "provenanceClass",
    "hypothesisDisposition",
    "notObservableDomain",
    "omittedCount",
    "omissionReasons",
    "stopReason",
    "executionBoundary",
    "preservedTruth",
    "possiblyOccurred",
    "worldEnvelope",
    "worldEnvelopeDigest",
];

/// Public control-plane execution surface participating in equivalence proof.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SurfaceKind {
    /// Direct in-process Rust library API (`parse_fss_args` + `execute_live_fss_with_exit`).
    RustApi,
    /// Standalone `fss` CLI binary over OS argv and stdout/exit code.
    Cli,
    /// Standalone `fss-mcp` stdio JSON-RPC 2.0 server (`tools/call`).
    Mcp,
}

impl SurfaceKind {
    /// Canonical stable surface name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RustApi => "rust_api",
            Self::Cli => "cli",
            Self::Mcp => "mcp",
        }
    }
}

impl fmt::Display for SurfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable error identity for transcript-equivalence harness validation and execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EquivalenceError {
    /// A surface response exceeded `MAX_SURFACE_OUTPUT_BYTES` or was empty.
    OutputBudgetExceeded {
        /// Surface whose output violated bounds.
        surface: SurfaceKind,
        /// Observed byte length.
        observed_bytes: usize,
        /// Maximum admitted byte length.
        max_bytes: usize,
    },
    /// A surface response was not valid strict JSON (or not a JSON object).
    InvalidSurfaceJson {
        /// Surface whose output failed strict JSON parsing.
        surface: SurfaceKind,
        /// Safe diagnostic detail (never raw secret bytes).
        detail: String,
    },
    /// The caller tried to ignore a protected semantic key or exceed policy bounds.
    InvalidNormalizationPolicy {
        /// Safe diagnostic detail.
        detail: String,
    },
    /// Direct Rust API command parsing failed.
    RustApiParseFailed {
        /// Stable CLI error ID from `parse_fss_args`.
        error_id: String,
        /// Safe diagnostic detail.
        detail: String,
    },
    /// Report step count was zero or exceeded `MAX_TRANSCRIPT_STEPS`.
    InvalidStepCount {
        /// Observed step count.
        observed: usize,
        /// Maximum admitted step count.
        max: usize,
    },
}

impl EquivalenceError {
    /// Stable registered-style error class identifier.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::OutputBudgetExceeded { .. } => "EQUIV-OUTPUT-BUDGET",
            Self::InvalidSurfaceJson { .. } => "EQUIV-INVALID-JSON",
            Self::InvalidNormalizationPolicy { .. } => "EQUIV-INVALID-POLICY",
            Self::RustApiParseFailed { .. } => "EQUIV-RUST-API-PARSE",
            Self::InvalidStepCount { .. } => "EQUIV-INVALID-STEPS",
        }
    }
}

impl fmt::Display for EquivalenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputBudgetExceeded {
                surface,
                observed_bytes,
                max_bytes,
            } => write!(
                f,
                "{}: {surface} output size {observed_bytes} bytes violates 1..={max_bytes}",
                self.code()
            ),
            Self::InvalidSurfaceJson { surface, detail } => {
                write!(f, "{}: {surface} JSON error: {detail}", self.code())
            }
            Self::InvalidNormalizationPolicy { detail } => {
                write!(f, "{}: {detail}", self.code())
            }
            Self::RustApiParseFailed { error_id, detail } => {
                write!(f, "{}: {error_id}: {detail}", self.code())
            }
            Self::InvalidStepCount { observed, max } => {
                write!(
                    f,
                    "{}: step count {observed} outside 1..={max}",
                    self.code()
                )
            }
        }
    }
}

impl Error for EquivalenceError {}

/// Explicit, fail-closed normalization policy governing cross-surface comparison.
///
/// Protected semantic keys (`PROTECTED_SEMANTIC_KEYS`) can never be ignored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizationPolicy {
    /// Policy mode name for receipts and logs (`"exact"` or `"stateful_clone"`).
    pub mode: String,
    /// Keys recursively stripped before canonical JSON hashing (must never intersect
    /// [`PROTECTED_SEMANTIC_KEYS`]).
    pub ignored_keys: BTreeSet<String>,
    /// Whether `payloadDigest` is permitted to differ across independently timed clones.
    pub ignore_payload_digest: bool,
    /// Whether `decisionFingerprint` is permitted to differ across independently timed clones.
    pub ignore_decision_fingerprint: bool,
    /// Whether `approvalDigest` is permitted to differ across independently timed clones.
    pub ignore_approval_digest: bool,
}

impl NormalizationPolicy {
    /// Exact zero-stripping equivalence mode for read-only, query, explain,
    /// follow, doctor, and refusal comparisons against one shared deployment.
    #[must_use]
    pub fn exact() -> Self {
        Self {
            mode: "exact".to_owned(),
            ignored_keys: BTreeSet::new(),
            ignore_payload_digest: false,
            ignore_decision_fingerprint: false,
            ignore_approval_digest: false,
        }
    }

    /// Controlled stateful-clone equivalence mode for three bit-identical
    /// isolated deployment clones executing stateful session/case/effect/handoff
    /// mutations at distinct host wall-clock instants.
    ///
    /// Strips ONLY wall-clock nanosecond timestamps and host-clock-derived
    /// instance identifiers/digests while preserving every semantic invariant,
    /// epistemic state, contradiction, warning, coverage witness, execution
    /// boundary, and affordance classification.
    #[must_use]
    pub fn stateful_clone() -> Self {
        let ignored_keys = [
            "createdAtNs",
            "updatedAtNs",
            "openedAtNs",
            "issuedAtNs",
            "expiresAtNs",
            "expiryNs",
            "validUntilNs",
            "decisionDeadlineNs",
            "deadlineNs",
            "admissionTimeNs",
            "admittedAtNs",
            "leaseExpiresAtNs",
            "watermarkNs",
            "lastSeenAtNs",
            "recordedAtNs",
            "evaluatedAtNs",
            "observedAtNs",
            "publishedAtNs",
            "closedAtNs",
            "dispatchedAtNs",
            "reconciledAtNs",
            "cancelledAtNs",
            "preparedAtNs",
            "committedNs",
            "observedNs",
            "preparedNs",
            "requestedNs",
            "verifiedNs",
            "retentionUntilNs",
            "reviewAfterNs",
            "resultDigest",
            "requestId",
            "requestDigest",
            "responseId",
            "traceId",
            "taskId",
            "sessionId",
            "sourceSessionId",
            "missionId",
            "workspaceId",
            "handoffId",
            "handoffRoot",
            "planId",
            "claimId",
            "proposalId",
            "feedbackId",
            "episodeId",
            "objectiveId",
            "objectiveDigest",
            "worldEnvelopeId",
            "envelopeId",
            "envelopeDigest",
            "packId",
            "packDigest",
            "receiptId",
            "publicationReceiptId",
            "idempotencyKey",
            "compressionReceiptId",
            "sessionCapsuleDigest",
            "situationCapsuleDigest",
            "situationCapsuleRoot",
            "situationFingerprint",
            "situationFrameDigest",
            "selectionFrontierDigest",
            "decisionPathDigest",
            "hypothesisWorkspaceDigest",
            "decisionDigest",
            "decisionFingerprint",
            "payloadDigest",
            "proofPointers",
            "revisionDigest",
            "handoffDigest",
            "capsuleDigest",
            "episodeDigest",
            "proposalDigest",
            "feedbackDigest",
            "planDigest",
            "receiptDigest",
            "objectDigest",
            "outputDigest",
            "witnessDigest",
            "unresolvedOutcomeRoot",
            "continuation",
            "cursor",
            "anchorToken",
            "authorityRoot",
            "stateRoot",
            "digest",
            "leaseId",
            "fencingToken",
            "incarnation",
            "networkBytes",
            "latencyMs",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();

        Self {
            mode: "stateful_clone".to_owned(),
            ignored_keys,
            ignore_payload_digest: true,
            ignore_decision_fingerprint: true,
            ignore_approval_digest: false,
        }
    }

    /// Validates that no protected semantic key is ignored and all policy bounds hold.
    pub fn validate(&self) -> Result<(), EquivalenceError> {
        if self.mode.is_empty() || self.mode.len() > 64 || self.mode.chars().any(char::is_control) {
            return Err(EquivalenceError::InvalidNormalizationPolicy {
                detail: "policy mode must be 1..=64 control-free characters".to_owned(),
            });
        }
        if self.ignored_keys.len() > MAX_IGNORED_KEYS {
            return Err(EquivalenceError::InvalidNormalizationPolicy {
                detail: format!(
                    "ignored_keys length {} exceeds {MAX_IGNORED_KEYS}",
                    self.ignored_keys.len()
                ),
            });
        }
        for key in &self.ignored_keys {
            if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
                return Err(EquivalenceError::InvalidNormalizationPolicy {
                    detail: "ignored_keys entries must be 1..=128 control-free characters"
                        .to_owned(),
                });
            }
            if PROTECTED_SEMANTIC_KEYS.contains(&key.as_str()) {
                return Err(EquivalenceError::InvalidNormalizationPolicy {
                    detail: format!(
                        "refused policy attempting to strip protected semantic key `{key}`"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Deterministic digest of the policy configuration itself.
    #[must_use]
    pub fn policy_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("normalization-policy-v1");
        enc.text(&self.mode);
        enc.bool(self.ignore_payload_digest);
        enc.bool(self.ignore_decision_fingerprint);
        enc.bool(self.ignore_approval_digest);
        enc.u64(self.ignored_keys.len() as u64);
        for key in &self.ignored_keys {
            enc.text(key);
        }
        ContentDigest::sha256(&enc.finish())
    }
}

/// Optional per-surface literal token substitutions applied to string leaves
/// during canonical JSON projection (for example replacing each stateful clone's
/// concrete `session_id` or temporary deployment root with a canonical placeholder
/// like `<SESSION_ID>` or `<DEPLOY_ROOT>` so prose/executionBoundary/affordance
/// checks remain strict across isolated clones).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenNormalizer {
    replacements: Vec<(String, String)>,
    normalize_embedded_unix_ns: bool,
    normalize_embedded_sha256: bool,
    normalize_instance_ids: bool,
}

impl TokenNormalizer {
    /// Empty no-op normalizer (leaves every string byte untouched).
    #[must_use]
    pub const fn none() -> Self {
        Self {
            replacements: Vec::new(),
            normalize_embedded_unix_ns: false,
            normalize_embedded_sha256: false,
            normalize_instance_ids: false,
        }
    }

    /// Stateful-clone normalizer for three isolated deployment clones executing
    /// host-clock-timed mutations at distinct wall-clock instants.
    ///
    /// Masks ONLY:
    /// - standalone 19-digit Unix nanosecond timestamps -> `<UNIX_NS>`,
    /// - `sha256:<64 lower-hex>` publication digests inside prose -> `<SHA256>`, and
    /// - wall-clock-seeded hex instance IDs (`session:`, `mission:`, `handoff:`,
    ///   `plan:`, `claim:`, `feedback:`, `episode:`, `proposal:`, `worlds:`,
    ///   `capsule:`, `frame:`, `pack:`, `receipt:`, `obj:`) -> `<prefix>:<HEX_ID>`.
    ///
    /// Never used in [`NormalizationPolicy::exact`] mode; all semantic invariants
    /// and deterministic content approvals remain compared verbatim.
    #[must_use]
    pub const fn stateful_clone() -> Self {
        Self {
            replacements: Vec::new(),
            normalize_embedded_unix_ns: true,
            normalize_embedded_sha256: true,
            normalize_instance_ids: true,
        }
    }

    /// Returns `true` when this normalizer performs zero literal substitutions
    /// and zero heuristic token masking.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.replacements.is_empty()
            && !self.normalize_embedded_unix_ns
            && !self.normalize_embedded_sha256
            && !self.normalize_instance_ids
    }

    /// Adds a literal `(needle, placeholder)` substitution.
    pub fn push(
        &mut self,
        needle: impl Into<String>,
        placeholder: impl Into<String>,
    ) -> Result<(), EquivalenceError> {
        let needle = needle.into();
        let placeholder = placeholder.into();
        if needle.is_empty() || placeholder.is_empty() {
            return Err(EquivalenceError::InvalidNormalizationPolicy {
                detail: "token substitution needle and placeholder must be non-empty".to_owned(),
            });
        }
        if self.replacements.len() >= MAX_TOKEN_SUBSTITUTIONS {
            return Err(EquivalenceError::InvalidNormalizationPolicy {
                detail: format!("token substitutions exceed {MAX_TOKEN_SUBSTITUTIONS}"),
            });
        }
        self.replacements.push((needle, placeholder));
        Ok(())
    }

    fn apply(&self, input: &str) -> String {
        let mut out = input.to_owned();
        for (needle, placeholder) in &self.replacements {
            if out.contains(needle.as_str()) {
                out = out.replace(needle.as_str(), placeholder.as_str());
            }
        }
        if self.normalize_embedded_sha256 {
            out = mask_embedded_sha256(&out);
        }
        if self.normalize_instance_ids {
            out = mask_instance_hex_ids(&out);
            out = mask_anchor_binding_hashes(&out);
        }
        if self.normalize_embedded_unix_ns {
            out = mask_embedded_unix_ns(&out);
        }
        out
    }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Masks ONLY the trailing 64-hex binding digest of `anchor:<16hex>:<commit>:<effects>:<64hex>`
/// while preserving `<site>:<commit>:<effects>` verbatim so commit/effect drift still fails closed.
fn mask_anchor_binding_hashes(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0_usize;
    while i < bytes.len() {
        let prev_is_word = i > 0 && is_word_byte(bytes[i - 1]);
        if !prev_is_word && input[i..].starts_with("anchor:") {
            let tail = &input[i..];
            // anchor:<16hex>:<digits>:<e<digits>|none>:<64hex>
            let mut segs = tail.splitn(6, ':');
            if let (Some("anchor"), Some(site), Some(commit), Some(effects), Some(rest)) = (
                segs.next(),
                segs.next(),
                segs.next(),
                segs.next(),
                segs.next(),
            ) {
                let binding_candidate = rest.as_bytes();
                let is_lower_hex = |s: &[u8]| {
                    s.iter()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                };
                if site.len() == 16
                    && is_lower_hex(site.as_bytes())
                    && !commit.is_empty()
                    && commit.bytes().all(|b| b.is_ascii_digit())
                    && (effects == "none"
                        || effects.strip_prefix('e').is_some_and(|d| {
                            !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())
                        }))
                    && binding_candidate.len() >= 64
                    && is_lower_hex(&binding_candidate[..64])
                    && (binding_candidate.len() == 64 || !binding_candidate[64].is_ascii_hexdigit())
                {
                    let prefix_len = 7 + site.len() + 1 + commit.len() + 1 + effects.len() + 1;
                    out.push_str(&input[i..i + prefix_len]);
                    out.push_str("<ANCHOR_BINDING>");
                    i += prefix_len + 64;
                    continue;
                }
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn mask_embedded_sha256(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0_usize;
    while i < bytes.len() {
        let prev_is_word = i > 0 && is_word_byte(bytes[i - 1]);
        if !prev_is_word && input[i..].starts_with("sha256:") && i + 7 + 64 <= bytes.len() {
            let hex = &bytes[i + 7..i + 7 + 64];
            let next_is_hex = i + 7 + 64 < bytes.len() && bytes[i + 7 + 64].is_ascii_hexdigit();
            if !next_is_hex
                && hex
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            {
                out.push_str("<SHA256>");
                i += 7 + 64;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn mask_instance_hex_ids(input: &str) -> String {
    const PREFIXES: &[&str] = &[
        "session:",
        "mission:",
        "handoff:",
        "plan:",
        "claim:",
        "feedback:",
        "episode:",
        "proposal:",
        "worlds:",
        "capsule:",
        "frame:",
        "pack:",
        "receipt:",
        "obj:",
        "alert-wire-",
        "episode-",
        "feedback-",
        "handoff-",
        "plan-",
        "session-",
    ];
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0_usize;
    while i < bytes.len() {
        let mut matched = false;
        let prev_is_word = i > 0 && is_word_byte(bytes[i - 1]);
        if !prev_is_word {
            for prefix in PREFIXES {
                if input[i..].starts_with(prefix) {
                    let hex_start = i + prefix.len();
                    let mut hex_end = hex_start;
                    while hex_end < bytes.len()
                        && (bytes[hex_end].is_ascii_digit()
                            || (b'a'..=b'f').contains(&bytes[hex_end]))
                    {
                        hex_end += 1;
                    }
                    let hex_len = hex_end - hex_start;
                    let next_is_alnum =
                        hex_end < bytes.len() && bytes[hex_end].is_ascii_alphanumeric();
                    if hex_len >= 16 && !next_is_alnum {
                        out.push_str(prefix);
                        out.push_str("<HEX_ID>");
                        i = hex_end;
                        matched = true;
                        break;
                    }
                }
            }
        }
        if !matched {
            let ch = input[i..].chars().next().unwrap_or('\0');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Replaces standalone 19-digit Unix nanosecond timestamps (`2020..2039`) inside
/// prose strings with `<UNIX_NS>` without touching hex digests or shorter numbers.
fn mask_embedded_unix_ns(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0_usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let slice = &input[start..i];
            let prev_is_hex_or_word =
                start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
            let next_is_hex_or_word =
                i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_');
            let is_unix_ns = slice.len() == 19
                && !prev_is_hex_or_word
                && !next_is_hex_or_word
                && slice.parse::<u64>().is_ok_and(|ns| {
                    (1_600_000_000_000_000_000..=2_200_000_000_000_000_000).contains(&ns)
                });
            if is_unix_ns {
                out.push_str("<UNIX_NS>");
            } else {
                out.push_str(slice);
            }
        } else {
            let ch = input[i..].chars().next().unwrap_or('\0');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Extracted control-envelope affordance classification (`(affordanceId, robustnessClass)`).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AffordanceClassification {
    /// Registered affordance identifier.
    pub affordance_id: String,
    /// Control-envelope robustness class (`robust`, `conditional`, `information_gathering`,
    /// `wait_and_watch`, `blocked`, `unavailable`, etc.).
    pub robustness_class: String,
}

/// Extracted typed semantic projection of one surface execution response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticProjection {
    /// Which public surface produced this response.
    pub surface: SurfaceKind,
    /// Whether the surface reported an error outcome (non-zero CLI exit or MCP `isError`).
    pub is_error: bool,
    /// Top-level JSON `schema` identifier (`fss.agent_response_envelope.v1` or `fss.doctor.v1`).
    pub schema: String,
    /// Registered operation ID (`AOP-001`..`AOP-014`) when present.
    pub operation_id: Option<String>,
    /// Envelope `outcome` (`ok`, `refused`, `partial`, `waiting`, `indeterminate`, ...).
    pub outcome: Option<String>,
    /// Registered `ERR-*` identity when present.
    pub error_id: Option<String>,
    /// Envelope `epistemicState` when present.
    pub epistemic_state: Option<String>,
    /// Envelope `completeness` when present.
    pub completeness: Option<String>,
    /// Audited `principalId` when present.
    pub principal_id: Option<String>,
    /// Effective `AVIEW-*` view identity when present.
    pub effective_view_id: Option<String>,
    /// Sorted effective capability grants when present.
    pub effective_capabilities: Vec<String>,
    /// Inner `payloadSchema` when present.
    pub payload_schema: Option<String>,
    /// Envelope `payloadDigest` when present.
    pub payload_digest: Option<String>,
    /// Envelope `decisionFingerprint` when present.
    pub decision_fingerprint: Option<String>,
    /// Exact canonical hash of `contractBasis` when present.
    pub contract_basis_digest: Option<ContentDigest>,
    /// Inner `worldEnvelopeDigest` when present in `payload`.
    pub world_envelope_digest: Option<String>,
    /// Sorted control-envelope `(affordanceId, robustnessClass)` entries.
    pub control_envelope: Vec<AffordanceClassification>,
    /// Normalized sorted envelope warnings.
    pub warnings: Vec<String>,
    /// Normalized sorted envelope contradictions.
    pub contradictions: Vec<String>,
    /// Normalized sorted envelope degradation dimensions.
    pub degradation: Vec<String>,
    /// Envelope `recoveryClass` when present.
    pub recovery_class: Option<String>,
    /// Envelope `safeRetry` policy when present.
    pub safe_retry: Option<String>,
    /// Envelope `resnapshotRequired` flag when present.
    pub resnapshot_required: Option<bool>,
    /// `fss.doctor.v1` `verdict` when present.
    pub doctor_verdict: Option<String>,
    /// `fss.doctor.v1` `possibly_stale` when present.
    pub doctor_possibly_stale: Option<bool>,
    /// Inner payload `state` (for operation receipts / plans / cases) when present.
    pub payload_state: Option<String>,
    /// Inner `activePolicyMutation` flag (for feedback proposals) when present.
    pub active_policy_mutation: Option<bool>,
    /// Exact approval digest extracted from `payload.approvalDigest` when present.
    pub approval_digest: Option<String>,
    /// Canonical SHA-256 of the sorted, policy-normalized full JSON document.
    pub canonical_payload_digest: ContentDigest,
    /// Canonical normalized JSON string (retained in memory for exact diff pinpointing).
    pub canonical_json: String,
    /// Raw UTF-8 response byte length.
    pub raw_bytes: usize,
    /// Wall-clock surface execution latency in microseconds (diagnostic only; never hashed into equivalence).
    pub elapsed_us: u64,
}

/// One exact field-level semantic divergence detected across surfaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EquivalenceMismatch {
    /// Zero-based step index inside the transcript.
    pub step_index: usize,
    /// Human-readable step label.
    pub step_label: String,
    /// Semantic field name that diverged.
    pub field: String,
    /// Observed value on the Direct Rust API surface.
    pub rust_api: String,
    /// Observed value on the CLI binary surface.
    pub cli: String,
    /// Observed value on the MCP stdio server surface.
    pub mcp: String,
}

impl EquivalenceMismatch {
    /// Deterministic JSON rendering of a mismatch row.
    #[must_use]
    pub fn to_json(&self) -> String {
        object(&[
            ("stepIndex", self.step_index.to_string()),
            ("stepLabel", string(&self.step_label)),
            ("field", string(&self.field)),
            ("rustApi", string(&self.rust_api)),
            ("cli", string(&self.cli)),
            ("mcp", string(&self.mcp)),
        ])
    }
}

/// Three-surface comparison record for one transcript step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepEquivalenceRow {
    /// Zero-based step index inside the transcript.
    pub step_index: usize,
    /// Human-readable step label (e.g., `"AOP-003 orient brief"`).
    pub step_label: String,
    /// Expected registered operation ID (e.g., `"AOP-003"` or `"AOP-014"`).
    pub expected_operation_id: String,
    /// Normalization policy mode used for this step.
    pub policy_mode: String,
    /// Digest of the normalization policy.
    pub policy_digest: ContentDigest,
    /// Direct Rust API semantic projection.
    pub rust_api: SemanticProjection,
    /// Live CLI binary semantic projection.
    pub cli: SemanticProjection,
    /// Live MCP stdio server semantic projection.
    pub mcp: SemanticProjection,
    /// Whether all three surfaces matched on every protected and policy-active field.
    pub equivalent: bool,
    /// Exact field-level mismatches (empty iff `equivalent == true`).
    pub mismatches: Vec<EquivalenceMismatch>,
    /// Deterministic SHA-256 receipt of this step's semantic comparison (excludes volatile timing).
    pub step_digest: ContentDigest,
}

impl StepEquivalenceRow {
    /// Deterministic JSON rendering of this step record.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mismatch_json: Vec<String> = self
            .mismatches
            .iter()
            .map(EquivalenceMismatch::to_json)
            .collect();
        object(&[
            ("stepIndex", self.step_index.to_string()),
            ("stepLabel", string(&self.step_label)),
            ("expectedOperationId", string(&self.expected_operation_id)),
            ("policyMode", string(&self.policy_mode)),
            ("policyDigest", string(&self.policy_digest.to_text())),
            ("equivalent", self.equivalent.to_string()),
            ("stepDigest", string(&self.step_digest.to_text())),
            ("schema", string(&self.rust_api.schema)),
            ("outcome", optional_string(self.rust_api.outcome.as_deref())),
            (
                "errorId",
                optional_string(self.rust_api.error_id.as_deref()),
            ),
            (
                "payloadSchema",
                optional_string(self.rust_api.payload_schema.as_deref()),
            ),
            (
                "canonicalPayloadDigest",
                string(&self.rust_api.canonical_payload_digest.to_text()),
            ),
            (
                "latenciesUs",
                object(&[
                    ("rustApi", self.rust_api.elapsed_us.to_string()),
                    ("cli", self.cli.elapsed_us.to_string()),
                    ("mcp", self.mcp.elapsed_us.to_string()),
                ]),
            ),
            (
                "rawBytes",
                object(&[
                    ("rustApi", self.rust_api.raw_bytes.to_string()),
                    ("cli", self.cli.raw_bytes.to_string()),
                    ("mcp", self.mcp.raw_bytes.to_string()),
                ]),
            ),
            ("mismatches", array(&mismatch_json)),
        ])
    }
}

/// Complete multi-step 3-surface transcript-equivalence verification report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptEquivalenceReport {
    /// Ordered step-level comparison rows.
    pub steps: Vec<StepEquivalenceRow>,
    /// Distinct registered `AOP-*` operations proved in this transcript.
    pub operations_covered: BTreeSet<String>,
    /// Total mismatches across all steps.
    pub total_mismatches: usize,
    /// `true` iff every step matched cleanly across Rust API, CLI, and MCP.
    pub equivalent: bool,
    /// Always `false`: transcript verification is pure cognition and never grants effect authority.
    pub grants_effect_authority: bool,
    /// Deterministic SHA-256 digest over all step receipts and aggregate verdict.
    pub transcript_digest: ContentDigest,
}

impl TranscriptEquivalenceReport {
    /// Deterministic JSON rendering suitable for `CAPLOG` / retained proof artifacts.
    #[must_use]
    pub fn to_json(&self) -> String {
        let step_json: Vec<String> = self.steps.iter().map(StepEquivalenceRow::to_json).collect();
        let ops: Vec<&str> = self.operations_covered.iter().map(String::as_str).collect();
        object(&[
            ("reportKind", string("fss.transcript_equivalence_report")),
            ("stepCount", self.steps.len().to_string()),
            ("operationsCovered", strings(ops)),
            ("totalMismatches", self.total_mismatches.to_string()),
            ("equivalent", self.equivalent.to_string()),
            (
                "grantsEffectAuthority",
                self.grants_effect_authority.to_string(),
            ),
            (
                "transcriptDigest",
                string(&self.transcript_digest.to_text()),
            ),
            ("steps", array(&step_json)),
        ])
    }
}

/// Recursively renders `value` as deterministic sorted-key canonical JSON,
/// omitting ONLY object keys listed in `ignored_keys` and applying optional
/// literal string substitutions via `tokens`.
#[must_use]
pub fn render_canonical_json_normalized(
    value: &Value,
    ignored_keys: &BTreeSet<String>,
    tokens: &TokenNormalizer,
) -> String {
    let mut out = String::new();
    write_canonical_value(value, ignored_keys, tokens, &mut out);
    out
}

fn write_canonical_value(
    value: &Value,
    ignored_keys: &BTreeSet<String>,
    tokens: &TokenNormalizer,
    out: &mut String,
) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(n),
        Value::Text(s) => {
            let normalized = tokens.apply(s);
            out.push('"');
            out.push_str(&escape_json_str(&normalized));
            out.push('"');
        }
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical_value(item, ignored_keys, tokens, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // `BTreeMap` iterates in deterministic lexicographical key order.
            out.push('{');
            let mut first = true;
            for (key, val) in map {
                if ignored_keys.contains(key.as_str()) {
                    continue;
                }
                if !first {
                    out.push(',');
                }
                first = false;
                out.push('"');
                out.push_str(&escape_json_str(key));
                out.push_str("\":");
                write_canonical_value(val, ignored_keys, tokens, out);
            }
            out.push('}');
        }
    }
}

/// Strictly parses and projects one raw surface JSON response into a [`SemanticProjection`].
pub fn project_surface_response(
    surface: SurfaceKind,
    is_error: bool,
    raw_json: &str,
    elapsed_us: u64,
    policy: &NormalizationPolicy,
    tokens: &TokenNormalizer,
) -> Result<SemanticProjection, EquivalenceError> {
    policy.validate()?;
    if policy.mode == "exact" && !tokens.is_noop() {
        return Err(EquivalenceError::InvalidNormalizationPolicy {
            detail: "exact normalization policy forbids non-empty or heuristic TokenNormalizer"
                .to_owned(),
        });
    }
    let trimmed = raw_json.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_SURFACE_OUTPUT_BYTES {
        return Err(EquivalenceError::OutputBudgetExceeded {
            surface,
            observed_bytes: trimmed.len(),
            max_bytes: MAX_SURFACE_OUTPUT_BYTES,
        });
    }
    let parsed = parse_mcp_reply(trimmed).map_err(|err| EquivalenceError::InvalidSurfaceJson {
        surface,
        detail: err.to_string(),
    })?;
    let root = parsed
        .object()
        .ok_or_else(|| EquivalenceError::InvalidSurfaceJson {
            surface,
            detail: "top-level surface response must be a JSON object".to_owned(),
        })?;

    let schema = root
        .get("schema")
        .and_then(Value::text)
        .ok_or_else(|| EquivalenceError::InvalidSurfaceJson {
            surface,
            detail: "top-level response is missing string field `schema`".to_owned(),
        })?
        .to_owned();

    let contract_basis_digest = root.get("contractBasis").map(|basis| {
        let canonical =
            render_canonical_json_normalized(basis, &BTreeSet::new(), &TokenNormalizer::none());
        let mut enc = CanonicalEncoder::new();
        enc.text(CONTRACT_BASIS_HASH_TAG);
        enc.text(&canonical);
        ContentDigest::sha256(&enc.finish())
    });

    let payload = root.get("payload").and_then(Value::object);
    let world_envelope_digest = extract_world_envelope_digest(payload);
    let approval_digest = payload
        .and_then(|p| p.get("approvalDigest"))
        .and_then(Value::text)
        .map(str::to_owned);
    let payload_state = payload
        .and_then(|p| p.get("state"))
        .and_then(Value::text)
        .map(str::to_owned);
    let active_policy_mutation = payload
        .and_then(|p| p.get("activePolicyMutation"))
        .and_then(Value::boolean);

    let mut effective_capabilities =
        extract_string_array(root.get("effectiveCapabilities"), tokens);
    effective_capabilities.sort();

    let mut warnings = extract_string_array(root.get("warnings"), tokens);
    warnings.sort();

    let mut contradictions = extract_string_array(root.get("contradictions"), tokens);
    contradictions.sort();

    let mut degradation = extract_string_array(root.get("degradation"), tokens);
    degradation.sort();

    let mut control_envelope = extract_control_envelope(root.get("affordances"), tokens);
    control_envelope.sort();

    let canonical_json = render_canonical_json_normalized(&parsed, &policy.ignored_keys, tokens);
    let mut enc = CanonicalEncoder::new();
    enc.text(CANONICAL_JSON_HASH_TAG);
    enc.text(&canonical_json);
    let canonical_payload_digest = ContentDigest::sha256(&enc.finish());

    Ok(SemanticProjection {
        surface,
        is_error,
        schema,
        operation_id: opt_str(root, "operationId"),
        outcome: opt_str(root, "outcome"),
        error_id: opt_str(root, "errorId"),
        epistemic_state: opt_str(root, "epistemicState"),
        completeness: opt_str(root, "completeness"),
        principal_id: opt_str(root, "principalId"),
        effective_view_id: opt_str(root, "effectiveViewId"),
        effective_capabilities,
        payload_schema: opt_str(root, "payloadSchema"),
        payload_digest: opt_str(root, "payloadDigest"),
        decision_fingerprint: opt_str(root, "decisionFingerprint"),
        contract_basis_digest,
        world_envelope_digest,
        control_envelope,
        warnings,
        contradictions,
        degradation,
        recovery_class: opt_str(root, "recoveryClass"),
        safe_retry: opt_str(root, "safeRetry"),
        resnapshot_required: root.get("resnapshotRequired").and_then(Value::boolean),
        doctor_verdict: opt_str(root, "verdict"),
        doctor_possibly_stale: root.get("possibly_stale").and_then(Value::boolean),
        payload_state,
        active_policy_mutation,
        approval_digest,
        canonical_payload_digest,
        canonical_json,
        raw_bytes: trimmed.len(),
        elapsed_us,
    })
}

/// Executes one command directly via the in-process Rust library API
/// (`parse_fss_args` + `execute_live_fss_with_exit`) and returns both its
/// [`SemanticProjection`] and the raw JSON output text.
pub fn execute_rust_api_argv(
    argv: &[OsString],
    policy: &NormalizationPolicy,
    tokens: &TokenNormalizer,
) -> Result<(SemanticProjection, String), EquivalenceError> {
    policy.validate()?;
    if policy.mode == "exact" && !tokens.is_noop() {
        return Err(EquivalenceError::InvalidNormalizationPolicy {
            detail: "exact normalization policy forbids non-empty or heuristic TokenNormalizer"
                .to_owned(),
        });
    }
    let command = parse_fss_args(argv.iter().cloned()).map_err(|err| {
        EquivalenceError::RustApiParseFailed {
            error_id: err.error_id().to_owned(),
            detail: err.to_string(),
        }
    })?;
    let started = Instant::now();
    let (raw_output, exit_id) = execute_live_fss_with_exit(command);
    let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let is_error = exit_id != ExitIdentity::SUCCESS;
    let projection = project_surface_response(
        SurfaceKind::RustApi,
        is_error,
        &raw_output,
        elapsed_us,
        policy,
        tokens,
    )?;
    Ok((projection, raw_output))
}

/// Compares one transcript step across Direct Rust API, CLI binary, and MCP server.
///
/// Fails closed by recording every field-level divergence in `mismatches` and
/// setting `equivalent = mismatches.is_empty()`.
pub fn compare_step(
    step_index: usize,
    step_label: impl Into<String>,
    expected_operation_id: impl Into<String>,
    policy: &NormalizationPolicy,
    rust_api: SemanticProjection,
    cli: SemanticProjection,
    mcp: SemanticProjection,
) -> Result<StepEquivalenceRow, EquivalenceError> {
    policy.validate()?;
    let step_label = step_label.into();
    let expected_operation_id = expected_operation_id.into();
    let mut mismatches = Vec::new();

    check_eq(
        &mut mismatches,
        step_index,
        &step_label,
        "is_error",
        &rust_api.is_error.to_string(),
        &cli.is_error.to_string(),
        &mcp.is_error.to_string(),
    );
    check_eq(
        &mut mismatches,
        step_index,
        &step_label,
        "schema",
        &rust_api.schema,
        &cli.schema,
        &mcp.schema,
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "operationId",
        rust_api.operation_id.as_deref(),
        cli.operation_id.as_deref(),
        mcp.operation_id.as_deref(),
    );
    // Verify expected_operation_id against envelope operationId.
    // Only AOP-014 doctor may omit operationId when returning `fss.doctor.v1`.
    if expected_operation_id == "AOP-014" {
        let ok_doctor = |p: &SemanticProjection| {
            p.schema == "fss.doctor.v1" || p.operation_id.as_deref() == Some("AOP-014")
        };
        if !ok_doctor(&rust_api) || !ok_doctor(&cli) || !ok_doctor(&mcp) {
            mismatches.push(EquivalenceMismatch {
                step_index,
                step_label: step_label.clone(),
                field: format!("expected_operation_id({expected_operation_id})"),
                rust_api: rust_api
                    .operation_id
                    .clone()
                    .unwrap_or_else(|| format!("schema:{}", rust_api.schema)),
                cli: cli
                    .operation_id
                    .clone()
                    .unwrap_or_else(|| format!("schema:{}", cli.schema)),
                mcp: mcp
                    .operation_id
                    .clone()
                    .unwrap_or_else(|| format!("schema:{}", mcp.schema)),
            });
        }
    } else if rust_api.operation_id.as_deref() != Some(expected_operation_id.as_str())
        || cli.operation_id.as_deref() != Some(expected_operation_id.as_str())
        || mcp.operation_id.as_deref() != Some(expected_operation_id.as_str())
    {
        mismatches.push(EquivalenceMismatch {
            step_index,
            step_label: step_label.clone(),
            field: format!("expected_operation_id({expected_operation_id})"),
            rust_api: rust_api
                .operation_id
                .clone()
                .unwrap_or_else(|| "<none>".to_owned()),
            cli: cli
                .operation_id
                .clone()
                .unwrap_or_else(|| "<none>".to_owned()),
            mcp: mcp
                .operation_id
                .clone()
                .unwrap_or_else(|| "<none>".to_owned()),
        });
    }
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "outcome",
        rust_api.outcome.as_deref(),
        cli.outcome.as_deref(),
        mcp.outcome.as_deref(),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "errorId",
        rust_api.error_id.as_deref(),
        cli.error_id.as_deref(),
        mcp.error_id.as_deref(),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "epistemicState",
        rust_api.epistemic_state.as_deref(),
        cli.epistemic_state.as_deref(),
        mcp.epistemic_state.as_deref(),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "completeness",
        rust_api.completeness.as_deref(),
        cli.completeness.as_deref(),
        mcp.completeness.as_deref(),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "principalId",
        rust_api.principal_id.as_deref(),
        cli.principal_id.as_deref(),
        mcp.principal_id.as_deref(),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "effectiveViewId",
        rust_api.effective_view_id.as_deref(),
        cli.effective_view_id.as_deref(),
        mcp.effective_view_id.as_deref(),
    );
    check_eq(
        &mut mismatches,
        step_index,
        &step_label,
        "effectiveCapabilities",
        &format!("{:?}", rust_api.effective_capabilities),
        &format!("{:?}", cli.effective_capabilities),
        &format!("{:?}", mcp.effective_capabilities),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "payloadSchema",
        rust_api.payload_schema.as_deref(),
        cli.payload_schema.as_deref(),
        mcp.payload_schema.as_deref(),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "contractBasisDigest",
        rust_api
            .contract_basis_digest
            .map(ContentDigest::to_text)
            .as_deref(),
        cli.contract_basis_digest
            .map(ContentDigest::to_text)
            .as_deref(),
        mcp.contract_basis_digest
            .map(ContentDigest::to_text)
            .as_deref(),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "worldEnvelopeDigest",
        rust_api.world_envelope_digest.as_deref(),
        cli.world_envelope_digest.as_deref(),
        mcp.world_envelope_digest.as_deref(),
    );
    check_eq(
        &mut mismatches,
        step_index,
        &step_label,
        "controlEnvelope",
        &format!("{:?}", rust_api.control_envelope),
        &format!("{:?}", cli.control_envelope),
        &format!("{:?}", mcp.control_envelope),
    );
    check_eq(
        &mut mismatches,
        step_index,
        &step_label,
        "warnings",
        &format!("{:?}", rust_api.warnings),
        &format!("{:?}", cli.warnings),
        &format!("{:?}", mcp.warnings),
    );
    check_eq(
        &mut mismatches,
        step_index,
        &step_label,
        "contradictions",
        &format!("{:?}", rust_api.contradictions),
        &format!("{:?}", cli.contradictions),
        &format!("{:?}", mcp.contradictions),
    );
    check_eq(
        &mut mismatches,
        step_index,
        &step_label,
        "degradation",
        &format!("{:?}", rust_api.degradation),
        &format!("{:?}", cli.degradation),
        &format!("{:?}", mcp.degradation),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "recoveryClass",
        rust_api.recovery_class.as_deref(),
        cli.recovery_class.as_deref(),
        mcp.recovery_class.as_deref(),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "safeRetry",
        rust_api.safe_retry.as_deref(),
        cli.safe_retry.as_deref(),
        mcp.safe_retry.as_deref(),
    );
    check_eq(
        &mut mismatches,
        step_index,
        &step_label,
        "resnapshotRequired",
        &format!("{:?}", rust_api.resnapshot_required),
        &format!("{:?}", cli.resnapshot_required),
        &format!("{:?}", mcp.resnapshot_required),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "doctor.verdict",
        rust_api.doctor_verdict.as_deref(),
        cli.doctor_verdict.as_deref(),
        mcp.doctor_verdict.as_deref(),
    );
    check_eq(
        &mut mismatches,
        step_index,
        &step_label,
        "doctor.possibly_stale",
        &format!("{:?}", rust_api.doctor_possibly_stale),
        &format!("{:?}", cli.doctor_possibly_stale),
        &format!("{:?}", mcp.doctor_possibly_stale),
    );
    check_opt(
        &mut mismatches,
        step_index,
        &step_label,
        "payload.state",
        rust_api.payload_state.as_deref(),
        cli.payload_state.as_deref(),
        mcp.payload_state.as_deref(),
    );
    check_eq(
        &mut mismatches,
        step_index,
        &step_label,
        "payload.activePolicyMutation",
        &format!("{:?}", rust_api.active_policy_mutation),
        &format!("{:?}", cli.active_policy_mutation),
        &format!("{:?}", mcp.active_policy_mutation),
    );

    if !policy.ignore_payload_digest {
        check_opt(
            &mut mismatches,
            step_index,
            &step_label,
            "payloadDigest",
            rust_api.payload_digest.as_deref(),
            cli.payload_digest.as_deref(),
            mcp.payload_digest.as_deref(),
        );
    }
    if !policy.ignore_decision_fingerprint {
        check_opt(
            &mut mismatches,
            step_index,
            &step_label,
            "decisionFingerprint",
            rust_api.decision_fingerprint.as_deref(),
            cli.decision_fingerprint.as_deref(),
            mcp.decision_fingerprint.as_deref(),
        );
    }
    if !policy.ignore_approval_digest {
        check_opt(
            &mut mismatches,
            step_index,
            &step_label,
            "payload.approvalDigest",
            rust_api.approval_digest.as_deref(),
            cli.approval_digest.as_deref(),
            mcp.approval_digest.as_deref(),
        );
    }

    if rust_api.canonical_payload_digest != cli.canonical_payload_digest
        || rust_api.canonical_payload_digest != mcp.canonical_payload_digest
    {
        let diff_hint = if rust_api.canonical_json != cli.canonical_json {
            format!(
                " ({})",
                first_diff_hint(
                    "rust_api",
                    &rust_api.canonical_json,
                    "cli",
                    &cli.canonical_json
                )
            )
        } else {
            format!(
                " ({})",
                first_diff_hint(
                    "rust_api",
                    &rust_api.canonical_json,
                    "mcp",
                    &mcp.canonical_json
                )
            )
        };
        mismatches.push(EquivalenceMismatch {
            step_index,
            step_label: step_label.clone(),
            field: "canonicalPayloadDigest".to_owned(),
            rust_api: format!("{}{diff_hint}", rust_api.canonical_payload_digest.to_text()),
            cli: cli.canonical_payload_digest.to_text(),
            mcp: mcp.canonical_payload_digest.to_text(),
        });
    }

    let equivalent = mismatches.is_empty();
    let policy_digest = policy.policy_digest();
    let step_digest = compute_step_digest(
        step_index,
        &step_label,
        &expected_operation_id,
        policy_digest,
        equivalent,
        &rust_api,
        &cli,
        &mcp,
        &mismatches,
    );

    Ok(StepEquivalenceRow {
        step_index,
        step_label,
        expected_operation_id,
        policy_mode: policy.mode.clone(),
        policy_digest,
        rust_api,
        cli,
        mcp,
        equivalent,
        mismatches,
        step_digest,
    })
}

/// Aggregates bounded step comparison rows into a deterministic [`TranscriptEquivalenceReport`].
pub fn build_report(
    steps: Vec<StepEquivalenceRow>,
) -> Result<TranscriptEquivalenceReport, EquivalenceError> {
    if steps.is_empty() || steps.len() > MAX_TRANSCRIPT_STEPS {
        return Err(EquivalenceError::InvalidStepCount {
            observed: steps.len(),
            max: MAX_TRANSCRIPT_STEPS,
        });
    }
    let mut operations_covered = BTreeSet::new();
    let mut total_mismatches = 0_usize;
    for step in &steps {
        operations_covered.insert(step.expected_operation_id.clone());
        total_mismatches = total_mismatches.saturating_add(step.mismatches.len());
    }
    let equivalent = total_mismatches == 0 && steps.iter().all(|s| s.equivalent);

    let mut enc = CanonicalEncoder::new();
    enc.text(REPORT_RECEIPT_HASH_TAG);
    enc.u64(steps.len() as u64);
    enc.u64(total_mismatches as u64);
    enc.bool(equivalent);
    enc.bool(false); // grants_effect_authority is always false
    for step in &steps {
        enc.digest(step.step_digest);
    }
    let transcript_digest = ContentDigest::sha256(&enc.finish());

    Ok(TranscriptEquivalenceReport {
        steps,
        operations_covered,
        total_mismatches,
        equivalent,
        grants_effect_authority: false,
        transcript_digest,
    })
}

fn opt_str(map: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    map.get(key).and_then(Value::text).map(str::to_owned)
}

fn extract_string_array(val: Option<&Value>, tokens: &TokenNormalizer) -> Vec<String> {
    let Some(items) = val.and_then(Value::array) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|item| match item.text() {
            Some(s) => tokens.apply(s),
            None => {
                let raw = render_canonical_json_normalized(item, &BTreeSet::new(), tokens);
                format!(
                    "<non-string:{}>",
                    crate::redact::sanitize_and_truncate(&raw, 128)
                )
            }
        })
        .collect()
}

fn extract_world_envelope_digest(payload: Option<&BTreeMap<String, Value>>) -> Option<String> {
    let payload = payload?;
    if let Some(d) = payload
        .get("worldEnvelope")
        .and_then(Value::object)
        .and_then(|o| o.get("worldEnvelopeDigest"))
        .and_then(Value::text)
    {
        return Some(d.to_owned());
    }
    payload
        .get("situationFrame")
        .and_then(Value::object)
        .and_then(|sf| sf.get("worldEnvelope"))
        .and_then(Value::object)
        .and_then(|we| we.get("worldEnvelopeDigest"))
        .and_then(Value::text)
        .map(str::to_owned)
}

fn extract_control_envelope(
    val: Option<&Value>,
    tokens: &TokenNormalizer,
) -> Vec<AffordanceClassification> {
    let Some(items) = val.and_then(Value::array) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(obj) = item.object() else {
            out.push(AffordanceClassification {
                affordance_id: "<non-object-affordance>".to_owned(),
                robustness_class: "<invalid>".to_owned(),
            });
            continue;
        };
        let affordance_id = obj
            .get("affordanceId")
            .and_then(Value::text)
            .map(|s| tokens.apply(s))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "<missing-affordance-id>".to_owned());
        let robustness_class = obj
            .get("robustnessClass")
            .or_else(|| obj.get("class"))
            .and_then(Value::text)
            .filter(|s| !s.is_empty())
            .unwrap_or("<missing>")
            .to_owned();
        out.push(AffordanceClassification {
            affordance_id,
            robustness_class,
        });
    }
    out
}

fn first_diff_hint(label_a: &str, a: &str, label_b: &str, b: &str) -> String {
    fn slice_window(s: &str, offset: usize) -> String {
        let mut start = offset.saturating_sub(32);
        while start > 0 && !s.is_char_boundary(start) {
            start -= 1;
        }
        let mut end = (offset + 64).min(s.len());
        while end < s.len() && !s.is_char_boundary(end) {
            end += 1;
        }
        crate::redact::sanitize_and_truncate(&s[start..end], 120)
    }
    let offset = a
        .bytes()
        .zip(b.bytes())
        .position(|(x, y)| x != y)
        .unwrap_or_else(|| a.len().min(b.len()));
    format!(
        "first diff at byte {offset}: {label_a}=`{}` vs {label_b}=`{}`",
        slice_window(a, offset),
        slice_window(b, offset)
    )
}

fn check_eq(
    mismatches: &mut Vec<EquivalenceMismatch>,
    step_index: usize,
    step_label: &str,
    field: &str,
    rust_api: &str,
    cli: &str,
    mcp: &str,
) {
    if rust_api != cli || rust_api != mcp {
        mismatches.push(EquivalenceMismatch {
            step_index,
            step_label: step_label.to_owned(),
            field: field.to_owned(),
            rust_api: rust_api.to_owned(),
            cli: cli.to_owned(),
            mcp: mcp.to_owned(),
        });
    }
}

fn check_opt(
    mismatches: &mut Vec<EquivalenceMismatch>,
    step_index: usize,
    step_label: &str,
    field: &str,
    rust_api: Option<&str>,
    cli: Option<&str>,
    mcp: Option<&str>,
) {
    if rust_api != cli || rust_api != mcp {
        mismatches.push(EquivalenceMismatch {
            step_index,
            step_label: step_label.to_owned(),
            field: field.to_owned(),
            rust_api: rust_api.unwrap_or("<none>").to_owned(),
            cli: cli.unwrap_or("<none>").to_owned(),
            mcp: mcp.unwrap_or("<none>").to_owned(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_step_digest(
    step_index: usize,
    step_label: &str,
    expected_operation_id: &str,
    policy_digest: ContentDigest,
    equivalent: bool,
    rust_api: &SemanticProjection,
    cli: &SemanticProjection,
    mcp: &SemanticProjection,
    mismatches: &[EquivalenceMismatch],
) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(STEP_RECEIPT_HASH_TAG);
    enc.u64(step_index as u64);
    enc.text(step_label);
    enc.text(expected_operation_id);
    enc.digest(policy_digest);
    enc.bool(equivalent);
    for proj in [rust_api, cli, mcp] {
        enc.text(proj.surface.as_str());
        enc.bool(proj.is_error);
        enc.text(&proj.schema);
        enc.digest(proj.canonical_payload_digest);
    }
    enc.u64(mismatches.len() as u64);
    for m in mismatches {
        enc.text(&m.field);
        enc.text(&m.rust_api);
        enc.text(&m.cli);
        enc.text(&m.mcp);
    }
    ContentDigest::sha256(&enc.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn sample_envelope(
        outcome: &str,
        error_id: &str,
        payload_digest: &str,
        decision_fp: &str,
        extra_payload_field: &str,
    ) -> String {
        format!(
            r#"{{"schema":"fss.agent_response_envelope.v1","contractBasis":{{"registryVersion":"1","schemaEpoch":1}},"operationId":"AOP-003","principalId":"principal:test-owner","effectiveViewId":"AVIEW-002","effectiveCapabilities":["CAP-AGENT-SITUATION-READ-001"],"outcome":"{outcome}","errorId":{error_id},"payloadSchema":"fss.situation_capsule.v1","payload":{{"worldEnvelope":{{"worldEnvelopeDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"extra":"{extra_payload_field}","createdAtNs":"100"}},"payloadDigest":"{payload_digest}","epistemicState":"known","completeness":"complete","warnings":[],"contradictions":[],"degradation":[],"affordances":[{{"affordanceId":"affordance:orient:query","robustnessClass":"robust"}}],"decisionFingerprint":"{decision_fp}","recoveryClass":"none","safeRetry":"idempotent","resnapshotRequired":false,"createdAtNs":"100"}}"#
        )
    }

    #[test]
    fn exact_policy_passes_bit_identical_reordered_json() -> TestResult {
        let policy = NormalizationPolicy::exact();
        let tokens = TokenNormalizer::none();
        let a = sample_envelope(
            "ok",
            "null",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "same",
        );
        // Same semantic object with keys in different lexical order -> canonical digest MUST match.
        let b = r#"{"createdAtNs":"100","resnapshotRequired":false,"safeRetry":"idempotent","recoveryClass":"none","decisionFingerprint":"sha256:2222222222222222222222222222222222222222222222222222222222222222","affordances":[{"robustnessClass":"robust","affordanceId":"affordance:orient:query"}],"degradation":[],"contradictions":[],"warnings":[],"completeness":"complete","epistemicState":"known","payloadDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","payload":{"createdAtNs":"100","extra":"same","worldEnvelope":{"worldEnvelopeDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"payloadSchema":"fss.situation_capsule.v1","errorId":null,"outcome":"ok","effectiveCapabilities":["CAP-AGENT-SITUATION-READ-001"],"effectiveViewId":"AVIEW-002","principalId":"principal:test-owner","operationId":"AOP-003","contractBasis":{"schemaEpoch":1,"registryVersion":"1"},"schema":"fss.agent_response_envelope.v1"}"#;

        let p_api =
            project_surface_response(SurfaceKind::RustApi, false, &a, 10, &policy, &tokens)?;
        let p_cli = project_surface_response(SurfaceKind::Cli, false, b, 20, &policy, &tokens)?;
        let p_mcp = project_surface_response(SurfaceKind::Mcp, false, &a, 30, &policy, &tokens)?;
        let row = compare_step(0, "orient", "AOP-003", &policy, p_api, p_cli, p_mcp)?;
        assert!(row.equivalent, "mismatches: {:?}", row.mismatches);
        assert!(row.mismatches.is_empty());

        let report = build_report(vec![row])?;
        assert!(report.equivalent);
        assert!(!report.grants_effect_authority);
        assert_eq!(report.total_mismatches, 0);
        assert!(report.operations_covered.contains("AOP-003"));
        Ok(())
    }

    #[test]
    fn planted_single_field_divergences_fail_closed() -> TestResult {
        let policy = NormalizationPolicy::exact();
        let tokens = TokenNormalizer::none();
        let base = sample_envelope(
            "ok",
            "null",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "same",
        );
        let cases = [
            (
                "outcome",
                sample_envelope(
                    "refused",
                    "null",
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "same",
                ),
            ),
            (
                "errorId",
                sample_envelope(
                    "ok",
                    "\"ERR-AUTH-DENIED-001\"",
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "same",
                ),
            ),
            (
                "payloadDigest",
                sample_envelope(
                    "ok",
                    "null",
                    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "same",
                ),
            ),
            (
                "decisionFingerprint",
                sample_envelope(
                    "ok",
                    "null",
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "sha256:4444444444444444444444444444444444444444444444444444444444444444",
                    "same",
                ),
            ),
            (
                "canonicalPayloadDigest",
                sample_envelope(
                    "ok",
                    "null",
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "drifted",
                ),
            ),
        ];

        for (expected_field, mutated) in cases {
            let p_api =
                project_surface_response(SurfaceKind::RustApi, false, &base, 5, &policy, &tokens)?;
            let p_cli =
                project_surface_response(SurfaceKind::Cli, false, &base, 5, &policy, &tokens)?;
            let p_mcp =
                project_surface_response(SurfaceKind::Mcp, false, &mutated, 5, &policy, &tokens)?;
            let row = compare_step(0, expected_field, "AOP-003", &policy, p_api, p_cli, p_mcp)?;
            assert!(!row.equivalent, "expected failure for {expected_field}");
            assert!(
                row.mismatches.iter().any(|m| m.field == expected_field),
                "expected mismatch on `{expected_field}`, got {:?}",
                row.mismatches
            );
        }
        Ok(())
    }

    #[test]
    fn normalization_policy_forbids_stripping_protected_semantic_keys() {
        for protected in PROTECTED_SEMANTIC_KEYS {
            let mut policy = NormalizationPolicy::exact();
            policy.ignored_keys.insert((*protected).to_owned());
            let err = policy.validate();
            assert!(
                matches!(
                    err,
                    Err(EquivalenceError::InvalidNormalizationPolicy { .. })
                ),
                "protected key `{protected}` must be refused by validate()"
            );
        }
        assert!(NormalizationPolicy::exact().validate().is_ok());
        assert!(NormalizationPolicy::stateful_clone().validate().is_ok());
        assert_ne!(
            NormalizationPolicy::exact().policy_digest(),
            NormalizationPolicy::stateful_clone().policy_digest()
        );
    }

    #[test]
    fn empty_overbudget_and_invalid_step_counts_fail_closed() {
        let policy = NormalizationPolicy::exact();
        let tokens = TokenNormalizer::none();
        assert!(matches!(
            project_surface_response(SurfaceKind::Cli, false, "   ", 1, &policy, &tokens),
            Err(EquivalenceError::OutputBudgetExceeded { .. })
        ));
        let oversized = "x".repeat(MAX_SURFACE_OUTPUT_BYTES + 1);
        assert!(matches!(
            project_surface_response(SurfaceKind::Mcp, false, &oversized, 1, &policy, &tokens),
            Err(EquivalenceError::OutputBudgetExceeded { .. })
        ));
        assert!(matches!(
            project_surface_response(SurfaceKind::RustApi, false, "[1,2,3]", 1, &policy, &tokens),
            Err(EquivalenceError::InvalidSurfaceJson { .. })
        ));
        assert!(matches!(
            build_report(Vec::new()),
            Err(EquivalenceError::InvalidStepCount { observed: 0, .. })
        ));
    }

    #[test]
    fn stateful_clone_token_masking_is_opt_in_and_preserves_counts_and_prose() {
        let digest = "sha256:2a66dff2340be41e1fd7c04f567e3421dbc6be1d69f1e3fdcc778a0bd6461d55";
        let anchor = "anchor:3f3e90e95f59458c:11:e7:d37ac53c44974ae7fa37805b26fb02f02d56703a7ca887b95534bbd9a72f7a20";
        let sample = format!(
            "Session session:0123456789abcdef expires at 1796422979035168000 ns; count 1600; published {digest}; moved to {anchor}"
        );
        assert_eq!(TokenNormalizer::none().apply(&sample), sample);
        assert_eq!(
            TokenNormalizer::stateful_clone().apply(&sample),
            "Session session:<HEX_ID> expires at <UNIX_NS> ns; count 1600; published <SHA256>; moved to anchor:3f3e90e95f59458c:11:e7:<ANCHOR_BINDING>"
        );
    }

    #[test]
    fn exact_policy_refuses_non_noop_token_normalizer() -> TestResult {
        let policy = NormalizationPolicy::exact();
        let sample = sample_envelope(
            "ok",
            "null",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "same",
        );
        assert!(matches!(
            project_surface_response(
                SurfaceKind::RustApi,
                false,
                &sample,
                1,
                &policy,
                &TokenNormalizer::stateful_clone(),
            ),
            Err(EquivalenceError::InvalidNormalizationPolicy { .. })
        ));
        let mut lit = TokenNormalizer::none();
        lit.push("same", "<REPLACED>")?;
        assert!(matches!(
            project_surface_response(SurfaceKind::Cli, false, &sample, 1, &policy, &lit),
            Err(EquivalenceError::InvalidNormalizationPolicy { .. })
        ));
        Ok(())
    }

    #[test]
    fn doctor_schema_cannot_bypass_non_doctor_operation_check() -> TestResult {
        let policy = NormalizationPolicy::exact();
        let tokens = TokenNormalizer::none();
        let doctor = r#"{"schema":"fss.doctor.v1","verdict":"ok","possibly_stale":false}"#;
        let p_api =
            project_surface_response(SurfaceKind::RustApi, false, doctor, 1, &policy, &tokens)?;
        let p_cli = project_surface_response(SurfaceKind::Cli, false, doctor, 1, &policy, &tokens)?;
        let p_mcp = project_surface_response(SurfaceKind::Mcp, false, doctor, 1, &policy, &tokens)?;

        let ok_row = compare_step(
            0,
            "doctor",
            "AOP-014",
            &policy,
            p_api.clone(),
            p_cli.clone(),
            p_mcp.clone(),
        )?;
        assert!(ok_row.equivalent, "mismatches: {:?}", ok_row.mismatches);

        let bad_row = compare_step(1, "fake-orient", "AOP-003", &policy, p_api, p_cli, p_mcp)?;
        assert!(!bad_row.equivalent);
        assert!(
            bad_row
                .mismatches
                .iter()
                .any(|m| m.field == "expected_operation_id(AOP-003)")
        );
        Ok(())
    }

    #[test]
    fn token_masking_respects_word_boundaries_and_preserves_case_id_and_malformed_entries()
    -> TestResult {
        let norm = TokenNormalizer::stateful_clone();
        let intact = "replan:0123456789abcdef impression:0123456789abcdef notsha256:2a66dff2340be41e1fd7c04f567e3421dbc6be1d69f1e3fdcc778a0bd6461d55 reanchor:3f3e90e95f59458c:11:e7:d37ac53c44974ae7fa37805b26fb02f02d56703a7ca887b95534bbd9a72f7a20";
        assert_eq!(norm.apply(intact), intact);

        // Caller-specified caseId is NOT ignored in stateful_clone policy.
        assert!(
            !NormalizationPolicy::stateful_clone()
                .ignored_keys
                .contains("caseId")
        );

        // Non-string array entries and malformed affordances must not vanish silently.
        let malformed_env = r#"{"schema":"fss.agent_response_envelope.v1","operationId":"AOP-003","outcome":"ok","warnings":[123,"ok"],"affordances":[42,{"robustnessClass":"robust"}]}"#;
        let proj = project_surface_response(
            SurfaceKind::Cli,
            false,
            malformed_env,
            1,
            &NormalizationPolicy::exact(),
            &TokenNormalizer::none(),
        )?;
        assert!(proj.warnings.iter().any(|w| w.contains("<non-string:123>")));
        assert!(
            proj.control_envelope
                .iter()
                .any(|a| a.affordance_id == "<non-object-affordance>")
        );
        assert!(
            proj.control_envelope
                .iter()
                .any(|a| a.affordance_id == "<missing-affordance-id>")
        );

        // Control characters in diff hints must be sanitized.
        let hint = first_diff_hint("a", "ok\x1b[31mred\n", "b", "ok\x1b[32mgreen\n");
        assert!(!hint.contains('\x1b'));
        assert!(!hint.contains('\n'));
        Ok(())
    }
}
