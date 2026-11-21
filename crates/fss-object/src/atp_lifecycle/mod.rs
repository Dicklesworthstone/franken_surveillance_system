#![forbid(unsafe_code)]
//! Canonical ATP transfer, path, and archive lifecycles (`fss-x4a.13.31`).
//!
//! Reconciles the three distinct ATP lifecycle layers defined across
//! `docs/ATP_AND_DISTRIBUTED_EVIDENCE.md`, `docs/ATP_ARCHIVE_AND_REPLICATION.md`, and
//! `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md` into one registered vocabulary
//! (`architecture/atp_lifecycles.json`, `registries/ATP_LIFECYCLES.md`) with deterministic safe-Rust
//! reducers, an append-only checksummed resumable journal, an exhaustive legacy crosswalk, and
//! secret-free structured receipts conforming to `schemas/transfer_receipt.v1.json`.
//!
//! Non-collapse rule: `offered`, `received`, `verified`, `graph_closed`, `durable`, `committed`,
//! `published`, `replicated`, `retrievable`, `protected`, and `complete` are never synonyms, and
//! delivery of bytes never grants retention, indexing, activation, or effect authority.

pub mod crosswalk;
pub mod journal;
pub mod reducer;

use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};

pub use crosswalk::{
    ArchiveObjectState, ArchivePublicationState, CanonicalLifecycleState, CrosswalkResolution,
    LegacyMappingKind, LifecycleLayer, NON_COLLAPSE_TERMS, PathState, SemanticTransferState,
    resolve_state_spelling,
};
pub use journal::{JournalRecord, LifecycleEvent, MAX_JOURNAL_RECORD_BYTES, TransferJournal};
pub use reducer::AtpLifecycleCoordinator;

/// Canonical digest domain for deterministic transfer identities (`XFER-INV-002`).
pub const ATP_TRANSFER_ID_DOMAIN: &str = "fss.atp_transfer_id.v1";

/// Canonical digest domain for append-only checksummed lifecycle journal records.
pub const ATP_LIFECYCLE_JOURNAL_RECORD_DOMAIN: &str = "fss.atp_lifecycle_journal_record.v1";

/// Canonical digest domain for sealed lifecycle transfer receipts.
pub const ATP_LIFECYCLE_RECEIPT_DOMAIN: &str = "fss.atp_lifecycle_receipt.v1";

/// Supported durable journal and transfer specification format version.
pub const ATP_LIFECYCLE_FORMAT_VERSION: u32 = 1;

/// Maximum manifest children tracked by one transfer reducer.
pub const MAX_TRANSFER_CHILDREN: usize = 4_096;

/// Maximum multipath candidates tracked by one transfer reducer.
pub const MAX_TRANSFER_PATHS: usize = 64;

/// Maximum append-only journal records retained for one transfer.
pub const MAX_JOURNAL_RECORDS: usize = 8_192;

/// Maximum UTF-8 bytes in labels (sender, receiver, path_id, failure_domain, reason).
pub const MAX_LABEL_BYTES: usize = 256;

/// Maximum distinct failure domains tracked per transfer.
pub const MAX_FAILURE_DOMAINS: usize = 32;

/// Maximum critical extension entries inspected before refusal.
pub const MAX_CRITICAL_EXTENSIONS: usize = 32;

/// Deterministic domain-separated transfer identity (`XFER-INV-002`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransferId(ContentDigest);

impl TransferId {
    /// Derives a deterministic `TransferId` from all critical transfer identity inputs.
    ///
    /// Retrying with identical inputs yields the identical `TransferId`; changing any critical
    /// input (generation, sender, receiver, nonce, manifest root, contract basis, policy digest)
    /// yields a distinct identity.
    #[must_use]
    pub fn derive(
        protocol_generation: u64,
        sender: &str,
        receiver: &str,
        session_nonce: u64,
        manifest_root: ContentDigest,
        contract_basis_digest: ContentDigest,
        transfer_policy_digest: ContentDigest,
    ) -> Self {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_TRANSFER_ID_DOMAIN);
        enc.u64(protocol_generation);
        enc.text(sender);
        enc.text(receiver);
        enc.u64(session_nonce);
        enc.digest(manifest_root);
        enc.digest(contract_basis_digest);
        enc.digest(transfer_policy_digest);
        Self(ContentDigest::sha256(&enc.finish()))
    }

    /// Wraps an already-derived canonical digest.
    #[must_use]
    pub const fn from_digest(digest: ContentDigest) -> Self {
        Self(digest)
    }

    /// Underlying SHA-256 digest.
    #[must_use]
    pub const fn digest(self) -> ContentDigest {
        self.0
    }
}

impl fmt::Display for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "xfer:{}", self.0)
    }
}

/// Immutable specification governing one ATP transfer lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferSpec {
    /// Durable format version (must equal [`ATP_LIFECYCLE_FORMAT_VERSION`]).
    pub format_version: u32,
    /// Protocol generation (>= 1).
    pub protocol_generation: u64,
    /// Sender node identity.
    pub sender: String,
    /// Receiver / destination identity.
    pub receiver: String,
    /// Deterministic session nonce.
    pub session_nonce: u64,
    /// Canonical manifest root digest.
    pub manifest_root: ContentDigest,
    /// Exact semantic `ContractBasis` / anchor digest.
    pub contract_basis_digest: ContentDigest,
    /// Transfer policy digest (chunking, privacy, residency, repair policy).
    pub transfer_policy_digest: ContentDigest,
    /// Expected authority generation pinned at transfer creation.
    pub expected_authority_generation: u64,
    /// Initial publication/lease fence.
    pub initial_fence: u64,
    /// Whether the archive publication layer (`atp.archive.*`) is coupled to this transfer.
    pub archive_enabled: bool,
    /// Minimum distinct failure domains required for durability / replica qualification.
    pub required_failure_domains: u32,
    /// Declared unique manifest children `(digest, expected_bytes)`.
    pub expected_children: Vec<(ContentDigest, u64)>,
    /// Maximum journal records retained for this transfer.
    pub max_journal_records: usize,
    /// Unknown critical extensions (any non-empty list fails closed).
    pub unknown_critical_extensions: Vec<String>,
}

impl TransferSpec {
    /// Computes the deterministic [`TransferId`] for this specification.
    #[must_use]
    pub fn transfer_id(&self) -> TransferId {
        TransferId::derive(
            self.protocol_generation,
            &self.sender,
            &self.receiver,
            self.session_nonce,
            self.manifest_root,
            self.contract_basis_digest,
            self.transfer_policy_digest,
        )
    }
}

/// Live authority, privacy, generation, and budget projection evaluated at every boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritySnapshot {
    /// Exact `ContractBasis` / evidence-anchor digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Active privacy policy epoch.
    pub privacy_epoch: u64,
    /// True while the transfer capability remains valid.
    pub capability_active: bool,
    /// True while privacy authorization remains valid.
    pub privacy_active: bool,
    /// True while the target destination remains authorized.
    pub destination_authorized: bool,
    /// Hard upper bound on cumulative bytes spent.
    pub max_bytes_budget: u64,
    /// Hard upper bound on cumulative operations spent.
    pub max_ops_budget: u64,
}

impl AuthoritySnapshot {
    /// Validates live authority, privacy, destination authorization, and exact anchor/generation.
    pub fn validate_active(&self, spec: &TransferSpec) -> Result<(), AtpLifecycleError> {
        if !self.capability_active {
            return Err(AtpLifecycleError::AuthorityRevoked {
                reason: "transfer capability revoked".to_owned(),
            });
        }
        if !self.privacy_active {
            return Err(AtpLifecycleError::AuthorityRevoked {
                reason: "privacy authorization revoked".to_owned(),
            });
        }
        if !self.destination_authorized {
            return Err(AtpLifecycleError::AuthorityRevoked {
                reason: "destination authorization revoked".to_owned(),
            });
        }
        if self.contract_basis_digest != spec.contract_basis_digest {
            return Err(AtpLifecycleError::StaleAnchorOrGeneration {
                reason: "contract_basis_digest drifted from transfer spec".to_owned(),
            });
        }
        if self.authority_generation != spec.expected_authority_generation {
            return Err(AtpLifecycleError::StaleAnchorOrGeneration {
                reason: format!(
                    "authority_generation ({}) differs from expected ({})",
                    self.authority_generation, spec.expected_authority_generation
                ),
            });
        }
        Ok(())
    }
}

/// Non-collapsed transfer counters (`XFER-INV-003`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransferCounters {
    /// Bytes offered by the sender.
    pub offered_bytes: u64,
    /// Fresh bytes received over transport paths.
    pub received_bytes: u64,
    /// Bytes proven by canonical digest verification.
    pub verified_bytes: u64,
    /// Bytes bound into a committed transfer root.
    pub committed_bytes: u64,
    /// Bytes satisfied via content-addressed deduplication/reuse.
    pub reused_bytes: u64,
    /// Objects offered by the sender.
    pub offered_objects: u64,
    /// Objects proven by canonical digest verification.
    pub verified_objects: u64,
    /// Objects bound into a committed transfer root.
    pub committed_objects: u64,
    /// Repair symbols consumed during reconstruction.
    pub repair_symbols_used: u64,
    /// Redundant duplicate deliveries safely ignored.
    pub duplicate_offers_ignored: u64,
}

/// Classification of every staged child (`XFER-INV-008`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StagedChildDisposition {
    /// Not yet verified or finalized.
    Pending,
    /// Digest-verified while transfer is in progress.
    Verified,
    /// Verified staged child retained for future transfer reuse after cancellation.
    Reusable,
    /// Suspect or corrupt staged bytes quarantined for diagnosis.
    Quarantined,
    /// Unverified incomplete staged bytes safe for garbage collection.
    Collectable,
    /// Bound into a committed transfer root.
    Committed,
}

impl StagedChildDisposition {
    /// Stable machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Reusable => "reusable",
            Self::Quarantined => "quarantined",
            Self::Collectable => "collectable",
            Self::Committed => "committed",
        }
    }
}

impl CanonicalEncode for StagedChildDisposition {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let tag: u8 = match self {
            Self::Pending => 1,
            Self::Verified => 2,
            Self::Reusable => 3,
            Self::Quarantined => 4,
            Self::Collectable => 5,
            Self::Committed => 6,
        };
        encoder.u8(tag);
    }
}

impl CanonicalDecode for StagedChildDisposition {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Verified),
            3 => Ok(Self::Reusable),
            4 => Ok(Self::Quarantined),
            5 => Ok(Self::Collectable),
            6 => Ok(Self::Committed),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Per-child custody and verification record tracked by [`AtpLifecycleCoordinator`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildTransferRecord {
    /// Canonical content digest declared in the manifest.
    pub digest: ContentDigest,
    /// Declared canonical byte length.
    pub expected_bytes: u64,
    /// True once offered by the sender.
    pub offered: bool,
    /// Cumulative bytes received or reconstructed for this child.
    pub received_bytes: u64,
    /// True if repair symbols participated in reconstruction.
    pub repaired: bool,
    /// Reconstructed post-repair canonical digest when `repaired` is true.
    pub post_repair_digest: Option<ContentDigest>,
    /// True only after independent canonical digest verification passed.
    pub verified: bool,
    /// Current per-object archive custody state when archive mode is enabled.
    pub archive_object_state: Option<ArchiveObjectState>,
    /// Current or post-cancellation disposition.
    pub disposition: StagedChildDisposition,
}

/// Multipath transport path state and live resource work tracker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathRecord {
    /// Stable path identifier.
    pub path_id: String,
    /// Current path lifecycle state.
    pub state: PathState,
    /// Physical or administrative failure domain.
    pub failure_domain: String,
    /// In-flight transport operations owned by this path.
    pub in_flight_ops: u64,
    /// Live memory buffers held by this path.
    pub live_buffers: u64,
    /// Open file or network handles held by this path.
    pub open_handles: u64,
    /// Total bytes delivered over this path.
    pub bytes_delivered: u64,
    /// Ordered history of path states traversed.
    pub transitions: Vec<PathState>,
}

impl PathRecord {
    /// Total live work that must reach zero before `Draining -> Closed`.
    #[must_use]
    pub const fn live_work(&self) -> u64 {
        self.in_flight_ops
            .saturating_add(self.live_buffers)
            .saturating_add(self.open_handles)
    }
}

/// Witnessed proof-of-retrievability sample required before archive `Complete`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofOfRetrievability {
    /// Unique sample/challenge identifier.
    pub sample_id: String,
    /// Expected manifest root digest.
    pub root_digest: ContentDigest,
    /// Replica generation audited.
    pub replica_generation: u64,
    /// Failure domain audited.
    pub failure_domain: String,
    /// Independently recomputed digest observed from readback.
    pub observed_digest: ContentDigest,
    /// Byte count independently read and verified.
    pub sampled_bytes: u64,
    /// Timestamp when the sample completed.
    pub sampled_at: TimestampNs,
}

impl ProofOfRetrievability {
    /// Validates that the sample matches the exact manifest root and observed nonzero bytes.
    pub fn validate_for(&self, expected_root: ContentDigest) -> Result<(), AtpLifecycleError> {
        if self.sample_id.is_empty()
            || self.sample_id.len() > MAX_LABEL_BYTES
            || self.failure_domain.is_empty()
            || self.failure_domain.len() > MAX_LABEL_BYTES
        {
            return Err(AtpLifecycleError::InvalidInput(
                "retrievability proof requires non-empty bounded sample_id and failure_domain"
                    .to_owned(),
            ));
        }
        if self.sampled_bytes == 0 || self.replica_generation == 0 {
            return Err(AtpLifecycleError::InvalidInput(
                "retrievability proof requires nonzero sampled_bytes and replica_generation"
                    .to_owned(),
            ));
        }
        if self.root_digest != expected_root || self.observed_digest != expected_root {
            return Err(AtpLifecycleError::ManifestMismatch {
                expected: expected_root,
                supplied: self.observed_digest,
            });
        }
        Ok(())
    }

    /// Canonical SHA-256 digest of this proof-of-retrievability witness.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_canonical(&mut enc);
        ContentDigest::sha256(&enc.finish())
    }
}

impl CanonicalEncode for ProofOfRetrievability {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.sample_id);
        encoder.digest(self.root_digest);
        encoder.u64(self.replica_generation);
        encoder.text(&self.failure_domain);
        encoder.digest(self.observed_digest);
        encoder.u64(self.sampled_bytes);
        encoder.i128(self.sampled_at.0);
    }
}

impl CanonicalDecode for ProofOfRetrievability {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            sample_id: decoder.text()?.to_owned(),
            root_digest: decoder.digest()?,
            replica_generation: decoder.u64()?,
            failure_domain: decoder.text()?.to_owned(),
            observed_digest: decoder.digest()?,
            sampled_bytes: decoder.u64()?,
            sampled_at: TimestampNs(decoder.i128()?),
        })
    }
}

/// Durable reconciliation obligation owned whenever a transfer terminates `Indeterminate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndeterminateTransferObligation {
    /// Stable obligation identifier.
    pub obligation_id: String,
    /// Owning transfer identity.
    pub transfer_id: TransferId,
    /// Active publication fence at the time indeterminacy was recorded.
    pub fence: u64,
    /// Machine-readable reason lookup could not resolve commit status.
    pub reason: String,
    /// Follow-up reconciliation handle digest.
    pub follow_up_digest: ContentDigest,
    /// Monotonic creation timestamp.
    pub created_at: TimestampNs,
}

impl IndeterminateTransferObligation {
    /// Validates non-empty bounded identity/reason and matching transfer & fence.
    pub fn validate_for(
        &self,
        expected_transfer_id: TransferId,
        expected_fence: u64,
    ) -> Result<(), AtpLifecycleError> {
        if self.obligation_id.is_empty()
            || self.obligation_id.len() > MAX_LABEL_BYTES
            || self.reason.is_empty()
            || self.reason.len() > MAX_LABEL_BYTES
        {
            return Err(AtpLifecycleError::InvalidInput(
                "indeterminate obligation requires non-empty bounded obligation_id and reason"
                    .to_owned(),
            ));
        }
        if self.transfer_id != expected_transfer_id {
            return Err(AtpLifecycleError::InvalidInput(
                "indeterminate obligation transfer_id mismatch".to_owned(),
            ));
        }
        if self.fence != expected_fence {
            return Err(AtpLifecycleError::StaleFence {
                active: expected_fence,
                supplied: self.fence,
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for IndeterminateTransferObligation {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.obligation_id);
        encoder.digest(self.transfer_id.digest());
        encoder.u64(self.fence);
        encoder.text(&self.reason);
        encoder.digest(self.follow_up_digest);
        encoder.i128(self.created_at.0);
    }
}

impl CanonicalDecode for IndeterminateTransferObligation {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            obligation_id: decoder.text()?.to_owned(),
            transfer_id: TransferId::from_digest(decoder.digest()?),
            fence: decoder.u64()?,
            reason: decoder.text()?.to_owned(),
            follow_up_digest: decoder.digest()?,
            created_at: TimestampNs(decoder.i128()?),
        })
    }
}

/// Sealed canonical ATP lifecycle receipt (secret-free; maps to `schemas/transfer_receipt.v1.json`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleReceipt {
    /// Deterministic domain-separated transfer identity.
    pub transfer_id: TransferId,
    /// Canonical manifest root digest.
    pub root_digest: ContentDigest,
    /// Source node identity.
    pub source: String,
    /// Destination node or archive identity.
    pub destination: String,
    /// Exact semantic `ContractBasis` / anchor digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Active publication fence bound into this receipt.
    pub publication_fence: u64,
    /// Current or terminal semantic transfer state.
    pub semantic_state: SemanticTransferState,
    /// Current or terminal archive publication state, if archive mode is enabled.
    pub archive_state: Option<ArchivePublicationState>,
    /// Ordered sequence of semantic transfer states observed.
    pub semantic_transitions: Vec<SemanticTransferState>,
    /// Ordered sequence of archive publication states observed.
    pub archive_transitions: Vec<ArchivePublicationState>,
    /// Final state and remaining live work of every registered transport path.
    pub path_states: Vec<(String, PathState, u64)>,
    /// Non-collapsed byte and object counters.
    pub counters: TransferCounters,
    /// Distinct verified failure domains.
    pub failure_domains: Vec<String>,
    /// Published remote provider identity tuple, if archive root published.
    pub provider_tuple: Option<String>,
    /// Authoritative ledger commit anchor, if semantic root committed.
    pub commit_anchor: Option<ContentDigest>,
    /// Digest of the verified proof-of-retrievability witness, if recorded.
    pub proof_of_retrievability_digest: Option<ContentDigest>,
    /// Digest of the latest append-only journal record.
    pub journal_head_digest: Option<ContentDigest>,
    /// Total records persisted in the resumable journal.
    pub journal_record_count: u64,
    /// Cumulative observed bytes charged.
    pub bytes_spent: u64,
    /// Cumulative observed operations charged.
    pub ops_spent: u64,
    /// Explicit per-child custody disposition.
    pub staged_child_dispositions: Vec<(ContentDigest, StagedChildDisposition)>,
    /// Durable reconciliation obligation when terminal state is `Indeterminate`.
    pub reconciliation_obligation: Option<IndeterminateTransferObligation>,
    /// Optional terminal diagnostic reason.
    pub terminal_reason: Option<String>,
    /// Canonical SHA-256 receipt digest (`fss.atp_lifecycle_receipt.v1`).
    pub receipt_digest: ContentDigest,
}

impl LifecycleReceipt {
    /// Emits one secret-free JSON-lines record carrying both semantic and path transitions,
    /// digests, publication fence, object counts/bytes, provider tuple, proof-of-retrievability,
    /// obligation state, and exact reproduction command.
    #[must_use]
    pub fn to_jsonl_line(&self, scenario: &str, seed: u64, repro_cmd: &str) -> String {
        let semantic_seq: Vec<String> = self
            .semantic_transitions
            .iter()
            .map(|s| format!("\"{}\"", s.canonical_id()))
            .collect();
        let archive_seq: Vec<String> = self
            .archive_transitions
            .iter()
            .map(|a| format!("\"{}\"", a.canonical_id()))
            .collect();
        let paths_json: Vec<String> = self
            .path_states
            .iter()
            .map(|(pid, st, work)| {
                format!(
                    "{{\"pathId\":\"{}\",\"state\":\"{}\",\"liveWork\":{work}}}",
                    json_escape(pid),
                    st.canonical_id()
                )
            })
            .collect();
        let archive_state_json = match self.archive_state {
            Some(a) => format!("\"{}\"", a.canonical_id()),
            None => "null".to_owned(),
        };
        let state_str = self
            .archive_state
            .map_or("planned", ArchivePublicationState::receipt_state_str);
        let provider_json = match &self.provider_tuple {
            Some(pt) => format!("\"{}\"", json_escape(pt)),
            None => "null".to_owned(),
        };
        let por_json = match self.proof_of_retrievability_digest {
            Some(d) => format!("\"{d}\""),
            None => "null".to_owned(),
        };
        let journal_json = match self.journal_head_digest {
            Some(d) => format!("\"{d}\""),
            None => "null".to_owned(),
        };
        let obligation_json = match &self.reconciliation_obligation {
            Some(ob) => format!(
                "{{\"obligationId\":\"{}\",\"fence\":{},\"reason\":\"{}\"}}",
                json_escape(&ob.obligation_id),
                ob.fence,
                json_escape(&ob.reason),
            ),
            None => "null".to_owned(),
        };
        format!(
            concat!(
                "{{\"schema\":\"fss.transfer_receipt.v1\",",
                "\"scenario\":\"{}\",\"seed\":{},",
                "\"transferId\":\"{}\",\"rootDigest\":\"{}\",",
                "\"state\":\"{}\",\"semanticState\":\"{}\",\"archiveState\":{},",
                "\"source\":\"{}\",\"destination\":\"{}\",",
                "\"publicationFence\":{},\"contractBasisDigest\":\"{}\",\"authorityGeneration\":{},",
                "\"bytes\":{},\"objects\":{},",
                "\"counters\":{{\"offeredBytes\":{},\"receivedBytes\":{},\"verifiedBytes\":{},\"committedBytes\":{},\"reusedBytes\":{},\"offeredObjects\":{},\"verifiedObjects\":{},\"committedObjects\":{}}},",
                "\"semanticTransitions\":[{}],\"archiveTransitions\":[{}],\"pathStates\":[{}],",
                "\"providerTuple\":{},\"proofOfRetrievability\":{},",
                "\"journalDigest\":{},\"journalRecords\":{},\"bytesSpent\":{},\"opsSpent\":{},",
                "\"reconciliationObligation\":{},\"receiptDigest\":\"{}\",\"repro\":\"{}\"}}"
            ),
            json_escape(scenario),
            seed,
            self.transfer_id,
            self.root_digest,
            state_str,
            self.semantic_state.canonical_id(),
            archive_state_json,
            json_escape(&self.source),
            json_escape(&self.destination),
            self.publication_fence,
            self.contract_basis_digest,
            self.authority_generation,
            self.counters.verified_bytes,
            self.counters.verified_objects,
            self.counters.offered_bytes,
            self.counters.received_bytes,
            self.counters.verified_bytes,
            self.counters.committed_bytes,
            self.counters.reused_bytes,
            self.counters.offered_objects,
            self.counters.verified_objects,
            self.counters.committed_objects,
            semantic_seq.join(","),
            archive_seq.join(","),
            paths_json.join(","),
            provider_json,
            por_json,
            journal_json,
            self.journal_record_count,
            self.bytes_spent,
            self.ops_spent,
            obligation_json,
            self.receipt_digest,
            json_escape(repro_cmd),
        )
    }
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Typed, machine-readable refusals emitted by the ATP lifecycle crosswalk, reducers, and journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AtpLifecycleError {
    /// Skipped or backward state transition (`atp.refuse.skipped_publication`).
    SkippedTransition {
        /// Lifecycle layer where the illegal move was attempted.
        layer: LifecycleLayer,
        /// Current state identifier.
        from: &'static str,
        /// Rejected target state identifier.
        to: &'static str,
    },
    /// Root commit/publication attempted while a child is unverified/incomplete (`atp.refuse.root_before_child`).
    RootBeforeChild {
        /// Offending child digest.
        child: ContentDigest,
        /// Machine-readable reason.
        reason: String,
    },
    /// Publication or mutation presented a fence older than active lease (`atp.refuse.stale_fence`).
    StaleFence {
        /// Currently active publication fence.
        active: u64,
        /// Rejected stale fence.
        supplied: u64,
    },
    /// Committed receipt requested before `RootCommitted` / `RootPublished` (`atp.refuse.receipt_before_commit`).
    ReceiptBeforeCommit {
        /// Current semantic state.
        semantic: SemanticTransferState,
        /// Current archive state, if enabled.
        archive: Option<ArchivePublicationState>,
    },
    /// Path close attempted while in-flight ops, buffers, or open handles remain nonzero (`atp.refuse.path_close_live_work`).
    PathCloseWithLiveWork {
        /// Path identifier.
        path_id: String,
        /// Remaining in-flight operations.
        in_flight_ops: u64,
        /// Remaining live memory buffers.
        live_buffers: u64,
        /// Remaining open handles.
        open_handles: u64,
    },
    /// Cancellation finalize attempted while paths remain unclosed.
    ActivePathsRemaining {
        /// Unclosed path identifier.
        path_id: String,
        /// Current path state.
        state: PathState,
        /// Remaining live work on that path.
        live_work: u64,
    },
    /// Archive `Complete` attempted without a matching witnessed `RetrievabilityVerified` proof (`atp.refuse.complete_without_retrievability`).
    ArchiveCompleteWithoutRetrievability {
        /// Current archive state that lacked verified retrievability.
        current: ArchivePublicationState,
    },
    /// Capability, privacy, or destination authorization revoked (`atp.refuse.authority_revoked`).
    AuthorityRevoked {
        /// Revocation detail.
        reason: String,
    },
    /// Anchor or generation drifted (`atp.refuse.incompatible_version`).
    StaleAnchorOrGeneration {
        /// Drift detail.
        reason: String,
    },
    /// Reconstructed post-repair digest disagrees with declared child (`atp.refuse.repair_digest_mismatch`).
    RepairDigestMismatch {
        /// Expected manifest child digest.
        expected: ContentDigest,
        /// Observed post-repair digest.
        reconstructed: ContentDigest,
    },
    /// Unregistered state spelling (`atp.refuse.unknown_spelling`).
    UnknownStateSpelling {
        /// Rejected spelling.
        spelling: String,
    },
    /// Cross-layer shared spelling passed bare without a layer qualifier (`atp.refuse.unknown_spelling`).
    AmbiguousBareSpelling {
        /// Ambiguous spelling requiring layer qualification.
        spelling: String,
    },
    /// Layer-qualified spelling disagreed with caller's expected layer.
    LayerMismatch {
        /// Supplied state spelling.
        spelling: String,
        /// Layer requested by the caller.
        expected: LifecycleLayer,
        /// Owning layer of the spelling.
        actual: LifecycleLayer,
    },
    /// Incompatible format/protocol version (`atp.refuse.incompatible_version`).
    IncompatibleVersion {
        /// Version incompatibility detail.
        reason: String,
    },
    /// Unknown critical extension in manifest/spec (`atp.refuse.incompatible_version`).
    UnknownCriticalExtension {
        /// Unrecognized critical extension identifier.
        extension: String,
    },
    /// Manifest root differed from pinned transfer spec.
    ManifestMismatch {
        /// Expected manifest root.
        expected: ContentDigest,
        /// Supplied mismatched digest.
        supplied: ContentDigest,
    },
    /// Undeclared child referenced by delivery, repair, or verification.
    UndeclaredChild {
        /// Undeclared child digest.
        child: ContentDigest,
    },
    /// Path was not registered.
    UnknownPath {
        /// Missing path identifier.
        path_id: String,
    },
    /// Duplicate path registration.
    DuplicatePath {
        /// Duplicate path identifier.
        path_id: String,
    },
    /// Path is not `Active` (e.g., `Suspect` or `Draining`) and cannot expose data.
    PathNotActive {
        /// Path identifier.
        path_id: String,
        /// Non-active current state.
        state: PathState,
    },
    /// Distinct failure domains below policy requirement.
    InsufficientFailureDomains {
        /// Minimum failure domains required by policy.
        required: u32,
        /// Distinct failure domains verified.
        observed: u32,
    },
    /// Byte, operation, or path budget exhausted.
    BudgetExhausted {
        /// Resource class that exhausted its allowance.
        resource: &'static str,
        /// Attempted cumulative usage.
        spent: u64,
        /// Hard allowance limit.
        limit: u64,
    },
    /// Cancellation already requested; no new forward offers/work admitted.
    CancellationInProgress,
    /// Monotonic clock moved backwards.
    ClockRewind {
        /// Previous monotonic timestamp.
        previous: TimestampNs,
        /// Rejected earlier timestamp.
        supplied: TimestampNs,
    },
    /// Corrupted, torn, truncated, or sequence-broken journal record.
    JournalCorrupt {
        /// Record sequence index where corruption was detected.
        seq: u64,
        /// Corruption detail.
        reason: String,
    },
    /// Journal record or size ceiling exceeded.
    JournalBoundsExceeded {
        /// Bound detail.
        reason: String,
    },
    /// Malformed request or invariant input.
    InvalidInput(String),
}

impl AtpLifecycleError {
    /// Stable refusal code matching `architecture/atp_lifecycles.json`.
    #[must_use]
    pub const fn refusal_code(&self) -> &'static str {
        match self {
            Self::SkippedTransition { .. } => "atp.refuse.skipped_publication",
            Self::RootBeforeChild { .. } | Self::UndeclaredChild { .. } => {
                "atp.refuse.root_before_child"
            }
            Self::StaleFence { .. } => "atp.refuse.stale_fence",
            Self::ReceiptBeforeCommit { .. } => "atp.refuse.receipt_before_commit",
            Self::PathCloseWithLiveWork { .. } | Self::ActivePathsRemaining { .. } => {
                "atp.refuse.path_close_live_work"
            }
            Self::ArchiveCompleteWithoutRetrievability { .. } => {
                "atp.refuse.complete_without_retrievability"
            }
            Self::AuthorityRevoked { .. } => "atp.refuse.authority_revoked",
            Self::RepairDigestMismatch { .. } => "atp.refuse.repair_digest_mismatch",
            Self::UnknownStateSpelling { .. }
            | Self::AmbiguousBareSpelling { .. }
            | Self::LayerMismatch { .. } => "atp.refuse.unknown_spelling",
            Self::IncompatibleVersion { .. }
            | Self::UnknownCriticalExtension { .. }
            | Self::StaleAnchorOrGeneration { .. } => "atp.refuse.incompatible_version",
            Self::ManifestMismatch { .. }
            | Self::UnknownPath { .. }
            | Self::DuplicatePath { .. }
            | Self::PathNotActive { .. }
            | Self::InsufficientFailureDomains { .. }
            | Self::BudgetExhausted { .. }
            | Self::CancellationInProgress
            | Self::ClockRewind { .. }
            | Self::JournalCorrupt { .. }
            | Self::JournalBoundsExceeded { .. }
            | Self::InvalidInput(_) => "atp.refuse.invalid_state_or_bounds",
        }
    }
}

impl fmt::Display for AtpLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.refusal_code())
    }
}

impl std::error::Error for AtpLifecycleError {}
