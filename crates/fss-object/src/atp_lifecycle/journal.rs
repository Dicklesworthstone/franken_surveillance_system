#![forbid(unsafe_code)]
//! Append-only, checksummed, canonical resumable journal for ATP lifecycles.
//!
//! Every record binds format version, sequence number, predecessor record digest,
//! [`TransferId`], active publication fence, timestamp, typed transition event, and observed work
//! delta, sealed with a domain-separated SHA-256 checksum (`fss.atp_lifecycle_journal_record.v1`).
//! Torn bytes, unknown format versions, sequence gaps, broken hash chains, and trailing bytes fail
//! closed on decode/replay.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};

use super::crosswalk::{ArchiveObjectState, ArchivePublicationState, PathState};
use super::{
    ATP_LIFECYCLE_FORMAT_VERSION, ATP_LIFECYCLE_JOURNAL_RECORD_DOMAIN, AtpLifecycleError,
    IndeterminateTransferObligation, MAX_FAILURE_DOMAINS, MAX_JOURNAL_RECORDS, MAX_LABEL_BYTES,
    MAX_TRANSFER_CHILDREN, ProofOfRetrievability, StagedChildDisposition, TransferId,
};

/// Maximum canonical byte length of one serialized journal record (64 KiB).
pub const MAX_JOURNAL_RECORD_BYTES: usize = 64 * 1024;
/// Maximum total byte length of one persisted framed transfer journal file (16 MiB).
pub const MAX_JOURNAL_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Typed event appended to the resumable ATP lifecycle journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleEvent {
    /// Semantic: `Proposed -> Reserved` (and Archive: `Planned -> Reserved` when enabled).
    Reserve {
        /// Reserved byte allowance.
        reserved_bytes: u64,
        /// Reserved operation count.
        reserved_ops: u64,
    },
    /// Archive: `Reserved -> ManifestVerified`.
    VerifyManifest {
        /// Verified manifest root digest.
        manifest_root: ContentDigest,
    },
    /// Semantic: `Reserved -> Offered`.
    OfferGraph {
        /// Total offered bytes across manifest children.
        offered_bytes: u64,
        /// Total offered child objects.
        offered_objects: u64,
    },
    /// Semantic: `Offered -> Receiving` (and Archive: `ManifestVerified -> Fetching`).
    BeginReceiving,
    /// Path registration (`Discover`).
    PathDiscover {
        /// Stable path identifier.
        path_id: String,
        /// Physical or administrative failure domain.
        failure_domain: String,
    },
    /// Path transition (`Discover -> Candidate -> Probing -> Active | Suspect -> Draining -> Closed`).
    PathTransition {
        /// Target path identifier.
        path_id: String,
        /// Next path lifecycle state.
        to: PathState,
        /// Machine-readable reason for the transition.
        reason: String,
    },
    /// Path work-accounting update (in-flight operations, live buffers, open handles).
    PathWorkDelta {
        /// Target path identifier.
        path_id: String,
        /// Active in-flight transport operations.
        in_flight_ops: u64,
        /// Live memory buffers held by this path.
        live_buffers: u64,
        /// Open file/socket handles owned by this path.
        open_handles: u64,
    },
    /// Records an offered/received chunk or child object delivered over an active path.
    DeliverChild {
        /// Active path delivering this child.
        path_id: String,
        /// Declared content digest of the child object.
        child_digest: ContentDigest,
        /// Byte count delivered.
        bytes: u64,
        /// True when satisfied by an already-retained content-addressed copy.
        reused_existing: bool,
    },
    /// Records post-repair reconstruction of a child object; verifies canonical digest equality.
    RepairChild {
        /// Declared content digest of the child object.
        child_digest: ContentDigest,
        /// Reconstructed canonical digest after repair decode.
        reconstructed_digest: ContentDigest,
        /// Number of repair symbols consumed.
        repair_symbols_used: u64,
        /// Reconstructed byte length.
        bytes: u64,
    },
    /// Marks one child verified after full canonical rehash/post-repair verification.
    VerifyChild {
        /// Declared content digest of the verified child.
        child_digest: ContentDigest,
        /// Verified byte count matching the manifest.
        verified_bytes: u64,
    },
    /// Advances one child's archive-object custody state on the monotone 7-step ladder.
    AdvanceChildArchiveState {
        /// Declared content digest of the child object.
        child_digest: ContentDigest,
        /// Next archive-object custody state.
        to: ArchiveObjectState,
    },
    /// Archive: `Fetching -> Staged`.
    MarkStaged,
    /// Semantic: `Receiving -> ChildrenVerified` and/or Archive: `Staged -> ObjectVerified`.
    MarkChildrenVerified,
    /// Semantic/Archive: `GraphClosed`.
    CloseGraph,
    /// Semantic: `GraphClosed -> DurabilitySatisfied`.
    SatisfyDurability {
        /// Distinct verified failure domains.
        failure_domains: Vec<String>,
    },
    /// Archive: `GraphClosed -> ExposureReady`.
    MarkExposureReady {
        /// Policy epoch verified prior to root exposure.
        policy_epoch: u64,
    },
    /// Explicit fence renewal (`new_fence > active_fence`).
    AdvanceFence {
        /// Strictly greater replacement publication fence.
        new_fence: u64,
    },
    /// Semantic: `DurabilitySatisfied -> RootCommitted`.
    CommitRoot {
        /// Committed manifest root digest.
        root_digest: ContentDigest,
        /// Authoritative ledger commit anchor.
        commit_anchor: ContentDigest,
    },
    /// Archive: `ExposureReady -> RootPublished`.
    PublishArchiveRoot {
        /// Published manifest root digest.
        root_digest: ContentDigest,
        /// Target provider identity tuple.
        provider_tuple: String,
    },
    /// Archive: `RootPublished -> ReplicaQualified`.
    QualifyReplicas {
        /// Independent failure domains holding qualified replicas.
        failure_domains: Vec<String>,
    },
    /// Archive: `ReplicaQualified -> RetrievabilityVerified`.
    VerifyRetrievability {
        /// Witnessed proof-of-retrievability sample.
        proof: ProofOfRetrievability,
    },
    /// Archive: `RetrievabilityVerified -> Complete`.
    CompleteArchive,
    /// Archive: `Complete | Scrubbed -> Scrubbed`.
    ScrubArchive {
        /// Integrity scrub digest.
        scrub_digest: ContentDigest,
    },
    /// Archive: `Complete | Scrubbed -> Retired`.
    RetireArchive {
        /// Graph-complete deletion proof digest.
        deletion_proof: ContentDigest,
    },
    /// Semantic: `RootCommitted -> ReceiptSealed`.
    SealReceipt {
        /// Digest of the committed receipt built immediately before appending this seal.
        receipt_digest: ContentDigest,
    },
    /// Semantic: `ReceiptSealed -> Superseded`.
    Supersede {
        /// Newer transfer superseding this generation.
        successor_transfer_id: TransferId,
    },
    /// Semantic: `Proposed | Reserved -> Rejected`.
    Reject {
        /// Policy or admission refusal reason.
        reason: String,
    },
    /// Quarantine invalid/corrupt bytes without exposing them.
    Quarantine {
        /// Diagnostic quarantine reason.
        reason: String,
        /// Children marked quarantined.
        affected_children: Vec<ContentDigest>,
    },
    /// Request cooperative cancellation: stops new offers and requires path drain before finalize.
    RequestCancel {
        /// Cancellation reason.
        reason: String,
    },
    /// Finalize cancellation once every path is `Closed` with `live_work == 0`.
    FinalizeCancel {
        /// Explicit post-cancellation disposition for every declared child.
        child_dispositions: Vec<(ContentDigest, StagedChildDisposition)>,
    },
    /// Explicit terminal archive failure with typed reason.
    FailArchive {
        /// Failure cause description.
        reason: String,
    },
    /// Remote commit/publication cannot be resolved: moves to `Indeterminate` with durable obligation.
    MarkIndeterminate {
        /// Durable reconciliation obligation owned by this outcome.
        obligation: IndeterminateTransferObligation,
        /// True when archive publication state also enters `Indeterminate`.
        archive_state_affected: bool,
    },
}

impl LifecycleEvent {
    // Nested lists have their own wire bounds, independent of the overall record length.
    fn check_list_bounds(&self) -> Result<(), AtpLifecycleError> {
        let fits = match self {
            Self::SatisfyDurability { failure_domains }
            | Self::QualifyReplicas { failure_domains } => {
                failure_domains.len() <= MAX_FAILURE_DOMAINS
                    && failure_domains.iter().all(|d| d.len() <= MAX_LABEL_BYTES)
            }
            Self::Quarantine { affected_children, .. } => {
                affected_children.len() <= MAX_TRANSFER_CHILDREN
            }
            Self::FinalizeCancel { child_dispositions } => {
                child_dispositions.len() <= MAX_TRANSFER_CHILDREN
            }
            _ => true,
        };
        if fits {
            Ok(())
        } else {
            Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: "event list exceeds the canonical journal decoder bounds".to_owned(),
            })
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Self::Reserve { .. } => 1,
            Self::VerifyManifest { .. } => 2,
            Self::OfferGraph { .. } => 3,
            Self::BeginReceiving => 4,
            Self::PathDiscover { .. } => 5,
            Self::PathTransition { .. } => 6,
            Self::PathWorkDelta { .. } => 7,
            Self::DeliverChild { .. } => 8,
            Self::RepairChild { .. } => 9,
            Self::VerifyChild { .. } => 10,
            Self::AdvanceChildArchiveState { .. } => 11,
            Self::MarkStaged => 12,
            Self::MarkChildrenVerified => 13,
            Self::CloseGraph => 14,
            Self::SatisfyDurability { .. } => 15,
            Self::MarkExposureReady { .. } => 16,
            Self::AdvanceFence { .. } => 17,
            Self::CommitRoot { .. } => 18,
            Self::PublishArchiveRoot { .. } => 19,
            Self::QualifyReplicas { .. } => 20,
            Self::VerifyRetrievability { .. } => 21,
            Self::CompleteArchive => 22,
            Self::ScrubArchive { .. } => 23,
            Self::RetireArchive { .. } => 24,
            Self::SealReceipt { .. } => 25,
            Self::Supersede { .. } => 26,
            Self::Reject { .. } => 27,
            Self::Quarantine { .. } => 28,
            Self::RequestCancel { .. } => 29,
            Self::FinalizeCancel { .. } => 30,
            Self::FailArchive { .. } => 31,
            Self::MarkIndeterminate { .. } => 32,
        }
    }
}

fn encode_bounded_text_list(encoder: &mut CanonicalEncoder, items: &[String]) {
    encoder.u64(items.len() as u64);
    for item in items {
        encoder.text(item);
    }
}

fn decode_bounded_text_list(
    decoder: &mut CanonicalDecoder<'_>,
    max_items: usize,
) -> Result<Vec<String>, ContractError> {
    let count = usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
    if count > max_items || count.saturating_mul(4) > decoder.remaining() {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let s = decoder.text()?;
        if s.len() > MAX_LABEL_BYTES {
            return Err(ContractError::InvalidIdentifier);
        }
        out.push(s.to_owned());
    }
    Ok(out)
}

impl CanonicalEncode for LifecycleEvent {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.tag());
        match self {
            Self::Reserve {
                reserved_bytes,
                reserved_ops,
            } => {
                encoder.u64(*reserved_bytes);
                encoder.u64(*reserved_ops);
            }
            Self::VerifyManifest { manifest_root } => encoder.digest(*manifest_root),
            Self::OfferGraph {
                offered_bytes,
                offered_objects,
            } => {
                encoder.u64(*offered_bytes);
                encoder.u64(*offered_objects);
            }
            Self::BeginReceiving
            | Self::MarkStaged
            | Self::MarkChildrenVerified
            | Self::CloseGraph
            | Self::CompleteArchive => {}
            Self::PathDiscover {
                path_id,
                failure_domain,
            } => {
                encoder.text(path_id);
                encoder.text(failure_domain);
            }
            Self::PathTransition {
                path_id,
                to,
                reason,
            } => {
                encoder.text(path_id);
                to.encode_canonical(encoder);
                encoder.text(reason);
            }
            Self::PathWorkDelta {
                path_id,
                in_flight_ops,
                live_buffers,
                open_handles,
            } => {
                encoder.text(path_id);
                encoder.u64(*in_flight_ops);
                encoder.u64(*live_buffers);
                encoder.u64(*open_handles);
            }
            Self::DeliverChild {
                path_id,
                child_digest,
                bytes,
                reused_existing,
            } => {
                encoder.text(path_id);
                encoder.digest(*child_digest);
                encoder.u64(*bytes);
                encoder.bool(*reused_existing);
            }
            Self::RepairChild {
                child_digest,
                reconstructed_digest,
                repair_symbols_used,
                bytes,
            } => {
                encoder.digest(*child_digest);
                encoder.digest(*reconstructed_digest);
                encoder.u64(*repair_symbols_used);
                encoder.u64(*bytes);
            }
            Self::VerifyChild {
                child_digest,
                verified_bytes,
            } => {
                encoder.digest(*child_digest);
                encoder.u64(*verified_bytes);
            }
            Self::AdvanceChildArchiveState { child_digest, to } => {
                encoder.digest(*child_digest);
                to.encode_canonical(encoder);
            }
            Self::SatisfyDurability { failure_domains } => {
                encode_bounded_text_list(encoder, failure_domains);
            }
            Self::MarkExposureReady { policy_epoch } => encoder.u64(*policy_epoch),
            Self::AdvanceFence { new_fence } => encoder.u64(*new_fence),
            Self::CommitRoot {
                root_digest,
                commit_anchor,
            } => {
                encoder.digest(*root_digest);
                encoder.digest(*commit_anchor);
            }
            Self::PublishArchiveRoot {
                root_digest,
                provider_tuple,
            } => {
                encoder.digest(*root_digest);
                encoder.text(provider_tuple);
            }
            Self::QualifyReplicas { failure_domains } => {
                encode_bounded_text_list(encoder, failure_domains);
            }
            Self::VerifyRetrievability { proof } => proof.encode_canonical(encoder),
            Self::ScrubArchive { scrub_digest } => encoder.digest(*scrub_digest),
            Self::RetireArchive { deletion_proof } => encoder.digest(*deletion_proof),
            Self::SealReceipt { receipt_digest } => encoder.digest(*receipt_digest),
            Self::Supersede {
                successor_transfer_id,
            } => encoder.digest(successor_transfer_id.digest()),
            Self::Reject { reason }
            | Self::RequestCancel { reason }
            | Self::FailArchive { reason } => encoder.text(reason),
            Self::Quarantine {
                reason,
                affected_children,
            } => {
                encoder.text(reason);
                encoder.u64(affected_children.len() as u64);
                for digest in affected_children {
                    encoder.digest(*digest);
                }
            }
            Self::FinalizeCancel { child_dispositions } => {
                encoder.u64(child_dispositions.len() as u64);
                for (digest, disp) in child_dispositions {
                    encoder.digest(*digest);
                    disp.encode_canonical(encoder);
                }
            }
            Self::MarkIndeterminate {
                obligation,
                archive_state_affected,
            } => {
                obligation.encode_canonical(encoder);
                encoder.bool(*archive_state_affected);
            }
        }
    }
}

impl CanonicalDecode for LifecycleEvent {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Reserve {
                reserved_bytes: decoder.u64()?,
                reserved_ops: decoder.u64()?,
            }),
            2 => Ok(Self::VerifyManifest {
                manifest_root: decoder.digest()?,
            }),
            3 => Ok(Self::OfferGraph {
                offered_bytes: decoder.u64()?,
                offered_objects: decoder.u64()?,
            }),
            4 => Ok(Self::BeginReceiving),
            5 => Ok(Self::PathDiscover {
                path_id: decoder.text()?.to_owned(),
                failure_domain: decoder.text()?.to_owned(),
            }),
            6 => Ok(Self::PathTransition {
                path_id: decoder.text()?.to_owned(),
                to: PathState::decode_canonical(decoder)?,
                reason: decoder.text()?.to_owned(),
            }),
            7 => Ok(Self::PathWorkDelta {
                path_id: decoder.text()?.to_owned(),
                in_flight_ops: decoder.u64()?,
                live_buffers: decoder.u64()?,
                open_handles: decoder.u64()?,
            }),
            8 => Ok(Self::DeliverChild {
                path_id: decoder.text()?.to_owned(),
                child_digest: decoder.digest()?,
                bytes: decoder.u64()?,
                reused_existing: decoder.bool()?,
            }),
            9 => Ok(Self::RepairChild {
                child_digest: decoder.digest()?,
                reconstructed_digest: decoder.digest()?,
                repair_symbols_used: decoder.u64()?,
                bytes: decoder.u64()?,
            }),
            10 => Ok(Self::VerifyChild {
                child_digest: decoder.digest()?,
                verified_bytes: decoder.u64()?,
            }),
            11 => Ok(Self::AdvanceChildArchiveState {
                child_digest: decoder.digest()?,
                to: ArchiveObjectState::decode_canonical(decoder)?,
            }),
            12 => Ok(Self::MarkStaged),
            13 => Ok(Self::MarkChildrenVerified),
            14 => Ok(Self::CloseGraph),
            15 => Ok(Self::SatisfyDurability {
                failure_domains: decode_bounded_text_list(decoder, MAX_FAILURE_DOMAINS)?,
            }),
            16 => Ok(Self::MarkExposureReady {
                policy_epoch: decoder.u64()?,
            }),
            17 => Ok(Self::AdvanceFence {
                new_fence: decoder.u64()?,
            }),
            18 => Ok(Self::CommitRoot {
                root_digest: decoder.digest()?,
                commit_anchor: decoder.digest()?,
            }),
            19 => Ok(Self::PublishArchiveRoot {
                root_digest: decoder.digest()?,
                provider_tuple: decoder.text()?.to_owned(),
            }),
            20 => Ok(Self::QualifyReplicas {
                failure_domains: decode_bounded_text_list(decoder, MAX_FAILURE_DOMAINS)?,
            }),
            21 => Ok(Self::VerifyRetrievability {
                proof: ProofOfRetrievability::decode_canonical(decoder)?,
            }),
            22 => Ok(Self::CompleteArchive),
            23 => Ok(Self::ScrubArchive {
                scrub_digest: decoder.digest()?,
            }),
            24 => Ok(Self::RetireArchive {
                deletion_proof: decoder.digest()?,
            }),
            25 => Ok(Self::SealReceipt {
                receipt_digest: decoder.digest()?,
            }),
            26 => Ok(Self::Supersede {
                successor_transfer_id: TransferId::from_digest(decoder.digest()?),
            }),
            27 => Ok(Self::Reject {
                reason: decoder.text()?.to_owned(),
            }),
            28 => {
                let reason = decoder.text()?.to_owned();
                let count = usize::try_from(decoder.u64()?)
                    .map_err(|_| ContractError::InvalidIdentifier)?;
                if count > MAX_TRANSFER_CHILDREN || count.saturating_mul(33) > decoder.remaining() {
                    return Err(ContractError::InvalidIdentifier);
                }
                let mut affected_children = Vec::with_capacity(count);
                for _ in 0..count {
                    affected_children.push(decoder.digest()?);
                }
                Ok(Self::Quarantine {
                    reason,
                    affected_children,
                })
            }
            29 => Ok(Self::RequestCancel {
                reason: decoder.text()?.to_owned(),
            }),
            30 => {
                let count = usize::try_from(decoder.u64()?)
                    .map_err(|_| ContractError::InvalidIdentifier)?;
                if count > MAX_TRANSFER_CHILDREN || count.saturating_mul(34) > decoder.remaining() {
                    return Err(ContractError::InvalidIdentifier);
                }
                let mut child_dispositions = Vec::with_capacity(count);
                for _ in 0..count {
                    let digest = decoder.digest()?;
                    let disp = StagedChildDisposition::decode_canonical(decoder)?;
                    child_dispositions.push((digest, disp));
                }
                Ok(Self::FinalizeCancel { child_dispositions })
            }
            31 => Ok(Self::FailArchive {
                reason: decoder.text()?.to_owned(),
            }),
            32 => Ok(Self::MarkIndeterminate {
                obligation: IndeterminateTransferObligation::decode_canonical(decoder)?,
                archive_state_affected: decoder.bool()?,
            }),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// One append-only, hash-chained, checksummed journal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    /// Durable record format version (`ATP_LIFECYCLE_FORMAT_VERSION`).
    pub format_version: u32,
    /// Strictly contiguous zero-based sequence number.
    pub seq: u64,
    /// Previous record's `record_digest` (None for `seq == 0`).
    pub prev_digest: Option<ContentDigest>,
    /// Deterministic transfer identity.
    pub transfer_id: TransferId,
    /// Publication/lease fence active when this event was admitted.
    pub fence: u64,
    /// Monotonic timestamp (nanoseconds).
    pub timestamp_ns: TimestampNs,
    /// Semantic/archive/path lifecycle event.
    pub event: LifecycleEvent,
    /// Observed bytes charged on this transition.
    pub work_bytes: u64,
    /// Observed operations charged on this transition.
    pub work_ops: u64,
    /// Domain-separated SHA-256 checksum over the canonical body.
    pub record_digest: ContentDigest,
}

impl JournalRecord {
    /// Constructs and seals a new journal record with its canonical digest.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        seq: u64,
        prev_digest: Option<ContentDigest>,
        transfer_id: TransferId,
        fence: u64,
        timestamp_ns: TimestampNs,
        event: LifecycleEvent,
        work_bytes: u64,
        work_ops: u64,
    ) -> Self {
        let mut record = Self {
            format_version: ATP_LIFECYCLE_FORMAT_VERSION,
            seq,
            prev_digest,
            transfer_id,
            fence,
            timestamp_ns,
            event,
            work_bytes,
            work_ops,
            record_digest: ContentDigest::sha256(b"unsealed-record"),
        };
        record.record_digest = record.compute_digest();
        record
    }

    /// Computes the canonical SHA-256 digest of this record's body.
    #[must_use]
    pub fn compute_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        ContentDigest::sha256(&enc.finish())
    }

    fn encode_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(ATP_LIFECYCLE_JOURNAL_RECORD_DOMAIN);
        encoder.u32(self.format_version);
        encoder.u64(self.seq);
        match self.prev_digest {
            Some(prev) => {
                encoder.bool(true);
                encoder.digest(prev);
            }
            None => encoder.bool(false),
        }
        encoder.digest(self.transfer_id.digest());
        encoder.u64(self.fence);
        encoder.i128(self.timestamp_ns.0);
        self.event.encode_canonical(encoder);
        encoder.u64(self.work_bytes);
        encoder.u64(self.work_ops);
    }

    /// Serializes this record (body + sealed digest) to exact canonical bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AtpLifecycleError> {
        self.event.check_list_bounds()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.record_digest);
        let bytes = enc
            .finish_checked()
            .map_err(|_| AtpLifecycleError::JournalBoundsExceeded {
                reason: "canonical encoder rejected oversized journal record field".to_owned(),
            })?;
        if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
            return Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: format!(
                    "journal record size {} exceeds max {MAX_JOURNAL_RECORD_BYTES}",
                    bytes.len()
                ),
            });
        }
        Ok(bytes)
    }

    /// Cold-decodes one canonical record, validating format version, checksum, and exact length.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AtpLifecycleError> {
        if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
            return Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: format!(
                    "journal record bytes {} exceed max {MAX_JOURNAL_RECORD_BYTES}",
                    bytes.len()
                ),
            });
        }
        let mut dec = CanonicalDecoder::new(bytes);
        let domain = dec.text().map_err(|_| AtpLifecycleError::JournalCorrupt {
            seq: 0,
            reason: "invalid journal record domain header".to_owned(),
        })?;
        if domain != ATP_LIFECYCLE_JOURNAL_RECORD_DOMAIN {
            return Err(AtpLifecycleError::IncompatibleVersion {
                reason: format!("unexpected journal record domain '{domain}'"),
            });
        }
        let format_version = dec.u32().map_err(|_| AtpLifecycleError::JournalCorrupt {
            seq: 0,
            reason: "truncated journal format version".to_owned(),
        })?;
        if format_version != ATP_LIFECYCLE_FORMAT_VERSION {
            return Err(AtpLifecycleError::IncompatibleVersion {
                reason: format!(
                    "unsupported journal format version {format_version}; expected {ATP_LIFECYCLE_FORMAT_VERSION}"
                ),
            });
        }
        let seq = dec.u64().map_err(|_| AtpLifecycleError::JournalCorrupt {
            seq: 0,
            reason: "truncated journal sequence".to_owned(),
        })?;
        let has_prev = dec.bool().map_err(|_| AtpLifecycleError::JournalCorrupt {
            seq,
            reason: "truncated prev_digest tag".to_owned(),
        })?;
        let prev_digest = if has_prev {
            Some(
                dec.digest()
                    .map_err(|_| AtpLifecycleError::JournalCorrupt {
                        seq,
                        reason: "truncated prev_digest".to_owned(),
                    })?,
            )
        } else {
            None
        };
        let transfer_id = TransferId::from_digest(dec.digest().map_err(|_| {
            AtpLifecycleError::JournalCorrupt {
                seq,
                reason: "truncated transfer_id".to_owned(),
            }
        })?);
        let fence = dec.u64().map_err(|_| AtpLifecycleError::JournalCorrupt {
            seq,
            reason: "truncated fence".to_owned(),
        })?;
        let timestamp_ns =
            TimestampNs(dec.i128().map_err(|_| AtpLifecycleError::JournalCorrupt {
                seq,
                reason: "truncated timestamp".to_owned(),
            })?);
        let event = LifecycleEvent::decode_canonical(&mut dec).map_err(|_| {
            AtpLifecycleError::JournalCorrupt {
                seq,
                reason: "malformed or truncated lifecycle event".to_owned(),
            }
        })?;
        let work_bytes = dec.u64().map_err(|_| AtpLifecycleError::JournalCorrupt {
            seq,
            reason: "truncated work_bytes".to_owned(),
        })?;
        let work_ops = dec.u64().map_err(|_| AtpLifecycleError::JournalCorrupt {
            seq,
            reason: "truncated work_ops".to_owned(),
        })?;
        let stored_digest = dec
            .digest()
            .map_err(|_| AtpLifecycleError::JournalCorrupt {
                seq,
                reason: "truncated record checksum digest".to_owned(),
            })?;
        dec.ensure_finished()
            .map_err(|_| AtpLifecycleError::JournalCorrupt {
                seq,
                reason: "trailing garbage bytes after journal record".to_owned(),
            })?;

        let record = Self {
            format_version,
            seq,
            prev_digest,
            transfer_id,
            fence,
            timestamp_ns,
            event,
            work_bytes,
            work_ops,
            record_digest: stored_digest,
        };
        let computed = record.compute_digest();
        if computed != stored_digest {
            return Err(AtpLifecycleError::JournalCorrupt {
                seq,
                reason: "record checksum mismatch".to_owned(),
            });
        }
        Ok(record)
    }
}

/// Bounded in-memory append-only transfer journal (with raw canonical byte export/import).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferJournal {
    transfer_id: TransferId,
    max_records: usize,
    records: Vec<JournalRecord>,
    framed_bytes: u64,
}

impl TransferJournal {
    /// Creates an empty bounded journal for one transfer.
    pub fn new(transfer_id: TransferId, max_records: usize) -> Result<Self, AtpLifecycleError> {
        if max_records == 0 || max_records > MAX_JOURNAL_RECORDS {
            return Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: format!(
                    "max_records ({max_records}) must be within 1..={MAX_JOURNAL_RECORDS}"
                ),
            });
        }
        Ok(Self {
            transfer_id,
            max_records,
            records: Vec::new(),
            framed_bytes: 0,
        })
    }

    /// Appends one new event, chaining `prev_digest` and checking hard bounds.
    pub fn append(
        &mut self,
        fence: u64,
        timestamp_ns: TimestampNs,
        event: LifecycleEvent,
        work_bytes: u64,
        work_ops: u64,
    ) -> Result<JournalRecord, AtpLifecycleError> {
        if self.records.len() >= self.max_records {
            return Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: format!("journal record cap ({}) exhausted", self.max_records),
            });
        }
        event.check_list_bounds()?;
        let seq = self.records.len() as u64;
        let prev_digest = self.records.last().map(|r| r.record_digest);
        let record = JournalRecord::seal(
            seq,
            prev_digest,
            self.transfer_id,
            fence,
            timestamp_ns,
            event,
            work_bytes,
            work_ops,
        );
        let record_len = record.to_canonical_bytes()?.len() as u64;
        let next_size = self.framed_bytes + 4 + record_len;
        if next_size > MAX_JOURNAL_FILE_BYTES {
            return Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: format!("framed journal size {next_size} exceeds max {MAX_JOURNAL_FILE_BYTES}"),
            });
        }
        self.framed_bytes = next_size;
        self.records.push(record.clone());
        Ok(record)
    }

    /// Verifies and returns all records in append order.
    #[must_use]
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }

    /// Head digest of the latest journal record, if any.
    #[must_use]
    pub fn head_digest(&self) -> Option<ContentDigest> {
        self.records.last().map(|r| r.record_digest)
    }

    /// Exports a prefix `0..prefix_len` as raw canonical framed bytes (for crash-cut replay tests).
    pub fn export_framed_prefix(&self, prefix_len: usize) -> Result<Vec<u8>, AtpLifecycleError> {
        let len = prefix_len.min(self.records.len());
        let mut out = Vec::new();
        for rec in &self.records[..len] {
            let bytes = rec.to_canonical_bytes()?;
            let frame_len = u32::try_from(bytes.len()).map_err(|_| {
                AtpLifecycleError::JournalBoundsExceeded {
                    reason: "framed record length exceeds u32".to_owned(),
                }
            })?;
            out.extend_from_slice(&frame_len.to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }

    /// Decodes a framed canonical journal stream, validating every checksum, sequence number,
    /// hash-chain predecessor link, and transfer identity. Any torn frame fails closed.
    pub fn decode_framed_records(
        expected_transfer_id: TransferId,
        framed: &[u8],
        max_records: usize,
    ) -> Result<Vec<JournalRecord>, AtpLifecycleError> {
        if max_records == 0 || max_records > MAX_JOURNAL_RECORDS {
            return Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: format!(
                    "max_records ({max_records}) must be within 1..={MAX_JOURNAL_RECORDS}"
                ),
            });
        }
        if framed.len() as u64 > MAX_JOURNAL_FILE_BYTES {
            return Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: format!("framed journal exceeds max {MAX_JOURNAL_FILE_BYTES} bytes"),
            });
        }
        let mut pos = 0usize;
        let mut out = Vec::new();
        let mut expected_prev: Option<ContentDigest> = None;

        while pos < framed.len() {
            if out.len() >= max_records {
                return Err(AtpLifecycleError::JournalBoundsExceeded {
                    reason: format!("framed journal exceeds max_records ({max_records})"),
                });
            }
            if framed.len().saturating_sub(pos) < 4 {
                return Err(AtpLifecycleError::JournalCorrupt {
                    seq: out.len() as u64,
                    reason: "torn journal frame length prefix".to_owned(),
                });
            }
            let frame_len = u32::from_be_bytes([
                framed[pos],
                framed[pos + 1],
                framed[pos + 2],
                framed[pos + 3],
            ]) as usize;
            pos += 4;
            if frame_len == 0 || framed.len().saturating_sub(pos) < frame_len {
                return Err(AtpLifecycleError::JournalCorrupt {
                    seq: out.len() as u64,
                    reason: "torn journal frame payload".to_owned(),
                });
            }
            let record = JournalRecord::from_canonical_bytes(&framed[pos..pos + frame_len])?;
            pos += frame_len;

            let expected_seq = out.len() as u64;
            if record.seq != expected_seq {
                return Err(AtpLifecycleError::JournalCorrupt {
                    seq: expected_seq,
                    reason: format!("sequence gap: expected {expected_seq}, got {}", record.seq),
                });
            }
            if record.prev_digest != expected_prev {
                return Err(AtpLifecycleError::JournalCorrupt {
                    seq: expected_seq,
                    reason: "broken journal hash chain (prev_digest mismatch)".to_owned(),
                });
            }
            if record.transfer_id != expected_transfer_id {
                return Err(AtpLifecycleError::JournalCorrupt {
                    seq: expected_seq,
                    reason: "journal record belongs to a different transfer_id".to_owned(),
                });
            }
            expected_prev = Some(record.record_digest);
            out.push(record);
        }
        Ok(out)
    }

    /// Atomically persists the complete framed canonical journal to a regular non-symlink file.
    ///
    /// Writes to a sibling temporary file, fsyncs it, and renames into `path` so a crash mid-write
    /// never exposes a half-written journal at `path`. Refuses symlink targets and oversize files.
    pub fn write_framed_file(&self, path: &Path) -> Result<(), AtpLifecycleError> {
        if let Ok(meta) = fs::symlink_metadata(path)
            && !meta.file_type().is_file()
        {
            return Err(AtpLifecycleError::InvalidInput(
                "transfer journal target path must be a regular non-symlink file".to_owned(),
            ));
        }
        let bytes = self.export_framed_prefix(self.records.len())?;
        if (bytes.len() as u64) > MAX_JOURNAL_FILE_BYTES {
            return Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: format!(
                    "framed journal size {} exceeds max {MAX_JOURNAL_FILE_BYTES}",
                    bytes.len()
                ),
            });
        }
        let parent = path.parent().ok_or_else(|| {
            AtpLifecycleError::InvalidInput(
                "transfer journal path has no parent directory".to_owned(),
            )
        })?;
        let parent_dir = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            AtpLifecycleError::InvalidInput("transfer journal path has invalid filename".to_owned())
        })?;
        let seq = NEXT_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_path = parent_dir.join(format!(
            ".{file_name}.tmp-{}-{}-{}",
            std::process::id(),
            self.records.len(),
            seq,
        ));
        let write_result = (|| -> Result<(), AtpLifecycleError> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)
                .map_err(|err| {
                    AtpLifecycleError::InvalidInput(format!(
                        "open temp transfer journal failed: {err}"
                    ))
                })?;
            file.write_all(&bytes).map_err(|err| {
                AtpLifecycleError::InvalidInput(format!(
                    "write temp transfer journal failed: {err}"
                ))
            })?;
            file.sync_all().map_err(|err| {
                AtpLifecycleError::InvalidInput(format!("sync temp transfer journal failed: {err}"))
            })?;
            fs::rename(&tmp_path, path).map_err(|err| {
                AtpLifecycleError::InvalidInput(format!("rename transfer journal failed: {err}"))
            })?;
            if let Ok(dir) = File::open(parent_dir) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        write_result
    }

    /// Reads and verifies a persisted framed transfer journal from a bounded regular non-symlink file.
    pub fn read_framed_file(
        expected_transfer_id: TransferId,
        path: &Path,
        max_records: usize,
    ) -> Result<Vec<JournalRecord>, AtpLifecycleError> {
        let meta = fs::symlink_metadata(path).map_err(|err| AtpLifecycleError::JournalCorrupt {
            seq: 0,
            reason: format!("cannot stat transfer journal: {err}"),
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(AtpLifecycleError::JournalCorrupt {
                seq: 0,
                reason: "transfer journal must be a regular non-symlink file".to_owned(),
            });
        }
        if meta.len() > MAX_JOURNAL_FILE_BYTES {
            return Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: format!(
                    "transfer journal file size {} exceeds max {MAX_JOURNAL_FILE_BYTES}",
                    meta.len()
                ),
            });
        }
        let file = File::open(path).map_err(|err| AtpLifecycleError::JournalCorrupt {
            seq: 0,
            reason: format!("cannot open transfer journal: {err}"),
        })?;
        let opened_meta = file
            .metadata()
            .map_err(|err| AtpLifecycleError::JournalCorrupt {
                seq: 0,
                reason: format!("cannot inspect opened transfer journal: {err}"),
            })?;
        if !opened_meta.file_type().is_file() {
            return Err(AtpLifecycleError::JournalCorrupt {
                seq: 0,
                reason: "opened transfer journal is not a regular file".to_owned(),
            });
        }
        let mut framed = Vec::new();
        file.take(MAX_JOURNAL_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut framed)
            .map_err(|err| AtpLifecycleError::JournalCorrupt {
                seq: 0,
                reason: format!("read transfer journal failed: {err}"),
            })?;
        if (framed.len() as u64) > MAX_JOURNAL_FILE_BYTES {
            return Err(AtpLifecycleError::JournalBoundsExceeded {
                reason: format!(
                    "transfer journal grew past max {MAX_JOURNAL_FILE_BYTES} bytes during read"
                ),
            });
        }
        Self::decode_framed_records(expected_transfer_id, &framed, max_records)
    }
}

/// Helper mapping an archive state to whether archive-layer receipt sealing is allowed.
#[must_use]
pub const fn archive_state_allows_committed_receipt(state: ArchivePublicationState) -> bool {
    matches!(
        state,
        ArchivePublicationState::RootPublished
            | ArchivePublicationState::ReplicaQualified
            | ArchivePublicationState::RetrievabilityVerified
            | ArchivePublicationState::Complete
            | ArchivePublicationState::Scrubbed
            | ArchivePublicationState::Retired
    )
}
