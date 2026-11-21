#![forbid(unsafe_code)]
//! Object-store provider trait and publication-lattice handles (FSS-061).
//!
//! The provider is the ATP-facing write protocol: immutable object bytes
//! climb a strictly monotone lattice —
//!
//! ```text
//! Staged -> Visible -> Durable -> Replicated -> Protected
//! ```
//!
//! — and retrievability is a *witnessed probe*, not an assumed property.
//! Canonical [`crate::ObjectManifest`] roots activate LAST: the root body and
//! every object in its declared, registered closure must already be `Durable`.
//! Root bindings are immutable, including across deactivation. Retirement requires
//! that no active root contain the object, including the root itself and descendants
//! of previously activated sub-manifests. No transition ever moves backwards. These rules are the
//! Rust projection of the TLC-checked `RootLastPublication` model
//! (`proofs/tla/`): R1 root-last, R2 monotonicity, R3 deletion closure,
//! R5 referential integrity.
//!
//! The lattice states are protocol-visible and canonically encoded
//! (tag-based, hand-audited; distinct from any convenience JSON).

pub mod memory;
/// Provider conformance oracle (FSS-062).
pub mod oracle;
/// Remote eventual-consistency and partial-list provider simulator (FSS-132).
pub mod remote_simulator;

use fss_core::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use fss_core::{ContentDigest, TimestampNs};

/// One object's position on the publication lattice.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PublicationState {
    /// Bytes staged under their content identity; not yet visible.
    Staged,
    /// Visible to readers through the store, single copy only.
    Visible,
    /// Durable on the primary provider (committed, not just buffered).
    Durable,
    /// Present on at least the provider's required replica count.
    Replicated,
    /// Protection parity admitted and verified (owner: `fss-custody`).
    Protected,
    /// Terminally retired (no active root references remain).
    Retired,
}

impl PublicationState {
    /// Stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Visible => "visible",
            Self::Durable => "durable",
            Self::Replicated => "replicated",
            Self::Protected => "protected",
            Self::Retired => "retired",
        }
    }

    /// Lattice rank; `Retired` is terminal off the ladder.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Staged => 1,
            Self::Visible => 2,
            Self::Durable => 3,
            Self::Replicated => 4,
            Self::Protected => 5,
            Self::Retired => 0,
        }
    }

    /// True only for `Retired`.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Retired)
    }

    /// Legal forward moves on the LADDER (never backwards, never skipping).
    /// `Retired` is deliberately absent: retirement is an authority-bearing
    /// act reachable only through [`ObjectStoreProvider::retire`], never
    /// through a positional advance.
    #[must_use]
    pub const fn can_advance_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Staged, Self::Visible)
                | (Self::Visible, Self::Durable)
                | (Self::Durable, Self::Replicated)
                | (Self::Replicated, Self::Protected)
        )
    }
}

impl CanonicalEncode for PublicationState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let tag: u8 = match self {
            Self::Staged => 1,
            Self::Visible => 2,
            Self::Durable => 3,
            Self::Replicated => 4,
            Self::Protected => 5,
            Self::Retired => 0,
        };
        encoder.u8(tag);
    }
}

impl CanonicalDecode for PublicationState {
    fn decode_canonical(
        decoder: &mut CanonicalDecoder<'_>,
    ) -> Result<Self, fss_core::ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Staged),
            2 => Ok(Self::Visible),
            3 => Ok(Self::Durable),
            4 => Ok(Self::Replicated),
            5 => Ok(Self::Protected),
            0 => Ok(Self::Retired),
            _ => Err(fss_core::ContractError::InvalidIdentifier),
        }
    }
}

/// Typed provider refusal. Every variant names the digest and the exact
/// lattice positions involved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderError {
    /// A transition attempted to move backwards or skip a lattice level.
    IllegalTransition {
        /// The object.
        digest: ContentDigest,
        /// Current state.
        from: PublicationState,
        /// Attempted target.
        to: PublicationState,
    },
    /// Root activation was attempted while a referenced child sits below
    /// `Durable` (root-last violation).
    RootBeforeDurableChildren {
        /// The manifest root that was refused.
        root: ContentDigest,
        /// Offending child digest.
        child: ContentDigest,
        /// The child's current state.
        child_state: PublicationState,
    },
    /// The manifest body itself has not reached durable custody.
    RootNotDurable {
        /// The root whose activation was refused.
        root: ContentDigest,
        /// The body's current provider state.
        state: PublicationState,
    },
    /// Retained root bytes are not an exact canonical object manifest.
    InvalidRootManifest {
        /// The root whose activation was refused.
        root: ContentDigest,
    },
    /// The supplied child list is oversized, duplicated, self-referential, or differs
    /// from the exact retained manifest, including its metadata dependency.
    RootChildrenMismatch {
        /// The immutable manifest root.
        root: ContentDigest,
    },
    /// A newly declared manifest would introduce a cycle through registered roots.
    RootCycle {
        /// The root whose activation was refused.
        root: ContentDigest,
    },
    /// Retirement was attempted while an active root still references the
    /// object.
    ActiveRootReference {
        /// The object.
        digest: ContentDigest,
        /// A root still referencing it.
        root: ContentDigest,
    },
    /// The object is unknown to this provider.
    UnknownObject(ContentDigest),
    /// A root activation named no children (a meaningless root).
    EmptyRoot {
        /// The root that was refused.
        root: ContentDigest,
    },
    /// Retrievability probe failed (bytes unreadable or digest mismatch).
    NotRetrievable {
        /// The object.
        digest: ContentDigest,
        /// Machine-readable reason.
        reason: String,
    },
    /// The underlying custody store refused (bounds, quota, corruption).
    Custody(String),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IllegalTransition { digest, from, to } => write!(
                f,
                "object {digest:?}: illegal lattice move {} -> {}",
                from.as_str(),
                to.as_str()
            ),
            Self::RootBeforeDurableChildren {
                root,
                child,
                child_state,
            } => write!(
                f,
                "root {root:?} refused: child {child:?} is only {}",
                child_state.as_str()
            ),
            Self::RootNotDurable { root, state } => write!(
                f,
                "root {root:?} refused: its manifest body is only {}",
                state.as_str()
            ),
            Self::InvalidRootManifest { root } => {
                write!(f, "root {root:?} is not a canonical retained manifest")
            }
            Self::RootChildrenMismatch { root } => {
                write!(
                    f,
                    "root {root:?} child list differs from its immutable manifest"
                )
            }
            Self::RootCycle { root } => {
                write!(f, "root {root:?} would introduce a manifest cycle")
            }
            Self::ActiveRootReference { digest, root } => {
                write!(
                    f,
                    "object {digest:?} still referenced by active root {root:?}"
                )
            }
            Self::UnknownObject(digest) => write!(f, "unknown object {digest:?}"),
            Self::EmptyRoot { root } => write!(f, "root {root:?} named no children"),
            Self::NotRetrievable { digest, reason } => {
                write!(f, "object {digest:?} not retrievable: {reason}")
            }
            Self::Custody(detail) => write!(f, "custody refusal: {detail}"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// A witnessed retrievability probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrievabilityWitness {
    /// The object probed.
    pub digest: ContentDigest,
    /// Ladder position at probe time.
    pub state: PublicationState,
    /// Replica copies the provider could read at probe time.
    pub readable_copies: u32,
    /// Probe instant (caller-time domain).
    pub probed_at: TimestampNs,
}

/// The ATP-facing object-store provider protocol (FSS-061).
///
/// Implementations are first-party and pure Rust. Every mutation advances
/// the lattice forward only; every read is witnessed; retirement is closed
/// under active-root references.
pub trait ObjectStoreProvider {
    /// Stages immutable bytes under their content identity. Idempotent:
    /// staging already-staged bytes is a no-op returning the same handle.
    fn stage(&mut self, bytes: &[u8]) -> Result<ContentDigest, ProviderError>;

    /// Advances one object one ladder step (e.g. `Visible -> Durable`).
    /// Refuses backwards moves, skips, unknown objects, and any target of
    /// `Retired` (use `retire`). Admission to `Visible` re-hashes the bytes
    /// against their identity: visibility means verified-and-readable.
    fn advance(
        &mut self,
        digest: ContentDigest,
        to: PublicationState,
    ) -> Result<PublicationState, ProviderError>;

    /// Activates an exact canonical [`crate::ObjectManifest`] root LAST.
    ///
    /// The root's retained body and declared, registered closure must be at least `Durable`
    /// and reverify against their content identities. `children` must be bounded, unique,
    /// and exactly match the retained manifest, including metadata; input order is immaterial.
    /// Previously activated sub-manifests retain their bindings even while inactive. A
    /// never-activated child stays opaque; parsing as a manifest does not confer graph authority.
    /// Exact retries are idempotent, while changing a root's child set always refuses.
    fn activate_root(
        &mut self,
        root: ContentDigest,
        children: &[ContentDigest],
    ) -> Result<(), ProviderError>;

    /// Deactivates this root's independent pin, preserving its immutable manifest binding.
    /// An active ancestor continues to pin the root and its declared, registered closure.
    fn deactivate_root(&mut self, root: ContentDigest) -> Result<(), ProviderError>;

    /// Retires an object terminally. Refused while any active root's registered closure
    /// contains it (including the active root itself), and refused without a deletion
    /// authority witness: the
    /// digest of the owner-authorized deletion record, which must itself be
    /// a distinct retained, verified object in this provider's custody. Retirement
    /// is an authority-bearing act, not a bookkeeping convenience.
    fn retire(
        &mut self,
        digest: ContentDigest,
        deletion_authority_witness: ContentDigest,
    ) -> Result<(), ProviderError>;

    /// Probes retrievability: the bytes must be readable and re-hash to the
    /// digest. Returns a witness, never a bare boolean.
    fn verify_retrievable(
        &mut self,
        digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<RetrievabilityWitness, ProviderError>;

    /// Reads one object's current lattice position.
    fn state(&self, digest: ContentDigest) -> Result<PublicationState, ProviderError>;
}
