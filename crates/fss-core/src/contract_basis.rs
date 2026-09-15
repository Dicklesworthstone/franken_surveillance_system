#![forbid(unsafe_code)]
//! Deterministic ContractBasis canonical encoding, registry-digest computation,
//! compatibility negotiation, and fail-closed stale-basis refusal semantics (FSS-241).
//!
//! Governed by INV-083..116 and ADR-0001 (authority plane).
//!
//! Under semantic protocol `fss/1`, every decision-bearing agent request and response
//! binds an exact `ContractBasis` that pins the semantic protocol, schema catalog,
//! ontology generation, and the exact content digests of the operation, view, capability,
//! error, and cost registries, alongside producer release and accepted nightly identities.
//!
//! Incompatible or stale contract bases fail closed with typed errors conforming to
//! `registries/ERRORS.md`:
//! - `ERR-AGENT-PROTOCOL-001`: Protocol, schema, ontology, registry mismatch or unregistered surface
//! - `ERR-AGENT-SESSION-STALE-001`: Stale basis referencing superseded generations or older anchors
//! - `ERR-SCHEMA-UNSUPPORTED-001`: Unknown durable binary format version, corrupt magic, or length violation
//! - `ERR-NEG-CHECKSUM-MISMATCH-001`: Corrupt trailing checksum verification failure

use core::fmt;
use std::error::Error;

use crate::agent::{ContractBasis, ContractBasisRegistryBytes};
use crate::agent_operation::AgentOperation;
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode};
use crate::contract::ContractError;
use crate::digest::{ContentDigest, DigestAlgorithm, Sha256Hasher};
use crate::evidence::LedgerAnchor;

/// Canonical schema URI for agent contract basis instances.
pub const SCHEMA_CONTRACT_BASIS: &str = "fss.agent_contract_basis.v1";

/// Magic 8-byte header for canonical contract-basis binary envelopes.
pub const CONTRACT_BASIS_MAGIC: [u8; 8] = *b"FSSBAS01";

/// Current format version for contract-basis binary envelopes.
pub const CONTRACT_BASIS_FORMAT_VERSION: u32 = 1;

/// Standard semantic protocol version for FSS.
pub const CANONICAL_SEMANTIC_PROTOCOL: &str = "fss/1";

/// Standard reference ontology generation.
pub const CANONICAL_ONTOLOGY_GENERATION_ID: &str = "ontology:reference:v1";

/// Standard producer release identifier.
pub const CANONICAL_PRODUCER_RELEASE_ID: &str = "fss:release:v1";

/// Generation tag for the frozen reference contract basis.
pub const REFERENCE_CONTRACT_BASIS_GENERATION: &str = "gen:fss1:reference-v1";

/// Pinned freeze digest of the schema catalog for the reference generation (`registries/SCHEMAS.md`).
pub const REFERENCE_SCHEMA_CATALOG_DIGEST: &str =
    "sha256:a82134f79c3922ebdd2ee7f0ab2a10528f6289c19000cb64f67385d7ebc6a577";

/// Pinned freeze digest of the public operation registry (`gen:fss1:public-v1`).
pub const REFERENCE_OPERATION_REGISTRY_DIGEST: &str =
    "sha256:9bbec4e6845ea702f676cd22472e5fb0d35ca3b3d97f66cbfccb452182413da8";

/// Pinned freeze digest of the registered views (`architecture/agent_views.json`).
pub const REFERENCE_VIEW_REGISTRY_DIGEST: &str =
    "sha256:a757a7698a79e1c72fb71d6aefa80df264a1896e8ac7f0ad455c411b2f3f5704";

/// Pinned freeze digest of the capability registry (`gen:fss1:capabilities-v1`).
pub const REFERENCE_CAPABILITY_REGISTRY_DIGEST: &str =
    "sha256:5056fe20103a6c9a157fdb0e29bf5371384b976e874bf2964ff817fb202f045a";

/// Pinned freeze digest of the error registry (`registries/ERRORS.md`).
pub const REFERENCE_ERROR_REGISTRY_DIGEST: &str =
    "sha256:94b31547a77d2b1b598acca17e320d7100633f46d4a7a89caee3c230fe204b63";

/// Pinned freeze digest of the operation cost registry (`gen:fss1:operation-cost-v1`).
pub const REFERENCE_COST_REGISTRY_DIGEST: &str =
    "sha256:c885c834fe3d492076090e551c5988d6ed363bcf3a2432c41e67fe527ccf83b9";

/// Pinned canonical semantic basis digest of the reference contract basis.
pub const REFERENCE_CONTRACT_BASIS_CANONICAL_DIGEST: &str =
    "sha256:fa54646d17da5fc021e5bc1b39647064030d00ea76eebf7f09a315963de07d0f";

/// Pinned binary freeze digest of the serialized canonical binary reference contract basis.
pub const REFERENCE_CONTRACT_BASIS_FREEZE_DIGEST: &str =
    "sha256:a28c7480524a6e5763a433ebe2ebcfe1df771cd8f6e29998f37ee6d68d4516ab";

/// Maximum byte size of a canonical contract-basis binary payload (64 KiB).
pub const MAX_CONTRACT_BASIS_BINARY_BYTES: usize = 64 * 1024;

/// Minimum byte size of a canonical binary contract-basis envelope (8 magic + 4 version + 4 length + 32 checksum = 48 bytes).
pub const MIN_CONTRACT_BASIS_BINARY_BYTES: usize = 48;

/// Maximum character length of an identifier field (e.g. producer release, ontology).
pub const MAX_IDENTIFIER_LEN: usize = 256;

/// Maximum character length of a single compatibility note.
pub const MAX_NOTE_LEN: usize = 1024;

/// Maximum number of compatibility notes allowed in negotiation.
pub const MAX_NOTES_COUNT: usize = 64;

/// Exact set of cryptographic digests covering all six canonical registries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryDigestSet {
    /// Digest of the schema catalog.
    pub schema_catalog_digest: ContentDigest,
    /// Digest of the public operation registry.
    pub operation_registry_digest: ContentDigest,
    /// Digest of the registered view definitions.
    pub view_registry_digest: ContentDigest,
    /// Digest of the capability registry.
    pub capability_registry_digest: ContentDigest,
    /// Digest of the error registry.
    pub error_registry_digest: ContentDigest,
    /// Digest of the operation cost registry.
    pub cost_registry_digest: ContentDigest,
}

impl RegistryDigestSet {
    /// Computes canonical digests directly from exact raw registry byte slices.
    #[must_use]
    pub fn from_registry_bytes(spec: ContractBasisRegistryBytes<'_>) -> Self {
        Self {
            schema_catalog_digest: ContentDigest::sha256(spec.schema_catalog),
            operation_registry_digest: ContentDigest::sha256(spec.operations),
            view_registry_digest: ContentDigest::sha256(spec.views),
            capability_registry_digest: ContentDigest::sha256(spec.capabilities),
            error_registry_digest: ContentDigest::sha256(spec.errors),
            cost_registry_digest: ContentDigest::sha256(spec.costs),
        }
    }

    /// Assembles a complete `ContractBasis` from this digest set and metadata.
    #[must_use]
    pub fn into_contract_basis(
        self,
        producer_release_id: impl Into<String>,
        accepted_nightly: Option<String>,
    ) -> ContractBasis {
        ContractBasis {
            semantic_protocol: CANONICAL_SEMANTIC_PROTOCOL.to_owned(),
            schema_catalog_digest: self.schema_catalog_digest,
            ontology_generation_id: CANONICAL_ONTOLOGY_GENERATION_ID.to_owned(),
            operation_registry_digest: self.operation_registry_digest,
            view_registry_digest: self.view_registry_digest,
            capability_registry_digest: self.capability_registry_digest,
            error_registry_digest: self.error_registry_digest,
            cost_registry_digest: self.cost_registry_digest,
            producer_release_id: producer_release_id.into(),
            accepted_nightly,
        }
    }
}

/// Detailed result of evaluating compatibility between two contract bases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompatibilityResult {
    /// Exact match across all protocol, ontology, registry digests, and release IDs.
    Identical,
    /// Compatible protocol, ontology, and registry digests, but differing release or nightly metadata.
    CompatibleWithNotes {
        /// Non-fatal divergence observations.
        notes: Vec<String>,
    },
    /// Incompatible basis: fails closed with an explicit typed refusal reason.
    Incompatible(ContractBasisRefusal),
}

/// Type alias aligning with the semantic specification.
pub type BasisCompatibility = CompatibilityResult;

/// Typed refusal reason when a candidate ContractBasis cannot be accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractBasisRefusal {
    /// Incompatible semantic protocol (expected `fss/1`).
    IncompatibleProtocol {
        /// Expected protocol.
        expected: String,
        /// Observed protocol.
        actual: String,
    },
    /// Incompatible ontology generation.
    IncompatibleOntology {
        /// Expected ontology generation.
        expected: String,
        /// Observed ontology generation.
        actual: String,
    },
    /// Incompatible schema catalog digest.
    IncompatibleSchemaCatalog {
        /// Expected schema catalog digest.
        expected: ContentDigest,
        /// Observed schema catalog digest.
        actual: ContentDigest,
    },
    /// Incompatible operation registry digest.
    IncompatibleOperationRegistry {
        /// Expected operation registry digest.
        expected: ContentDigest,
        /// Observed operation registry digest.
        actual: ContentDigest,
    },
    /// Incompatible view registry digest.
    IncompatibleViewRegistry {
        /// Expected view registry digest.
        expected: ContentDigest,
        /// Observed view registry digest.
        actual: ContentDigest,
    },
    /// Incompatible capability registry digest.
    IncompatibleCapabilityRegistry {
        /// Expected capability registry digest.
        expected: ContentDigest,
        /// Observed capability registry digest.
        actual: ContentDigest,
    },
    /// Incompatible error registry digest.
    IncompatibleErrorRegistry {
        /// Expected error registry digest.
        expected: ContentDigest,
        /// Observed error registry digest.
        actual: ContentDigest,
    },
    /// Incompatible cost registry digest.
    IncompatibleCostRegistry {
        /// Expected cost registry digest.
        expected: ContentDigest,
        /// Observed cost registry digest.
        actual: ContentDigest,
    },
    /// Basis is stale: references a superseded generation, tombstoned digest, or expired anchor.
    StaleBasis {
        /// Specific staleness classification.
        reason: StaleBasisReason,
    },
    /// Empty or malformed producer release ID.
    InvalidProducerRelease {
        /// Rationale for refusal.
        reason: String,
    },
    /// Incompatible nightly build requirement.
    IncompatibleNightly {
        /// Server required nightly toolchain.
        required: String,
        /// Candidate nightly toolchain.
        actual: Option<String>,
    },
    /// Operation name is not a registered `fss/1` operation (`AOP-001`..`AOP-014`).
    UnregisteredOperation {
        /// The refused operation name.
        name: String,
    },
}

impl ContractBasisRefusal {
    /// Returns the stable diagnostic error code from `registries/ERRORS.md`.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::IncompatibleProtocol { .. } => "ERR-AGENT-PROTOCOL-001",
            Self::StaleBasis { .. } => "ERR-AGENT-SESSION-STALE-001",
            Self::IncompatibleOntology { .. }
            | Self::IncompatibleSchemaCatalog { .. }
            | Self::IncompatibleOperationRegistry { .. }
            | Self::IncompatibleViewRegistry { .. }
            | Self::IncompatibleCapabilityRegistry { .. }
            | Self::IncompatibleErrorRegistry { .. }
            | Self::IncompatibleCostRegistry { .. }
            | Self::InvalidProducerRelease { .. }
            | Self::IncompatibleNightly { .. }
            | Self::UnregisteredOperation { .. } => "ERR-AGENT-PROTOCOL-001",
        }
    }

    /// Provides deterministic discovery and upgrade guidance per the comprehensive plan.
    #[must_use]
    pub fn remediation_guidance(&self) -> &'static str {
        match self {
            Self::IncompatibleProtocol { .. } => {
                "upgrade client to semantic protocol fss/1; run session.open to negotiate basis"
            }
            Self::IncompatibleOntology { .. } => {
                "upgrade client to matching ontology generation; run session.open to negotiate basis"
            }
            Self::StaleBasis { .. } => {
                "rebase session and enumerate every invalidated assumption, alias, grant, lease, plan, continuation, and affordance before proceeding"
            }
            Self::IncompatibleSchemaCatalog { .. } => {
                "fetch current schema catalog from registries/SCHEMAS.md and rebuild request envelopes"
            }
            Self::IncompatibleOperationRegistry { .. } => {
                "fetch current public operations from architecture/fss1_public_registry.json"
            }
            Self::IncompatibleViewRegistry { .. } => {
                "fetch current view definitions from architecture/agent_views.json"
            }
            Self::IncompatibleCapabilityRegistry { .. } => {
                "fetch current capability definitions from architecture/capabilities.json"
            }
            Self::IncompatibleErrorRegistry { .. } => {
                "fetch current error definitions from registries/ERRORS.md"
            }
            Self::IncompatibleCostRegistry { .. } => {
                "fetch current operation cost registry from architecture/operation_cost_registry.toml"
            }
            Self::InvalidProducerRelease { .. } => {
                "provide a non-empty, valid producer release identifier"
            }
            Self::IncompatibleNightly { .. } => {
                "use the pinned nightly toolchain matching the server contract basis"
            }
            Self::UnregisteredOperation { .. } => {
                "fetch current public operations from architecture/fss1_public_registry.json and address only registered AOP-001..AOP-014 operation names"
            }
        }
    }
}

impl fmt::Display for ContractBasisRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompatibleProtocol { expected, actual } => {
                write!(
                    f,
                    "incompatible protocol: expected {expected}, got {actual}"
                )
            }
            Self::IncompatibleOntology { expected, actual } => {
                write!(
                    f,
                    "incompatible ontology: expected {expected}, got {actual}"
                )
            }
            Self::IncompatibleSchemaCatalog { expected, actual } => {
                write!(
                    f,
                    "incompatible schema catalog digest: expected {expected}, got {actual}"
                )
            }
            Self::IncompatibleOperationRegistry { expected, actual } => {
                write!(
                    f,
                    "incompatible operation registry digest: expected {expected}, got {actual}"
                )
            }
            Self::IncompatibleViewRegistry { expected, actual } => {
                write!(
                    f,
                    "incompatible view registry digest: expected {expected}, got {actual}"
                )
            }
            Self::IncompatibleCapabilityRegistry { expected, actual } => {
                write!(
                    f,
                    "incompatible capability registry digest: expected {expected}, got {actual}"
                )
            }
            Self::IncompatibleErrorRegistry { expected, actual } => {
                write!(
                    f,
                    "incompatible error registry digest: expected {expected}, got {actual}"
                )
            }
            Self::IncompatibleCostRegistry { expected, actual } => {
                write!(
                    f,
                    "incompatible cost registry digest: expected {expected}, got {actual}"
                )
            }
            Self::StaleBasis { reason } => {
                write!(f, "stale basis: {reason}")
            }
            Self::InvalidProducerRelease { reason } => {
                write!(f, "invalid producer release: {reason}")
            }
            Self::IncompatibleNightly { required, actual } => {
                write!(
                    f,
                    "incompatible nightly toolchain: required {required}, got {actual:?}"
                )
            }
            Self::UnregisteredOperation { name } => {
                write!(f, "unregistered operation name: {name}")
            }
        }
    }
}

/// Cause classification for a stale-basis refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StaleBasisReason {
    /// Registry generation is older than the current pinned active generation.
    SupersededGeneration {
        /// Registry name.
        registry: &'static str,
        /// Current pinned active generation.
        current_generation: String,
        /// Candidate basis generation.
        basis_generation: String,
    },
    /// Digest matches a known historical or tombstoned generation.
    TombstonedRegistryDigest {
        /// Registry name.
        registry: &'static str,
        /// Tombstoned digest referenced.
        tombstoned_digest: ContentDigest,
    },
    /// Candidate anchor is not strictly older than the active anchor, or lineages diverge.
    StaleAnchor {
        /// Detailed description of the anchor comparison violation.
        detail: String,
    },
    /// Other domain-specific staleness condition.
    Other(String),
}

impl fmt::Display for StaleBasisReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SupersededGeneration {
                registry,
                current_generation,
                basis_generation,
            } => {
                write!(
                    f,
                    "superseded generation for {registry}: current is {current_generation}, basis has {basis_generation}"
                )
            }
            Self::TombstonedRegistryDigest {
                registry,
                tombstoned_digest,
            } => {
                write!(
                    f,
                    "references tombstoned {registry} digest {tombstoned_digest}"
                )
            }
            Self::StaleAnchor { detail } => {
                write!(f, "anchor staleness: {detail}")
            }
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

/// Typed error returned by contract-basis operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractBasisError {
    /// Binary magic header does not match `CONTRACT_BASIS_MAGIC`.
    BadMagic {
        /// Expected magic bytes.
        expected: [u8; 8],
        /// Observed magic bytes.
        actual: [u8; 8],
    },
    /// Format version is not supported by this implementation.
    UnknownVersion {
        /// Expected format version.
        expected: u32,
        /// Observed format version.
        actual: u32,
    },
    /// Input ended prematurely before one complete header, trailer, or declared payload.
    Truncated {
        /// Minimum expected length.
        expected_len: usize,
        /// Actual observed length.
        actual_len: usize,
    },
    /// Declared payload length or file size exceeds pre-allocation limit.
    InputOversized {
        /// Configured limit.
        limit: usize,
        /// Actual observed length.
        actual_len: usize,
    },
    /// Trailing bytes remain after one complete validated envelope.
    TrailingBytes {
        /// Expected byte length.
        expected_len: usize,
        /// Actual observed byte length.
        actual_len: usize,
    },
    /// Checksum verification over the exact bytes failed.
    ChecksumMismatch {
        /// Expected checksum from envelope trailer.
        expected: ContentDigest,
        /// Actual computed checksum.
        actual: ContentDigest,
    },
    /// Contract basis was refused during compatibility check or negotiation.
    IncompatibleBasis {
        /// Refusal classification and remediation guidance.
        refusal: ContractBasisRefusal,
    },
    /// Basis is stale: references a superseded generation or invalid anchor.
    StaleBasis {
        /// Staleness reason.
        reason: StaleBasisReason,
    },
    /// Field failed identifier syntax validation.
    InvalidIdentifier {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// Incompatible semantic protocol.
    IncompatibleProtocol {
        /// Expected protocol.
        expected: String,
        /// Actual protocol.
        actual: String,
    },
    /// Underlying contract or canonical codec error.
    Contract(ContractError),
}

impl ContractBasisError {
    /// Returns the stable diagnostic error code from `registries/ERRORS.md`.
    #[must_use]
    pub fn error_id(&self) -> &'static str {
        match self {
            Self::IncompatibleBasis { refusal } => refusal.error_code(),
            Self::StaleBasis { .. } => "ERR-AGENT-SESSION-STALE-001",
            Self::IncompatibleProtocol { .. } => "ERR-AGENT-PROTOCOL-001",
            Self::BadMagic { .. }
            | Self::UnknownVersion { .. }
            | Self::Truncated { .. }
            | Self::InputOversized { .. }
            | Self::TrailingBytes { .. } => "ERR-SCHEMA-UNSUPPORTED-001",
            Self::ChecksumMismatch { .. } => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::InvalidIdentifier { .. } => "ERR-AGENT-PROTOCOL-001",
            Self::Contract(err) => match err {
                ContractError::StaleBasisRequired | ContractError::StaleBasisNotOlder => {
                    "ERR-AGENT-SESSION-STALE-001"
                }
                _ => "ERR-AGENT-PROTOCOL-001",
            },
        }
    }
}

impl fmt::Display for ContractBasisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic { expected, actual } => {
                write!(f, "bad magic header: expected {expected:?}, got {actual:?}")
            }
            Self::UnknownVersion { expected, actual } => {
                write!(
                    f,
                    "unknown format version: expected {expected}, got {actual}"
                )
            }
            Self::Truncated {
                expected_len,
                actual_len,
            } => {
                write!(
                    f,
                    "truncated input: expected at least {expected_len} bytes, got {actual_len}"
                )
            }
            Self::InputOversized { limit, actual_len } => {
                write!(
                    f,
                    "input oversized: limit is {limit} bytes, got {actual_len}"
                )
            }
            Self::TrailingBytes {
                expected_len,
                actual_len,
            } => {
                write!(
                    f,
                    "trailing bytes: expected {expected_len} bytes, got {actual_len}"
                )
            }
            Self::ChecksumMismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected}, computed {actual}"
                )
            }
            Self::IncompatibleBasis { refusal } => {
                write!(f, "incompatible contract basis: {refusal}")
            }
            Self::StaleBasis { reason } => {
                write!(f, "stale contract basis: {reason}")
            }
            Self::InvalidIdentifier { field } => {
                write!(f, "invalid identifier in field '{field}'")
            }
            Self::IncompatibleProtocol { expected, actual } => {
                write!(
                    f,
                    "incompatible protocol: expected {expected}, got {actual}"
                )
            }
            Self::Contract(err) => write!(f, "contract error: {err}"),
        }
    }
}

impl Error for ContractBasisError {}

impl CanonicalDecode for ContractBasis {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let semantic_protocol = decoder.text()?.to_string();
        let schema_catalog_digest = ContentDigest::decode_canonical(decoder)?;
        let ontology_generation_id = decoder.text()?.to_string();
        let operation_registry_digest = ContentDigest::decode_canonical(decoder)?;
        let view_registry_digest = ContentDigest::decode_canonical(decoder)?;
        let capability_registry_digest = ContentDigest::decode_canonical(decoder)?;
        let error_registry_digest = ContentDigest::decode_canonical(decoder)?;
        let cost_registry_digest = ContentDigest::decode_canonical(decoder)?;
        let producer_release_id = decoder.text()?.to_string();
        let accepted_nightly = if decoder.bool()? {
            Some(decoder.text()?.to_string())
        } else {
            None
        };
        let basis = Self {
            semantic_protocol,
            schema_catalog_digest,
            ontology_generation_id,
            operation_registry_digest,
            view_registry_digest,
            capability_registry_digest,
            error_registry_digest,
            cost_registry_digest,
            producer_release_id,
            accepted_nightly,
        };
        basis.validate()?;
        Ok(basis)
    }
}

fn parse_reference_digest(s: &str) -> ContentDigest {
    match ContentDigest::parse(s) {
        Ok(digest) => digest,
        Err(_) => ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32]),
    }
}

/// Constructs the canonical normative reference `ContractBasis` for the frozen baseline.
#[must_use]
pub fn reference_contract_basis() -> ContractBasis {
    ContractBasis {
        semantic_protocol: CANONICAL_SEMANTIC_PROTOCOL.to_owned(),
        schema_catalog_digest: parse_reference_digest(REFERENCE_SCHEMA_CATALOG_DIGEST),
        ontology_generation_id: CANONICAL_ONTOLOGY_GENERATION_ID.to_owned(),
        operation_registry_digest: parse_reference_digest(REFERENCE_OPERATION_REGISTRY_DIGEST),
        view_registry_digest: parse_reference_digest(REFERENCE_VIEW_REGISTRY_DIGEST),
        capability_registry_digest: parse_reference_digest(REFERENCE_CAPABILITY_REGISTRY_DIGEST),
        error_registry_digest: parse_reference_digest(REFERENCE_ERROR_REGISTRY_DIGEST),
        cost_registry_digest: parse_reference_digest(REFERENCE_COST_REGISTRY_DIGEST),
        producer_release_id: CANONICAL_PRODUCER_RELEASE_ID.to_owned(),
        accepted_nightly: None,
    }
}

/// Computes the exact set of registry digests from raw registry byte slices.
#[must_use]
pub fn compute_registry_digests(spec: ContractBasisRegistryBytes<'_>) -> RegistryDigestSet {
    RegistryDigestSet::from_registry_bytes(spec)
}

/// Validates structural invariants of a `ContractBasis`.
pub fn validate_contract_basis(basis: &ContractBasis) -> Result<(), ContractBasisError> {
    if basis.semantic_protocol != CANONICAL_SEMANTIC_PROTOCOL {
        return Err(ContractBasisError::IncompatibleProtocol {
            expected: CANONICAL_SEMANTIC_PROTOCOL.to_owned(),
            actual: basis.semantic_protocol.clone(),
        });
    }
    if basis.producer_release_id.trim().is_empty()
        || basis.producer_release_id.len() > MAX_IDENTIFIER_LEN
    {
        return Err(ContractBasisError::InvalidIdentifier {
            field: "producer_release_id",
        });
    }
    if basis.ontology_generation_id.trim().is_empty()
        || basis.ontology_generation_id.len() > MAX_IDENTIFIER_LEN
    {
        return Err(ContractBasisError::InvalidIdentifier {
            field: "ontology_generation_id",
        });
    }
    if basis
        .accepted_nightly
        .as_deref()
        .is_some_and(|nightly| nightly.trim().is_empty() || nightly.len() > MAX_IDENTIFIER_LEN)
    {
        return Err(ContractBasisError::InvalidIdentifier {
            field: "accepted_nightly",
        });
    }
    basis.validate().map_err(ContractBasisError::Contract)?;
    Ok(())
}

/// Encodes a `ContractBasis` into its self-describing canonical binary representation.
///
/// Binary format layout:
/// - 8 bytes: magic header `FSSBAS01`
/// - 4 bytes: format version (big-endian `u32`, current = 1)
/// - 4 bytes: inner canonical payload length (big-endian `u32`)
/// - N bytes: canonical payload bytes (via `CanonicalEncoder`)
/// - 32 bytes: trailing domain-separated SHA-256 checksum over schema domain
pub fn encode_canonical_binary(basis: &ContractBasis) -> Result<Vec<u8>, ContractBasisError> {
    validate_contract_basis(basis)?;

    let inner_bytes = basis
        .try_canonical_bytes()
        .map_err(ContractBasisError::Contract)?;

    let mut payload = Vec::with_capacity(16 + inner_bytes.len() + 32);
    payload.extend_from_slice(&CONTRACT_BASIS_MAGIC);
    payload.extend_from_slice(&CONTRACT_BASIS_FORMAT_VERSION.to_be_bytes());
    payload.extend_from_slice(&(inner_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&inner_bytes);

    if payload.len() + 32 > MAX_CONTRACT_BASIS_BINARY_BYTES {
        return Err(ContractBasisError::InputOversized {
            limit: MAX_CONTRACT_BASIS_BINARY_BYTES,
            actual_len: payload.len() + 32,
        });
    }

    // Domain-separated trailing SHA-256 checksum over domain `fss.agent_contract_basis.v1`
    let mut hasher = Sha256Hasher::new();
    hasher.update(SCHEMA_CONTRACT_BASIS.as_bytes());
    hasher.update(&payload);
    let checksum_bytes = hasher.finalize().map_err(ContractBasisError::Contract)?;

    payload.extend_from_slice(&checksum_bytes);
    Ok(payload)
}

/// Decodes a `ContractBasis` from its self-describing canonical binary representation.
///
/// Fails closed on truncated input, bad magic, unknown version, length over bound,
/// trailing bytes, or checksum mismatch.
pub fn decode_canonical_binary(bytes: &[u8]) -> Result<ContractBasis, ContractBasisError> {
    if bytes.len() < MIN_CONTRACT_BASIS_BINARY_BYTES {
        return Err(ContractBasisError::Truncated {
            expected_len: MIN_CONTRACT_BASIS_BINARY_BYTES,
            actual_len: bytes.len(),
        });
    }
    if bytes.len() > MAX_CONTRACT_BASIS_BINARY_BYTES {
        return Err(ContractBasisError::InputOversized {
            limit: MAX_CONTRACT_BASIS_BINARY_BYTES,
            actual_len: bytes.len(),
        });
    }

    // 1. Separate payload and trailing 32-byte checksum
    let payload_len = bytes.len() - 32;
    let (payload, trailer) = bytes.split_at(payload_len);

    // 2. Verify domain-separated checksum
    let mut hasher = Sha256Hasher::new();
    hasher.update(SCHEMA_CONTRACT_BASIS.as_bytes());
    hasher.update(payload);
    let computed = hasher.finalize().map_err(ContractBasisError::Contract)?;

    if computed != trailer {
        let mut trailer_bytes = [0u8; 32];
        trailer_bytes.copy_from_slice(trailer);
        return Err(ContractBasisError::ChecksumMismatch {
            expected: ContentDigest::new(DigestAlgorithm::Sha256, trailer_bytes),
            actual: ContentDigest::new(DigestAlgorithm::Sha256, computed),
        });
    }

    // 3. Verify magic header
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&payload[..8]);
    if magic != CONTRACT_BASIS_MAGIC {
        return Err(ContractBasisError::BadMagic {
            expected: CONTRACT_BASIS_MAGIC,
            actual: magic,
        });
    }

    // 4. Verify format version (refuse unknown versions; never guess)
    let mut ver_bytes = [0u8; 4];
    ver_bytes.copy_from_slice(&payload[8..12]);
    let version = u32::from_be_bytes(ver_bytes);
    if version != CONTRACT_BASIS_FORMAT_VERSION {
        return Err(ContractBasisError::UnknownVersion {
            expected: CONTRACT_BASIS_FORMAT_VERSION,
            actual: version,
        });
    }

    // 5. Read declared inner length
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&payload[12..16]);
    let declared_len = u32::from_be_bytes(len_bytes) as usize;
    let inner = &payload[16..];
    if inner.len() < declared_len {
        return Err(ContractBasisError::Truncated {
            expected_len: 16 + declared_len + 32,
            actual_len: bytes.len(),
        });
    }
    if inner.len() > declared_len {
        return Err(ContractBasisError::TrailingBytes {
            expected_len: 16 + declared_len + 32,
            actual_len: bytes.len(),
        });
    }

    // 6. Decode canonical inner payload
    let mut decoder = CanonicalDecoder::new(&inner[..declared_len]);
    let basis =
        ContractBasis::decode_canonical(&mut decoder).map_err(ContractBasisError::Contract)?;
    decoder
        .ensure_finished()
        .map_err(ContractBasisError::Contract)?;

    validate_contract_basis(&basis)?;
    Ok(basis)
}

/// Evaluates whether a candidate `ContractBasis` is compatible with this server/peer basis.
///
/// Fails closed: any mismatch in protocol, ontology, or any of the 6 registry digests
/// results in an explicit refusal variant with discovery/upgrade guidance.
#[must_use]
pub fn check_compatibility(
    expected: &ContractBasis,
    candidate: &ContractBasis,
) -> CompatibilityResult {
    // 1. Semantic protocol must match exactly ("fss/1")
    if candidate.semantic_protocol != expected.semantic_protocol {
        return CompatibilityResult::Incompatible(ContractBasisRefusal::IncompatibleProtocol {
            expected: expected.semantic_protocol.clone(),
            actual: candidate.semantic_protocol.clone(),
        });
    }

    // 2. Ontology generation must match
    if candidate.ontology_generation_id != expected.ontology_generation_id {
        return CompatibilityResult::Incompatible(ContractBasisRefusal::IncompatibleOntology {
            expected: expected.ontology_generation_id.clone(),
            actual: candidate.ontology_generation_id.clone(),
        });
    }

    // 3. Schema catalog digest must match
    if candidate.schema_catalog_digest != expected.schema_catalog_digest {
        return CompatibilityResult::Incompatible(
            ContractBasisRefusal::IncompatibleSchemaCatalog {
                expected: expected.schema_catalog_digest,
                actual: candidate.schema_catalog_digest,
            },
        );
    }

    // 4. Operation registry digest must match
    if candidate.operation_registry_digest != expected.operation_registry_digest {
        return CompatibilityResult::Incompatible(
            ContractBasisRefusal::IncompatibleOperationRegistry {
                expected: expected.operation_registry_digest,
                actual: candidate.operation_registry_digest,
            },
        );
    }

    // 5. View registry digest must match
    if candidate.view_registry_digest != expected.view_registry_digest {
        return CompatibilityResult::Incompatible(ContractBasisRefusal::IncompatibleViewRegistry {
            expected: expected.view_registry_digest,
            actual: candidate.view_registry_digest,
        });
    }

    // 6. Capability registry digest must match
    if candidate.capability_registry_digest != expected.capability_registry_digest {
        return CompatibilityResult::Incompatible(
            ContractBasisRefusal::IncompatibleCapabilityRegistry {
                expected: expected.capability_registry_digest,
                actual: candidate.capability_registry_digest,
            },
        );
    }

    // 7. Error registry digest must match
    if candidate.error_registry_digest != expected.error_registry_digest {
        return CompatibilityResult::Incompatible(
            ContractBasisRefusal::IncompatibleErrorRegistry {
                expected: expected.error_registry_digest,
                actual: candidate.error_registry_digest,
            },
        );
    }

    // 8. Cost registry digest must match
    if candidate.cost_registry_digest != expected.cost_registry_digest {
        return CompatibilityResult::Incompatible(ContractBasisRefusal::IncompatibleCostRegistry {
            expected: expected.cost_registry_digest,
            actual: candidate.cost_registry_digest,
        });
    }

    // 9. Producer release ID must be valid (non-empty)
    if candidate.producer_release_id.trim().is_empty() {
        return CompatibilityResult::Incompatible(ContractBasisRefusal::InvalidProducerRelease {
            reason: "producer release ID cannot be empty".to_owned(),
        });
    }

    // 10. Check nightly compatibility if specified on both
    match (&expected.accepted_nightly, &candidate.accepted_nightly) {
        (Some(expected_nightly), Some(candidate_nightly))
            if expected_nightly != candidate_nightly =>
        {
            return CompatibilityResult::Incompatible(ContractBasisRefusal::IncompatibleNightly {
                required: expected_nightly.clone(),
                actual: Some(candidate_nightly.clone()),
            });
        }
        _ => {}
    }

    // Check if identical or compatible with notes
    if candidate == expected {
        CompatibilityResult::Identical
    } else {
        let mut notes = Vec::new();
        if candidate.producer_release_id != expected.producer_release_id {
            notes.push(format!(
                "producer release divergence: server={}, client={}",
                expected.producer_release_id, candidate.producer_release_id
            ));
        }
        if candidate.accepted_nightly != expected.accepted_nightly {
            notes.push(format!(
                "accepted nightly divergence: server={:?}, client={:?}",
                expected.accepted_nightly, candidate.accepted_nightly
            ));
        }
        CompatibilityResult::CompatibleWithNotes { notes }
    }
}

/// Negotiates a shared `ContractBasis` between server and client during `session.open`.
///
/// Returns the agreed basis if compatible, or fails closed with `ContractBasisError`
/// containing the refusal details and discovery/upgrade guidance.
pub fn negotiate_basis(
    server_basis: &ContractBasis,
    client_basis: &ContractBasis,
) -> Result<ContractBasis, ContractBasisError> {
    match check_compatibility(server_basis, client_basis) {
        CompatibilityResult::Identical => Ok(server_basis.clone()),
        CompatibilityResult::CompatibleWithNotes { .. } => {
            // Under compatible registries, server basis governs interpretation
            Ok(server_basis.clone())
        }
        CompatibilityResult::Incompatible(refusal) => {
            Err(ContractBasisError::IncompatibleBasis { refusal })
        }
    }
}

/// Resolves an operation name against a negotiated basis (AOP-001..AOP-014).
///
/// This is the decision-bearing `session.open` boundary: an operation is addressable
/// only under a basis whose semantic protocol is exactly `fss/1`, and only by its
/// registered canonical name. Unknown names fail closed with
/// `ContractBasisRefusal::UnregisteredOperation` (`ERR-AGENT-PROTOCOL-001`) and
/// deterministic remediation guidance; stable IDs (`AOP-001`) are never accepted as
/// names at this boundary.
///
/// Failures are typed; no unregistered surface is ever silently mapped.
pub fn registered_operation(
    basis: &ContractBasis,
    operation_name: &str,
) -> Result<AgentOperation, ContractBasisError> {
    if basis.semantic_protocol != CANONICAL_SEMANTIC_PROTOCOL {
        return Err(ContractBasisError::IncompatibleBasis {
            refusal: ContractBasisRefusal::IncompatibleProtocol {
                expected: CANONICAL_SEMANTIC_PROTOCOL.to_owned(),
                actual: basis.semantic_protocol.clone(),
            },
        });
    }
    let operation = AgentOperation::from_name(operation_name).map_err(|_| {
        ContractBasisError::IncompatibleBasis {
            refusal: ContractBasisRefusal::UnregisteredOperation {
                name: operation_name.to_owned(),
            },
        }
    })?;
    operation
        .validate_row()
        .map_err(ContractBasisError::Contract)?;
    Ok(operation)
}

/// Checks that a basis does not reference known tombstoned or superseded registry digests.
///
/// Fails closed with `ContractBasisError::StaleBasis` (`ERR-AGENT-SESSION-STALE-001`).
pub fn check_basis_freshness(
    basis: &ContractBasis,
    current_basis: &ContractBasis,
    tombstoned_digests: &[ContentDigest],
) -> Result<(), ContractBasisError> {
    for tombstone in tombstoned_digests {
        if basis.operation_registry_digest == *tombstone {
            return Err(ContractBasisError::StaleBasis {
                reason: StaleBasisReason::TombstonedRegistryDigest {
                    registry: "operation",
                    tombstoned_digest: *tombstone,
                },
            });
        }
        if basis.schema_catalog_digest == *tombstone {
            return Err(ContractBasisError::StaleBasis {
                reason: StaleBasisReason::TombstonedRegistryDigest {
                    registry: "schema_catalog",
                    tombstoned_digest: *tombstone,
                },
            });
        }
        if basis.capability_registry_digest == *tombstone {
            return Err(ContractBasisError::StaleBasis {
                reason: StaleBasisReason::TombstonedRegistryDigest {
                    registry: "capability",
                    tombstoned_digest: *tombstone,
                },
            });
        }
        if basis.view_registry_digest == *tombstone {
            return Err(ContractBasisError::StaleBasis {
                reason: StaleBasisReason::TombstonedRegistryDigest {
                    registry: "view",
                    tombstoned_digest: *tombstone,
                },
            });
        }
        if basis.error_registry_digest == *tombstone {
            return Err(ContractBasisError::StaleBasis {
                reason: StaleBasisReason::TombstonedRegistryDigest {
                    registry: "error",
                    tombstoned_digest: *tombstone,
                },
            });
        }
        if basis.cost_registry_digest == *tombstone {
            return Err(ContractBasisError::StaleBasis {
                reason: StaleBasisReason::TombstonedRegistryDigest {
                    registry: "cost",
                    tombstoned_digest: *tombstone,
                },
            });
        }
    }

    if basis.ontology_generation_id != current_basis.ontology_generation_id {
        return Err(ContractBasisError::StaleBasis {
            reason: StaleBasisReason::SupersededGeneration {
                registry: "ontology",
                current_generation: current_basis.ontology_generation_id.clone(),
                basis_generation: basis.ontology_generation_id.clone(),
            },
        });
    }

    Ok(())
}

/// Refuses a stale basis anchor that is not strictly older than the active anchor,
/// or that originates from a divergent site lineage.
///
/// Fails closed with `ContractBasisError::StaleBasis` (`ERR-AGENT-SESSION-STALE-001`).
pub fn refuse_stale_anchor(
    valid_at: &LedgerAnchor,
    current: &LedgerAnchor,
) -> Result<(), ContractBasisError> {
    if valid_at.site_lineage != current.site_lineage {
        return Err(ContractBasisError::StaleBasis {
            reason: StaleBasisReason::StaleAnchor {
                detail: format!(
                    "site lineage divergence: valid_at lineage '{}' != current '{}'",
                    valid_at.site_lineage, current.site_lineage
                ),
            },
        });
    }
    if (valid_at.ledger_epoch, valid_at.commit_sequence)
        >= (current.ledger_epoch, current.commit_sequence)
    {
        return Err(ContractBasisError::StaleBasis {
            reason: StaleBasisReason::StaleAnchor {
                detail: format!(
                    "valid_at anchor ({}, {}) is not strictly older than current ({}, {})",
                    valid_at.ledger_epoch,
                    valid_at.commit_sequence,
                    current.ledger_epoch,
                    current.commit_sequence
                ),
            },
        });
    }
    Ok(())
}
