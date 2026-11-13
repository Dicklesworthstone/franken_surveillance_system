#![forbid(unsafe_code)]
//! Explicit presentation basis for metadata delivery with durable session accounting.
//!
//! Native descriptors, requests, cursor scopes and existing session checkpoints keep their
//! original reference basis. This outer response profile neither grants authority nor rebases
//! them. Its separate operation pin names the exact charging/retry row, not only a payload list.

use super::{ContractBasis, parse_reference_digest, reference_contract_basis};

/// Explicit hydration presentation generation; never a replacement for durable reference-v4.
pub const HYDRATION_CONTRACT_BASIS_GENERATION: &str = "gen:fss1:event-hydration-v2";
/// Registered operation profile for the query/evidence-hydration target alone.
pub const HYDRATION_OPERATION_REGISTRY_GENERATION: &str = "gen:fss1:hydration-operations-v1";
/// Native composite carrying existing H0/H1 payloads and protected cognitive context.
pub const HYDRATION_RESPONSE_SCHEMA: &str = "fss.agent_evidence_hydration.v1";
/// Frozen row extends the reference operation universe only through explicit profile selection.
pub const HYDRATION_QUERY_CANONICAL_ROW: &str = "AOP-005|query|cognition_write|fss-query-plan|AVIEW-003|fss.agent_query_plan.v1|fss.agent_cognitive_envelope.v1;fss.agent_evidence_hydration.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|CAP-AGENT-QUERY-001;CAP-AGENT-EVIDENCE-HYDRATE-001|never_unchanged;refresh_and_retry;rebase_required;backoff;reconciliation_required;operator_action_required;resume_from_continuation";
/// CanonicalEncoder text profile domain, frozen reference operation digest and exact row text.
pub const HYDRATION_OPERATION_REGISTRY_DIGEST: &str =
    "sha256:1fa8bd342678b607db8c0d4d1c72a501d36c1ebac087e15098713a38b19a2202";
/// Exact closed wrapper schema bytes; native nested schemas retain their existing identities.
pub const HYDRATION_RESPONSE_SCHEMA_DIGEST: &str =
    "sha256:978059a46a34cee7783f99015fc1f889229b8401a849a6cf8ab754f678219b3a";
/// CanonicalEncoder text catalog domain, frozen reference schema digest, wrapper name and digest.
pub const HYDRATION_SCHEMA_CATALOG_DIGEST: &str =
    "sha256:f604dcbb58aaab5ec27d3ba4bbdeb7601639ff2eb71fdb29de4f5aebf426396d";
/// Semantic identity of this explicit presentation basis.
pub const HYDRATION_CONTRACT_BASIS_CANONICAL_DIGEST: &str =
    "sha256:d7baa77c92610dcc4c659a7d46c6cf1cb14842568c17a94d4b42b9c0bb70d91f";
/// Exact binary fixture identity, independently pinned alongside the legacy/probe fixtures.
pub const HYDRATION_CONTRACT_BASIS_FREEZE_DIGEST: &str =
    "sha256:cb0a45ff5c5da3ea438d2a56e96ca45fad3ae837094fec64f5b4a1eae659e785";

/// Published v1 schema bytes, retained unchanged before admitting a fresh session's generation 0.
pub const HISTORICAL_HYDRATION_RESPONSE_SCHEMA_DIGEST_V1: &str =
    "sha256:fb02b9740e8386527973bf3038e509e7b8b94edcd928c526bc0717cc6f5f6f29";
/// Published v1 schema catalog pin; never rewritten to describe the corrected live profile.
pub const HISTORICAL_HYDRATION_SCHEMA_CATALOG_DIGEST_V1: &str =
    "sha256:1ab2e294b55a77c37e039c5abf0aafe20f8da844ed119aa032dbe63bb91aac0e";
/// Historical v1 semantic basis identity.
pub const HISTORICAL_HYDRATION_CONTRACT_BASIS_CANONICAL_DIGEST_V1: &str =
    "sha256:46ddaba230a55412994d9e8229fd65db9a78b4edd07b93214c01d41581051979";
/// Historical v1 binary fixture identity.
pub const HISTORICAL_HYDRATION_CONTRACT_BASIS_FREEZE_DIGEST_V1: &str =
    "sha256:ad5daaea78fb4e0600bbd9c17aa25a9806d2e9827937625612617541847832e6";

/// Select the exact outer metadata-hydration response profile without upgrading stored state.
#[must_use]
pub fn hydration_contract_basis() -> ContractBasis {
    let mut basis = reference_contract_basis();
    basis.schema_catalog_digest = parse_reference_digest(HYDRATION_SCHEMA_CATALOG_DIGEST);
    basis.operation_registry_digest = parse_reference_digest(HYDRATION_OPERATION_REGISTRY_DIGEST);
    basis
}

/// Refuse partial combinations or arbitrary capability/ontology/producer changes.
#[must_use]
pub fn is_hydration_contract_basis(basis: &ContractBasis) -> bool {
    basis == &hydration_contract_basis()
}
