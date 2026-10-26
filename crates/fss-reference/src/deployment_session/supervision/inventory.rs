#![forbid(unsafe_code)]
//! Discover session-owned supervision without a remembered subscription name or source access.

use fss_core::{AgentSession, SessionId};

use crate::agent_session::checkpoint::journal::supervision::SupervisionInventoryEntry;
use super::{
    ContentDigest, DeploymentHistory, DigestAlgorithm, OrientLimits, Path, PrincipalId,
    SessionJournal, SupervisionAdapterError, SupervisionSessionError, SupervisionSessionHead,
    observe_head, same_generations, valid_history_limits,
};

/// Explicit current authority and existing session whose bounded work inventory is requested.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionInventoryRequest {
    /// Existing owning session; listing never opens or renews one.
    pub session_id: SessionId,
    /// Complete current deployment root supplied by the caller.
    pub expected_authority_root: ContentDigest,
}

/// Complete request scope at each admitted metadata boundary.
pub struct SupervisionInventoryBinding<'a> {
    root: &'a Path,
    principal: &'a PrincipalId,
    request: &'a SupervisionInventoryRequest,
    limits: &'a OrientLimits,
}

impl<'a> SupervisionInventoryBinding<'a> {
    /// Existing deployment namespace.
    pub const fn root(&self) -> &'a Path { self.root }
    /// Authenticated session owner.
    pub const fn principal(&self) -> &'a PrincipalId { self.principal }
    /// Existing session and explicitly admitted current root.
    pub const fn request(&self) -> &'a SupervisionInventoryRequest { self.request }
    /// Bounded history admission; independent of native source-work budgets.
    pub const fn limits(&self) -> &'a OrientLimits { self.limits }
}

/// Every metadata operation requires explicit context admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisionInventoryBoundary {
    /// Before reading bounded deployment history.
    ReadHistory,
    /// Before exclusive journal ownership and root-pin recovery.
    OpenJournal,
    /// Before live owner admission and complete metadata lookup.
    ReadInventory,
    /// Before verifying the exact deployment history has not changed.
    RevalidateHistory,
    /// Before returning the complete inventory after durable session pinning.
    Deliver,
}

/// Caller-owned cancellation and authority; no permissive implementation is supplied.
pub trait SupervisionInventoryControl {
    /// Admit this exact binding and operation boundary.
    fn admit_inventory(
        &mut self,
        binding: &SupervisionInventoryBinding<'_>,
        boundary: SupervisionInventoryBoundary,
    ) -> Result<(), SupervisionAdapterError>;
}

/// Complete, session-scoped metadata. It grants no historical payload or native source access.
#[derive(Clone, Debug, PartialEq)]
pub struct SupervisionInventoryDelivery {
    /// Live admitted owner session.
    pub session: AgentSession,
    /// Current authority, distinct from each historical pending report's basis.
    pub head: SupervisionSessionHead,
    /// Exact journal root from which the metadata was recovered.
    pub journal_root: ContentDigest,
    /// Every subscription for this session, sorted by label with no silent truncation.
    pub subscriptions: Vec<SupervisionInventoryEntry>,
}

fn admit(
    control: &mut impl SupervisionInventoryControl,
    binding: &SupervisionInventoryBinding<'_>,
    boundary: SupervisionInventoryBoundary,
) -> Result<(), SupervisionSessionError> {
    control.admit_inventory(binding, boundary).map_err(SupervisionSessionError::Denied)
}

/// Discover durable work after context loss without knowing a label or retaining a plan file.
///
/// Complete journal replay, live session grants and privacy scope admit the metadata. Exact
/// deployment history brackets the read. No source attempt is reserved, no report is released,
/// and no subscription is created, acknowledged or advanced. Session clock/expiry observations
/// and journal root-pin recovery can remain durable even if the command subsequently refuses.
pub fn list_supervision(
    root: &Path,
    principal: &PrincipalId,
    request: &SupervisionInventoryRequest,
    limits: &OrientLimits,
    control: &mut impl SupervisionInventoryControl,
) -> Result<SupervisionInventoryDelivery, SupervisionSessionError> {
    if root.as_os_str().is_empty()
        || request.expected_authority_root.algorithm() != DigestAlgorithm::Sha256
        || request.expected_authority_root.bytes() == [0; 32]
        || !valid_history_limits(limits)
    {
        return Err(SupervisionSessionError::InvalidRequest);
    }
    let binding = SupervisionInventoryBinding { root, principal, request, limits };
    admit(control, &binding, SupervisionInventoryBoundary::ReadHistory)?;
    let history = DeploymentHistory::read(root, limits)
        .map_err(|error| SupervisionSessionError::Session(error.into()))?;
    let head = observe_head(&history)?;
    if head.anchor.state_root != request.expected_authority_root {
        return Err(SupervisionSessionError::ChangedAuthority);
    }
    admit(control, &binding, SupervisionInventoryBoundary::OpenJournal)?;
    let mut journal = SessionJournal::open(root).map_err(SupervisionSessionError::Session)?;
    let recovered = (|| {
        admit(control, &binding, SupervisionInventoryBoundary::ReadInventory)?;
        let session = journal.store.session(principal, &request.session_id, head.observed_at)
            .map_err(|error| SupervisionSessionError::Session(error.into()))?;
        if !same_generations(&session.current_anchor, &head.anchor) {
            return Err(SupervisionSessionError::StaleAuthority);
        }
        let subscriptions = journal.store.supervision_inventory(&session, head.observed_at)
            .map_err(SupervisionSessionError::Store)?;
        admit(control, &binding, SupervisionInventoryBoundary::RevalidateHistory)?;
        let current = DeploymentHistory::read(root, limits)
            .map_err(|error| SupervisionSessionError::Session(error.into()))?;
        if observe_head(&current)? != head {
            return Err(SupervisionSessionError::ChangedAuthority);
        }
        Ok((session, subscriptions))
    })();
    journal.commit_pin().map_err(SupervisionSessionError::Session)?;
    let (session, subscriptions) = recovered?;
    admit(control, &binding, SupervisionInventoryBoundary::Deliver)?;
    // The delivery admission can observe cancellation or allow the caller's authority to
    // advance. Check the complete bounded history once more after that callback so an older
    // inventory cannot escape with a falsely current head after this last admission boundary.
    admit(control, &binding, SupervisionInventoryBoundary::RevalidateHistory)?;
    let current = DeploymentHistory::read(root, limits)
        .map_err(|error| SupervisionSessionError::Session(error.into()))?;
    if observe_head(&current)? != head {
        return Err(SupervisionSessionError::ChangedAuthority);
    }
    Ok(SupervisionInventoryDelivery {
        session, head, journal_root: journal.store.committed_root(), subscriptions,
    })
}
