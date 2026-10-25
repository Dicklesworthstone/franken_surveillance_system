#![forbid(unsafe_code)]
//! Recover an existing immutable supervision recipe through its owning session and journal.

use fss_core::SessionId;

use super::{
    ContentDigest, DigestAlgorithm, OrientLimits, Path, PrincipalId, SessionJournal,
    SupervisionAdapterError, SupervisionRegistration, SupervisionSessionError,
    DeploymentHistory, observe_head, same_generations, valid_history_limits,
};

/// Existing subscription selected under an explicitly supplied current deployment authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionRecoveryRequest {
    /// Existing owning session; recovery never opens or renews a session.
    pub session_id: SessionId,
    /// Exact existing session-local subscription label.
    pub subscription_id: String,
    /// Current root explicitly admitted for this recovery, never silently inferred.
    pub expected_authority_root: ContentDigest,
}

/// Complete recovery scope at each metadata and journal boundary; no report or source access.
pub struct SupervisionRecoveryBinding<'a> {
    root: &'a Path,
    principal: &'a PrincipalId,
    request: &'a SupervisionRecoveryRequest,
    limits: &'a OrientLimits,
}

impl<'a> SupervisionRecoveryBinding<'a> {
    /// Existing deployment namespace.
    pub const fn root(&self) -> &'a Path { self.root }
    /// Authenticated session owner.
    pub const fn principal(&self) -> &'a PrincipalId { self.principal }
    /// Exact requested subscription and current authority.
    pub const fn request(&self) -> &'a SupervisionRecoveryRequest { self.request }
    /// Explicit bounded metadata-history admission, independent of the stored native recipe.
    pub const fn limits(&self) -> &'a OrientLimits { self.limits }
}

/// Every recovery operation is admitted explicitly by its caller's context owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisionRecoveryBoundary {
    /// Before the initial bounded deployment-history observation.
    ReadHistory,
    /// Before the existing exclusive journal owner and its root-pin recovery.
    OpenJournal,
    /// Before live-session admission and exact immutable registration lookup.
    ReadRegistration,
    /// Before checking the current authority and both histories again.
    RevalidateHistory,
    /// Before returning configuration bytes after journal changes are pinned.
    Deliver,
}

/// Explicit authority/cancellation admission; there is no permissive implementation.
pub trait SupervisionRecoveryControl {
    /// Admit exactly this recovery binding and operation boundary.
    fn admit_recovery(
        &mut self,
        binding: &SupervisionRecoveryBinding<'_>,
        boundary: SupervisionRecoveryBoundary,
    ) -> Result<(), SupervisionAdapterError>;
}

fn admit(
    control: &mut impl SupervisionRecoveryControl,
    binding: &SupervisionRecoveryBinding<'_>,
    boundary: SupervisionRecoveryBoundary,
) -> Result<(), SupervisionSessionError> {
    control.admit_recovery(binding, boundary).map_err(SupervisionSessionError::Denied)
}

/// Recover exact stored configuration and immutable limits without an external recipe file.
///
/// The existing journal lock, complete semantic replay, live owner grants and authority digest
/// admit the lookup. Current deployment history brackets it. No subscription is registered, no
/// native read is reserved and no pending report bytes are exposed. Opening the journal and
/// observing the session may retain clock/expiry or root-pin recovery changes even on refusal.
/// The caller must parse the returned exact bytes and use `supervise_existing_session` for its
/// subsequent operation; this return value grants no source access or effect authority.
pub fn recover_supervision_registration(
    root: &Path,
    principal: &PrincipalId,
    request: &SupervisionRecoveryRequest,
    limits: &OrientLimits,
    control: &mut impl SupervisionRecoveryControl,
) -> Result<SupervisionRegistration, SupervisionSessionError> {
    if root.as_os_str().is_empty()
        || fss_core::validate_id(&request.subscription_id).is_err()
        || request.expected_authority_root.algorithm() != DigestAlgorithm::Sha256
        || request.expected_authority_root.bytes() == [0; 32]
        || !valid_history_limits(limits)
    {
        return Err(SupervisionSessionError::InvalidRequest);
    }
    let binding = SupervisionRecoveryBinding { root, principal, request, limits };
    admit(control, &binding, SupervisionRecoveryBoundary::ReadHistory)?;
    let history = DeploymentHistory::read(root, limits)
        .map_err(|error| SupervisionSessionError::Session(error.into()))?;
    let head = observe_head(&history)?;
    if head.anchor.state_root != request.expected_authority_root {
        return Err(SupervisionSessionError::ChangedAuthority);
    }
    admit(control, &binding, SupervisionRecoveryBoundary::OpenJournal)?;
    let mut journal = SessionJournal::open(root).map_err(SupervisionSessionError::Session)?;
    let recovered = (|| {
        admit(control, &binding, SupervisionRecoveryBoundary::ReadRegistration)?;
        let session = journal.store.session(principal, &request.session_id, head.observed_at)
            .map_err(|error| SupervisionSessionError::Session(error.into()))?;
        if !same_generations(&session.current_anchor, &head.anchor) {
            return Err(SupervisionSessionError::StaleAuthority);
        }
        let registration = journal.store.recover_supervision_registration(
            principal, &request.session_id, &request.subscription_id, head.observed_at,
        ).map_err(SupervisionSessionError::Store)?;
        admit(control, &binding, SupervisionRecoveryBoundary::RevalidateHistory)?;
        let current = DeploymentHistory::read(root, limits)
            .map_err(|error| SupervisionSessionError::Session(error.into()))?;
        if observe_head(&current)? != head {
            return Err(SupervisionSessionError::ChangedAuthority);
        }
        Ok(registration)
    })();
    // Error-side session clock/expiry transitions are durable, too. Pin them before replying.
    journal.commit_pin().map_err(SupervisionSessionError::Session)?;
    let registration = recovered?;
    admit(control, &binding, SupervisionRecoveryBoundary::Deliver)?;
    Ok(registration)
}
