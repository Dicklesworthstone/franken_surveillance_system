#![forbid(unsafe_code)]
//! AOP-010 owner-approved revocation of one retained session. The existing session lock drains
//! cooperating work before a tombstone is committed. Claims become explicitly reclaimable;
//! plans, follow progress, pending deliveries and external obligations remain in custody.

use fss_core::ContextAuthority;

use super::*;
pub use crate::agent_session::checkpoint::journal::cancellation::{
    SessionCancellationPlan, SessionCancellationReceipt,
};
use crate::agent_session::checkpoint::journal::{
    cancellation::retained_receipt, inspect_session_bytes,
};

/// Existing AOP-010 capability, supplied by the current local owner, never by session history.
pub const CAP_SESSION_CANCEL: &str = "CAP-AGENT-CANCEL-001";

/// Typed refusal before revocation, or an uncertain append requiring exact cold recovery.
#[derive(Debug)]
pub enum SessionCancellationError {
    /// Missing, cancelled, expired or foreign fresh authority.
    Unauthorized,
    /// The entire preview has changed; no partial or automatically refreshed approval is used.
    ApprovalMismatch,
    /// Session admission, retained custody or bounded read failed before the cancellation append.
    Session(DeploymentSessionError),
    /// The append may have committed. Reopen and retry the same exact approved request.
    CommitUncertain,
}
impl fmt::Display for SessionCancellationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unauthorized => "current session cancellation authority denied",
            Self::ApprovalMismatch => {
                "session cancellation approval no longer matches the exact request"
            }
            Self::Session(_) => "session cancellation custody or admission refused",
            Self::CommitUncertain => "session cancellation commit requires exact recovery",
        })
    }
}
impl std::error::Error for SessionCancellationError {}
impl From<DeploymentSessionError> for SessionCancellationError {
    fn from(value: DeploymentSessionError) -> Self {
        Self::Session(value)
    }
}
impl From<DurableSessionError> for SessionCancellationError {
    fn from(value: DurableSessionError) -> Self {
        Self::Session(value.into())
    }
}

/// What this invocation established about session authority, never an external effect status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionCancellationOutcome {
    /// The complete request is read-only; no clock, pin, lease or journal was changed.
    Proposed,
    /// This invocation appended the request and revocation tombstone atomically.
    Cancelled,
    /// The exact original request and tombstone were already committed.
    AlreadyCancelled,
}

/// Native result. Historical inventories remain anchored to the original approval on retry.
#[derive(Clone, Debug, PartialEq)]
pub struct SessionCancellation {
    /// Retained identity; its past grants never authorize this command.
    pub session: AgentSession,
    /// Exact retained workspace, preserved by revocation.
    pub workspace: WorkspaceRevision,
    /// Complete immutable approval scope.
    pub plan: SessionCancellationPlan,
    /// What this call established.
    pub outcome: SessionCancellationOutcome,
    /// The original durable cancellation receipt, absent only for a live preview.
    pub receipt: Option<SessionCancellationReceipt>,
    /// A committed cancellation survives pin replacement failure. Exact approved retry repairs
    /// only the verified journal extension and never appends another tombstone.
    pub pin_repair_pending: bool,
}

fn authorize(authority: &ContextAuthority) -> Result<PrincipalId, SessionCancellationError> {
    if authority.validate().is_err()
        || !authority.has_capability(CAP_SESSION_CANCEL)
        || authority.cancellation_reason.is_some()
        // There is no independent deadline sampler at this synchronous local boundary.
        || authority.deadline.is_some()
    {
        return Err(SessionCancellationError::Unauthorized);
    }
    PrincipalId::parse(&authority.principal).map_err(|_| SessionCancellationError::Unauthorized)
}

/// The native deployment owner holds this same lock for authority/effect writes. Open only an
/// existing ordinary file: taking the lock must not initialize a spool or trigger recovery.
fn lock_deployment(root: &Path) -> Result<SpoolLock, DeploymentSessionError> {
    let directory = root.join(crate::reference_deployment::RELATIVE_PATH_OBJECTS);
    admit_agent_directory(&directory, false)?;
    let path = directory.join(fss_object::SPOOL_LOCK_FILE);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| io_failure("session cancellation deployment lock", &error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(DeploymentSessionError::StoreInvalid(
            "deployment lock is not an ordinary file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(DeploymentSessionError::StoreInvalid(
                "deployment lock is hardlinked".into(),
            ));
        }
    }
    let file = File::open(path)
        .map_err(|error| io_failure("session cancellation deployment lock", &error))?;
    match SpoolLock::try_acquire(file, Arc::new(HostSpoolIo)) {
        Ok(lock) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(DeploymentSessionError::StoreLocked),
        Err(TryLockError::Error(error)) => {
            Err(io_failure("session cancellation deployment lock", &error))
        }
    }
}

/// Preview, commit with exact approval, or recover an already committed session revocation.
/// The exclusive session and existing deployment locks are held across admission and append.
/// Both acquisitions are nonblocking, so a competing owner is refused rather than labelled
/// drained. No network I/O, deployment recovery or new effect authority is performed here.
pub fn cancel_session(
    root: &Path,
    session_id: &SessionId,
    authority: &ContextAuthority,
    approval: Option<ContentDigest>,
) -> Result<SessionCancellation, SessionCancellationError> {
    let principal = authorize(authority)?;
    let root = ensure_agent_writable(root)?;
    let directory = root.join(SESSIONS_RELPATH);
    let lock_file = File::open(directory.join(SESSION_LOCK_FILE)).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            DeploymentSessionError::SessionUnknown
        } else {
            io_failure("session cancellation lock", &error)
        }
    })?;
    let lock = match SpoolLock::try_acquire(lock_file, Arc::new(HostSpoolIo)) {
        Ok(lock) => lock,
        Err(TryLockError::WouldBlock) => return Err(DeploymentSessionError::StoreLocked.into()),
        Err(TryLockError::Error(error)) => {
            return Err(io_failure("session cancellation lock", &error).into());
        }
    };
    // This guard remains alive through the final ROOT pin write. Native external effects cannot
    // change the approval's complete authority/effect prefix while session revocation commits.
    let _deployment_lock = lock_deployment(&root)?;
    ensure_agent_writable(&root)?;
    let pin_path = directory.join(SESSION_ROOT_PIN_FILE);
    let pin_bytes = read_bounded(&pin_path, MAX_PIN_BYTES)
        .map_err(|error| io_failure("session cancellation pin", &error))?
        .ok_or_else(|| DeploymentSessionError::StoreInvalid("session root pin missing".into()))?;
    let pin = std::str::from_utf8(&pin_bytes)
        .ok()
        .and_then(|text| ContentDigest::parse(text.trim_end()).ok())
        .ok_or_else(|| DeploymentSessionError::StoreInvalid("session root pin malformed".into()))?;
    let journal_path = directory.join(SESSION_JOURNAL_FILE);
    let bytes = read_bounded(&journal_path, MAX_SESSION_JOURNAL_BYTES)
        .map_err(|error| io_failure("session cancellation journal", &error))?
        .ok_or_else(|| DeploymentSessionError::StoreInvalid("session journal missing".into()))?;
    let limits = DurableSessionLimits::default();
    let recovered = inspect_session_bytes(&bytes, limits, WorkClaimLimits::default())?;
    let report = fss_ledger::recover_bytes(&bytes).map_err(DurableSessionError::from)?;
    if recovered.inspection.incomplete_tail.is_some()
        || (pin != report.last_root()
            && !report.records().iter().any(|record| record.root() == pin))
    {
        return Err(DurableSessionError::RootMismatch.into());
    }
    // Bind the actor before revealing any workspace, plan or prior cancellation metadata.
    let retained = recovered
        .sessions
        .iter()
        .find(|retained| {
            retained.session.session_id == *session_id && retained.session.principal_id == principal
        })
        .ok_or(DeploymentSessionError::SessionUnknown)?;
    if retained.basis != fss_core::reference_contract_basis() {
        return Err(
            DeploymentSessionError::SessionStale("session contract basis differs".into()).into(),
        );
    }
    let session = retained.session.clone();
    if authority.anchor_universe
        != ContentDigest::sha256(session.current_anchor.site_lineage.as_bytes())
    {
        return Err(SessionCancellationError::Unauthorized);
    }
    let history = DeploymentHistory::read(&root, &OrientLimits::default())
        .map_err(DeploymentSessionError::from)?;
    if history.site_lineage() != session.current_anchor.site_lineage {
        return Err(SessionCancellationError::Unauthorized);
    }
    let workspace = recovered
        .workspace_revisions
        .iter()
        .filter(|revision| revision.capsule().session_id == *session_id)
        .max_by_key(|revision| revision.capsule().revision)
        .cloned()
        .ok_or_else(|| DeploymentSessionError::StoreInvalid("session workspace missing".into()))?;
    let previous = retained_receipt(&report, &principal, session_id)?;
    let (plan, previous) = if let Some(receipt) = previous {
        if !retained.closed || receipt.plan.session_digest != session.session_digest() {
            return Err(DurableSessionError::InvalidHistory.into());
        }
        (receipt.plan.clone(), Some(receipt))
    } else {
        if retained.closed {
            return Err(DeploymentSessionError::SessionUnknown.into());
        }
        let head = history
            .snapshot_at(history.head())
            .map_err(DeploymentSessionError::from)?;
        let now = evidence_now(&head);
        if session.current_anchor.site_lineage != head.site_lineage
            || now.0 < retained.last_observed_at.0
            || now.0 >= session.expires_at_ns
        {
            return Err(DeploymentSessionError::SessionUnknown.into());
        }
        let (basis_anchor, authority_root, effect_root) =
            history.roots_at(history.head()).ok_or_else(|| {
                DeploymentSessionError::StoreInvalid("deployment prefix missing".into())
            })?;
        let briefs = plan::plan_briefs(&root, &head, &session.mission_id, &principal)?;
        let operations: BTreeSet<_> = briefs
            .iter()
            .map(|brief| brief.operation_id.as_str())
            .collect();
        let carried: BTreeSet<_> = workspace
            .capsule()
            .open_obligations
            .iter()
            .cloned()
            .collect();
        // A carried workspace entry is historical cognition, not proof that an obligation is
        // still pending. Keep missing entries explicitly unresolved; exclude those whose
        // terminal state is already proved by the complete current effect prefix.
        let mut unresolved: BTreeSet<_> = carried
            .iter()
            .filter(|id| {
                !head
                    .obligations
                    .iter()
                    .any(|obligation| obligation.obligation_id.as_str() == id.as_str())
            })
            .cloned()
            .collect();
        for obligation in head.open_obligations() {
            if operations.contains(obligation.operation_id.as_str())
                || carried.contains(obligation.obligation_id.as_str())
            {
                unresolved.insert(obligation.obligation_id.as_str().to_owned());
            }
        }
        let plan = SessionCancellationPlan {
            session_id: session_id.clone(),
            principal: principal.clone(),
            session_digest: session.session_digest(),
            checkpoint_digest: recovered.inspection.checkpoint_digest,
            journal_root: report.last_root(),
            basis_anchor,
            authority_root,
            effect_root,
            observed_at: now,
            unresolved_obligations: unresolved.into_iter().collect(),
            retained_plans: briefs.into_iter().map(|brief| brief.plan_id).collect(),
        };
        (plan, None)
    };
    let exact = plan.approval_digest()?;
    if approval.is_some_and(|approved| approved != exact) {
        return Err(SessionCancellationError::ApprovalMismatch);
    }
    authorize(authority)?;
    ensure_agent_writable(&root)?;
    if read_bounded(&journal_path, MAX_SESSION_JOURNAL_BYTES)
        .map_err(|error| io_failure("session cancellation verification", &error))?
        .as_deref()
        != Some(bytes.as_slice())
        || read_bounded(&pin_path, MAX_PIN_BYTES)
            .map_err(|error| io_failure("session cancellation pin verification", &error))?
            .as_deref()
            != Some(pin_bytes.as_slice())
    {
        return Err(DurableSessionError::RootMismatch.into());
    }
    if approval.is_none() {
        return Ok(SessionCancellation {
            session,
            workspace,
            plan,
            outcome: if previous.is_some() {
                SessionCancellationOutcome::AlreadyCancelled
            } else {
                SessionCancellationOutcome::Proposed
            },
            receipt: previous,
            pin_repair_pending: pin != report.last_root(),
        });
    }
    // Open an existing verified prefix only. No initialization, expiry or implicit pin repair.
    let store = DurableSessionStore::open_existing_with_coordination(
        &journal_path,
        report.last_root(),
        limits,
        WorkClaimLimits::default(),
    )?;
    let mut journal = SessionJournal {
        root,
        directory,
        store,
        _lock: lock,
    };
    let (receipt, outcome) = match previous {
        Some(receipt) => (receipt, SessionCancellationOutcome::AlreadyCancelled),
        None => (
            journal
                .store
                .cancel_session_authority(&plan)
                .map_err(|_| SessionCancellationError::CommitUncertain)?,
            SessionCancellationOutcome::Cancelled,
        ),
    };
    let pin_repair_pending = journal.pin(Some(pin)).is_err();
    Ok(SessionCancellation {
        session,
        workspace,
        plan,
        outcome,
        receipt: Some(receipt),
        pin_repair_pending,
    })
}
