#![forbid(unsafe_code)]
//! Read-only current orientation for an existing durable session (AOP-003).
//!
//! Captured session bytes are replayed without constructing a journal writer. Admission uses
//! isolated session memory: no clock, expiry tombstone, workspace, budget, ROOT pin, publication,
//! subscription or effect changes. The current situation is distinct from the retained workspace.

use super::*;
use crate::agent_orient::orient_deployment_for_workspace;
use crate::agent_session::checkpoint::journal::projection::SessionProjectionSnapshot;

/// One explicitly scoped read. View and budget affect this response, never the retained session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientSessionRequest {
    /// Exact retained session identity.
    pub session_id: SessionId,
    /// Caller whose existing session grants must admit the read.
    pub principal: PrincipalId,
    /// Registered response view; does not change the retained session view.
    pub view: AgentView,
    /// Optional response allowance within both the view and remaining session grant.
    pub budget_tokens: Option<u64>,
}

/// Current evidence and live agent metadata, with the unchanged retained workspace alongside it.
#[derive(Clone, Debug, PartialEq)]
pub struct OrientedSession {
    /// Unchanged admitted session authority and anchor.
    pub session: AgentSession,
    /// Unchanged current workspace revision.
    pub revision: WorkspaceRevision,
    /// Situation compiled at the current deployment head.
    pub orientation: DeploymentOrientation,
    /// Exact captured and replayed session journal root.
    pub journal_root: ContentDigest,
    /// Canonical identity binding request, captured workspace and full read position.
    pub request_digest: ContentDigest,
    /// Exact historical position retained by the workspace.
    pub workspace_anchor_token: String,
    /// Whether the current full position differs from the workspace's position.
    pub anchor_moved: bool,
    /// Retained assumptions/actions that require explicit revalidation, not claims of falsity.
    pub invalidated: Vec<String>,
}

/// Inspect an existing session at the current deployment head without performing a rebase.
/// The caller supplies its ordinary local operator scope; possession of a session ID grants none.
pub fn orient_session(
    root: &Path,
    request: &OrientSessionRequest,
) -> Result<OrientedSession, DeploymentSessionError> {
    if !matches!(
        request.view,
        AgentView::Pulse | AgentView::Brief | AgentView::EpistemicMap
    ) {
        return Err(OrientError::UnsupportedView(request.view).into());
    }
    let maximum = u64::from(request.view.maximum_tokens());
    if request
        .budget_tokens
        .is_some_and(|tokens| tokens == 0 || tokens > maximum)
    {
        return Err(OrientError::ContextBudgetExceeded {
            view: request.view,
            budget_tokens: request.budget_tokens.unwrap_or(0),
        }
        .into());
    }

    let (oriented, _, _) = with_admitted_session_read(
        root,
        &request.principal,
        &request.session_id,
        |read| {
            let root = read.root;
            let store = read.store;
            let session = read.session;
            let revision = read.revision;
            let head = read.head;
            let now = evidence_now(head);
            let workspace_anchor_token = read.workspace_anchor_token;
            let invalidated = read.invalidated;
            let remaining_tokens = read.remaining_tokens;
            let limits = OrientLimits::default();
            let mission = mission_for_workspace(root, session, revision)?;
            let briefs = session_briefs(root, store, session, head, now)?;
            let binding = OrientSessionBinding {
                mission_id: session.mission_id.clone(),
                session_id: session.session_id.clone(),
                mission: Some(mission.orientation_brief()),
                mission_progress: briefs.mission_progress,
                cases: briefs.cases,
                claims: briefs.claims,
                findings: briefs.findings,
                supervisions: briefs.supervisions,
                captured_learning: briefs.captured_learning.map(|inventory| inventory.briefs),
                trauma_warnings: if briefs.advisory_memory_allowed {
                    Some(trauma_guard::derive_trauma_guard_warnings(
                        root,
                        &request.principal,
                        now.0,
                    )?)
                } else {
                    None
                },
                plans: plan::plan_briefs(root, head, &session.mission_id, &session.principal_id)?,
            };
            let allowance = request.budget_tokens.unwrap_or(maximum);
            if remaining_tokens == 0 || request.budget_tokens.is_some_and(|n| n > remaining_tokens)
            {
                return Err(
                    DurableSessionError::Session(ReferenceSessionError::BudgetExceeded).into(),
                );
            }
            let oriented_request = OrientRequest {
                view: request.view,
                principal: request.principal.clone(),
                budget_tokens: Some(allowance.min(remaining_tokens)),
            };
            let mut orientation = orient_deployment_for_workspace(
                head,
                &oriented_request,
                &limits,
                &binding,
                invalidated,
            )?;
            let journal_root = store.root();
            let request_digest = digest_of("fss.reference_session_orient_request.v1", |encoder| {
                request.principal.encode_canonical(encoder);
                request.session_id.encode_canonical(encoder);
                encoder.text(request.view.id());
                encoder.u64(request.budget_tokens.unwrap_or(0));
                encoder.text(&orientation.anchor_token);
                encoder.digest(revision.digest());
                encoder.digest(journal_root);
            });
            orientation.request_digest = request_digest;
            orientation.degradation.push(
        "Current read-only session projection; retained workspace, assumptions, grants, clocks and budgets are unchanged. No rebase or historical semantic delta is claimed.".to_owned()
    );
            orientation.degradation.push(
        "Response budgets meter the deployment snapshot and compiled context. Session-journal replay, root-pin and publication-custody checks, and repeat verification reads are additional bounded work that is not fully metered or claimed to be free.".to_owned()
    );
            if read.pinned_root != journal_root {
                orientation.degradation.push(
            "The session journal extends its retained ROOT pin; this read verified the extension and did not repair the pin.".to_owned()
        );
            }

            Ok(OrientedSession {
                session: session.clone(),
                revision: revision.clone(),
                orientation,
                journal_root,
                request_digest,
                workspace_anchor_token: workspace_anchor_token.to_owned(),
                anchor_moved: read.anchor_moved,
                invalidated: invalidated.to_vec(),
            })
        },
    )?;
    Ok(oriented)
}

/// Common immutable admission for a current session read. The borrowed projection and selected
/// files may only be used while the caller owns the existing session lock.
pub(super) struct AdmittedSessionRead<'a> {
    pub root: &'a Path,
    pub store: &'a SessionProjectionSnapshot,
    pub head: &'a DeploymentSnapshot,
    pub session: &'a AgentSession,
    pub revision: &'a WorkspaceRevision,
    pub workspace_anchor_token: &'a str,
    pub anchor_moved: bool,
    pub invalidated: &'a [String],
    pub remaining_tokens: u64,
    pub pinned_root: ContentDigest,
}

/// Hold the existing lock across admission, a bounded read, and final prefix verification.
/// The two counters report the actual session-journal and root-pin bytes/files read here.
/// Deployment/fence reads and the caller's selected objects are accounted separately.
pub(super) fn with_admitted_session_read<T>(
    root: &Path,
    principal: &PrincipalId,
    session_id: &SessionId,
    read: impl FnOnce(&AdmittedSessionRead<'_>) -> Result<T, DeploymentSessionError>,
) -> Result<(T, u64, u64), DeploymentSessionError> {
    // These existing layout/restore-fence checks perform reads only. In particular a restored
    // historical checkpoint cannot regain live session authority through this read operation.
    let root = ensure_agent_writable(root)?;
    let directory = root.join(SESSIONS_RELPATH);
    let lock_file = match File::open(directory.join(SESSION_LOCK_FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(DeploymentSessionError::SessionUnknown);
        }
        Err(error) => return Err(io_failure("read-only session lock", &error)),
    };
    let _lock = match SpoolLock::try_acquire(lock_file, Arc::new(HostSpoolIo)) {
        Ok(lock) => lock,
        Err(TryLockError::WouldBlock) => return Err(DeploymentSessionError::StoreLocked),
        Err(TryLockError::Error(error)) => {
            return Err(io_failure("read-only session lock", &error));
        }
    };
    ensure_agent_writable(&root)?;
    let pin_path = directory.join(SESSION_ROOT_PIN_FILE);
    let pin_bytes = read_bounded(&pin_path, MAX_PIN_BYTES)
        .map_err(|error| io_failure("session root pin", &error))?
        .ok_or_else(|| {
            DeploymentSessionError::StoreInvalid(
                "the existing session root pin is missing; explicit recovery is required"
                    .to_owned(),
            )
        })?;
    let pin = std::str::from_utf8(&pin_bytes)
        .ok()
        .and_then(|text| ContentDigest::parse(text.trim_end()).ok())
        .ok_or_else(|| {
            DeploymentSessionError::StoreInvalid("the pinned session root is malformed".to_owned())
        })?;
    let journal_path = directory.join(SESSION_JOURNAL_FILE);
    let bytes = read_bounded(&journal_path, MAX_SESSION_JOURNAL_BYTES)
        .map_err(|error| io_failure("session journal", &error))?
        .ok_or_else(|| {
            DeploymentSessionError::StoreInvalid("the pinned session journal is missing".to_owned())
        })?;
    let store = SessionProjectionSnapshot::from_bytes(
        &bytes,
        pin,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(&root, &limits)?;
    let head = history.snapshot_at(history.head())?;
    let now = evidence_now(&head);
    let (session, revision, remaining_tokens) =
        store.session_workspace(principal, session_id, now)?;
    if !["CAP-AGENT-SESSION-READ-001", "CAP-AGENT-SITUATION-READ-001"]
        .iter()
        .all(|capability| session.capabilities.contains(*capability))
        || !session.privacy_scope.contains(SESSION_PRIVACY_SCOPE)
    {
        return Err(DurableSessionError::Session(ReferenceSessionError::GrantEscalation).into());
    }
    if !crate::agent_session::mission::same_generations(&session.current_anchor, &head.anchor) {
        return Err(DeploymentSessionError::SessionStale(
            "current interpretation generations differ from the retained session; explicit rebase is required".to_owned()
        ));
    }
    let workspace_anchor_token = capsule_anchor_token(revision.capsule())
        .ok_or_else(|| {
            DeploymentSessionError::StoreInvalid(
                "the workspace names no anchor-bound position".to_owned(),
            )
        })?
        .to_owned();
    let token = AnchorToken::parse(&workspace_anchor_token).ok_or_else(|| {
        DeploymentSessionError::StoreInvalid("the workspace anchor token is malformed".to_owned())
    })?;
    let position = resolve_anchor(&history, &token).map_err(|refusal| {
        DeploymentSessionError::SessionStale(format!(
            "the retained workspace does not resolve in this deployment ({})",
            refusal.code()
        ))
    })?;
    let basis = history.snapshot_at(position)?;
    if basis.anchor != session.current_anchor
        || revision.capsule().current_anchor != session.current_anchor
    {
        return Err(DeploymentSessionError::SessionStale(
            "the retained workspace and session anchors disagree".to_owned(),
        ));
    }
    let anchor_moved = position != head.position;
    let mut invalidated = Vec::new();
    if anchor_moved {
        invalidated.push(format!(
            "Workspace revision {} remains at {}; this current read does not rebase it.",
            revision.capsule().revision,
            workspace_anchor_token
        ));
        for assumption in &revision.capsule().assumptions {
            invalidated.push(format!(
                "Retained assumption {} requires revalidation at the current head.",
                split_assumption(assumption).0
            ));
        }
        for action in &revision.capsule().next_actions {
            invalidated.push(format!(
                "Retained next action {action} requires re-derivation at the current head."
            ));
        }
    }

    let result = read(&AdmittedSessionRead {
        root: &root,
        store: &store,
        head: &head,
        session: &session,
        revision: &revision,
        workspace_anchor_token: &workspace_anchor_token,
        anchor_moved,
        invalidated: &invalidated,
        remaining_tokens,
        pinned_root: pin,
    })?;

    // A cooperating writer is excluded by the existing lock. Out-of-contract drift observed
    // during metadata/custody reads must still withhold the answer rather than mix prefixes.
    ensure_agent_writable(&root)?;
    let verified_journal = read_bounded(&journal_path, MAX_SESSION_JOURNAL_BYTES)
        .map_err(|error| io_failure("session journal verification", &error))?;
    let verified_pin = read_bounded(&pin_path, MAX_PIN_BYTES)
        .map_err(|error| io_failure("session root pin verification", &error))?;
    if verified_journal.as_deref() != Some(bytes.as_slice())
        || verified_pin.as_deref() != Some(pin_bytes.as_slice())
    {
        return Err(DeploymentSessionError::StoreInvalid(
            "session history changed during read-only projection; retry from a stable prefix"
                .to_owned(),
        ));
    }
    let bytes_read = (bytes.len() as u64 + pin_bytes.len() as u64) * 2;
    Ok((result, bytes_read, 4))
}
