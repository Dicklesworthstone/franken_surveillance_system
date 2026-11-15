#![forbid(unsafe_code)]
//! Explicit runtime time for session admission, separate from the evidence being projected.
//!
//! Plain paths select the deterministic evidence clock. A live owner passes a
//! [`SessionContext`] to every session operation and supplies its clock through
//! [`SessionTimeAuthority`]. Requests never carry authoritative current time. Both paths use
//! the existing durable session watermark, expiry tombstone and cumulative budgets.

use std::fmt;
use std::path::Path;

use fss_core::{PrincipalId, TimestampNs};

use super::{DeploymentSessionError, DeploymentSnapshot, evidence_now};

/// A runtime could not admit a current clock observation. No payload is disclosed on refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTimeError {
    /// The runtime does not authorize this deployment/principal scope.
    Denied,
    /// The owning operation was cancelled.
    Cancelled,
    /// No trustworthy nonnegative time in the session's clock domain is available.
    Uncertain,
}

impl fmt::Display for SessionTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Denied => "runtime session clock scope was denied",
            Self::Cancelled => "runtime session clock owner was cancelled",
            Self::Uncertain => "runtime session clock is unavailable or uncertain",
        })
    }
}

impl std::error::Error for SessionTimeError {}

/// Clock capability supplied by the trusted runtime, never decoded from an agent request.
///
/// The owner admits its immutable deployment/principal scope, cancellation and deadlines
/// before sampling. Observations must share one clock domain across commands and restarts.
/// The session journal independently rejects regression and permanently closes expired
/// sessions; a fresh clock owner cannot reset either that watermark or the token budget.
pub trait SessionTimeAuthority {
    /// Observe current time for this already selected operation scope.
    fn observe(
        &self,
        root: &Path,
        principal: &PrincipalId,
    ) -> Result<TimestampNs, SessionTimeError>;
}

/// A deployment root together with the explicit clock authority of one runtime operation.
///
/// This deliberately does not implement `AsRef<Path>`: passing the context to another owner
/// preserves its clock instead of silently selecting the deterministic path implementation.
#[derive(Clone, Copy)]
pub struct SessionContext<'a> {
    root: &'a Path,
    authority: Option<&'a dyn SessionTimeAuthority>,
    persist_read_watermark: bool,
}

impl<'a> SessionContext<'a> {
    /// Deterministic reference/replay admission using committed evidence time.
    pub const fn evidence(root: &'a Path) -> Self {
        Self {
            root,
            authority: None,
            persist_read_watermark: true,
        }
    }

    /// Live admission using an explicitly owned clock capability.
    pub const fn runtime(root: &'a Path, authority: &'a dyn SessionTimeAuthority) -> Self {
        Self {
            root,
            authority: Some(authority),
            persist_read_watermark: true,
        }
    }

    /// The deployment whose session state this context owns.
    pub const fn root(self) -> &'a Path {
        self.root
    }

    pub(super) const fn is_runtime(self) -> bool {
        self.authority.is_some()
    }

    /// Private compositions preserve a sealed native root until their final durable charge.
    /// They still check fresh time on a verified fork and persist refused admission/expiry.
    /// This mode is never selected by a request and must not release an uncharged projection.
    pub(super) const fn pinned_read(mut self) -> Self {
        self.persist_read_watermark = false;
        self
    }

    pub(super) const fn persist_read_watermark(self) -> bool {
        self.persist_read_watermark
    }

    pub(super) fn now(
        self,
        snapshot: &DeploymentSnapshot,
        principal: &PrincipalId,
    ) -> Result<TimestampNs, DeploymentSessionError> {
        self.now_at(evidence_now(snapshot), principal)
    }

    pub(super) fn now_at(
        self,
        evidence_time: TimestampNs,
        principal: &PrincipalId,
    ) -> Result<TimestampNs, DeploymentSessionError> {
        match self.authority {
            None => Ok(evidence_time),
            Some(authority) => {
                let now = authority.observe(self.root, principal)?;
                if now.0 < 0 {
                    return Err(SessionTimeError::Uncertain.into());
                }
                Ok(now)
            }
        }
    }
}

/// Session owner input: a deterministic path or an explicitly timed runtime context.
pub trait SessionRoot {
    /// Retain the root and clock together while delegating to another owner.
    fn session_context(&self) -> SessionContext<'_>;
}

impl<T: AsRef<Path> + ?Sized> SessionRoot for T {
    fn session_context(&self) -> SessionContext<'_> {
        SessionContext::evidence(self.as_ref())
    }
}

impl SessionRoot for SessionContext<'_> {
    fn session_context(&self) -> SessionContext<'_> {
        *self
    }
}

impl SessionRoot for &SessionContext<'_> {
    fn session_context(&self) -> SessionContext<'_> {
        **self
    }
}

impl From<SessionTimeError> for DeploymentSessionError {
    fn from(value: SessionTimeError) -> Self {
        Self::Time(value)
    }
}
