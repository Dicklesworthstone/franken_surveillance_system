#![forbid(unsafe_code)]
//! Explicit `Cx` secret-access authority checks binding capabilities, cancellation, and scope.

use core::fmt;

use fss_core::{ContextAuthority, RegionTree, RootAuthoritySpec, TimestampNs};
use fss_runtime::authority::AuthorityCx;

use crate::error::SecretError;
use crate::scope::SecretScope;
use crate::secret::SecretId;

/// Capability required to read secrets and list handles within the declared scope.
pub const CAP_SECRET_READ_001: &str = "CAP-SECRET-READ-001";

/// Capability required to store new secrets within the declared scope.
pub const CAP_SECRET_WRITE_001: &str = "CAP-SECRET-WRITE-001";

/// Capability required to rotate or revoke secrets within the declared scope.
pub const CAP_SECRET_ROTATE_001: &str = "CAP-SECRET-ROTATE-001";

/// Vault operation class checked against caller capabilities.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecretOperation {
    /// Fetch secret bytes within scope (`CAP-SECRET-READ-001`).
    Read,
    /// List non-secret handles within scope (`CAP-SECRET-READ-001`).
    List,
    /// Store a new secret within scope (`CAP-SECRET-WRITE-001`).
    Write,
    /// Rotate an existing secret to a new generation (`CAP-SECRET-ROTATE-001`).
    Rotate,
    /// Revoke and tombstone an existing secret (`CAP-SECRET-ROTATE-001` or `CAP-SECRET-WRITE-001`).
    Revoke,
}

/// Explicit `Cx` authority token required for every secret store access.
///
/// Binds a validated [`ContextAuthority`], caller-supplied [`SecretScope`],
/// explicit timestamp, and cancellation state. No ambient authority is ever read.
#[derive(Clone, PartialEq)]
pub struct SecretAccessCx {
    authority: ContextAuthority,
    scope: SecretScope,
    now: TimestampNs,
    cancelled_reason: Option<String>,
}

impl SecretAccessCx {
    /// Creates an explicit secret-access context from a validated [`ContextAuthority`].
    pub fn new(
        authority: ContextAuthority,
        scope: SecretScope,
        now: TimestampNs,
    ) -> Result<Self, SecretError> {
        authority
            .validate()
            .map_err(|err| SecretError::InvalidInput {
                detail: format!("invalid ContextAuthority: {err}"),
            })?;
        let cancelled_reason = authority.cancellation_reason.clone();
        Ok(Self {
            authority,
            scope,
            now,
            cancelled_reason,
        })
    }

    /// Creates a secret-access context bound to a live [`AuthorityCx`] and [`RegionTree`],
    /// propagating live region cancellation state immediately.
    pub fn from_runtime_region(
        authority_cx: &AuthorityCx,
        tree: &RegionTree,
        secret_capabilities: &[&str],
        scope: SecretScope,
        now: TimestampNs,
    ) -> Result<Self, SecretError> {
        let is_cancelled =
            authority_cx
                .is_cancel_requested(tree)
                .map_err(|err| SecretError::Unauthorized {
                    required_capability: CAP_SECRET_READ_001,
                    detail: format!("runtime authority binding failed: {err}"),
                })?;
        let node = tree
            .get(authority_cx.region())
            .map_err(|err| SecretError::Unauthorized {
                required_capability: CAP_SECRET_READ_001,
                detail: format!("region lookup failed: {err}"),
            })?;
        let mut caps = node.authority.capabilities().to_vec();
        for &cap in secret_capabilities {
            caps.push(cap.to_string());
        }
        let spec = RootAuthoritySpec {
            trace_id: node.authority.trace_id.clone(),
            operation_id: node.authority.operation_id.clone(),
            principal: node.authority.principal.clone(),
            capabilities: caps,
            deadline: node.authority.deadline,
            priority: node.authority.priority,
            budgets: node.authority.budgets,
            privacy_scope: node.authority.privacy_scope.clone(),
            retention_scope: node.authority.retention_scope.clone(),
            anchor_universe: node.authority.anchor_universe,
            generation: node.authority.generation,
        };
        let mut authority =
            ContextAuthority::new_root(spec).map_err(|err| SecretError::InvalidInput {
                detail: format!("cannot construct scoped ContextAuthority: {err}"),
            })?;
        if is_cancelled {
            authority.cancellation_reason = node
                .authority
                .cancellation_reason
                .clone()
                .or_else(|| Some("runtime region cancelled".to_string()));
        }
        Self::new(authority, scope, now)
    }

    /// Marks this access context as cancelled with an explicit non-secret reason.
    #[must_use]
    pub fn with_cancelled(mut self, reason: impl Into<String>) -> Self {
        self.cancelled_reason = Some(reason.into());
        self
    }

    /// Returns the underlying validated [`ContextAuthority`].
    #[must_use]
    pub const fn authority(&self) -> &ContextAuthority {
        &self.authority
    }

    /// Returns the caller's declared [`SecretScope`].
    #[must_use]
    pub const fn scope(&self) -> &SecretScope {
        &self.scope
    }

    /// Returns the caller-supplied explicit timestamp.
    #[must_use]
    pub const fn now(&self) -> TimestampNs {
        self.now
    }

    /// Returns `true` if this context is cancelled or past its deadline.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled_reason.is_some()
            || self.authority.cancellation_reason.is_some()
            || self.authority.deadline.is_some_and(|dl| self.now > dl)
    }

    /// Enforces cancellation, capability, and optional target-scope checks, failing closed.
    pub fn authorize(
        &self,
        operation: SecretOperation,
        target_secret_id: Option<&SecretId>,
        expected_scope: Option<&SecretScope>,
    ) -> Result<(), SecretError> {
        if let Some(reason) = &self.cancelled_reason {
            return Err(SecretError::Cancelled {
                reason: reason.clone(),
            });
        }
        if let Some(reason) = &self.authority.cancellation_reason {
            return Err(SecretError::Cancelled {
                reason: reason.clone(),
            });
        }
        if let Some(deadline) = self.authority.deadline
            && self.now > deadline
        {
            return Err(SecretError::Cancelled {
                reason: "authority deadline expired".to_string(),
            });
        }

        let (permitted, required_capability) = match operation {
            SecretOperation::Read | SecretOperation::List => (
                self.authority.has_capability(CAP_SECRET_READ_001),
                CAP_SECRET_READ_001,
            ),
            SecretOperation::Write => (
                self.authority.has_capability(CAP_SECRET_WRITE_001),
                CAP_SECRET_WRITE_001,
            ),
            SecretOperation::Rotate => (
                self.authority.has_capability(CAP_SECRET_ROTATE_001),
                CAP_SECRET_ROTATE_001,
            ),
            SecretOperation::Revoke => (
                self.authority.has_capability(CAP_SECRET_ROTATE_001)
                    || self.authority.has_capability(CAP_SECRET_WRITE_001),
                CAP_SECRET_ROTATE_001,
            ),
        };
        if !permitted {
            return Err(SecretError::Unauthorized {
                required_capability,
                detail: format!(
                    "principal '{}' lacks required grant for {operation:?}",
                    self.authority.principal
                ),
            });
        }

        if let Some(stored_scope) = expected_scope {
            let expected_digest = stored_scope.scope_digest();
            let requested_digest = self.scope.scope_digest();
            if stored_scope != &self.scope || expected_digest != requested_digest {
                return Err(SecretError::ScopeMismatch {
                    secret_id: target_secret_id
                        .map_or_else(|| "<unspecified>".to_string(), |id| id.as_str().to_string()),
                    expected_scope_digest: expected_digest,
                    requested_scope_digest: requested_digest,
                });
            }
        }
        Ok(())
    }
}

impl fmt::Debug for SecretAccessCx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretAccessCx")
            .field("principal", &self.authority.principal)
            .field("trace_id", &self.authority.trace_id)
            .field("scope", &self.scope)
            .field("cancelled", &self.is_cancelled())
            .field("now", &self.now)
            .finish()
    }
}
