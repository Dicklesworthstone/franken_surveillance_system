//! Capability grants and resource scopes for the runtime authority core
//! (FSS-025).
//!
//! The durable capability fact is the string set on `fss-core`'s
//! `ContextAuthority` (canonical-encoded, narrowing-checked by the region
//! tree). This module gives the runtime layer a TYPED view of that set:
//! strings resolve through the registered `RuntimeGrant` vocabulary, and each
//! grant may carry a resource scope — an explicit set of resource ids the
//! grant is limited to. An unscoped grant covers every resource.
//!
//! Enforcement rules:
//! - Unknown capability strings are refused at scope construction (never
//!   silently dropped).
//! - `require_grant` fails closed with the missing grant named.
//! - `require_grant_for` additionally checks the resource is inside the
//!   grant's scope when scoped.
//! - Scope-down narrows: a child's grant set must be a subset of the
//!   parent's, and a child's resource scope must be a subset of the parent's
//!   scope for the same grant (a child may narrow a scope, never widen one).

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContextAuthority, RuntimeGrant};

/// Typed capability refusal. Every variant names the exact grant and, for
/// scope violations, the resource that fell outside the granted scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantError {
    /// The authority does not hold the grant at all.
    MissingGrant {
        /// The required grant.
        grant: RuntimeGrant,
    },
    /// The grant is held but scoped, and the resource is outside the scope.
    OutsideScope {
        /// The required grant.
        grant: RuntimeGrant,
        /// The resource that was requested.
        resource: String,
    },
    /// A capability string does not resolve to a registered grant.
    UnregisteredCapability {
        /// The offending string.
        capability: String,
    },
    /// A child scope would widen the parent's grants or scopes.
    Widening {
        /// The grant that would widen.
        grant: RuntimeGrant,
        /// Why it widens.
        detail: String,
    },
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingGrant { grant } => write!(f, "missing grant: {grant:?}"),
            Self::OutsideScope { grant, resource } => {
                write!(f, "resource '{resource}' outside scope of {grant:?}")
            }
            Self::UnregisteredCapability { capability } => {
                write!(f, "unregistered capability string: {capability}")
            }
            Self::Widening { grant, detail } => {
                write!(f, "grant {grant:?} widens on scope-down: {detail}")
            }
        }
    }
}

impl std::error::Error for GrantError {}

/// One grant's resource scope. `None` = unscoped (covers every resource);
/// `Some(set)` = only the named resources.
pub type ResourceScope = Option<BTreeSet<String>>;

/// A typed view of one authority's grants: grant → resource scope.
///
/// In canonical order (BTreeMap over the grant's `Ord`), so reports and
/// digests derived from a `GrantSet` are deterministic.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrantSet {
    grants: BTreeMap<RuntimeGrant, ResourceScope>,
}

impl GrantSet {
    /// Builds an empty grant set.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Resolves an authority's capability strings into typed grants, all
    /// unscoped. Unknown strings are refused — never silently dropped.
    pub fn from_authority(authority: &ContextAuthority) -> Result<Self, GrantError> {
        let mut grants = BTreeMap::new();
        for cap in authority.capabilities() {
            let grant =
                RuntimeGrant::from_id(cap).map_err(|_| GrantError::UnregisteredCapability {
                    capability: cap.clone(),
                })?;
            grants.insert(grant, None);
        }
        Ok(Self { grants })
    }

    /// Inserts or narrows a grant's scope. Scoping an existing unscoped
    /// grant narrows it; scoping a scoped grant intersects the scopes.
    pub fn with_scope(mut self, grant: RuntimeGrant, resources: BTreeSet<String>) -> Self {
        let entry = self
            .grants
            .entry(grant)
            .or_insert_with(|| Some(resources.clone()));
        *entry = match (entry.take(), resources) {
            (Some(existing), new) => Some(existing.intersection(&new).cloned().collect()),
            (None, new) => Some(new),
        };
        self
    }

    /// Does this set hold the grant at all?
    #[must_use]
    pub fn has(&self, grant: RuntimeGrant) -> bool {
        self.grants.contains_key(&grant)
    }

    /// Requires the grant; fails closed naming the missing grant.
    pub fn require_grant(&self, grant: RuntimeGrant) -> Result<(), GrantError> {
        if self.has(grant) {
            Ok(())
        } else {
            Err(GrantError::MissingGrant { grant })
        }
    }

    /// Requires the grant for a specific resource: the grant must be held,
    /// and if it is scoped the resource must be inside the scope.
    pub fn require_grant_for(&self, grant: RuntimeGrant, resource: &str) -> Result<(), GrantError> {
        self.require_grant(grant)?;
        if let Some(scope) = &self.grants[&grant]
            && !scope.contains(resource)
        {
            return Err(GrantError::OutsideScope {
                grant,
                resource: resource.to_string(),
            });
        }
        Ok(())
    }

    /// Verifies that `child` narrows `self`: every child grant must be held
    /// by the parent, and a child resource scope must be a subset of the
    /// parent's scope for that grant. An unscoped parent grant admits any
    /// child scope (narrowing is always legal); a scoped parent grant refuses
    /// an unscoped child grant.
    pub fn verify_narrowed_by(&self, child: &GrantSet) -> Result<(), GrantError> {
        for (grant, child_scope) in &child.grants {
            match self.grants.get(grant) {
                None => {
                    return Err(GrantError::Widening {
                        grant: *grant,
                        detail: "parent does not hold the grant".to_string(),
                    });
                }
                Some(None) => {} // unscoped parent admits any child scope
                Some(Some(parent_scope)) => match child_scope {
                    None => {
                        return Err(GrantError::Widening {
                            grant: *grant,
                            detail: "child is unscoped but parent is scoped".to_string(),
                        });
                    }
                    Some(child_scope) => {
                        if !child_scope.is_subset(parent_scope) {
                            return Err(GrantError::Widening {
                                grant: *grant,
                                detail: format!(
                                    "child scope {:?} exceeds parent scope {:?}",
                                    child_scope, parent_scope
                                ),
                            });
                        }
                    }
                },
            }
        }
        Ok(())
    }

    /// Number of grants held (bounded by the grant registry size).
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Is the set empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
}
