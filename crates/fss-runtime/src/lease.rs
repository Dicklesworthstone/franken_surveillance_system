//! Leases, epochs, and fencing tokens for the runtime authority core
//! (FSS-026).
//!
//! A lease grants one region exclusive control of one resource for a bounded
//! time. Every lease carries a fence token drawn from a single monotone
//! source; effect paths present their token and stale tokens are refused
//! with the current epoch named — a zombie holder can never act after
//! revocation or expiry-takeover.
//!
//! Semantics:
//! - `acquire` refuses while an active, unexpired lease exists (the holder
//!   is named). Expired leases are taken over lazily at the next acquire —
//!   expiry is evaluated against caller-supplied time; there is no ambient
//!   clock and no background reaper.
//! - `renew` extends the SAME lease's expiry; the fence token is unchanged.
//! - `release` ends a lease cooperatively; the token stays valid historically
//!   but the resource becomes acquirable.
//! - `revoke` forcibly ends a lease and invalidates its fence immediately.
//! - `check_fence` is the effect-path gate: the presented token must equal
//!   the resource's current fence and the lease must be unexpired and active.
//!
//! All arithmetic is checked; tokens are never reissued within a registry.

use std::collections::BTreeMap;
use std::sync::Arc;

use fss_core::TimestampNs;

/// Lifecycle of one lease.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LeaseState {
    /// Held and (as of last evaluation) unexpired.
    Active,
    /// Cooperatively released by the holder.
    Released,
    /// Forcibly revoked; fence invalidated.
    Revoked,
    /// Taken over after expiry was observed.
    Expired,
}

impl LeaseState {
    /// Stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Released => "released",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

/// One lease record. The fence token is globally unique within its registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    /// Stable lease identity (`lease:<resource>:<fence>`).
    pub id: String,
    /// The leased resource identity.
    pub resource: String,
    /// Holding region identity.
    pub holder: String,
    /// Fence token (monotone, globally unique in this registry).
    pub fence: u64,
    /// Expiry instant (caller-time domain). `None` = no expiry (still
    /// revocable; still fence-checked).
    pub expires_at: Option<TimestampNs>,
    /// Current lifecycle state.
    pub state: LeaseState,
}

/// Typed lease refusal. Every variant names the resource and, where
/// relevant, the holder or fence values involved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseError {
    /// The resource is held by another live lease.
    Held {
        /// The resource.
        resource: String,
        /// The current holder's region.
        holder: String,
        /// The current fence token.
        fence: u64,
    },
    /// The presented fence is older than the resource's current fence.
    StaleFence {
        /// The resource.
        resource: String,
        /// The presented token.
        presented: u64,
        /// The resource's current fence.
        current: u64,
    },
    /// The lease exists but is not active (released/revoked/expired).
    NotActive {
        /// The lease identity.
        lease: String,
        /// Its current state.
        state: LeaseState,
    },
    /// The lease expired before the presented instant.
    LeaseExpired {
        /// The lease identity.
        lease: String,
        /// The expiry instant.
        expired_at: TimestampNs,
        /// The evaluation instant.
        now: TimestampNs,
    },
    /// No lease with this identity exists.
    UnknownLease {
        /// The lease identity.
        lease: String,
    },
    /// No fence has ever been issued for this resource.
    NoFence {
        /// The resource.
        resource: String,
    },
    /// The monotone fence source is exhausted (u64::MAX leases issued);
    /// no token may ever be reused, so acquisition is refused permanently.
    FenceSourceExhausted,
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held {
                resource,
                holder,
                fence,
            } => write!(
                f,
                "resource '{resource}' held by '{holder}' (fence {fence})"
            ),
            Self::StaleFence {
                resource,
                presented,
                current,
            } => write!(
                f,
                "stale fence on '{resource}': presented {presented}, current {current}"
            ),
            Self::NotActive { lease, state } => {
                write!(f, "lease '{lease}' is {}", state.as_str())
            }
            Self::LeaseExpired {
                lease,
                expired_at,
                now,
            } => write!(f, "lease '{lease}' expired at {expired_at:?} (now {now:?})"),
            Self::UnknownLease { lease } => write!(f, "unknown lease '{lease}'"),
            Self::NoFence { resource } => write!(f, "no fence issued for '{resource}'"),
            Self::FenceSourceExhausted => {
                write!(f, "fence source exhausted: no further leases can be issued")
            }
        }
    }
}

impl std::error::Error for LeaseError {}

/// Per-resource fence state: the current fence token and the lease carrying
/// it (if any).
#[derive(Clone, Debug)]
struct ResourceFence {
    current_fence: u64,
    lease: Option<Lease>,
}

/// In-process ownership of one live registry. A numeric fence is meaningful only
/// within its issuing registry; a freshly opened registry may start at the same
/// number but cannot inherit an earlier registry's effect preparations.
#[derive(Clone, Debug)]
pub(crate) struct LeaseRegistryBinding(Arc<()>);

impl PartialEq for LeaseRegistryBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for LeaseRegistryBinding {}

/// The lease registry: one monotone fence source, per-resource lease state.
/// Deterministic records; expiry evaluated against caller time only. The opaque
/// live-owner binding is not part of any persisted lease identity or record.
#[derive(Debug)]
pub struct LeaseRegistry {
    binding: LeaseRegistryBinding,
    /// Global monotone fence source. Never reused, never rewinds.
    next_fence: u64,
    /// Leases by stable identity.
    leases: BTreeMap<String, Lease>,
    /// Per-resource fence state.
    resources: BTreeMap<String, ResourceFence>,
}

impl Default for LeaseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LeaseRegistry {
    /// Opens an empty registry. The fence source starts at 1 (0 is never a
    /// valid token, so a default-constructed fence value can never pass).
    #[must_use]
    pub fn new() -> Self {
        Self {
            binding: LeaseRegistryBinding(Arc::new(())),
            next_fence: 1,
            leases: BTreeMap::new(),
            resources: BTreeMap::new(),
        }
    }

    pub(crate) fn binding(&self) -> &LeaseRegistryBinding {
        &self.binding
    }

    fn evaluate_expiry(lease: &mut Lease, now: TimestampNs) {
        if lease.state == LeaseState::Active
            && let Some(expires_at) = lease.expires_at
            && now >= expires_at
        {
            lease.state = LeaseState::Expired;
        }
    }

    /// Acquires a lease on `resource` for `holder`, valid until
    /// `now + ttl_ns` (or without expiry when `ttl_ns` is `None`). Refuses
    /// while another live lease holds the resource; expired holders are
    /// taken over lazily. The new lease carries a fresh fence token,
    /// immediately staling the previous holder's token.
    pub fn acquire(
        &mut self,
        resource: &str,
        holder: &str,
        ttl_ns: Option<u64>,
        now: TimestampNs,
    ) -> Result<Lease, LeaseError> {
        // Lazily expire the current holder, then enforce exclusivity.
        let resource_key = resource.to_string();
        if let Some(fence_state) = self.resources.get_mut(&resource_key)
            && let Some(lease) = &mut fence_state.lease
        {
            Self::evaluate_expiry(lease, now);
            if lease.state == LeaseState::Expired
                && let Some(stored) = self.leases.get_mut(&lease.id)
            {
                stored.state = LeaseState::Expired;
            }
            if let Some(lease) = &fence_state.lease
                && lease.state == LeaseState::Active
            {
                return Err(LeaseError::Held {
                    resource: resource_key,
                    holder: lease.holder.clone(),
                    fence: lease.fence,
                });
            }
        }

        let fence = self.next_fence;
        self.next_fence = match self.next_fence.checked_add(1) {
            Some(next) => next,
            // The monotone fence source is exhausted: no token may ever be
            // reused, so the registry refuses further leases permanently.
            None => {
                return Err(LeaseError::FenceSourceExhausted);
            }
        };
        let lease = Lease {
            id: format!("lease:{resource}:{fence}"),
            resource: resource_key.clone(),
            holder: holder.to_string(),
            fence,
            expires_at: ttl_ns.map(|ttl| TimestampNs(now.0.saturating_add(i128::from(ttl)))),
            state: LeaseState::Active,
        };
        self.leases.insert(lease.id.clone(), lease.clone());
        let fence_state = self.resources.entry(resource_key).or_insert(ResourceFence {
            current_fence: 0,
            lease: None,
        });
        // New lease supersedes: fence advances (staling the old token).
        fence_state.current_fence = fence;
        fence_state.lease = Some(lease.clone());
        Ok(lease)
    }

    /// Renews a lease's expiry. The fence token is unchanged — renewal never
    /// stales the holder's own token.
    pub fn renew(
        &mut self,
        lease_id: &str,
        ttl_ns: u64,
        now: TimestampNs,
    ) -> Result<(), LeaseError> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| LeaseError::UnknownLease {
                lease: lease_id.to_string(),
            })?;
        Self::evaluate_expiry(lease, now);
        if lease.state != LeaseState::Active {
            // Expiry is irreversible once observed. Keep the effect gate's copy
            // consistent even if this renewal is refused or caller time moves back.
            if let Some(fence_state) = self.resources.get_mut(&lease.resource)
                && let Some(current) = &mut fence_state.lease
                && current.id == lease.id
            {
                current.state = lease.state;
            }
            return Err(LeaseError::NotActive {
                lease: lease_id.to_string(),
                state: lease.state,
            });
        }
        lease.expires_at = Some(TimestampNs(now.0.saturating_add(i128::from(ttl_ns))));
        // Mirror into the per-resource copy.
        if let Some(fence_state) = self.resources.get_mut(&lease.resource)
            && let Some(current) = &mut fence_state.lease
            && current.id == lease.id
        {
            current.expires_at = lease.expires_at;
        }
        Ok(())
    }

    /// Cooperative release. The token is not revoked historically — records
    /// made under it remain attributable — but the resource becomes
    /// acquirable and `check_fence` refuses further use.
    pub fn release(&mut self, lease_id: &str) -> Result<(), LeaseError> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| LeaseError::UnknownLease {
                lease: lease_id.to_string(),
            })?;
        if lease.state != LeaseState::Active {
            return Err(LeaseError::NotActive {
                lease: lease_id.to_string(),
                state: lease.state,
            });
        }
        lease.state = LeaseState::Released;
        if let Some(fence_state) = self.resources.get_mut(&lease.resource)
            && let Some(current) = &mut fence_state.lease
            && current.id == lease.id
        {
            current.state = LeaseState::Released;
        }
        Ok(())
    }

    /// Forcible revocation: the lease ends and its fence is invalidated
    /// immediately by advancing the resource's current fence past the
    /// revoked token.
    pub fn revoke(&mut self, lease_id: &str) -> Result<(), LeaseError> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| LeaseError::UnknownLease {
                lease: lease_id.to_string(),
            })?;
        if lease.state != LeaseState::Active {
            return Err(LeaseError::NotActive {
                lease: lease_id.to_string(),
                state: lease.state,
            });
        }
        lease.state = LeaseState::Revoked;
        let resource = lease.resource.clone();
        let fence = lease.fence;
        let Some(fence_state) = self.resources.get_mut(&resource) else {
            return Err(LeaseError::NoFence {
                resource: resource.clone(),
            });
        };
        if let Some(current) = &mut fence_state.lease
            && current.id == lease_id
        {
            current.state = LeaseState::Revoked;
        }
        // Advance the fence so the revoked token is permanently stale.
        fence_state.current_fence = fence_state.current_fence.max(fence) + 1;
        Ok(())
    }

    /// The effect-path gate: the presented token must be the resource's
    /// current fence AND the carrying lease must still be active and
    /// unexpired at `now`.
    pub fn check_fence(
        &mut self,
        resource: &str,
        fence: u64,
        now: TimestampNs,
    ) -> Result<(), LeaseError> {
        let fence_state = self
            .resources
            .get_mut(resource)
            .ok_or_else(|| LeaseError::NoFence {
                resource: resource.to_string(),
            })?;
        if fence != fence_state.current_fence {
            return Err(LeaseError::StaleFence {
                resource: resource.to_string(),
                presented: fence,
                current: fence_state.current_fence,
            });
        }
        let lease = fence_state
            .lease
            .as_mut()
            .ok_or_else(|| LeaseError::NoFence {
                resource: resource.to_string(),
            })?;
        Self::evaluate_expiry(lease, now);
        // Readers and renewal use the identity index; they must see an expiry
        // established by this effect gate as well as by acquire or renew.
        if let Some(stored) = self.leases.get_mut(&lease.id) {
            stored.state = lease.state;
        }
        match lease.state {
            LeaseState::Active => Ok(()),
            LeaseState::Expired => match lease.expires_at {
                // An Expired state is only reachable through evaluate_expiry,
                // which requires an expiry; the fallback stays typed.
                Some(expired_at) => Err(LeaseError::LeaseExpired {
                    lease: lease.id.clone(),
                    expired_at,
                    now,
                }),
                None => Err(LeaseError::NotActive {
                    lease: lease.id.clone(),
                    state: LeaseState::Expired,
                }),
            },
            state => Err(LeaseError::NotActive {
                lease: lease.id.clone(),
                state,
            }),
        }
    }

    /// Reads a lease by identity.
    #[must_use]
    pub fn get(&self, lease_id: &str) -> Option<&Lease> {
        self.leases.get(lease_id)
    }

    /// The current fence for a resource, if any was ever issued.
    #[must_use]
    pub fn current_fence(&self, resource: &str) -> Option<u64> {
        self.resources.get(resource).map(|f| f.current_fence)
    }
}
