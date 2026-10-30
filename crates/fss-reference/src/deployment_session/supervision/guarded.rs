#![forbid(unsafe_code)]
//! Exact subscription admission for compositions that must not silently follow later work.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum SubscriptionAdmission {
    RegisterIfAbsent,
    Existing,
    Exact(ContentDigest),
}

impl SubscriptionAdmission {
    pub(super) const fn requires_existing(self) -> bool {
        !matches!(self, Self::RegisterIfAbsent)
    }

    pub(super) const fn expected_state(self) -> Option<ContentDigest> {
        match self {
            Self::Exact(state) => Some(state),
            Self::RegisterIfAbsent | Self::Existing => None,
        }
    }
}

/// Successful native operation admitted against an exact pre-operation subscription state.
///
/// Only the native owner constructs this proof, after checking the state while holding the
/// session-journal writer. Compositions may inspect the immutable result, but cannot relabel
/// an unguarded delivery or substitute the expected state after native work has occurred.
#[derive(Debug)]
pub struct GuardedSupervisionDelivery {
    expected_subscription_state: ContentDigest,
    delivery: SupervisionSessionDelivery,
}

impl GuardedSupervisionDelivery {
    /// Exact original state accepted before any native action or new work reservation.
    #[must_use]
    pub const fn expected_subscription_state(&self) -> ContentDigest {
        self.expected_subscription_state
    }

    /// Complete original native result; reading it does not alter its immutable journal root.
    #[must_use]
    pub const fn delivery(&self) -> &SupervisionSessionDelivery {
        &self.delivery
    }

    /// Consume the proof when a caller only needs the ordinary delivery afterward.
    #[must_use]
    pub fn into_delivery(self) -> SupervisionSessionDelivery {
        self.delivery
    }
}

/// Execute only if the existing subscription still equals the explicitly selected state.
///
/// The comparison occurs under the same exclusive session-journal ownership as every action
/// and full-cap reservation. A successful earlier call changes that state; blindly repeating
/// its original expectation therefore refuses before source work. A caller must separately
/// inspect retained progress and explicitly select its next expectation. Legacy entrypoints
/// retain their existing behavior; this function never registers a missing subscription.
pub fn supervise_existing_session_at(
    root: &Path,
    principal: &PrincipalId,
    request: &SupervisionSessionRequest,
    expected_subscription_state: ContentDigest,
    limits: &OrientLimits,
    control: &mut impl SupervisionEvaluator,
) -> Result<GuardedSupervisionDelivery, Box<SupervisionSessionFailure>> {
    supervise(
        root,
        principal,
        request,
        limits,
        control,
        SubscriptionAdmission::Exact(expected_subscription_state),
    )
    .map(|delivery| GuardedSupervisionDelivery {
        expected_subscription_state,
        delivery,
    })
}
