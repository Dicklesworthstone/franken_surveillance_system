use super::*;

/// Stable hydration failures with deterministic recovery guidance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HydrationError {
    /// Shared semantic contract failure.
    Contract(ContractError),
    /// Stable handle identity was presented with a different immutable subject.
    HandleRebound,
    /// The exact descriptor revision is unknown.
    DescriptorNotFound,
    /// The requested level is not published for this subject.
    LevelUnavailable,
    /// Required read capability is absent.
    CapabilityDenied,
    /// Required privacy class is absent.
    PrivacyDenied,
    /// H4 purpose or debugging grant is insufficient.
    LaboratoryGrantRequired,
    /// No permitted level fits the declared full resource budget.
    BudgetExceeded,
    /// A request set exceeds the maximum permitted cardinality.
    CapacityExceeded,
    /// A progressive cursor belongs to another handle, session, basis, or position.
    WrongContinuation,
    /// A progressive cursor was presented after its expiration time.
    ContinuationExpired,
    /// A progressive cursor was presented that was never issued by the catalog.
    ContinuationUnissued,
    /// A progressive cursor was presented by a different session than the one to which it was issued.
    ContinuationCrossSession,
    /// A progressive cursor was already consumed by a prior hydration request.
    ContinuationAlreadyConsumed,
    /// A canonical binary input was truncated or missing required bytes.
    Truncated,
}

impl HydrationError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Contract(error) => error.code(),
            Self::HandleRebound => "semantic_handle_rebound",
            Self::DescriptorNotFound => "semantic_handle_descriptor_not_found",
            Self::LevelUnavailable => "hydration_level_unavailable",
            Self::CapabilityDenied => "hydration_capability_denied",
            Self::PrivacyDenied => "hydration_privacy_denied",
            Self::LaboratoryGrantRequired => "hydration_laboratory_grant_required",
            Self::BudgetExceeded => "hydration_budget_exceeded",
            Self::CapacityExceeded => "hydration_capacity_exceeded",
            Self::WrongContinuation => "hydration_wrong_continuation",
            Self::ContinuationExpired => "hydration_continuation_expired",
            Self::ContinuationUnissued => "hydration_continuation_unissued",
            Self::ContinuationCrossSession => "hydration_continuation_cross_session",
            Self::ContinuationAlreadyConsumed => "hydration_continuation_already_consumed",
            Self::Truncated => "hydration_truncated",
        }
    }

    /// Returns deterministic recovery guidance.
    #[must_use]
    pub const fn recovery(&self) -> RecoveryClass {
        match self {
            Self::Contract(ContractError::StaleAnchor)
            | Self::DescriptorNotFound
            | Self::WrongContinuation
            | Self::ContinuationExpired
            | Self::ContinuationAlreadyConsumed => RecoveryClass::RebaseRequired,
            Self::CapabilityDenied
            | Self::PrivacyDenied
            | Self::LaboratoryGrantRequired
            | Self::BudgetExceeded
            | Self::CapacityExceeded => RecoveryClass::OperatorActionRequired,
            Self::Contract(_)
            | Self::HandleRebound
            | Self::LevelUnavailable
            | Self::ContinuationUnissued
            | Self::ContinuationCrossSession
            | Self::Truncated => RecoveryClass::NeverUnchanged,
        }
    }
}

impl fmt::Display for HydrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for HydrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::HandleRebound
            | Self::DescriptorNotFound
            | Self::LevelUnavailable
            | Self::CapabilityDenied
            | Self::PrivacyDenied
            | Self::LaboratoryGrantRequired
            | Self::BudgetExceeded
            | Self::CapacityExceeded
            | Self::WrongContinuation
            | Self::ContinuationExpired
            | Self::ContinuationUnissued
            | Self::ContinuationCrossSession
            | Self::ContinuationAlreadyConsumed
            | Self::Truncated => None,
        }
    }
}

impl From<ContractError> for HydrationError {
    fn from(value: ContractError) -> Self {
        match value {
            ContractError::LaboratoryGrantRequired => Self::LaboratoryGrantRequired,
            other => Self::Contract(other),
        }
    }
}

impl From<ContinuationError> for HydrationError {
    fn from(value: ContinuationError) -> Self {
        match value {
            ContinuationError::Contract(error) => Self::Contract(error),
            ContinuationError::Expired => Self::ContinuationExpired,
            ContinuationError::WrongStream
            | ContinuationError::NonMonotone
            | ContinuationError::OutOfRange => Self::WrongContinuation,
        }
    }
}
