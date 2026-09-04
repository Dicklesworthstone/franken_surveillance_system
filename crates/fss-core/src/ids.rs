//! Stable identifiers used by the reference semantic kernel.

use core::fmt;

use crate::{CanonicalEncode, CanonicalEncoder, ContractError};

macro_rules! stable_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Parses an identifier in the canonical portable alphabet.
            pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                validate_id(&value)?;
                Ok(Self(value))
            }

            /// Returns the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl CanonicalEncode for $name {
            fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
                encoder.text(&self.0);
            }
        }
    };
}

stable_id!(
    SensorId,
    "A stable opaque identifier for a configured sensor."
);
stable_id!(
    StreamId,
    "A stable opaque identifier for one logical stream generation."
);
stable_id!(
    CapsuleId,
    "A stable identifier for one immutable sensor capsule."
);
stable_id!(BatchId, "A stable identifier for one evidence delta batch.");
stable_id!(EventId, "A stable identifier for one event lineage.");
stable_id!(OperationId, "A stable identifier for one effect operation.");
stable_id!(
    IdempotencyKey,
    "A stable idempotency identity for replay-safe effects."
);
stable_id!(
    ObligationId,
    "A stable identifier for a terminal-proof obligation."
);
stable_id!(PrincipalId, "A stable principal identity.");
stable_id!(SessionId, "A stable agent session identity.");
stable_id!(MissionId, "A stable mission identity.");
stable_id!(HandoffId, "A stable handoff-capsule identity.");
stable_id!(ObjectId, "A stable object identity in the semantic ledger.");

fn validate_id(value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}
