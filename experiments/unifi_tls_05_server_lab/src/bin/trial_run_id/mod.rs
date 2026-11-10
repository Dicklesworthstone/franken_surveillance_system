#![forbid(unsafe_code)]
//! Run-scoped identities for laboratory effects, not retry authority.

use fss_core::OperationId;
use std::error::Error;

/// The caller admits entropy under its task before generating this value.
/// The laboratory TLS provider is not a production-admitted entropy boundary.
pub(crate) struct TrialRunId(String);

impl TrialRunId {
    pub(crate) fn fresh() -> Result<Self, Box<dyn Error>> {
        let mut nonce = [0u8; 16];
        rustls_pure::provider()
            .secure_random
            .fill(&mut nonce)
            .map_err(|_| "trial run identity entropy unavailable")?;
        if nonce == [0; 16] {
            return Err("invalid trial run identity entropy".into());
        }
        Ok(Self(nonce.iter().map(|byte| format!("{byte:02x}")).collect()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn operation(&self, name: &str) -> Result<OperationId, Box<dyn Error>> {
        Ok(OperationId::parse(format!("operation:unifi-trial-{}-{name}", self.0))?)
    }

    pub(crate) fn owned_step(&self, count: u64) -> Result<OperationId, Box<dyn Error>> {
        self.operation(&format!("owned-step-{count:016x}"))
    }

    pub(crate) fn owned_event(&self, count: u64) -> Result<OperationId, Box<dyn Error>> {
        self.operation(&format!("owned-event-{count:016x}"))
    }
}
