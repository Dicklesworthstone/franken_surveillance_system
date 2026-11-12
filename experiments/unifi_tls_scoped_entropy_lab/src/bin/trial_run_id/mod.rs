#![forbid(unsafe_code)]
//! Run-scoped identities for laboratory effects, not retry authority.

use fss_core::OperationId;
use std::error::Error;

/// The caller supplies a one-use task-owned public nonce.
pub(crate) struct TrialRunId(String);

impl TrialRunId {
    pub(crate) fn from_nonce(nonce: [u8; 16]) -> Result<Self, Box<dyn Error>> {
        if nonce == [0; 16] {
            return Err("invalid trial run identity entropy".into());
        }
        Ok(Self(
            nonce.iter().map(|byte| format!("{byte:02x}")).collect(),
        ))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn operation(&self, name: &str) -> Result<OperationId, Box<dyn Error>> {
        Ok(OperationId::parse(format!(
            "operation:unifi-trial-{}-{name}",
            self.0
        ))?)
    }

    pub(crate) fn owned_step(&self, count: u64) -> Result<OperationId, Box<dyn Error>> {
        self.operation(&format!("owned-step-{count:016x}"))
    }

    pub(crate) fn owned_event(&self, count: u64) -> Result<OperationId, Box<dyn Error>> {
        self.operation(&format!("owned-event-{count:016x}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_and_keeps_operations_run_scoped() -> Result<(), Box<dyn Error>> {
        assert!(TrialRunId::from_nonce([0; 16]).is_err());
        let first = TrialRunId::from_nonce([1; 16])?;
        let second = TrialRunId::from_nonce([2; 16])?;
        assert_ne!(first.operation("handoff")?, first.operation("stream")?);
        assert_ne!(first.operation("handoff")?, second.operation("handoff")?);
        assert_ne!(first.owned_step(1)?, first.owned_event(1)?);
        Ok(())
    }
}
