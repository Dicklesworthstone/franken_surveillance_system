//! Sealed laboratory-oracle process ownership, drain, and taint (FSS-024).
//!
//! Foreign frameworks and applications are laboratory or migration oracles
//! ONLY (workspace `foreign_runtime_role = "sealed_laboratory_oracle_only"`).
//! This module is the single surface through which such an oracle may be
//! consulted, and it is COMPILE-TIME EXCLUDED from production builds: the
//! module is gated on `lab-oracle` (never a default feature) or the crate's
//! own test build. `scripts/lab_oracle_absence.py` is the production-absence
//! harness proving no ungated reference exists.
//!
//! Ownership and drain semantics:
//! - `seal` registers a durable obligation on the authority's region:
//!   the oracle process is sealed, drained, and every output taint-stamped.
//!   A session that is dropped or never finalized leaves that obligation
//!   PENDING — visible to the tree-wide leak oracle, never silently gone.
//! - `consult` refuses once drain has been requested (no new oracle work
//!   after teardown begins) and stamps every output with the session's
//!   [`LabTaint`] so lab-derived bytes can never masquerade as source
//!   evidence (INV-007: provenance is orthogonal and preserved).
//! - `finalize` resolves the drain obligation terminally and returns the
//!   taint record for the evidence ledger.
//!
//! The executor is caller-injected: the deterministic reference tests use a
//! scripted executor; a real process adapter (spawned under the same seal)
//! is laboratory-only code and lives outside production crates.

use fss_core::{OperationId, RegionTree, TimestampNs};

use crate::authority::AuthorityCx;
use crate::obligation::{ObligationTerminal, new_obligation};

/// Typed lab-oracle refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LabError {
    /// The oracle executor failed (crash, malformed output, timeout).
    OracleFailure {
        /// The oracle identity.
        oracle: String,
        /// Machine-readable failure reason.
        reason: String,
    },
    /// A consultation was attempted after drain was requested.
    AlreadyDraining {
        /// The oracle identity.
        oracle: String,
    },
    /// The session was already finalized.
    AlreadyFinalized {
        /// The oracle identity.
        oracle: String,
    },
    /// The region tree refused the ownership bookkeeping.
    Region {
        /// Detail from the tree refusal.
        detail: String,
    },
}

impl std::fmt::Display for LabError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OracleFailure { oracle, reason } => {
                write!(f, "lab oracle '{oracle}' failed: {reason}")
            }
            Self::AlreadyDraining { oracle } => {
                write!(f, "lab oracle '{oracle}' is draining; no new consultations")
            }
            Self::AlreadyFinalized { oracle } => {
                write!(f, "lab oracle '{oracle}' session already finalized")
            }
            Self::Region { detail } => write!(f, "region refusal: {detail}"),
        }
    }
}

impl std::error::Error for LabError {}

/// Taint stamped on every lab-oracle output. Carries the oracle identity and
/// the consultation count at issue time; distinct from every production
/// provenance class by construction (it only exists behind the lab gate).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabTaint {
    /// Oracle identity (e.g. `lab:ffmpeg-decode`).
    pub oracle: String,
    /// Number of consultations issued before this taint was minted.
    pub consultations: u64,
    /// Drain state at mint time.
    pub drained: bool,
}

/// The provenance-marked output of one oracle consultation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabOutput {
    /// Oracle-produced bytes (reference-shaped; real adapters stream).
    pub bytes: Vec<u8>,
    /// The mandatory taint stamp.
    pub taint: LabTaint,
}

/// Caller-injected oracle execution. Production crates never implement this;
/// laboratory adapters and scripted test doubles do.
pub trait LabOracleExecutor {
    /// Runs one consultation. Deterministic implementations must return
    /// identical bytes for identical input.
    fn run_oracle(&mut self, input: &[u8]) -> Result<Vec<u8>, String>;
}

/// Session lifecycle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LabState {
    /// Sealed and accepting consultations.
    Sealed,
    /// Drain requested; consultations refused.
    Draining,
    /// Terminal.
    Finalized,
}

/// One sealed lab-oracle session owned by an authority's region.
pub struct LabSession<E: LabOracleExecutor> {
    executor: E,
    oracle: String,
    obligation: fss_core::ObligationId,
    state: LabState,
    consultations: u64,
}

impl<E: LabOracleExecutor> LabSession<E> {
    /// Seals a lab-oracle session under `authority`'s region: registers the
    /// drain obligation that stays PENDING until a terminal `finalize`.
    pub fn seal(
        authority: &AuthorityCx,
        tree: &mut RegionTree,
        executor: E,
        oracle: &str,
        operation: OperationId,
    ) -> Result<Self, LabError> {
        let obligation = new_obligation(
            format!("obligation:{oracle}:drain"),
            operation,
            "oracle process sealed, drained, and every output taint-stamped",
        )
        .map_err(|e| LabError::Region {
            detail: format!("{e}"),
        })?;
        let obligation_id = obligation.obligation_id.clone();
        authority
            .register_obligation(tree, obligation)
            .map_err(|e| LabError::Region {
                detail: format!("{e}"),
            })?;
        Ok(Self {
            executor,
            oracle: oracle.to_string(),
            obligation: obligation_id,
            state: LabState::Sealed,
            consultations: 0,
        })
    }

    /// Current session state.
    #[must_use]
    pub fn state(&self) -> LabState {
        self.state
    }

    /// The drain obligation registered at seal time.
    #[must_use]
    pub fn obligation(&self) -> &fss_core::ObligationId {
        &self.obligation
    }

    /// Consults the oracle once; the output is taint-stamped before it can
    /// leave the session. Refused after drain begins.
    pub fn consult(&mut self, input: &[u8]) -> Result<LabOutput, LabError> {
        match self.state {
            LabState::Sealed => {}
            LabState::Draining => {
                return Err(LabError::AlreadyDraining {
                    oracle: self.oracle.clone(),
                });
            }
            LabState::Finalized => {
                return Err(LabError::AlreadyFinalized {
                    oracle: self.oracle.clone(),
                });
            }
        }
        let bytes = self
            .executor
            .run_oracle(input)
            .map_err(|reason| LabError::OracleFailure {
                oracle: self.oracle.clone(),
                reason,
            })?;
        // u64 consultation counter: saturation is unreachable in practice and
        // never reuses a count (taint stays monotone).
        self.consultations = self.consultations.saturating_add(1);
        Ok(LabOutput {
            bytes,
            taint: LabTaint {
                oracle: self.oracle.clone(),
                consultations: self.consultations,
                drained: false,
            },
        })
    }

    /// Requests drain: consultations stop being accepted; the obligation
    /// stays pending until `finalize`.
    pub fn request_drain(&mut self) {
        if self.state == LabState::Sealed {
            self.state = LabState::Draining;
        }
    }

    /// Terminal close: resolves the drain obligation and returns the final
    /// taint record for the evidence ledger.
    pub fn finalize(
        mut self,
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        now: TimestampNs,
    ) -> Result<LabTaint, LabError> {
        let _ = now;
        if self.state == LabState::Finalized {
            return Err(LabError::AlreadyFinalized {
                oracle: self.oracle.clone(),
            });
        }
        self.state = LabState::Finalized;
        let taint = LabTaint {
            oracle: self.oracle.clone(),
            consultations: self.consultations,
            drained: true,
        };
        authority
            .resolve_obligation(
                tree,
                &self.obligation,
                ObligationTerminal::Completed,
                None,
                None,
            )
            .map_err(|e| LabError::Region {
                detail: format!("{e}"),
            })?;
        Ok(taint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::AuthorityCx;
    use fss_core::{
        BudgetVector, ContentDigest, ObligationId, OperationId, RegionId, RegionKind,
        RootAuthoritySpec, TimestampNs,
    };

    fn authority() -> Result<(AuthorityCx, RegionTree), Box<dyn std::error::Error>> {
        let spec = RootAuthoritySpec {
            trace_id: "trace:lab".to_string(),
            operation_id: OperationId::parse("op:lab-root")?,
            principal: "principal:test".to_string(),
            capabilities: vec!["CAP-MEDIA-DECODE-001".to_string()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder().bytes(1024).build()?,
            privacy_scope: "privacy:test".to_string(),
            retention_scope: "retention:test".to_string(),
            anchor_universe: ContentDigest::sha256(b"lab-universe"),
            generation: 1,
        };
        let root = AuthorityCx::root(
            spec,
            RegionId::new("region:process")?,
            RegionKind::Process,
            BudgetVector::builder().tokens(64).bytes(4096).build()?,
            TimestampNs(1),
        )?;
        Ok(root)
    }

    struct ScriptedOracle {
        fail: bool,
    }

    impl LabOracleExecutor for ScriptedOracle {
        fn run_oracle(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
            if self.fail {
                return Err("oracle crashed".to_string());
            }
            Ok(vec![input.len() as u8; 4])
        }
    }

    #[test]
    fn seal_consult_drain_finalize() -> Result<(), Box<dyn std::error::Error>> {
        let (auth, mut tree) = authority()?;
        let mut session = LabSession::seal(
            &auth,
            &mut tree,
            ScriptedOracle { fail: false },
            "lab:ffmpeg-decode",
            OperationId::parse("op:lab-1")?,
        )?;
        assert_eq!(session.state(), LabState::Sealed);

        let out = session.consult(b"frame")?;
        assert_eq!(out.taint.oracle, "lab:ffmpeg-decode");
        assert_eq!(out.taint.consultations, 1);
        assert!(!out.taint.drained);
        assert_eq!(out.bytes, vec![5; 4]);

        session.request_drain();
        assert_eq!(session.state(), LabState::Draining);
        assert!(matches!(
            session.consult(b"frame"),
            Err(LabError::AlreadyDraining { .. })
        ));

        let taint = session.finalize(&mut tree, &auth, TimestampNs(1_000))?;
        assert!(taint.drained);
        assert!(
            auth.finalize_report(&tree).is_empty(),
            "no lab obligation leaks"
        );
        Ok(())
    }

    #[test]
    fn crash_leaves_visible_leak_and_reconciles() -> Result<(), Box<dyn std::error::Error>> {
        let (auth, mut tree) = authority()?;
        let session = LabSession::seal(
            &auth,
            &mut tree,
            ScriptedOracle { fail: false },
            "lab:h264-oracle",
            OperationId::parse("op:lab-2")?,
        )?;
        let obligation = session.obligation().clone();

        drop(session);
        let report = crate::obligation::tree_report(&tree);
        assert_eq!(report[0].leaked.len(), 1);
        assert_eq!(report[0].leaked[0].id, obligation.as_str());

        auth.resolve_obligation(
            &mut tree,
            &ObligationId::parse(obligation.as_str())?,
            crate::obligation::ObligationTerminal::Failed,
            Some(ContentDigest::sha256(b"lab-session-crashed")),
            None,
        )?;
        assert!(auth.finalize_report(&tree).is_empty());
        Ok(())
    }

    #[test]
    fn oracle_failure_is_typed_and_nonterminal() -> Result<(), Box<dyn std::error::Error>> {
        let (auth, mut tree) = authority()?;
        let mut session = LabSession::seal(
            &auth,
            &mut tree,
            ScriptedOracle { fail: true },
            "lab:flaky-oracle",
            OperationId::parse("op:lab-3")?,
        )?;
        assert!(matches!(
            session.consult(b"x"),
            Err(LabError::OracleFailure { .. })
        ));
        assert_eq!(session.state(), LabState::Sealed);
        session.request_drain();
        session.finalize(&mut tree, &auth, TimestampNs(2))?;
        Ok(())
    }
}
