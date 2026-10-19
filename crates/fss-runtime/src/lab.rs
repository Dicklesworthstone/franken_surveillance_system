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
//! - `consult` requires the sealing authority and its live canonical tree,
//!   refusing new work after canonical cancellation or local drain. It stamps
//!   every output with the session's
//!   [`LabTaint`] so lab-derived bytes can never masquerade as source
//!   evidence (INV-007: provenance is orthogonal and preserved).
//! - `finalize` resolves the exact sealing obligation through its original
//!   owner, including during cancellation, and returns the taint record for
//!   the evidence ledger. A snapshot or another session cannot supply proof.
//!
//! The executor is caller-injected: the deterministic reference tests use a
//! scripted executor; a real process adapter (spawned under the same seal)
//! is laboratory-only code and lives outside production crates.

use fss_core::{ObligationState, OperationId, RegionTree};

use crate::authority::{AuthorityBinding, AuthorityCx};
use crate::obligation::{ObligationTerminal, new_obligation};

const DRAIN_PREDICATE: &str = "oracle process sealed, drained, and every output taint-stamped";

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
    /// The session belongs to a different authority handle.
    WrongAuthority {
        /// The oracle identity.
        oracle: String,
    },
    /// The original drain obligation is missing, changed, or already settled.
    ObligationMismatch {
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
            Self::WrongAuthority { oracle } => {
                write!(f, "lab oracle '{oracle}' belongs to a different authority")
            }
            Self::ObligationMismatch { oracle } => {
                write!(
                    f,
                    "lab oracle '{oracle}' drain obligation changed or is settled"
                )
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
    authority: AuthorityBinding,
    operation: OperationId,
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
            operation.clone(),
            DRAIN_PREDICATE,
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
            authority: authority.binding().clone(),
            operation,
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
    /// leave the session. The sealing authority must still admit work through
    /// its actual tree; cancellation, snapshots, and local drain refuse before
    /// the executor runs.
    pub fn consult(
        &mut self,
        authority: &AuthorityCx,
        tree: &RegionTree,
        input: &[u8],
    ) -> Result<LabOutput, LabError> {
        self.require_scope(authority, tree)?;
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
        authority
            .require_active(tree)
            .map_err(|error| LabError::Region {
                detail: error.to_string(),
            })?;
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
    /// taint record for the evidence ledger. Cleanup remains permitted while
    /// the owning region is cancelling or draining. The original obligation
    /// must still be pending; another settlement cannot be rewritten.
    pub fn finalize(
        mut self,
        tree: &mut RegionTree,
        authority: &AuthorityCx,
    ) -> Result<LabTaint, LabError> {
        if self.state == LabState::Finalized {
            return Err(LabError::AlreadyFinalized {
                oracle: self.oracle.clone(),
            });
        }
        self.require_scope(authority, tree)?;
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
        self.state = LabState::Finalized;
        Ok(LabTaint {
            oracle: self.oracle.clone(),
            consultations: self.consultations,
            drained: true,
        })
    }

    fn require_scope(&self, authority: &AuthorityCx, tree: &RegionTree) -> Result<(), LabError> {
        if authority.binding() != &self.authority {
            return Err(LabError::WrongAuthority {
                oracle: self.oracle.clone(),
            });
        }
        authority
            .require_bound(tree)
            .map_err(|error| LabError::Region {
                detail: error.to_string(),
            })?;
        let node = tree
            .get(authority.region())
            .map_err(|error| LabError::Region {
                detail: error.to_string(),
            })?;
        let Some(obligation) = node.obligations.get(&self.obligation) else {
            return Err(LabError::ObligationMismatch {
                oracle: self.oracle.clone(),
            });
        };
        if obligation.obligation_id != self.obligation
            || obligation.operation_id != self.operation
            || obligation.terminal_predicate != DRAIN_PREDICATE
            || obligation.state != ObligationState::Pending
            || obligation.proof_digest.is_some()
        {
            return Err(LabError::ObligationMismatch {
                oracle: self.oracle.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::authority::AuthorityCx;
    use fss_core::{
        BudgetVector, ContentDigest, ObligationId, OperationId, RegionId, RegionKind,
        RootAuthoritySpec, TimestampNs,
    };

    fn authority_spec(operation: &str) -> Result<RootAuthoritySpec, Box<dyn std::error::Error>> {
        Ok(RootAuthoritySpec {
            trace_id: "trace:lab".to_string(),
            operation_id: OperationId::parse(operation)?,
            principal: "principal:test".to_string(),
            capabilities: vec!["CAP-MEDIA-DECODE-001".to_string()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder().tokens(64).bytes(4096).build()?,
            privacy_scope: "privacy:test".to_string(),
            retention_scope: "retention:test".to_string(),
            anchor_universe: ContentDigest::sha256(b"lab-universe"),
            generation: 1,
        })
    }

    fn authority() -> Result<(AuthorityCx, RegionTree), Box<dyn std::error::Error>> {
        let root = AuthorityCx::root(
            authority_spec("op:lab-root")?,
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

    struct CountingOracle(Rc<Cell<usize>>);

    impl LabOracleExecutor for CountingOracle {
        fn run_oracle(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
            self.0.set(self.0.get() + 1);
            Ok(input.to_vec())
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

        let out = session.consult(&auth, &tree, b"frame")?;
        assert_eq!(out.taint.oracle, "lab:ffmpeg-decode");
        assert_eq!(out.taint.consultations, 1);
        assert!(!out.taint.drained);
        assert_eq!(out.bytes, vec![5; 4]);

        session.request_drain();
        assert_eq!(session.state(), LabState::Draining);
        assert!(matches!(
            session.consult(&auth, &tree, b"frame"),
            Err(LabError::AlreadyDraining { .. })
        ));

        let taint = session.finalize(&mut tree, &auth)?;
        assert!(taint.drained);
        assert!(
            auth.finalize_report(&tree)?.is_empty(),
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
        assert!(auth.finalize_report(&tree)?.is_empty());
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
            session.consult(&auth, &tree, b"x"),
            Err(LabError::OracleFailure { .. })
        ));
        assert_eq!(session.state(), LabState::Sealed);
        session.request_drain();
        session.finalize(&mut tree, &auth)?;
        Ok(())
    }

    #[test]
    fn identical_labels_do_not_transfer_session_ownership() -> Result<(), Box<dyn std::error::Error>>
    {
        let (first, mut first_tree) = authority()?;
        let (second, mut second_tree) = authority()?;
        let calls = Rc::new(Cell::new(0));
        let mut first_session = LabSession::seal(
            &first,
            &mut first_tree,
            CountingOracle(Rc::clone(&calls)),
            "lab:shared-name",
            OperationId::parse("op:shared-operation")?,
        )?;
        let second_session = LabSession::seal(
            &second,
            &mut second_tree,
            CountingOracle(Rc::clone(&calls)),
            "lab:shared-name",
            OperationId::parse("op:shared-operation")?,
        )?;
        let first_before = first_tree.clone();
        let second_before = second_tree.clone();

        assert!(matches!(
            first_session.consult(&second, &second_tree, b"frame"),
            Err(LabError::WrongAuthority { .. })
        ));
        assert!(matches!(
            first_session.finalize(&mut second_tree, &second),
            Err(LabError::WrongAuthority { .. })
        ));
        assert_eq!(
            calls.get(),
            0,
            "a different owner must never run the oracle"
        );
        assert_eq!(first_tree, first_before);
        assert_eq!(second_tree, second_before);
        assert_eq!(first.finalize_report(&first_tree)?.len(), 1);
        assert_eq!(second.finalize_report(&second_tree)?.len(), 1);
        second_session.finalize(&mut second_tree, &second)?;
        assert!(second.finalize_report(&second_tree)?.is_empty());
        Ok(())
    }

    #[test]
    fn stale_snapshot_cannot_admit_work_or_supply_drain_proof()
    -> Result<(), Box<dyn std::error::Error>> {
        let (auth, mut tree) = authority()?;
        let calls = Rc::new(Cell::new(0));
        let mut session = LabSession::seal(
            &auth,
            &mut tree,
            CountingOracle(Rc::clone(&calls)),
            "lab:snapshot",
            OperationId::parse("op:lab-snapshot")?,
        )?;
        let mut snapshot = tree.clone();
        auth.request_cancellation(&mut tree, TimestampNs(2))?;
        let original_before = tree.clone();
        let snapshot_before = snapshot.clone();

        assert!(matches!(
            session.consult(&auth, &snapshot, b"frame"),
            Err(LabError::Region { .. })
        ));
        assert!(matches!(
            session.finalize(&mut snapshot, &auth),
            Err(LabError::Region { .. })
        ));
        assert_eq!(calls.get(), 0, "a stale active snapshot must not run work");
        assert_eq!(tree, original_before);
        assert_eq!(snapshot, snapshot_before);
        assert_eq!(auth.finalize_report(&tree)?.len(), 1);
        Ok(())
    }

    #[test]
    fn canonical_cancellation_stops_consultation_and_preserves_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        for begin_drain in [false, true] {
            let (auth, mut tree) = authority()?;
            let calls = Rc::new(Cell::new(0));
            let mut session = LabSession::seal(
                &auth,
                &mut tree,
                CountingOracle(Rc::clone(&calls)),
                "lab:cancellation",
                OperationId::parse("op:lab-cancellation")?,
            )?;
            session.consult(&auth, &tree, b"before cancellation")?;
            auth.request_cancellation(&mut tree, TimestampNs(2))?;
            if begin_drain {
                auth.begin_drain(&mut tree, TimestampNs(3))?;
            }

            assert_eq!(session.state(), LabState::Sealed);
            assert!(matches!(
                session.consult(&auth, &tree, b"after cancellation"),
                Err(LabError::Region { .. })
            ));
            assert_eq!(calls.get(), 1, "canonical cancellation stops execution");
            let taint = session.finalize(&mut tree, &auth)?;
            assert!(taint.drained);
            assert_eq!(taint.consultations, 1);
            assert!(auth.finalize_report(&tree)?.is_empty());
            if !begin_drain {
                auth.begin_drain(&mut tree, TimestampNs(3))?;
            }
            auth.finalize(&mut tree, TimestampNs(4))?;
        }
        Ok(())
    }

    #[test]
    fn ancestor_cancellation_stops_the_child_oracle_before_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut parent, mut tree) = authority()?;
        let child = parent.scope_down(
            &mut tree,
            RegionId::new("region:lab-property")?,
            RegionKind::Property,
            BudgetVector::builder().tokens(1).bytes(1).build()?,
            authority_spec("op:lab-child")?,
            TimestampNs(2),
        )?;
        let calls = Rc::new(Cell::new(0));
        let mut session = LabSession::seal(
            &child,
            &mut tree,
            CountingOracle(Rc::clone(&calls)),
            "lab:child-oracle",
            OperationId::parse("op:lab-child-oracle")?,
        )?;

        parent.request_cancellation(&mut tree, TimestampNs(3))?;
        assert!(matches!(
            session.consult(&child, &tree, b"frame"),
            Err(LabError::Region { .. })
        ));
        assert_eq!(calls.get(), 0, "ancestor cancellation stops new child work");
        session.finalize(&mut tree, &child)?;
        assert!(child.finalize_report(&tree)?.is_empty());
        Ok(())
    }

    #[test]
    fn external_settlement_cannot_be_used_for_more_work_or_rewritten()
    -> Result<(), Box<dyn std::error::Error>> {
        for terminal in [
            ObligationTerminal::Completed,
            ObligationTerminal::Failed,
            ObligationTerminal::Drained,
            ObligationTerminal::Indeterminate,
        ] {
            let (auth, mut tree) = authority()?;
            let calls = Rc::new(Cell::new(0));
            let mut session = LabSession::seal(
                &auth,
                &mut tree,
                CountingOracle(Rc::clone(&calls)),
                "lab:externally-settled",
                OperationId::parse("op:lab-externally-settled")?,
            )?;
            let note = (terminal == ObligationTerminal::Indeterminate)
                .then_some("reconcile the independently reported oracle exit");
            auth.resolve_obligation(&mut tree, session.obligation(), terminal, None, note)?;
            let settled = tree.clone();

            assert!(matches!(
                session.consult(&auth, &tree, b"frame"),
                Err(LabError::ObligationMismatch { .. })
            ));
            assert!(matches!(
                session.finalize(&mut tree, &auth),
                Err(LabError::ObligationMismatch { .. })
            ));
            assert_eq!(calls.get(), 0, "a settled obligation cannot admit work");
            assert_eq!(
                tree, settled,
                "existing evidence and reconciliation survive"
            );
        }
        Ok(())
    }
}
