#![forbid(unsafe_code)]
//! Local object-store oracle (FSS-062): the deterministic conformance
//! harness for [`ObjectStoreProvider`] implementations.
//!
//! The oracle drives ANY provider through one canonical, fully determined
//! scenario — stage, climb, root activation, pinning, retirement,
//! retrievability — checking the TLA-derived publication invariants
//! (R1/R2/R3 + witnessed retrievability) after every step. The scenario's
//! final state folds into a scenario digest: two providers agreeing on
//! the digest agree on every observable the oracle measures.
//!
//! The in-memory reference provider passes by construction; a real
//! ATP-backed provider plugs in and must reproduce the same digest before
//! it may claim conformance. This is the differential anchor the transfer
//! lane compares against.

use fss_core::{ContentDigest, TimestampNs};

use crate::provider::{ObjectStoreProvider, PublicationState};

/// One oracle check result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleCheck {
    /// Stable check name.
    pub name: &'static str,
    /// Whether it held.
    pub passed: bool,
}

/// The oracle's final report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleReport {
    /// Ordered check results.
    pub checks: Vec<OracleCheck>,
    /// Digest over every observable the oracle measured (final lattice
    /// positions of every object, in canonical order).
    pub scenario_digest: ContentDigest,
    /// True iff every check passed.
    pub all_passed: bool,
}

fn check(checks: &mut Vec<OracleCheck>, name: &'static str, passed: bool) {
    checks.push(OracleCheck { name, passed });
}

/// Runs the canonical conformance scenario against one provider.
///
/// The provider is consumed: the oracle owns it for the scenario's
/// lifetime and returns the report. Deterministic: identical provider
/// behavior yields identical reports and digests.
pub fn run_oracle(mut provider: impl ObjectStoreProvider) -> OracleReport {
    let mut checks = Vec::new();
    let mut observables: Vec<(ContentDigest, PublicationState)> = Vec::new();

    // ---- scenario material -------------------------------------------
    let a = ContentDigest::sha256(b"oracle-object-a");
    let b = ContentDigest::sha256(b"oracle-object-b");
    let authority = ContentDigest::sha256(b"oracle-deletion-authority");
    let root = ContentDigest::sha256(b"oracle-manifest-root");
    let now = TimestampNs(1);

    // R2 monotone admission: both children climb to Durable; skipping is
    // refused.
    let da = provider.stage(b"oracle-object-a").ok();
    let db = provider.stage(b"oracle-object-b").ok();
    let authority_id = provider.stage(b"oracle-deletion-authority").ok();
    check(&mut checks, "stage-admits", da.is_some() && db.is_some());
    let skip = da.and_then(|d| provider.advance(d, PublicationState::Protected).err());
    check(&mut checks, "ladder-skip-refused", skip.is_some());
    for id in [da, db, authority_id].into_iter().flatten() {
        let mut current = provider.state(id).ok();
        for next in [PublicationState::Visible, PublicationState::Durable] {
            if current == Some(next) {
                continue;
            }
            current = provider.advance(id, next).ok();
        }
        check(
            &mut checks,
            "durable-reached",
            current == Some(PublicationState::Durable),
        );
    }

    // R1 root-last: activation over durable children succeeds.
    let (Some(da), Some(db), Some(_authority_id)) = (da, db, authority_id) else {
        return OracleReport {
            checks,
            scenario_digest: ContentDigest::sha256(b"oracle-stage-failed"),
            all_passed: false,
        };
    };
    let children = [da, db];
    let activated = provider.activate_root(root, &children).is_ok();
    check(&mut checks, "root-activates-over-durable", activated);

    // R3 pinning: retirement of a pinned child is refused even with
    // authority; deactivation unpins; retirement then succeeds and is
    // terminal; the retired object is no longer retrievable.
    let pinned = da;
    let refused = provider.retire(pinned, authority).err();
    check(&mut checks, "pin-refuses-retirement", refused.is_some());
    let unpinned = provider.deactivate_root(root).is_ok();
    let retired = provider.retire(pinned, authority).is_ok();
    let terminal = provider.state(pinned).ok();
    let probe = provider.verify_retrievable(pinned, now).err();
    check(
        &mut checks,
        "retire-after-deactivate",
        unpinned && retired && terminal == Some(PublicationState::Retired) && probe.is_some(),
    );

    // Witnessed retrievability on a live object: the probe re-hashes and
    // reports the digest.
    let live = db;
    let witness = provider.verify_retrievable(live, now).ok();
    check(
        &mut checks,
        "retrievability-witnessed",
        witness
            .map(|w| w.digest == live && w.readable_copies >= 1)
            .unwrap_or(false),
    );

    // Unknown digests are typed refusals, never silent defaults.
    let ghost = ContentDigest::sha256(b"oracle-never-staged");
    let unknown_state = provider.state(ghost).err();
    check(&mut checks, "unknown-is-typed", unknown_state.is_some());

    // ---- observables + digest ----------------------------------------
    for id in [a, b, authority, ghost] {
        if let Ok(state) = provider.state(id) {
            observables.push((id, state));
        }
    }
    observables.sort_by_key(|(id, _)| id.bytes().to_vec());
    let mut material = Vec::new();
    for (id, state) in &observables {
        material.extend_from_slice(&id.bytes());
        material.push(state.rank());
    }
    let scenario_digest = ContentDigest::sha256(&material);
    let all_passed = checks.iter().all(|c| c.passed);
    OracleReport {
        checks,
        scenario_digest,
        all_passed,
    }
}
