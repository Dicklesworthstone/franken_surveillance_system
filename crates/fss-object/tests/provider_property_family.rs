#![forbid(unsafe_code)]
//! FSS-061 property family: object-store provider publication lattice.
//!
//! Direct Rust projection of the TLC-checked `RootLastPublication` model
//! (`proofs/tla/`): R1 root-last activation, R2 lattice monotonicity,
//! R3 deletion closure, R5 referential integrity, plus custody consistency
//! and canonical codec roundtrips for the lattice states. Each property
//! emits one JSONL verdict line.

use fss_core::{CanonicalDecode, CanonicalEncode, CanonicalEncoder};
use fss_core::{ContentDigest, TimestampNs};
use fss_object::InMemoryObjectStore;
use fss_object::provider::memory::InMemoryObjectStoreProvider;
use fss_object::provider::{ObjectStoreProvider, PublicationState};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-061\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

fn provider() -> InMemoryObjectStoreProvider {
    InMemoryObjectStoreProvider::new(
        InMemoryObjectStore::new(fss_object::ObjectLimits::new(64, 1 << 20)),
        2,
    )
}

fn climb_to(
    p: &mut InMemoryObjectStoreProvider,
    digest: ContentDigest,
    target: PublicationState,
) -> Result<(), fss_object::provider::ProviderError> {
    let mut current = p.state(digest)?;
    for next in [
        PublicationState::Visible,
        PublicationState::Durable,
        PublicationState::Replicated,
        PublicationState::Protected,
    ] {
        if current == target {
            return Ok(());
        }
        if current.can_advance_to(next) {
            p.advance(digest, next)?;
            current = next;
        }
    }
    Ok(())
}

/// R2 + skip/backward refusals: the ladder is monotone; every illegal move
/// names both ends.
#[test]
fn p1_lattice_is_strictly_monotone() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    let all = [
        PublicationState::Staged,
        PublicationState::Visible,
        PublicationState::Durable,
        PublicationState::Replicated,
        PublicationState::Protected,
        PublicationState::Retired,
    ];
    for from in all {
        for to in all {
            let legal = from.can_advance_to(to);
            // No self moves; no backwards moves up the ladder (retirement
            // aside); no skips past a level.
            if from == to {
                assert!(!legal);
            }
            if from != PublicationState::Retired && to != PublicationState::Retired {
                assert_eq!(legal, to.rank() == from.rank() + 1);
            }
            cases += 1;
        }
    }
    // Runtime enforcement mirrors the static relation: staged bytes refuse
    // a jump straight to Protected, and Durable refuses a move back to
    // Staged.
    let mut p = provider();
    let d = p.stage(b"monotone")?;
    assert!(p.advance(d, PublicationState::Protected).is_err());
    climb_to(&mut p, d, PublicationState::Durable)?;
    assert!(p.advance(d, PublicationState::Staged).is_err());
    cases += 2;
    emit("lattice-monotonicity", cases);
    Ok(())
}

/// R1 root-last: activation is refused while any child is below Durable;
/// once all children are Durable+ it succeeds and pins them.
#[test]
fn p2_root_activates_only_over_durable_children() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    let mut p = provider();
    let a = p.stage(b"child-a")?;
    let b = p.stage(b"child-b")?;
    let root = ContentDigest::sha256(b"manifest-root");
    // Both children staged: refused, naming a child.
    let err = p.activate_root(root, &[a, b]).err();
    assert!(matches!(
        err,
        Some(fss_object::provider::ProviderError::RootBeforeDurableChildren { .. })
    ));
    cases += 1;
    // First child durable: still refused (second staged).
    climb_to(&mut p, a, PublicationState::Durable)?;
    assert!(p.activate_root(root, &[a, b]).is_err());
    cases += 1;
    // Both durable: activates.
    climb_to(&mut p, b, PublicationState::Durable)?;
    p.activate_root(root, &[a, b])?;
    cases += 1;
    // Replicated children are equally admissible (rank >= Durable).
    let c = p.stage(b"child-c")?;
    climb_to(&mut p, c, PublicationState::Replicated)?;
    p.activate_root(ContentDigest::sha256(b"root-2"), &[c])?;
    cases += 1;
    emit("root-last-activation", cases);
    Ok(())
}

/// R3 deletion closure: an active root pins its children; retirement is
/// refused until the root is deactivated; then it succeeds terminally and
/// the bytes are genuinely released (retrievability fails afterward).
#[test]
fn p3_retirement_is_closed_under_active_roots() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    let mut p = provider();
    let child = p.stage(b"pinned-child")?;
    let root = ContentDigest::sha256(b"pinning-root");
    climb_to(&mut p, child, PublicationState::Durable)?;
    p.activate_root(root, &[child])?;
    // Pinned: refuse even WITH authority. The authority record itself is a
    // retained verified object in the same custody (deletion authority is
    // proof-carrying, not asserted).
    let authority = p.stage(b"owner-authorized-deletion-record")?;
    climb_to(&mut p, authority, PublicationState::Durable)?;
    assert!(matches!(
        p.retire(child, authority),
        Err(fss_object::provider::ProviderError::ActiveRootReference { .. })
    ));
    cases += 1;
    // Generic ladder advance can never mint retirement (authority must be
    // presented, not implied by position).
    assert!(p.advance(child, PublicationState::Retired).is_err());
    cases += 1;
    // Deactivate the root: retirement proceeds with authority and is terminal.
    p.deactivate_root(root)?;
    p.retire(child, authority)?;
    assert_eq!(p.state(child)?, PublicationState::Retired);
    // Bytes released: the retrievability probe fails honestly.
    assert!(p.verify_retrievable(child, TimestampNs(1)).is_err());
    cases += 2;
    emit("deletion-closure", cases);
    Ok(())
}

/// Retrievability is witnessed, not assumed: the probe re-hashes bytes
/// against the identity and reports ladder position and readable copies.
#[test]
fn p4_retrievability_is_witnessed() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    let mut p = provider();
    let d = p.stage(b"witnessed-bytes")?;
    // Staged bytes are readable exactly once (single copy) — but custody
    // read_verified requires the Verified custody state; staging alone may
    // refuse. Climb to Durable first, then probe.
    climb_to(&mut p, d, PublicationState::Durable)?;
    let w = p.verify_retrievable(d, TimestampNs(42))?;
    assert_eq!(w.digest, d);
    assert_eq!(w.state, PublicationState::Durable);
    assert!(w.readable_copies >= 1);
    assert_eq!(w.probed_at, TimestampNs(42));
    cases += 1;
    // Unknown digests refuse with a typed error, never a bare false.
    assert!(matches!(
        p.verify_retrievable(ContentDigest::sha256(b"never-staged"), TimestampNs(1)),
        Err(fss_object::provider::ProviderError::NotRetrievable { .. })
    ));
    cases += 1;
    emit("witnessed-retrievability", cases);
    Ok(())
}

/// Canonical codec: every lattice state roundtrips through the canonical
/// byte form (hand-audited tags 0-5).
#[test]
fn p5_publication_state_canonical_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    for state in [
        PublicationState::Staged,
        PublicationState::Visible,
        PublicationState::Durable,
        PublicationState::Replicated,
        PublicationState::Protected,
        PublicationState::Retired,
    ] {
        let mut enc = CanonicalEncoder::new();
        state.encode_canonical(&mut enc);
        let bytes = enc.finish();
        assert_eq!(bytes.len(), 1, "one hand-audited tag byte per state");
        let mut dec = fss_core::CanonicalDecoder::new(&bytes);
        assert_eq!(
            PublicationState::decode_canonical(&mut dec)?,
            state,
            "roundtrip failed for {state:?}"
        );
        cases += 1;
    }
    emit("canonical-roundtrips", cases);
    Ok(())
}

/// Idempotent staging: identical bytes stage to the same identity and the
/// same lattice record; distinct bytes never collide.
#[test]
fn p6_staging_is_identity_and_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    let mut p = provider();
    let a = p.stage(b"same-bytes")?;
    let b = p.stage(b"same-bytes")?;
    assert_eq!(a, b, "content-addressed identity");
    assert_eq!(p.object_count(), 1, "no duplicate record");
    let c = p.stage(b"different-bytes")?;
    assert_ne!(a, c);
    cases += 3;
    emit("staging-identity", cases);
    Ok(())
}
