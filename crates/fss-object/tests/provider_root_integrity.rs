#![forbid(unsafe_code)]
//! Canonical root custody, transitive pins, and failure atomicity through the public provider.

use fss_core::{CanonicalEncode, ContentDigest, TimestampNs};
use fss_object::provider::memory::InMemoryObjectStoreProvider;
use fss_object::provider::{ObjectStoreProvider, ProviderError, PublicationState};
use fss_object::{InMemoryObjectStore, MAX_MANIFEST_CHILDREN, ObjectLimits, ObjectManifest};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn provider() -> InMemoryObjectStoreProvider {
    InMemoryObjectStoreProvider::new(
        InMemoryObjectStore::new(ObjectLimits::new(64, 1 << 20)),
        2,
    )
}

fn durable(
    provider: &mut InMemoryObjectStoreProvider,
    bytes: &[u8],
) -> Result<ContentDigest, ProviderError> {
    let digest = provider.stage(bytes)?;
    provider.advance(digest, PublicationState::Visible)?;
    provider.advance(digest, PublicationState::Durable)?;
    Ok(digest)
}

fn manifest(
    provider: &mut InMemoryObjectStoreProvider,
    kind: &str,
    children: &[ContentDigest],
    metadata: Option<ContentDigest>,
) -> Result<ObjectManifest, Box<dyn std::error::Error>> {
    let manifest = ObjectManifest::new(kind, children.iter().copied(), metadata)?;
    assert_eq!(
        durable(provider, &manifest.try_canonical_bytes()?)?,
        manifest.root()
    );
    Ok(manifest)
}

#[test]
fn phantom_and_opaque_roots_cannot_create_pins() -> TestResult {
    let mut p = provider();
    let child = durable(&mut p, b"retained-child")?;
    let witness = durable(&mut p, b"separate-owner-deletion-record")?;
    let missing = ContentDigest::sha256(b"no manifest was retained");
    assert!(matches!(
        p.activate_root(missing, &[child]),
        Err(ProviderError::UnknownObject(d)) if d == missing
    ));
    let opaque = durable(&mut p, b"an arbitrary alias is not a manifest")?;
    assert!(matches!(
        p.activate_root(opaque, &[child]),
        Err(ProviderError::InvalidRootManifest { root }) if root == opaque
    ));
    p.retire(child, witness)?;
    assert_eq!(p.state(child)?, PublicationState::Retired);
    assert_eq!(p.state(opaque)?, PublicationState::Durable);
    Ok(())
}

#[test]
fn root_body_and_every_child_must_be_durable_without_implicit_advancement() -> TestResult {
    let mut p = provider();
    let child = p.stage(b"unpublished child")?;
    let m = ObjectManifest::new("root-lattice", [child], None)?;
    let root = p.stage(&m.try_canonical_bytes()?)?;
    for state in [PublicationState::Staged, PublicationState::Visible] {
        assert!(matches!(
            p.activate_root(root, &[child]),
            Err(ProviderError::RootNotDurable { root: r, state: s })
                if r == root && s == state
        ));
        assert_eq!(p.state(root)?, state);
        if state == PublicationState::Staged {
            p.advance(root, PublicationState::Visible)?;
        }
    }
    p.advance(root, PublicationState::Durable)?;
    for state in [PublicationState::Staged, PublicationState::Visible] {
        assert!(matches!(
            p.activate_root(root, &[child]),
            Err(ProviderError::RootBeforeDurableChildren {
                root: r,
                child: c,
                child_state: s,
            }) if r == root && c == child && s == state
        ));
        assert_eq!(p.state(child)?, state);
        if state == PublicationState::Staged {
            assert!(p.verify_retrievable(child, TimestampNs(1)).is_err());
            p.advance(child, PublicationState::Visible)?;
        }
    }
    p.advance(child, PublicationState::Durable)?;
    p.activate_root(root, &[child])?;
    assert_eq!(
        p.verify_retrievable(root, TimestampNs(2))?.state,
        PublicationState::Durable
    );
    Ok(())
}

#[test]
fn exact_child_binding_includes_metadata_and_survives_deactivation() -> TestResult {
    let mut p = provider();
    let source = durable(&mut p, b"source")?;
    let metadata = durable(&mut p, b"provenance")?;
    let extra = durable(&mut p, b"not in the graph")?;
    let witness = durable(&mut p, b"deletion witness")?;
    let m = manifest(&mut p, "metadata-root", &[source], Some(metadata))?;
    let root = m.root();
    for children in [
        vec![source],
        vec![metadata],
        vec![source, metadata, extra],
        vec![source, metadata, metadata],
        vec![root],
    ] {
        assert!(matches!(
            p.activate_root(root, &children),
            Err(ProviderError::RootChildrenMismatch { root: r }) if r == root
        ));
    }
    assert!(matches!(
        p.activate_root(root, &vec![source; MAX_MANIFEST_CHILDREN + 1]),
        Err(ProviderError::RootChildrenMismatch { root: r }) if r == root
    ));
    p.activate_root(root, &[source, metadata])?;
    p.activate_root(root, &[metadata, source])?;
    // An attempted extension must not pin the extra child or mutate the original binding.
    assert!(p.activate_root(root, &[source, metadata, extra]).is_err());
    p.retire(extra, witness)?;
    assert!(matches!(
        p.retire(metadata, witness),
        Err(ProviderError::ActiveRootReference { .. })
    ));
    p.deactivate_root(root)?;
    assert!(matches!(
        p.activate_root(root, &[source]),
        Err(ProviderError::RootChildrenMismatch { .. })
    ));
    p.activate_root(root, m.children())?;
    assert!(matches!(
        p.retire(metadata, witness),
        Err(ProviderError::ActiveRootReference { .. })
    ));
    Ok(())
}

#[test]
fn active_manifest_body_is_pinned_and_retired_roots_cannot_reactivate() -> TestResult {
    let mut p = provider();
    let child = durable(&mut p, b"root-pinned-child")?;
    let witness = durable(&mut p, b"root-pinned-witness")?;
    let m = manifest(&mut p, "body-pinning", &[child], None)?;
    p.activate_root(m.root(), m.children())?;
    assert!(matches!(
        p.retire(m.root(), witness),
        Err(ProviderError::ActiveRootReference { digest, root })
            if digest == m.root() && root == m.root()
    ));
    assert_eq!(p.state(m.root())?, PublicationState::Durable);
    assert!(p.verify_retrievable(m.root(), TimestampNs(1)).is_ok());
    p.deactivate_root(m.root())?;
    p.retire(m.root(), witness)?;
    assert!(matches!(
        p.activate_root(m.root(), m.children()),
        Err(ProviderError::RootNotDurable { state: PublicationState::Retired, .. })
    ));
    assert!(p.stage(&m.try_canonical_bytes()?).is_err());
    p.retire(child, witness)?;
    Ok(())
}

#[test]
fn inactive_nested_manifest_cannot_hide_an_active_ancestors_pins() -> TestResult {
    let mut p = provider();
    let leaf = durable(&mut p, b"nested source")?;
    let witness = durable(&mut p, b"nested witness")?;
    let inner = manifest(&mut p, "inner", &[leaf], None)?;
    p.activate_root(inner.root(), inner.children())?;
    p.deactivate_root(inner.root())?;
    let outer = manifest(&mut p, "outer", &[inner.root()], None)?;
    p.activate_root(outer.root(), outer.children())?;
    for digest in [leaf, inner.root(), outer.root()] {
        assert!(matches!(
            p.retire(digest, witness),
            Err(ProviderError::ActiveRootReference { digest: d, root })
                if d == digest && root == outer.root()
        ));
        assert_eq!(p.state(digest)?, PublicationState::Durable);
    }
    p.deactivate_root(outer.root())?;
    p.retire(leaf, witness)?;
    assert!(matches!(
        p.activate_root(outer.root(), outer.children()),
        Err(ProviderError::RootBeforeDurableChildren {
            child,
            child_state: PublicationState::Retired,
            ..
        }) if child == leaf
    ));
    // A different wrapper cannot launder the known invalid graph into an opaque object.
    let wrapper = manifest(&mut p, "new-wrapper", &[inner.root()], None)?;
    assert!(matches!(
        p.activate_root(wrapper.root(), wrapper.children()),
        Err(ProviderError::RootBeforeDurableChildren {
            child,
            child_state: PublicationState::Retired,
            ..
        }) if child == leaf
    ));
    Ok(())
}

#[test]
fn shared_descendants_stay_pinned_until_every_ancestor_is_inactive() -> TestResult {
    let mut p = provider();
    let leaf = durable(&mut p, b"shared source")?;
    let witness = durable(&mut p, b"shared witness")?;
    let inner = manifest(&mut p, "shared-inner", &[leaf], None)?;
    p.activate_root(inner.root(), inner.children())?;
    let first = manifest(&mut p, "first-parent", &[inner.root()], None)?;
    let second = manifest(&mut p, "second-parent", &[inner.root()], None)?;
    for m in [&first, &second] {
        p.activate_root(m.root(), m.children())?;
    }
    p.deactivate_root(inner.root())?;
    p.deactivate_root(first.root())?;
    assert!(matches!(
        p.retire(leaf, witness),
        Err(ProviderError::ActiveRootReference { root, .. }) if root == second.root()
    ));
    p.deactivate_root(second.root())?;
    p.retire(leaf, witness)?;
    Ok(())
}

#[test]
fn late_manifest_activation_adds_verified_semantics_without_sniffing_opaque_bytes() -> TestResult {
    let mut p = provider();
    let leaf = p.stage(b"late source")?;
    let witness = durable(&mut p, b"late witness")?;
    let inner = manifest(&mut p, "late-inner", &[leaf], None)?;
    let outer = manifest(&mut p, "late-outer", &[inner.root()], None)?;
    // The inner object has never been activated, so its bytes remain an opaque durable child.
    p.activate_root(outer.root(), outer.children())?;
    assert!(matches!(
        p.activate_root(inner.root(), inner.children()),
        Err(ProviderError::RootBeforeDurableChildren {
            child_state: PublicationState::Staged,
            ..
        })
    ));
    p.advance(leaf, PublicationState::Visible)?;
    p.advance(leaf, PublicationState::Durable)?;
    p.activate_root(inner.root(), inner.children())?;
    p.deactivate_root(inner.root())?;
    // Once explicitly registered, the nested binding remains traversable from the outer root.
    assert!(matches!(
        p.retire(leaf, witness),
        Err(ProviderError::ActiveRootReference { root, .. }) if root == outer.root()
    ));
    Ok(())
}

#[test]
fn unregistered_custody_retirement_refuses_before_deleting_bytes() -> TestResult {
    let mut custody = InMemoryObjectStore::new(ObjectLimits::new(8, 1024));
    let target = custody.put_verified(b"pre-existing bytes")?;
    let witness = custody.put_verified(b"pre-existing deletion record")?;
    let mut p = InMemoryObjectStoreProvider::new(custody, 1);
    assert!(matches!(
        p.retire(target, witness),
        Err(ProviderError::UnknownObject(d)) if d == target
    ));
    assert_eq!(p.object_count(), 0);
    assert_eq!(p.stage(b"pre-existing bytes")?, target);
    assert_eq!(p.state(target)?, PublicationState::Staged);
    Ok(())
}

#[test]
fn invalid_witness_cannot_make_staged_bytes_readable() -> TestResult {
    let mut p = provider();
    let target = p.stage(b"private staged bytes")?;
    let witness = p.stage(b"unverified deletion witness")?;
    for invalid in [witness, ContentDigest::sha256(b"absent witness"), target] {
        assert!(p.retire(target, invalid).is_err());
        assert_eq!(p.state(target)?, PublicationState::Staged);
        assert!(p.verify_retrievable(target, TimestampNs(1)).is_err());
        assert_eq!(p.stage(b"private staged bytes")?, target);
    }
    p.advance(witness, PublicationState::Visible)?;
    p.retire(target, witness)?;
    assert_eq!(p.state(target)?, PublicationState::Retired);
    Ok(())
}

#[test]
fn preverified_custody_never_bypasses_the_provider_visibility_gate() -> TestResult {
    let mut custody = InMemoryObjectStore::new(ObjectLimits::new(8, 1024));
    let digest = custody.put_verified(b"already verified")?;
    let mut p = InMemoryObjectStoreProvider::new(custody, 1);
    assert!(p.verify_retrievable(digest, TimestampNs(1)).is_err());
    assert_eq!(p.stage(b"already verified")?, digest);
    assert!(p.verify_retrievable(digest, TimestampNs(2)).is_err());
    p.advance(digest, PublicationState::Visible)?;
    assert_eq!(
        p.verify_retrievable(digest, TimestampNs(3))?.state,
        PublicationState::Visible
    );
    Ok(())
}

#[test]
fn deletion_witness_cannot_delete_itself() -> TestResult {
    let mut p = provider();
    let digest = durable(&mut p, b"cannot be my own surviving deletion witness")?;
    assert!(p.retire(digest, digest).is_err());
    assert_eq!(
        p.verify_retrievable(digest, TimestampNs(1))?.state,
        PublicationState::Durable
    );
    Ok(())
}
