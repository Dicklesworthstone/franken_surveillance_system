#![forbid(unsafe_code)]
//! Bounded hostile input and unchanged canonical identities at the manifest boundary.

use std::cell::Cell;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest};
use fss_object::{MAX_MANIFEST_CHILDREN, ObjectError, ObjectManifest};

fn digest(index: usize) -> ContentDigest {
    ContentDigest::sha256(&(index as u64).to_be_bytes())
}

#[test]
fn infinite_input_stops_at_the_first_excess_child() {
    let inspected = Cell::new(0_usize);
    let source = std::iter::repeat(digest(0)).inspect(|_| {
        inspected.set(inspected.get() + 1);
    });
    assert!(matches!(
        ObjectManifest::new("bounded", source, None),
        Err(ObjectError::ManifestChildren { count, maximum })
            if count == MAX_MANIFEST_CHILDREN + 1 && maximum == MAX_MANIFEST_CHILDREN
    ));
    assert_eq!(inspected.get(), MAX_MANIFEST_CHILDREN + 1);
}

#[test]
fn metadata_consumes_one_child_slot_before_input_admission() {
    let inspected = Cell::new(0_usize);
    let source = std::iter::repeat(digest(0)).inspect(|_| {
        inspected.set(inspected.get() + 1);
    });
    assert!(matches!(
        ObjectManifest::new("bounded", source, Some(digest(1))),
        Err(ObjectError::ManifestChildren { count, maximum })
            if count == MAX_MANIFEST_CHILDREN + 1 && maximum == MAX_MANIFEST_CHILDREN
    ));
    assert_eq!(inspected.get(), MAX_MANIFEST_CHILDREN);
}

#[test]
fn invalid_kind_never_polls_the_source() {
    let inspected = Cell::new(0_usize);
    let source = std::iter::repeat(digest(0)).inspect(|_| {
        inspected.set(inspected.get() + 1);
    });
    assert!(matches!(
        ObjectManifest::new("", source, None),
        Err(ObjectError::InvalidManifestKind)
    ));
    assert_eq!(inspected.get(), 0);
}

struct MisleadingSizeHint {
    value: Option<ContentDigest>,
}

impl Iterator for MisleadingSizeHint {
    type Item = ContentDigest;

    fn next(&mut self) -> Option<Self::Item> {
        self.value.take()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // A safe Iterator implementation can lie. Manifest admission must not use this
        // unchecked hint to reserve memory or confuse it with observed input cardinality.
        (usize::MAX, Some(usize::MAX))
    }
}

#[test]
fn iterator_size_hint_is_not_allocation_authority() -> Result<(), ObjectError> {
    let child = digest(7);
    let manifest = ObjectManifest::new(
        "bounded",
        MisleadingSizeHint { value: Some(child) },
        None,
    )?;
    assert_eq!(manifest.children(), &[child]);
    Ok(())
}

#[test]
fn exact_child_ceiling_is_admitted_with_and_without_metadata() -> Result<(), ObjectError> {
    for with_metadata in [false, true] {
        let count = MAX_MANIFEST_CHILDREN - usize::from(with_metadata);
        let metadata = with_metadata.then(|| digest(MAX_MANIFEST_CHILDREN));
        let manifest = ObjectManifest::new("ceiling", (0..count).map(digest), metadata)?;
        assert_eq!(manifest.children().len(), MAX_MANIFEST_CHILDREN);
        assert_eq!(manifest.metadata_digest(), metadata);
        assert_eq!(
            ObjectManifest::from_canonical_bytes(&manifest.canonical_bytes())?,
            manifest
        );
    }
    Ok(())
}

#[test]
fn duplicate_children_and_metadata_are_still_refused() {
    let child = digest(0);
    assert!(matches!(
        ObjectManifest::new("bounded", [child, child], None),
        Err(ObjectError::DuplicateChild(value)) if value == child
    ));
    assert!(matches!(
        ObjectManifest::new("bounded", [child], Some(child)),
        Err(ObjectError::DuplicateChild(value)) if value == child
    ));
}

#[test]
fn valid_bytes_match_the_existing_canonical_format() -> Result<(), ObjectError> {
    let metadata = digest(9);
    let mut expected_children = vec![digest(2), digest(1), metadata];
    expected_children.sort_unstable();
    let mut oracle = CanonicalEncoder::new();
    oracle.text("fss.object_manifest.v1");
    oracle.text("same-format");
    oracle.u64(expected_children.len() as u64);
    for child in &expected_children {
        oracle.digest(*child);
    }
    oracle.bool(true);
    oracle.digest(metadata);
    let expected_bytes = oracle.finish();
    for input in [[digest(2), digest(1)], [digest(1), digest(2)]] {
        let manifest = ObjectManifest::new("same-format", input, Some(metadata))?;
        assert_eq!(manifest.canonical_bytes(), expected_bytes);
        assert_eq!(manifest.root(), ContentDigest::sha256(&expected_bytes));
    }
    Ok(())
}

#[test]
fn in_range_count_must_fit_input_before_child_allocation() {
    for count in [1, 2, 127, MAX_MANIFEST_CHILDREN] {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.object_manifest.v1");
        encoder.text("truncated");
        encoder.u64(count as u64);
        let bytes = encoder.finish();
        assert!(matches!(
            ObjectManifest::from_canonical_bytes(&bytes),
            Err(ObjectError::Corrupt(value)) if value == ContentDigest::sha256(&bytes)
        ));
    }
}

#[test]
fn out_of_range_count_keeps_the_typed_bound_refusal() {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.object_manifest.v1");
    encoder.text("oversized");
    encoder.u64((MAX_MANIFEST_CHILDREN + 1) as u64);
    assert!(matches!(
        ObjectManifest::from_canonical_bytes(&encoder.finish()),
        Err(ObjectError::ManifestChildren { count, maximum })
            if count == MAX_MANIFEST_CHILDREN + 1 && maximum == MAX_MANIFEST_CHILDREN
    ));
}

#[test]
fn every_truncation_and_trailing_byte_are_refused() -> Result<(), ObjectError> {
    let manifest = ObjectManifest::new("truncation", [digest(1), digest(2)], Some(digest(3)))?;
    let bytes = manifest.canonical_bytes();
    for end in 0..bytes.len() {
        assert!(ObjectManifest::from_canonical_bytes(&bytes[..end]).is_err());
    }
    let mut extended = bytes;
    extended.push(0);
    assert!(ObjectManifest::from_canonical_bytes(&extended).is_err());
    Ok(())
}
