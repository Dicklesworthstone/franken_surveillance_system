#![forbid(unsafe_code)]
//! Atlas archive contracts: packaged localization atlas staging and recovery.
mod common;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::{
    PropertyTwin,
    atlas_archive::{
        ArchiveError, ArchiveExpectation, ReferenceProvenance, decode_atlas, encode_atlas,
    },
    localization::{
        AtlasBinding, AtlasLandmark, AtlasReference, BinaryDescriptor, FeatureFrame, ImageFeature,
        ImageIdentity, LocalizationAtlas, LocalizationError, MatchOptions,
    },
};
use std::sync::atomic::AtomicBool;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn budget() -> WorkBudget<'static> {
    WorkBudget::new(100_000_000)
}
fn atlas(twin: &PropertyTwin) -> Result<LocalizationAtlas, Box<dyn std::error::Error>> {
    let points = vec![
        AtlasLandmark {
            id: 3,
            physical_group: 103,
            feature: 0,
            world: [0.0, 1.0, 2.0],
            evidence: [8; 32],
            error: None,
        },
        AtlasLandmark {
            id: 9,
            physical_group: 109,
            feature: 0,
            world: [1.0, 2.0, 3.0],
            evidence: [9; 32],
            error: Some([0.0, 0.2, 0.3]),
        },
    ];
    let frame = FeatureFrame::new(
        ImageIdentity {
            exposure: [2; 32],
            pixels: [3; 32],
            image_domain: [4; 32],
            dimensions: [128, 96],
        },
        [5; 32],
        vec![
            ImageFeature {
                id: 7,
                pixel: [23.25, 24.5],
                descriptor: BinaryDescriptor([0; 4]),
            },
            ImageFeature {
                id: 8,
                pixel: [80.5, 40.25],
                descriptor: BinaryDescriptor([u64::MAX; 4]),
            },
        ],
        &mut budget(),
    )?;
    Ok(LocalizationAtlas::new(
        twin,
        points,
        vec![AtlasReference { id: 6, frame }],
        vec![
            AtlasBinding {
                landmark: 3,
                reference: 6,
                image_feature: 7,
            },
            AtlasBinding {
                landmark: 9,
                reference: 6,
                image_feature: 8,
            },
        ],
        &mut budget(),
    )?)
}
fn sources() -> [ReferenceProvenance; 1] {
    [ReferenceProvenance {
        reference: 6,
        source_record: [10; 32],
        allowed_mask: [11; 32],
    }]
}
fn expectation(bytes: &[u8]) -> ArchiveExpectation {
    ArchiveExpectation {
        package: ContentDigest::sha256(bytes).bytes(),
        provenance: [12; 32],
        descriptor: [5; 32],
    }
}
fn reseal(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let hash = ContentDigest::sha256(&bytes[..end]).bytes();
    bytes[end..].copy_from_slice(&hash);
}

#[test]
fn reload_preserves_matching_lineage_and_unknown_errors() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let original = atlas(&twin)?;
    let bytes = encode_atlas(&original, [12; 32], &sources(), &mut budget())?;
    assert_eq!(bytes.len(), 706);
    assert_eq!(
        ContentDigest::sha256(&bytes).to_text(),
        "sha256:36764662860d5f075820570a1e42c4ff93d3a24763999ed58b3fb64e356812e3"
    );
    let loaded = decode_atlas(&bytes, &twin, expectation(&bytes), &mut budget())?;
    assert_eq!(loaded.atlas().digest(), original.digest());
    assert_eq!(loaded.atlas().landmarks(), original.landmarks());
    assert_eq!(loaded.references(), sources());
    assert_eq!(loaded.atlas().landmarks()[0].error, None);
    assert_eq!(loaded.provenance(), [12; 32]);
    assert_eq!(loaded.package(), expectation(&bytes).package);
    let old = &original.references()[0].frame;
    let mut identity = old.identity();
    identity.exposure = [17; 32];
    let query = FeatureFrame::new(
        identity,
        old.descriptor_domain(),
        old.features().to_vec(),
        &mut budget(),
    )?;
    let a = original.match_frame(&twin, &query, MatchOptions::default(), &mut budget())?;
    let b = loaded
        .atlas()
        .match_frame(&twin, &query, MatchOptions::default(), &mut budget())?;
    assert_eq!(a.correspondences, b.correspondences);
    assert_eq!(a.decisions, b.decisions);
    assert_eq!(
        encode_atlas(loaded.atlas(), [12; 32], loaded.references(), &mut budget())?,
        bytes
    );
    Ok(())
}

#[test]
fn every_truncation_and_bit_mutation_fails() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let bytes = encode_atlas(&atlas(&twin)?, [12; 32], &sources(), &mut budget())?;
    for end in 0..bytes.len() {
        assert!(
            decode_atlas(
                &bytes[..end],
                &twin,
                expectation(&bytes[..end]),
                &mut budget()
            )
            .is_err()
        );
    }
    for index in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[index] ^= 1;
        assert!(decode_atlas(&bad, &twin, expectation(&bad), &mut budget()).is_err());
    }
    Ok(())
}

#[test]
fn independently_pinned_roots_are_required() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let bytes = encode_atlas(&atlas(&twin)?, [12; 32], &sources(), &mut budget())?;
    for mode in 0..3 {
        let mut expected = expectation(&bytes);
        match mode {
            0 => expected.package = [1; 32],
            1 => expected.provenance = [1; 32],
            _ => expected.descriptor = [1; 32],
        }
        assert!(decode_atlas(&bytes, &twin, expected, &mut budget()).is_err());
    }
    let other = common::twin(&[0.1], None)?;
    assert!(matches!(
        decode_atlas(&bytes, &other, expectation(&bytes), &mut budget()),
        Err(ArchiveError::Basis)
    ));
    let mut source = sources();
    source[0].reference += 1;
    assert!(encode_atlas(&atlas(&twin)?, [12; 32], &source, &mut budget()).is_err());
    source = sources();
    source[0].allowed_mask = [0; 32];
    assert!(encode_atlas(&atlas(&twin)?, [12; 32], &source, &mut budget()).is_err());
    Ok(())
}

#[test]
fn resealed_noncanonical_and_semantically_invalid_inputs_fail() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let bytes = encode_atlas(&atlas(&twin)?, [12; 32], &sources(), &mut budget())?;
    let changes: &[(usize, &[u8])] = &[
        (144, &u32::MAX.to_le_bytes()),
        (156, &0_u64.to_le_bytes()),
        (172, &u32::MAX.to_le_bytes()),
        (176, &(-0.0_f64).to_le_bytes()),
        (176, &f64::NAN.to_le_bytes()),
        (80, &[0; 32]),
    ];
    for &(offset, replacement) in changes {
        let mut bad = bytes.clone();
        bad[offset..offset + replacement.len()].copy_from_slice(replacement);
        reseal(&mut bad);
        assert!(decode_atlas(&bad, &twin, expectation(&bad), &mut budget()).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.insert(bytes.len() - 32, 0);
    reseal(&mut trailing);
    assert!(decode_atlas(&trailing, &twin, expectation(&trailing), &mut budget()).is_err());
    Ok(())
}

#[test]
fn cancellation_and_budget_never_yield_partial_archives() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let a = atlas(&twin)?;
    let bytes = encode_atlas(&a, [12; 32], &sources(), &mut budget())?;
    let flag = AtomicBool::new(true);
    for exporting in [false, true] {
        let mut work = WorkBudget::cancellable(100_000_000, &flag);
        let error = if exporting {
            encode_atlas(&a, [12; 32], &sources(), &mut work).err()
        } else {
            decode_atlas(&bytes, &twin, expectation(&bytes), &mut work).err()
        };
        assert_eq!(
            error,
            Some(ArchiveError::Localization(LocalizationError::Geometry(
                GeometryError::Cancelled
            )))
        );
    }
    assert!(decode_atlas(&bytes, &twin, expectation(&bytes), &mut WorkBudget::new(0)).is_err());
    Ok(())
}
