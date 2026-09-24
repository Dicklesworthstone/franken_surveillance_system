#![forbid(unsafe_code)]
//! Twin import contracts: neutral package admission, limits, and digest binding.
use fss_core::ContentDigest;
use fss_geometry::{GeometryBasis, Ray, WorkBudget};
use fss_twin::{
    ImportExpectation, ImportLimits, ScaleEvidence, SurfaceKind, TwinError, import_twin,
};
use std::sync::atomic::AtomicBool;

fn text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}
fn fixture() -> Vec<u8> {
    let mut b = vec![1; 32];
    text(&mut b, "synthetic/Z-up/frame=0");
    text(&mut b, "synthetic");
    b.push(0);
    for n in [0.0f64, -1.0, -1.0] {
        b.extend_from_slice(&n.to_le_bytes());
    }
    for n in [1u32, 1, 4, 2] {
        b.extend_from_slice(&n.to_le_bytes());
    }
    text(&mut b, "walk");
    b.push(1);
    text(&mut b, "ground");
    b.extend_from_slice(&[0; 4]);
    b.extend_from_slice(&[1, 1]);
    for p in [
        [0.0f64, 0.0, 0.0],
        [4.0, 0.0, 0.0],
        [4.0, 4.0, 0.0],
        [0.0, 4.0, 0.0],
    ] {
        for n in p {
            b.extend_from_slice(&n.to_le_bytes());
        }
    }
    for n in [0u32, 1, 2, 0, 0, 2, 3, 0] {
        b.extend_from_slice(&n.to_le_bytes());
    }
    let mut out = b"FSSTWIN1".to_vec();
    out.extend_from_slice(&(b.len() as u64).to_le_bytes());
    out.extend_from_slice(&b);
    out.extend_from_slice(&ContentDigest::sha256(&out).bytes());
    out
}
fn expectation(bytes: &[u8]) -> Result<ImportExpectation, Box<dyn std::error::Error>> {
    Ok(ImportExpectation {
        package_sha256: ContentDigest::sha256(bytes).bytes(),
        source_scene_sha256: [1; 32],
        basis: GeometryBasis::new(1, 1)?,
    })
}
fn reseal(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let digest = ContentDigest::sha256(&bytes[..end]).bytes();
    bytes[end..].copy_from_slice(&digest);
}

#[test]
fn imports_cross_language_golden_and_preserves_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let b = fixture();
    assert_eq!(
        ContentDigest::sha256(&b).to_text(),
        "sha256:1d997fa681292b2eac58f73be61ca31c76bbf1e15f3af46c2ddf033ad9782c24"
    );
    let expected = expectation(&b)?;
    let twin = import_twin(
        &b,
        expected,
        ImportLimits::default(),
        &mut WorkBudget::new(100_000),
    )?;
    assert_eq!(twin.scale(), ScaleEvidence::Relative);
    assert_eq!(twin.geometry_error(), None);
    assert_eq!(twin.features()[0].surface, SurfaceKind::PedestrianPath);
    let (object, feature) = twin.triangle_identity(1).ok_or("identity missing")?;
    assert_eq!((&*object.id, &*feature.id), ("ground", "walk"));
    let hits = twin.mesh().support_hits(
        twin.basis(),
        Ray::new([1.0, 2.0, 3.0], [0.0, 0.0, -1.0])?,
        0.0,
        10.0,
        4,
        &mut WorkBudget::new(100),
    )?;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].point, [1.0, 2.0, 0.0]);
    Ok(())
}
#[test]
fn rejects_every_truncation_and_payload_corruption() -> Result<(), Box<dyn std::error::Error>> {
    let b = fixture();
    let expected = expectation(&b)?;
    for cut in 0..b.len() {
        assert!(
            import_twin(
                &b[..cut],
                expected,
                ImportLimits::default(),
                &mut WorkBudget::new(100_000)
            )
            .is_err()
        );
    }
    for i in 0..b.len() {
        let mut bad = b.clone();
        bad[i] ^= 1;
        assert!(
            import_twin(
                &bad,
                expected,
                ImportLimits::default(),
                &mut WorkBudget::new(100_000)
            )
            .is_err()
        );
    }
    Ok(())
}
#[test]
fn checks_source_and_resource_bounds_before_publication() -> Result<(), Box<dyn std::error::Error>>
{
    let b = fixture();
    let mut expected = expectation(&b)?;
    expected.source_scene_sha256 = [2; 32];
    assert_eq!(
        import_twin(
            &b,
            expected,
            ImportLimits::default(),
            &mut WorkBudget::new(100_000)
        )
        .err(),
        Some(TwinError::Basis)
    );
    let expected = expectation(&b)?;
    assert!(
        import_twin(
            &b,
            expected,
            ImportLimits {
                vertices: 3,
                ..ImportLimits::default()
            },
            &mut WorkBudget::new(100_000)
        )
        .is_err()
    );
    assert!(
        import_twin(
            &b,
            expected,
            ImportLimits::default(),
            &mut WorkBudget::new(0)
        )
        .is_err()
    );
    let cancel = AtomicBool::new(true);
    assert!(
        import_twin(
            &b,
            expected,
            ImportLimits::default(),
            &mut WorkBudget::cancellable(100_000, &cancel)
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn rejects_resealed_nonfinite_vertices_and_bad_references() -> Result<(), Box<dyn std::error::Error>>
{
    let original = fixture();
    let vertex_start = original.len() - 32 - 32 - 96;
    for value in [f64::NAN, f64::INFINITY, -0.0, 1e13] {
        let mut b = original.clone();
        b[vertex_start..vertex_start + 8].copy_from_slice(&value.to_le_bytes());
        reseal(&mut b);
        assert!(
            import_twin(
                &b,
                expectation(&b)?,
                ImportLimits::default(),
                &mut WorkBudget::new(100_000)
            )
            .is_err()
        );
    }
    let mut b = original;
    let index = b.len() - 32 - 4;
    b[index..index + 4].copy_from_slice(&1u32.to_le_bytes());
    reseal(&mut b);
    assert_eq!(
        import_twin(
            &b,
            expectation(&b)?,
            ImportLimits::default(),
            &mut WorkBudget::new(100_000)
        )
        .err(),
        Some(TwinError::Reference)
    );
    Ok(())
}
#[test]
fn trailing_bytes_and_huge_declared_lengths_fail() -> Result<(), Box<dyn std::error::Error>> {
    let mut b = fixture();
    b.push(0);
    assert!(
        import_twin(
            &b,
            expectation(&b)?,
            ImportLimits::default(),
            &mut WorkBudget::new(100_000)
        )
        .is_err()
    );
    let mut b = fixture();
    b[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(
        import_twin(
            &b,
            expectation(&b)?,
            ImportLimits::default(),
            &mut WorkBudget::new(100_000)
        )
        .is_err()
    );
    Ok(())
}
