#![forbid(unsafe_code)]
//! FSS-122 property family: scalar image resize/color/normalize
//! reference kernels. Each property emits one JSONL verdict line.

use fss_reference::image_kernels::{
    ImageKernelError, MAX_AXIS, normalize_luma, resize_bilinear_luma, rgb_to_luma,
};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-122\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

/// P1 RESIZE IDENTITY + DETERMINISM: resizing to the same dimensions is
/// the identity (within one rounding step); repeated resizes are
/// byte-identical; axis bounds and buffer mismatch refuse typed.
#[test]
fn p1_resize_identity_and_determinism() -> Result<(), Box<dyn std::error::Error>> {
    let src: Vec<u8> = (0..16u32 * 16).map(|i| (i * 7 % 256) as u8).collect();
    let identity = resize_bilinear_luma(&src, 16, 16, 16, 16)?;
    assert_eq!(identity.len(), 256);
    // Every pixel differs from its source by at most one rounding step.
    for (a, b) in identity.iter().zip(src.iter()) {
        let diff = i16::from(*a) - i16::from(*b);
        assert!(diff.abs() <= 1, "identity resize stays within rounding");
    }
    let again = resize_bilinear_luma(&src, 16, 16, 16, 16)?;
    assert_eq!(identity, again, "deterministic");
    // Bounds.
    assert!(matches!(
        resize_bilinear_luma(&src, 16, 16, MAX_AXIS + 1, 8),
        Err(ImageKernelError::EmptyTarget)
    ));
    assert!(matches!(
        resize_bilinear_luma(&src[..10], 16, 16, 8, 8),
        Err(ImageKernelError::BufferMismatch { .. })
    ));
    assert!(matches!(
        resize_bilinear_luma(&src, 0, 16, 8, 8),
        Err(ImageKernelError::InvalidDimension { .. })
    ));
    emit("resize-identity-determinism", 6);
    Ok(())
}

/// P2 RESIZE GEOMETRY: downscale and upscale produce exact target sizes;
/// a constant source resizes to exactly that constant (area weighting is
/// conservative).
#[test]
fn p2_resize_geometry() -> Result<(), Box<dyn std::error::Error>> {
    let const_src = vec![137u8; 32 * 32];
    for &(w, h) in &[(8usize, 8), (64, 64), (5, 17), (100, 3)] {
        let out = resize_bilinear_luma(&const_src, 32, 32, w, h)?;
        assert_eq!(out.len(), w * h);
        assert!(
            out.iter().all(|&v| v == 137),
            "constant source stays constant at {w}x{h}"
        );
    }
    emit("resize-geometry", 4);
    Ok(())
}

/// P3 LUMA CONVERSION: BT.601 integer constants — primary channels land
/// in their expected bands; pure gray maps to itself; buffer length
/// discipline refuses.
#[test]
fn p3_rgb_to_luma() -> Result<(), Box<dyn std::error::Error>> {
    let luma = rgb_to_luma(&[255, 0, 0, 0, 255, 0, 0, 0, 255, 128, 128, 128])?;
    assert_eq!(luma.len(), 4);
    assert!((60..=90).contains(&luma[0]), "red -> ~76, got {}", luma[0]);
    assert!(
        (135..=165).contains(&luma[1]),
        "green -> ~150, got {}",
        luma[1]
    );
    assert!((15..=40).contains(&luma[2]), "blue -> ~29, got {}", luma[2]);
    assert_eq!(luma[3], 128, "gray maps to itself");
    assert!(matches!(
        rgb_to_luma(&[1, 2]),
        Err(ImageKernelError::BufferMismatch { .. })
    ));
    emit("rgb-to-luma", 4);
    Ok(())
}

/// P4 NORMALIZE: full-range stretch; constant image maps to the stated
/// fill (never divide-by-zero, never invented gradient); determinism.
#[test]
fn p4_normalize() -> Result<(), Box<dyn std::error::Error>> {
    let src = [10u8, 20, 30, 40, 50, 60, 70, 80, 90];
    let out = normalize_luma(&src, 3, 3, 128)?;
    assert_eq!(out[0], 0, "min maps to 0");
    assert_eq!(out[8], 255, "max maps to 255");
    assert!(out[0] <= out[1] && out[1] <= out[2], "monotone preserved");
    // Constant image.
    let flat = vec![77u8; 16];
    let filled = normalize_luma(&flat, 4, 4, 128)?;
    assert!(filled.iter().all(|&v| v == 128));
    // Determinism.
    let again = normalize_luma(&src, 3, 3, 128)?;
    assert_eq!(out, again);
    // Bounds.
    assert!(matches!(
        normalize_luma(&src[..4], 3, 3, 0),
        Err(ImageKernelError::BufferMismatch { .. })
    ));
    emit("normalize", 4);
    Ok(())
}

/// P5 NO-FLOAT DETERMINISM ACROSS VALUES: a gradient plane normalizes
/// with exact expected endpoints for every width/height combination in
/// the sweep (fixed-point path exercised broadly).
#[test]
fn p5_gradient_sweep() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    for &w in &[1usize, 2, 3, 7, 16, 33] {
        for &h in &[1usize, 2, 5, 16] {
            let n = w * h;
            let plane: Vec<u8> = (0..n).map(|i| (i * 255 / n.max(1)) as u8).collect();
            let out = normalize_luma(&plane, w, h, 128)?;
            if n > 1 {
                assert_eq!(out[0], 0);
                assert_eq!(out[n - 1], 255);
            }
            cases += 1;
        }
    }
    emit("gradient-sweep", cases);
    Ok(())
}
