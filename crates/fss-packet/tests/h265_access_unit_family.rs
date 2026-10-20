#![forbid(unsafe_code)]
//! FSS-114 property family: bounded H.265 access-unit/VPS/SPS/PPS parser.
//! Each property emits one JSONL verdict line.

use fss_packet::h265_access_unit::{
    H265AccessUnitAssembler, H265AccessUnitError, H265AccessUnitLimits,
};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-114\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

/// Builds one NAL: 2-byte header encoding `kind`, then the slice-segment
/// payload byte whose MSB is `first_slice`.
fn nal(kind: u8, first_slice: bool) -> Vec<u8> {
    // Header: forbidden_zero(1) + type(6) + layer(6, 0) + tid(3, 1).
    let h0 = ((kind as u16) << 1) >> 1; // type in bits 1..6
    let h0 = ((kind & 0x3F) << 1) as u8;
    vec![h0, 0x01, if first_slice { 0x80 } else { 0x00 }, 0xFF]
}

fn simple_nal(kind: u8) -> Vec<u8> {
    let h0 = ((kind & 0x3F) << 1) as u8;
    vec![h0, 0x01, 0xFF]
}

/// P1 FIRST-SLICE-SEGMENT BOUNDARY: a VCL NAL with the picture-start bit
/// splits; continuation segments (bit clear) never split.
#[test]
fn p1_first_slice_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut asm = H265AccessUnitAssembler::new(H265AccessUnitLimits::default());
    asm.push(&nal(1, true))?; // first slice of picture 1
    assert!(asm.push(&nal(1, false))?.is_none(), "continuation attaches");
    let done = asm
        .push(&nal(1, true))?
        .ok_or("picture-start bit must split")?;
    assert_eq!(done.nals.len(), 2);
    assert!(!done.contains_idr && !done.contains_cra);
    let tail = asm.flush().ok_or("tail")?;
    assert_eq!(tail.nals.len(), 1);
    assert_eq!(asm.emitted(), 2);
    emit("first-slice-boundary", 4);
    Ok(())
}

/// P2 AUD + PARAMETER-SET BOUNDARIES: AUD always splits; VPS/SPS/PPS
/// after VCL data split (parameter sets belong to the NEXT picture).
#[test]
fn p2_aud_and_param_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let mut asm = H265AccessUnitAssembler::new(H265AccessUnitLimits::default());
    asm.push(&nal(1, true))?;
    asm.push(&simple_nal(39))?; // SEI attaches
    assert!(asm.push(&simple_nal(33))?.is_some(), "SPS after VCL splits");
    asm.push(&simple_nal(34))?; // PPS attaches to the next unit
    asm.push(&simple_nal(32))?; // VPS attaches (no VCL yet since split)
    asm.push(&nal(1, true))?;
    let split = asm.push(&simple_nal(35))?.ok_or("AUD always splits")?;
    assert!(
        split.has_vps && split.has_sps && split.has_pps,
        "parameter sets stay with the picture they precede"
    );
    let tail = asm.flush().ok_or("tail")?;
    assert_eq!(tail.nals.len(), 1, "tail is the AUD alone");
    emit("aud-param-boundaries", 6);
    Ok(())
}

/// P3 IDR + CRA MARKING: types 19/20 mark IDR; type 21 marks CRA; both
/// distinct from an ordinary trailing picture.
#[test]
fn p3_idr_cra_marking() -> Result<(), Box<dyn std::error::Error>> {
    let mut asm = H265AccessUnitAssembler::new(H265AccessUnitLimits::default());
    asm.push(&simple_nal(32))?;
    asm.push(&simple_nal(33))?;
    asm.push(&simple_nal(34))?;
    asm.push(&nal(19, true))?; // IDR_W_RADL
    asm.push(&nal(19, false))?;
    let idr = asm
        .push(&nal(21, true))?
        .ok_or("CRA picture-start splits")?;
    assert!(idr.contains_idr);
    assert!(!idr.contains_cra);
    assert!(idr.has_vps && idr.has_sps && idr.has_pps);
    let cra = asm.push(&nal(1, true))?.ok_or("ordinary picture splits")?;
    assert!(cra.contains_cra);
    assert!(!cra.contains_idr);
    let plain = asm.flush().ok_or("tail")?;
    assert!(!plain.contains_idr && !plain.contains_cra);
    emit("idr-cra-marking", 5);
    Ok(())
}

/// P4 BUDGETS + HEADER: truncated headers, NAL-count and byte budgets are
/// typed refusals, and refusals are atomic (a completed AU is never
/// discarded; state survives).
#[test]
fn p4_budgets_and_atomicity() -> Result<(), Box<dyn std::error::Error>> {
    let mut asm = H265AccessUnitAssembler::new(H265AccessUnitLimits {
        max_nals: 2,
        max_bytes: 1_000,
    });
    assert_eq!(asm.push(&[0x26]), Err(H265AccessUnitError::TruncatedHeader));
    asm.push(&nal(1, true))?;
    asm.push(&nal(1, false))?;
    let done = asm.push(&nal(1, true))?.ok_or("split completes the AU")?;
    assert_eq!(done.nals.len(), 2);
    // Single over-budget NAL refused before any state change.
    let huge = vec![0x02u8; 2_000];
    assert!(matches!(
        asm.push(&huge),
        Err(H265AccessUnitError::TooManyBytes { maximum: 1_000 })
    ));
    let tail = asm.flush().ok_or("current AU survives")?;
    assert_eq!(tail.nals.len(), 1);
    emit("budgets-atomicity", 4);
    Ok(())
}

/// P5 DETERMINISM: identical streams assemble identically.
#[test]
fn p5_determinism() -> Result<(), Box<dyn std::error::Error>> {
    let stream = || {
        vec![
            simple_nal(32),
            simple_nal(33),
            simple_nal(34),
            nal(19, true),
            nal(19, false),
            simple_nal(35),
            nal(1, true),
        ]
    };
    let mut a = H265AccessUnitAssembler::new(H265AccessUnitLimits::default());
    let mut b = H265AccessUnitAssembler::new(H265AccessUnitLimits::default());
    let mut aus_a = Vec::new();
    let mut aus_b = Vec::new();
    for n in stream() {
        if let Some(au) = a.push(&n)? {
            aus_a.push(au);
        }
        if let Some(au) = b.push(&n)? {
            aus_b.push(au);
        }
    }
    aus_a.push(a.flush().ok_or("a tail")?);
    aus_b.push(b.flush().ok_or("b tail")?);
    assert_eq!(aus_a, aus_b);
    assert_eq!(
        aus_a.len(),
        2,
        "VPS/SPS/PPS+IDR picture, then AUD-headed trailing picture"
    );
    assert!(aus_a[0].contains_idr);
    assert!(!aus_a[1].contains_idr);
    emit("determinism", 2);
    Ok(())
}
