#![forbid(unsafe_code)]
//! FSS-113 property family: bounded H.264 access-unit/SPS/PPS parser.
//! Each property emits one JSONL verdict line.

use fss_packet::access_unit::{AccessUnitAssembler, AccessUnitError, AccessUnitLimits};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-113\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

/// Builds a VCL slice NAL (type 1) whose first_mb_in_slice is `first_mb`.
fn slice(first_mb: u32) -> Vec<u8> {
    // ue(v) encoding: value 0 -> '1'; value k -> (k+1) in binary with
    // (len-1) leading zeros. Header byte 0x41 (nal_ref_idc 2, type 1).
    let mut bits = String::new();
    let code = first_mb + 1;
    let bin = format!("{code:b}");
    for _ in 0..bin.len() - 1 {
        bits.push('0');
    }
    bits.push_str(&bin);
    // Pad to a whole byte with a terminating '1' bit of the next field.
    while bits.len() < 8 {
        bits.push('1');
    }
    let byte = u8::from_str_radix(&bits[..8], 2).map_or(0xFF, |b| b);
    vec![0x41, byte]
}

/// Builds a VCL slice NAL (type 1) with first_mb 0 and pps_id `pps`.
fn slice_with_pps(pps: u32) -> Vec<u8> {
    // ue(0) = '1'; ue(pps): standard encoding.
    let mut bits = String::from("1"); // first_mb = 0
    let code = pps + 1;
    let bin = format!("{code:b}");
    for _ in 0..bin.len() - 1 {
        bits.push('0');
    }
    bits.push_str(&bin);
    while bits.len() < 8 {
        bits.push('1');
    }
    let byte = u8::from_str_radix(&bits[..8], 2).unwrap_or(0xFF);
    vec![0x41, byte]
}

fn nal(kind: u8) -> Vec<u8> {
    // NAL header: forbidden_zero(0) + ref_idc(3) + type(5).
    vec![(kind & 0x1F) | 0x60, 0xFF]
}

/// P1 FIRST-VCL BOUNDARY: a second picture's first slice (first_mb == 0)
/// splits; continuation slices (first_mb > 0) never split.
#[test]
fn p1_first_vcl_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut asm = AccessUnitAssembler::new(AccessUnitLimits::default());
    // Picture 1: first slice (mb 0), then a continuation slice (mb 5).
    assert!(asm.push(&slice(0))?.is_none());
    assert!(asm.push(&slice(5))?.is_none());
    // Picture 2's first slice completes picture 1.
    let done = asm.push(&slice(0))?.ok_or("expected split")?;
    assert_eq!(done.nals.len(), 2);
    assert!(!done.contains_idr);
    // The trailing picture flushes.
    let tail = asm.flush().ok_or("tail missing")?;
    assert_eq!(tail.nals.len(), 1);
    assert_eq!(asm.emitted(), 2);
    emit("first-vcl-boundary", 4);
    Ok(())
}

/// P2 AUD + PARAMETER-SET BOUNDARIES: AUD always splits; SPS/PPS after
/// VCL data split (parameter sets belong to the NEXT picture).
#[test]
fn p2_aud_and_param_set_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let mut asm = AccessUnitAssembler::new(AccessUnitLimits::default());
    asm.push(&slice(0))?;
    asm.push(&nal(6))?; // SEI attaches
    assert!(asm.push(&nal(7))?.is_some(), "SPS after VCL splits");
    asm.push(&nal(8))?; // PPS attaches to the (empty) next unit
    asm.push(&slice(0))?;
    let aud_split = asm.push(&nal(9))?.is_some();
    assert!(aud_split, "AUD always splits");
    emit("aud-param-boundaries", 5);
    Ok(())
}

/// P3 IDR + PARAMETER-SET IDS: IDR slices mark the access unit; SPS/PPS
/// ids are parsed and deduplicated.
#[test]
fn p3_idr_and_parameter_ids() -> Result<(), Box<dyn std::error::Error>> {
    let mut asm = AccessUnitAssembler::new(AccessUnitLimits::default());
    asm.push(&nal(7))?; // SPS id 0 prefix (ue(0)='1')
    asm.push(&vec![0xE8, 0xC0])?; // PPS: ue(0) ue(0) -> pps 0 referencing sps 0
    asm.push(&vec![0x65, 0xFF])?; // IDR slice (type 5), first_mb 0
    let au = asm
        .push(&slice_with_pps(3))?
        .ok_or("slice after IDR splits the picture")?;
    assert!(au.contains_idr);
    assert_eq!(au.sps_ids, [0]);
    assert_eq!(
        au.pps_ids,
        vec![0],
        "pps 0 from the PPS NAL and the IDR slice header"
    );
    // The splitting slice's pps 3 belongs to the NEXT picture.
    let tail = asm.flush().ok_or("tail")?;
    assert_eq!(tail.pps_ids, [3]);
    emit("idr-parameter-ids", 3);
    Ok(())
}

/// P4 BUDGETS: NAL-count and byte budgets refuse with typed errors.
#[test]
fn p4_budgets() -> Result<(), Box<dyn std::error::Error>> {
    let mut asm = AccessUnitAssembler::new(AccessUnitLimits {
        max_nals: 2,
        max_bytes: 4,
    });
    asm.push(&slice(0))?;
    asm.push(&slice(5))?;
    assert_eq!(
        asm.push(&slice(5)),
        Err(AccessUnitError::TooManyNals { maximum: 2 })
    );
    let mut tiny = AccessUnitAssembler::new(AccessUnitLimits {
        max_nals: 10,
        max_bytes: 3,
    });
    assert_eq!(
        tiny.push(&[0x41, 0xFF, 0xFF, 0xFF]),
        Err(AccessUnitError::TooManyBytes { maximum: 3 })
    );
    emit("budgets", 2);
    Ok(())
}

/// P5 DETERMINISM: identical streams assemble identically.
#[test]
fn p5_determinism() -> Result<(), Box<dyn std::error::Error>> {
    let stream = || {
        vec![
            nal(7),
            nal(8),
            slice(0),
            slice(5),
            slice(0),
            nal(9),
            vec![0x65, 0xFF],
        ]
    };
    let mut a = AccessUnitAssembler::new(AccessUnitLimits::default());
    let mut b = AccessUnitAssembler::new(AccessUnitLimits::default());
    let mut aus_a = Vec::new();
    let mut aus_b = Vec::new();
    for nal in stream() {
        if let Some(au) = a.push(&nal)? {
            aus_a.push(au);
        }
        if let Some(au) = b.push(&nal)? {
            aus_b.push(au);
        }
    }
    aus_a.push(a.flush().ok_or("a tail")?);
    aus_b.push(b.flush().ok_or("b tail")?);
    assert_eq!(aus_a, aus_b);
    assert_eq!(
        aus_a.len(),
        3,
        "SPS+PPS+2-slice picture, AUD-separated single-slice picture, IDR picture"
    );
    emit("determinism", 2);
    Ok(())
}
