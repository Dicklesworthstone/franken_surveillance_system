#![forbid(unsafe_code)]
//! Contract tests for bounded H.264 Annex-B elementary-stream splitter.

use std::error::Error;

use fss_reference::{AnnexBError, AnnexBLimits, ReplayCx, SourceSpan, split_annexb};

/// Helper: builds a 4-byte start code AUD NAL (type 9).
fn make_aud_nal() -> Vec<u8> {
    vec![0x00, 0x00, 0x00, 0x01, 0x09, 0x10]
}

/// Helper: builds a 4-byte start code SPS NAL (type 7).
fn make_sps_nal() -> Vec<u8> {
    vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E]
}

/// Helper: builds a 4-byte start code PPS NAL (type 8).
fn make_pps_nal() -> Vec<u8> {
    vec![0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80]
}

/// Helper: encodes unsigned Exp-Golomb `first_mb_in_slice` header into a slice.
fn encode_ue_first_mb(first_mb: u64) -> Vec<u8> {
    match first_mb {
        0 => vec![0x80],
        1 => vec![0x40],
        2 => vec![0x60],
        3 => vec![0x20],
        _ => {
            // General encoding for test vectors
            let mut leading_zeros = 0usize;
            let mut temp = first_mb.saturating_add(1);
            while temp > 1 {
                temp >>= 1;
                leading_zeros = leading_zeros.saturating_add(1);
            }
            let info = first_mb
                .saturating_add(1)
                .saturating_sub(1 << leading_zeros);
            let total_bits = (2 * leading_zeros).saturating_add(1);
            let code = ((1u64 << leading_zeros) | info) << (64 - total_bits);
            let mut out = Vec::new();
            let mut bits_written = 0;
            while bits_written < total_bits {
                let byte = ((code >> (56 - bits_written)) & 0xFF) as u8;
                out.push(byte);
                bits_written = bits_written.saturating_add(8);
            }
            out
        }
    }
}

/// Helper: builds an IDR slice NAL (type 5).
fn make_idr_slice(three_byte_sc: bool, first_mb: u64, extra: &[u8]) -> Vec<u8> {
    let mut v = if three_byte_sc {
        vec![0x00, 0x00, 0x01]
    } else {
        vec![0x00, 0x00, 0x00, 0x01]
    };
    v.push(0x65); // forbidden=0, ref_idc=3, type=5
    v.extend(encode_ue_first_mb(first_mb));
    v.extend_from_slice(extra);
    v
}

/// Helper: builds a non-IDR slice NAL (type 1).
fn make_non_idr_slice(three_byte_sc: bool, first_mb: u64, extra: &[u8]) -> Vec<u8> {
    let mut v = if three_byte_sc {
        vec![0x00, 0x00, 0x01]
    } else {
        vec![0x00, 0x00, 0x00, 0x01]
    };
    v.push(0x41); // forbidden=0, ref_idc=2, type=1
    v.extend(encode_ue_first_mb(first_mb));
    v.extend_from_slice(extra);
    v
}

#[test]
fn test_01_empty_input() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();
    let res = split_annexb(&[], limits, &cx);
    assert_eq!(res, Err(AnnexBError::EmptyInput));
}

#[test]
fn test_02_oversize_input_rejected_before_allocation() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default().with_max_input_bytes(16);
    let bytes = vec![0xAA; 32];
    let res = split_annexb(&bytes, limits, &cx);
    assert_eq!(res, Err(AnnexBError::InputTooLarge { len: 32, max: 16 }));
}

#[test]
fn test_03_no_start_code_found() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();
    let bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
    let res = split_annexb(&bytes, limits, &cx);
    assert_eq!(res, Err(AnnexBError::NoStartCode));
}

#[test]
fn test_04_zero_length_nal_rejected() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    // 3-byte adjacent start codes
    let stream1 = vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x01];
    assert_eq!(
        split_annexb(&stream1, limits, &cx),
        Err(AnnexBError::ZeroLengthNal { offset: 3 })
    );

    // 4-byte adjacent start codes
    let stream2 = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
    assert_eq!(
        split_annexb(&stream2, limits, &cx),
        Err(AnnexBError::ZeroLengthNal { offset: 4 })
    );

    // Only zeros between start codes
    let stream3 = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    assert_eq!(
        split_annexb(&stream3, limits, &cx),
        Err(AnnexBError::ZeroLengthNal { offset: 4 })
    );
}

#[test]
fn test_05_truncated_nal_at_eof() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    // Start code at EOF with zero bytes following
    let stream1 = vec![0x00, 0x00, 0x00, 0x01];
    assert_eq!(
        split_annexb(&stream1, limits, &cx),
        Err(AnnexBError::TruncatedNal { offset: 4 })
    );

    // Start code followed only by zeros at EOF
    let stream2 = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
    assert_eq!(
        split_annexb(&stream2, limits, &cx),
        Err(AnnexBError::TruncatedNal { offset: 4 })
    );
}

#[test]
fn test_06_forbidden_bit_set_rejected() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    // NAL with forbidden_zero_bit = 1 (0x80 | 0x01 = 0x81)
    let stream = vec![0x00, 0x00, 0x00, 0x01, 0x81, 0x80, 0x00];
    assert_eq!(
        split_annexb(&stream, limits, &cx),
        Err(AnnexBError::ForbiddenBitSet { nal: 0, offset: 4 })
    );
}

#[test]
fn test_07_nal_too_large_rejected() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default().with_max_nal_bytes(4);

    let mut stream = vec![0x00, 0x00, 0x00, 0x01];
    stream.extend(vec![0x65, 0x80, 0x01, 0x02, 0x03, 0x04]); // 6 bytes NAL
    assert_eq!(
        split_annexb(&stream, limits, &cx),
        Err(AnnexBError::NalTooLarge {
            offset: 4,
            len: 6,
            max: 4
        })
    );
}

#[test]
fn test_08_too_many_nals_rejected() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default().with_max_nals(2);

    let mut stream = Vec::new();
    stream.extend(make_aud_nal());
    stream.extend(make_sps_nal());
    stream.extend(make_pps_nal());

    assert_eq!(
        split_annexb(&stream, limits, &cx),
        Err(AnnexBError::TooManyNals { count: 3, max: 2 })
    );
}

#[test]
fn test_09_too_many_access_units_rejected() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default().with_max_aus(1);

    let mut stream = Vec::new();
    stream.extend(make_idr_slice(false, 0, &[0x01]));
    stream.extend(make_non_idr_slice(false, 0, &[0x02])); // new AU (first_mb == 0)

    assert_eq!(
        split_annexb(&stream, limits, &cx),
        Err(AnnexBError::TooManyAccessUnits { count: 2, max: 1 })
    );
}

#[test]
fn test_10_leading_garbage_refusal_and_omission() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let mut stream = vec![0xEE, 0xFF]; // 2 bytes non-zero garbage
    stream.extend(make_aud_nal());

    // Default: 0 tolerance for leading garbage -> refusal
    let default_limits = AnnexBLimits::default();
    assert_eq!(
        split_annexb(&stream, default_limits, &cx),
        Err(AnnexBError::LeadingGarbage { len: 2 })
    );

    // Permissive: up to 4 bytes tolerated -> omission span recorded
    let permissive_limits = AnnexBLimits::default().with_max_leading_garbage_bytes(4);
    let scan = split_annexb(&stream, permissive_limits, &cx)?;
    assert_eq!(scan.omission_spans, vec![SourceSpan::new(0, 2)]);
    assert_eq!(scan.nals.len(), 1);
    assert_eq!(scan.nals[0].start_code_span, SourceSpan::new(2, 4));

    Ok(())
}

#[test]
fn test_11_malformed_emulation_prevention() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    // 00 00 03 04 (fourth byte > 3)
    let stream1 = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x80, 0x00, 0x00, 0x03, 0x04];
    assert_eq!(
        split_annexb(&stream1, limits, &cx),
        Err(AnnexBError::MalformedEmulationPrevention { offset: 6 })
    );

    // 00 00 03 at NAL EOF
    let stream2 = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x80, 0x00, 0x00, 0x03];
    assert_eq!(
        split_annexb(&stream2, limits, &cx),
        Err(AnnexBError::MalformedEmulationPrevention { offset: 6 })
    );

    // 00 00 00 unescaped in NAL payload
    let stream3 = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x80, 0x00, 0x00, 0x00, 0x10];
    assert_eq!(
        split_annexb(&stream3, limits, &cx),
        Err(AnnexBError::MalformedEmulationPrevention { offset: 6 })
    );

    // 00 00 02 unescaped in NAL payload
    let stream4 = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x80, 0x00, 0x00, 0x02, 0x10];
    assert_eq!(
        split_annexb(&stream4, limits, &cx),
        Err(AnnexBError::MalformedEmulationPrevention { offset: 6 })
    );
}

#[test]
fn test_12_valid_emulation_prevention_and_start_code_in_payload() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    // Payload contains escaped start code: 00 00 03 01
    // And other valid escapes: 00 00 03 00, 00 00 03 02, 00 00 03 03
    let mut stream = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x80];
    stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x01]); // escaped 00 00 01
    stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x00]); // escaped 00 00 00
    stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x02]); // escaped 00 00 02
    stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x03]); // escaped 00 00 03

    let scan = split_annexb(&stream, limits, &cx)?;
    // Must NOT split on 00 00 03 01
    assert_eq!(scan.nals.len(), 1);
    assert_eq!(scan.nals[0].nal_span.len, 18);
    assert_eq!(scan.nals[0].nal_span.offset, 4);
    assert_eq!(scan.access_units.len(), 1);

    Ok(())
}

#[test]
fn test_13_cooperative_cancellation_and_drain() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();
    let stream = make_aud_nal();

    cx.request_cancellation();
    assert!(cx.is_cancelled());
    let res = split_annexb(&stream, limits, &cx);
    assert_eq!(res, Err(AnnexBError::Cancelled));
    assert!(cx.is_drain_completed());
}

#[test]
fn test_14_two_slice_access_unit() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    let mut stream = Vec::new();
    stream.extend(make_sps_nal());
    stream.extend(make_pps_nal());
    // Slice 0: first_mb = 0
    stream.extend(make_idr_slice(false, 0, &[0xAA]));
    // Slice 1: first_mb = 1 (continuation slice in same AU)
    stream.extend(make_idr_slice(false, 1, &[0xBB]));

    let scan = split_annexb(&stream, limits, &cx)?;
    assert_eq!(scan.nals.len(), 4);
    assert_eq!(scan.access_units.len(), 1);
    let au = &scan.access_units[0];
    assert_eq!(au.slice_count, 2);
    assert_eq!(au.nal_indices, vec![0, 1, 2, 3]);
    assert!(au.is_idr);
    assert!(au.has_sps);
    assert!(au.has_pps);
    assert!(!au.undecodable_without_parameter_sets);

    Ok(())
}

#[test]
fn test_15_aud_and_no_aud_streams() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    // Stream with AUD
    let mut stream_with_aud = Vec::new();
    stream_with_aud.extend(make_aud_nal());
    stream_with_aud.extend(make_sps_nal());
    stream_with_aud.extend(make_pps_nal());
    stream_with_aud.extend(make_idr_slice(false, 0, &[0x11]));

    let scan_aud = split_annexb(&stream_with_aud, limits, &cx)?;
    assert_eq!(scan_aud.access_units.len(), 1);
    assert_eq!(scan_aud.nals.len(), 4);
    assert!(scan_aud.nals[0].is_aud());

    // Stream without AUD
    let mut stream_no_aud = Vec::new();
    stream_no_aud.extend(make_sps_nal());
    stream_no_aud.extend(make_pps_nal());
    stream_no_aud.extend(make_idr_slice(false, 0, &[0x22]));

    let scan_no_aud = split_annexb(&stream_no_aud, limits, &cx)?;
    assert_eq!(scan_no_aud.access_units.len(), 1);
    assert_eq!(scan_no_aud.nals.len(), 3);
    assert!(!scan_no_aud.nals[0].is_aud());
    assert!(scan_no_aud.nals[0].is_sps());

    Ok(())
}

#[test]
fn test_16_trailing_zero_8bits_and_padding_spans() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    let mut stream = Vec::new();
    // NAL 0: AUD (4-byte SC)
    stream.extend(make_aud_nal()); // len 6 (0..6)
    // 3 bytes padding (trailing zeros)
    stream.extend_from_slice(&[0x00, 0x00, 0x00]); // offsets 6..9
    // NAL 1: SPS (4-byte SC)
    stream.extend(make_sps_nal()); // offsets 9..17
    // 2 bytes trailing zeros at EOF
    stream.extend_from_slice(&[0x00, 0x00]); // offsets 17..19

    let scan = split_annexb(&stream, limits, &cx)?;
    assert_eq!(scan.padding_spans.len(), 2);
    assert_eq!(scan.padding_spans[0], SourceSpan::new(6, 3));
    assert_eq!(scan.padding_spans[1], SourceSpan::new(17, 2));

    Ok(())
}

#[test]
fn test_17_undecodable_without_parameter_sets_flag() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    // Stream with only slices and no preceding SPS/PPS
    let mut stream = Vec::new();
    stream.extend(make_idr_slice(false, 0, &[0x11]));
    let scan = split_annexb(&stream, limits, &cx)?;
    assert_eq!(scan.access_units.len(), 1);
    assert!(scan.access_units[0].undecodable_without_parameter_sets);

    // Stream with SPS and PPS
    let mut valid_stream = Vec::new();
    valid_stream.extend(make_sps_nal());
    valid_stream.extend(make_pps_nal());
    valid_stream.extend(make_idr_slice(false, 0, &[0x11]));
    let valid_scan = split_annexb(&valid_stream, limits, &cx)?;
    assert!(!valid_scan.access_units[0].undecodable_without_parameter_sets);

    Ok(())
}

#[test]
fn test_18_sps_pps_spans_catalog() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    let mut stream = Vec::new();
    stream.extend(make_sps_nal());
    stream.extend(make_pps_nal());
    stream.extend(make_idr_slice(false, 0, &[0x11]));

    let scan = split_annexb(&stream, limits, &cx)?;
    assert_eq!(scan.sps_spans.len(), 1);
    assert_eq!(scan.pps_spans.len(), 1);
    assert_eq!(scan.sps_spans[0], SourceSpan::new(4, 4));
    assert_eq!(scan.pps_spans[0], SourceSpan::new(12, 4));

    Ok(())
}

#[test]
fn test_19_deterministic_synthetic_stream_pinned_golden_spans() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    // Deterministic synthetic stream:
    // AU 0:
    //   0..4: 4-byte SC, 4..6: AUD (len 2)
    //   6..10: 4-byte SC, 10..14: SPS (len 4)
    //   14..18: 4-byte SC, 18..22: PPS (len 4)
    //   22..26: 4-byte SC, 26..29: IDR Slice (first_mb=0, len 3)
    //   29..31: 2 bytes padding (trailing zeros 00 00)
    // AU 1:
    //   31..35: 4-byte SC, 35..38: Non-IDR Slice 0 (first_mb=0, len 3)
    //   38..41: 3-byte SC, 41..48: Non-IDR Slice 1 (first_mb=2, with emulation prevention 00 00 03 01, len 7)
    //   48..50: 2 bytes trailing zeros at EOF (00 00)
    let mut stream = Vec::new();
    // NAL 0: AUD
    stream.extend(make_aud_nal()); // 0..6
    // NAL 1: SPS
    stream.extend(make_sps_nal()); // 6..14
    // NAL 2: PPS
    stream.extend(make_pps_nal()); // 14..22
    // NAL 3: IDR Slice 0
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0x80, 0xFF]); // 22..29
    // Padding: 3 zero bytes (last zero absorbed into NAL 4 4-byte start code per Annex B)
    stream.extend_from_slice(&[0x00, 0x00, 0x00]); // 29..32
    // NAL 4: Non-IDR Slice 0 (4-byte SC absorbed from preceding zero)
    stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x41, 0x80, 0xAA]); // 32..38
    // NAL 5: Non-IDR Slice 1 (3-byte SC, first_mb=2 (0x60) + emulation prevention)
    stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x41, 0x60, 0x00, 0x00, 0x03, 0x01, 0xBB]); // 38..48
    // Padding: 2 trailing zero bytes
    stream.extend_from_slice(&[0x00, 0x00]); // 48..50

    assert_eq!(stream.len(), 50);

    let scan = split_annexb(&stream, limits, &cx)?;

    // Exact total bytes
    assert_eq!(scan.total_bytes, 50);

    // Exact NALs
    assert_eq!(scan.nals.len(), 6);
    assert_eq!(
        scan.nals[0],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(0, 4),
            nal_span: SourceSpan::new(4, 2),
            forbidden_zero_bit: 0,
            nal_ref_idc: 0,
            nal_unit_type: 9,
        }
    );
    assert_eq!(
        scan.nals[1],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(6, 4),
            nal_span: SourceSpan::new(10, 4),
            forbidden_zero_bit: 0,
            nal_ref_idc: 3,
            nal_unit_type: 7,
        }
    );
    assert_eq!(
        scan.nals[2],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(14, 4),
            nal_span: SourceSpan::new(18, 4),
            forbidden_zero_bit: 0,
            nal_ref_idc: 3,
            nal_unit_type: 8,
        }
    );
    assert_eq!(
        scan.nals[3],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(22, 4),
            nal_span: SourceSpan::new(26, 3),
            forbidden_zero_bit: 0,
            nal_ref_idc: 3,
            nal_unit_type: 5,
        }
    );
    assert_eq!(
        scan.nals[4],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(31, 4),
            nal_span: SourceSpan::new(35, 3),
            forbidden_zero_bit: 0,
            nal_ref_idc: 2,
            nal_unit_type: 1,
        }
    );
    assert_eq!(
        scan.nals[5],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(38, 3),
            nal_span: SourceSpan::new(41, 7),
            forbidden_zero_bit: 0,
            nal_ref_idc: 2,
            nal_unit_type: 1,
        }
    );

    // Exact Access Units
    assert_eq!(scan.access_units.len(), 2);
    assert_eq!(
        scan.access_units[0],
        fss_reference::AnnexBAccessUnit {
            span: SourceSpan::new(0, 31),
            nal_indices: vec![0, 1, 2, 3],
            is_idr: true,
            has_sps: true,
            has_pps: true,
            slice_count: 1,
            undecodable_without_parameter_sets: false,
        }
    );
    assert_eq!(
        scan.access_units[1],
        fss_reference::AnnexBAccessUnit {
            span: SourceSpan::new(31, 19),
            nal_indices: vec![4, 5],
            is_idr: false,
            has_sps: false,
            has_pps: false,
            slice_count: 2,
            undecodable_without_parameter_sets: false,
        }
    );

    // Exact padding spans
    assert_eq!(
        scan.padding_spans,
        vec![SourceSpan::new(29, 2), SourceSpan::new(48, 2)]
    );

    // Exact parameter set spans
    assert_eq!(scan.sps_spans, vec![SourceSpan::new(10, 4)]);
    assert_eq!(scan.pps_spans, vec![SourceSpan::new(18, 4)]);

    // Zero omissions
    assert!(scan.omission_spans.is_empty());

    Ok(())
}

#[test]
fn test_20_exact_equality_planted_bypasses() {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    // Truncated slice header: VCL slice with only header byte (0 payload bytes)
    let truncated_slice = vec![0x00, 0x00, 0x00, 0x01, 0x65];
    assert_eq!(
        split_annexb(&truncated_slice, limits, &cx),
        Err(AnnexBError::TruncatedSliceHeader { offset: 4 })
    );

    // 3-byte start code followed immediately by 3-byte start code
    let adjacent_3b = vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x01];
    assert_eq!(
        split_annexb(&adjacent_3b, limits, &cx),
        Err(AnnexBError::ZeroLengthNal { offset: 3 })
    );
}

#[test]
fn test_21_unsupported_extensions_and_au_grouping_heuristic() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = AnnexBLimits::default();

    let mut stream = Vec::new();
    // SPS (type 7)
    stream.extend(make_sps_nal());
    // PPS (type 8)
    stream.extend(make_pps_nal());
    // IDR slice (type 5)
    stream.extend(make_idr_slice(false, 0, &[0xAA]));
    // Subset SPS (type 15) - should start new AU and be flagged as unsupported extension
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x0F, 0x01]);
    // Coded slice extension (type 20) - should be flagged as unsupported extension
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x14, 0x02]);

    let scan = split_annexb(&stream, limits, &cx)?;
    assert_eq!(scan.au_grouping, "first_mb_in_slice_heuristic");
    assert_eq!(scan.access_units.len(), 2);
    assert_eq!(scan.unsupported_extension_spans.len(), 2);

    Ok(())
}
