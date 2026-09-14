#![forbid(unsafe_code)]
//! Contract tests for bounded H.264 Annex-B elementary-stream splitter.

use std::error::Error;

use fss_reference::{
    AnnexBError, AnnexBLimits, AnnexBScan, CEILING_MAX_NAL_BYTES, DEFAULT_MAX_INPUT_BYTES,
    ReplayCx, SourceSpan, split_annexb,
};

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

    // 00 00 03 at NAL EOF is valid per H.264 7.4.1 (cabac_zero_word)
    let stream2 = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x80, 0x00, 0x00, 0x03];
    assert!(split_annexb(&stream2, limits, &cx).is_ok());

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
    // And other valid escapes: 00 00 03 02, 00 00 03 03, 00 00 03 00
    let mut stream = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x80];
    stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x01]); // escaped 00 00 01
    stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x02]); // escaped 00 00 02
    stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x03]); // escaped 00 00 03
    stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x00]); // escaped 00 00 00
    stream.push(0x80); // non-zero trailing byte so 0x00 is not treated as trailing_zero_8bits padding

    let scan = split_annexb(&stream, limits, &cx)?;
    // Must NOT split on 00 00 03 01
    assert_eq!(scan.nals.len(), 1);
    assert_eq!(scan.nals[0].nal_span.len, 19);
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
            nal_ref_idc: 0,
            nal_unit_type: 9,
        }
    );
    assert_eq!(
        scan.nals[1],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(6, 4),
            nal_span: SourceSpan::new(10, 4),
            nal_ref_idc: 3,
            nal_unit_type: 7,
        }
    );
    assert_eq!(
        scan.nals[2],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(14, 4),
            nal_span: SourceSpan::new(18, 4),
            nal_ref_idc: 3,
            nal_unit_type: 8,
        }
    );
    assert_eq!(
        scan.nals[3],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(22, 4),
            nal_span: SourceSpan::new(26, 3),
            nal_ref_idc: 3,
            nal_unit_type: 5,
        }
    );
    assert_eq!(
        scan.nals[4],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(31, 4),
            nal_span: SourceSpan::new(35, 3),
            nal_ref_idc: 2,
            nal_unit_type: 1,
        }
    );
    assert_eq!(
        scan.nals[5],
        fss_reference::AnnexBNal {
            start_code_span: SourceSpan::new(38, 3),
            nal_span: SourceSpan::new(41, 7),
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

// =========================================================================
// Reviewer Probe Tests (p01 - p14, m07)
// =========================================================================

fn run(bytes: &[u8], limits: AnnexBLimits) -> Result<AnnexBScan, AnnexBError> {
    let cx = ReplayCx::for_test();
    split_annexb(bytes, limits, &cx)
}

fn d() -> AnnexBLimits {
    AnnexBLimits::default()
}

fn nal_spans(s: &AnnexBScan) -> Vec<(usize, usize, usize, usize, u8)> {
    s.nals
        .iter()
        .map(|n| {
            (
                n.start_code_span.offset,
                n.start_code_span.len,
                n.nal_span.offset,
                n.nal_span.len,
                n.nal_unit_type,
            )
        })
        .collect()
}

// ---------- P1 mixed 3/4-byte start codes ----------
#[test]
fn p01_mixed_start_codes() {
    let s = [
        0, 0, 1, 0x09, 0x10, 0, 0, 0, 1, 0x67, 0x42, 0, 0, 1, 0x68, 0xCE, 0, 0, 0, 1, 0x65, 0x80,
        0xFF,
    ];
    let scan = run(&s, d()).map_err(|e| format!("{e:?}"));
    let got = scan.map(|s| nal_spans(&s));
    assert_eq!(
        got,
        Ok(vec![
            (0, 3, 3, 2, 9),
            (5, 4, 9, 2, 7),
            (11, 3, 14, 2, 8),
            (16, 4, 20, 3, 5)
        ])
    );
}

// ---------- P2 00 00 03 01 inside payload must not split (3-byte SC) ----------
#[test]
fn p02_ep_start_code_no_split() {
    let s = [0, 0, 1, 0x41, 0x80, 0, 0, 3, 1, 0xAA];
    let got = run(&s, d())
        .map(|s| nal_spans(&s))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(got, Ok(vec![(0, 3, 3, 7, 1)]));
}

// ---------- P3 EP removal is applied before ue(v) decode; span keeps EP bytes (kills M1) ----------
#[test]
fn p03_ep_removal_changes_ue_decode() {
    // payload after header: 00 00 03 00 00 03 00 80 -> RBSP 00 00 00 00 00 80 (40 zeros)
    let s = [0, 0, 0, 1, 0x41, 0, 0, 3, 0, 0, 3, 0, 0x80];
    assert_eq!(
        run(&s, d()),
        Err(AnnexBError::MalformedSliceHeader {
            offset: 4,
            detail: "ue(v) leading zero count exceeds 31"
        })
    );
    // Same bytes in a non-VCL NAL (filler, type 12): accepted, span keeps both EP bytes.
    let f = [0, 0, 0, 1, 0x0C, 0, 0, 3, 0, 0, 3, 0, 0x80];
    let got = run(&f, d())
        .map(|s| nal_spans(&s))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(got, Ok(vec![(0, 4, 4, 9, 12)]));
}

// ---------- P4 trailing_zero_8bits between and at EOF, with 3-byte SC after zeros ----------
#[test]
fn p04_trailing_zeros() {
    // AUD, 00 00 00 00, 3-byte SC, SPS, 00 at EOF
    let s = [0, 0, 1, 0x09, 0x10, 0, 0, 0, 0, 0, 0, 1, 0x67, 0x42, 0];
    let scan = run(&s, d());
    let got = scan
        .as_ref()
        .map(|s| (nal_spans(s), s.padding_spans.clone()))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(
        got,
        Ok((
            vec![(0, 3, 3, 2, 9), (8, 4, 12, 2, 7)],
            vec![SourceSpan::new(5, 3), SourceSpan::new(14, 1)]
        ))
    );
}

// ---------- P5 zero-length NAL ----------
#[test]
fn p05_zero_length_nal() {
    let s = [0, 0, 1, 0x09, 0x10, 0, 0, 1, 0, 0, 1, 0x09, 0x10];
    assert_eq!(run(&s, d()), Err(AnnexBError::ZeroLengthNal { offset: 8 }));
}

// ---------- P6 forbidden bit on second NAL ----------
#[test]
fn p06_forbidden_bit_second() {
    let s = [0, 0, 1, 0x09, 0x10, 0, 0, 1, 0x89, 0x10];
    assert_eq!(
        run(&s, d()),
        Err(AnnexBError::ForbiddenBitSet { nal: 1, offset: 8 })
    );
}

// ---------- P7 leading garbage: exact span, == limit accepted, +1 refused, zeros are padding ----------
#[test]
fn p07_leading_garbage() {
    let s = [0xAA, 0, 0, 0, 0, 1, 0x09, 0x10];
    let ok = run(&s, d().with_max_leading_garbage_bytes(2));
    let got = ok
        .as_ref()
        .map(|s| {
            (
                s.omission_spans.clone(),
                s.padding_spans.clone(),
                nal_spans(s),
            )
        })
        .map_err(|e| format!("{e:?}"));
    assert_eq!(
        got,
        Ok((vec![SourceSpan::new(0, 2)], vec![], vec![(2, 4, 6, 2, 9)]))
    );
    assert_eq!(
        run(&s, d().with_max_leading_garbage_bytes(1)),
        Err(AnnexBError::LeadingGarbage { len: 2 })
    );
    let z = [0, 0, 0, 0, 0, 1, 0x09, 0x10];
    let got = run(&z, d())
        .map(|s| (s.omission_spans.clone(), s.padding_spans.clone()))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(got, Ok((vec![], vec![SourceSpan::new(0, 2)])));
}

// ---------- P8 truncation ----------
#[test]
fn p08_truncated_final() {
    let s = [0, 0, 1, 0x09, 0x10, 0, 0, 1];
    assert_eq!(run(&s, d()), Err(AnnexBError::TruncatedNal { offset: 8 }));
    let s2 = [0, 0, 1];
    assert_eq!(run(&s2, d()), Err(AnnexBError::TruncatedNal { offset: 3 }));
    let s3 = [0, 0, 1, 0x41, 0x80, 0, 0, 3];
    // Trailing 00 00 03 at NAL end is accepted per H.264 7.4.1 (cabac_zero_word)
    assert!(run(&s3, d()).is_ok());
    let s4 = [0, 0, 1, 0x41, 0x80, 0, 0, 3, 4];
    assert_eq!(
        run(&s4, d()),
        Err(AnnexBError::MalformedEmulationPrevention { offset: 5 })
    );
    assert_eq!(run(&[0, 0, 0], d()), Err(AnnexBError::NoStartCode));
    assert_eq!(run(&[], d()), Err(AnnexBError::EmptyInput));
}

// Observation only: a final NAL cut inside payload is indistinguishable; record behaviour.
#[test]
fn p08b_mid_payload_truncation_observed() {
    let s = [0, 0, 1, 0x41, 0x80, 0x12, 0, 0];
    let got = run(&s, d())
        .map(|s| (nal_spans(&s), s.padding_spans.clone()))
        .map_err(|e| format!("{e:?}"));
    assert!(got.is_ok());
}

// ---------- P9 limit boundaries (kills M4b) ----------
#[test]
fn p09_limits_boundaries() {
    let s = [
        0, 0, 1, 0x09, 0x10, 0, 0, 1, 0x67, 0x42, 0, 0, 1, 0x68, 0xCE,
    ];
    assert!(run(&s, d().with_max_nals(3)).is_ok());
    assert_eq!(
        run(&s, d().with_max_nals(2)),
        Err(AnnexBError::TooManyNals { count: 3, max: 2 })
    );
    assert!(run(&s, d().with_max_input_bytes(s.len())).is_ok());
    assert_eq!(
        run(&s, d().with_max_input_bytes(s.len() - 1)),
        Err(AnnexBError::InputTooLarge { len: 15, max: 14 })
    );
    assert!(run(&s, d().with_max_nal_bytes(2)).is_ok());
    assert_eq!(
        run(&s, d().with_max_nal_bytes(1)),
        Err(AnnexBError::NalTooLarge {
            offset: 3,
            len: 2,
            max: 1
        })
    );
    // two AUs
    let a = [0, 0, 1, 0x65, 0x80, 0, 0, 1, 0x41, 0x80];
    assert!(run(&a, d().with_max_aus(2)).is_ok());
    assert_eq!(
        run(&a, d().with_max_aus(1)),
        Err(AnnexBError::TooManyAccessUnits { count: 2, max: 1 })
    );
}

// ---------- P10 defaults and 16 MiB boundary (kills M4b) ----------
#[test]
fn p10_defaults() {
    let l = AnnexBLimits::default();
    assert_eq!(l.max_input_bytes, 512 * 1024 * 1024);
    assert_eq!(l.max_nal_bytes, 8 * 1024 * 1024);

    let lim = AnnexBLimits::default().with_max_input_bytes(16 * 1024 * 1024);
    // 16 MiB exact input accepted with two filler NALs of 8 MiB total each
    let half = 8 * 1024 * 1024;
    let mut v = Vec::with_capacity(2 * half + 1);
    for _ in 0..2 {
        v.extend_from_slice(&[0, 0, 0, 1, 0x0C]);
        v.resize(v.len() + half - 5, 0xFF);
    }
    assert_eq!(v.len(), 16 * 1024 * 1024);
    let got = run(&v, lim)
        .map(|s| nal_spans(&s))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(
        got,
        Ok(vec![
            (0, 4, 4, half - 4, 12),
            (half, 4, half + 4, half - 4, 12)
        ])
    );
    v.push(0xFF);
    assert_eq!(
        run(&v, lim),
        Err(AnnexBError::InputTooLarge {
            len: 16 * 1024 * 1024 + 1,
            max: 16 * 1024 * 1024
        })
    );
}

// Bead: 16 MiB ceiling on max_nal_bytes. Does the splitter enforce it?
#[test]
fn p10b_ceiling_enforced() {
    let n = 16 * 1024 * 1024 + 1;
    let mut v = Vec::with_capacity(n + 5);
    v.extend_from_slice(&[0, 0, 0, 1, 0x0C]);
    v.resize(4 + n, 0xFF);
    let l = d()
        .with_max_input_bytes(64 * 1024 * 1024)
        .with_max_nal_bytes(64 * 1024 * 1024);
    let r = run(&v, l);
    assert!(
        r.is_err(),
        "NAL of 16 MiB + 1 accepted despite CEILING_MAX_NAL_BYTES"
    );
}

// ---------- P11 AU grouping ----------
fn au_groups(s: &AnnexBScan) -> Vec<Vec<usize>> {
    s.access_units
        .iter()
        .map(|a| a.nal_indices.clone())
        .collect()
}

// Kills M6b
#[test]
fn p11a_aud_and_param_boundaries() {
    // IDR(0), AUD, P(0) -> 2 AUs; P(0), SEI, SPS, PPS, IDR(0) -> SEI after VCL starts AU
    let s = [
        0, 0, 1, 0x65, 0x80, // 0 IDR
        0, 0, 1, 0x09, 0x10, // 1 AUD
        0, 0, 1, 0x41, 0x80, // 2 P
        0, 0, 1, 0x06, 0x05, // 3 SEI
        0, 0, 1, 0x67, 0x42, // 4 SPS
        0, 0, 1, 0x68, 0xCE, // 5 PPS
        0, 0, 1, 0x65, 0x80, // 6 IDR
        0, 0, 1, 0x41, 0x40, // 7 P first_mb=1 (same AU)
        0, 0, 1, 0x0E, 0x80, // 8 prefix NAL 14 after VCL -> new AU
        0, 0, 1, 0x41, 0x80, // 9 P(0)
    ];
    let got = run(&s, d())
        .map(|s| au_groups(&s))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(
        got,
        Ok(vec![vec![0], vec![1, 2], vec![3, 4, 5, 6, 7], vec![8, 9]])
    );
}

// AUD mid-AU with no VCL in current AU: SPS, AUD, IDR (kills M6b)
#[test]
fn p11b_aud_is_boundary_even_without_vcl() {
    let s = [
        0, 0, 1, 0x67, 0x42, 0, 0, 1, 0x09, 0x10, 0, 0, 1, 0x65, 0x80,
    ];
    let got = run(&s, d())
        .map(|s| au_groups(&s))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(got, Ok(vec![vec![0], vec![1, 2]]));
}

// Spec 7.4.1.2.3: end of sequence (10) / end of stream (11) are the LAST NALs of the AU.
#[test]
fn p11c_end_of_seq_belongs_to_current_au() {
    let s = [
        0, 0, 1, 0x65, 0x80, // 0 IDR
        0, 0, 1, 0x0A, 0x80, // 1 EOS  (payload byte to avoid len-1 NAL issues)
        0, 0, 1, 0x67, 0x42, // 2 SPS
        0, 0, 1, 0x65, 0x80, // 3 IDR
        0, 0, 1, 0x0B, 0x80, // 4 end of stream
    ];
    let got = run(&s, d())
        .map(|s| au_groups(&s))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(got, Ok(vec![vec![0, 1], vec![2, 3, 4]]));
}

// Data partitions B/C (types 3/4) begin with slice_id, not first_mb_in_slice.
#[test]
fn p11d_partition_b_slice_id_zero_same_au() {
    let s = [
        0, 0, 1, 0x62, 0x80, // 0 partition A, first_mb=0
        0, 0, 1, 0x63, 0x80, // 1 partition B, slice_id=0
        0, 0, 1, 0x64, 0x80, // 2 partition C, slice_id=0
    ];
    let got = run(&s, d())
        .map(|s| au_groups(&s))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(got, Ok(vec![vec![0, 1, 2]]));
}

// Gap cases of the heuristic that need no SPS/PPS (IdrPicFlag, nal_ref_idc==0).
#[test]
fn p11e_heuristic_gap_observed() {
    // IDR first_mb=0 then non-IDR first_mb=3: spec says new picture (IdrPicFlag differs)
    let s = [0, 0, 1, 0x65, 0x80, 0, 0, 1, 0x41, 0x20];
    let got = run(&s, d())
        .map(|s| (au_groups(&s), s.au_grouping))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(got, Ok((vec![vec![0, 1]], "first_mb_in_slice_heuristic")));
}

// AU spans: exact, include inter-AU padding, exclude leading padding/omission (kills M4b).
#[test]
fn p11f_au_spans_exact() {
    let s = [0xAA, 0, 0, 1, 0x65, 0x80, 0, 0, 0, 0, 1, 0x41, 0x80, 0];
    let got = run(&s, d().with_max_leading_garbage_bytes(1))
        .map(|s| s.access_units.iter().map(|a| a.span).collect::<Vec<_>>())
        .map_err(|e| format!("{e:?}"));
    assert_eq!(got, Ok(vec![SourceSpan::new(1, 6), SourceSpan::new(7, 7)]));
}

// ---------- spec conformance of EP validation ----------
// 7.4.1: NAL ending in cabac_zero_word gets a trailing 0x03 -> 00 00 03 at NAL end is VALID.
#[test]
fn p12a_cabac_zero_word_trailing_03_accepted() {
    let s = [0, 0, 1, 0x41, 0x80, 0x11, 0, 0, 3, 0, 0, 1, 0x09, 0x10];
    let got = run(&s, d())
        .map(|s| nal_spans(&s))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(got, Ok(vec![(0, 3, 3, 6, 1), (9, 3, 12, 2, 9)]));
}

// 7.4.1: 00 00 00 must not occur at any byte-aligned position inside a NAL.
#[test]
fn p12b_000000_inside_nal_refused() {
    let s = [0, 0, 1, 0x0C, 0x11, 0, 0, 0, 3, 1, 0xFF];
    let r = run(&s, d());
    assert!(r.is_err());
}

// ---------- coverage property over random inputs ----------
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn check_coverage(bytes: &[u8], s: &AnnexBScan) -> Result<(), String> {
    let mut spans: Vec<(usize, usize, &'static str)> = Vec::new();
    for o in &s.omission_spans {
        spans.push((o.offset, o.len, "omit"));
    }
    for p in &s.padding_spans {
        spans.push((p.offset, p.len, "pad"));
        if bytes[p.offset..p.end()].iter().any(|&b| b != 0) {
            return Err(format!("nonzero padding {p:?}"));
        }
    }
    for n in &s.nals {
        spans.push((n.start_code_span.offset, n.start_code_span.len, "sc"));
        spans.push((n.nal_span.offset, n.nal_span.len, "nal"));
        let sc = &bytes[n.start_code_span.offset..n.start_code_span.end()];
        if sc != [0, 0, 1] && sc != [0, 0, 0, 1] {
            return Err(format!("bad start code {sc:?}"));
        }
        let nb = &bytes[n.nal_span.offset..n.nal_span.end()];
        if nb.is_empty() || nb[0] & 0x80 != 0 || nb[nb.len() - 1] == 0 {
            return Err(format!("bad nal {:?}", n.nal_span));
        }
        if nb[0] & 0x1F != n.nal_unit_type || (nb[0] >> 5) & 3 != n.nal_ref_idc {
            return Err("header mismatch".into());
        }
    }
    spans.sort_unstable();
    let mut pos = 0usize;
    for (off, len, k) in &spans {
        if *len == 0 {
            return Err(format!("empty {k} span at {off}"));
        }
        if *off != pos {
            return Err(format!("gap/overlap at {pos}: next {k} span at {off}"));
        }
        pos = off + len;
    }
    if pos != bytes.len() {
        return Err(format!("coverage ends at {pos} of {}", bytes.len()));
    }
    // AU partition
    let mut next_nal = 0usize;
    let mut au_pos = s.nals.first().map_or(0, |n| n.start_code_span.offset);
    for a in &s.access_units {
        if a.span.offset != au_pos {
            return Err(format!("AU gap at {au_pos} vs {:?}", a.span));
        }
        au_pos = a.span.end();
        for &i in &a.nal_indices {
            if i != next_nal {
                return Err("AU nal indices not a partition".into());
            }
            next_nal += 1;
        }
        let first = &s.nals[a.nal_indices[0]];
        if first.start_code_span.offset != a.span.offset {
            return Err("AU does not start at its first NAL".into());
        }
    }
    if next_nal != s.nals.len() || au_pos != bytes.len() {
        return Err(format!("AU coverage {au_pos} nals {next_nal}"));
    }
    Ok(())
}

#[test]
fn p13_random_coverage_property() {
    let mut rng = Lcg(0x5EED_1234_ABCD_0019);
    let toks: [&[u8]; 12] = [
        &[0, 0, 1],
        &[0, 0, 0, 1],
        &[0],
        &[0, 0],
        &[3],
        &[0x65, 0x80],
        &[0x41, 0x40],
        &[0x09, 0x10],
        &[0x67],
        &[0xFF],
        &[0x80],
        &[0x01],
    ];
    let mut ok = 0u32;
    for _ in 0..200_000 {
        let n = 1 + rng.below(24) as usize;
        let mut v = Vec::new();
        for _ in 0..n {
            v.extend_from_slice(toks[rng.below(toks.len() as u64) as usize]);
        }
        let lim = d().with_max_leading_garbage_bytes(rng.below(4) as usize);
        match run(&v, lim) {
            Ok(s) => {
                ok += 1;
                assert!(
                    check_coverage(&v, &s).is_ok(),
                    "coverage violated for {v:02x?}"
                );
            }
            Err(_e) => {}
        }
    }
    assert!(ok > 1000);
}

// Structured round trip: escape random RBSPs, frame with random SC/padding, compare spans.
fn escape(rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut zeros = 0;
    for &b in rbsp {
        if zeros >= 2 && b <= 3 {
            out.push(3);
            zeros = 0;
        }
        out.push(b);
        zeros = if b == 0 { zeros + 1 } else { 0 };
    }
    out
}

#[test]
fn p14_structured_round_trip() {
    let mut rng = Lcg(0x0019_2B5A_0019_0019);
    let types = [1u8, 5, 6, 7, 8, 9, 12];
    for iter in 0..20_000 {
        let k = 1 + rng.below(8) as usize;
        let mut v = Vec::new();
        let mut expect = Vec::new();
        let lead = rng.below(3) as usize;
        v.resize(lead, 0);
        for j in 0..k {
            let t = types[rng.below(types.len() as u64) as usize];
            let hdr = ((rng.below(4) as u8) << 5) | t;
            let mut rbsp = Vec::new();
            if t == 1 || t == 5 {
                rbsp.push([0x80u8, 0x40, 0x60, 0x20, 0x88][rng.below(5) as usize]);
            }
            for _ in 0..rng.below(10) {
                rbsp.push([0u8, 0, 1, 2, 3, 0xFF, 0x7E][rng.below(7) as usize]);
            }
            rbsp.push(0x80);
            let payload = escape(&rbsp);
            let four = j == 0 || rng.below(2) == 0;
            let pad = if j > 0 { rng.below(3) as usize } else { 0 };
            let sc_len = if four || pad > 0 { 4 } else { 3 };
            let pad_eff = if !four && pad > 0 { pad - 1 } else { pad };
            v.resize(v.len() + pad_eff, 0);
            let sc_off = v.len();
            if sc_len == 4 {
                v.extend_from_slice(&[0, 0, 0, 1]);
            } else {
                v.extend_from_slice(&[0, 0, 1]);
            }
            let nal_off = v.len();
            v.push(hdr);
            v.extend_from_slice(&payload);
            expect.push((sc_off, sc_len, nal_off, 1 + payload.len(), t));
        }
        v.resize(v.len() + rng.below(3) as usize, 0);
        let got = run(&v, d()).map(|s| {
            assert!(check_coverage(&v, &s).is_ok(), "iter {iter}");
            nal_spans(&s)
        });
        assert_eq!(got, Ok(expect), "iter {iter} bytes {v:02x?}");
    }
}

type ProbeRow = (usize, usize, usize, usize, u8);
const PROBE_SC: &[u8] = &[0, 0, 1];

fn probe_spans(
    bytes: &[u8],
    l: AnnexBLimits,
) -> Result<(Vec<ProbeRow>, Vec<SourceSpan>), AnnexBError> {
    run(bytes, l).map(|s| {
        (
            s.nals
                .iter()
                .map(|n| {
                    (
                        n.start_code_span.offset,
                        n.start_code_span.len,
                        n.nal_span.offset,
                        n.nal_span.len,
                        n.nal_unit_type,
                    )
                })
                .collect(),
            s.padding_spans.clone(),
        )
    })
}

fn probe_aus(bytes: &[u8]) -> Result<Vec<(Vec<usize>, SourceSpan)>, AnnexBError> {
    run(bytes, d()).map(|s| {
        s.access_units
            .iter()
            .map(|a| (a.nal_indices.clone(), a.span))
            .collect()
    })
}

fn probe_groups(bytes: &[u8]) -> Result<Vec<Vec<usize>>, AnnexBError> {
    run(bytes, d()).map(|s| {
        s.access_units
            .iter()
            .map(|a| a.nal_indices.clone())
            .collect()
    })
}

fn probe_cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn probe_mep(offset: usize) -> Result<AnnexBScan, AnnexBError> {
    Err(AnnexBError::MalformedEmulationPrevention { offset })
}

#[test]
fn probe_q01_start_codes_leading_and_trailing_zeros() {
    assert_eq!(
        probe_spans(&[0, 0, 1, 0x09, 0x10], d()),
        Ok((vec![(0, 3, 3, 2, 9)], vec![]))
    );
    assert_eq!(
        probe_spans(&[0, 0, 0, 1, 0x09, 0x10], d()),
        Ok((vec![(0, 4, 4, 2, 9)], vec![]))
    );
    assert_eq!(
        probe_spans(&[0, 0, 0, 0, 0, 0, 1, 0x09, 0x10], d()),
        Ok((vec![(3, 4, 7, 2, 9)], vec![SourceSpan::new(0, 3)]))
    );
    assert_eq!(
        probe_spans(&[0, 0, 1, 0x09, 0x10, 0, 0, 0, 1, 0x67, 0x42], d()),
        Ok((vec![(0, 3, 3, 2, 9), (5, 4, 9, 2, 7)], vec![]))
    );
    assert_eq!(
        probe_spans(&[0, 0, 1, 0x09, 0x10, 0, 0, 0, 0, 0, 1, 0x67, 0x42], d()),
        Ok((
            vec![(0, 3, 3, 2, 9), (7, 4, 11, 2, 7)],
            vec![SourceSpan::new(5, 2)]
        ))
    );
    assert_eq!(
        probe_spans(&[0, 0, 1, 0x09, 0x10, 0, 0, 0, 0], d()),
        Ok((vec![(0, 3, 3, 2, 9)], vec![SourceSpan::new(5, 4)]))
    );
}

#[test]
fn probe_q02_ep_followers_and_cabac_zero_word() {
    for x in 0u8..=3 {
        let s = [0, 0, 1, 0x0C, 0xAA, 0, 0, 3, x, 0xBB];
        assert_eq!(
            probe_spans(&s, d()),
            Ok((vec![(0, 3, 3, 7, 12)], vec![])),
            "follower {x}"
        );
    }
    for x in [4u8, 0x10, 0x80, 0xFF] {
        let s = [0, 0, 1, 0x0C, 0xAA, 0, 0, 3, x, 0xBB];
        assert_eq!(run(&s, d()), probe_mep(5), "follower {x}");
    }
    assert_eq!(
        probe_spans(&[0, 0, 1, 0x0C, 0xAA, 0, 0, 3], d()),
        Ok((vec![(0, 3, 3, 5, 12)], vec![]))
    );
    assert_eq!(
        probe_spans(&[0, 0, 1, 0x0C, 0xAA, 0, 0, 3, 0, 0, 1, 0x09, 0x10], d()),
        Ok((vec![(0, 3, 3, 5, 12), (8, 3, 11, 2, 9)], vec![]))
    );
    assert_eq!(
        probe_spans(&[0, 0, 1, 0x0C, 0xAA, 0, 0, 3, 0, 0, 0, 1, 0x09, 0x10], d()),
        Ok((vec![(0, 3, 3, 5, 12), (8, 4, 12, 2, 9)], vec![]))
    );
    assert_eq!(
        probe_spans(
            &[0, 0, 1, 0x0C, 0xAA, 0, 0, 3, 0, 0, 3, 0, 0, 3, 1, 0xBB],
            d()
        ),
        Ok((vec![(0, 3, 3, 13, 12)], vec![]))
    );
    assert_eq!(
        probe_spans(&[0, 0, 1, 0x41, 0x80, 0, 0, 3], d()),
        Ok((vec![(0, 3, 3, 5, 1)], vec![]))
    );
}

#[test]
fn probe_q03_forbidden_sequences_in_payload() {
    assert_eq!(
        run(&[0, 0, 1, 0x0C, 0xAA, 0, 0, 0, 0xBB], d()),
        probe_mep(5)
    );
    assert_eq!(
        run(&[0, 0, 1, 0x0C, 0xAA, 0, 0, 2, 0xBB], d()),
        probe_mep(5)
    );
    assert_eq!(
        run(&[0, 0, 1, 0x0C, 0x11, 0, 0, 0, 3, 1, 0xFF], d()),
        probe_mep(5)
    );
    assert_eq!(run(&[0, 0, 1, 0x0C, 0, 0, 0, 0xBB], d()), probe_mep(4));
}

#[test]
fn probe_q03b_header_spanning_forbidden_sequences() {
    let a = run(&[0, 0, 1, 0x00, 0x00, 0x02, 0xAA], d());
    let b = run(&[0, 0, 1, 0x00, 0x00, 0x00, 0xAA], d());
    assert!(
        a.is_err() && b.is_err(),
        "header-spanning forbidden 3-byte sequence accepted"
    );
}

#[test]
fn probe_q04_eos_terminal() {
    let s = probe_cat(&[
        PROBE_SC,
        &[0x65, 0x80],
        PROBE_SC,
        &[0x0A],
        PROBE_SC,
        &[0x67, 0x42],
        PROBE_SC,
        &[0x68, 0xCE],
        PROBE_SC,
        &[0x65, 0x80],
        PROBE_SC,
        &[0x0B],
    ]);
    assert_eq!(
        probe_aus(&s),
        Ok(vec![
            (vec![0, 1], SourceSpan::new(0, 9)),
            (vec![2, 3, 4, 5], SourceSpan::new(9, 19))
        ])
    );
    let s = probe_cat(&[
        PROBE_SC,
        &[0x65, 0x80],
        PROBE_SC,
        &[0x0A],
        PROBE_SC,
        &[0x41, 0x40],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0, 1], vec![2]]));
    let s = probe_cat(&[
        PROBE_SC,
        &[0x65, 0x80],
        PROBE_SC,
        &[0x0B],
        PROBE_SC,
        &[0x41, 0x40],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0, 1], vec![2]]));
    let s = probe_cat(&[
        PROBE_SC,
        &[0x67, 0x42],
        PROBE_SC,
        &[0x0A],
        PROBE_SC,
        &[0x67, 0x42],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0, 1], vec![2]]));
    let s = probe_cat(&[PROBE_SC, &[0x0A], PROBE_SC, &[0x65, 0x80]]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0], vec![1]]));
    let s = [0, 0, 1, 0x65, 0x80, 0, 0, 1, 0x0A, 0, 0];
    assert_eq!(
        probe_aus(&s),
        Ok(vec![(vec![0, 1], SourceSpan::new(0, 11))])
    );
    assert_eq!(
        probe_spans(&s, d()).map(|x| x.1),
        Ok(vec![SourceSpan::new(9, 2)])
    );
}

#[test]
fn probe_q05_first_mb_expgolomb() {
    let s = probe_cat(&[
        PROBE_SC,
        &[0x41, 0x80],
        PROBE_SC,
        &[0x41, 0x40],
        PROBE_SC,
        &[0x41, 0x60],
        PROBE_SC,
        &[0x41, 0x20],
        PROBE_SC,
        &[0x41, 0x10],
        PROBE_SC,
        &[0x41, 0x80],
        PROBE_SC,
        &[0x41, 0x38],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0, 1, 2, 3, 4], vec![5, 6]]));
    let s = probe_cat(&[
        PROBE_SC,
        &[0x41, 0x80],
        PROBE_SC,
        &[0x41, 0, 0, 3, 0, 1, 0xFF, 0xFF, 0xFF, 0xFE],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0, 1]]));
    assert_eq!(
        run(&[0, 0, 1, 0x41, 0, 0, 3, 0, 0, 0x80], d()),
        Err(AnnexBError::MalformedSliceHeader {
            offset: 3,
            detail: "ue(v) leading zero count exceeds 31"
        })
    );
    assert_eq!(
        run(&[0, 0, 1, 0x41, 0, 0, 3], d()),
        Err(AnnexBError::TruncatedSliceHeader { offset: 3 })
    );
    assert_eq!(
        run(&[0, 0, 1, 0x65], d()),
        Err(AnnexBError::TruncatedSliceHeader { offset: 3 })
    );
    let s = probe_cat(&[
        PROBE_SC,
        &[0x67, 0x42],
        PROBE_SC,
        &[0x68, 0xCE],
        PROBE_SC,
        &[0x65, 0x80],
        PROBE_SC,
        &[0x65, 0x80],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0, 1, 2], vec![3]]));
}

#[test]
fn probe_q06_partitions() {
    let s = probe_cat(&[
        PROBE_SC,
        &[0x62, 0x80],
        PROBE_SC,
        &[0x63, 0x80],
        PROBE_SC,
        &[0x64, 0x80],
        PROBE_SC,
        &[0x62, 0x80],
        PROBE_SC,
        &[0x63, 0x80],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0, 1, 2], vec![3, 4]]));
    let s = probe_cat(&[PROBE_SC, &[0x62, 0x80], PROBE_SC, &[0x63, 0, 0, 3]]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0, 1]]));
}

#[test]
fn probe_q07_truncated_final() {
    let t = |offset| Err(AnnexBError::TruncatedNal { offset });
    assert_eq!(run(&[0, 0, 1, 0x09, 0x10, 0, 0, 1], d()), t(8));
    assert_eq!(run(&[0, 0, 1, 0x09, 0x10, 0, 0, 0, 1], d()), t(9));
    assert_eq!(run(&[0, 0, 1, 0x09, 0x10, 0, 0, 1, 0, 0], d()), t(8));
    assert_eq!(run(&[0, 0, 1], d()), t(3));
    assert_eq!(run(&[0, 0, 0, 1], d()), t(4));
}

#[test]
fn probe_q08_limits_exact() {
    let fin = [0, 0, 1, 0x0C, 0xFF, 0xFF, 0, 0, 1, 0x0C, 0xFF, 0xFF, 0xFF];
    assert!(run(&fin, d().with_max_nal_bytes(4)).is_ok());
    assert_eq!(
        run(&fin, d().with_max_nal_bytes(3)),
        Err(AnnexBError::NalTooLarge {
            offset: 9,
            len: 4,
            max: 3
        })
    );
    let mid = [0, 0, 1, 0x0C, 0xFF, 0xFF, 0xFF, 0, 0, 1, 0x0C, 0xFF, 0xFF];
    assert!(run(&mid, d().with_max_nal_bytes(4)).is_ok());
    assert_eq!(
        run(&mid, d().with_max_nal_bytes(3)),
        Err(AnnexBError::NalTooLarge {
            offset: 3,
            len: 4,
            max: 3
        })
    );
    let three = [
        0, 0, 1, 0x09, 0x10, 0, 0, 1, 0x67, 0x42, 0, 0, 1, 0x68, 0xCE,
    ];
    assert!(run(&three, d().with_max_nals(3)).is_ok());
    assert_eq!(
        run(&three, d().with_max_nals(1)),
        Err(AnnexBError::TooManyNals { count: 2, max: 1 })
    );
    assert_eq!(
        run(&three, d().with_max_nals(0)),
        Err(AnnexBError::TooManyNals { count: 1, max: 0 })
    );
    assert!(run(&three, d().with_max_aus(1)).is_ok());
    assert_eq!(
        run(&three, d().with_max_aus(0)),
        Err(AnnexBError::TooManyAccessUnits { count: 1, max: 0 })
    );
    assert!(run(&three, d().with_max_input_bytes(15)).is_ok());
    assert_eq!(
        run(&three, d().with_max_input_bytes(14)),
        Err(AnnexBError::InputTooLarge { len: 15, max: 14 })
    );
    let g = [0xAA, 0xBB, 0, 0, 1, 0x09, 0x10];
    assert!(run(&g, d().with_max_leading_garbage_bytes(2)).is_ok());
    assert_eq!(
        run(&g, d().with_max_leading_garbage_bytes(1)),
        Err(AnnexBError::LeadingGarbage { len: 2 })
    );
    assert_eq!(run(&g, d()), Err(AnnexBError::LeadingGarbage { len: 2 }));
}

#[test]
fn probe_q09_ceiling() {
    assert_eq!(CEILING_MAX_NAL_BYTES, 16 * 1024 * 1024);
    assert_eq!(
        d().with_max_nal_bytes(usize::MAX).max_nal_bytes,
        CEILING_MAX_NAL_BYTES
    );
    assert_eq!(
        d().with_max_nal_bytes(CEILING_MAX_NAL_BYTES).max_nal_bytes,
        CEILING_MAX_NAL_BYTES
    );
    let literal = AnnexBLimits {
        max_input_bytes: 64 << 20,
        max_nal_bytes: usize::MAX,
        max_nals: 10,
        max_aus: 10,
        max_leading_garbage_bytes: 0,
    };
    let mut v = vec![0, 0, 0, 1, 0x0C];
    v.resize(4 + CEILING_MAX_NAL_BYTES, 0xFF);
    assert_eq!(
        probe_spans(&v, literal).map(|x| x.0),
        Ok(vec![(0, 4, 4, CEILING_MAX_NAL_BYTES, 12)])
    );
    v.push(0xFF);
    let want = Err(AnnexBError::NalTooLarge {
        offset: 4,
        len: CEILING_MAX_NAL_BYTES + 1,
        max: CEILING_MAX_NAL_BYTES,
    });
    assert_eq!(run(&v, literal), want, "struct-literal limits");
    let built = d()
        .with_max_input_bytes(64 << 20)
        .with_max_nal_bytes(usize::MAX);
    assert_eq!(run(&v, built), want, "builder limits");
}

#[test]
fn probe_q10_default_input_boundary() {
    assert_eq!(DEFAULT_MAX_INPUT_BYTES, 512 * 1024 * 1024);
    let n = DEFAULT_MAX_INPUT_BYTES;
    let v = vec![0u8; n + 1];
    assert_eq!(
        run(&v, d()),
        Err(AnnexBError::InputTooLarge { len: n + 1, max: n })
    );
    assert_eq!(run(&v[..n], d()), Err(AnnexBError::NoStartCode));
}

#[test]
fn probe_q11_au_boundaries() {
    let s = probe_cat(&[
        PROBE_SC,
        &[0x06, 0x05],
        PROBE_SC,
        &[0x67, 0x42],
        PROBE_SC,
        &[0x68, 0xCE],
        PROBE_SC,
        &[0x65, 0x80],
        PROBE_SC,
        &[0x65, 0x40],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0, 1, 2, 3, 4]]));
    let s = probe_cat(&[
        PROBE_SC,
        &[0x41, 0x80],
        PROBE_SC,
        &[0x06, 0x05],
        PROBE_SC,
        &[0x41, 0x80],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0], vec![1, 2]]));
    let s = probe_cat(&[
        PROBE_SC,
        &[0x41, 0x80],
        PROBE_SC,
        &[0x0C, 0xFF],
        PROBE_SC,
        &[0x41, 0x40],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0, 1, 2]]));
    let s = probe_cat(&[
        PROBE_SC,
        &[0x65, 0x80],
        PROBE_SC,
        &[0x68, 0xCE],
        PROBE_SC,
        &[0x41, 0x80],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0], vec![1, 2]]));
    let s = probe_cat(&[
        PROBE_SC,
        &[0x41, 0x80],
        PROBE_SC,
        &[0x09, 0x10],
        PROBE_SC,
        &[0x41, 0x40],
    ]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0], vec![1, 2]]));
    let s = probe_cat(&[PROBE_SC, &[0x09, 0x10], PROBE_SC, &[0x09, 0x10]]);
    assert_eq!(probe_groups(&s), Ok(vec![vec![0], vec![1]]));
}

#[test]
fn probe_q12_cancel_before_scan() {
    let cx = ReplayCx::for_test();
    cx.request_cancellation();
    assert_eq!(
        split_annexb(&[0, 0, 1, 0x09, 0x10], d(), &cx),
        Err(AnnexBError::Cancelled)
    );
    assert!(cx.is_drain_completed());
}
