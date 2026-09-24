#![forbid(unsafe_code)]
//! Access-unit splitting of real libx265 streams (the committed codec fixtures) and of
//! hand-assembled NAL sequences exercising the H.265 7.4.2.4.4 boundary rules.

use super::*;
use std::error::Error;
use std::path::PathBuf;

use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};

use crate::{ADP_REPLAY_ROW_ID, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-codec-h265/tests/fixtures/decode/"
);

fn test_cx(label: &str) -> TestResult<ReplayCx> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:unit-test-{label}"),
        operation_id: OperationId::parse(format!("operation:unit-test-{label}"))?,
        principal: format!("operator:unit-test-{label}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    };
    let root_auth = ContextAuthority::new_root(spec)?;
    let scratch_root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("test-replay-cx-hevc-annexb-unit-{label}"));
    let io = ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
}

fn fixture(name: &str) -> TestResult<Vec<u8>> {
    Ok(std::fs::read(format!("{FIXTURES}{name}.h265"))?)
}

fn split(bytes: &[u8]) -> Result<HevcScan, AnnexBError> {
    let cx = test_cx("split").map_err(|_| AnnexBError::Cancelled)?;
    split_hevc_annexb(bytes, AnnexBLimits::default(), &cx)
}

/// Access units tile the stream exactly: contiguous, starting at the first start code.
fn assert_tiles(scan: &HevcScan, bytes: &[u8]) {
    let mut expected = scan.access_units[0].span.offset;
    for unit in &scan.access_units {
        assert_eq!(unit.span.offset, expected);
        expected = unit.span.end();
    }
    assert_eq!(expected, bytes.len());
}

#[test]
fn open_gop_stream_splits_one_picture_per_access_unit_with_prefix_parameter_sets() -> TestResult {
    let bytes = fixture("b_qcif_opengop")?;
    let scan = split(&bytes)?;
    assert_eq!(scan.au_grouping, HEVC_AU_GROUPING);
    // The FFmpeg oracle for this stream lists twelve frames.
    assert_eq!(scan.access_units.len(), 12);
    assert_tiles(&scan, &bytes);
    let types: Vec<Option<u8>> = scan
        .access_units
        .iter()
        .map(|unit| unit.picture_nal_unit_type)
        .collect();
    // IDR_W_RADL, four trailing pictures, CRA, its RASL_N picture, then trailing pictures.
    assert_eq!(types[0], Some(20));
    assert_eq!(types[5], Some(21));
    assert_eq!(types[6], Some(8));
    for (index, unit) in scan.access_units.iter().enumerate() {
        assert_eq!(unit.slice_segment_count, 1, "access unit {index}");
        assert!(!unit.undecodable_without_parameter_sets);
        assert_eq!(unit.is_irap, index == 0 || index == 5);
        assert_eq!(unit.is_idr, index == 0);
        // VPS, SPS and PPS are repeated before each IRAP picture and travel with it.
        let parameter_sets = unit.has_vps && unit.has_sps && unit.has_pps;
        assert_eq!(parameter_sets, unit.is_irap, "access unit {index}");
    }
    Ok(())
}

#[test]
fn multi_slice_pictures_stay_in_one_access_unit() -> TestResult {
    for (name, pictures, slices) in [("i_qcif_slices4", 2, 4), ("f_qcif_slices_filters", 4, 2)] {
        let bytes = fixture(name)?;
        let scan = split(&bytes)?;
        assert_eq!(scan.access_units.len(), pictures, "{name}");
        assert_tiles(&scan, &bytes);
        assert!(
            scan.access_units
                .iter()
                .all(|unit| unit.slice_segment_count == slices),
            "{name}"
        );
    }
    Ok(())
}

fn nal(header: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 1, header[0], header[1]];
    bytes.extend_from_slice(payload);
    bytes
}

fn header(nal_unit_type: u8) -> [u8; 2] {
    [nal_unit_type << 1, 1]
}

#[test]
fn delimiters_prefix_sei_and_first_slice_flags_open_access_units() -> TestResult {
    let mut stream = Vec::new();
    stream.extend(nal(header(35), &[0x50])); // AUD
    stream.extend(nal(header(32), &[0x0c])); // VPS
    stream.extend(nal(header(33), &[0x01])); // SPS
    stream.extend(nal(header(34), &[0xc1])); // PPS
    stream.extend(nal(header(39), &[0x05])); // prefix SEI
    stream.extend(nal(header(19), &[0xaf])); // IDR, first slice segment
    stream.extend(nal(header(19), &[0x2f])); // IDR, second slice segment
    stream.extend(nal(header(40), &[0x05])); // suffix SEI stays
    stream.extend(nal(header(39), &[0x05])); // prefix SEI opens the next picture
    stream.extend(nal(header(1), &[0xa0])); // TRAIL_R, first slice segment
    stream.extend(nal(header(1), &[0xa0])); // TRAIL_R, next picture without prefix NALs
    stream.extend(nal(header(36), &[])); // EOS closes it
    stream.extend(nal(header(21), &[0x80])); // CRA after EOS
    let scan = split(&stream)?;
    let counts: Vec<usize> = scan
        .access_units
        .iter()
        .map(|u| u.nal_indices.len())
        .collect();
    assert_eq!(counts, [8, 2, 2, 1]);
    let types: Vec<Option<u8>> = scan
        .access_units
        .iter()
        .map(|u| u.picture_nal_unit_type)
        .collect();
    assert_eq!(types, [Some(19), Some(1), Some(1), Some(21)]);
    assert_eq!(scan.access_units[0].slice_segment_count, 2);
    assert!(scan.access_units[0].is_idr && scan.access_units[3].is_irap);
    assert!(!scan.access_units[3].is_idr);
    assert_tiles(&scan, &stream);
    Ok(())
}

#[test]
fn slices_before_parameter_sets_are_flagged_undecodable() -> TestResult {
    let mut stream = nal(header(1), &[0x80]);
    stream.extend(nal(header(32), &[0x0c]));
    stream.extend(nal(header(33), &[0x01]));
    stream.extend(nal(header(34), &[0xc1]));
    stream.extend(nal(header(19), &[0x80]));
    let scan = split(&stream)?;
    assert_eq!(scan.access_units.len(), 2);
    assert!(scan.access_units[0].undecodable_without_parameter_sets);
    assert!(!scan.access_units[1].undecodable_without_parameter_sets);
    Ok(())
}

#[test]
fn invalid_headers_and_pictureless_streams_are_refused() {
    // nuh_temporal_id_plus1 == 0.
    assert_eq!(
        split(&nal([19 << 1, 0], &[0x80])),
        Err(AnnexBError::InvalidHevcNalHeader { nal: 0, offset: 4 })
    );
    // One-byte NAL unit: no room for the two-byte header.
    assert_eq!(
        split(&[0, 0, 0, 1, 0x40]),
        Err(AnnexBError::InvalidHevcNalHeader { nal: 0, offset: 4 })
    );
    // Slice segment without payload.
    assert_eq!(
        split(&nal(header(1), &[])),
        Err(AnnexBError::TruncatedSliceHeader { offset: 4 })
    );
    // Parameter sets only.
    let mut parameters = nal(header(32), &[0x0c]);
    parameters.extend(nal(header(33), &[0x01]));
    assert_eq!(split(&parameters), Err(AnnexBError::NoHevcPicture));
    // Forbidden bit still refused by the shared framing pass.
    assert_eq!(
        split(&nal([0x80 | (1 << 1), 1], &[0x80])),
        Err(AnnexBError::ForbiddenBitSet { nal: 0, offset: 4 })
    );
}
