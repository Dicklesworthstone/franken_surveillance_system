#![forbid(unsafe_code)]

use super::*;
use crate::mpeg_ts::TS_PACKET_BYTES;
use crate::mpeg_ts::framing_tests::m2ts;

const AVC: &[u8] = include_bytes!("../../../tests/fixtures/avc_i64.ts");
const HEVC: &[u8] = include_bytes!("../../../tests/fixtures/hevc_i64.ts");

fn video(bytes: &[u8]) -> MpegTsVideo<'_> {
    MpegTsVideo::parse(bytes, TsSelection::default(), TsLimits::default()).unwrap()
}

fn reseal(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let checksum = ContentDigest::sha256(&bytes[..end]);
    bytes[end..].copy_from_slice(&checksum.bytes());
}

#[test]
fn legacy_ts_receipts_remain_byte_identical_to_the_original_v1_encoder() {
    // Captured by compiling the unmodified receipt encoder from7286814285fa8c35912d6899f0605f035fcbfdba,
    // then checking it byte-for-byte against this implementation for both retained fixtures.
    for (source, golden) in [
        (
            AVC,
            include_str!("../../../tests/fixtures/avc_i64.receipt-v1.hex"),
        ),
        (
            HEVC,
            include_str!("../../../tests/fixtures/hevc_i64.receipt-v1.hex"),
        ),
    ] {
        let receipt = TsExtractionReceipt::from_extraction(&video(source)).unwrap();
        assert_eq!(receipt.framing(), TsFraming::Ts188);
        let encoded = receipt.to_bytes().unwrap();
        assert_eq!(encoded.len(), 299);
        let actual: String = encoded.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(actual, golden.trim());
        assert_eq!(
            TsExtractionReceipt::from_bytes(&encoded)
                .unwrap()
                .to_bytes()
                .unwrap(),
            encoded
        );
    }
}

#[test]
fn avc_and_hevc_receipts_round_trip_and_reconstruct_exact_mapping() {
    for source in [AVC, HEVC] {
        let parsed = video(source);
        let receipt = TsExtractionReceipt::from_extraction(&parsed).unwrap();
        let encoded = receipt.to_bytes().unwrap();
        assert!(encoded.len() <= MAX_RECEIPT_BYTES);
        let loaded = TsExtractionReceipt::from_bytes(&encoded).unwrap();
        assert_eq!(loaded, receipt);
        assert_eq!(loaded.to_bytes().unwrap(), encoded);
        let reconstructed = loaded
            .verify_with_checkpoint(source, &mut || Ok(()))
            .unwrap();
        assert_eq!(reconstructed.source(), source);
        assert_eq!(
            reconstructed.elementary_stream(),
            parsed.elementary_stream()
        );
        assert_eq!(reconstructed.pes(), parsed.pes());
        assert_eq!(reconstructed.payload_spans(), parsed.payload_spans());
        assert_eq!(receipt.source_digest(), ContentDigest::sha256(source));
        assert_eq!(receipt.source_bytes(), source.len() as u64);
        assert_eq!(
            receipt.elementary_digest(),
            ContentDigest::sha256(parsed.elementary_stream())
        );
        assert_eq!(
            receipt.elementary_bytes(),
            parsed.elementary_stream().len() as u64
        );
        assert_eq!(receipt.codec(), parsed.codec());
        assert_eq!(receipt.program(), parsed.program());
        assert_eq!(receipt.video_pid(), parsed.video_pid());
        assert_eq!(receipt.pcr_pid(), parsed.pcr_pid());
        assert_eq!(
            receipt.packets_inspected(),
            parsed.packets_inspected() as u64
        );
        assert_eq!(receipt.pes_count(), parsed.pes().len() as u64);
        assert_eq!(
            receipt.payload_span_count(),
            parsed.payload_spans().len() as u64
        );
    }
}

#[test]
fn original_nonvideo_bytes_are_part_of_custody() {
    let mut source = AVC.to_vec();
    let mut null = [0xff; TS_PACKET_BYTES];
    null[..4].copy_from_slice(&[0x47, 0x1f, 0xff, 0x10]);
    source.extend_from_slice(&null);
    let parsed = video(&source);
    let receipt = TsExtractionReceipt::from_extraction(&parsed).unwrap();
    let original_elementary = parsed.elementary_stream().to_vec();
    source.last_mut().map(|byte| *byte ^= 1).unwrap();
    let changed = video(&source);
    assert_eq!(changed.elementary_stream(), original_elementary);
    assert_eq!(
        changed.packets_inspected() as u64,
        receipt.packets_inspected()
    );
    assert_eq!(
        receipt
            .verify_with_checkpoint(&source, &mut || Ok(()))
            .unwrap_err(),
        TsError::Receipt
    );
}

#[test]
fn selection_and_actual_parser_limits_are_bound_without_changing_media() {
    let automatic = video(AVC);
    let original = TsExtractionReceipt::from_extraction(&automatic).unwrap();
    let selection = TsSelection {
        program: Some(automatic.program()),
        video_pid: Some(automatic.video_pid()),
    };
    let limits = TsLimits {
        max_input_bytes: AVC.len(),
        max_packets: AVC.len() / TS_PACKET_BYTES,
        ..TsLimits::default()
    };
    let explicit = MpegTsVideo::parse(AVC, selection, limits).unwrap();
    let receipt = TsExtractionReceipt::from_extraction(&explicit).unwrap();
    assert_eq!(receipt.selection(), selection);
    assert_eq!(receipt.limits(), limits);
    assert_eq!(receipt.source_digest(), original.source_digest());
    assert_eq!(receipt.elementary_digest(), original.elementary_digest());
    assert_eq!(receipt.mapping_digest(), original.mapping_digest());
    assert_ne!(receipt.to_bytes().unwrap(), original.to_bytes().unwrap());
    assert!(receipt.verify_with_checkpoint(AVC, &mut || Ok(())).is_ok());
}

#[test]
fn current_resource_ceilings_only_narrow_historical_policy() {
    let parsed = video(AVC);
    let receipt = TsExtractionReceipt::from_extraction(&parsed).unwrap();
    let exact = TsLimits {
        max_input_bytes: AVC.len(),
        max_packets: parsed.packets_inspected(),
        max_psi_sections: parsed.psi_sections_inspected(),
        max_pes: parsed.pes().len(),
        max_payload_spans: parsed.payload_spans().len(),
        max_elementary_bytes: parsed.elementary_stream().len(),
        ..TsLimits::default()
    };
    let result = receipt
        .verify_bounded_with_checkpoint(AVC, exact, &mut || Ok(()))
        .unwrap();
    assert_eq!(result.limits(), exact);
    assert_eq!(result.elementary_stream(), parsed.elementary_stream());
    for limits in [
        TsLimits {
            max_input_bytes: exact.max_input_bytes - 1,
            ..exact
        },
        TsLimits {
            max_packets: exact.max_packets - 1,
            ..exact
        },
        TsLimits {
            max_psi_sections: exact.max_psi_sections - 1,
            ..exact
        },
        TsLimits {
            max_pes_bytes: 9,
            ..exact
        },
        TsLimits {
            max_payload_spans: exact.max_payload_spans - 1,
            ..exact
        },
        TsLimits {
            max_elementary_bytes: exact.max_elementary_bytes - 1,
            ..exact
        },
    ] {
        assert_eq!(
            receipt
                .verify_bounded_with_checkpoint(AVC, limits, &mut || Ok(()))
                .unwrap_err(),
            TsError::Limit
        );
    }
    let mut forged = receipt.clone();
    forged.limits.max_input_bytes = 1;
    assert_eq!(forged.to_bytes().unwrap_err(), TsError::Receipt);
}

#[test]
fn malformed_unknown_truncated_and_noncanonical_encodings_refuse() {
    let receipt = TsExtractionReceipt::from_extraction(&video(AVC)).unwrap();
    let encoded = receipt.to_bytes().unwrap();
    for end in 0..encoded.len() {
        assert_eq!(
            TsExtractionReceipt::from_bytes(&encoded[..end]).unwrap_err(),
            TsError::Receipt
        );
    }
    let mut corrupt = encoded.clone();
    corrupt[20] ^= 1;
    assert_eq!(
        TsExtractionReceipt::from_bytes(&corrupt).unwrap_err(),
        TsError::Receipt
    );
    let mut unknown = encoded.clone();
    unknown[8 + RECEIPT_SCHEMA.len() - 1] = b'9';
    reseal(&mut unknown);
    assert_eq!(
        TsExtractionReceipt::from_bytes(&unknown).unwrap_err(),
        TsError::Receipt
    );
    let mut bad_bool = encoded.clone();
    bad_bool[8 + RECEIPT_SCHEMA.len()] = 2;
    reseal(&mut bad_bool);
    assert_eq!(
        TsExtractionReceipt::from_bytes(&bad_bool).unwrap_err(),
        TsError::Receipt
    );
    let mut extra = encoded[..encoded.len() - 32].to_vec();
    extra.push(0);
    extra.extend_from_slice(&[0; 32]);
    reseal(&mut extra);
    assert_eq!(
        TsExtractionReceipt::from_bytes(&extra).unwrap_err(),
        TsError::Receipt
    );
    assert_eq!(
        TsExtractionReceipt::from_bytes(&[0; MAX_RECEIPT_BYTES + 1]).unwrap_err(),
        TsError::Receipt
    );
}

#[test]
fn well_formed_forged_claims_do_not_verify_against_the_source() {
    let receipt = TsExtractionReceipt::from_extraction(&video(AVC)).unwrap();
    let mut claims = Vec::new();
    let mut mapping = receipt.clone();
    mapping.mapping_digest = ContentDigest::sha256(b"other mapping");
    claims.push(mapping);
    let mut elementary = receipt.clone();
    elementary.elementary_digest = ContentDigest::sha256(b"other elementary bytes");
    claims.push(elementary);
    let mut codec = receipt.clone();
    codec.codec = VideoCodec::Hevc;
    claims.push(codec);
    let mut program = receipt.clone();
    program.program += 1;
    claims.push(program);
    for claim in claims {
        let encoded = claim.to_bytes().unwrap();
        let loaded = TsExtractionReceipt::from_bytes(&encoded).unwrap();
        assert_eq!(
            loaded
                .verify_with_checkpoint(AVC, &mut || Ok(()))
                .unwrap_err(),
            TsError::Receipt
        );
    }
    assert_eq!(
        receipt
            .verify_with_checkpoint(&AVC[..AVC.len() - 1], &mut || Ok(()))
            .unwrap_err(),
        TsError::Receipt
    );
}

#[test]
fn cancellation_withholds_hashing_and_reconstruction_results() {
    let parsed = video(AVC);
    let mut checkpoints = 0;
    let receipt = TsExtractionReceipt::from_extraction_with_checkpoint(&parsed, &mut || {
        checkpoints += 1;
        Ok(())
    })
    .unwrap();
    for stop in [0, 1, 2, checkpoints - 1] {
        let mut calls = 0;
        let result = TsExtractionReceipt::from_extraction_with_checkpoint(&parsed, &mut || {
            if calls == stop {
                return Err(TsError::Cancelled);
            }
            calls += 1;
            Ok(())
        });
        assert_eq!(result.unwrap_err(), TsError::Cancelled);
    }
    let mut verify_checkpoints = 0;
    receipt
        .verify_with_checkpoint(AVC, &mut || {
            verify_checkpoints += 1;
            Ok(())
        })
        .unwrap();
    for stop in [0, 1, verify_checkpoints / 2, verify_checkpoints - 1] {
        let mut calls = 0;
        let result = receipt.verify_with_checkpoint(AVC, &mut || {
            if calls == stop {
                return Err(TsError::Cancelled);
            }
            calls += 1;
            Ok(())
        });
        assert_eq!(result.unwrap_err(), TsError::Cancelled);
    }
}

#[test]
fn explicit_m2ts_receipts_reconstruct_original_coordinates_and_bind_opaque_prefixes() {
    for source in [AVC, HEVC] {
        let standard = TsExtractionReceipt::from_extraction(&video(source)).unwrap();
        let framed = m2ts(source);
        let parsed = MpegTsVideo::parse_framed(
            &framed,
            TsFraming::M2ts192,
            TsSelection::default(),
            TsLimits::default(),
        )
        .unwrap();
        let receipt = TsExtractionReceipt::from_extraction(&parsed).unwrap();
        assert_eq!(receipt.framing(), TsFraming::M2ts192);
        assert_eq!(receipt.source_digest(), ContentDigest::sha256(&framed));
        assert_eq!(receipt.elementary_digest(), standard.elementary_digest());
        assert_ne!(receipt.mapping_digest(), standard.mapping_digest());
        let bytes = receipt.to_bytes().unwrap();
        let mut decoder = CanonicalDecoder::new(&bytes[..bytes.len() - 32]);
        assert_eq!(decoder.text().unwrap(), FRAMED_RECEIPT_SCHEMA);
        assert_eq!(decoder.u8().unwrap(), 2);
        let loaded = TsExtractionReceipt::from_bytes(&bytes).unwrap();
        assert_eq!(loaded, receipt);
        assert_eq!(loaded.to_bytes().unwrap(), bytes);
        let reconstructed = loaded
            .verify_with_checkpoint(&framed, &mut || Ok(()))
            .unwrap();
        assert_eq!(reconstructed.payload_spans(), parsed.payload_spans());
        assert_eq!(reconstructed.pes(), parsed.pes());
        let mut changed = framed.clone();
        changed[0] ^= 1;
        let changed_video = MpegTsVideo::parse_framed(
            &changed,
            TsFraming::M2ts192,
            TsSelection::default(),
            TsLimits::default(),
        )
        .unwrap();
        assert_eq!(
            changed_video.elementary_stream(),
            parsed.elementary_stream()
        );
        assert_eq!(changed_video.payload_spans(), parsed.payload_spans());
        assert_eq!(
            loaded
                .verify_with_checkpoint(&changed, &mut || Ok(()))
                .unwrap_err(),
            TsError::Receipt
        );
        let narrower = TsLimits {
            max_input_bytes: framed.len() - 1,
            ..TsLimits::default()
        };
        assert_eq!(
            loaded
                .verify_bounded_with_checkpoint(&framed, narrower, &mut || Ok(()))
                .unwrap_err(),
            TsError::Limit
        );
        assert_eq!(
            loaded
                .verify_with_checkpoint(&framed, &mut || Err(TsError::Cancelled))
                .unwrap_err(),
            TsError::Cancelled
        );
    }
}

#[test]
fn m2ts_receipts_refuse_resealed_framing_tags_and_version_mismatches() {
    let framed = m2ts(AVC);
    let parsed = MpegTsVideo::parse_framed(
        &framed,
        TsFraming::M2ts192,
        TsSelection::default(),
        TsLimits::default(),
    )
    .unwrap();
    let receipt = TsExtractionReceipt::from_extraction(&parsed).unwrap();
    let bytes = receipt.to_bytes().unwrap();
    let framing_offset = 8 + FRAMED_RECEIPT_SCHEMA.len();
    for tag in [0, 1, 3, u8::MAX] {
        let mut forged = bytes.clone();
        forged[framing_offset] = tag;
        reseal(&mut forged);
        assert_eq!(
            TsExtractionReceipt::from_bytes(&forged).unwrap_err(),
            TsError::Receipt
        );
    }
    let mut forged_version = bytes.clone();
    forged_version[framing_offset - 1] = b'1';
    reseal(&mut forged_version);
    assert_eq!(
        TsExtractionReceipt::from_bytes(&forged_version).unwrap_err(),
        TsError::Receipt
    );
    // Even removing the framing tag and recomputing the checksum cannot make
    // physical 192-byte packet accounting a legacy 188-byte receipt.
    forged_version.remove(framing_offset);
    reseal(&mut forged_version);
    assert_eq!(
        TsExtractionReceipt::from_bytes(&forged_version).unwrap_err(),
        TsError::Receipt
    );
    let legacy = TsExtractionReceipt::from_extraction(&video(AVC)).unwrap();
    let mut forged_legacy = legacy.to_bytes().unwrap();
    forged_legacy[framing_offset - 1] = b'2';
    forged_legacy.insert(framing_offset, 2);
    reseal(&mut forged_legacy);
    assert_eq!(
        TsExtractionReceipt::from_bytes(&forged_legacy).unwrap_err(),
        TsError::Receipt
    );
}
