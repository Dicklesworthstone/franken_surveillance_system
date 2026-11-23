#![forbid(unsafe_code)]
//! Framing has one canonical request identity and must agree with the retained extraction.

use super::*;

fn policy(framing: TsFraming) -> MpegTsImportRequest {
    let mut file = FileIngestRequest::new(
        "unused",
        SensorId::parse("sensor:framing").unwrap(),
        StreamId::parse("stream:framing").unwrap(),
    );
    file.receive_time = Some(TimestampNs(10_000_000_000));
    let mut value = MpegTsImportRequest::new(file);
    value.framing = framing;
    value
}

#[test]
fn request_framing_has_exact_versions_and_no_alternate_legacy_encoding() {
    let legacy = policy(TsFraming::Ts188);
    let framed = policy(TsFraming::M2ts192);
    let legacy_bytes = legacy.encode();
    let framed_bytes = framed.encode();
    let offset = 8 + REQUEST_DOMAIN.len();
    assert_eq!(&framed_bytes[offset + 1..], &legacy_bytes[offset..]);
    assert_eq!(framed_bytes[offset], 2);
    assert_eq!(request(&legacy_bytes).unwrap().framing, TsFraming::Ts188);
    assert_eq!(request(&framed_bytes).unwrap().framing, TsFraming::M2ts192);
    assert_ne!(legacy.digest().unwrap(), framed.digest().unwrap());
    for tag in [0, 1, 3, u8::MAX] {
        let mut forged = framed_bytes.clone();
        forged[offset] = tag;
        assert!(request(&forged).is_err());
    }
    let mut v2_without_framing = legacy_bytes.clone();
    v2_without_framing[offset - 1] = b'2';
    assert!(request(&v2_without_framing).is_err());
    let mut v1_with_framing = framed_bytes.clone();
    v1_with_framing[offset - 1] = b'1';
    assert!(request(&v1_with_framing).is_err());
}

#[test]
fn even_reencoded_origin_proofs_require_request_and_receipt_framing_to_agree() {
    let source: Vec<u8> = include_bytes!("../../../../fss-container/tests/fixtures/avc_i64.ts")
        .chunks_exact(188)
        .flat_map(|packet| [0xff; 4].into_iter().chain(packet.iter().copied()))
        .collect();
    let request = policy(TsFraming::M2ts192);
    let parsed = MpegTsVideo::parse_framed(
        &source,
        request.framing,
        request.selection,
        request.transport_limits,
    )
    .unwrap();
    let receipt = TsExtractionReceipt::from_extraction(&parsed).unwrap();
    let mut proof = Proof {
        request,
        receipt,
        original_chunks: vec![(ContentDigest::sha256(&source), source.len() as u64)],
        scan_digest: ContentDigest::sha256(b"bounded scan commitment"),
    };
    let encoded = proof.encode().unwrap();
    assert_eq!(
        Proof::decode(&encoded).unwrap().request.framing,
        TsFraming::M2ts192
    );
    proof.request.framing = TsFraming::Ts188;
    assert!(proof.encode().is_err());
    // A caller able to recalculate every enclosing digest still cannot substitute
    // a canonical v1 policy for an explicitly framed extraction.
    let mut encoder = CanonicalEncoder::new();
    encoder.text(DOMAIN);
    encoder.bytes(&proof.request.encode());
    encoder.bytes(&proof.receipt.to_bytes().unwrap());
    encoder.digest(proof.scan_digest);
    encoder.u64(1);
    encoder.digest(proof.original_chunks[0].0);
    encoder.u64(proof.original_chunks[0].1);
    assert!(Proof::decode(&encoder.finish()).is_err());
}
