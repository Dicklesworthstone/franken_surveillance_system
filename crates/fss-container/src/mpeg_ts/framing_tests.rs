#![forbid(unsafe_code)]
//! Physical framing is explicit; prefixes are custody bytes, never transport or clock authority.

use super::*;

const AVC: &[u8] = include_bytes!("../../tests/fixtures/avc_i64.ts");
const HEVC: &[u8] = include_bytes!("../../tests/fixtures/hevc_i64.ts");

pub(super) fn m2ts(source: &[u8]) -> Vec<u8> {
    source
        .as_chunks::<TS_PACKET_BYTES>()
        .0
        .iter()
        .enumerate()
        .flat_map(|(index, packet)| {
            // Disordered/wrapping arrival timestamps and copyright bits are deliberately
            // opaque. A sync-looking prefix must not be mistaken for a TS header.
            let prefix = [u32::MAX, 0, 0x4747_4747, 0x8000_0001][index % 4];
            prefix
                .to_be_bytes()
                .into_iter()
                .chain(packet.iter().copied())
        })
        .collect()
}

fn parse(source: &[u8]) -> Result<MpegTsVideo<'_>, TsError> {
    MpegTsVideo::parse_framed(
        source,
        TsFraming::M2ts192,
        TsSelection::default(),
        TsLimits::default(),
    )
}

#[test]
fn m2ts_avc_and_hevc_preserve_elementary_bytes_timestamps_and_absolute_source_spans() {
    for source in [AVC, HEVC] {
        let standard =
            MpegTsVideo::parse(source, TsSelection::default(), TsLimits::default()).unwrap();
        let framed = m2ts(source);
        let parsed = parse(&framed).unwrap();
        assert_eq!(standard.framing(), TsFraming::Ts188);
        assert_eq!(parsed.framing(), TsFraming::M2ts192);
        assert_eq!(parsed.source(), framed);
        assert_eq!(parsed.elementary_stream(), standard.elementary_stream());
        assert_eq!(parsed.codec(), standard.codec());
        assert_eq!(parsed.pes(), standard.pes());
        assert_eq!(parsed.packets_inspected(), source.len() / TS_PACKET_BYTES);
        assert_eq!(parsed.payload_spans().len(), standard.payload_spans().len());
        for (original, prefixed) in standard.payload_spans().iter().zip(parsed.payload_spans()) {
            assert_eq!(original.elementary, prefixed.elementary);
            assert_eq!(original.pes, prefixed.pes);
            let packet = original.source.start / TS_PACKET_BYTES;
            assert_eq!((original.source.end - 1) / TS_PACKET_BYTES, packet);
            assert_eq!(
                prefixed.source,
                original.source.start + 4 * (packet + 1)..original.source.end + 4 * (packet + 1)
            );
            assert_eq!(
                &framed[prefixed.source.clone()],
                &source[original.source.clone()]
            );
            assert!(prefixed.source.start % M2TS_PACKET_BYTES >= 4);
        }
        let first = parsed.payload_spans().first().unwrap();
        let last = parsed.payload_spans().last().unwrap();
        assert_eq!(
            parsed
                .source_envelope(0..parsed.elementary_stream().len())
                .unwrap(),
            first.source.start..last.source.end
        );
    }
}

#[test]
fn m2ts_requires_exact_explicit_stride_and_sync_position_without_resynchronizing() {
    let framed = m2ts(AVC);
    assert!(MpegTsVideo::parse(&framed, TsSelection::default(), TsLimits::default()).is_err());
    assert!(parse(AVC).is_err());
    for trailing in 1..M2TS_PACKET_BYTES {
        assert_eq!(
            parse(&framed[..framed.len() - trailing]).unwrap_err(),
            TsError::Truncated
        );
    }
    let mut prefix_only = framed.clone();
    prefix_only.extend_from_slice(&[0x47, 0, 0, 0]);
    assert_eq!(parse(&prefix_only).unwrap_err(), TsError::Truncated);
    let mut wrong_sync = framed.clone();
    // Even a sync byte at offset zero cannot authorize scanning past a bad offset-four sync.
    wrong_sync[0] = 0x47;
    wrong_sync[4] = 0;
    assert_eq!(parse(&wrong_sync).unwrap_err(), TsError::Packet);
    let mut mixed = framed.clone();
    mixed[M2TS_PACKET_BYTES..M2TS_PACKET_BYTES + TS_PACKET_BYTES]
        .copy_from_slice(&AVC[TS_PACKET_BYTES..2 * TS_PACKET_BYTES]);
    assert!(parse(&mixed).is_err());
}

#[test]
fn opaque_prefix_changes_do_not_authorize_or_conflict_with_ts_continuity() {
    // Duplicate PAT transport packet, with distinct physical arrival prefixes.
    let pat_start = AVC
        .as_chunks::<TS_PACKET_BYTES>()
        .0
        .iter()
        .position(|packet| packet[1] & 0x1f == 0 && packet[2] == 0)
        .unwrap()
        * TS_PACKET_BYTES;
    let duplicated = [&AVC[..pat_start + TS_PACKET_BYTES], &AVC[pat_start..]].concat();
    let duplicate_start = (pat_start / TS_PACKET_BYTES + 1) * M2TS_PACKET_BYTES;
    let framed = m2ts(&duplicated);
    let parsed = parse(&framed).unwrap();
    assert_eq!(parsed.duplicate_packets(), 1);
    assert_eq!(
        parsed.elementary_stream(),
        parse(&m2ts(AVC)).unwrap().elementary_stream()
    );
    let mut changed_prefix = framed.clone();
    changed_prefix[duplicate_start..duplicate_start + 4].fill(0x47);
    assert_eq!(parse(&changed_prefix).unwrap().duplicate_packets(), 1);
    let mut changed_packet = framed.clone();
    changed_packet[duplicate_start + M2TS_PACKET_BYTES - 1] ^= 1;
    assert_eq!(parse(&changed_packet).unwrap_err(), TsError::Continuity);
    // Changing only an arrival prefix cannot hide a transport sequence error.
    let mut reordered = framed.clone();
    reordered[duplicate_start + 7] ^= 2;
    assert_eq!(parse(&reordered).unwrap_err(), TsError::Continuity);
}

#[test]
fn m2ts_prefix_bytes_count_toward_input_limits_and_packets_share_one_cancellation_budget() {
    let framed = m2ts(AVC);
    let baseline = parse(&framed).unwrap();
    let exact = TsLimits {
        max_input_bytes: framed.len(),
        max_packets: framed.len() / M2TS_PACKET_BYTES,
        max_elementary_bytes: baseline.elementary_stream().len(),
        ..TsLimits::default()
    };
    assert!(
        MpegTsVideo::parse_framed(&framed, TsFraming::M2ts192, TsSelection::default(), exact)
            .is_ok()
    );
    for limits in [
        TsLimits {
            max_input_bytes: framed.len() - 1,
            ..exact
        },
        TsLimits {
            max_packets: exact.max_packets - 1,
            ..exact
        },
        TsLimits {
            max_elementary_bytes: exact.max_elementary_bytes - 1,
            ..exact
        },
    ] {
        assert_eq!(
            MpegTsVideo::parse_framed(&framed, TsFraming::M2ts192, TsSelection::default(), limits)
                .unwrap_err(),
            TsError::Limit
        );
    }
    let mut checkpoints = 0;
    MpegTsVideo::parse_framed_with_checkpoint(
        &framed,
        TsFraming::M2ts192,
        TsSelection::default(),
        exact,
        &mut || {
            checkpoints += 1;
            Ok(())
        },
    )
    .unwrap();
    for stop in [0, 1, checkpoints / 2, checkpoints - 1] {
        let mut current = 0;
        let result = MpegTsVideo::parse_framed_with_checkpoint(
            &framed,
            TsFraming::M2ts192,
            TsSelection::default(),
            exact,
            &mut || {
                if current == stop {
                    return Err(TsError::Cancelled);
                }
                current += 1;
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err(), TsError::Cancelled);
    }
}

#[test]
fn dvb204_retains_trailers_and_maps_only_transport_bytes() {
    fn parse_dvb(input: &[u8]) -> Result<MpegTsVideo<'_>, TsError> {
        MpegTsVideo::parse_framed(
            input,
            TsFraming::Dvb204,
            TsSelection::default(),
            TsLimits::default(),
        )
    }
    for source in [AVC, HEVC] {
        let standard =
            MpegTsVideo::parse(source, TsSelection::default(), TsLimits::default()).unwrap();
        let framed: Vec<_> = source
            .as_chunks::<TS_PACKET_BYTES>()
            .0
            .iter()
            .flat_map(|packet| packet.iter().copied().chain([0x47; 16]))
            .collect();
        let parsed = parse_dvb(&framed).unwrap();
        assert_eq!(parsed.elementary_stream(), standard.elementary_stream());
        assert_eq!(parsed.pes(), standard.pes());
        assert_eq!(parsed.payload_spans().len(), standard.payload_spans().len());
        for (before, after) in standard.payload_spans().iter().zip(parsed.payload_spans()) {
            let shift = 16 * (before.source.start / TS_PACKET_BYTES);
            assert_eq!(
                after.source,
                before.source.start + shift..before.source.end + shift
            );
            assert_eq!(after.elementary, before.elementary);
        }
        let receipt = receipt::TsExtractionReceipt::from_extraction(&parsed).unwrap();
        let cold = receipt::TsExtractionReceipt::from_bytes(&receipt.to_bytes().unwrap()).unwrap();
        assert_eq!(cold.framing(), TsFraming::Dvb204);
        assert_eq!(
            cold.verify_with_checkpoint(&framed, &mut || Ok(()))
                .unwrap()
                .pes(),
            parsed.pes()
        );
        assert!(parse_dvb(source).is_err());
        for cut in 1..204 {
            assert_eq!(
                parse_dvb(&framed[..framed.len() - cut]).unwrap_err(),
                TsError::Truncated
            );
        }
        let mut changed = framed.clone();
        changed[TS_PACKET_BYTES] ^= 1;
        assert_eq!(
            parse_dvb(&changed).unwrap().elementary_stream(),
            parsed.elementary_stream()
        );
        assert_eq!(
            cold.verify_with_checkpoint(&changed, &mut || Ok(()))
                .unwrap_err(),
            TsError::Receipt
        );
    }
}
