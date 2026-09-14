#![forbid(unsafe_code)]
//! Property tests for H.264 Annex-B and RTP media fixtures.
//!
//! Verifies:
//! - Byte-exact NAL equivalence across >= 200 (seed, gop, frame_count, mtu, two_slice_au) configs
//!   between Annex-B output (split by an independent start-code scanner) and RTP depacketized NALs.
//! - Every NAL's final byte is strictly nonzero (rbsp_stop_one_bit + zero alignment).
//! - generate_rtpdump_ssrc_reset succeeds when MTU is small (150) and two_slice_au is false,
//!   correctly switching SSRC at packet index 4 and fragmenting the IDR slice via FU-A.

use std::error::Error;

use fss_reference::media_fixture::{
    ExpectedSequenceClass, H264FixtureParams, RtpdumpParams, generate_h264_annexb,
    generate_rtpdump_clean, generate_rtpdump_ssrc_reset,
};

/// Independent Annex-B start-code scanner written directly in the test suite.
/// Never references generator internals, SyntheticNal lists, or NalUnitSpan metadata.
fn independent_split_annexb(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut pos = Vec::new();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1 {
            pos.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut nals = Vec::with_capacity(pos.len());
    for k in 0..pos.len() {
        let p = pos[k];
        let mut e = if k + 1 < pos.len() {
            pos[k + 1] - 3
        } else {
            bytes.len()
        };
        while e > p && bytes[e - 1] == 0 {
            e -= 1;
        }
        nals.push(bytes[p..e].to_vec());
    }
    nals
}

/// Independent parser extracting raw RTP packet payloads from an rtpdump file.
fn independent_parse_rtpdump_records(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let nl = bytes
        .iter()
        .position(|&b| b == b'\n')
        .ok_or("missing magic newline in rtpdump")?;
    if &bytes[..=nl] != b"#!rtpplay1.0 0.0.0.0/0\n" {
        return Err("invalid rtpplay magic header".into());
    }
    let mut o = nl + 1 + 16; // skip 16-byte RD_hdr_t
    let mut out = Vec::new();
    while o < bytes.len() {
        if o + 8 > bytes.len() {
            return Err("truncated packet header in rtpdump".into());
        }
        let len = usize::from(u16::from_be_bytes([bytes[o], bytes[o + 1]]));
        if len < 8 || o + len > bytes.len() {
            return Err("invalid packet record length in rtpdump".into());
        }
        out.push(bytes[o + 8..o + len].to_vec());
        o += len;
    }
    Ok(out)
}

/// Independent RFC 6184 depacketizer: reassembles SingleNal, STAP-A, and FU-A into complete NALs.
/// Skips record 0 (the sacrificial probation AUD packet).
fn independent_depacketize_rtp(records: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut nals = Vec::new();
    let mut fu_buf: Option<Vec<u8>> = None;
    let mut fu_seq: Option<u16> = None;
    let mut expected_inner_type: Option<u8> = None;

    for (idx, r) in records.iter().enumerate().skip(1) {
        if r.len() < 12 {
            return Err(format!("record {idx} too short for 12-byte RTP header").into());
        }
        let version = r[0] >> 6;
        let payload_type = r[1] & 0x7f;
        if version != 2 || payload_type != 96 {
            return Err(format!("record {idx} unexpected V={version} PT={payload_type}").into());
        }
        let seq = u16::from_be_bytes([r[2], r[3]]);
        let p = &r[12..];
        if p.is_empty() {
            return Err(format!("record {idx} has empty RTP payload").into());
        }
        let nal_type = p[0] & 0x1f;

        if nal_type == 28 {
            // FU-A fragmentation unit
            if p.len() < 2 {
                return Err(format!("record {idx} FU-A payload too short").into());
            }
            let s_bit = (p[1] & 0x80) != 0;
            let e_bit = (p[1] & 0x40) != 0;
            let inner_type = p[1] & 0x1f;
            let reconstructed_header = (p[0] & 0xe0) | inner_type;

            if s_bit {
                if fu_buf.is_some() {
                    return Err(format!(
                        "record {idx} FU-A S-bit while previous fragment unclosed"
                    )
                    .into());
                }
                let mut buf = Vec::with_capacity(1 + p.len());
                buf.push(reconstructed_header);
                buf.extend_from_slice(&p[2..]);
                fu_buf = Some(buf);
                fu_seq = Some(seq);
                expected_inner_type = Some(inner_type);
            } else {
                let Some(ref mut buf) = fu_buf else {
                    return Err(format!("record {idx} FU-A continuation without start").into());
                };
                if fu_seq.map(|s| s.wrapping_add(1)) != Some(seq) {
                    return Err(format!("record {idx} FU-A sequence discontinuity").into());
                }
                if expected_inner_type != Some(inner_type) {
                    return Err(format!("record {idx} FU-A inner type drift").into());
                }
                buf.extend_from_slice(&p[2..]);
                fu_seq = Some(seq);
            }

            if e_bit {
                let buf = fu_buf.take().ok_or("missing FU-A buffer at end bit")?;
                nals.push(buf);
                expected_inner_type = None;
            }
        } else if nal_type == 24 {
            // STAP-A aggregation packet
            if fu_buf.is_some() {
                return Err(format!("record {idx} STAP-A inside open FU-A sequence").into());
            }
            let mut q = 1;
            while q + 2 <= p.len() {
                let nlen = usize::from(u16::from_be_bytes([p[q], p[q + 1]]));
                q += 2;
                if q + nlen > p.len() {
                    return Err(format!("record {idx} STAP-A truncated NAL entry").into());
                }
                nals.push(p[q..q + nlen].to_vec());
                q += nlen;
            }
        } else if (1..=23).contains(&nal_type) {
            // Single NAL unit packet
            if fu_buf.is_some() {
                return Err(format!("record {idx} Single NAL inside open FU-A sequence").into());
            }
            nals.push(p.to_vec());
        } else {
            return Err(format!("record {idx} unsupported NAL type {nal_type}").into());
        }
    }

    if fu_buf.is_some() {
        return Err("RTP stream ended with unclosed FU-A fragment".into());
    }

    Ok(nals)
}

#[test]
fn test_h264_annexb_rtp_nal_equivalence_property() -> Result<(), Box<dyn Error>> {
    // Systematic matrix yielding exactly 240 distinct parameter configurations.
    let seeds = [42u64, 99, 12345, 7, 31415, 65535, 1000, 2026, 88888, 54321];
    let gops = [1usize, 2, 3, 5];
    let frame_counts = [3usize, 5, 7];
    let mtus = [150usize, 300, 1200];
    let two_slice_options = [true, false];

    let mut total_configs = 0usize;
    let mut total_nals_verified = 0usize;

    for &seed in &seeds {
        for &gop in &gops {
            for &frames in &frame_counts {
                for &mtu in &mtus {
                    for &two_slice in &two_slice_options {
                        let h264_params = H264FixtureParams {
                            seed,
                            frame_count: frames,
                            gop_size: gop,
                            include_aud: true,
                            include_sei: true,
                            two_slice_au: two_slice,
                            force_emulation_prevention: true,
                            trailing_zeros: 1,
                        };

                        let annexb = generate_h264_annexb(&h264_params)?;
                        let annexb_nals = independent_split_annexb(&annexb.bytes);

                        let rtp_params = RtpdumpParams {
                            mtu,
                            ..RtpdumpParams::default()
                        };
                        let clean = generate_rtpdump_clean(&annexb, &rtp_params)?;
                        let records = independent_parse_rtpdump_records(&clean.bytes)?;
                        let rtp_nals = independent_depacketize_rtp(&records)?;

                        assert_eq!(
                            annexb_nals.len(),
                            rtp_nals.len(),
                            "config #{total_configs} (seed={seed}, gop={gop}, frames={frames}, mtu={mtu}, two_slice={two_slice}): NAL count mismatch"
                        );

                        for (nal_idx, (ab_nal, rtp_nal)) in
                            annexb_nals.iter().zip(&rtp_nals).enumerate()
                        {
                            // Every NAL's last byte must be strictly nonzero
                            let ab_last = ab_nal.last().copied().ok_or("empty annexb NAL")?;
                            assert_ne!(
                                ab_last, 0x00,
                                "config #{total_configs} annexb NAL {nal_idx} ends in 0x00"
                            );

                            let rtp_last = rtp_nal.last().copied().ok_or("empty rtp NAL")?;
                            assert_ne!(
                                rtp_last, 0x00,
                                "config #{total_configs} rtp NAL {nal_idx} ends in 0x00"
                            );

                            // Byte-exact equality between Annex-B and RTP depacketized NALs
                            assert_eq!(
                                ab_nal, rtp_nal,
                                "config #{total_configs} NAL {nal_idx} byte content mismatch"
                            );
                            total_nals_verified += 1;
                        }

                        total_configs += 1;
                    }
                }
            }
        }
    }

    assert!(
        total_configs >= 200,
        "must test at least 200 configs, observed {total_configs}"
    );
    assert!(
        total_nals_verified >= 1000,
        "must verify at least 1000 NALs, verified {total_nals_verified}"
    );

    Ok(())
}

#[test]
fn test_ssrc_reset_mtu150_single_slice_fua_succeeds() -> Result<(), Box<dyn Error>> {
    // Exercises the FU-A IDR slice path in generate_rtpdump_ssrc_reset
    // with MTU 150 and two_slice_au=false where no SingleNal IDR slice exists.
    let h264_params = H264FixtureParams {
        seed: 99,
        frame_count: 5,
        gop_size: 3,
        include_aud: true,
        include_sei: true,
        two_slice_au: false,
        force_emulation_prevention: false,
        trailing_zeros: 0,
    };
    let annexb = generate_h264_annexb(&h264_params)?;
    let rtp_params = RtpdumpParams {
        mtu: 150,
        ..RtpdumpParams::default()
    };

    let ssrc_reset = generate_rtpdump_ssrc_reset(&annexb, &rtp_params)?;

    // Generation 1: first 4 packets under original SSRC
    assert_eq!(ssrc_reset.packets[0].ssrc, rtp_params.ssrc);
    assert_eq!(ssrc_reset.packets[1].ssrc, rtp_params.ssrc);
    assert_eq!(ssrc_reset.packets[2].ssrc, rtp_params.ssrc);
    assert_eq!(ssrc_reset.packets[3].ssrc, rtp_params.ssrc);

    // Generation 2 begins at packet index 4: SSRC change must occur here
    let gen2_ssrc = ssrc_reset.packets[4].ssrc;
    assert_ne!(
        gen2_ssrc, rtp_params.ssrc,
        "SSRC change must occur at packet index 4"
    );
    assert_eq!(
        ssrc_reset.packets[4].expected_sequence_class,
        ExpectedSequenceClass::Probation
    );
    assert!(ssrc_reset.packets[4].is_sacrificial);

    // Packet index 5: baseline AUD
    assert_eq!(ssrc_reset.packets[5].ssrc, gen2_ssrc);
    assert_eq!(
        ssrc_reset.packets[5].expected_sequence_class,
        ExpectedSequenceClass::Baseline
    );
    assert!(!ssrc_reset.packets[5].is_sacrificial);

    // Every packet in generation 2 (packet index 4 onwards) must share gen2_ssrc
    for (i, p) in ssrc_reset.packets[4..].iter().enumerate() {
        assert_eq!(
            p.ssrc,
            gen2_ssrc,
            "packet index {} must share generation 2 SSRC",
            4 + i
        );
        assert_eq!(
            p.timestamp,
            180_000,
            "packet index {} must have generation 2 timestamp",
            4 + i
        );
    }

    // Packet index 6 onwards must be the FU-A fragments of the IDR slice
    let slice_fragments: Vec<_> = ssrc_reset.packets[6..].iter().collect();
    assert!(
        slice_fragments.len() > 1,
        "1400-byte IDR slice under MTU 150 must fragment into multiple FU-A packets"
    );

    for (frag_idx, frag) in slice_fragments.iter().enumerate() {
        assert_eq!(frag.packetization, "FU-A");
        assert_eq!(frag.nal_types, vec![5]);
        assert_eq!(
            frag.expected_sequence_class,
            ExpectedSequenceClass::Advanced
        );
        assert!(!frag.is_sacrificial);
        assert!(frag.expected_delivered);

        if frag_idx + 1 == slice_fragments.len() {
            assert!(
                frag.marker,
                "final FU-A fragment must have RTP marker bit set"
            );
        } else {
            assert!(
                !frag.marker,
                "non-final FU-A fragment {frag_idx} must NOT have RTP marker bit set"
            );
        }
    }

    Ok(())
}
