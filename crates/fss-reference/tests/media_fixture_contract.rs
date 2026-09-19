#![forbid(unsafe_code)]
//! Deterministic contract tests for H.264 Annex-B and rtpdump media fixtures.
//!
//! Verifies:
//! - Deterministic synthetic bitstream generation from seeds
//! - Exact NAL spans, AU boundaries, and two-slice AU structure
//! - SEI payload presence and trailing_zero_8bits before start codes
//! - 3-byte and 4-byte start codes
//! - Emulation prevention byte (0x03) insertion and absence of 0x000000/0x000001/0x000002
//! - rtpdump format compliance: #!rtpplay1.0 0.0.0.0/0, 16-byte RD_hdr_t, 8-byte RD_packet_t
//! - RFC 3550 A.1 sequence tracking: Probation, Baseline, Advanced, Reordered, Duplicate,
//!   DiscontinuitySuspected, and RestartRequired
//! - NAL equivalence between Annex-B and delivered RTP packets
//! - Byte-for-byte identity against committed fixture files and pinned SHA-256 literals

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::ContentDigest;
use fss_reference::media_fixture::{
    ExpectedSequenceClass, H264FixtureParams, MEDIA_FIXTURE_NOTE, RD_HDR_LEN, RD_PKT_HDR_LEN,
    RTPDUMP_MAGIC_HEADER, RtpdumpParams, build_h264_manifest_json, build_rtp_manifest_json,
    generate_h264_annexb, generate_rtpdump_clean, generate_rtpdump_duplicate,
    generate_rtpdump_large_gap, generate_rtpdump_loss, generate_rtpdump_reorder,
    generate_rtpdump_ssrc_reset, generate_rtpdump_truncated_last_record, nal_wire_to_rbsp,
};

/// Pinned SHA-256 digest literal for clean.264.
pub const PINNED_SHA256_H264_CLEAN: &str =
    "8c306a4717970585256481714c96b1e868206c83f7cfa964602878276a09eff8";

/// Pinned SHA-256 digest literal for clean.rtp.
pub const PINNED_SHA256_RTP_CLEAN: &str =
    "273e5af560d81731b4d8c2bf8f98c5275f0162b44863fbf47e3174a30b2b8ea6";

/// Pinned SHA-256 digest literal for loss.rtp.
pub const PINNED_SHA256_RTP_LOSS: &str =
    "906d031f04e70369162c08d1f17096a6933eccba8e7f0744aebe489911548fa2";

/// Pinned SHA-256 digest literal for reorder.rtp.
pub const PINNED_SHA256_RTP_REORDER: &str =
    "737bf714b7e8c7530eb5e6f42edb8e6d581916f63c3cb9f6346a115315429ce1";

/// Pinned SHA-256 digest literal for duplicate.rtp.
pub const PINNED_SHA256_RTP_DUPLICATE: &str =
    "02be7735e662cfd3ca8092837bb3b0f35601d5ebc87d29131b2e2600e4cbb0ab";

/// Pinned SHA-256 digest literal for ssrc_reset.rtp.
pub const PINNED_SHA256_RTP_SSRC_RESET: &str =
    "24b0cecc209a1fb46e4d99eb6f888d7fe1a928b9610ec409b0a662c5b0e4a0ed";

/// Pinned SHA-256 digest literal for truncated_last_record.rtp.
pub const PINNED_SHA256_RTP_TRUNCATED: &str =
    "a625bd71db64a2eb3d88aef1f8a27b1b0492b52cc9cfc3bbe80617677c585660";

/// Pinned SHA-256 digest literal for large_gap.rtp.
pub const PINNED_SHA256_RTP_LARGE_GAP: &str =
    "13b695dd9b62bf66072ccb1508f32636e4f135d1b184a16f3caab8226f13c142";

/// Formats a 32-byte digest slice as a 64-character lowercase hex string.
fn to_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Independent minimal start-code scanner for testing Annex-B streams without
/// production parsing helpers.
struct ScannedNal {
    offset: usize,
    len: usize,
    start_code_len: usize,
    header_byte: u8,
}

fn scan_annexb_start_codes(bytes: &[u8]) -> Vec<ScannedNal> {
    let mut nals = Vec::new();
    let mut i = 0;
    let mut last_nal_start: Option<(usize, usize)> = None;

    while i + 2 < bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 {
            if bytes[i + 2] == 1 {
                if let Some((prev_offset, prev_sc_len)) = last_nal_start {
                    let mut nal_end = i;
                    while nal_end > prev_offset && bytes[nal_end - 1] == 0 {
                        nal_end -= 1;
                    }
                    nals.push(ScannedNal {
                        offset: prev_offset,
                        len: nal_end - prev_offset,
                        start_code_len: prev_sc_len,
                        header_byte: bytes[prev_offset],
                    });
                }
                last_nal_start = Some((i + 3, 3));
                i += 3;
                continue;
            } else if i + 3 < bytes.len() && bytes[i + 2] == 0 && bytes[i + 3] == 1 {
                if let Some((prev_offset, prev_sc_len)) = last_nal_start {
                    let mut nal_end = i;
                    while nal_end > prev_offset && bytes[nal_end - 1] == 0 {
                        nal_end -= 1;
                    }
                    nals.push(ScannedNal {
                        offset: prev_offset,
                        len: nal_end - prev_offset,
                        start_code_len: prev_sc_len,
                        header_byte: bytes[prev_offset],
                    });
                }
                last_nal_start = Some((i + 4, 4));
                i += 4;
                continue;
            }
        }
        i += 1;
    }

    if let Some((prev_offset, prev_sc_len)) = last_nal_start {
        let mut nal_end = bytes.len();
        while nal_end > prev_offset && bytes[nal_end - 1] == 0 {
            nal_end -= 1;
        }
        nals.push(ScannedNal {
            offset: prev_offset,
            len: nal_end - prev_offset,
            start_code_len: prev_sc_len,
            header_byte: bytes[prev_offset],
        });
    }

    nals
}

/// Independent model of RFC 3550 A.1 sequence tracking for test verification.
#[derive(Debug)]
struct TestSequenceTracker {
    base_seq: Option<u64>,
    highest_seq: u64,
    probation: Option<u16>,
    seen: u128,
    bad_next: Option<u16>,
    restart_required: bool,
}

impl TestSequenceTracker {
    fn new() -> Self {
        Self {
            base_seq: None,
            highest_seq: 0,
            probation: None,
            seen: 0,
            bad_next: None,
            restart_required: false,
        }
    }

    fn step(&mut self, sequence: u16) -> ExpectedSequenceClass {
        if self.restart_required {
            return ExpectedSequenceClass::RestartRequired;
        }

        let Some(base) = self.base_seq else {
            if self.probation.map(|last| last.wrapping_add(1)) != Some(sequence) {
                self.probation = Some(sequence);
                return ExpectedSequenceClass::Probation;
            }
            let extended = u64::from(sequence);
            self.base_seq = Some(extended);
            self.highest_seq = extended;
            self.seen = 1;
            return ExpectedSequenceClass::Baseline;
        };

        let forward = sequence.wrapping_sub(self.highest_seq as u16);
        if forward != 0 && forward < 3_000 {
            let extended = self.highest_seq + u64::from(forward);
            self.seen = if forward >= 128 {
                1
            } else {
                (self.seen << forward) | 1
            };
            self.highest_seq = extended;
            self.bad_next = None;
            ExpectedSequenceClass::Advanced
        } else if forward == 0 || forward > u16::MAX - 127 {
            let behind = (self.highest_seq as u16).wrapping_sub(sequence);
            let extended = self.highest_seq.saturating_sub(u64::from(behind));
            if extended < base {
                return ExpectedSequenceClass::BeforeBaseline;
            }
            let mask = 1_u128 << behind;
            let class = if self.seen & mask != 0 {
                ExpectedSequenceClass::Duplicate
            } else {
                ExpectedSequenceClass::Reordered
            };
            self.seen |= mask;
            self.bad_next = None;
            class
        } else {
            if self.bad_next == Some(sequence) {
                self.restart_required = true;
                return ExpectedSequenceClass::RestartRequired;
            }
            self.bad_next = Some(sequence.wrapping_add(1));
            ExpectedSequenceClass::DiscontinuitySuspected
        }
    }
}

#[test]
fn test_h264_annexb_generation_and_structure() -> Result<(), Box<dyn Error>> {
    let params = H264FixtureParams::default();
    let stream = generate_h264_annexb(&params)?;

    assert!(!stream.bytes.is_empty());
    assert_eq!(stream.access_unit_count, 5);
    assert!(!stream.nal_spans.is_empty());

    let scanned = scan_annexb_start_codes(&stream.bytes);
    assert_eq!(
        scanned.len(),
        stream.nal_spans.len(),
        "scanned NAL count must match generated NAL count"
    );

    for (sc, span) in scanned.iter().zip(stream.nal_spans.iter()) {
        assert_eq!(sc.offset, span.offset);
        assert_eq!(sc.len, span.len);
        assert_eq!(sc.start_code_len, span.start_code_len);
        assert_eq!(sc.header_byte & 0x1f, span.nal_unit_type);
    }

    let has_sps = stream.nal_spans.iter().any(|s| s.nal_unit_type == 7);
    let has_pps = stream.nal_spans.iter().any(|s| s.nal_unit_type == 8);
    let has_aud = stream.nal_spans.iter().any(|s| s.nal_unit_type == 9);
    let has_sei = stream.nal_spans.iter().any(|s| s.nal_unit_type == 6);
    let has_idr = stream.nal_spans.iter().any(|s| s.nal_unit_type == 5);
    let has_non_idr = stream.nal_spans.iter().any(|s| s.nal_unit_type == 1);

    assert!(has_sps, "Annex-B fixture must include SPS (type 7)");
    assert!(has_pps, "Annex-B fixture must include PPS (type 8)");
    assert!(has_aud, "Annex-B fixture must include AUD (type 9)");
    assert!(has_sei, "Annex-B fixture must include SEI (type 6)");
    assert!(has_idr, "Annex-B fixture must include IDR (type 5)");
    assert!(has_non_idr, "Annex-B fixture must include non-IDR (type 1)");

    let au0_slices: Vec<_> = stream
        .nal_spans
        .iter()
        .filter(|s| s.access_unit_index == 0 && s.nal_unit_type == 5)
        .collect();
    assert_eq!(
        au0_slices.len(),
        2,
        "AU 0 must contain two slices (two-slice AU)"
    );

    let slice0_nal = &stream.bytes[au0_slices[0].offset..au0_slices[0].offset + au0_slices[0].len];
    let slice1_nal = &stream.bytes[au0_slices[1].offset..au0_slices[1].offset + au0_slices[1].len];

    let (_, slice0_rbsp) = nal_wire_to_rbsp(slice0_nal);
    let (_, slice1_rbsp) = nal_wire_to_rbsp(slice1_nal);

    assert_eq!(
        slice0_rbsp[0] & 0x80,
        0x80,
        "first slice must have first_mb_in_slice == 0"
    );

    assert_eq!(
        slice1_rbsp[0] & 0x80,
        0x00,
        "second slice must have first_mb_in_slice > 0 (leading zeros in Exp-Golomb)"
    );

    let has_trailing_zeros = stream.nal_spans.iter().any(|s| s.trailing_zeros_before > 0);
    assert!(
        has_trailing_zeros,
        "Annex-B fixture must include trailing_zero_8bits before at least one start code"
    );

    let has_3byte_sc = stream.nal_spans.iter().any(|s| s.start_code_len == 3);
    let has_4byte_sc = stream.nal_spans.iter().any(|s| s.start_code_len == 4);
    assert!(
        has_3byte_sc,
        "Annex-B fixture must include 3-byte start code"
    );
    assert!(
        has_4byte_sc,
        "Annex-B fixture must include 4-byte start code"
    );

    for span in &stream.nal_spans {
        let nal_wire = &stream.bytes[span.offset..span.offset + span.len];
        assert!(
            nal_wire.len() >= 2,
            "NAL wire length must be at least 2 bytes"
        );
        let payload = &nal_wire[1..];
        for window in payload.windows(3) {
            assert!(
                !(window[0] == 0 && window[1] == 0 && window[2] <= 2),
                "emulation prevention violation: found 0x00000{:02x} in NAL payload",
                window[2]
            );
        }
    }
    Ok(())
}

#[test]
fn test_rtpdump_format_and_variants() -> Result<(), Box<dyn Error>> {
    let h264_params = H264FixtureParams::default();
    let annexb = generate_h264_annexb(&h264_params)?;
    let rtp_params = RtpdumpParams::default();

    let clean = generate_rtpdump_clean(&annexb, &rtp_params)?;
    let loss = generate_rtpdump_loss(&annexb, &rtp_params)?;
    let reorder = generate_rtpdump_reorder(&annexb, &rtp_params)?;
    let duplicate = generate_rtpdump_duplicate(&annexb, &rtp_params)?;
    let ssrc_reset = generate_rtpdump_ssrc_reset(&annexb, &rtp_params)?;
    let truncated = generate_rtpdump_truncated_last_record(&annexb, &rtp_params)?;
    let large_gap = generate_rtpdump_large_gap(&annexb, &rtp_params)?;

    let all_fixtures = [
        &clean,
        &loss,
        &reorder,
        &duplicate,
        &ssrc_reset,
        &truncated,
        &large_gap,
    ];

    for fix in all_fixtures {
        assert!(
            fix.bytes.starts_with(RTPDUMP_MAGIC_HEADER),
            "{}: rtpdump file must start with #!rtpplay1.0 0.0.0.0/0\\n",
            fix.variant_name
        );

        let rd_hdr =
            &fix.bytes[RTPDUMP_MAGIC_HEADER.len()..RTPDUMP_MAGIC_HEADER.len() + RD_HDR_LEN];
        assert_eq!(
            rd_hdr, &[0u8; 16],
            "{}: RD_hdr_t must be all zero",
            fix.variant_name
        );

        if !fix.is_truncated {
            let mut offset = RTPDUMP_MAGIC_HEADER.len() + RD_HDR_LEN;
            let mut record_sum = 0usize;
            while offset + RD_PKT_HDR_LEN <= fix.bytes.len() {
                let length =
                    u16::from_be_bytes([fix.bytes[offset], fix.bytes[offset + 1]]) as usize;
                let plen =
                    u16::from_be_bytes([fix.bytes[offset + 2], fix.bytes[offset + 3]]) as usize;
                assert_eq!(
                    length,
                    RD_PKT_HDR_LEN + plen,
                    "{}: length must equal RD_PKT_HDR_LEN + plen",
                    fix.variant_name
                );

                let rtp_offset = offset + RD_PKT_HDR_LEN;
                assert!(
                    rtp_offset + 12 <= fix.bytes.len(),
                    "{}: rtp header must fit",
                    fix.variant_name
                );
                let byte0 = fix.bytes[rtp_offset];
                assert_eq!(byte0 >> 6, 2, "{}: RTP version must be 2", fix.variant_name);
                let byte1 = fix.bytes[rtp_offset + 1];
                assert_eq!(
                    byte1 & 0x7f,
                    rtp_params.payload_type,
                    "{}: RTP payload type must be {}",
                    fix.variant_name,
                    rtp_params.payload_type
                );

                record_sum += length;
                offset += length;
            }
            assert_eq!(
                offset,
                fix.bytes.len(),
                "{}: all bytes accounted for in records",
                fix.variant_name
            );
            assert_eq!(
                record_sum + RTPDUMP_MAGIC_HEADER.len() + RD_HDR_LEN,
                fix.bytes.len(),
                "{}: record lengths sum must equal file size",
                fix.variant_name
            );
        }
    }

    assert!(clean.packets[0].is_sacrificial);
    assert_eq!(
        clean.packets[0].expected_sequence_class,
        ExpectedSequenceClass::Probation
    );
    assert!(!clean.packets[0].expected_delivered);
    assert_eq!(clean.packets[0].sequence, 65_534);

    assert!(!clean.packets[1].is_sacrificial);
    assert_eq!(
        clean.packets[1].expected_sequence_class,
        ExpectedSequenceClass::Baseline
    );
    assert!(clean.packets[1].expected_delivered);
    assert_eq!(clean.packets[1].sequence, 65_535);

    assert_eq!(clean.packets[2].sequence, 0);
    assert_eq!(
        clean.packets[2].expected_sequence_class,
        ExpectedSequenceClass::Advanced
    );

    let mut tracker = TestSequenceTracker::new();
    for pkt in &clean.packets {
        let observed = tracker.step(pkt.sequence);
        assert_eq!(
            observed, pkt.expected_sequence_class,
            "packet seq {} classification mismatch",
            pkt.sequence
        );
    }

    assert_eq!(loss.missing_sequences, vec![1]);
    assert!(
        !loss.packets.iter().any(|p| p.sequence == 1),
        "loss fixture must not contain dropped sequence 1"
    );

    assert_eq!(
        reorder.packets[2].expected_sequence_class,
        ExpectedSequenceClass::Advanced
    );
    assert_eq!(
        reorder.packets[3].expected_sequence_class,
        ExpectedSequenceClass::Reordered
    );
    assert!(!reorder.packets[3].expected_delivered);

    let dup_count = duplicate.packets.iter().filter(|p| p.sequence == 0).count();
    assert_eq!(dup_count, 2, "duplicate fixture must contain seq 0 twice");
    assert_eq!(
        duplicate.packets[3].expected_sequence_class,
        ExpectedSequenceClass::Duplicate
    );
    assert!(!duplicate.packets[3].expected_delivered);

    let gen1_first = &ssrc_reset.packets[0];
    assert!(gen1_first.is_sacrificial);
    assert_eq!(
        gen1_first.expected_sequence_class,
        ExpectedSequenceClass::Probation
    );

    let gen2_first = &ssrc_reset.packets[4];
    assert!(gen2_first.is_sacrificial);
    assert_eq!(
        gen2_first.expected_sequence_class,
        ExpectedSequenceClass::Probation
    );
    assert_ne!(gen1_first.ssrc, gen2_first.ssrc);
    for pkt in &ssrc_reset.packets[4..] {
        assert_eq!(pkt.timestamp, 180_000);
        assert_eq!(pkt.ssrc, gen2_first.ssrc);
    }
    assert!(
        ssrc_reset.packets[6].marker,
        "last packet of ssrc_reset gen2 must have marker bit set"
    );

    assert_eq!(
        truncated.packets.len(),
        14,
        "truncated fixture descriptors must exclude partial record"
    );
    assert!(truncated.is_truncated);

    assert_eq!(
        large_gap.packets[4].expected_sequence_class,
        ExpectedSequenceClass::DiscontinuitySuspected
    );
    assert_eq!(
        large_gap.packets[5].expected_sequence_class,
        ExpectedSequenceClass::RestartRequired
    );
    assert_eq!(
        large_gap.packets[6].expected_sequence_class,
        ExpectedSequenceClass::RestartRequired
    );

    Ok(())
}

#[test]
fn test_manifest_formatting_and_disclaimer() -> Result<(), Box<dyn Error>> {
    let h264_params = H264FixtureParams::default();
    let annexb = generate_h264_annexb(&h264_params)?;
    let rtp_params = RtpdumpParams::default();
    let clean = generate_rtpdump_clean(&annexb, &rtp_params)?;

    let h264_manifest = build_h264_manifest_json(&annexb, &h264_params, "clean.264");
    assert!(
        h264_manifest.contains(MEDIA_FIXTURE_NOTE),
        "H.264 manifest must include explicit non-decodability note"
    );

    let rtp_manifest = build_rtp_manifest_json(&[clean], &rtp_params);
    assert!(
        rtp_manifest.contains(MEDIA_FIXTURE_NOTE),
        "RTP manifest must include explicit non-decodability note"
    );
    Ok(())
}

#[test]
fn test_committed_fixtures_regeneration_identity() -> Result<(), Box<dyn Error>> {
    let h264_params = H264FixtureParams::default();
    let annexb = generate_h264_annexb(&h264_params)?;
    let rtp_params = RtpdumpParams::default();

    let clean = generate_rtpdump_clean(&annexb, &rtp_params)?;
    let loss = generate_rtpdump_loss(&annexb, &rtp_params)?;
    let reorder = generate_rtpdump_reorder(&annexb, &rtp_params)?;
    let duplicate = generate_rtpdump_duplicate(&annexb, &rtp_params)?;
    let ssrc_reset = generate_rtpdump_ssrc_reset(&annexb, &rtp_params)?;
    let truncated = generate_rtpdump_truncated_last_record(&annexb, &rtp_params)?;
    let large_gap = generate_rtpdump_large_gap(&annexb, &rtp_params)?;

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .ok_or("cannot find repo root")?;

    let h264_file = repo_root.join("tests/fixtures/media/h264/clean.264");
    assert!(
        h264_file.is_file(),
        "committed clean.264 must exist on disk"
    );
    let on_disk = fs::read(&h264_file)?;
    assert_eq!(
        on_disk, annexb.bytes,
        "committed clean.264 must match regenerated bytes byte-for-byte"
    );
    let digest_on_disk = to_hex(&ContentDigest::sha256(&on_disk).bytes());
    assert_eq!(digest_on_disk, PINNED_SHA256_H264_CLEAN);

    let rtp_files = [
        ("clean.rtp", &clean, PINNED_SHA256_RTP_CLEAN),
        ("loss.rtp", &loss, PINNED_SHA256_RTP_LOSS),
        ("reorder.rtp", &reorder, PINNED_SHA256_RTP_REORDER),
        ("duplicate.rtp", &duplicate, PINNED_SHA256_RTP_DUPLICATE),
        ("ssrc_reset.rtp", &ssrc_reset, PINNED_SHA256_RTP_SSRC_RESET),
        (
            "truncated_last_record.rtp",
            &truncated,
            PINNED_SHA256_RTP_TRUNCATED,
        ),
        ("large_gap.rtp", &large_gap, PINNED_SHA256_RTP_LARGE_GAP),
    ];

    for (fname, fix, pinned_sha) in rtp_files {
        let rtp_path = repo_root.join("tests/fixtures/media/rtp").join(fname);
        assert!(rtp_path.is_file(), "committed {fname} must exist on disk");
        let on_disk = fs::read(&rtp_path)?;
        assert_eq!(
            on_disk, fix.bytes,
            "committed {fname} must match regenerated bytes byte-for-byte"
        );
        let digest_on_disk = to_hex(&ContentDigest::sha256(&on_disk).bytes());
        assert_eq!(digest_on_disk, pinned_sha);
    }
    Ok(())
}

#[test]
fn test_committed_manifests_match_regenerated() -> Result<(), Box<dyn Error>> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .ok_or("cannot find repo root")?;

    let h264_params = H264FixtureParams::default();
    let annexb = generate_h264_annexb(&h264_params)?;
    let h264_man_path = repo_root.join("tests/fixtures/media/h264/fixture_manifest.json");
    assert!(
        h264_man_path.is_file(),
        "tests/fixtures/media/h264/fixture_manifest.json must exist"
    );
    let h264_man_disk = fs::read_to_string(&h264_man_path)?;
    let h264_man_regen = build_h264_manifest_json(&annexb, &h264_params, "clean.264");
    assert_eq!(
        h264_man_disk, h264_man_regen,
        "committed h264 fixture_manifest.json must match regenerated"
    );

    let rtp_params = RtpdumpParams::default();
    let clean = generate_rtpdump_clean(&annexb, &rtp_params)?;
    let loss = generate_rtpdump_loss(&annexb, &rtp_params)?;
    let reorder = generate_rtpdump_reorder(&annexb, &rtp_params)?;
    let duplicate = generate_rtpdump_duplicate(&annexb, &rtp_params)?;
    let ssrc_reset = generate_rtpdump_ssrc_reset(&annexb, &rtp_params)?;
    let truncated = generate_rtpdump_truncated_last_record(&annexb, &rtp_params)?;
    let large_gap = generate_rtpdump_large_gap(&annexb, &rtp_params)?;
    let all_fixtures = [
        clean, loss, reorder, duplicate, ssrc_reset, truncated, large_gap,
    ];

    let rtp_man_path = repo_root.join("tests/fixtures/media/rtp/fixture_manifest.json");
    assert!(
        rtp_man_path.is_file(),
        "tests/fixtures/media/rtp/fixture_manifest.json must exist"
    );
    let rtp_man_disk = fs::read_to_string(&rtp_man_path)?;
    let rtp_man_regen = build_rtp_manifest_json(&all_fixtures, &rtp_params);
    assert_eq!(
        rtp_man_disk, rtp_man_regen,
        "committed rtp fixture_manifest.json must match regenerated"
    );

    Ok(())
}

#[test]
fn test_structural_fua_and_marker_bits() -> Result<(), Box<dyn Error>> {
    let h264_params = H264FixtureParams::default();
    let annexb = generate_h264_annexb(&h264_params)?;
    let rtp_params = RtpdumpParams::default();
    let clean = generate_rtpdump_clean(&annexb, &rtp_params)?;

    // Parse RTP packets from clean.bytes
    let mut offset = RTPDUMP_MAGIC_HEADER.len() + RD_HDR_LEN;
    let mut rtp_packets = Vec::new();
    while offset + RD_PKT_HDR_LEN <= clean.bytes.len() {
        let length = u16::from_be_bytes([clean.bytes[offset], clean.bytes[offset + 1]]) as usize;
        let rtp_bytes = &clean.bytes[offset + RD_PKT_HDR_LEN..offset + length];
        rtp_packets.push(rtp_bytes);
        offset += length;
    }

    assert_eq!(rtp_packets.len(), clean.packets.len());

    let mut found_fua = false;
    let mut in_fua = false;
    let mut fua_inner_type = 0u8;
    for (idx, rtp_wire) in rtp_packets.iter().enumerate() {
        assert!(rtp_wire.len() >= 12);
        let m_bit = (rtp_wire[1] & 0x80) != 0;
        let payload = &rtp_wire[12..];
        assert!(!payload.is_empty());

        let nal_header = payload[0];
        let nal_type = nal_header & 0x1f;

        if nal_type == 28 {
            found_fua = true;
            assert!(payload.len() >= 2);
            let fu_header = payload[1];
            let s_bit = (fu_header & 0x80) != 0;
            let e_bit = (fu_header & 0x40) != 0;
            let r_bit = (fu_header & 0x20) != 0;

            // Structural FU-A assertions (M2 guard against corrupted reserved/end bits)
            assert!(!r_bit, "pkt {idx}: FU-A reserved bit must be 0 (M2 guard)");
            assert!(
                !(s_bit && e_bit),
                "pkt {idx}: FU-A S and E cannot both be set"
            );
            let inner_type = fu_header & 0x1f;
            assert!(
                (1..=23).contains(&inner_type),
                "pkt {idx}: FU-A inner type {inner_type} must be valid"
            );

            // F2 / M1 guard: assert S on first fragment, E on last, and fragment contiguity
            if !in_fua {
                assert!(
                    s_bit,
                    "pkt {idx}: first FU-A fragment must have S bit set (M1 guard)"
                );
                assert!(
                    !e_bit,
                    "pkt {idx}: first FU-A fragment must not have E bit set"
                );
                in_fua = true;
                fua_inner_type = inner_type;
            } else {
                assert!(
                    !s_bit,
                    "pkt {idx}: continuation FU-A fragment must not have S bit set (M1 guard)"
                );
                assert_eq!(
                    inner_type, fua_inner_type,
                    "pkt {idx}: FU-A continuation fragment inner type {inner_type} differs from start {fua_inner_type}"
                );
                if e_bit {
                    in_fua = false;
                }
            }

            if m_bit {
                assert!(
                    e_bit,
                    "pkt {idx}: RTP marker bit on FU-A packet may only be set if FU-A E bit is set"
                );
            }
        } else {
            assert!(
                !in_fua,
                "pkt {idx}: non-FU-A packet (nal_type={nal_type}) observed while FU-A fragment sequence was incomplete"
            );
        }
    }
    assert!(!in_fua, "FU-A sequence did not terminate with an E bit");
    assert!(found_fua, "clean.rtp must exercise FU-A fragmentation");

    // Group packets by access unit timestamp and verify marker bit placement (M5 guard)
    let mut current_ts = None;
    let mut au_packets: Vec<(usize, bool)> = Vec::new();

    for (idx, desc) in clean.packets.iter().enumerate() {
        if current_ts != Some(desc.timestamp) {
            if current_ts.is_some() {
                assert!(
                    !au_packets.is_empty(),
                    "access unit must have at least one packet"
                );
                // All packets in AU except the last must have marker == false
                for &(p_idx, marker) in &au_packets[..au_packets.len() - 1] {
                    assert!(
                        !marker,
                        "pkt {p_idx} in AU must NOT have marker bit set (M5 guard)"
                    );
                }
                // The last packet in AU must have marker == true
                let (last_idx, last_marker) = au_packets[au_packets.len() - 1];
                assert!(
                    last_marker,
                    "last pkt {last_idx} in AU must have marker bit set (M5 guard)"
                );
            }
            current_ts = Some(desc.timestamp);
            au_packets.clear();
        }
        au_packets.push((idx, desc.marker));
    }

    // Check final AU
    if !au_packets.is_empty() {
        for &(p_idx, marker) in &au_packets[..au_packets.len() - 1] {
            assert!(
                !marker,
                "pkt {p_idx} in AU must NOT have marker bit set (M5 guard)"
            );
        }
        let (last_idx, last_marker) = au_packets[au_packets.len() - 1];
        assert!(
            last_marker,
            "last pkt {last_idx} in AU must have marker bit set (M5 guard)"
        );
    }

    Ok(())
}

#[test]
fn test_nal_wire_to_rbsp_escapes_only_when_next_byte_le_3() {
    // When 0x00, 0x00, 0x03 is followed by byte <= 3, unescapes
    let wire_unescape = [0x65, 0x00, 0x00, 0x03, 0x01, 0xAA];
    let (hdr, rbsp) = nal_wire_to_rbsp(&wire_unescape);
    assert_eq!(hdr, 0x65);
    assert_eq!(rbsp, vec![0x00, 0x00, 0x01, 0xAA]);

    // When 0x00, 0x00, 0x03 is followed by byte > 3, preserves 0x03
    let wire_preserve = [0x65, 0x00, 0x00, 0x03, 0x04, 0xAA];
    let (hdr, rbsp) = nal_wire_to_rbsp(&wire_preserve);
    assert_eq!(hdr, 0x65);
    assert_eq!(rbsp, vec![0x00, 0x00, 0x03, 0x04, 0xAA]);

    // When 0x00, 0x00, 0x03 is at end of NAL (i+3 >= len), unescapes
    let wire_end = [0x65, 0x00, 0x00, 0x03];
    let (hdr, rbsp) = nal_wire_to_rbsp(&wire_end);
    assert_eq!(hdr, 0x65);
    assert_eq!(rbsp, vec![0x00, 0x00]);
}

/// The ssrc_reset fixture must build even when generation 1 delivered the IDR as FU-A fragments
/// (small MTU, two_slice_au=false): the reset generation re-emits the IDR whole as a single-NAL
/// packet taken from the stream's own NAL list. Pins the fss-vnn0q defect where the builder
/// only looked for a SingleNal slice packet and failed with "missing slice packet in proto".
#[test]
fn ssrc_reset_builds_when_idr_is_fragmented_as_fu_a() -> Result<(), Box<dyn Error>> {
    let h264_params = H264FixtureParams {
        seed: 99,
        frame_count: 5,
        gop_size: 7,
        two_slice_au: false,
        ..H264FixtureParams::default()
    };
    let annexb = generate_h264_annexb(&h264_params)?;
    let rtp_params = RtpdumpParams {
        mtu: 150,
        ..RtpdumpParams::default()
    };
    let ssrc_reset = generate_rtpdump_ssrc_reset(&annexb, &rtp_params)?;

    // Generation 2 closes with a whole single-NAL IDR slice under the new SSRC.
    let last = ssrc_reset
        .packets
        .last()
        .ok_or_else(|| -> Box<dyn Error> { "ssrc_reset fixture has no packets".into() })?;
    assert_eq!(last.ssrc, 0x5566_7788);
    assert_eq!(last.packetization, "SingleNal");
    assert_eq!(last.nal_types, vec![5]);
    assert!(last.marker);
    assert!(last.expected_delivered);
    let idr_wire = &annexb
        .nals
        .iter()
        .find(|nal| nal.nal_unit_type == 5)
        .ok_or_else(|| -> Box<dyn Error> { "stream has no IDR NAL".into() })?
        .wire_bytes;
    // RtpdumpPacketDesc carries lengths, not payload bytes: 12-byte RTP header + whole NAL.
    assert_eq!(last.packet_len, 12 + idr_wire.len());
    Ok(())
}
