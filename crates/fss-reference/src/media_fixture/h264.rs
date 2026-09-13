#![forbid(unsafe_code)]
//! Deterministic synthetic H.264 Annex-B bitstream generator.
//!
//! Generates Annex-B elementary streams with structurally valid NAL units,
//! SPS/PPS, SEI, multi-slice access units, emulation prevention bytes, and
//! trailing zeros before start codes.
//!
//! Note on media decodability: all generated payloads have structurally valid
//! NAL syntax, slice headers, and packet framing; pictures are not decodable.

use super::{
    BitWriter, DeterministicMediaPrng, MEDIA_FIXTURE_NOTE, MediaFixtureError, rbsp_to_nal_wire,
};
use fss_core::ContentDigest;

/// Descriptor for a single NAL unit span within an Annex-B elementary stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NalUnitSpan {
    /// 0-based sequential NAL index within stream.
    pub index: usize,
    /// Byte offset in the stream where the NAL unit payload begins (after start code).
    pub offset: usize,
    /// Length of the NAL unit wire bytes in the stream (excluding start code).
    pub len: usize,
    /// Length of the preceding start code (3 or 4 bytes).
    pub start_code_len: usize,
    /// Number of trailing zero padding bytes preceding the start code.
    pub trailing_zeros_before: usize,
    /// NAL unit type (lower 5 bits of NAL header byte).
    pub nal_unit_type: u8,
    /// Human-readable NAL unit type name.
    pub nal_unit_type_name: &'static str,
    /// True if this NAL is an IDR slice (type 5).
    pub is_idr: bool,
    /// 0-based index of the containing access unit.
    pub access_unit_index: usize,
}

/// In-memory representation of a synthesized NAL unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticNal {
    /// NAL unit type (1..=23).
    pub nal_unit_type: u8,
    /// True if this NAL is an IDR slice (type 5).
    pub is_idr: bool,
    /// Access unit index.
    pub access_unit_index: usize,
    /// Complete wire bytes including NAL header and emulation prevention bytes.
    pub wire_bytes: Vec<u8>,
    /// Preceding start code length (3 or 4).
    pub start_code_len: usize,
    /// Preceding zero padding byte count.
    pub trailing_zeros_before: usize,
}

/// Generation parameters for synthetic H.264 Annex-B bitstream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H264FixtureParams {
    /// Deterministic PRNG seed.
    pub seed: u64,
    /// Total number of access units (frames) to produce.
    pub frame_count: usize,
    /// Group-of-pictures length (interval between IDR frames).
    pub gop_size: usize,
    /// Whether to include Access Unit Delimiters (type 9).
    pub include_aud: bool,
    /// Whether to include SEI user data (type 6).
    pub include_sei: bool,
    /// Whether at least one AU includes multiple slices (first_mb_in_slice > 0 on second slice).
    pub two_slice_au: bool,
    /// Whether to explicitly force 0x000003 emulation-prevention insertion patterns.
    pub force_emulation_prevention: bool,
    /// Base number of trailing zero padding bytes before selected start codes.
    pub trailing_zeros: usize,
}

impl Default for H264FixtureParams {
    fn default() -> Self {
        Self {
            seed: 42,
            frame_count: 5,
            gop_size: 5,
            include_aud: true,
            include_sei: true,
            two_slice_au: true,
            force_emulation_prevention: true,
            trailing_zeros: 1,
        }
    }
}

/// Complete synthesized Annex-B elementary stream with metadata spans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H264AnnexBStream {
    /// Complete concatenated byte stream.
    pub bytes: Vec<u8>,
    /// Exact byte spans and metadata for every NAL unit in the stream.
    pub nal_spans: Vec<NalUnitSpan>,
    /// Individual synthesized NAL units.
    pub nals: Vec<SyntheticNal>,
    /// Total access unit count.
    pub access_unit_count: usize,
    /// Hex-encoded SHA-256 digest of the byte stream.
    pub sha256: String,
}

/// Maps a NAL unit type byte (0..=31) to its canonical short name.
#[must_use]
pub const fn nal_type_name(t: u8) -> &'static str {
    match t & 0x1f {
        1 => "NonIDR",
        2 => "SliceDataA",
        3 => "SliceDataB",
        4 => "SliceDataC",
        5 => "IDR",
        6 => "SEI",
        7 => "SPS",
        8 => "PPS",
        9 => "AUD",
        10 => "EndSequence",
        11 => "EndStream",
        12 => "FillerData",
        24 => "STAP-A",
        28 => "FU-A",
        _ => "Unknown",
    }
}

/// Generates a valid minimal H.264 Baseline Profile Sequence Parameter Set (SPS).
#[must_use]
pub fn generate_sps(_seed: u64) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.write_bits(66, 8); // profile_idc = 66 (Baseline)
    writer.write_bits(0xc0, 8); // constraint_set0_flag=1, constraint_set1_flag=1
    writer.write_bits(10, 8); // level_idc = 10 (1.0)
    writer.write_ue(0); // seq_parameter_set_id = 0
    writer.write_ue(0); // log2_max_frame_num_minus4 = 0 (frame_num is 4 bits)
    writer.write_ue(0); // pic_order_cnt_type = 0
    writer.write_ue(0); // log2_max_pic_order_cnt_lsb_minus4 = 0 (4 bits)
    writer.write_ue(1); // max_num_ref_frames = 1
    writer.write_bit(0); // gaps_in_frame_num_value_allowed_flag = 0
    writer.write_ue(9); // pic_width_in_mbs_minus1 = 9 (160 px)
    writer.write_ue(7); // pic_height_in_map_units_minus1 = 7 (128 px)
    writer.write_bit(1); // frame_mbs_only_flag = 1
    writer.write_bit(1); // direct_8x8_inference_flag = 1
    writer.write_bit(0); // frame_cropping_flag = 0
    writer.write_bit(0); // vui_parameters_present_flag = 0
    writer.write_rbsp_trailing_bits();
    let rbsp = writer.finish();
    rbsp_to_nal_wire(0x67, &rbsp) // NRI=3, type=7 (SPS)
}

/// Generates a valid minimal H.264 Picture Parameter Set (PPS).
#[must_use]
pub fn generate_pps(_seed: u64) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.write_ue(0); // pic_parameter_set_id = 0
    writer.write_ue(0); // seq_parameter_set_id = 0
    writer.write_bit(0); // entropy_coding_mode_flag = 0 (CAVLC)
    writer.write_bit(0); // bottom_field_pic_order_in_frame_present_flag = 0
    writer.write_ue(0); // num_slice_groups_minus1 = 0
    writer.write_ue(0); // num_ref_idx_l0_default_active_minus1 = 0
    writer.write_ue(0); // num_ref_idx_l1_default_active_minus1 = 0
    writer.write_bit(0); // weighted_pred_flag = 0
    writer.write_bits(0, 2); // weighted_bipred_idc = 0
    writer.write_se(0); // pic_init_qp_minus26 = 0
    writer.write_se(0); // pic_init_qs_minus26 = 0
    writer.write_se(0); // chroma_qp_index_offset = 0
    writer.write_bit(0); // deblocking_filter_control_present_flag = 0
    writer.write_bit(0); // constrained_intra_pred_flag = 0
    writer.write_bit(0); // redundant_pic_cnt_present_flag = 0
    writer.write_rbsp_trailing_bits();
    let rbsp = writer.finish();
    rbsp_to_nal_wire(0x68, &rbsp) // NRI=3, type=8 (PPS)
}

/// Generates an Access Unit Delimiter (AUD, type 9).
#[must_use]
pub fn generate_aud(primary_pic_type: u8) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.write_bits(primary_pic_type as u64 & 0x07, 3);
    writer.write_rbsp_trailing_bits();
    let rbsp = writer.finish();
    rbsp_to_nal_wire(0x09, &rbsp) // NRI=0, type=9 (AUD)
}

/// Generates an SEI user_data_unregistered payload (type 6).
#[must_use]
pub fn generate_sei(_seed: u64, message: &str) -> Vec<u8> {
    let mut rbsp = Vec::new();
    // SEI message: payloadType = 5 (user_data_unregistered)
    rbsp.push(0x05);
    // Payload length: 16 bytes UUID + message bytes
    let payload_len = 16 + message.len();
    rbsp.push(payload_len as u8);
    // Fixed 16-byte UUID for FSS synthetic test fixture
    let uuid = [
        0x46, 0x53, 0x53, 0x5f, 0x53, 0x45, 0x49, 0x5f, 0x46, 0x49, 0x58, 0x54, 0x55, 0x52, 0x45,
        0x31,
    ];
    rbsp.extend_from_slice(&uuid);
    rbsp.extend_from_slice(message.as_bytes());
    // rbsp_trailing_bits
    rbsp.push(0x80);
    rbsp_to_nal_wire(0x06, &rbsp) // NRI=0, type=6 (SEI)
}

/// Generates a slice NAL (type 5 IDR or type 1 Non-IDR) with slice header syntax.
#[must_use]
pub fn generate_slice(
    is_idr: bool,
    first_mb_in_slice: u32,
    frame_num: u32,
    payload_target_len: usize,
    force_ep: bool,
    prng: &mut DeterministicMediaPrng,
) -> Vec<u8> {
    let mut writer = BitWriter::new();
    // first_mb_in_slice: ue(v)
    writer.write_ue(first_mb_in_slice);
    // slice_type: ue(v) -> 7 for I slice, 5 for P slice
    writer.write_ue(if is_idr { 7 } else { 5 });
    // pic_parameter_set_id: ue(v) = 0
    writer.write_ue(0);
    // frame_num: u(4)
    writer.write_bits(frame_num as u64 & 0x0f, 4);
    if is_idr {
        // idr_pic_id: ue(v) = 0
        writer.write_ue(0);
    }
    // pic_order_cnt_lsb: u(4)
    writer.write_bits((frame_num.wrapping_mul(2)) as u64 & 0x0f, 4);
    writer.write_rbsp_trailing_bits();
    let mut rbsp = writer.finish();

    // Fill synthetic macroblock payload
    let current_len = rbsp.len();
    let extra_needed = if payload_target_len > current_len {
        payload_target_len - current_len
    } else {
        64
    };
    let mut extra = vec![0u8; extra_needed];
    prng.fill_bytes(&mut extra);

    if force_ep {
        // Explicitly inject byte sequences exercising emulation prevention byte (0x03)
        // insertion across consecutive zero runs and trailing values <= 0x03.
        let ep_pattern = [
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x01,
            0x00, 0x00, 0x02,
            0x00, 0x00, 0x03,
        ];
        let pos = extra.len().min(16);
        extra.splice(pos..pos, ep_pattern);
    }
    rbsp.extend_from_slice(&extra);

    let nal_header = if is_idr {
        0x65 // NRI=3 (0b01100000), type=5
    } else {
        0x41 // NRI=2 (0b01000000), type=1
    };
    rbsp_to_nal_wire(nal_header, &rbsp)
}

/// Generates a complete deterministic Annex-B H.264 stream matching parameters.
pub fn generate_h264_annexb(
    params: &H264FixtureParams,
) -> Result<H264AnnexBStream, MediaFixtureError> {
    if params.frame_count == 0 {
        return Err(MediaFixtureError::InvalidParam("frame_count must be > 0"));
    }
    let mut prng = DeterministicMediaPrng::new(params.seed);
    let mut nals = Vec::new();

    for au_idx in 0..params.frame_count {
        let is_idr_au = au_idx % params.gop_size == 0;

        // AUD NAL
        if params.include_aud {
            let pic_type = if is_idr_au { 0 } else { 1 };
            let aud_wire = generate_aud(pic_type);
            nals.push(SyntheticNal {
                nal_unit_type: 9,
                is_idr: false,
                access_unit_index: au_idx,
                wire_bytes: aud_wire,
                start_code_len: 4,
                trailing_zeros_before: 0,
            });
        }

        // Parameter sets at IDR boundary
        if is_idr_au {
            let sps_wire = generate_sps(params.seed);
            nals.push(SyntheticNal {
                nal_unit_type: 7,
                is_idr: false,
                access_unit_index: au_idx,
                wire_bytes: sps_wire,
                start_code_len: 4,
                trailing_zeros_before: 0,
            });

            let pps_wire = generate_pps(params.seed);
            nals.push(SyntheticNal {
                nal_unit_type: 8,
                is_idr: false,
                access_unit_index: au_idx,
                wire_bytes: pps_wire,
                start_code_len: 4,
                trailing_zeros_before: 0,
            });

            if params.include_sei {
                let sei_wire = generate_sei(params.seed, "fss.media_fixture.synthetic.v1");
                nals.push(SyntheticNal {
                    nal_unit_type: 6,
                    is_idr: false,
                    access_unit_index: au_idx,
                    wire_bytes: sei_wire,
                    start_code_len: 4,
                    trailing_zeros_before: 0,
                });
            }

            // IDR slice 0 (first_mb_in_slice = 0, size 1400 bytes to exercise FU-A packetization)
            let slice0_wire = generate_slice(
                true,
                0,
                0,
                1400,
                params.force_emulation_prevention && au_idx == 0,
                &mut prng,
            );
            nals.push(SyntheticNal {
                nal_unit_type: 5,
                is_idr: true,
                access_unit_index: au_idx,
                wire_bytes: slice0_wire,
                start_code_len: 4,
                trailing_zeros_before: 0,
            });

            // AU 0 two-slice case: second slice has first_mb_in_slice = 40 (> 0) and 3-byte start code
            if params.two_slice_au && au_idx == 0 {
                let slice1_wire = generate_slice(true, 40, 0, 320, false, &mut prng);
                nals.push(SyntheticNal {
                    nal_unit_type: 5,
                    is_idr: true,
                    access_unit_index: au_idx,
                    wire_bytes: slice1_wire,
                    start_code_len: 3, // 3-byte start code
                    trailing_zeros_before: 0,
                });
            }
        } else {
            // Non-IDR AU: frame_num = au_idx
            let force_ep = params.force_emulation_prevention && au_idx == 2;
            let start_code_len = if au_idx == 3 { 3 } else { 4 };
            let trailing_zeros = if au_idx == 1 {
                params.trailing_zeros
            } else if au_idx == 2 {
                params.trailing_zeros.wrapping_add(1)
            } else {
                0
            };

            let slice_wire = generate_slice(
                false,
                0,
                au_idx as u32,
                if force_ep { 512 } else { 384 },
                force_ep,
                &mut prng,
            );
            nals.push(SyntheticNal {
                nal_unit_type: 1,
                is_idr: false,
                access_unit_index: au_idx,
                wire_bytes: slice_wire,
                start_code_len,
                trailing_zeros_before: trailing_zeros,
            });
        }
    }

    // Assemble the complete Annex-B stream and compute exact spans
    let mut bytes = Vec::new();
    let mut nal_spans = Vec::with_capacity(nals.len());

    for (idx, nal) in nals.iter().enumerate() {
        // Prepend trailing zeros before start code
        bytes.resize(bytes.len() + nal.trailing_zeros_before, 0x00);

        // Prepend start code (3-byte or 4-byte)
        if nal.start_code_len == 4 {
            bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        } else {
            bytes.extend_from_slice(&[0x00, 0x00, 0x01]);
        }

        let nal_offset = bytes.len();
        bytes.extend_from_slice(&nal.wire_bytes);
        let nal_len = nal.wire_bytes.len();

        nal_spans.push(NalUnitSpan {
            index: idx,
            offset: nal_offset,
            len: nal_len,
            start_code_len: nal.start_code_len,
            trailing_zeros_before: nal.trailing_zeros_before,
            nal_unit_type: nal.nal_unit_type,
            nal_unit_type_name: nal_type_name(nal.nal_unit_type),
            is_idr: nal.is_idr,
            access_unit_index: nal.access_unit_index,
        });
    }

    // Trailing zero at the very end of stream to ensure trailing_zero_8bits after final NAL
    bytes.push(0x00);

    let digest = ContentDigest::sha256(&bytes);
    let mut sha256 = String::with_capacity(64);
    for b in digest.bytes() {
        use std::fmt::Write;
        let _ = write!(sha256, "{:02x}", b);
    }

    Ok(H264AnnexBStream {
        bytes,
        nal_spans,
        nals,
        access_unit_count: params.frame_count,
        sha256,
    })
}

/// Builds the canonical per-family JSON manifest string for H.264 fixtures.
#[must_use]
pub fn build_h264_manifest_json(
    stream: &H264AnnexBStream,
    params: &H264FixtureParams,
    fixture_filename: &str,
) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("{\n");
    out.push_str("  \"schema\": \"fss.media_fixture.manifest.v1\",\n");
    out.push_str("  \"family\": \"h264\",\n");
    out.push_str(&format!("  \"note\": \"{MEDIA_FIXTURE_NOTE}\",\n"));
    out.push_str("  \"generator\": \"fss-reference::media_fixture::h264\",\n");
    out.push_str("  \"generator_version\": \"1.0.0\",\n");
    out.push_str("  \"fixtures\": [\n");
    out.push_str("    {\n");
    out.push_str(&format!("      \"name\": \"{fixture_filename}\",\n"));
    out.push_str("      \"format\": \"annex_b\",\n");
    out.push_str(&format!("      \"seed\": {},\n", params.seed));
    out.push_str(&format!("      \"sha256\": \"{}\",\n", stream.sha256));
    out.push_str(&format!("      \"byte_len\": {},\n", stream.bytes.len()));
    out.push_str(&format!("      \"note\": \"{MEDIA_FIXTURE_NOTE}\",\n"));
    out.push_str("      \"params\": {\n");
    out.push_str(&format!(
        "        \"frame_count\": {},\n",
        params.frame_count
    ));
    out.push_str(&format!("        \"gop_size\": {},\n", params.gop_size));
    out.push_str(&format!(
        "        \"include_aud\": {},\n",
        params.include_aud
    ));
    out.push_str(&format!(
        "        \"include_sei\": {},\n",
        params.include_sei
    ));
    out.push_str(&format!(
        "        \"two_slice_au\": {},\n",
        params.two_slice_au
    ));
    out.push_str(&format!(
        "        \"force_emulation_prevention\": {}\n",
        params.force_emulation_prevention
    ));
    out.push_str("      },\n");
    out.push_str(&format!(
        "      \"expected_nal_count\": {},\n",
        stream.nal_spans.len()
    ));
    out.push_str(&format!(
        "      \"expected_au_count\": {},\n",
        stream.access_unit_count
    ));
    out.push_str("      \"expected_nals\": [\n");

    for (i, span) in stream.nal_spans.iter().enumerate() {
        out.push_str("        {\n");
        out.push_str(&format!("          \"index\": {},\n", span.index));
        out.push_str(&format!("          \"offset\": {},\n", span.offset));
        out.push_str(&format!("          \"len\": {},\n", span.len));
        out.push_str(&format!(
            "          \"start_code_len\": {},\n",
            span.start_code_len
        ));
        out.push_str(&format!(
            "          \"trailing_zeros_before\": {},\n",
            span.trailing_zeros_before
        ));
        out.push_str(&format!(
            "          \"nal_unit_type\": {},\n",
            span.nal_unit_type
        ));
        out.push_str(&format!(
            "          \"nal_unit_type_name\": \"{}\",\n",
            span.nal_unit_type_name
        ));
        out.push_str(&format!("          \"is_idr\": {},\n", span.is_idr));
        out.push_str(&format!(
            "          \"access_unit_index\": {}\n",
            span.access_unit_index
        ));
        if i + 1 == stream.nal_spans.len() {
            out.push_str("        }\n");
        } else {
            out.push_str("        },\n");
        }
    }

    out.push_str("      ]\n");
    out.push_str("    }\n");
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}
