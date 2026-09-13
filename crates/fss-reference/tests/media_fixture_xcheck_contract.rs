#![forbid(unsafe_code)]
//! Integration contract cross-check: verifies synthetic media fixtures using fss-packet public API.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_packet::{
    H264Depacketizer, H264Limits, H264Mode, H264Status, PacketLimits, RtpPacket, SequenceTracker,
    StreamKey,
};
use fss_reference::media_fixture::{
    H264AnnexBStream, H264FixtureParams, MediaFixtureError, RtpdumpFixture, RtpdumpParams,
    build_h264_manifest_json, build_rtp_manifest_json, generate_h264_annexb,
    generate_rtpdump_clean, generate_rtpdump_duplicate, generate_rtpdump_large_gap,
    generate_rtpdump_loss, generate_rtpdump_reorder, generate_rtpdump_ssrc_reset,
    generate_rtpdump_truncated_last_record,
};

type GenFn = fn(&H264AnnexBStream, &RtpdumpParams) -> Result<RtpdumpFixture, MediaFixtureError>;

fn root() -> Result<PathBuf, Box<dyn Error>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .ok_or("missing root ancestor")?;
    Ok(p)
}

fn records(bytes: &[u8]) -> (Vec<Vec<u8>>, bool) {
    let mut o = match bytes.iter().position(|&b| b == b'\n') {
        Some(p) => p + 1 + 16,
        None => return (Vec::new(), true),
    };
    let mut out = Vec::new();
    while o < bytes.len() {
        if o + 8 > bytes.len() {
            return (out, true);
        }
        let len = usize::from(u16::from_be_bytes([bytes[o], bytes[o + 1]]));
        if o + len > bytes.len() || len < 8 {
            return (out, true);
        }
        out.push(bytes[o + 8..o + len].to_vec());
        o += len;
    }
    (out, false)
}

#[test]
fn test_media_fixture_xcheck_with_fss_packet() -> Result<(), Box<dyn Error>> {
    let repo_root = root()?;
    let mut bad: Vec<String> = Vec::new();
    let hp = H264FixtureParams::default();
    let a1 = generate_h264_annexb(&hp)?;
    let a2 = generate_h264_annexb(&hp)?;
    let disk264 = fs::read(repo_root.join("tests/fixtures/media/h264/clean.264"))?;
    if a1.bytes != a2.bytes || disk264 != a1.bytes {
        bad.push("h264 determinism/disk".into());
    }
    let hman =
        fs::read_to_string(repo_root.join("tests/fixtures/media/h264/fixture_manifest.json"))?;
    let hman_regen = build_h264_manifest_json(&a1, &hp, "clean.264");
    if hman != hman_regen {
        bad.push("h264 manifest drift".into());
    }

    let rp = RtpdumpParams::default();
    let gens: [(&str, GenFn); 7] = [
        ("clean.rtp", generate_rtpdump_clean),
        ("loss.rtp", generate_rtpdump_loss),
        ("reorder.rtp", generate_rtpdump_reorder),
        ("duplicate.rtp", generate_rtpdump_duplicate),
        ("ssrc_reset.rtp", generate_rtpdump_ssrc_reset),
        (
            "truncated_last_record.rtp",
            generate_rtpdump_truncated_last_record,
        ),
        ("large_gap.rtp", generate_rtpdump_large_gap),
    ];
    let mut all = Vec::new();
    for (name, g) in gens {
        let f1 = g(&a1, &rp)?;
        let f2 = g(&a2, &rp)?;
        let disk = fs::read(repo_root.join("tests/fixtures/media/rtp").join(name))?;
        if f1.bytes != f2.bytes || disk != f1.bytes {
            bad.push(format!("{name} determinism/disk"));
        }

        // fss-packet public API pass over the committed bytes.
        let (recs, trunc) = records(&disk);
        if recs.len() != f1.packets.len() {
            bad.push(format!(
                "{name}: file has {} complete records (truncated={trunc}) but descriptors list {}",
                recs.len(),
                f1.packets.len()
            ));
        }
        let mut states: Vec<(u32, u64, SequenceTracker, H264Depacketizer)> = Vec::new();
        let mut delivered: Vec<Vec<u8>> = Vec::new();
        for (idx, rec) in recs.iter().enumerate() {
            let pkt = RtpPacket::parse(rec, PacketLimits::default())?;
            let ssrc = pkt.ssrc();
            if !states.iter().any(|s| s.0 == ssrc) {
                let generation = states.len() as u64 + 1;
                let key = StreamKey {
                    ingress: 1,
                    generation,
                    ssrc,
                };
                let tr = SequenceTracker::new(key, 96).map_err(|e| format!("{e}"))?;
                let dp =
                    H264Depacketizer::new(key, 96, H264Mode::NonInterleaved, H264Limits::default())
                        .map_err(|e| format!("{e}"))?;
                states.push((ssrc, generation, tr, dp));
            }
            let st = states
                .iter_mut()
                .find(|s| s.0 == ssrc)
                .ok_or("state missing")?;
            let key = StreamKey {
                ingress: 1,
                generation: st.1,
                ssrc,
            };
            let obs = st.2.observe(key, pkt).map_err(|e| format!("{e}"))?;
            let class = format!("{:?}", obs.class);
            let mut status = String::from("-");
            let mut dlv = false;
            let mut types = Vec::new();
            if let Some(ext) = obs.extended_sequence {
                match st.3.push(key, ext, pkt, idx as u64 * 1_000_000) {
                    Ok(out) => {
                        status = format!("{:?}", out.status);
                        dlv = matches!(
                            out.status,
                            H264Status::Complete | H264Status::FragmentPending
                        );
                        for n in &out.nals {
                            types.push(n.nal_type());
                            delivered.push(n.bytes().to_vec());
                        }
                    }
                    Err(e) => status = format!("ERR:{e}"),
                }
            }
            let (ec, ed) = match f1.packets.get(idx) {
                Some(d) => (d.expected_sequence_class.as_str().to_string(), d.expected_delivered),
                None => ("<none>".to_string(), false),
            };
            let ok = ec == class && ed == dlv;
            if !ok {
                bad.push(format!(
                    "{name} #{idx}: class {class}/{ec} delivered {dlv}/{ed} (depack={status})"
                ));
            }
        }
        if name == "clean.rtp" {
            let annex: Vec<Vec<u8>> = a1.nals.iter().map(|n| n.wire_bytes.clone()).collect();
            let ordered = delivered == annex;
            if !ordered {
                bad.push("clean ordered NAL equivalence".into());
            }
        }
        all.push(f1);
    }
    let rman =
        fs::read_to_string(repo_root.join("tests/fixtures/media/rtp/fixture_manifest.json"))?;
    let rman_regen = build_rtp_manifest_json(&all, &rp);
    if rman != rman_regen {
        bad.push("rtp manifest drift".into());
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!("{} mismatches: {bad:#?}", bad.len()).into())
    }
}
