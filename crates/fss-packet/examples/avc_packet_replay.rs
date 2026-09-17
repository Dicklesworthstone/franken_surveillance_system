#![forbid(unsafe_code)]
//! Deterministic, source-linked RTP-to-picture rehearsal over real synthetic H.264.
//! Run: cargo run --locked -p fss-packet --example avc_packet_replay

use fss_core::ContentDigest;
use fss_packet::avc::{
    AvcAssemblyStep, AvcPictureGroup, AvcReceiveLimits, AvcReceivePoll, AvcReceiver, parse_pps,
    parse_sps,
};
use fss_packet::{H264Mode, StreamKey};

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    replay(
        "baseline",
        include_bytes!("../tests/fixtures/avc/baseline.264"),
        &[90_000, 93_600, 97_200, 100_800],
    )?;
    replay(
        "high_cropped",
        include_bytes!("../tests/fixtures/avc/high_cropped.264"),
        &[90_000, 100_800, 93_600, 97_200, 108_000, 104_400],
    )
}

fn replay(name: &str, bytes: &[u8], times: &[u32]) -> Result<(), Error> {
    let nals = split(bytes);
    let limits = AvcReceiveLimits::default();
    let sps = parse_sps(nals.first().ok_or("fixture lacks SPS")?, limits.syntax)?;
    let pps = parse_pps(nals.get(1).ok_or("fixture lacks PPS")?, &sps, limits.syntax)?;
    let key = StreamKey {
        ingress: 17,
        generation: 1,
        ssrc: 7,
    };
    let mut r = AvcReceiver::new(key, 96, H264Mode::NonInterleaved, limits, (sps, pps))?;
    r.ingest(key, &packet(key, 0, times[0], nals[0]), 0)?;
    let mut frame = 0;
    let mut pictures = 0;
    for (index, nal) in nals.iter().enumerate() {
        let now = index as u64 + 1;
        let wire = packet(key, now as u16, times[frame.min(times.len() - 1)], nal);
        r.ingest(key, &wire, now)?;
        pictures += drain(&mut r, name, now, false)?;
        if matches!(nal[0] & 31, 1 | 5) {
            frame += 1;
        }
    }
    r.finish();
    pictures += drain(&mut r, name, 100, true)?;
    if pictures != times.len() || r.retained_nal_bytes() != 0 || r.queued_packets() != 0 {
        return Err("fixture did not reach expected picture count and quiescence".into());
    }
    println!(
        "{{\"kind\":\"terminal\",\"fixture\":\"{name}\",\"pictures\":{pictures},\"retained_bytes\":0,\"decoded_by_this_receiver\":false,\"qualification\":\"reference_rehearsal_only\"}}"
    );
    Ok(())
}

fn drain(r: &mut AvcReceiver, name: &str, now: u64, finishing: bool) -> Result<usize, Error> {
    let mut count = 0;
    for _ in 0..1_024 {
        match r.poll(now)? {
            AvcReceivePoll::Source {
                source,
                queued_nals,
                picture,
                fragment,
                gap_before,
                ..
            } => {
                if picture.is_some() || fragment.is_some() || gap_before {
                    return Err("clean source discontinuity".into());
                }
                let digest = ContentDigest::try_sha256(source.bytes())?.to_text();
                println!(
                    "{{\"kind\":\"source\",\"fixture\":\"{name}\",\"sequence\":{},\"digest\":\"{digest}\",\"queued_nals\":{queued_nals}}}",
                    source.sequence()
                );
            }
            AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => {
                if output.retired.is_some() {
                    return Err("clean assembly retired".into());
                }
                if let Some(picture) = output.picture {
                    report(name, &picture)?;
                    count += 1;
                }
            }
            AvcReceivePoll::Picture(picture) => {
                report(name, &picture)?;
                count += 1;
            }
            AvcReceivePoll::Pending { .. } if !finishing => return Ok(count),
            AvcReceivePoll::Ended {
                fragment: None,
                interrupted_picture: None,
                tail,
            } if finishing => {
                if let Some(tail) = tail {
                    if tail.retired.is_some() {
                        return Err("clean tail retired".into());
                    }
                    if let Some(picture) = tail.picture {
                        report(name, &picture)?;
                        count += 1;
                    }
                }
                return Ok(count);
            }
            other => return Err(format!("unexpected fixture transition: {other:?}").into()),
        }
    }
    Err("bounded poll count exceeded".into())
}

fn report(name: &str, picture: &AvcPictureGroup) -> Result<(), Error> {
    let (width, height) = picture.sps().display_dimensions();
    println!(
        "{{\"kind\":\"picture_group\",\"fixture\":\"{name}\",\"timestamp\":{},\"frame_num\":{},\"nals\":{},\"bytes\":{},\"width\":{width},\"height\":{height},\"boundary\":\"{:?}\",\"saw_first_macroblock\":{},\"discontinuity_before\":{},\"complete_picture_certified\":false}}",
        picture.timestamp(),
        picture.identity().frame_num(),
        picture.nals().len(),
        picture.byte_len(),
        picture.boundary(),
        picture.saw_first_macroblock(),
        picture.discontinuity_before()
    );
    for nal in picture.nals() {
        let digest = ContentDigest::try_sha256(nal.bytes())?.to_text();
        println!(
            "{{\"kind\":\"group_nal\",\"fixture\":\"{name}\",\"digest\":\"{digest}\",\"source_spans\":{}}}",
            nal.sources().len()
        );
    }
    Ok(())
}

fn packet(key: StreamKey, sequence: u16, timestamp: u32, nal: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80, 96];
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&key.ssrc.to_be_bytes());
    out.extend_from_slice(nal);
    out
}

// Laboratory-fixture framing only. Production ingress uses its bounded byte owner.
fn split(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = None;
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
            4
        } else if bytes[at..at + 3] == [0, 0, 1] {
            3
        } else {
            0
        };
        if prefix != 0 {
            if let Some(begin) = start {
                let mut end = at;
                while end > begin && bytes[end - 1] == 0 {
                    end -= 1;
                }
                if begin < end {
                    out.push(&bytes[begin..end]);
                }
            }
            start = Some(at + prefix);
            at += prefix;
        } else {
            at += 1;
        }
    }
    if let Some(begin) = start {
        if begin < bytes.len() {
            out.push(&bytes[begin..]);
        }
    }
    out
}
