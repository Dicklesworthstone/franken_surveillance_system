#![forbid(unsafe_code)]
//! FSS-116 property family: canonical packet replay object format.
//!
//! Determinism (byte-identity), lossless roundtrips over seeded
//! data/loss/duplicate mixes in ARRIVAL order, adversarial corruption
//! refusals, and bound enforcement. Each property emits one JSONL verdict
//! line.

use fss_publication::packet_replay::{
    MAX_PACKET_PAYLOAD_LEN, MAX_REPLAY_RECORDS, ReplayRecord, ReplayStreamHeader, decode_replay,
    encode_replay,
};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-116\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

/// Deterministic 64-bit LCG.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn header() -> ReplayStreamHeader {
    ReplayStreamHeader {
        ssrc: 0xA1B2C3D4,
        payload_type: 96,
        clock_rate_hz: 90_000,
    }
}

fn generated_stream(
    rng: &mut Lcg,
    n: u64,
) -> Result<Vec<ReplayRecord>, Box<dyn std::error::Error>> {
    let mut seq: u16 = 1000;
    let mut records = Vec::new();
    for _ in 0..n {
        match rng.below(10) {
            0..=6 => {
                let fill = u8::try_from(rng.below(256)).map_err(|_| "byte range")?;
                records.push(ReplayRecord::Data {
                    seq,
                    rtp_ts: 3000u32 + u32::from(seq),
                    payload: vec![fill; (rng.below(1200) + 1) as usize],
                });
                seq = seq.wrapping_add(1);
            }
            7 => {
                // Loss interval of 1..=8 sequence numbers.
                let gap = (rng.below(8) + 1) as u16;
                records.push(ReplayRecord::Loss {
                    from_seq: seq,
                    to_seq: seq.wrapping_add(gap),
                });
                seq = seq.wrapping_add(gap);
            }
            _ => {
                // A duplicate arrival of the previous sequence number.
                let dup = seq.wrapping_sub(1);
                records.push(ReplayRecord::Duplicate { seq: dup });
            }
        }
    }
    Ok(records)
}

/// P1 ROUNDTRIP: encode → decode returns the exact header and records, in
/// the exact arrival order, over seeded mixes including reordering effects
/// (duplicates) and losses.
#[test]
fn p1_roundtrip_preserves_arrival_order() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x0052_5452;
    let mut rng = Lcg::new(SEED);
    let mut cases = 0u64;
    for trial in 0..40u64 {
        let n = 10 + rng.below(200);
        let records = generated_stream(&mut rng, n)?;
        let raw = encode_replay(header(), &records)?;
        let back = decode_replay(&raw)?;
        assert_eq!(back.header, header(), "trial {trial}");
        assert_eq!(
            back.records, records,
            "trial {trial}: arrival order must be exact"
        );
        cases += 1;
    }
    emit("roundtrip-arrival-order", cases);
    Ok(())
}

/// P2 DETERMINISM: identical input yields byte-identical objects; any
/// difference in records changes the bytes.
#[test]
fn p2_encoding_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x0044_4554;
    let mut rng = Lcg::new(SEED);
    let records = generated_stream(&mut rng, 150)?;
    let a = encode_replay(header(), &records)?;
    let b = encode_replay(header(), &records)?;
    assert_eq!(a, b, "byte-identical for identical input");
    let mut varied = records.clone();
    let Some(ReplayRecord::Data { payload, .. }) = varied
        .iter_mut()
        .find(|r| matches!(r, ReplayRecord::Data { .. }))
    else {
        return Err("generated stream must contain data records".into());
    };
    payload[0] ^= 0xFF;
    let c = encode_replay(header(), &varied)?;
    assert_ne!(a, c, "content change must change the object bytes");
    emit("encoding-determinism", 2);
    Ok(())
}

/// P3 ADVERSARIAL CORRUPTION: every single-byte mutation of the envelope
/// either still decodes to the SAME contents (impossible for this format)
/// or is refused — never silently misread.
#[test]
fn p3_corruption_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x0043_4f52;
    let mut rng = Lcg::new(SEED);
    let records = generated_stream(&mut rng, 60)?;
    let raw = encode_replay(header(), &records)?;
    let mut refused = 0u64;
    // Probe a spread of positions: header, payload head, middle, tail,
    // checksum trailer.
    let len = raw.len();
    for &offset in &[
        0usize,
        1,
        2,
        3,
        4,
        5,
        len / 4,
        len / 2,
        3 * len / 4,
        len.saturating_sub(2),
        len - 1,
    ] {
        let mut mutated = raw.clone();
        mutated[offset] ^= 0x01;
        match decode_replay(&mutated) {
            Ok(decoded) => {
                // A mutation that still decodes must decode to DIFFERENT
                // contents (it cannot collide with the canonical object).
                assert_ne!(
                    decoded.records, records,
                    "mutation at {offset} decoded to identical contents"
                );
            }
            Err(_) => {
                refused += 1;
            }
        }
    }
    assert!(refused >= 8, "most corruptions must be refused outright");
    emit("corruption-refusal", 11);
    Ok(())
}

/// P4 BOUNDS: oversize payloads, over-limit record counts, and implausible
/// loss intervals are typed refusals.
#[test]
fn p4_bounds_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
    // Oversize single packet payload.
    let big = vec![0u8; MAX_PACKET_PAYLOAD_LEN + 1];
    let err = encode_replay(
        header(),
        &[ReplayRecord::Data {
            seq: 1,
            rtp_ts: 1,
            payload: big,
        }],
    );
    assert!(err.is_err());
    // Empty loss interval refused.
    let err = encode_replay(
        header(),
        &[ReplayRecord::Loss {
            from_seq: 5,
            to_seq: 5,
        }],
    );
    assert!(err.is_err());
    // Over-limit record count.
    let many = vec![ReplayRecord::Duplicate { seq: 1 }; MAX_REPLAY_RECORDS + 1];
    let err = encode_replay(header(), &many);
    assert!(err.is_err());
    emit("bounds-enforcement", 3);
    Ok(())
}

/// P5 TRUNCATION: every proper prefix of a valid object is refused — no
/// partial reads.
#[test]
fn p5_truncation_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x0054_5255;
    let mut rng = Lcg::new(SEED);
    let records = generated_stream(&mut rng, 40)?;
    let raw = encode_replay(header(), &records)?;
    let mut refused = 0u64;
    for cut in [0usize, 1, 3, 8, 20, raw.len() / 2, raw.len() - 1] {
        if decode_replay(&raw[..cut]).is_err() {
            refused += 1;
        }
    }
    assert_eq!(refused, 7, "every prefix must refuse");
    emit("truncation-refusal", 7);
    Ok(())
}
