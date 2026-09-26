#![forbid(unsafe_code)]
//! FSS-059 malformed-media gauntlet for the fss-reference file-import probes that are
//! not already covered by a mutation gauntlet: `split_hevc_annexb`, the rtpdump
//! `RtpDumpReader`, and `sniff_format`. (`split_annexb` and `split_jpeg_stream` keep
//! their existing 10k-mutation gauntlets in `annexb_split_contract.rs` and
//! `mjpeg_split_contract.rs`; they are not duplicated here.)
//!
//! Seeds are checked-in fixtures only: libx265 streams from
//! `fss-codec-h265/tests/fixtures/decode/` and recorded RTP from
//! `tests/fixtures/media/rtp/`. Mutants come from the shared fixed-seed engine in
//! `fss-packet/tests/media_mutation`.
//!
//! Invariants per mutant (run twice): no panic in a debug build, Ok or a typed error,
//! every reported span lies inside the input, access units tile the stream from the
//! first start code, every NAL belongs to exactly one access unit, rtpdump records
//! tile the input from the header with each call advancing (so the read loop is
//! bounded by the input size), a framing failure latches, and the two runs agree.
//!
//! No-Claim: evidence against these mutation classes over this corpus only; not
//! coverage-guided fuzzing and not a proof.

#[path = "../../fss-packet/tests/media_mutation/mod.rs"]
mod media_mutation;

use std::error::Error;
use std::path::PathBuf;

use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::ingest::rtpdump::{RtpDumpFault, RtpDumpKind, RtpDumpLimits, RtpDumpReader};
use fss_reference::ingest::{HevcScan, split_hevc_annexb};
use fss_reference::{ADP_REPLAY_ROW_ID, AnnexBLimits, ReplayCx, ReplayIoAuthority, sniff_format};
use media_mutation::{
    CLASSES, Class, Failure, LengthField, Rng, Seed, Tally, annex_b_markers, annex_b_units, check,
    mutate_stacked, report,
};

const HEVC_FIXTURES: [(&str, &[u8]); 5] = [
    (
        "pcm_mixed_nodeblock",
        include_bytes!("../../fss-codec-h265/tests/fixtures/decode/pcm_mixed_nodeblock.h265"),
    ),
    (
        "i_qcif_nostrong",
        include_bytes!("../../fss-codec-h265/tests/fixtures/decode/i_qcif_nostrong.h265"),
    ),
    (
        "p_100x60_crop",
        include_bytes!("../../fss-codec-h265/tests/fixtures/decode/p_100x60_crop.h265"),
    ),
    (
        "b_128x96_weighted",
        include_bytes!("../../fss-codec-h265/tests/fixtures/decode/b_128x96_weighted.h265"),
    ),
    (
        "i_qcif_slices4",
        include_bytes!("../../fss-codec-h265/tests/fixtures/decode/i_qcif_slices4.h265"),
    ),
];
const RTP_FIXTURES: [(&str, &[u8]); 3] = [
    (
        "clean.rtp",
        include_bytes!("../../../tests/fixtures/media/rtp/clean.rtp"),
    ),
    (
        "ssrc_reset.rtp",
        include_bytes!("../../../tests/fixtures/media/rtp/ssrc_reset.rtp"),
    ),
    (
        "large_gap.rtp",
        include_bytes!("../../../tests/fixtures/media/rtp/large_gap.rtp"),
    ),
];

const HEVC_MUTANTS: usize = 20_000;
const RTPDUMP_MUTANTS: usize = 40_000;

fn cx() -> Result<ReplayCx, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: "trace:fss-059-gauntlet".to_string(),
        operation_id: OperationId::parse("operation:fss-059-gauntlet")?,
        principal: "operator:fss-059-gauntlet".to_string(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"fss-059-gauntlet"),
        generation: 1,
    };
    let root = ContextAuthority::new_root(spec)?;
    let scratch = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("test-replay-cx-fss-059-gauntlet");
    let io = ReplayIoAuthority::from_context_authority(&root, scratch)?;
    Ok(ReplayCx::new(io))
}

fn finish(target: &str, tally: &Tally, failures: Vec<Failure>, expected: usize) {
    report(target, tally);
    assert_eq!(tally.mutants, expected, "{target}: mutant count drifted");
    assert!(
        tally.refused > 0 && tally.ok > 0,
        "{target}: degenerate outcomes"
    );
    assert!(failures.is_empty(), "{target}: {failures:#?}");
}

fn limits() -> AnnexBLimits {
    AnnexBLimits {
        max_input_bytes: 64 * 1024,
        max_nal_bytes: 32 * 1024,
        max_nals: 256,
        max_aus: 128,
        max_leading_garbage_bytes: 64,
    }
}

fn scan_invariants(scan: &HevcScan, bytes: &[u8], limits: AnnexBLimits) -> Result<(), String> {
    let inside =
        |offset: usize, len: usize| offset.checked_add(len).is_some_and(|e| e <= bytes.len());
    if scan.total_bytes != bytes.len()
        || scan.nals.len() > limits.max_nals
        || scan.access_units.len() > limits.max_aus
    {
        return Err("scan totals exceed input or limits".into());
    }
    let mut previous_end = 0;
    for nal in &scan.nals {
        let (sc, body) = (nal.start_code_span, nal.nal_span);
        if !inside(sc.offset, sc.len)
            || !inside(body.offset, body.len)
            || sc.offset < previous_end
            || sc.offset + sc.len != body.offset
            || !matches!(sc.len, 3 | 4)
            || bytes.get(sc.offset + sc.len - 3..sc.offset + sc.len) != Some(&[0, 0, 1][..])
            || body.len > limits.max_nal_bytes
        {
            return Err(format!(
                "NAL span {sc:?}/{body:?} is not an exact in-bounds unit"
            ));
        }
        let header = bytes.get(body.offset).copied().unwrap_or(0);
        if nal.nal_unit_type != (header >> 1) & 63 {
            return Err("reported nal_unit_type differs from the header byte".into());
        }
        previous_end = body.offset + body.len;
    }
    // Access units tile [first start code, end) and partition the NAL list in order.
    let mut expected = scan.access_units.first().map_or(0, |au| au.span.offset);
    let mut next_nal = 0;
    for au in &scan.access_units {
        if au.span.offset != expected || !inside(au.span.offset, au.span.len) {
            return Err("access units do not tile the stream".into());
        }
        expected = au.span.offset + au.span.len;
        for &index in &au.nal_indices {
            if index != next_nal || index >= scan.nals.len() {
                return Err("access units do not partition the NALs in order".into());
            }
            next_nal += 1;
        }
    }
    if !scan.access_units.is_empty() && (expected != bytes.len() || next_nal != scan.nals.len()) {
        return Err("access units leave uncovered bytes or NALs".into());
    }
    for span in scan.padding_spans.iter().chain(&scan.omission_spans) {
        if !inside(span.offset, span.len) {
            return Err("padding/omission span escapes the input".into());
        }
    }
    Ok(())
}

#[test]
fn hevc_annexb_probe_survives_mutation_gauntlet() -> Result<(), Box<dyn Error>> {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0F01;
    let cx = cx()?;
    let seeds: Vec<Seed> = HEVC_FIXTURES
        .iter()
        .map(|(name, bytes)| {
            let mut seed = Seed::new(*name, bytes.to_vec());
            seed.units = annex_b_units(bytes);
            seed.markers = annex_b_markers();
            seed.markers.push(vec![0, 0, 1, 0x46, 0x01]); // access unit delimiter
            seed.markers.push(vec![0, 0, 1, 0x4E, 0x01]); // prefix SEI
            seed.markers.push(vec![0, 0, 1, 0x02, 0x09]); // nonzero layer
            seed
        })
        .collect();
    let limits = limits();
    for seed in &seeds {
        let scan = split_hevc_annexb(&seed.bytes, limits, &cx)
            .map_err(|e| format!("{}: clean fixture refused: {e:?}", seed.name))?;
        scan_invariants(&scan, &seed.bytes, limits)?;
    }
    let classes: Vec<Class> = CLASSES
        .iter()
        .copied()
        .filter(|c| *c != Class::LengthField)
        .collect();
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..HEVC_MUTANTS {
        let seed = &seeds[index % seeds.len()];
        // Annex-B carries no binary length fields; that class is exercised elsewhere.
        let class = classes[(index / seeds.len()) % classes.len()];
        let (mutation, bytes) = mutate_stacked(seed, &seeds, class, &mut rng);
        tally.count(class);
        tally.note(&mutation);
        let run = || -> Result<Result<HevcScan, String>, String> {
            let sniffed = sniff_format(&bytes).map(|(format, _)| format);
            match split_hevc_annexb(&bytes, limits, &cx) {
                Ok(scan) => {
                    scan_invariants(&scan, &bytes, limits)?;
                    Ok(Ok(scan))
                }
                Err(error) => Ok(Err(format!("{error:?} / sniff {sniffed:?}"))),
            }
        };
        if let Some(outcome) = check(
            "hevc-annexb-probe",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if outcome.is_ok() {
                tally.ok += 1;
            } else {
                tally.refused += 1;
            }
        }
    }
    finish("hevc-annexb-probe", &tally, failures, HEVC_MUTANTS);
    Ok(())
}

/// rtpdump structure: text header line, 16-byte preamble, then 8-byte-headed records.
fn rtpdump_seed(name: &str, bytes: &[u8]) -> Seed {
    let mut seed = Seed::new(name, bytes.to_vec());
    let line_end = bytes
        .iter()
        .position(|b| *b == b'\n')
        .map_or(0, |at| at + 1);
    seed.units.push(0..line_end);
    let header_end = (line_end + 16).min(bytes.len());
    seed.units.push(line_end..header_end);
    let mut at = header_end;
    while at + 8 <= bytes.len() {
        let length = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
        if length < 8 || at + length > bytes.len() {
            break;
        }
        seed.units.push(at..at + length);
        seed.length_fields.push(LengthField::Binary {
            offset: at,
            width: 2,
        });
        seed.length_fields.push(LengthField::Binary {
            offset: at + 2,
            width: 2,
        });
        at += length;
    }
    seed.markers = vec![
        b"#!rtpplay1.0 127.0.0.1/5004\n".to_vec(),
        b"\n".to_vec(),
        vec![0, 8, 0, 0, 0, 0, 0, 0],
        vec![0xFF, 0xFF, 0, 0],
        vec![0, 0, 0, 0],
    ];
    seed
}

#[derive(Debug, PartialEq)]
struct DumpOutcome {
    records: Vec<(std::ops::Range<usize>, RtpDumpKind, u32)>,
    end: Result<usize, RtpDumpFault>,
}

fn read_dump(bytes: &[u8]) -> Result<DumpOutcome, String> {
    let limits = RtpDumpLimits {
        max_input_bytes: 64 * 1024,
        max_records: 256,
        max_packet_bytes: 2_048,
    };
    let mut reader = match RtpDumpReader::new(bytes, limits) {
        Ok(reader) => reader,
        Err(error) => {
            if error.span.end > bytes.len() || error.span.start > error.span.end {
                return Err("header error span escapes the input".into());
            }
            return Ok(DumpOutcome {
                records: Vec::new(),
                end: Err(error.fault),
            });
        }
    };
    let header = reader.header_span();
    if header.end > bytes.len() {
        return Err("header span escapes the input".into());
    }
    let mut records = Vec::new();
    let mut cursor = header.end;
    // Each record consumes at least eight bytes, so this bound cannot be reached
    // by a reader that makes progress.
    for _ in 0..=bytes.len() / 8 + 1 {
        match reader.next_record() {
            Ok(Some(record)) => {
                let span = record.span();
                let packet = record.packet_span();
                if span.start != cursor
                    || span.end > bytes.len()
                    || span.len() < 8
                    || packet.start != span.start + 8
                    || packet.end != span.end
                    || bytes.get(packet.clone()) != Some(record.packet())
                    || record.packet().len() > limits.max_packet_bytes
                    || records.len() >= limits.max_records
                    || reader.consumed_bytes() != span.end
                {
                    return Err(format!("record {span:?} does not tile the input"));
                }
                let kind_ok = match record.kind() {
                    RtpDumpKind::Rtcp => record.original_len() == 0,
                    RtpDumpKind::CapturedPrefix => {
                        record.packet().len() < usize::from(record.original_len())
                    }
                    RtpDumpKind::Rtp => record.packet().len() == usize::from(record.original_len()),
                };
                if !kind_ok {
                    return Err("record kind contradicts its lengths".into());
                }
                // Recorded packets reach the real RTP parser; any typed outcome is fine.
                if record.kind() == RtpDumpKind::Rtp {
                    let _ = fss_packet::RtpPacket::parse(
                        record.packet(),
                        fss_packet::PacketLimits::default(),
                    );
                }
                cursor = span.end;
                records.push((span, record.kind(), record.offset_ms()));
            }
            Ok(None) => {
                if cursor != bytes.len() {
                    return Err("clean EOF before the end of input".into());
                }
                return Ok(DumpOutcome {
                    records,
                    end: Ok(reader.records_read()),
                });
            }
            Err(error) => {
                if error.span.start != cursor || error.span.end != bytes.len() {
                    return Err("failure span is not the exact refused suffix".into());
                }
                // A framing failure latches; no resynchronization is attempted.
                match reader.next_record() {
                    Err(again) if again.fault == RtpDumpFault::Stopped => {}
                    _ => return Err("reader resumed after a framing failure".into()),
                }
                return Ok(DumpOutcome {
                    records,
                    end: Err(error.fault),
                });
            }
        }
    }
    Err("rtpdump reader made no progress (hang)".into())
}

#[test]
fn rtpdump_reader_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0F02;
    let seeds: Vec<Seed> = RTP_FIXTURES
        .iter()
        .map(|(name, bytes)| rtpdump_seed(name, bytes))
        .collect();
    for seed in &seeds {
        let clean = read_dump(&seed.bytes);
        assert!(
            clean
                .as_ref()
                .is_ok_and(|o| o.end.is_ok() && !o.records.is_empty()),
            "{}: clean fixture must frame: {clean:?}",
            seed.name
        );
    }
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..RTPDUMP_MUTANTS {
        let seed = &seeds[index % seeds.len()];
        let class = CLASSES[(index / seeds.len()) % CLASSES.len()];
        let (mutation, bytes) = mutate_stacked(seed, &seeds, class, &mut rng);
        tally.count(class);
        tally.note(&mutation);
        let run = || -> Result<(DumpOutcome, String), String> {
            let sniffed = format!("{:?}", sniff_format(&bytes).map(|(f, _)| f));
            Ok((read_dump(&bytes)?, sniffed))
        };
        if let Some((outcome, _)) = check(
            "rtpdump",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if outcome.end.is_ok() {
                tally.ok += 1;
            } else {
                tally.refused += 1;
            }
        }
    }
    finish("rtpdump", &tally, failures, RTPDUMP_MUTANTS);
}
