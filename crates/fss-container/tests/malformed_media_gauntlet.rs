#![forbid(unsafe_code)]
//! FSS-059 malformed-media gauntlet for the AVC and HEVC fragmented-MP4 writers.
//!
//! The container crate writes, it does not parse: its untrusted input is the picture
//! groups that fss-packet assembled from camera RTP, the parameter sets those groups
//! carry, and the caller-supplied timing. Each mutant therefore mutates the checked-in
//! elementary streams (`fss-packet/tests/fixtures/avc/*.264` and the shared HEVC remux
//! fixture) with the shared fixed-seed engine, re-packetizes and re-assembles them with
//! the real fss-packet depacketizer/assembler, tries the mutant's own parameter sets
//! for the muxer configuration, and additionally corrupts the timing fields (the
//! writer's only length-like inputs) with boundary values.
//!
//! Invariants per mutant (run twice): no panic in a debug build, Ok or a typed
//! `Mp4Error`, a refused fragment leaves `next_sequence` unchanged (transactional),
//! every emitted initialization/fragment stays under its `Mp4Limits` byte ceiling and
//! tiles exactly into well-formed boxes, every media NAL is length-prefixed and
//! byte-identical to its source NAL, sample timing is exactly what was supplied, and
//! the two runs produce identical bytes and receipts.
//!
//! No-Claim: evidence against these mutation classes over this corpus only; not
//! coverage-guided fuzzing and not a proof.

#[path = "../../fss-packet/tests/media_mutation/mod.rs"]
mod media_mutation;

use fss_container::{
    AvcMuxer, HevcMuxer, Mp4Error, Mp4Limits, NalTarget, TimedAvcPicture, TimedHevcPicture,
};
use fss_packet::avc::{
    AvcAssembler, AvcAssemblyLimits, AvcAssemblyStep, AvcPictureGroup, AvcSyntaxLimits, parse_pps,
    parse_sps,
};
use fss_packet::hevc::{
    HevcAssembler, HevcAssemblyLimits, HevcAssemblyStep, HevcConfiguration,
    HevcConfigurationLimits, HevcPictureGroup,
};
use fss_packet::{
    H264Depacketizer, H264Limits, H264Mode, H265Depacketizer, H265Limits, PacketLimits, RtpPacket,
    StreamKey,
};
use media_mutation::{
    CLASSES, Class, Failure, Rng, Seed, Tally, annex_b_markers, annex_b_units, check,
    mutate_stacked, report,
};

const KEY: StreamKey = StreamKey {
    ingress: 59,
    generation: 1,
    ssrc: 0x0F55_0059,
};
const BASELINE: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
const HIGH: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/high_cropped.264");
const HEVC_HEX: &str = include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex");

const AVC_MUTANTS: usize = 20_000;
const HEVC_MUTANTS: usize = 20_000;

fn limits() -> Mp4Limits {
    Mp4Limits {
        max_samples: 8,
        max_nals: 64,
        max_source_spans: 256,
        max_fragment_bytes: 48 * 1024,
        max_initialization_bytes: 2 * 1024,
    }
}

fn split(bytes: &[u8]) -> Vec<Vec<u8>> {
    annex_b_units(bytes)
        .into_iter()
        .filter_map(|unit| {
            let unit = bytes.get(unit)?;
            let start = unit.windows(3).position(|w| w == [0, 0, 1])? + 3;
            let mut nal = unit.get(start..)?.to_vec();
            while nal.last() == Some(&0) {
                nal.pop();
            }
            (!nal.is_empty()).then_some(nal)
        })
        .collect()
}

fn hevc_fixture() -> Vec<u8> {
    let digit = |b: u8| match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => 0,
    };
    let mut annex_b = Vec::new();
    for line in HEVC_HEX.lines().filter(|l| !l.trim().is_empty()) {
        let compact: Vec<u8> = line.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        annex_b.extend_from_slice(&[0, 0, 0, 1]);
        annex_b.extend(
            compact
                .chunks(2)
                .map(|p| digit(p[0]) * 16 + digit(*p.get(1).unwrap_or(&b'0'))),
        );
    }
    // Explicit end-of-sequence closes the final group, as in the remux contract.
    annex_b.extend_from_slice(&[0, 0, 0, 1, 0x48, 0x01, 0x80]);
    annex_b
}

fn stream_seed(name: &str, bytes: Vec<u8>) -> Seed {
    let mut seed = Seed::new(name, bytes);
    seed.units = annex_b_units(&seed.bytes);
    seed.markers = annex_b_markers();
    seed
}

fn wire(sequence: u16, timestamp: u32, marker: bool, nal: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80, 96 | if marker { 0x80 } else { 0 }];
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&KEY.ssrc.to_be_bytes());
    out.extend_from_slice(nal);
    out
}

/// Picture timestamps: a non-VCL NAL carries the timestamp of the next VCL NAL, or of
/// the last VCL NAL when none follows (trailing end-of-sequence).
fn timestamps(nals: &[Vec<u8>], vcl: impl Fn(&[u8]) -> bool, step: u32) -> Vec<u32> {
    let total = nals.iter().filter(|n| vcl(n)).count() as u32;
    let mut out = Vec::with_capacity(nals.len());
    let mut pictures = 0_u32;
    for nal in nals {
        out.push(pictures.min(total.saturating_sub(1)).wrapping_mul(step));
        if vcl(nal) {
            pictures = pictures.wrapping_add(1);
        }
    }
    out
}

/// Timing supplied to the writer, optionally corrupted (the "length field" class).
fn timing(count: usize, step: u32, corrupt: Option<(usize, u8)>) -> Vec<(u64, u32, i32)> {
    let mut out: Vec<(u64, u32, i32)> = (0..count)
        .map(|i| (i as u64 * u64::from(step), step, 0))
        .collect();
    if let Some((index, kind)) = corrupt
        && let Some(slot) = out.get_mut(index)
    {
        match kind % 8 {
            0 => slot.1 = 0,
            1 => slot.1 = u32::MAX,
            2 => slot.2 = i32::MIN,
            3 => slot.2 = i32::MAX,
            4 => slot.0 = u64::MAX,
            5 => slot.0 = slot.0.wrapping_sub(1),
            6 => slot.0 = slot.0.saturating_add(1),
            _ => slot.1 = step.wrapping_add(1),
        }
    }
    out
}

/// Top-level (and moof/traf/moov/trak/mdia/minf/stbl/mvex) boxes must tile exactly.
fn check_boxes(bytes: &[u8], depth: usize) -> Result<Vec<[u8; 4]>, String> {
    let mut at = 0;
    let mut names = Vec::new();
    while at < bytes.len() {
        let header = bytes.get(at..at + 8).ok_or("box header truncated")?;
        let size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let name = [header[4], header[5], header[6], header[7]];
        if size < 8 || at + size > bytes.len() {
            return Err(format!("box {:?} size {size} escapes its parent", name));
        }
        if depth < 8
            && matches!(
                &name,
                b"moof" | b"traf" | b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"mvex"
            )
        {
            check_boxes(&bytes[at + 8..at + size], depth + 1)?;
        }
        names.push(name);
        at += size;
    }
    Ok(names)
}

/// One emitted fragment: sequence, exact bytes, and its sample/gap receipts.
type Emitted = (u32, Vec<u8>, String);

#[derive(Debug, PartialEq)]
struct MuxOutcome {
    init: Result<Vec<u8>, Mp4Error>,
    fragments: Vec<Result<Emitted, Mp4Error>>,
    pictures: usize,
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

fn avc_groups(nals: &[Vec<u8>], sps: &[u8], pps: &[u8]) -> Result<Vec<AvcPictureGroup>, String> {
    let syntax = AvcSyntaxLimits::default();
    let sps = parse_sps(sps, syntax).map_err(|e| format!("{e:?}"))?;
    let pps = parse_pps(pps, &sps, syntax).map_err(|e| format!("{e:?}"))?;
    let mut assembler = AvcAssembler::new(KEY, sps, pps, syntax, AvcAssemblyLimits::default())
        .map_err(|e| format!("{e:?}"))?;
    let mut depacketizer =
        H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, H264Limits::default())
            .map_err(|e| format!("{e:?}"))?;
    let vcl = |nal: &[u8]| matches!(nal.first().map(|h| h & 31), Some(1 | 5));
    let times = timestamps(nals, vcl, 3_600);
    let mut groups = Vec::new();
    for (index, nal) in nals.iter().enumerate() {
        let sequence = index as u64 + 1;
        let raw = wire(sequence as u16, times[index], vcl(nal), nal);
        let Ok(packet) = RtpPacket::parse(&raw, PacketLimits::default()) else {
            continue;
        };
        let Ok(output) = depacketizer.push(KEY, sequence, packet, sequence) else {
            continue;
        };
        for nal in output.nals {
            if let AvcAssemblyStep::Accepted(step) = assembler.push(nal, sequence) {
                groups.extend(step.picture);
            }
        }
    }
    if let Ok(tail) = assembler.finish(nals.len() as u64 + 1) {
        groups.extend(tail.picture);
    }
    Ok(groups)
}

fn avc_target(
    nals: &[Vec<u8>],
    clean: &[Vec<u8>],
    corrupt: Option<(usize, u8)>,
    chunks: &[usize],
) -> Result<MuxOutcome, String> {
    let limits = limits();
    // Prefer the mutant's own leading parameter sets; fall back to the clean ones.
    let pick = |i: usize| nals.get(i).cloned().unwrap_or_else(|| clean[i].clone());
    let (sps_nal, pps_nal) = (pick(0), pick(1));
    let (groups, sps_nal, pps_nal) = match avc_groups(nals, &sps_nal, &pps_nal) {
        Ok(groups) => (groups, sps_nal, pps_nal),
        Err(_) => (
            avc_groups(nals, &clean[0], &clean[1])?,
            clean[0].clone(),
            clean[1].clone(),
        ),
    };
    let syntax = AvcSyntaxLimits::default();
    let sps = parse_sps(&sps_nal, syntax).map_err(|e| format!("{e:?}"))?;
    let pps = parse_pps(&pps_nal, &sps, syntax).map_err(|e| format!("{e:?}"))?;
    let mut muxer = match AvcMuxer::new(KEY, sps, pps, 90_000, limits) {
        Ok(muxer) => muxer,
        Err(error) => {
            return Ok(MuxOutcome {
                init: Err(error),
                fragments: Vec::new(),
                pictures: groups.len(),
            });
        }
    };
    let init = muxer.initialization().bytes().to_vec();
    if init.len() > limits.max_initialization_bytes {
        return Err("initialization exceeds its byte ceiling".into());
    }
    let top = check_boxes(&init, 0)?;
    if top != [*b"ftyp", *b"moov"] {
        return Err(format!("initialization top-level boxes {top:?}"));
    }
    let clock = timing(groups.len(), 3_600, corrupt);
    let mut fragments = Vec::new();
    let mut at = 0;
    for &size in chunks {
        if at >= groups.len() {
            break;
        }
        let end = (at + size).min(groups.len());
        let samples: Vec<TimedAvcPicture<'_>> = (at..end)
            .map(|i| TimedAvcPicture {
                picture: &groups[i],
                decode_time: clock[i].0,
                duration: clock[i].1,
                composition_offset: clock[i].2,
            })
            .collect();
        let before = muxer.next_sequence();
        match muxer.fragment(&samples) {
            Ok(fragment) => {
                let bytes = fragment.bytes();
                if Some(fragment.sequence()) != before
                    || muxer.next_sequence() != before.and_then(|s| s.checked_add(1))
                    || fragment.key() != KEY
                    || bytes.len() > limits.max_fragment_bytes
                    || fragment.samples().len() != samples.len()
                    || samples.len() > limits.max_samples
                    || fragment.mappings().len() > limits.max_nals
                {
                    return Err("fragment escapes its limits or sequence cursor".into());
                }
                let top = check_boxes(bytes, 0)?;
                if top != [*b"moof", *b"mdat"] {
                    return Err(format!("fragment top-level boxes {top:?}"));
                }
                for (sample, timed) in fragment.samples().iter().zip(&samples) {
                    let presentation =
                        i128::from(timed.decode_time) + i128::from(timed.composition_offset);
                    if sample.decode_time != timed.decode_time
                        || i128::from(sample.presentation_time) != presentation
                        || sample.duration != timed.duration
                        || sample.range.end > bytes.len()
                    {
                        return Err("sample timing/range differs from what was supplied".into());
                    }
                    let mut cursor = sample.range.start;
                    for mapping in &fragment.mappings()[sample.mappings.clone()] {
                        let nal = timed
                            .picture
                            .nals()
                            .get(mapping.nal)
                            .ok_or("mapping names an absent NAL")?;
                        if mapping.sources != nal.sources() {
                            return Err("NAL source spans not preserved".into());
                        }
                        match &mapping.target {
                            NalTarget::Initialization(range) => {
                                if init.get(range.clone()) != Some(nal.bytes()) {
                                    return Err("parameter set not in initialization".into());
                                }
                            }
                            NalTarget::Media(range) => {
                                let prefix = bytes
                                    .get(cursor..cursor + 4)
                                    .ok_or("length prefix escapes fragment")?;
                                let declared = u32::from_be_bytes([
                                    prefix[0], prefix[1], prefix[2], prefix[3],
                                ]);
                                if range.start != cursor + 4
                                    || declared as usize != nal.bytes().len()
                                    || bytes.get(range.clone()) != Some(nal.bytes())
                                {
                                    return Err(
                                        "media NAL is not its exact length-prefixed bytes".into()
                                    );
                                }
                                cursor = range.end;
                            }
                        }
                    }
                    if cursor != sample.range.end {
                        return Err("sample range is not tiled by its NALs".into());
                    }
                }
                fragments.push(Ok((
                    fragment.sequence(),
                    bytes.to_vec(),
                    format!("{:?}{:?}", fragment.samples(), fragment.timeline_gap()),
                )));
            }
            Err(error) => {
                if muxer.next_sequence() != before {
                    return Err("refused fragment consumed a sequence number".into());
                }
                fragments.push(Err(error));
            }
        }
        at = end;
    }
    Ok(MuxOutcome {
        init: Ok(init),
        fragments,
        pictures: groups.len(),
    })
}

fn chunk_plan(rng: &mut Rng) -> Vec<usize> {
    (0..8).map(|_| 1 + rng.below(4)).collect()
}

#[test]
fn avc_mp4_writer_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0C01;
    let seeds = [
        stream_seed("baseline", BASELINE.to_vec()),
        stream_seed("high_cropped", HIGH.to_vec()),
    ];
    let cleans: Vec<Vec<Vec<u8>>> = seeds.iter().map(|s| split(&s.bytes)).collect();
    for (seed, clean) in seeds.iter().zip(&cleans) {
        let outcome = avc_target(clean, clean, None, &[8]);
        let fine = outcome
            .as_ref()
            .is_ok_and(|o| o.init.is_ok() && o.fragments.iter().all(Result::is_ok));
        assert!(fine, "{}: clean stream must mux: {outcome:?}", seed.name);
    }
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..AVC_MUTANTS {
        let slot = index % seeds.len();
        let seed = &seeds[slot];
        let class = CLASSES[(index / seeds.len()) % CLASSES.len()];
        // The writer's length-like inputs are its timing fields; corrupt those for
        // the length-field class and mutate stream bytes for every other class.
        let (mutation, nals, corrupt) = if class == Class::LengthField {
            let corrupt = (rng.below(6), rng.below(8) as u8);
            (
                format!("timing {corrupt:?}"),
                cleans[slot].clone(),
                Some(corrupt),
            )
        } else {
            let (mutation, bytes) = mutate_stacked(seed, &seeds, class, &mut rng);
            tally.note(&mutation);
            (format!("{mutation:?}"), split(&bytes), None)
        };
        let chunks = chunk_plan(&mut rng);
        tally.count(class);
        let run = || avc_target(&nals, &cleans[slot], corrupt, &chunks);
        if let Some(outcome) = check(
            "avc-mp4",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if outcome.init.is_ok() && outcome.fragments.iter().all(Result::is_ok) {
                tally.ok += 1;
            } else {
                tally.refused += 1;
            }
        }
    }
    finish("avc-mp4", &tally, failures, AVC_MUTANTS);
}

fn hevc_groups(nals: &[Vec<u8>]) -> Result<Vec<HevcPictureGroup>, String> {
    let mut depacketizer =
        H265Depacketizer::new(KEY, 96, 0, H265Limits::default()).map_err(|e| format!("{e:?}"))?;
    let mut assembler =
        HevcAssembler::new(KEY, HevcAssemblyLimits::default()).map_err(|e| format!("{e:?}"))?;
    let vcl = |nal: &[u8]| nal.first().is_some_and(|h| (h >> 1) & 63 < 32);
    let times = timestamps(nals, vcl, 18_000);
    let mut groups = Vec::new();
    for (index, nal) in nals.iter().enumerate() {
        let sequence = index as u64 + 1;
        let raw = wire(sequence as u16, times[index], false, nal);
        let Ok(packet) = RtpPacket::parse(&raw, PacketLimits::default()) else {
            continue;
        };
        let Ok(output) = depacketizer.push(KEY, sequence, packet, sequence) else {
            continue;
        };
        for nal in output.nals {
            if let HevcAssemblyStep::Accepted(step) = assembler.push(nal, sequence) {
                groups.extend(step.picture);
            }
        }
    }
    if let Ok(tail) = assembler.finish(nals.len() as u64 + 1) {
        groups.extend(tail.picture);
    }
    Ok(groups)
}

fn hevc_target(
    nals: &[Vec<u8>],
    clean: &[Vec<u8>],
    corrupt: Option<(usize, u8)>,
    chunks: &[usize],
) -> Result<MuxOutcome, String> {
    let limits = limits();
    let groups = hevc_groups(nals)?;
    let pick = |i: usize| nals.get(i).map_or(clean[i].as_slice(), Vec::as_slice);
    let config = HevcConfiguration::parse(
        pick(0),
        pick(1),
        pick(2),
        HevcConfigurationLimits::default(),
    )
    .or_else(|_| {
        HevcConfiguration::parse(
            &clean[0],
            &clean[1],
            &clean[2],
            HevcConfigurationLimits::default(),
        )
    })
    .map_err(|e| format!("clean configuration refused: {e:?}"))?;
    let mut muxer = match HevcMuxer::new(KEY, config, 90_000, limits) {
        Ok(muxer) => muxer,
        Err(error) => {
            return Ok(MuxOutcome {
                init: Err(error),
                fragments: Vec::new(),
                pictures: groups.len(),
            });
        }
    };
    let init = muxer.initialization().bytes().to_vec();
    if init.len() > limits.max_initialization_bytes {
        return Err("initialization exceeds its byte ceiling".into());
    }
    for range in muxer.initialization().parameter_ranges() {
        if range.end > init.len() {
            return Err("parameter range escapes initialization".into());
        }
    }
    let top = check_boxes(&init, 0)?;
    if top != [*b"ftyp", *b"moov"] {
        return Err(format!("initialization top-level boxes {top:?}"));
    }
    let clock = timing(groups.len(), 18_000, corrupt);
    let mut fragments = Vec::new();
    let mut at = 0;
    for &size in chunks {
        if at >= groups.len() {
            break;
        }
        let end = (at + size).min(groups.len());
        let samples: Vec<TimedHevcPicture<'_>> = (at..end)
            .map(|i| TimedHevcPicture {
                picture: &groups[i],
                decode_time: clock[i].0,
                duration: clock[i].1,
                composition_offset: clock[i].2,
            })
            .collect();
        let before = muxer.next_sequence();
        match muxer.fragment(&samples) {
            Ok(fragment) => {
                let bytes = fragment.bytes();
                if Some(fragment.sequence()) != before
                    || muxer.next_sequence() != before.and_then(|s| s.checked_add(1))
                    || fragment.key() != KEY
                    || bytes.len() > limits.max_fragment_bytes
                    || fragment.samples().len() != samples.len()
                    || fragment.mappings().len() > limits.max_nals
                {
                    return Err("fragment escapes its limits or sequence cursor".into());
                }
                let top = check_boxes(bytes, 0)?;
                if top != [*b"moof", *b"mdat"] {
                    return Err(format!("fragment top-level boxes {top:?}"));
                }
                for (sample, timed) in fragment.samples().iter().zip(&samples) {
                    let presentation =
                        i128::from(timed.decode_time) + i128::from(timed.composition_offset);
                    if sample.decode_time != timed.decode_time
                        || i128::from(sample.presentation_time) != presentation
                        || sample.duration != timed.duration
                        || sample.range.end > bytes.len()
                    {
                        return Err("sample timing/range differs from what was supplied".into());
                    }
                    let mut cursor = sample.range.start;
                    for mapping in &fragment.mappings()[sample.mappings.clone()] {
                        let nal = timed
                            .picture
                            .nals()
                            .get(mapping.nal)
                            .ok_or("mapping names an absent NAL")?;
                        let prefix = bytes
                            .get(cursor..cursor + 4)
                            .ok_or("length prefix escapes fragment")?;
                        let declared =
                            u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
                        if mapping.sources != nal.sources()
                            || mapping.range.start != cursor + 4
                            || declared as usize != nal.bytes().len()
                            || bytes.get(mapping.range.clone()) != Some(nal.bytes())
                        {
                            return Err("media NAL is not its exact length-prefixed bytes".into());
                        }
                        cursor = mapping.range.end;
                    }
                    if cursor != sample.range.end {
                        return Err("sample range is not tiled by its NALs".into());
                    }
                }
                fragments.push(Ok((
                    fragment.sequence(),
                    bytes.to_vec(),
                    format!("{:?}{:?}", fragment.samples(), fragment.timeline_gap()),
                )));
            }
            Err(error) => {
                if muxer.next_sequence() != before {
                    return Err("refused fragment consumed a sequence number".into());
                }
                fragments.push(Err(error));
            }
        }
        at = end;
    }
    Ok(MuxOutcome {
        init: Ok(init),
        fragments,
        pictures: groups.len(),
    })
}

#[test]
fn hevc_mp4_writer_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0C02;
    let seed = stream_seed("remux_main8", hevc_fixture());
    let seeds = [seed];
    let clean = split(&seeds[0].bytes);
    let outcome = hevc_target(&clean, &clean, None, &[8]);
    let fine = outcome
        .as_ref()
        .is_ok_and(|o| o.pictures == 4 && o.init.is_ok() && o.fragments.iter().all(Result::is_ok));
    assert!(fine, "clean HEVC stream must mux: {outcome:?}");
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..HEVC_MUTANTS {
        let class = CLASSES[index % CLASSES.len()];
        let (mutation, nals, corrupt) = if class == Class::LengthField {
            let corrupt = (rng.below(4), rng.below(8) as u8);
            (format!("timing {corrupt:?}"), clean.clone(), Some(corrupt))
        } else {
            let (mutation, bytes) = mutate_stacked(&seeds[0], &seeds, class, &mut rng);
            tally.note(&mutation);
            (format!("{mutation:?}"), split(&bytes), None)
        };
        let chunks = chunk_plan(&mut rng);
        tally.count(class);
        let run = || hevc_target(&nals, &clean, corrupt, &chunks);
        if let Some(outcome) = check(
            "hevc-mp4",
            "remux_main8",
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if outcome.init.is_ok() && outcome.fragments.iter().all(Result::is_ok) {
                tally.ok += 1;
            } else {
                tally.refused += 1;
            }
        }
    }
    finish("hevc-mp4", &tally, failures, HEVC_MUTANTS);
}
