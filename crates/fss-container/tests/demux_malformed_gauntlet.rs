#![forbid(unsafe_code)]
//! Malformed-media gauntlet for the container *parsers*: the MP4/QuickTime demuxer (indexed and
//! fragmented) and the Matroska/WebM demuxer, strict and tail-recovering.
//!
//! Imported files are untrusted bytes. Each mutant applies the shared fixed-seed engine's
//! stacked mutation classes (bit flips, boundary bytes, structural and random truncation,
//! duplication, splicing, length fields, injection, reordering) to a retained laboratory file,
//! aimed at its box or element structure. The units, length fields and markers come from an
//! independent box/EBML walker written here, not from the demuxer.
//!
//! Invariants per mutant, each parser run twice:
//! - no panic in a debug build, and an identical outcome on both runs;
//! - an accepted file reports only in-bounds sample, parameter-set and element ranges, every
//!   sample's length-prefixed NAL framing walks it exactly, and a reported truncated tail never
//!   precedes a sample;
//! - a file the strict parser accepts is accepted by the recovering parser with the same samples
//!   and no tail;
//! - Matroska elements tile the file up to its tail;
//! - an MP4 Annex-B extraction from the first random-access sample stays under its output
//!   ceiling and copies every NAL byte-exactly.
//!
//! No-Claim: evidence against these mutation classes over this corpus only; not
//! coverage-guided fuzzing and not a proof.

#[path = "../../fss-packet/tests/media_mutation/mod.rs"]
mod media_mutation;

use fss_container::demux::{
    AvcMp4, DemuxError, DemuxLimits, MatroskaVideo, VideoCodec, length_prefixed_nals,
};
use media_mutation::{
    CLASSES, Failure, LengthField, Rng, Seed, Tally, check, mutate_stacked, report,
};
use std::ops::Range;

const MP4_MUTANTS: usize = 18_000;
const MKV_MUTANTS: usize = 18_000;

const MP4_FIXTURES: [(&str, &[u8]); 6] = [
    (
        "indexed_avc.mp4",
        include_bytes!("fixtures/indexed_avc.mp4"),
    ),
    (
        "interleaved_av.mp4",
        include_bytes!("fixtures/interleaved_av.mp4"),
    ),
    (
        "fragmented_av.mp4",
        include_bytes!("fixtures/fragmented_av.mp4"),
    ),
    ("hevc_av.mp4", include_bytes!("fixtures/hevc_av.mp4")),
    (
        "hevc_fragmented_av.mp4",
        include_bytes!("fixtures/hevc_fragmented_av.mp4"),
    ),
    ("qt_av.mov", include_bytes!("fixtures/qt_av.mov")),
];
const MKV_FIXTURES: [(&str, &[u8]); 3] = [
    ("avc_av.mkv", include_bytes!("fixtures/avc_av.mkv")),
    ("avc_live.mkv", include_bytes!("fixtures/avc_live.mkv")),
    ("hevc_av.mkv", include_bytes!("fixtures/hevc_av.mkv")),
];

/// Small ceilings, so limit paths are exercised too.
fn limits() -> DemuxLimits {
    DemuxLimits {
        maximum_input_bytes: 64 * 1024,
        maximum_metadata_bytes: 32 * 1024,
        maximum_boxes: 512,
        maximum_tracks: 4,
        maximum_samples: 64,
        maximum_table_entries: 4096,
        maximum_nals: 1024,
        maximum_output_bytes: 64 * 1024,
    }
}

/// ISO-BMFF boxes (recursing into the containers the demuxer reads), as units, plus their
/// 32-bit size fields.
fn mp4_boxes(bytes: &[u8], range: Range<usize>, depth: usize, seed: &mut Seed) {
    let mut at = range.start;
    while at + 8 <= range.end {
        let size = u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        let size = size as usize;
        if size < 8 || at + size > range.end {
            return;
        }
        seed.units.push(at..at + size);
        seed.length_fields.push(LengthField::Binary {
            offset: at,
            width: 4,
        });
        let kind = &bytes[at + 4..at + 8];
        if depth < 8
            && matches!(
                kind,
                b"moov"
                    | b"trak"
                    | b"mdia"
                    | b"minf"
                    | b"stbl"
                    | b"dinf"
                    | b"edts"
                    | b"mvex"
                    | b"moof"
                    | b"traf"
            )
        {
            mp4_boxes(bytes, at + 8..at + size, depth + 1, seed);
        }
        at += size;
    }
}

fn mp4_seed(name: &str, bytes: &[u8]) -> Seed {
    let mut seed = Seed::new(name, bytes.to_vec());
    mp4_boxes(bytes, 0..bytes.len(), 0, &mut seed);
    seed.units.sort_by_key(|unit| (unit.start, unit.end));
    seed.markers = [
        b"moov", b"moof", b"mdat", b"trak", b"traf", b"trun", b"tfhd", b"tfdt", b"stsz", b"stco",
        b"stsc", b"stts", b"ctts", b"stss", b"avcC", b"hvcC", b"mvex", b"free",
    ]
    .iter()
    .map(|kind| {
        let mut marker = vec![0, 0, 0, 8];
        marker.extend_from_slice(*kind);
        marker
    })
    .collect();
    seed
}

/// An EBML variable-length integer: (width, value without marker), within `bytes`.
fn vint(bytes: &[u8], at: usize, keep_marker: bool) -> Option<(usize, u64)> {
    let first = *bytes.get(at)?;
    if first == 0 {
        return None;
    }
    let width = first.leading_zeros() as usize + 1;
    let raw = bytes.get(at..at + width)?;
    let value = raw.iter().fold(0_u64, |v, &b| (v << 8) | u64::from(b));
    Some(if keep_marker {
        (width, value)
    } else {
        (width, value & ((1_u64 << (7 * width)) - 1))
    })
}

/// EBML elements (recursing into masters), as units, plus their size fields.
fn ebml_elements(bytes: &[u8], range: Range<usize>, depth: usize, seed: &mut Seed) {
    let mut at = range.start;
    while at < range.end {
        let Some((id_width, id)) = vint(bytes, at, true) else {
            return;
        };
        let Some((size_width, size)) = vint(bytes, at + id_width, false) else {
            return;
        };
        let data = at + id_width + size_width;
        let unknown = size == (1_u64 << (7 * size_width)) - 1;
        let end = if unknown {
            range.end
        } else {
            match usize::try_from(size).ok().and_then(|s| data.checked_add(s)) {
                Some(end) if end <= range.end => end,
                _ => return,
            }
        };
        seed.units.push(at..end);
        if size_width <= 4 {
            seed.length_fields.push(LengthField::Binary {
                offset: at + id_width,
                width: size_width,
            });
        }
        let master = matches!(
            id,
            0x1A45_DFA3
                | 0x1853_8067
                | 0x114D_9B74
                | 0x1549_A966
                | 0x1654_AE6B
                | 0xAE
                | 0xE0
                | 0x1F43_B675
                | 0xA0
                | 0x1C53_BB6B
        );
        if master && depth < 6 {
            ebml_elements(bytes, data..end, depth + 1, seed);
        }
        at = end;
    }
}

fn mkv_seed(name: &str, bytes: &[u8]) -> Seed {
    let mut seed = Seed::new(name, bytes.to_vec());
    ebml_elements(bytes, 0..bytes.len(), 0, &mut seed);
    seed.units.sort_by_key(|unit| (unit.start, unit.end));
    seed.markers = vec![
        vec![0x1A, 0x45, 0xDF, 0xA3],
        vec![
            0x18, 0x53, 0x80, 0x67, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ],
        vec![0x1F, 0x43, 0xB6, 0x75, 0xFF],
        vec![0xA3, 0x84, 0x81, 0x00, 0x00, 0x80],
        vec![0xBF, 0x84, 0, 0, 0, 0],
        vec![0xE7, 0x81, 0x00],
        vec![0xEC, 0x80],
        vec![0xA0, 0x80],
    ];
    seed
}

/// What one parser reported, compared across the two runs.
#[derive(Debug, PartialEq)]
enum Parsed {
    Refused(DemuxError),
    Accepted {
        codec: VideoCodec,
        samples: Vec<(Range<usize>, bool)>,
        parameter_sets: Vec<Range<usize>>,
        tail: Option<usize>,
        extraction: Option<Result<usize, DemuxError>>,
    },
}

/// Bounds, framing and tail invariants shared by both containers.
fn accepted(
    source: &[u8],
    codec: VideoCodec,
    length_bytes: usize,
    samples: Vec<(Range<usize>, bool)>,
    parameter_sets: &[Range<usize>],
    tail: Option<usize>,
) -> Result<Parsed, String> {
    let end = tail.unwrap_or(source.len());
    if end > source.len() {
        return Err(format!("tail {end} beyond the {}-byte file", source.len()));
    }
    if samples.is_empty() || samples.len() > limits().maximum_samples {
        return Err(format!("{} samples accepted", samples.len()));
    }
    for (range, _) in &samples {
        let bytes = source
            .get(range.clone())
            .filter(|_| range.end <= end)
            .ok_or_else(|| format!("sample {range:?} escapes the demuxed bytes"))?;
        length_prefixed_nals(bytes, length_bytes)
            .map_err(|error| format!("accepted sample fails NAL framing: {error:?}"))?;
    }
    if parameter_sets
        .iter()
        .any(|range| range.is_empty() || range.end > end)
    {
        return Err("parameter set escapes the demuxed bytes".into());
    }
    Ok(Parsed::Accepted {
        codec,
        samples,
        parameter_sets: parameter_sets.to_vec(),
        tail,
        extraction: None,
    })
}

fn mp4_target(bytes: &[u8], recover: bool) -> Result<Parsed, String> {
    let parsed = if recover {
        AvcMp4::parse_recovering_tail(bytes, None, limits(), &mut || Ok(()))
    } else {
        AvcMp4::parse(bytes, None, limits())
    };
    let mp4 = match parsed {
        Ok(mp4) => mp4,
        Err(error) => return Ok(Parsed::Refused(error)),
    };
    if !recover && mp4.truncated_tail().is_some() {
        return Err("strict parse reported a truncated tail".into());
    }
    let samples = mp4
        .samples()
        .iter()
        .map(|s| (s.source.clone(), s.sync_sample && s.contains_idr))
        .collect();
    let mut outcome = accepted(
        bytes,
        mp4.codec(),
        mp4.nal_length_bytes(),
        samples,
        mp4.parameter_sets(),
        mp4.truncated_tail(),
    )?;
    // Extraction from the first random-access sample: bounded and byte-exact.
    if let Parsed::Accepted { extraction, .. } = &mut outcome
        && let Some(first) = mp4
            .samples()
            .iter()
            .position(|s| s.sync_sample && s.contains_idr)
    {
        let count = mp4.samples().len() - first;
        *extraction = Some(match mp4.annex_b(first, count) {
            Ok(annex_b) => {
                let out = annex_b.bytes();
                if out.len() > limits().maximum_output_bytes {
                    return Err("extraction exceeds its output ceiling".into());
                }
                for mapping in annex_b.mappings() {
                    let copy =
                        out.get(mapping.output_start..mapping.output_start + mapping.source.len());
                    if mapping.output_start < 4
                        || out.get(mapping.output_start - 4..mapping.output_start)
                            != Some(&[0, 0, 0, 1][..])
                        || copy != bytes.get(mapping.source.clone())
                    {
                        return Err("extracted NAL is not a byte-exact copy".into());
                    }
                }
                Ok(out.len())
            }
            Err(error) => Err(error),
        });
    }
    Ok(outcome)
}

fn mkv_target(bytes: &[u8], recover: bool) -> Result<Parsed, String> {
    let parsed = if recover {
        MatroskaVideo::parse_recovering_tail(bytes, None, limits(), &mut || Ok(()))
    } else {
        MatroskaVideo::parse(bytes, None, limits())
    };
    let mkv = match parsed {
        Ok(mkv) => mkv,
        Err(error) => return Ok(Parsed::Refused(error)),
    };
    if !recover && mkv.truncated_tail().is_some() {
        return Err("strict parse reported a truncated tail".into());
    }
    let end = mkv.truncated_tail().unwrap_or(bytes.len());
    let mut cursor = 0;
    for element in mkv.elements() {
        if element.range.start != cursor || element.range.end < element.range.start {
            return Err(format!("element {element:?} breaks the tiling at {cursor}"));
        }
        cursor = element.range.end;
    }
    if cursor != end {
        return Err(format!("elements end at {cursor}, not at {end}"));
    }
    let samples = mkv
        .samples()
        .iter()
        .map(|s| (s.source.clone(), s.keyframe && s.contains_idr))
        .collect();
    accepted(
        bytes,
        mkv.codec(),
        mkv.nal_length_bytes(),
        samples,
        mkv.parameter_sets(),
        mkv.truncated_tail(),
    )
}

/// Both parsers on one mutant; the recovering one must agree with an accepting strict one.
fn both(
    bytes: &[u8],
    target: fn(&[u8], bool) -> Result<Parsed, String>,
) -> Result<(Parsed, Parsed), String> {
    let strict = target(bytes, false)?;
    let recovered = target(bytes, true)?;
    if let Parsed::Accepted { samples, tail, .. } = &strict {
        match &recovered {
            Parsed::Accepted {
                samples: kept,
                tail: None,
                ..
            } if kept == samples => {}
            other => {
                return Err(format!(
                    "recovering parse disagrees with an accepting strict parse \
                     ({} samples, tail {tail:?}): {other:?}",
                    samples.len()
                ));
            }
        }
    }
    Ok((strict, recovered))
}

fn run(
    target_name: &'static str,
    rng_seed: u64,
    seeds: &[Seed],
    mutants: usize,
    target: fn(&[u8], bool) -> Result<Parsed, String>,
) {
    for seed in seeds {
        let clean = both(&seed.bytes, target);
        let fine = matches!(
            &clean,
            Ok((
                Parsed::Accepted { tail: None, .. },
                Parsed::Accepted { tail: None, .. }
            ))
        );
        assert!(
            fine,
            "{target_name}: clean {} must parse: {clean:?}",
            seed.name
        );
    }
    let mut rng = Rng::new(rng_seed);
    let mut failures: Vec<Failure> = Vec::new();
    let mut tally = Tally::default();
    for index in 0..mutants {
        let class = CLASSES[index % CLASSES.len()];
        let seed = &seeds[(index / CLASSES.len()) % seeds.len()];
        let (mutation, bytes) = mutate_stacked(seed, seeds, class, &mut rng);
        tally.note(&mutation);
        tally.count(class);
        if let Some((strict, recovered)) = check(
            target_name,
            &seed.name,
            rng_seed,
            index,
            &mutation,
            &mut failures,
            || both(&bytes, target),
        ) {
            match (strict, recovered) {
                (Parsed::Accepted { .. }, _) => tally.ok += 1,
                (_, Parsed::Accepted { .. }) => tally.ok += 1,
                _ => tally.refused += 1,
            }
        }
    }
    report(target_name, &tally);
    assert_eq!(
        tally.mutants, mutants,
        "{target_name}: mutant count drifted"
    );
    assert!(
        tally.refused > 0 && tally.ok > 0,
        "{target_name}: degenerate outcomes"
    );
    assert!(failures.is_empty(), "{target_name}: {failures:#?}");
}

#[test]
fn mp4_demuxer_survives_mutation_gauntlet() {
    let seeds: Vec<Seed> = MP4_FIXTURES
        .iter()
        .map(|(name, bytes)| mp4_seed(name, bytes))
        .collect();
    run(
        "mp4-demux",
        0x0F55_0115_0000_D001,
        &seeds,
        MP4_MUTANTS,
        mp4_target,
    );
}

/// The same file with every CRC-32 element turned into a Void of the same size, so mutations
/// reach the block and frame checks instead of stopping at the integrity check.
fn without_crcs(bytes: &[u8]) -> Vec<u8> {
    let mut seed = Seed::new("", bytes.to_vec());
    ebml_elements(bytes, 0..bytes.len(), 0, &mut seed);
    let mut out = bytes.to_vec();
    for unit in &seed.units {
        if unit.len() == 6 && out[unit.start] == 0xBF && out[unit.start + 1] == 0x84 {
            out[unit.start..unit.end].copy_from_slice(&[0xEC, 0x84, 0, 0, 0, 0]);
        }
    }
    out
}

#[test]
fn matroska_demuxer_survives_mutation_gauntlet() {
    let mut seeds: Vec<Seed> = MKV_FIXTURES
        .iter()
        .map(|(name, bytes)| mkv_seed(name, bytes))
        .collect();
    for (name, bytes) in MKV_FIXTURES {
        let plain = without_crcs(bytes);
        assert_ne!(plain, bytes, "{name} carries CRC-32 elements");
        seeds.push(mkv_seed(&format!("{name}:no-crc"), &plain));
    }
    run(
        "mkv-demux",
        0x0F55_0115_0000_D002,
        &seeds,
        MKV_MUTANTS,
        mkv_target,
    );
}
