#![forbid(unsafe_code)]
//! FSS-059 malformed-media gauntlet for the H.265/HEVC pixel decoder.
//!
//! `hostile_input.rs` already covers per-NAL truncation at every byte, single-byte XOR
//! corruption and random garbage; this gauntlet adds the remaining FSS-059 classes over the
//! checked-in conformance fixtures: boundary-byte substitution biased to NAL headers
//! and parameter sets, truncation at every NAL boundary (+-1 byte), NAL duplication,
//! cross-stream NAL splicing, start-code / emulation-prevention injection, NAL
//! reordering, and exhaustive single-NAL deletion. Annex-B elementary streams carry
//! no binary length fields, so the length-field class is exercised in fss-packet
//! (AP / FU sizes) instead of here.
//!
//! Invariants per mutant (run twice): no panic in a debug build (overflow checks on),
//! only typed `DecodeError`s, every published picture inside the narrowed owner
//! `DecoderLimits` with self-consistent planes, at most one picture per fed NAL unit
//! and never more than `max_pictures`, bit-identical outcome on the second run, and
//! for truncations/deletions every published picture is bit-identical to a picture of
//! the clean decode (nothing partial or concealed is published).
//!
//! No-Claim: evidence against these mutation classes over this corpus only; not
//! coverage-guided fuzzing and not a proof.

#[path = "../../fss-packet/tests/media_mutation/mod.rs"]
mod media_mutation;

use fss_codec_h265::{DecodeError, Decoder, DecoderLimits, annex_b_nal_units};
use media_mutation::{
    CLASSES, Class, Failure, Mutation, Rng, Seed, Tally, annex_b_markers, annex_b_units, check,
    mutate_stacked, report,
};

const FIXTURES: [(&str, &[u8]); 8] = [
    (
        "pcm_mixed_nodeblock",
        include_bytes!("fixtures/decode/pcm_mixed_nodeblock.h265"),
    ),
    (
        "i_qcif_nostrong",
        include_bytes!("fixtures/decode/i_qcif_nostrong.h265"),
    ),
    (
        "i_qcif_tskip",
        include_bytes!("fixtures/decode/i_qcif_tskip.h265"),
    ),
    (
        "f_mandel_sao_only",
        include_bytes!("fixtures/decode/f_mandel_sao_only.h265"),
    ),
    (
        "p_100x60_crop",
        include_bytes!("fixtures/decode/p_100x60_crop.h265"),
    ),
    (
        "f_100x60_full",
        include_bytes!("fixtures/decode/f_100x60_full.h265"),
    ),
    (
        "p_mandel_tu_inter",
        include_bytes!("fixtures/decode/p_mandel_tu_inter.h265"),
    ),
    (
        "f_qcif_deblock_offsets",
        include_bytes!("fixtures/decode/f_qcif_deblock_offsets.h265"),
    ),
];

/// Mutants in the randomized gauntlet (exhaustive NAL cuts/deletions are extra).
const MUTANTS: usize = 3_000;

/// Narrowed owner limits: every fixture fits (largest is QCIF).
fn limits() -> DecoderLimits {
    DecoderLimits {
        max_width: 192,
        max_height: 160,
        max_luma_samples: 192 * 160,
        max_pictures: 64,
        max_nal_bytes: 64 * 1024,
        max_slices_per_picture: 16,
        max_dpb_pictures: 16,
    }
}

fn seed(name: &str, bytes: &[u8]) -> Seed {
    let mut seed = Seed::new(name, bytes.to_vec());
    seed.units = annex_b_units(bytes);
    seed.markers = annex_b_markers();
    // Forged two-byte NAL headers: VPS, SPS, PPS, IDR_W_RADL, CRA, TRAIL_R, a
    // nonzero layer, temporal id zero, and the forbidden bit.
    for header in [
        [0x40_u8, 0x01],
        [0x42, 0x01],
        [0x44, 0x01],
        [0x26, 0x01],
        [0x2A, 0x01],
        [0x02, 0x01],
        [0x02, 0x09],
        [0x02, 0x00],
        [0x80, 0x01],
    ] {
        seed.markers.push(vec![0, 0, 1, header[0], header[1]]);
    }
    seed
}

/// Determinism fingerprint of one decode.
#[derive(Debug, PartialEq)]
struct Outcome {
    pictures: Vec<(u32, u32, i32, [u8; 32])>,
    errors: Vec<DecodeError>,
}

/// Lossy decode that keeps feeding after errors (exercising wait-for-IDR recovery).
fn decode(bytes: &[u8]) -> Result<Outcome, String> {
    let limits = limits();
    let mut decoder = Decoder::new(limits).map_err(|e| format!("limits refused: {e:?}"))?;
    let mut pictures = Vec::new();
    let mut errors = Vec::new();
    let mut nals = 0_usize;
    let mut take = |picture: fss_codec_h265::Picture| -> Result<(), String> {
        let (w, h) = (picture.width(), picture.height());
        let (cw, ch) = (picture.chroma_width(), picture.chroma_height());
        if w == 0
            || h == 0
            || w > limits.max_width
            || h > limits.max_height
            || u64::from(w) * u64::from(h) > limits.max_luma_samples
            || cw != w.div_ceil(2)
            || ch != h.div_ceil(2)
            || picture.luma().len() != (w * h) as usize
            || picture.cb().len() != (cw * ch) as usize
            || picture.cr().len() != (cw * ch) as usize
        {
            return Err(format!("picture {w}x{h} violates declared limits/planes"));
        }
        pictures.push((w, h, picture.poc(), picture.i420_sha256()));
        Ok(())
    };
    for nal in annex_b_nal_units(bytes) {
        nals += 1;
        match decoder.decode_nal(nal) {
            Ok(Some(picture)) => take(picture)?,
            Ok(None) => {}
            Err(error) => errors.push(error),
        }
        while let Some(picture) = decoder.next_output() {
            take(picture)?;
        }
    }
    match decoder.finish() {
        Ok(rest) => {
            for picture in rest {
                take(picture)?;
            }
        }
        Err(error) => {
            errors.push(error);
            while let Some(picture) = decoder.next_output() {
                take(picture)?;
            }
        }
    }
    if pictures.len() > nals || pictures.len() as u64 > limits.max_pictures {
        return Err(format!(
            "{} pictures from {nals} NAL units exceeds the work bound",
            pictures.len()
        ));
    }
    Ok(Outcome { pictures, errors })
}

fn clean_digests(bytes: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    let outcome = decode(bytes)?;
    if !outcome.errors.is_empty() || outcome.pictures.is_empty() {
        return Err(format!("clean fixture refused: {:?}", outcome.errors));
    }
    Ok(outcome.pictures.iter().map(|p| p.3).collect())
}

fn only_clean(outcome: &Outcome, clean: &[[u8; 32]]) -> Result<(), String> {
    match outcome.pictures.iter().find(|p| !clean.contains(&p.3)) {
        Some(p) => Err(format!(
            "published picture poc {} is not a clean picture (partial/concealed output)",
            p.2
        )),
        None => Ok(()),
    }
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

#[test]
fn h265_decoder_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0265;
    let seeds: Vec<Seed> = FIXTURES.iter().map(|(n, b)| seed(n, b)).collect();
    let clean: Vec<Vec<[u8; 32]>> = seeds
        .iter()
        .map(|s| clean_digests(&s.bytes).unwrap_or_default())
        .collect();
    assert!(clean.iter().all(|c| !c.is_empty()), "clean fixtures decode");
    // Annex-B has no binary length fields; see the module documentation.
    let classes: Vec<Class> = CLASSES
        .iter()
        .copied()
        .filter(|c| *c != Class::LengthField)
        .collect();
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..MUTANTS {
        let slot = index % seeds.len();
        let seed = &seeds[slot];
        let class = classes[(index / seeds.len()) % classes.len()];
        let (mutation, bytes) = mutate_stacked(seed, &seeds, class, &mut rng);
        tally.count(class);
        tally.note(&mutation);
        let prefix = matches!(mutation, Mutation::Truncate { .. });
        let run = || -> Result<Outcome, String> {
            let outcome = decode(&bytes)?;
            if prefix {
                only_clean(&outcome, &clean[slot])?;
            }
            Ok(outcome)
        };
        if let Some(outcome) = check(
            "h265",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if outcome.errors.is_empty() {
                tally.ok += 1;
            } else {
                tally.refused += 1;
            }
        }
    }
    finish("h265", &tally, failures, MUTANTS);
}

/// Exhaustive structural cuts (every NAL boundary and its +-1 neighbours) and every
/// single-NAL deletion: only bit-exact clean pictures may ever be published.
#[test]
fn h265_structural_truncation_and_nal_loss_publish_only_clean_pictures() {
    let mut failures = Vec::new();
    let mut cuts = 0;
    let mut deletions = 0;
    for (name, bytes) in FIXTURES {
        let seed = seed(name, bytes);
        let clean = clean_digests(bytes).unwrap_or_default();
        assert!(!clean.is_empty(), "{name} decodes cleanly");
        for cut in seed.structural_cuts() {
            cuts += 1;
            let mutation = Mutation::Truncate {
                len: cut,
                structural: true,
            };
            let run = || {
                let outcome = decode(&bytes[..cut])?;
                only_clean(&outcome, &clean)?;
                Ok(outcome)
            };
            check("h265-cut", name, 0, cut, &mutation, &mut failures, run);
        }
        for (index, unit) in seed.units.iter().enumerate() {
            deletions += 1;
            let mut damaged = bytes[..unit.start].to_vec();
            damaged.extend_from_slice(&bytes[unit.end..]);
            let mutation = Mutation::Splice {
                donor: "delete".into(),
                from: unit.start..unit.start,
                replaced: unit.clone(),
            };
            let run = || {
                let outcome = decode(&damaged)?;
                only_clean(&outcome, &clean)?;
                Ok(outcome)
            };
            check("h265-delete", name, 0, index, &mutation, &mut failures, run);
        }
    }
    println!(
        "FSS-059 gauntlet h265-structural: {cuts} NAL-boundary cuts, {deletions} single-NAL deletions"
    );
    assert!(failures.is_empty(), "{failures:#?}");
}
