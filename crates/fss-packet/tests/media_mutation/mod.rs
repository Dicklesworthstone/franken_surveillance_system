#![forbid(unsafe_code)]
//! Deterministic, dependency-free mutation engine for the FSS-059 malformed-media gauntlets.
//!
//! One source file is shared (via `#[path]`) by the fss-codec-mjpeg, fss-codec-h264,
//! fss-codec-h265, fss-container and fss-packet gauntlets, so every crate applies the
//! same mutation classes with the same fixed-seed PRNG. Nothing here reads a clock,
//! the environment, a file or a network: a (seed name, PRNG seed, mutant index)
//! triple reproduces every mutant exactly.
//!
//! A green gauntlet is evidence of robustness against these mutation classes over the
//! checked-in seed corpus only. It is not coverage-guided fuzzing and not a proof.
#![allow(dead_code)]

use std::fmt::Debug;
use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// splitmix64: tiny, well-distributed, and fully specified by its 64-bit state.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform-enough index in `0..n`; zero when `n == 0`.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            items.get(self.below(items.len()))
        }
    }
}

/// Boundary substitution values required by FSS-059.
pub const BOUNDARY_BYTES: [u8; 4] = [0x00, 0xFF, 0x7F, 0x80];

/// Mutation classes, applied round-robin so every class gets an equal share.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Class {
    BitFlip,
    BoundaryByte,
    StructuralTruncation,
    RandomTruncation,
    Duplicate,
    Splice,
    LengthField,
    Injection,
    Reorder,
}

pub const CLASSES: [Class; 9] = [
    Class::BitFlip,
    Class::BoundaryByte,
    Class::StructuralTruncation,
    Class::RandomTruncation,
    Class::Duplicate,
    Class::Splice,
    Class::LengthField,
    Class::Injection,
    Class::Reorder,
];

/// A length-bearing field inside a seed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LengthField {
    /// Big-endian binary integer of `width` bytes (1..=4) starting at `offset`.
    Binary { offset: usize, width: usize },
    /// A run of ASCII decimal digits (HTTP Content-Length).
    Decimal { range: Range<usize> },
    /// A run of ASCII hexadecimal digits (HTTP chunk size).
    Hex { range: Range<usize> },
}

/// One corpus member plus the structure the mutators aim at.
#[derive(Clone, Debug)]
pub struct Seed {
    pub name: String,
    pub bytes: Vec<u8>,
    /// Structural units (segments, NAL units, header lines, parts), in source order.
    pub units: Vec<Range<usize>>,
    pub length_fields: Vec<LengthField>,
    /// Marker / start-code / delimiter patterns worth injecting.
    pub markers: Vec<Vec<u8>>,
}

impl Seed {
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            bytes,
            units: Vec::new(),
            length_fields: Vec::new(),
            markers: Vec::new(),
        }
    }
    /// Every structural boundary (unit starts and ends), sorted and deduplicated.
    pub fn boundaries(&self) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .units
            .iter()
            .flat_map(|unit| [unit.start, unit.end])
            .filter(|&at| at <= self.bytes.len())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
    /// Exhaustive structural truncation points: every boundary and its +-1 neighbours.
    pub fn structural_cuts(&self) -> Vec<usize> {
        let mut out = Vec::new();
        for at in self.boundaries() {
            for cut in [at.saturating_sub(1), at, at.saturating_add(1)] {
                if cut < self.bytes.len() {
                    out.push(cut);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// Exact, reproducible description of one mutation (printed on failure).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mutation {
    BitFlips(Vec<(usize, u8)>),
    Substitute(Vec<(usize, u8)>),
    Truncate {
        len: usize,
        structural: bool,
    },
    Duplicate {
        from: Range<usize>,
        at: usize,
    },
    Splice {
        donor: String,
        from: Range<usize>,
        replaced: Range<usize>,
    },
    Length {
        field: LengthField,
        value: String,
    },
    Inject {
        at: usize,
        pattern: Vec<u8>,
    },
    Swap {
        a: Range<usize>,
        b: Range<usize>,
    },
    Reverse {
        units: Range<usize>,
    },
    /// Class requested but inapplicable to this seed; a bit flip was used instead.
    Fallback(Box<Mutation>),
    /// Several mutations applied in order, the first of the requested class.
    Stacked(Vec<Mutation>),
}

fn bit_flips(bytes: &mut [u8], rng: &mut Rng) -> Mutation {
    let mut flips = Vec::new();
    if bytes.is_empty() {
        return Mutation::BitFlips(flips);
    }
    for _ in 0..1 + rng.below(4) {
        let at = rng.below(bytes.len());
        let bit = rng.below(8) as u8;
        if let Some(byte) = bytes.get_mut(at) {
            *byte ^= 1 << bit;
        }
        flips.push((at, bit));
    }
    Mutation::BitFlips(flips)
}

fn header_biased_offset(seed: &Seed, rng: &mut Rng) -> usize {
    // Half of the substitutions land in the first 12 bytes of a unit (headers, lengths,
    // parameter-set fields); the rest anywhere.
    if rng.below(2) == 0
        && let Some(unit) = rng.pick(&seed.units).cloned()
    {
        let span = unit.end.saturating_sub(unit.start).clamp(1, 12);
        return (unit.start + rng.below(span)).min(seed.bytes.len().saturating_sub(1));
    }
    rng.below(seed.bytes.len())
}

fn set_length(bytes: &mut Vec<u8>, field: &LengthField, rng: &mut Rng) -> Option<String> {
    match field {
        LengthField::Binary { offset, width } => {
            let width = (*width).clamp(1, 4);
            let end = offset.checked_add(width)?;
            let slot = bytes.get(*offset..end)?;
            let original = slot.iter().fold(0_u64, |v, b| (v << 8) | u64::from(*b));
            let max = (1_u64 << (8 * width)) - 1;
            let (label, value) = match rng.below(4) {
                0 => ("zero", 0),
                1 => ("max", max),
                2 => ("plus_one", original.wrapping_add(1) & max),
                _ => ("minus_one", original.wrapping_sub(1) & max),
            };
            for (i, byte) in bytes.get_mut(*offset..end)?.iter_mut().enumerate() {
                *byte = (value >> (8 * (width - 1 - i))) as u8;
            }
            Some(format!("{label}={value}"))
        }
        LengthField::Decimal { range } | LengthField::Hex { range } => {
            let hex = matches!(field, LengthField::Hex { .. });
            let text = std::str::from_utf8(bytes.get(range.clone())?).ok()?;
            let original = if hex {
                u64::from_str_radix(text, 16).ok()?
            } else {
                text.parse::<u64>().ok()?
            };
            let render = |v: u64| {
                if hex { format!("{v:x}") } else { v.to_string() }
            };
            let replacement = match rng.below(5) {
                0 => "0".to_string(),
                1 => render(u64::MAX),
                2 => "99999999999999999999999999".to_string(),
                3 => render(original.saturating_add(1)),
                _ => render(original.saturating_sub(1)),
            };
            bytes.splice(range.clone(), replacement.bytes());
            Some(replacement)
        }
    }
}

/// Apply one mutation of `class` to `seed`. `donors` supply splice material.
pub fn mutate(seed: &Seed, donors: &[Seed], class: Class, rng: &mut Rng) -> (Mutation, Vec<u8>) {
    let mut bytes = seed.bytes.clone();
    let len = bytes.len();
    let fallback = |bytes: &mut Vec<u8>, rng: &mut Rng| {
        let inner = bit_flips(bytes, rng);
        Mutation::Fallback(Box::new(inner))
    };
    if len == 0 {
        return (Mutation::BitFlips(Vec::new()), bytes);
    }
    let mutation = match class {
        Class::BitFlip => bit_flips(&mut bytes, rng),
        Class::BoundaryByte => {
            let mut edits = Vec::new();
            for _ in 0..1 + rng.below(2) {
                let at = header_biased_offset(seed, rng);
                let value = BOUNDARY_BYTES[rng.below(BOUNDARY_BYTES.len())];
                if let Some(byte) = bytes.get_mut(at) {
                    *byte = value;
                }
                edits.push((at, value));
            }
            Mutation::Substitute(edits)
        }
        Class::StructuralTruncation => {
            let cuts = seed.structural_cuts();
            match rng.pick(&cuts) {
                Some(&cut) => {
                    bytes.truncate(cut);
                    Mutation::Truncate {
                        len: cut,
                        structural: true,
                    }
                }
                None => fallback(&mut bytes, rng),
            }
        }
        Class::RandomTruncation => {
            let cut = rng.below(len);
            bytes.truncate(cut);
            Mutation::Truncate {
                len: cut,
                structural: false,
            }
        }
        Class::Duplicate => {
            let from = rng.pick(&seed.units).cloned().unwrap_or_else(|| {
                let start = rng.below(len);
                start..(start + 1 + rng.below(16)).min(len)
            });
            let boundaries = seed.boundaries();
            let at = if rng.below(2) == 0 {
                from.end
            } else {
                rng.pick(&boundaries).copied().unwrap_or(from.end)
            }
            .min(len);
            match seed.bytes.get(from.clone()) {
                Some(copy) => {
                    bytes.splice(at..at, copy.iter().copied());
                    Mutation::Duplicate { from, at }
                }
                None => fallback(&mut bytes, rng),
            }
        }
        Class::Splice => {
            let donor = if donors.is_empty() {
                seed
            } else {
                &donors[rng.below(donors.len())]
            };
            let from = rng.pick(&donor.units).cloned();
            let replaced = rng.pick(&seed.units).cloned();
            match (from, replaced) {
                (Some(from), Some(replaced))
                    if donor.bytes.get(from.clone()).is_some() && replaced.end <= len =>
                {
                    let material = donor.bytes.get(from.clone()).unwrap_or(&[]).to_vec();
                    bytes.splice(replaced.clone(), material);
                    Mutation::Splice {
                        donor: donor.name.clone(),
                        from,
                        replaced,
                    }
                }
                _ => fallback(&mut bytes, rng),
            }
        }
        Class::LengthField => match rng.pick(&seed.length_fields).cloned() {
            Some(field) => match set_length(&mut bytes, &field, rng) {
                Some(value) => Mutation::Length { field, value },
                None => fallback(&mut bytes, rng),
            },
            None => fallback(&mut bytes, rng),
        },
        Class::Injection => match rng.pick(&seed.markers).cloned() {
            Some(pattern) => {
                let boundaries = seed.boundaries();
                let at = if rng.below(2) == 0 {
                    rng.pick(&boundaries).copied().unwrap_or(0)
                } else {
                    rng.below(len + 1)
                }
                .min(len);
                bytes.splice(at..at, pattern.iter().copied());
                Mutation::Inject { at, pattern }
            }
            None => fallback(&mut bytes, rng),
        },
        Class::Reorder => {
            let units = &seed.units;
            if units.len() < 2 {
                fallback(&mut bytes, rng)
            } else if rng.below(4) == 0 && units.len() >= 3 {
                let start = rng.below(units.len() - 2);
                let end = (start + 2 + rng.below(units.len() - start - 1)).min(units.len());
                bytes = reassemble(seed, |order| order[start..end].reverse());
                Mutation::Reverse { units: start..end }
            } else {
                let a = rng.below(units.len());
                let b = if rng.below(2) == 0 {
                    (a + 1) % units.len()
                } else {
                    rng.below(units.len())
                };
                bytes = reassemble(seed, |order| order.swap(a, b));
                Mutation::Swap {
                    a: units[a].clone(),
                    b: units[b].clone(),
                }
            }
        }
    };
    (mutation, bytes)
}

/// One mutation of `class`; one mutant in three then receives one or two further
/// mutations of pseudo-random classes, reusing the seed's (now approximate) structure.
/// Every structural access is bounds-checked, so stale offsets only reduce precision.
pub fn mutate_stacked(
    seed: &Seed,
    donors: &[Seed],
    class: Class,
    rng: &mut Rng,
) -> (Mutation, Vec<u8>) {
    let (first, bytes) = mutate(seed, donors, class, rng);
    if rng.below(3) != 0 {
        return (first, bytes);
    }
    let mut steps = vec![first];
    let mut current = Seed {
        bytes,
        ..seed.clone()
    };
    for _ in 0..1 + rng.below(2) {
        let extra = CLASSES[rng.below(CLASSES.len())];
        let (mutation, bytes) = mutate(&current, donors, extra, rng);
        steps.push(mutation);
        current.bytes = bytes;
    }
    (Mutation::Stacked(steps), current.bytes)
}

/// Rebuild a seed with its units permuted; bytes outside units keep their position.
fn reassemble(seed: &Seed, permute: impl FnOnce(&mut Vec<usize>)) -> Vec<u8> {
    let mut order: Vec<usize> = (0..seed.units.len()).collect();
    permute(&mut order);
    let mut out = Vec::with_capacity(seed.bytes.len());
    let mut cursor = 0;
    for (slot, unit) in seed.units.iter().enumerate() {
        if let Some(gap) = seed.bytes.get(cursor..unit.start) {
            out.extend_from_slice(gap);
        }
        let chosen = order.get(slot).and_then(|&i| seed.units.get(i));
        if let Some(bytes) = chosen.and_then(|u| seed.bytes.get(u.clone())) {
            out.extend_from_slice(bytes);
        }
        cursor = unit.end.max(cursor);
    }
    if let Some(tail) = seed.bytes.get(cursor..) {
        out.extend_from_slice(tail);
    }
    out
}

/// A sequence mutation over packets / NAL units (list elements are the structural units).
pub fn mutate_sequence(
    items: &[Seed],
    class: Class,
    rng: &mut Rng,
) -> (Option<usize>, Mutation, Vec<Vec<u8>>) {
    let mut out: Vec<Vec<u8>> = items.iter().map(|s| s.bytes.clone()).collect();
    if items.is_empty() {
        return (None, Mutation::BitFlips(Vec::new()), out);
    }
    match class {
        Class::StructuralTruncation if rng.below(2) == 0 => {
            // Drop the tail of the sequence at an element boundary.
            let keep = rng.below(items.len());
            out.truncate(keep);
            (
                None,
                Mutation::Truncate {
                    len: keep,
                    structural: true,
                },
                out,
            )
        }
        Class::Duplicate if rng.below(2) == 0 => {
            let from = rng.below(items.len());
            let at = rng.below(items.len() + 1);
            let copy = out[from].clone();
            out.insert(at, copy);
            (
                None,
                Mutation::Duplicate {
                    from: from..from + 1,
                    at,
                },
                out,
            )
        }
        Class::Splice if rng.below(2) == 0 => {
            // Drop one element (lost packet / NAL): splice the neighbours together.
            let drop = rng.below(items.len());
            out.remove(drop);
            (
                None,
                Mutation::Splice {
                    donor: "drop".to_string(),
                    from: drop..drop,
                    replaced: drop..drop + 1,
                },
                out,
            )
        }
        Class::Reorder => {
            if items.len() < 2 {
                return (
                    None,
                    Mutation::Fallback(Box::new(Mutation::BitFlips(Vec::new()))),
                    out,
                );
            }
            if rng.below(4) == 0 && items.len() >= 3 {
                let start = rng.below(items.len() - 2);
                let end = (start + 2 + rng.below(items.len() - start - 1)).min(items.len());
                out[start..end].reverse();
                (None, Mutation::Reverse { units: start..end }, out)
            } else {
                let a = rng.below(items.len());
                let b = if rng.below(2) == 0 {
                    (a + 1) % items.len()
                } else {
                    rng.below(items.len())
                };
                out.swap(a, b);
                (
                    None,
                    Mutation::Swap {
                        a: a..a + 1,
                        b: b..b + 1,
                    },
                    out,
                )
            }
        }
        _ => {
            // Byte-level mutation inside one element, using that element's structure.
            let index = rng.below(items.len());
            let (mutation, bytes) = mutate_stacked(&items[index], items, class, rng);
            out[index] = bytes;
            (Some(index), mutation, out)
        }
    }
}

/// Per-class tally for the report.
#[derive(Clone, Debug, Default)]
pub struct Tally {
    pub mutants: usize,
    pub per_class: Vec<(Class, usize)>,
    pub ok: usize,
    pub refused: usize,
    /// Mutants whose requested class did not apply to the seed (bit flip used instead).
    pub fallbacks: usize,
    /// Mutants that carry more than one stacked mutation.
    pub stacked: usize,
}

impl Tally {
    pub fn count(&mut self, class: Class) {
        self.mutants += 1;
        match self.per_class.iter_mut().find(|(c, _)| *c == class) {
            Some((_, n)) => *n += 1,
            None => self.per_class.push((class, 1)),
        }
    }
    pub fn note(&mut self, mutation: &Mutation) {
        match mutation {
            Mutation::Fallback(_) => self.fallbacks += 1,
            Mutation::Stacked(steps) => {
                self.stacked += 1;
                if matches!(steps.first(), Some(Mutation::Fallback(_))) {
                    self.fallbacks += 1;
                }
            }
            _ => {}
        }
    }
}

/// One failing mutant, reproducible from its identity.
#[derive(Debug)]
pub struct Failure {
    pub target: &'static str,
    pub seed: String,
    pub rng_seed: u64,
    pub index: usize,
    pub mutation: String,
    pub problem: String,
}

/// Run `target` twice on each mutant: a panic or a nondeterministic outcome is a failure;
/// `target` itself returns `Err(problem)` for any violated invariant.
pub fn check<O: Debug + PartialEq>(
    target: &'static str,
    seed: &str,
    rng_seed: u64,
    index: usize,
    mutation: &dyn Debug,
    failures: &mut Vec<Failure>,
    mut run: impl FnMut() -> Result<O, String>,
) -> Option<O> {
    let mut once = || catch_unwind(AssertUnwindSafe(&mut run));
    let first = once();
    let second = once();
    let problem = match (first, second) {
        (Ok(Ok(a)), Ok(Ok(b))) => {
            if a == b {
                return Some(a);
            }
            format!("nondeterministic: {a:?} != {b:?}")
        }
        (Ok(Err(problem)), _) | (_, Ok(Err(problem))) => problem,
        (Err(payload), _) | (_, Err(payload)) => {
            let text = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            format!("panic: {text}")
        }
    };
    failures.push(Failure {
        target,
        seed: seed.to_string(),
        rng_seed,
        index,
        mutation: format!("{mutation:?}"),
        problem,
    });
    None
}

/// Report line printed by every gauntlet (visible with `--nocapture`).
pub fn report(target: &str, tally: &Tally) {
    println!(
        "FSS-059 gauntlet {target}: {} mutants ({} ok, {} typed refusals, {} stacked, {} class fallbacks) per class {:?}",
        tally.mutants, tally.ok, tally.refused, tally.stacked, tally.fallbacks, tally.per_class
    );
}

/// Split Annex-B bytes into (start-code-inclusive unit ranges, NAL payload ranges).
pub fn annex_b_units(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut starts = Vec::new();
    let mut at = 0;
    while at + 3 <= bytes.len() {
        if bytes[at] == 0 && bytes[at + 1] == 0 && bytes[at + 2] == 1 {
            let begin = if at > 0 && bytes[at - 1] == 0 {
                at - 1
            } else {
                at
            };
            starts.push(begin);
            at += 3;
        } else {
            at += 1;
        }
    }
    let mut units = Vec::new();
    for (i, &start) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(bytes.len());
        if start < end {
            units.push(start..end);
        }
    }
    units
}

/// Annex-B start codes and emulation-prevention patterns for injection.
pub fn annex_b_markers() -> Vec<Vec<u8>> {
    vec![
        vec![0, 0, 1],
        vec![0, 0, 0, 1],
        vec![0, 0, 3],
        vec![0, 0, 0],
        vec![0, 0, 1, 0],
    ]
}
