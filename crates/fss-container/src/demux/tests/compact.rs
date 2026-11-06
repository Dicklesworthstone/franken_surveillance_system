#![forbid(unsafe_code)]
//! Compact sample-size tables are metadata-only variants of the same retained video bytes.

use super::*;
use crate::demux::reader::be32;

/// Independent fixture writer for ISO BMFF 8.7.3.3. Moov-last fixtures keep every media
/// offset unchanged. A moov-first fixture uses a free box for available padding instead.
fn compact(bytes: &[u8], width: u8) -> Test<Vec<u8>> {
    let start = nth_box(bytes, b"stsz", 0) - 4;
    let old_len = be32(bytes, start)? as usize;
    let body = &bytes[start + 8..start + old_len];
    let fixed = be32(body, 4)?;
    let count = be32(body, 8)? as usize;
    let mut values = Vec::new();
    for index in 0..count {
        values.push(if fixed == 0 {
            be32(body, 12 + index * 4)?
        } else {
            fixed
        });
    }
    let mut payload = words(&[u32::from(width), count as u32]);
    match width {
        4 => {
            for pair in values.chunks(2) {
                assert!(pair.iter().all(|n| *n <= 15));
                payload.push(((pair[0] << 4) | pair.get(1).copied().unwrap_or(0)) as u8);
            }
        }
        8 => {
            for value in values {
                payload.push(u8::try_from(value)?);
            }
        }
        16 => {
            for value in values {
                payload.extend_from_slice(&u16::try_from(value)?.to_be_bytes());
            }
        }
        _ => return Err("invalid fixture field size".into()),
    }
    let mut replacement = full_atom(b"stz2", 0, 0, &payload);
    let mut removed = old_len
        .checked_sub(replacement.len())
        .ok_or("fixture grew")?;
    if nth_box(bytes, b"moov", 0) < nth_box(bytes, b"mdat", 0) && removed != 0 {
        let padding = removed
            .checked_sub(8)
            .ok_or("insufficient free-box space")?;
        replacement.extend(atom(b"free", &vec![0; padding]));
        removed = 0;
    }
    let mut result = bytes.to_vec();
    for kind in [b"moov", b"trak", b"mdia", b"minf", b"stbl"] {
        let at = nth_box(bytes, kind, 0) - 4;
        assert!(at < start);
        patch32(&mut result, at, be32(bytes, at)? - removed as u32);
    }
    result.splice(start..start + old_len, replacement);
    Ok(result)
}

#[test]
fn compact_widths_match_regular_sizes_across_lengths_chunks_and_odd_counts() -> Test {
    for width in [4, 8, 16] {
        for length in [1, 2, 4] {
            for co64 in [false, true] {
                for count in [3, 4] {
                    let f = fixture(
                        Options {
                            length,
                            co64,
                            signed_ctts: true,
                            ..Options::default()
                        },
                        &[3, 5, 7, 9][..count],
                    );
                    let bytes = compact(&f.bytes, width)?;
                    let plain = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
                    let packed = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
                    assert_eq!(packed.samples(), plain.samples());
                    assert_eq!(packed.work(), plain.work());
                    assert_eq!(
                        packed.annex_b(0, count)?.bytes(),
                        plain.annex_b(0, count)?.bytes()
                    );
                    for sample in packed.samples() {
                        assert_eq!(sample.source, f.sources[sample.index]);
                        assert_eq!(
                            &bytes[sample.source.clone()],
                            &f.bytes[sample.source.clone()]
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn compact_packing_is_high_nibble_first_and_reaches_each_width_maximum() -> Test {
    for (width, payload_size, expected) in [
        (4, 11, vec![0x5f]),
        (8, 251, vec![5, 255]),
        (16, 65_531, vec![0, 5, 255, 255]),
    ] {
        let f = fixture(Options::default(), &[1, payload_size]);
        let bytes = compact(&f.bytes, width)?;
        let packed = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
        assert_eq!(packed.samples()[1].source.len(), payload_size + 4);
        let data = field(&bytes, b"stz2", 12);
        assert_eq!(&bytes[data..data + expected.len()], &expected);
    }
    let odd = compact(&fixture(Options::default(), &[1, 3, 7]).bytes, 4)?;
    let data = field(&odd, b"stz2", 12);
    assert_eq!(&odd[data..data + 2], &[0x57, 0xb0]);
    Ok(())
}

#[test]
fn compact_tables_preserve_real_avc_hevc_and_mixed_recording_samples() -> Test {
    for bytes in [
        include_bytes!("../../../tests/fixtures/interleaved_av.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/hevc_av.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/mixed_av.mp4").as_slice(),
    ] {
        let rewritten = compact(bytes, 16)?;
        let plain = AvcMp4::parse(bytes, None, DemuxLimits::default())?;
        let packed = AvcMp4::parse(&rewritten, None, DemuxLimits::default())?;
        assert_eq!(packed.codec(), plain.codec());
        assert_eq!(packed.samples(), plain.samples());
        assert_eq!(packed.samples().len(), 10);
        assert_eq!(
            packed.annex_b(0, 10)?.bytes(),
            plain.annex_b(0, 10)?.bytes()
        );
        // Neither layout gets an independent sample allowance in the mixed fixture.
        assert_eq!(
            AvcMp4::parse(
                &rewritten,
                None,
                DemuxLimits {
                    maximum_samples: 9,
                    ..DemuxLimits::default()
                }
            )
            .map(|_| ()),
            Err(DemuxError::Limit)
        );
    }
    Ok(())
}

#[test]
fn an_empty_compact_table_bootstraps_fragments_but_not_an_empty_movie() -> Test {
    let original = include_bytes!("../../../tests/fixtures/fragmented_av.mp4");
    let plain = AvcMp4::parse(original, None, DemuxLimits::default())?;
    for width in [4, 8, 16] {
        let bytes = compact(original, width)?;
        let packed = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
        assert_eq!(packed.samples(), plain.samples());
        assert_eq!(
            packed.annex_b(0, 10)?.bytes(),
            plain.annex_b(0, 10)?.bytes()
        );
        let end = nth_box(&bytes, b"moof", 0) - 4;
        assert!(AvcMp4::parse(&bytes[..end], None, DemuxLimits::default()).is_err());
    }
    Ok(())
}

#[test]
fn size_table_variants_are_required_mutually_exclusive_singletons() -> Test {
    let f = fixture(
        Options {
            duplicate_sizes: true,
            ..Options::default()
        },
        &[3, 5, 7],
    );
    let both = compact(&f.bytes, 4)?;
    assert_eq!(
        AvcMp4::parse(&both, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Layout)
    );
    let mut duplicate = both;
    let regular = nth_box(&duplicate, b"stsz", 0);
    duplicate[regular..regular + 4].copy_from_slice(b"stz2");
    assert_eq!(
        AvcMp4::parse(&duplicate, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::DuplicateBox(*b"stz2"))
    );
    let f = fixture(Options::default(), &[3, 5]);
    let mut missing = compact(&f.bytes, 4)?;
    let at = nth_box(&missing, b"stz2", 0);
    missing[at..at + 4].copy_from_slice(b"free");
    assert_eq!(
        AvcMp4::parse(&missing, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::MissingBox(*b"stsz"))
    );
    Ok(())
}

#[test]
fn malformed_compact_headers_counts_sizes_and_padding_refuse() -> Test {
    let original = compact(&fixture(Options::default(), &[3, 5, 7]).bytes, 4)?;
    let start = field(&original, b"stz2", 0);
    let parse = |bytes: &[u8]| AvcMp4::parse(bytes, None, DemuxLimits::default()).map(|_| ());
    for (at, value, error) in [
        (0, 1, DemuxError::Unsupported), // version
        (3, 1, DemuxError::Unsupported), // flags
        (4, 1, DemuxError::Layout),
        (5, 1, DemuxError::Layout),
        (6, 1, DemuxError::Layout), // reserved
        (7, 0, DemuxError::Unsupported),
        (7, 3, DemuxError::Unsupported),
        (7, 12, DemuxError::Unsupported),
        (7, 32, DemuxError::Unsupported),
        (12, 0x09, DemuxError::Layout), // zero-size first sample
        (13, 0xb1, DemuxError::Layout), // nonzero odd padding nibble
    ] {
        let mut bytes = original.clone();
        bytes[start + at] = value;
        assert_eq!(parse(&bytes), Err(error), "offset {at}, value {value}");
    }
    for count in [0, 1, 2, 4, 5, u32::MAX] {
        let mut bytes = original.clone();
        patch32(&mut bytes, start + 8, count);
        assert!(parse(&bytes).is_err(), "count {count}");
    }
    for width in [8, 16] {
        let mut bytes = compact(&fixture(Options::default(), &[3, 5]).bytes, width)?;
        let data = field(&bytes, b"stz2", 12);
        bytes[data..data + usize::from(width / 8)].fill(0);
        assert_eq!(parse(&bytes), Err(DemuxError::Layout));
    }
    for cut in 0..original.len() {
        assert!(
            parse(&original[..cut]).is_err(),
            "truncated compact file at {cut}"
        );
    }
    Ok(())
}

#[test]
fn compact_counts_remain_bounded_and_cancellable_before_sample_publication() -> Test {
    let f = fixture(Options::default(), &vec![3; 600]);
    let bytes = compact(&f.bytes, 4)?;
    let limits = DemuxLimits::default();
    let mut visits = 0;
    let parsed = AvcMp4::parse_with_checkpoint(&bytes, None, limits, &mut || {
        visits += 1;
        Ok(())
    })?;
    let [boxes, entries, nals] = parsed.work();
    for narrowed in [
        DemuxLimits {
            maximum_samples: 599,
            ..limits
        },
        DemuxLimits {
            maximum_table_entries: entries - 1,
            ..limits
        },
        DemuxLimits {
            maximum_nals: nals - 1,
            ..limits
        },
        DemuxLimits {
            maximum_boxes: boxes - 1,
            ..limits
        },
    ] {
        assert_eq!(
            AvcMp4::parse(&bytes, None, narrowed).map(|_| ()),
            Err(DemuxError::Limit)
        );
    }
    // Cancel after admission has begun, including checkpoints inside compact-table expansion.
    for stop in 1..=visits {
        let mut seen = 0;
        assert_eq!(
            AvcMp4::parse_with_checkpoint(&bytes, None, limits, &mut || {
                seen += 1;
                if seen == stop {
                    Err(DemuxError::Cancelled)
                } else {
                    Ok(())
                }
            })
            .map(|_| ()),
            Err(DemuxError::Cancelled)
        );
        assert_eq!(seen, stop);
    }
    assert_eq!(
        AvcMp4::parse(&bytes, None, limits)?.samples(),
        parsed.samples()
    );
    Ok(())
}
