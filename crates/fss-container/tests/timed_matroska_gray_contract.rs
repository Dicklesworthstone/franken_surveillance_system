#![forbid(unsafe_code)]
//! Timed production framing inspected with an independent bounded EBML reader.
//! No source-clock conversion, async runtime, filesystem durability or playback behavior
//! is substituted here. Gaps are timestamp holes, not generated black frames.

use fss_container::matroska_gray::{
    GrayMatroskaConfig, MAX_DIMENSION, MAX_FRAMES, MAX_PIXELS, MAX_TIMED_DURATION_NS,
    MatroskaGrayError, PlaybackRate, TimedGrayMatroskaConfig,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Element<'a> {
    id: u32,
    bytes: &'a [u8],
    consumed: usize,
    unknown: bool,
}

fn element(input: &[u8]) -> Test<Element<'_>> {
    let id_width = input.first().ok_or("missing ID")?.leading_zeros() as usize + 1;
    if id_width > 4 {
        return Err("invalid ID width".into());
    }
    let id = input
        .get(..id_width)
        .ok_or("truncated ID")?
        .iter()
        .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
    let head = *input.get(id_width).ok_or("missing size")?;
    let size_width = head.leading_zeros() as usize + 1;
    if size_width > 8 {
        return Err("invalid size width".into());
    }
    let header = id_width + size_width;
    let mut size = u64::from(head & (((1_u16 << (8 - size_width)) - 1) as u8));
    for byte in input.get(id_width + 1..header).ok_or("truncated size")? {
        size = (size << 8) | u64::from(*byte);
    }
    let unknown = size == (1_u64 << (7 * size_width)) - 1;
    let consumed = if unknown {
        input.len()
    } else {
        header
            .checked_add(usize::try_from(size)?)
            .ok_or("size overflow")?
    };
    Ok(Element {
        id,
        bytes: input.get(header..consumed).ok_or("truncated payload")?,
        consumed,
        unknown,
    })
}

fn elements(mut input: &[u8]) -> Test<Vec<Element<'_>>> {
    let mut result = Vec::new();
    while !input.is_empty() {
        if result.len() > 1026 {
            return Err("reader element limit".into());
        }
        let next = element(input)?;
        if next.consumed == 0 {
            return Err("reader made no progress".into());
        }
        input = &input[next.consumed..];
        result.push(next);
    }
    Ok(result)
}

fn child<'a>(children: &[Element<'a>], id: u32) -> Test<&'a [u8]> {
    let mut found = children.iter().filter(|value| value.id == id);
    let value = found.next().ok_or("missing child")?;
    if value.unknown || found.next().is_some() {
        return Err("unbounded or repeated child".into());
    }
    Ok(value.bytes)
}

fn integer(bytes: &[u8]) -> Test<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err("invalid integer".into());
    }
    Ok(bytes
        .iter()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte)))
}

fn duration_bits(initialization: &[u8]) -> Test<u64> {
    let root = elements(initialization)?;
    assert_eq!(root.len(), 2);
    assert_eq!((root[0].id, root[1].id), (0x1a45dfa3, 0x18538067));
    assert!(!root[0].unknown && root[1].unknown);
    let segment = elements(root[1].bytes)?;
    assert_eq!(
        segment.iter().map(|e| e.id).collect::<Vec<_>>(),
        [0x1549a966, 0x1654ae6b]
    );
    let info = elements(child(&segment, 0x1549a966)?)?;
    assert_eq!(
        info.iter().map(|e| e.id).collect::<Vec<_>>(),
        [0x2ad7b1, 0x4489, 0x4d80, 0x5741]
    );
    assert_eq!(integer(child(&info, 0x2ad7b1)?)?, 1);
    Ok(u64::from_be_bytes(child(&info, 0x4489)?.try_into()?))
}

#[test]
fn declared_duration_uses_exact_big_endian_binary64_in_nanosecond_segment_ticks() -> Test {
    // Exact IEEE754 bit patterns, including the boundary where float32 loses integer ns.
    for (duration, bits) in [
        (1, 0x3ff0_0000_0000_0000),
        (2, 0x4000_0000_0000_0000),
        (16_777_217, 0x4170_0000_1000_0000),
        (MAX_TIMED_DURATION_NS - 1, 0x433f_ffff_ffff_ffff),
        (MAX_TIMED_DURATION_NS, 0x4340_0000_0000_0000),
    ] {
        let config = TimedGrayMatroskaConfig::new([7, 5], duration)?;
        assert_eq!(config.dimensions(), [7, 5]);
        assert_eq!(config.duration_ns(), duration);
        let initialization = config.initialization()?;
        let actual = duration_bits(initialization.bytes())?;
        assert_eq!(actual, bits);
        let value = f64::from_bits(actual);
        assert!(value.is_finite() && value > 0.0);
        assert_eq!(value as u64, duration);
        assert!(initialization.bytes().len() <= 256);
    }
    Ok(())
}

#[test]
fn timed_dimensions_clip_duration_and_each_interval_are_checked_without_pixel_allocation() -> Test {
    for dimensions in [
        [0, 1],
        [1, 0],
        [MAX_DIMENSION + 1, 1],
        [4096, 1025],
        [u32::MAX, u32::MAX],
    ] {
        assert_eq!(
            TimedGrayMatroskaConfig::new(dimensions, 1),
            Err(MatroskaGrayError::InvalidDimensions)
        );
    }
    for duration in [0, MAX_TIMED_DURATION_NS + 1, u64::MAX] {
        assert_eq!(
            TimedGrayMatroskaConfig::new([1, 1], duration),
            Err(MatroskaGrayError::Timeline)
        );
    }
    for dimensions in [[1, 1], [7, 5], [4096, 1024], [1024, 4096], [2048, 2048]] {
        let config = TimedGrayMatroskaConfig::new(dimensions, MAX_TIMED_DURATION_NS)?;
        let last = config.frame(
            MAX_FRAMES - 1,
            MAX_TIMED_DURATION_NS - 1,
            MAX_TIMED_DURATION_NS,
        )?;
        assert_eq!(last.timestamp_ns(), MAX_TIMED_DURATION_NS - 1);
        assert_eq!(last.end_ns(), MAX_TIMED_DURATION_NS);
        assert_eq!(last.duration_ns(), 1);
        assert_eq!(
            last.payload_bytes(),
            dimensions[0] as usize * dimensions[1] as usize
        );
        assert!(last.payload_bytes() <= MAX_PIXELS);
        assert!(last.prefix().len() <= 64);
        assert!(config.initialization()?.bytes().len() <= 256);
        for ordinal in [MAX_FRAMES, MAX_FRAMES + 1, u64::MAX] {
            assert_eq!(
                config.frame(ordinal, 0, 1),
                Err(MatroskaGrayError::FrameLimit)
            );
        }
        for (start, end) in [
            (0, 0),
            (1, 1),
            (1, 0),
            (u64::MAX, 1),
            (0, MAX_TIMED_DURATION_NS + 1),
            (0, u64::MAX),
        ] {
            assert_eq!(
                config.frame(0, start, end),
                Err(MatroskaGrayError::Timeline)
            );
        }
    }
    Ok(())
}

#[test]
fn leading_internal_and_trailing_gaps_remain_holes_with_exact_pixels_and_clip_envelope() -> Test {
    let duration = 1_000_000_000;
    let config = TimedGrayMatroskaConfig::new([7, 5], duration)?;
    let intervals = [
        (100_000_000, 200_000_000),
        (350_000_000, 350_000_001),
        (500_000_000, 900_000_000),
    ];
    let mut bytes = config.initialization()?.bytes().to_vec();
    let mut expected = Vec::new();
    for (ordinal, (start, end)) in intervals.iter().copied().enumerate() {
        let frame = config.frame(ordinal as u64, start, end)?;
        assert_eq!(
            (frame.timestamp_ns(), frame.end_ns(), frame.duration_ns()),
            (start, end, end - start)
        );
        let pixels: Vec<_> = (0..35)
            .map(|index| ((index * 17 + ordinal * 29) & 255) as u8)
            .collect();
        bytes.extend_from_slice(frame.prefix());
        bytes.extend_from_slice(&pixels);
        expected.push(pixels);
    }
    let root = elements(&bytes)?;
    let segment = elements(root[1].bytes)?;
    let info = elements(child(&segment, 0x1549a966)?)?;
    let declared = f64::from_be_bytes(child(&info, 0x4489)?.try_into()?) as u64;
    assert_eq!(declared, duration);
    let clusters: Vec<_> = segment.iter().filter(|e| e.id == 0x1f43b675).collect();
    assert_eq!(
        clusters.len(),
        intervals.len(),
        "no pictures are synthesized for gaps"
    );
    for (ordinal, cluster) in clusters.into_iter().enumerate() {
        assert!(!cluster.unknown);
        let children = elements(cluster.bytes)?;
        assert_eq!(
            children.iter().map(|e| e.id).collect::<Vec<_>>(),
            [0xe7, 0xa0]
        );
        assert_eq!(integer(child(&children, 0xe7)?)?, intervals[ordinal].0);
        let group = elements(child(&children, 0xa0)?)?;
        assert_eq!(group.iter().map(|e| e.id).collect::<Vec<_>>(), [0x9b, 0xa1]);
        assert_eq!(
            integer(child(&group, 0x9b)?)?,
            intervals[ordinal].1 - intervals[ordinal].0
        );
        let block = child(&group, 0xa1)?;
        assert_eq!(&block[..4], &[0x81, 0, 0, 0]);
        assert_eq!(&block[4..], expected[ordinal].as_slice());
    }
    assert!(intervals[0].0 > 0);
    assert!(intervals.windows(2).all(|pair| pair[0].1 < pair[1].0));
    assert!(intervals.last().ok_or("last interval")?.1 < declared);
    // A complete declared duration does not hide a truncated finite Cluster payload.
    bytes.pop().ok_or("last pixel")?;
    let root = elements(&bytes)?;
    assert!(elements(root[1].bytes).is_err());
    Ok(())
}

#[test]
fn explicit_timestamps_are_independent_of_ordinal_and_have_no_relative_i16_limit() -> Test {
    let config = TimedGrayMatroskaConfig::new([1, 1], MAX_TIMED_DURATION_NS)?;
    for (start, end) in [
        (0, 1),
        (0, MAX_TIMED_DURATION_NS),
        (255, 256),
        (65_535, 65_536),
        (u32::MAX as u64, u32::MAX as u64 + 1),
        (MAX_TIMED_DURATION_NS - 17, MAX_TIMED_DURATION_NS),
    ] {
        let first = config.frame(0, start, end)?;
        let last = config.frame(MAX_FRAMES - 1, start, end)?;
        assert_eq!(
            first, last,
            "ordinal is an allowance, never a synthetic cadence"
        );
        let mut bytes = first.prefix().to_vec();
        bytes.push(93);
        let cluster = element(&bytes)?;
        assert_eq!(cluster.consumed, bytes.len());
        let children = elements(cluster.bytes)?;
        assert_eq!(integer(child(&children, 0xe7)?)?, start);
        let group = elements(child(&children, 0xa0)?)?;
        assert_eq!(integer(child(&group, 0x9b)?)?, end - start);
        assert_eq!(child(&group, 0xa1)?, [0x81, 0, 0, 0, 93]);
    }
    Ok(())
}

#[test]
fn uniform_wire_profile_stays_unchanged_and_explicit_frames_share_identical_framing() -> Test {
    let one = GrayMatroskaConfig::new([1, 1], PlaybackRate::new(1, 1)?)?;
    assert_eq!(
        one.frame(0)?.prefix(),
        [
            0x1f, 0x43, 0xb6, 0x75, 0x92, 0xe7, 0x81, 0x00, 0xa0, 0x8d, 0x9b, 0x84, 0x3b, 0x9a,
            0xca, 0x00, 0xa1, 0x85, 0x81, 0x00, 0x00, 0x00,
        ]
    );
    let initialization = one.initialization()?;
    let roots = elements(initialization.bytes())?;
    let children = elements(roots[1].bytes)?;
    let info = elements(child(&children, 0x1549a966)?)?;
    assert_eq!(
        info.iter().map(|e| e.id).collect::<Vec<_>>(),
        [0x2ad7b1, 0x4d80, 0x5741]
    );
    assert!(info.iter().all(|e| e.id != 0x4489));
    for (numerator, denominator) in [(1, 1), (30, 1), (30_000, 1001), (1_000_000, 1)] {
        let uniform = GrayMatroskaConfig::new([7, 5], PlaybackRate::new(numerator, denominator)?)?;
        let duration = uniform.frame(MAX_FRAMES - 1)?.end_ns();
        let timed = TimedGrayMatroskaConfig::new([7, 5], duration)?;
        for ordinal in [0, 1, 2, 255, 256, MAX_FRAMES - 1] {
            let prior = uniform.frame(ordinal)?;
            assert_eq!(
                prior,
                timed.frame(ordinal, prior.timestamp_ns(), prior.end_ns())?
            );
        }
        let uniform_header = uniform.initialization()?;
        let timed_header = timed.initialization()?;
        let uniform_root = elements(uniform_header.bytes())?;
        let timed_root = elements(timed_header.bytes())?;
        assert_eq!(uniform_root[0].bytes, timed_root[0].bytes);
        let uniform_segment = elements(uniform_root[1].bytes)?;
        let timed_segment = elements(timed_root[1].bytes)?;
        assert_eq!(
            child(&uniform_segment, 0x1654ae6b)?,
            child(&timed_segment, 0x1654ae6b)?
        );
        assert_eq!(
            timed_header.bytes().len(),
            uniform_header.bytes().len() + 11
        );
    }
    Ok(())
}
