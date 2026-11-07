#![forbid(unsafe_code)]
//! Actual public Matroska framing with a separate bounded EBML reader.
//! No production EBML helper is reused by the reader or numerical checks.

use fss_container::matroska_gray::{
    FrameFraming, GrayMatroskaConfig, Initialization, MAX_DIMENSION, MAX_FRAMES,
    MAX_PIXELS, MAX_RATE_COMPONENT, MatroskaGrayError, PlaybackRate,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct Element<'a> {
    id: u32,
    payload: &'a [u8],
    consumed: usize,
    unknown_size: bool,
}

fn element(input: &[u8]) -> Test<Element<'_>> {
    let first = *input.first().ok_or("missing EBML ID")?;
    let id_width = first.leading_zeros() as usize + 1;
    if id_width > 4 {
        return Err("invalid EBML ID width".into());
    }
    let id = input.get(..id_width).ok_or("truncated ID")?
        .iter().fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
    let first = *input.get(id_width).ok_or("missing EBML size")?;
    let size_width = first.leading_zeros() as usize + 1;
    if size_width > 8 {
        return Err("invalid EBML size width".into());
    }
    let header = id_width.checked_add(size_width).ok_or("header overflow")?;
    let mask = ((1_u16 << (8 - size_width)) - 1) as u8;
    let mut size = u64::from(first & mask);
    for byte in input.get(id_width + 1..header).ok_or("truncated size")? {
        size = (size << 8) | u64::from(*byte);
    }
    let unknown_size = size == (1_u64 << (size_width * 7)) - 1;
    let consumed = if unknown_size {
        input.len()
    } else {
        header.checked_add(usize::try_from(size)?).ok_or("element overflow")?
    };
    let payload = input.get(header..consumed).ok_or("truncated payload")?;
    Ok(Element { id, payload, consumed, unknown_size })
}

fn elements(mut input: &[u8]) -> Test<Vec<Element<'_>>> {
    let mut result = Vec::new();
    while !input.is_empty() {
        if result.len() >= 2048 {
            return Err("test reader child bound".into());
        }
        let next = element(input)?;
        if next.consumed == 0 {
            return Err("test reader made no progress".into());
        }
        input = &input[next.consumed..];
        result.push(next);
    }
    Ok(result)
}

fn child<'a>(children: &[Element<'a>], id: u32) -> Test<&'a [u8]> {
    let mut matching = children.iter().filter(|element| element.id == id);
    let result = matching.next().ok_or("missing child")?;
    if matching.next().is_some() || result.unknown_size {
        return Err("duplicate or unbounded child".into());
    }
    Ok(result.payload)
}

fn integer(bytes: &[u8]) -> Test<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err("invalid unsigned integer".into());
    }
    Ok(bytes.iter().fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)))
}

fn ids(children: &[Element<'_>]) -> Vec<u32> {
    children.iter().map(|element| element.id).collect()
}

fn pixels(dimensions: [u32; 2], ordinal: u64) -> Vec<u8> {
    let [width, height] = dimensions;
    (0..height).flat_map(|y| (0..width).map(move |x| {
        if x > width / 3 && x < width * 2 / 3 && y > height / 3 {
            if ordinal.is_multiple_of(2) { 0 } else { 16 }
        } else {
            ((u64::from(x) * 37 + u64::from(y) * 71 + ordinal * 101) & 255) as u8
        }
    })).collect()
}

#[test]
fn playback_rate_admits_only_bounded_positive_components_and_reduces_exactly() -> Test {
    let ntsc = PlaybackRate::new(30_000, 1001)?;
    assert_eq!(ntsc.numerator(), 30_000);
    assert_eq!(ntsc.denominator(), 1001);
    assert_eq!(PlaybackRate::new(60_000, 2002)?, ntsc);
    assert_eq!(PlaybackRate::new(1_000_000, 1_000_000)?, PlaybackRate::new(1, 1)?);
    for (numerator, denominator) in [
        (0, 1), (1, 0), (0, 0), (MAX_RATE_COMPONENT + 1, 1),
        (1, MAX_RATE_COMPONENT + 1), (u32::MAX, u32::MAX),
        (MAX_RATE_COMPONENT + 1, MAX_RATE_COMPONENT + 1),
    ] {
        assert_eq!(PlaybackRate::new(numerator, denominator), Err(MatroskaGrayError::InvalidRate));
    }
    Ok(())
}

#[test]
fn dimensions_pixels_and_ordinals_refuse_outside_the_profile_without_image_storage() -> Test {
    let rate = PlaybackRate::new(1, 1)?;
    for dimensions in [
        [0, 1], [1, 0], [0, 0], [MAX_DIMENSION + 1, 1],
        [1, MAX_DIMENSION + 1], [4096, 1025], [2048, 2049], [u32::MAX, u32::MAX],
    ] {
        assert_eq!(GrayMatroskaConfig::new(dimensions, rate), Err(MatroskaGrayError::InvalidDimensions));
    }
    for dimensions in [[1, 1], [1, 4096], [4096, 1], [4096, 1024], [1024, 4096], [2048, 2048]] {
        let config = GrayMatroskaConfig::new(dimensions, rate)?;
        assert_eq!(config.dimensions(), dimensions);
        assert_eq!(config.rate(), rate);
        let frame = config.frame(MAX_FRAMES - 1)?;
        assert_eq!(frame.payload_bytes(), dimensions[0] as usize * dimensions[1] as usize);
        assert!(frame.payload_bytes() <= MAX_PIXELS);
        assert!(frame.prefix().len() <= 64);
        assert!(config.initialization()?.bytes().len() <= 256);
        assert_eq!(frame.end_ns(), 1_024_000_000_000);
        for ordinal in [MAX_FRAMES, MAX_FRAMES + 1, u64::MAX] {
            assert_eq!(config.frame(ordinal), Err(MatroskaGrayError::FrameLimit));
        }
    }
    assert!(std::mem::size_of::<FrameFraming>() <= 128);
    assert!(std::mem::size_of::<Initialization>() <= 272);
    Ok(())
}

#[test]
fn initialization_declares_one_uncompressed_progressive_gray_track_without_source_metadata() -> Test {
    for dimensions in [[1, 1], [7, 5], [4096, 1024]] {
        let config = GrayMatroskaConfig::new(dimensions, PlaybackRate::new(30_000, 1001)?)?;
        let initialization = config.initialization()?;
        assert_eq!(initialization.as_ref(), initialization.bytes());
        let root = elements(initialization.bytes())?;
        assert_eq!(ids(&root), [0x1a45dfa3, 0x18538067]);
        assert!(!root[0].unknown_size);
        assert!(root[1].unknown_size);
        let ebml = elements(root[0].payload)?;
        assert_eq!(ids(&ebml), [0x4286, 0x42f7, 0x42f2, 0x42f3, 0x4282, 0x4287, 0x4285]);
        assert_eq!(child(&ebml, 0x4282)?, b"matroska");
        for (id, value) in [(0x4286, 1), (0x42f7, 1), (0x42f2, 4), (0x42f3, 8), (0x4287, 4), (0x4285, 2)] {
            assert_eq!(integer(child(&ebml, id)?)?, value);
        }
        let segment = elements(root[1].payload)?;
        assert_eq!(ids(&segment), [0x1549a966, 0x1654ae6b]);
        let info = elements(child(&segment, 0x1549a966)?)?;
        assert_eq!(ids(&info), [0x2ad7b1, 0x4d80, 0x5741]);
        assert_eq!(integer(child(&info, 0x2ad7b1)?)?, 1);
        assert_eq!(child(&info, 0x4d80)?, b"fss.matroska_gray.v1");
        assert_eq!(child(&info, 0x5741)?, b"fss.matroska_gray.v1");
        let tracks = elements(child(&segment, 0x1654ae6b)?)?;
        assert_eq!(ids(&tracks), [0xae]);
        let track = elements(child(&tracks, 0xae)?)?;
        assert_eq!(ids(&track), [0xd7, 0x73c5, 0x83, 0x9c, 0x86, 0xe0]);
        for (id, value) in [(0xd7, 1), (0x73c5, 1), (0x83, 1), (0x9c, 0)] {
            assert_eq!(integer(child(&track, id)?)?, value);
        }
        assert_eq!(child(&track, 0x86)?, b"V_UNCOMPRESSED");
        let video = elements(child(&track, 0xe0)?)?;
        assert_eq!(ids(&video), [0x9a, 0xb0, 0xba, 0x2eb524, 0x55b0]);
        assert_eq!(integer(child(&video, 0x9a)?)?, 2);
        assert_eq!(integer(child(&video, 0xb0)?)?, u64::from(dimensions[0]));
        assert_eq!(integer(child(&video, 0xba)?)?, u64::from(dimensions[1]));
        assert_eq!(child(&video, 0x2eb524)?, b"Y800");
        let colour = elements(child(&video, 0x55b0)?)?;
        assert_eq!(ids(&colour), [0x55b2, 0x55b9]);
        assert_eq!(integer(child(&colour, 0x55b2)?)?, 8);
        assert_eq!(integer(child(&colour, 0x55b9)?)?, 2);
    }
    Ok(())
}

#[test]
fn finite_frame_layout_preserves_every_payload_byte_including_odd_rows_and_mask_values() -> Test {
    for dimensions in [[1, 1], [7, 5], [65, 37], [256, 1]] {
        let config = GrayMatroskaConfig::new(dimensions, PlaybackRate::new(10, 1)?)?;
        let mut stream = config.initialization()?.bytes().to_vec();
        let mut expected = Vec::new();
        for ordinal in 0..3 {
            let frame = config.frame(ordinal)?;
            let samples = pixels(dimensions, ordinal);
            assert_eq!(frame.payload_bytes(), samples.len());
            stream.extend_from_slice(frame.prefix());
            stream.extend_from_slice(&samples);
            expected.push(samples);
        }
        let root = elements(&stream)?;
        let segment = elements(root[1].payload)?;
        assert_eq!(ids(&segment), [0x1549a966, 0x1654ae6b, 0x1f43b675, 0x1f43b675, 0x1f43b675]);
        for (ordinal, cluster) in segment[2..].iter().enumerate() {
            assert!(!cluster.unknown_size);
            let members = elements(cluster.payload)?;
            assert_eq!(ids(&members), [0xe7, 0xa0]);
            assert_eq!(integer(child(&members, 0xe7)?)?, ordinal as u64 * 100_000_000);
            let group = elements(child(&members, 0xa0)?)?;
            assert_eq!(ids(&group), [0x9b, 0xa1]);
            assert_eq!(integer(child(&group, 0x9b)?)?, 100_000_000);
            let block = child(&group, 0xa1)?;
            assert_eq!(&block[..4], &[0x81, 0, 0, 0]);
            assert_eq!(&block[4..], expected[ordinal].as_slice());
        }
        // The open Segment does not hide an incomplete last finite Cluster.
        assert!(stream.pop().is_some());
        let truncated = elements(&stream)?;
        assert!(elements(truncated[1].payload).is_err());
    }
    Ok(())
}

#[test]
fn rational_playback_boundaries_do_not_accumulate_rounded_duration_error() -> Test {
    for (numerator, denominator) in [
        (1_u32, 1_u32), (30, 1), (24_000, 1001), (30_000, 1001),
        (60_000, 1001), (1_000_000, 1), (1, 1_000_000), (999_983, 999_979),
    ] {
        let config = GrayMatroskaConfig::new([1, 1], PlaybackRate::new(numerator, denominator)?)?;
        // Independent quotient/remainder decomposition of the period.
        let period_numerator = 1_000_000_000_u64 * u64::from(denominator);
        let whole = period_numerator / u64::from(numerator);
        let remainder = period_numerator % u64::from(numerator);
        let boundary = |ordinal: u64| ordinal * whole + ordinal * remainder / u64::from(numerator);
        let mut duration_sum = 0_u64;
        for ordinal in 0..MAX_FRAMES {
            let frame = config.frame(ordinal)?;
            assert_eq!(frame.timestamp_ns(), boundary(ordinal));
            assert_eq!(frame.end_ns(), boundary(ordinal + 1));
            assert_eq!(frame.duration_ns(), frame.end_ns() - frame.timestamp_ns());
            assert!(frame.duration_ns() > 0);
            assert_eq!(frame.timestamp_ns(), duration_sum);
            duration_sum += frame.duration_ns();
            let exact_scaled = u128::from(ordinal + 1) * u128::from(period_numerator);
            let rounded_scaled = u128::from(frame.end_ns()) * u128::from(numerator);
            assert!(rounded_scaled <= exact_scaled);
            assert!(exact_scaled - rounded_scaled < u128::from(numerator));
        }
        assert_eq!(duration_sum, boundary(MAX_FRAMES));
    }
    let thirty = GrayMatroskaConfig::new([1, 1], PlaybackRate::new(30, 1)?)?;
    assert_eq!(thirty.frame(0)?.duration_ns(), 33_333_333);
    assert_eq!(thirty.frame(1)?.duration_ns(), 33_333_333);
    assert_eq!(thirty.frame(2)?.duration_ns(), 33_333_334);
    assert_eq!(thirty.frame(2)?.end_ns(), 100_000_000);
    let ntsc = GrayMatroskaConfig::new([1, 1], PlaybackRate::new(30_000, 1001)?)?;
    assert_eq!(ntsc.frame(0)?.duration_ns(), 33_366_666);
    assert_eq!(ntsc.frame(1)?.duration_ns(), 33_366_667);
    assert_eq!(ntsc.frame(2)?.end_ns(), 100_100_000);
    Ok(())
}

#[test]
fn equivalent_rates_and_repeated_queries_have_canonical_framing() -> Test {
    let a = GrayMatroskaConfig::new([17, 19], PlaybackRate::new(60_000, 2002)?)?;
    let b = GrayMatroskaConfig::new([17, 19], PlaybackRate::new(30_000, 1001)?)?;
    assert_eq!(a, b);
    assert_eq!(a.initialization()?, b.initialization()?);
    for ordinal in [0, 1, 2, 63, 64, 1022, 1023] {
        assert_eq!(a.frame(ordinal)?, b.frame(ordinal)?);
        assert_eq!(a.frame(ordinal)?, a.frame(ordinal)?);
    }
    // The track's image declaration is independent of playback cadence.
    let different_rate = GrayMatroskaConfig::new([17, 19], PlaybackRate::new(10, 1)?)?;
    assert_eq!(a.initialization()?, different_rate.initialization()?);
    assert_ne!(a.frame(0)?.prefix(), different_rate.frame(0)?.prefix());
    Ok(())
}
