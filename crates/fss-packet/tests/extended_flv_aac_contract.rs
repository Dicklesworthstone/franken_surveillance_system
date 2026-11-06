#![forbid(unsafe_code)]
//! AAC-in-FLV framing, bounded interpretation, and exact source-span contracts.

use fss_packet::extended_flv::{Limits as FlvLimits, Parse, Tag, aac};
use std::io::Read;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn wire(kind: u8, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let size = payload.len();
    let mut result = vec![
        kind,
        (size >> 16) as u8,
        (size >> 8) as u8,
        size as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    result.extend_from_slice(payload);
    result.extend_from_slice(&(11_u32 + size as u32).to_be_bytes());
    result
}

fn audio<'a>(source: &'a [u8], limits: aac::Limits) -> Result<aac::AudioTag<'a>, aac::Error> {
    let tag = match Tag::parse(source, FlvLimits::default()) {
        Ok(Parse::Complete(tag)) => tag,
        _ => return Err(aac::Error::UnsupportedConfiguration),
    };
    aac::AudioTag::parse(tag, limits)
}

#[test]
fn observed_aac_lc_profile_preserves_source_and_configuration() -> TestResult {
    // Synthetic AAC-LC, 16 kHz, mono, 1024 samples, matching the observed shape.
    let source = wire(8, 0x0123_4567, &[0xaf, 0, 0x14, 0x08]);
    let parsed = audio(&source, aac::Limits::default())?;
    assert_eq!(parsed.packet_type(), aac::PacketType::Configuration);
    assert_eq!(parsed.sender_header(), 0xaf);
    assert_eq!(parsed.timestamp_ms(), 0x0123_4567);
    assert_eq!(parsed.wire_bytes(), source);
    let config = parsed.configuration()?;
    assert_eq!(config.origin(), aac::ConfigurationOrigin::AudioTag);
    assert_eq!(config.bytes(), &[0x14, 0x08]);
    assert_eq!(&source[config.source_range()], config.bytes());
    assert_eq!(config.sample_rate(), 16_000);
    assert_eq!(config.channel_configuration(), 1);
    assert_eq!(config.channels(), 1);
    assert_eq!(config.frame_samples(), 1024);
    Ok(())
}

#[test]
fn raw_body_and_wrapping_timestamp_are_borrowed_without_codec_claims() -> TestResult {
    let source = wire(8, u32::MAX, &[0xaf, 1, 0xde, 0xad, 0xbe, 0xef]);
    let parsed = audio(&source, aac::Limits::default())?;
    assert_eq!(parsed.packet_type(), aac::PacketType::Raw);
    assert_eq!(parsed.timestamp_ms(), u32::MAX);
    assert_eq!(parsed.body(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(&source[parsed.body_range()], parsed.body());
    assert_eq!(parsed.configuration(), Err(aac::Error::WrongPacketType));
    assert!(!format!("{parsed:?}").contains("de, ad"));
    Ok(())
}

#[test]
fn rejects_unsupported_or_ambiguous_configuration() -> TestResult {
    let cases: &[(&[u8], aac::Error)] = &[
        (&[0x0c, 0x08], aac::Error::UnsupportedObjectType),
        (&[0x16, 0x88], aac::Error::UnsupportedSampleRate),
        (&[0x17, 0x88], aac::Error::UnsupportedSampleRate),
        (&[0x14, 0x00], aac::Error::UnsupportedChannelConfiguration),
        (&[0x14, 0x40], aac::Error::UnsupportedChannelConfiguration),
        (&[0x14, 0x09], aac::Error::UnsupportedGaFlags),
        (&[0x14, 0x0a], aac::Error::UnsupportedGaFlags),
        (&[0x14], aac::Error::UnsupportedConfiguration),
        (&[0x14, 0x08, 0x00], aac::Error::UnsupportedConfiguration),
    ];
    for (config, expected) in cases {
        let mut payload = vec![0xaf, 0];
        payload.extend_from_slice(config);
        let source = wire(8, 0, &payload);
        assert_eq!(
            audio(&source, aac::Limits::default())?.configuration(),
            Err(*expected)
        );
        assert_eq!(aac::Configuration::parse_explicit(config), Err(*expected));
    }
    Ok(())
}

#[test]
fn explicit_config_preserves_its_separate_source_and_matches_tag_properties() -> TestResult {
    let bytes = [0x14, 0x08];
    let explicit = aac::Configuration::parse_explicit(&bytes)?;
    let source = wire(8, 0, &[0xaf, 0, 0x14, 0x08]);
    let in_tag = audio(&source, aac::Limits::default())?.configuration()?;
    assert_eq!(explicit.origin(), aac::ConfigurationOrigin::ExplicitBytes);
    assert_eq!(explicit.source_range(), 0..bytes.len());
    assert_eq!(&bytes[explicit.source_range()], explicit.bytes());
    assert_eq!(explicit.sample_rate(), in_tag.sample_rate());
    assert_eq!(explicit.channels(), in_tag.channels());
    assert_eq!(explicit.frame_samples(), in_tag.frame_samples());
    assert_ne!(explicit.origin(), in_tag.origin());
    Ok(())
}

#[test]
fn reports_supported_short_frames_and_eight_channel_layout() -> TestResult {
    let short = wire(8, 0, &[0xaf, 0, 0x14, 0x0c]);
    assert_eq!(
        audio(&short, aac::Limits::default())?
            .configuration()?
            .frame_samples(),
        960
    );
    let surround = wire(8, 0, &[0xaf, 0, 0x14, 0x38]);
    let config = audio(&surround, aac::Limits::default())?.configuration()?;
    assert_eq!(config.channel_configuration(), 7);
    assert_eq!(config.channels(), 8);
    Ok(())
}

#[test]
fn rejects_wrong_kind_headers_and_limits_without_disclosing_payload() {
    let cases: &[(u8, &[u8], aac::Limits, aac::Error)] = &[
        (
            9,
            &[0xaf, 1, 1],
            aac::Limits::default(),
            aac::Error::NotAudio,
        ),
        (
            8,
            &[0xaf],
            aac::Limits::default(),
            aac::Error::TruncatedHeader,
        ),
        (
            8,
            &[0x2f, 1, 1],
            aac::Limits::default(),
            aac::Error::UnsupportedPacket,
        ),
        (
            8,
            &[0xaf, 2, 1],
            aac::Limits::default(),
            aac::Error::UnsupportedPacket,
        ),
        (8, &[0xaf, 1], aac::Limits::default(), aac::Error::EmptyBody),
        (
            8,
            &[0xaf, 1, 1, 2],
            aac::Limits { max_body_bytes: 1 },
            aac::Error::BodyLimit,
        ),
        (
            8,
            &[0xaf, 1, 1],
            aac::Limits { max_body_bytes: 0 },
            aac::Error::InvalidLimits,
        ),
    ];
    for (kind, payload, limits, expected) in cases {
        let source = wire(*kind, 0, payload);
        assert_eq!(audio(&source, *limits), Err(*expected));
    }
}

#[test]
#[ignore = "requires an explicitly authorized, bounded audio capture on stdin"]
fn owner_camera_audio_replay() -> TestResult {
    use fss_packet::extended_flv::stream::{Framer, Next, SearchMode};

    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut input)?;
    if input.len() > 8 * 1024 * 1024 || !input.starts_with(b"FLV\x01") {
        return Err("invalid bounded laboratory input".into());
    }
    let mut framer = Framer::with_mode(
        FlvLimits::default(),
        8 * 1024 * 1024,
        SearchMode::StructuredTrailer16,
    )?;
    framer.append(0, &input)?;
    let (mut records, mut raw, mut configurations, mut raw_bytes) =
        (0usize, 0usize, 0usize, 0usize);
    while let Next::Record(record) = framer.take()? {
        records += 1;
        if records > 10_000 {
            return Err("laboratory record limit".into());
        }
        let offset = usize::try_from(record.offset())?;
        let end = offset
            .checked_add(record.bytes().len())
            .ok_or("offset overflow")?;
        if input.get(offset..end) != Some(record.bytes()) {
            return Err("source record mismatch".into());
        }
        let Some(range) = record.tag_range() else {
            continue;
        };
        let Some(bytes) = record.bytes().get(range.clone()) else {
            return Err("tag range mismatch".into());
        };
        let Parse::Complete(tag) = Tag::parse(bytes, FlvLimits::default())? else {
            return Err("source tag incomplete".into());
        };
        if tag.wire_bytes().len() != bytes.len() {
            return Err("source tag length mismatch".into());
        }
        if tag.kind() != 8 {
            continue;
        }
        let audio = aac::AudioTag::parse(tag, aac::Limits::default())?;
        let body = audio.body_range();
        let body_start = offset
            .checked_add(range.start)
            .and_then(|v| v.checked_add(body.start))
            .ok_or("body offset overflow")?;
        let body_end = body_start
            .checked_add(audio.body().len())
            .ok_or("body end overflow")?;
        if input.get(body_start..body_end) != Some(audio.body()) {
            return Err("audio source range mismatch".into());
        }
        match audio.packet_type() {
            aac::PacketType::Raw => {
                raw += 1;
                raw_bytes = raw_bytes
                    .checked_add(audio.body().len())
                    .ok_or("audio byte limit")?;
            }
            aac::PacketType::Configuration => {
                let _ = audio.configuration()?;
                configurations += 1;
            }
        }
    }
    let remainder = framer.retire();
    let offset = usize::try_from(remainder.offset)?;
    if input.get(offset..) != Some(remainder.bytes()) {
        return Err("unparsed tail mismatch".into());
    }
    if raw == 0 {
        return Err("no AAC raw tags".into());
    }
    println!(
        "aac_raw_tags={raw} aac_raw_bytes={raw_bytes} aac_configurations={configurations} records={records} tail_bytes={} source=caller_supplied frame_decode=not_attempted authentication=unverified media_saved=no",
        remainder.bytes().len()
    );
    Ok(())
}
