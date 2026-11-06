#![forbid(unsafe_code)]
//! Explicit AAC configuration and bounded ADTS framing contracts.

use fss_packet::extended_flv::{Limits as FlvLimits, Parse, Tag, aac, aac_adts};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn wire(payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = vec![
        8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    out.extend_from_slice(payload);
    out.extend_from_slice(&(11_u32 + len as u32).to_be_bytes());
    out
}

fn audio(source: &[u8]) -> Result<aac::AudioTag<'_>, Box<dyn std::error::Error>> {
    let Parse::Complete(tag) = Tag::parse(source, FlvLimits::default())? else {
        return Err("incomplete fixture".into());
    };
    Ok(aac::AudioTag::parse(tag, aac::Limits::default())?)
}

#[test]
fn known_aac_lc_header_describes_exact_payload() -> TestResult {
    let config_wire = wire(&[0xaf, 0, 0x14, 0x08]);
    let config = audio(&config_wire)?.configuration()?;
    let raw_wire = wire(&[0xaf, 1, 0xde, 0xad, 0xbe, 0xef]);
    let raw = audio(&raw_wire)?;
    assert_eq!(
        aac_adts::header(&config, raw)?,
        [0xff, 0xf1, 0x60, 0x40, 0x01, 0x7f, 0xfc]
    );
    assert_eq!(raw.body(), &[0xde, 0xad, 0xbe, 0xef]);
    let external_bytes = [0x14, 0x08];
    let external = aac::Configuration::parse_explicit(&external_bytes)?;
    assert_eq!(
        aac_adts::header(&external, raw)?,
        aac_adts::header(&config, raw)?
    );
    Ok(())
}

#[test]
fn refuses_non_raw_and_short_frame_modes() -> TestResult {
    let normal_wire = wire(&[0xaf, 0, 0x14, 0x08]);
    let normal_tag = audio(&normal_wire)?;
    let normal = normal_tag.configuration()?;
    assert_eq!(
        aac_adts::header(&normal, normal_tag),
        Err(aac_adts::Error::NotRaw)
    );
    let short_wire = wire(&[0xaf, 0, 0x14, 0x0c]);
    let short = audio(&short_wire)?.configuration()?;
    let raw_wire = wire(&[0xaf, 1, 0x42]);
    assert_eq!(
        aac_adts::header(&short, audio(&raw_wire)?),
        Err(aac_adts::Error::ShortFrame)
    );
    Ok(())
}

#[test]
fn frame_length_field_accepts_its_exact_limit_and_rejects_overflow() -> TestResult {
    let config_wire = wire(&[0xaf, 0, 0x14, 0x08]);
    let config = audio(&config_wire)?.configuration()?;
    let mut payload = vec![0xaf, 1];
    payload.resize(2 + 8184, 0x55);
    let max_wire = wire(&payload);
    let header = aac_adts::header(&config, audio(&max_wire)?)?;
    let declared = (usize::from(header[3] & 3) << 11)
        | (usize::from(header[4]) << 3)
        | usize::from(header[5] >> 5);
    assert_eq!(declared, 8191);
    payload.push(0x55);
    let too_large_wire = wire(&payload);
    assert_eq!(
        aac_adts::header(&config, audio(&too_large_wire)?),
        Err(aac_adts::Error::FrameTooLarge)
    );
    Ok(())
}
