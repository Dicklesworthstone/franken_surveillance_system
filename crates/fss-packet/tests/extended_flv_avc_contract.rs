#![forbid(unsafe_code)]
//! Synthetic AVC-in-FLV configuration, timing, and exact source-span contracts.

#[allow(dead_code)]
mod avc_support;

use fss_packet::avc::{AvcSyntaxLimits, parse_pps, parse_slice_identity, parse_sps};
use fss_packet::extended_flv::{Limits as FlvLimits, Parse, Tag, avc};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn tag(kind: u8, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = vec![
        kind,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    out.extend_from_slice(payload);
    out.extend_from_slice(&(11_u32 + n as u32).to_be_bytes());
    out
}

fn config(width_code: u8) -> Vec<u8> {
    // Structurally framed SPS/PPS; this is deliberately not a full codec fixture.
    tag(
        9,
        0,
        &[
            0x17,
            0,
            0,
            0,
            0,
            1,
            100,
            0,
            31,
            0xfc | width_code,
            0xe1,
            0,
            3,
            0x67,
            0x64,
            0x1f,
            1,
            0,
            2,
            0x68,
            0xaa,
            0xde,
            0xad,
        ],
    )
}

fn video<'a>(wire: &'a [u8]) -> Result<avc::VideoTag<'a>, Box<dyn std::error::Error>> {
    let Parse::Complete(tag) = Tag::parse(wire, FlvLimits::default())? else {
        return Err("tag incomplete".into());
    };
    Ok(avc::VideoTag::parse(tag)?)
}

#[test]
fn configuration_preserves_exact_parameter_set_ranges_and_extensions() -> TestResult {
    let wire = config(3);
    let v = video(&wire)?;
    assert_eq!(v.packet_type(), avc::PacketType::Configuration);
    let c = v.configuration(avc::Limits::default())?;
    assert_eq!(c.nal_length_bytes(), 4);
    assert_eq!(c.extension(), &[0xde, 0xad]);
    assert_eq!(c.wire_bytes(), &wire[v.body_range()]);
    let sps = c.sps().next().ok_or("missing sps")?;
    let pps = c.pps().next().ok_or("missing pps")?;
    assert_eq!(sps.bytes(), &[0x67, 0x64, 0x1f]);
    assert_eq!(pps.bytes(), &[0x68, 0xaa]);
    assert_eq!(&wire[sps.range()], sps.bytes());
    assert_eq!(&wire[pps.range()], pps.bytes());
    assert_eq!(c.sps().len(), 1);
    assert_eq!(c.pps().len(), 1);
    Ok(())
}

#[test]
fn multiple_parameter_sets_have_bounded_distinct_source_ranges() -> TestResult {
    let payload = [
        0x17, 0, 0, 0, 0, 1, 100, 0, 31, 0xff, 0xe2, // two SPS entries
        0, 2, 0x67, 0x01, 0, 2, 0x67, 0x02, 2, // two PPS entries
        0, 2, 0x68, 0x03, 0, 2, 0x68, 0x04,
    ];
    let wire = tag(9, 0, &payload);
    let parsed = video(&wire)?;
    let c = parsed.configuration(avc::Limits::default())?;
    let sps: Vec<_> = c.sps().collect();
    let pps: Vec<_> = c.pps().collect();
    assert_eq!(sps.len(), 2);
    assert_eq!(pps.len(), 2);
    assert_eq!(sps[0].bytes(), &[0x67, 1]);
    assert_eq!(sps[1].bytes(), &[0x67, 2]);
    assert_eq!(pps[0].bytes(), &[0x68, 3]);
    assert_eq!(pps[1].bytes(), &[0x68, 4]);
    assert!(sps[0].range().end < sps[1].range().start);
    assert!(sps[1].range().end < pps[0].range().start);
    assert!(pps[0].range().end < pps[1].range().start);
    let limits = avc::Limits {
        max_parameter_sets: 3,
        ..avc::Limits::default()
    };
    assert_eq!(
        parsed.configuration(limits),
        Err(avc::Error::ConfigurationLimit)
    );
    Ok(())
}

#[test]
fn encoded_fixture_crosses_flv_framing_into_existing_avc_syntax() -> TestResult {
    let source = avc_support::split(include_bytes!("fixtures/avc/baseline.264"));
    let sps = source
        .iter()
        .copied()
        .find(|nal| nal[0] & 31 == 7)
        .ok_or("missing SPS")?;
    let pps = source
        .iter()
        .copied()
        .find(|nal| nal[0] & 31 == 8)
        .ok_or("missing PPS")?;
    let idr = source
        .iter()
        .copied()
        .find(|nal| nal[0] & 31 == 5)
        .ok_or("missing IDR")?;
    let mut configuration = vec![0x17, 0, 0, 0, 0, 1, sps[1], sps[2], sps[3], 0xff, 0xe1];
    configuration.extend_from_slice(&u16::try_from(sps.len())?.to_be_bytes());
    configuration.extend_from_slice(sps);
    configuration.push(1);
    configuration.extend_from_slice(&u16::try_from(pps.len())?.to_be_bytes());
    configuration.extend_from_slice(pps);
    let configuration_wire = tag(9, 0, &configuration);
    let c = video(&configuration_wire)?.configuration(avc::Limits::default())?;
    let source_sps = c.sps().next().ok_or("missing source SPS")?;
    let source_pps = c.pps().next().ok_or("missing source PPS")?;
    let syntax_limits = AvcSyntaxLimits::default();
    let parsed_sps = parse_sps(source_sps.bytes(), syntax_limits)?;
    let parsed_pps = parse_pps(source_pps.bytes(), &parsed_sps, syntax_limits)?;
    assert_eq!(parsed_sps.display_dimensions(), (160, 128));
    assert_eq!(
        &configuration_wire[source_sps.range()],
        parsed_sps.nal_bytes()
    );
    assert_eq!(
        &configuration_wire[source_pps.range()],
        parsed_pps.nal_bytes()
    );

    let mut picture = vec![0x17, 1, 0, 0, 0];
    picture.extend_from_slice(&u32::try_from(idr.len())?.to_be_bytes());
    picture.extend_from_slice(idr);
    let picture_wire = tag(9, 40, &picture);
    let units = video(&picture_wire)?.nal_units(&c, avc::Limits::default())?;
    let source_nal = units.iter().next().ok_or("missing source NAL")?;
    let identity =
        parse_slice_identity(source_nal.bytes(), &parsed_sps, &parsed_pps, syntax_limits)?;
    assert_eq!(identity.idr_pic_id(), Some(0));
    assert_eq!(&picture_wire[source_nal.range()], idr);
    Ok(())
}

#[test]
fn nals_have_exact_tag_offsets_and_keyframe_metadata_is_not_idr_proof() -> TestResult {
    for (code, width) in [(0_u8, 1_usize), (1, 2), (3, 4)] {
        let config_wire = config(code);
        let c = video(&config_wire)?.configuration(avc::Limits::default())?;
        assert_eq!(c.nal_length_bytes(), width);
        let mut payload = vec![0x17, 1, 0xff, 0xff, 0xfe]; // sender says keyframe; CTS=-2ms
        for bytes in [&[0x41, 0x11][..], &[0x65, 0x22, 0x33][..]] {
            let len = (bytes.len() as u32).to_be_bytes();
            payload.extend_from_slice(&len[4 - width..]);
            payload.extend_from_slice(bytes);
        }
        let wire = tag(9, 12, &payload);
        let v = video(&wire)?;
        assert_eq!(v.frame_type(), 1);
        assert_eq!(v.timestamp_ms(), 12);
        assert_eq!(v.composition_offset_ms(), -2);
        let nals = v.nal_units(&c, avc::Limits::default())?;
        assert_eq!(nals.len(), 2);
        assert!(nals.contains_idr_nal_type());
        let actual: Vec<_> = nals.iter().collect();
        assert_eq!(actual[0].bytes(), &[0x41, 0x11]);
        assert_eq!(actual[1].bytes(), &[0x65, 0x22, 0x33]);
        for nal in actual {
            assert_eq!(&wire[nal.range()], nal.bytes());
        }
        let non_idr = tag(9, 0, &[0x17, 1, 0, 0, 0, 0, 0, 0, 1, 0x41]);
        if width == 4 {
            let nals = video(&non_idr)?.nal_units(&c, avc::Limits::default())?;
            assert!(!nals.contains_idr_nal_type());
        }
    }
    Ok(())
}

#[test]
fn signed_composition_offset_is_not_silently_clamped() -> TestResult {
    for (bytes, expected) in [
        ([0x80, 0, 0], -8_388_608),
        ([0xff, 0xff, 0xff], -1),
        ([0, 0, 0], 0),
        ([0x7f, 0xff, 0xff], 8_388_607),
    ] {
        let wire = tag(
            9,
            u32::MAX,
            &[0x27, 1, bytes[0], bytes[1], bytes[2], 1, 0x41],
        );
        let v = video(&wire)?;
        assert_eq!(v.composition_offset_ms(), expected);
        assert_eq!(v.timestamp_ms(), u32::MAX);
    }
    Ok(())
}

#[test]
fn malformed_configurations_refuse_without_returning_partial_parameter_sets() -> TestResult {
    let c = config(3);
    let raw = video(&c)?.body().to_vec();
    for cut in 0..16 {
        let mut payload = vec![0x17, 0, 0, 0, 0];
        payload.extend_from_slice(&raw[..cut.min(raw.len())]);
        let wire = tag(9, 0, &payload);
        assert!(video(&wire)?.configuration(avc::Limits::default()).is_err());
    }
    let reserved = config(2);
    assert_eq!(
        video(&reserved)?.configuration(avc::Limits::default()),
        Err(avc::Error::InvalidConfiguration)
    );
    let too_small = avc::Limits {
        max_config_bytes: 7,
        ..avc::Limits::default()
    };
    assert_eq!(
        video(&c)?.configuration(too_small),
        Err(avc::Error::ConfigurationLimit)
    );
    let mut wrong_type = c.clone();
    wrong_type[24] = 0x68; // first SPS NAL header
    assert_eq!(
        video(&wrong_type)?.configuration(avc::Limits::default()),
        Err(avc::Error::InvalidConfiguration)
    );
    Ok(())
}

#[test]
fn malformed_samples_are_all_or_nothing_and_budgets_are_checked() -> TestResult {
    let config_wire = config(3);
    let c = video(&config_wire)?.configuration(avc::Limits::default())?;
    for sample in [
        vec![],
        vec![0, 0, 0, 0],
        vec![0, 0, 0, 5, 0x41],
        vec![0, 0, 0, 1, 0xc1],
        vec![0, 0, 0, 1, 0x41, 0],
    ] {
        let mut payload = vec![0x27, 1, 0, 0, 0];
        payload.extend_from_slice(&sample);
        let wire = tag(9, 0, &payload);
        assert!(video(&wire)?.nal_units(&c, avc::Limits::default()).is_err());
    }
    let wire = tag(
        9,
        0,
        &[0x27, 1, 0, 0, 0, 0, 0, 0, 1, 0x41, 0, 0, 0, 1, 0x65],
    );
    let one = avc::Limits {
        max_nals: 1,
        ..avc::Limits::default()
    };
    assert_eq!(
        video(&wire)?.nal_units(&c, one),
        Err(avc::Error::InvalidNalUnits)
    );
    assert_eq!(
        video(&wire)?.configuration(avc::Limits::default()),
        Err(avc::Error::WrongPacketType)
    );
    Ok(())
}

#[test]
fn debug_output_never_includes_media_bytes() -> TestResult {
    let cwire = config(3);
    let c = video(&cwire)?.configuration(avc::Limits::default())?;
    let wire = tag(
        9,
        0,
        &[
            0x27, 1, 0, 0, 0, 0, 0, 0, 8, 0x41, b'S', b'E', b'C', b'R', b'E', b'T', b'!',
        ],
    );
    let v = video(&wire)?;
    let nals = v.nal_units(&c, avc::Limits::default())?;
    let nal = nals.iter().next().ok_or("missing nal")?;
    for text in [
        format!("{v:?}"),
        format!("{c:?}"),
        format!("{nals:?}"),
        format!("{nal:?}"),
    ] {
        assert!(!text.contains("SECRET"));
    }
    Ok(())
}
