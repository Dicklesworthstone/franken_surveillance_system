#![forbid(unsafe_code)]
//! Exact RIFF frame ranges, stream timing, finite input bounds and cancellation.

#[path = "support/avi_fixture.rs"]
mod fixture;

use fss_container::avi::AviMjpeg;
use fss_container::demux::{DemuxError, DemuxLimits};

type Test = Result<(), Box<dyn std::error::Error>>;

fn tag(bytes: &[u8], name: &[u8; 4]) -> Result<usize, Box<dyn std::error::Error>> {
    bytes.windows(4).position(|part| part == name).ok_or_else(|| "missing fixture tag".into())
}

#[test]
fn interleaved_audio_and_record_lists_preserve_jpeg_and_rational_stream_time() -> Test {
    for audio_first in [false, true] {
        for records in [false, true] {
            let source = fixture::movie(audio_first, records);
            assert!(matches!(
                fss_container::probe::probe(&source[..12], &fss_container::probe::ProbeLimits::default()),
                fss_container::probe::ProbeOutcome::Identified {
                    container: fss_container::probe::ContainerKind::Avi, ..
                }
            ));
            let video = AviMjpeg::parse(&source, DemuxLimits::default())?;
            assert_eq!(video.source(), source.as_slice());
            assert_eq!(video.dimensions(), [64, 48]);
            assert_eq!(video.time_base(), (1001, 30_000));
            assert_eq!(video.samples().len(), 3);
            let mut end = 0;
            for (index, frame) in video.samples().iter().enumerate() {
                assert_eq!(frame.index, index);
                assert_eq!(frame.presentation_tick, index as u64 + 7);
                assert!(frame.source.start > end);
                assert_eq!(&source[frame.source.clone()], fixture::JPEG);
                end = frame.source.end;
            }
        }
    }
    Ok(())
}

#[test]
fn timing_order_and_profile_disagreements_refuse() -> Test {
    let source = fixture::movie(false, false);
    let avih = tag(&source, b"avih")? + 8;
    let strh = tag(&source, b"strh")? + 8;
    for (offset, value, expected) in [
        (avih + 12, 0x20_u32, DemuxError::Unsupported),
        (avih + 16, 4, DemuxError::Timeline),
        (strh + 20, 0, DemuxError::Timeline),
        (strh + 24, 0, DemuxError::Timeline),
        (strh + 32, 0, DemuxError::Timeline),
        (strh + 44, 8, DemuxError::Unsupported),
    ] {
        let mut changed = source.clone();
        changed[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert_eq!(AviMjpeg::parse(&changed, DemuxLimits::default()).map(|_| ()), Err(expected));
    }
    let frame = tag(&source, b"00dc")?;
    let mut changed = source.clone();
    changed[frame + 2..frame + 4].copy_from_slice(b"db");
    assert_eq!(
        AviMjpeg::parse(&changed, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Unsupported)
    );
    let mut changed = source;
    changed[frame + 8] = 0;
    assert_eq!(
        AviMjpeg::parse(&changed, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Layout)
    );
    Ok(())
}

#[test]
fn every_incomplete_file_refuses_without_returning_a_partial_index() -> Test {
    let source = fixture::movie(true, true);
    for cut in 0..source.len() {
        assert!(AviMjpeg::parse(&source[..cut], DemuxLimits::default()).is_err(), "cut {cut}");
    }
    let mut appended = source;
    appended.extend_from_slice(b"RIFF\x04\0\0\0AVIX");
    assert_eq!(
        AviMjpeg::parse(&appended, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Unsupported)
    );
    Ok(())
}

#[test]
fn source_track_chunk_sample_and_metadata_bounds_are_independent() -> Test {
    let source = fixture::movie(false, true);
    let base = DemuxLimits::default();
    for limits in [
        DemuxLimits { maximum_input_bytes: source.len() - 1, ..base },
        DemuxLimits { maximum_tracks: 1, ..base },
        DemuxLimits { maximum_boxes: 5, ..base },
        DemuxLimits { maximum_samples: 2, ..base },
        DemuxLimits { maximum_table_entries: 2, ..base },
        DemuxLimits { maximum_metadata_bytes: 8, ..base },
    ] {
        assert!(AviMjpeg::parse(&source, limits).is_err());
    }
    Ok(())
}

#[test]
fn every_parser_checkpoint_can_cancel_the_whole_selection() -> Test {
    let source = fixture::movie(false, true);
    let mut checkpoints = 0;
    AviMjpeg::parse_with_checkpoint(&source, DemuxLimits::default(), &mut || {
        checkpoints += 1;
        Ok(())
    })?;
    for stop in 1..=checkpoints {
        let mut at = 0;
        assert_eq!(
            AviMjpeg::parse_with_checkpoint(&source, DemuxLimits::default(), &mut || {
                at += 1;
                if at == stop { Err(DemuxError::Cancelled) } else { Ok(()) }
            }).map(|_| ()),
            Err(DemuxError::Cancelled)
        );
    }
    Ok(())
}

#[test]
fn presentation_geometry_must_be_full_frame_square_pixel_identity() -> Test {
    let source = fixture::movie(false, false);
    let strh = tag(&source, b"strh")? + 8;
    let avih = tag(&source, b"avih")? + 8;
    let vprp = tag(&source, b"vprp")? + 8;
    for offset in [avih + 32, avih + 36, strh + 48, strh + 52] {
        let mut changed = source.clone();
        changed[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
        assert!(AviMjpeg::parse(&changed, DemuxLimits::default()).is_err());
    }
    for offset in [0, 4, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64] {
        let mut changed = source.clone();
        let at = vprp + offset;
        let previous = u32::from_le_bytes(changed[at..at + 4].try_into()?);
        changed[at..at + 4].copy_from_slice(&(previous + 1).to_le_bytes());
        assert_eq!(
            AviMjpeg::parse(&changed, DemuxLimits::default()).map(|_| ()),
            Err(DemuxError::Unsupported),
            "vprp field {offset}"
        );
    }
    let mut default_rectangle = source.clone();
    default_rectangle[strh + 48..strh + 56].fill(0);
    AviMjpeg::parse(&default_rectangle, DemuxLimits::default())?;
    let mut signed_rectangle = source;
    let format = tag(&signed_rectangle, b"strf")? + 8;
    signed_rectangle[avih + 32..avih + 36].copy_from_slice(&32_768_u32.to_le_bytes());
    signed_rectangle[format + 4..format + 8].copy_from_slice(&32_768_u32.to_le_bytes());
    signed_rectangle[strh + 52..strh + 54].copy_from_slice(&32_768_u16.to_le_bytes());
    signed_rectangle[vprp - 8..vprp - 4].copy_from_slice(b"JUNK");
    assert_eq!(
        AviMjpeg::parse(&signed_rectangle, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Unsupported)
    );
    Ok(())
}

#[test]
fn undeclared_video_and_unsupported_streams_cannot_become_opaque_audio() -> Test {
    let source = fixture::movie(false, false);
    let audio = tag(&source, b"auds")?;
    let audio_chunk = tag(&source, b"01wb")?;
    for (offset, replacement) in [
        (audio, *b"iavs"),
        (audio, *b"text"),
        (audio_chunk, *b"99dc"),
        (audio_chunk, *b"01dc"),
        (audio_chunk, *b"99wb"),
        (audio_chunk, *b"hide"),
    ] {
        let mut changed = source.clone();
        changed[offset..offset + 4].copy_from_slice(&replacement);
        assert!(AviMjpeg::parse(&changed, DemuxLimits::default()).is_err());
    }
    Ok(())
}
