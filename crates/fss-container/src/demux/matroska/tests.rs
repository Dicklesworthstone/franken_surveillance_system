#![forbid(unsafe_code)]
#![allow(clippy::expect_used)] // fixture lookups over retained laboratory bytes
//! Retained FFmpeg Matroska remuxes of the MP4 laboratory fixtures, plus targeted tampering.
use super::*;
use crate::demux::AvcMp4;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

const AVC: &[u8] = include_bytes!("../../../tests/fixtures/avc_av.mkv");
const LIVE: &[u8] = include_bytes!("../../../tests/fixtures/avc_live.mkv");
const HEVC: &[u8] = include_bytes!("../../../tests/fixtures/hevc_av.mkv");
const AVC_MP4: &[u8] = include_bytes!("../../../tests/fixtures/interleaved_av.mp4");
const HEVC_MP4: &[u8] = include_bytes!("../../../tests/fixtures/hevc_av.mp4");

fn parse(bytes: &[u8]) -> Result<MatroskaVideo<'_>, DemuxError> {
    MatroskaVideo::parse(bytes, None, DemuxLimits::default())
}

/// Recomputes the leading CRC-32 of the top-level element starting at `start`, so a test edit
/// reaches the semantic check rather than the integrity check.
fn reseal(bytes: &mut [u8], start: usize) {
    let (_, data, size) = header(bytes, start, bytes.len()).expect("element header");
    let end = data + size.expect("known size");
    assert_eq!(bytes[data..data + 2], [0xBF, 0x84], "leading CRC-32");
    let crc = !crc32_update(!0, &bytes[data + 6..end]);
    bytes[data + 2..data + 6].copy_from_slice(&crc.to_le_bytes());
}

/// Start of the top-level element containing byte `at`.
fn containing(bytes: &[u8], at: usize) -> usize {
    parse(bytes)
        .expect("fixture parses")
        .elements()
        .iter()
        .find(|e| e.range.contains(&at))
        .expect("tiled")
        .range
        .start
}

fn find(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("fixture bytes")
}

#[test]
fn avc_matroska_frames_equal_the_mp4_samples_with_presentation_timestamps() -> Test {
    let mkv = parse(AVC)?;
    let mp4 = AvcMp4::parse(AVC_MP4, None, DemuxLimits::default())?;
    assert_eq!(mkv.doc_type(), "matroska");
    assert_eq!(mkv.codec(), VideoCodec::Avc);
    assert_eq!(mkv.dimensions(), [64, 48]);
    assert_eq!(mkv.timestamp_scale_ns(), 1_000_000);
    assert_eq!(mkv.nal_length_bytes(), mp4.nal_length_bytes());
    assert_eq!(mkv.tracks().len(), 2);
    assert_eq!(mkv.tracks()[mkv.tracks().len() - 1].track_type, 2);
    assert_eq!(mkv.samples().len(), 10);
    for (a, b) in mkv.parameter_sets().iter().zip(mp4.parameter_sets()) {
        assert_eq!(AVC[a.clone()], AVC_MP4[b.clone()]);
    }
    // FFprobe presentation timestamps (ms): the MP4 edit list's 128 ms lead is kept as written.
    let pts = [128, 728, 328, 528, 928, 1128, 1328, 1728, 1528, 1928];
    for (k, (a, b)) in mkv.samples().iter().zip(mp4.samples()).enumerate() {
        assert_eq!(a.index, k);
        assert_eq!(AVC[a.source.clone()], AVC_MP4[b.source.clone()]);
        assert_eq!(a.timestamp, pts[k]);
        assert_eq!((a.keyframe, a.contains_idr), (k % 5 == 0, k % 5 == 0));
    }
    // The elements tile the file exactly, in order.
    let mut cursor = 0;
    for element in mkv.elements() {
        assert_eq!(element.range.start, cursor);
        cursor = element.range.end;
    }
    assert_eq!(cursor, AVC.len());
    let names: Vec<_> = mkv.elements().iter().map(|e| e.name).collect();
    assert_eq!(names[..2], ["ebml_header", "segment_header"]);
    assert!(names.contains(&"tracks") && names.contains(&"cluster") && names.contains(&"cues"));
    Ok(())
}

#[test]
fn hevc_matroska_reads_its_hvcc_private_and_irap_frames() -> Test {
    let mkv = parse(HEVC)?;
    let mp4 = AvcMp4::parse(HEVC_MP4, None, DemuxLimits::default())?;
    assert_eq!(mkv.codec(), VideoCodec::Hevc);
    assert_eq!(mkv.parameter_sets().len(), 3);
    assert_eq!(mkv.samples().len(), mp4.samples().len());
    for (a, b) in mkv.samples().iter().zip(mp4.samples()) {
        assert_eq!(HEVC[a.source.clone()], HEVC_MP4[b.source.clone()]);
        assert_eq!(a.contains_idr, b.contains_idr);
    }
    Ok(())
}

#[test]
fn live_unknown_size_segment_and_cluster_read_like_the_seekable_file() -> Test {
    let seekable = parse(AVC)?;
    let live = parse(LIVE)?;
    assert_eq!(LIVE[find(LIVE, &SEGMENT.to_be_bytes()) + 4], 0x01);
    let frames = |m: &MatroskaVideo<'_>, bytes: &[u8]| -> Vec<(Vec<u8>, i64, bool)> {
        m.samples()
            .iter()
            .map(|s| (bytes[s.source.clone()].to_vec(), s.timestamp, s.keyframe))
            .collect()
    };
    assert_eq!(frames(&live, LIVE), frames(&seekable, AVC));
    // A live writer may leave each Cluster's size unknown: it ends at the next top-level element.
    let mut unknown = LIVE.to_vec();
    let cluster = find(&unknown, &CLUSTER.to_be_bytes());
    assert_eq!(unknown[cluster + 4] & 0xC0, 0x40, "two-byte cluster size");
    unknown[cluster + 4..cluster + 6].copy_from_slice(&[0x7F, 0xFF]);
    let parsed = parse(&unknown)?;
    assert_eq!(frames(&parsed, &unknown), frames(&live, LIVE));
    assert_eq!(parsed.elements().len(), live.elements().len());
    Ok(())
}

#[test]
fn every_truncated_prefix_and_trailing_byte_is_refused_without_panicking() {
    for bytes in [AVC, LIVE, HEVC] {
        for end in 0..bytes.len() {
            // A live (unknown-size) file cut exactly between top-level elements is complete.
            let _ = parse(&bytes[..end]);
        }
    }
    for end in 0..AVC.len() {
        assert!(parse(&AVC[..end]).is_err(), "seekable prefix {end}");
    }
    let mut trailing = AVC.to_vec();
    trailing.push(0);
    assert_eq!(parse(&trailing).map(|_| ()), Err(DemuxError::Layout));
}

#[test]
fn crc_mismatch_and_frame_interpretation_changes_are_refused_whole() -> Test {
    let first = parse(AVC)?.samples()[0].source.clone();
    let cluster = containing(AVC, first.start);
    // One flipped frame bit fails the cluster's CRC-32.
    let mut bytes = AVC.to_vec();
    bytes[first.start + 8] ^= 1;
    assert_eq!(parse(&bytes).map(|_| ()), Err(DemuxError::Layout));
    // Lacing and invisible flags on the video SimpleBlock, with a valid CRC.
    for flag in [0x02, 0x04, 0x06, 0x08] {
        let mut bytes = AVC.to_vec();
        bytes[first.start - 1] |= flag;
        reseal(&mut bytes, cluster);
        assert_eq!(parse(&bytes).map(|_| ()), Err(DemuxError::Unsupported));
    }
    // An unsupported codec on the only video track.
    let mut bytes = AVC.to_vec();
    let codec = find(&bytes, b"V_MPEG4/ISO/AVC");
    bytes[codec..codec + 15].copy_from_slice(b"V_MPEG4/ISO/ASP");
    reseal(&mut bytes, containing(AVC, codec));
    assert_eq!(parse(&bytes).map(|_| ()), Err(DemuxError::Unsupported));
    // WebM is the same element set; any other DocType is refused.
    let mut bytes = AVC.to_vec();
    let doc = find(&bytes, b"matroska");
    bytes[doc..doc + 8].copy_from_slice(b"webm\0\0\0\0");
    assert_eq!(parse(&bytes)?.doc_type(), "webm");
    bytes[doc..doc + 8].copy_from_slice(b"matroskb");
    assert_eq!(parse(&bytes).map(|_| ()), Err(DemuxError::Unsupported));
    Ok(())
}

#[test]
fn limits_and_cancellation_refuse_without_a_partial_index() {
    let tight = DemuxLimits {
        maximum_samples: 9,
        ..DemuxLimits::default()
    };
    assert_eq!(
        MatroskaVideo::parse(AVC, None, tight).map(|_| ()),
        Err(DemuxError::Limit)
    );
    let mut calls = 0;
    let cancelled =
        MatroskaVideo::parse_with_checkpoint(AVC, None, DemuxLimits::default(), &mut || {
            calls += 1;
            if calls > 20 {
                Err(DemuxError::Cancelled)
            } else {
                Ok(())
            }
        });
    assert_eq!(cancelled.map(|_| ()), Err(DemuxError::Cancelled));
    // An explicit selection of a non-video or absent track is refused.
    for track in [2, 9] {
        assert_eq!(
            MatroskaVideo::parse(AVC, Some(track), DemuxLimits::default()).map(|_| ()),
            Err(DemuxError::TrackSelection)
        );
    }
}

fn recover(bytes: &[u8]) -> Result<MatroskaVideo<'_>, DemuxError> {
    MatroskaVideo::parse_recovering_tail(bytes, None, DemuxLimits::default(), &mut || Ok(()))
}

/// Recovered frames are always a prefix of the complete file's frames, and the elements tile the
/// file up to the reported tail. Returns the recovered frame count per cut.
fn recovered_counts(bytes: &[u8]) -> Vec<usize> {
    let full = recover(bytes).expect("complete file");
    assert_eq!(full.truncated_tail(), None);
    let mut counts = Vec::new();
    for cut in 0..bytes.len() {
        let prefix = &bytes[..cut];
        // A live file cut exactly between top-level elements is complete: both parsers agree.
        if let Ok(strict) = parse(prefix) {
            let recovered = recover(prefix).expect("strictly valid prefix");
            assert_eq!(recovered.truncated_tail(), None);
            assert_eq!(recovered.samples(), strict.samples());
        }
        let Ok(video) = recover(prefix) else {
            counts.push(0);
            continue;
        };
        let tail = video.truncated_tail().unwrap_or(cut);
        assert!(tail <= cut);
        let k = video.samples().len();
        assert_eq!(video.samples(), &full.samples()[..k]);
        assert!(video.samples().iter().all(|s| s.source.end <= tail));
        let mut cursor = 0;
        for element in video.elements() {
            assert_eq!(element.range.start, cursor);
            cursor = element.range.end;
        }
        assert_eq!(cursor, tail, "cut {cut}");
        counts.push(k);
    }
    counts
}

#[test]
fn a_cut_recording_keeps_its_complete_crc_bound_clusters_only() {
    // FFmpeg binds every Cluster with a CRC-32: a cut Cluster cannot be verified, so it is dropped
    // whole and recovery moves in Cluster steps.
    let counts = recovered_counts(LIVE);
    let full = recover(LIVE).expect("complete");
    let clusters: Vec<_> = full
        .elements()
        .iter()
        .filter(|e| e.name == "cluster")
        .map(|e| e.range.clone())
        .collect();
    assert_eq!(clusters.len(), 3);
    for (cut, k) in counts.iter().enumerate() {
        let complete = full
            .samples()
            .iter()
            .filter(|s| {
                clusters
                    .iter()
                    .any(|c| c.contains(&s.source.start) && c.end <= cut)
            })
            .count();
        assert_eq!(*k, complete, "cut {cut}");
    }
    // The live fixture's Clusters hold 6, 3 and 1 frames.
    let steps: std::collections::BTreeSet<_> = counts.iter().copied().collect();
    assert_eq!(steps, [0, 6, 9].into());
}

#[test]
fn a_cut_cluster_without_a_crc_keeps_each_complete_block() -> Test {
    // Replace each Cluster's leading CRC-32 with a Void element of the same size.
    let mut bytes = LIVE.to_vec();
    let starts: Vec<_> = parse(LIVE)?
        .elements()
        .iter()
        .filter(|e| e.name == "cluster")
        .map(|e| e.range.start)
        .collect();
    for start in starts {
        let (_, data, _) = header(&bytes, start, bytes.len())?;
        assert_eq!(bytes[data..data + 2], [0xBF, 0x84]);
        bytes[data..data + 6].copy_from_slice(&[0xEC, 0x84, 0, 0, 0, 0]);
    }
    let full = parse(&bytes)?;
    let counts = recovered_counts(&bytes);
    for (cut, k) in counts.iter().enumerate() {
        // A frame survives exactly when its whole block element precedes the cut.
        let complete = full
            .samples()
            .iter()
            .filter(|s| s.source.end <= cut)
            .count();
        assert_eq!(*k, complete, "cut {cut}");
    }
    assert!((1..=10).all(|k| counts.contains(&k)));
    // Only running out of bytes is recovered: a corrupt element still refuses the whole file.
    let mut corrupt = bytes[..bytes.len() - 40].to_vec();
    let first = full.samples()[0].source.start;
    corrupt[first - 4] = 0x00;
    assert!(recover(&corrupt).is_err());
    Ok(())
}
