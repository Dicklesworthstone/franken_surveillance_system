#![forbid(unsafe_code)]
//! Bounded native demux/decode of a supplied completed recording. The optional
//! physical-input case is deliberately ignored unless an operator invokes it.
//! It does not contact a camera, assert capture time, or establish custody.

#[path = "../../fss-reference/src/ingest/recorded_decode/video_access_unit.rs"]
mod video_access_unit;

use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec, length_prefixed_nals};
use fss_core::ContentDigest;
use std::{error::Error, io::Read};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SAMPLES: usize = 30;

fn decode(source: &[u8]) -> Test<(u32, u32, usize, usize, usize, [u8; 32], ContentDigest)> {
    let movie = AvcMp4::parse(source, None, DemuxLimits::default())?;
    if movie.codec() != VideoCodec::Avc {
        return Err("recording is not AVC".into());
    }
    let start = movie
        .samples()
        .iter()
        .position(|sample| sample.sync_sample && sample.contains_idr)
        .ok_or("no declared IDR sample")?;
    let mut decoder = fss_codec_h264::Decoder::new(Default::default())?;
    for range in movie.parameter_sets() {
        if decoder.decode_nal(&source[range.clone()])?.is_some() {
            return Err("parameter set produced a picture".into());
        }
    }
    let mut frames = 0usize;
    let mut dimensions = None;
    let mut first_digest = None;
    let mut frame_digests = Vec::new();
    let mut samples = 0usize;
    for sample in movie.samples().iter().skip(start).take(MAX_SAMPLES) {
        let bytes = &source[sample.source.clone()];
        let ranges = length_prefixed_nals(bytes, movie.nal_length_bytes())?;
        let nals: Vec<_> = ranges.iter().map(|range| &bytes[range.clone()]).collect();
        let pictures = video_access_unit::h264(&mut decoder, &nals, &mut || Ok(()))
            .map_err(|error| format!("native AVC sample refusal: {error:?}"))?;
        samples += 1;
        for picture in pictures {
            let size = (picture.width(), picture.height());
            if dimensions.is_some_and(|old| old != size) {
                return Err("dimensions changed".into());
            }
            dimensions = Some(size);
            let digest = picture.i420_sha256();
            if first_digest.is_none() {
                first_digest = Some(digest);
            }
            frame_digests.extend_from_slice(&digest);
            frames += 1;
        }
    }
    for picture in decoder.finish()? {
        let size = (picture.width(), picture.height());
        if dimensions.is_some_and(|old| old != size) {
            return Err("dimensions changed".into());
        }
        dimensions = Some(size);
        let digest = picture.i420_sha256();
        if first_digest.is_none() {
            first_digest = Some(digest);
        }
        frame_digests.extend_from_slice(&digest);
        frames += 1;
    }
    let (width, height) = dimensions.ok_or("no picture decoded within sample limit")?;
    Ok((
        width,
        height,
        frames,
        samples,
        start,
        first_digest.ok_or("frame digest missing")?,
        ContentDigest::sha256(&frame_digests),
    ))
}

#[test]
fn indexed_fixture_decodes_with_native_pipeline() -> Test {
    let bytes = include_bytes!("fixtures/indexed_avc.mp4");
    let (_, _, frames, _, _, _, _) = decode(bytes)?;
    assert!(frames > 0);
    Ok(())
}

#[test]
#[ignore = "requires an explicitly supplied private, completed recording"]
fn supplied_recording_decodes_with_native_pipeline() -> Test {
    let path = std::env::var_os("FSS_UNIFI_RECORDING").ok_or("recording path required")?;
    let file = std::fs::File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_BYTES {
        return Err("recording is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.try_clone()?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err("recording changed during read".into());
    }
    let digest = ContentDigest::sha256(&bytes);
    let (width, height, frames, samples, start, first_digest, frame_digests) = decode(&bytes)?;
    let frame_digest: String = first_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!(
        "physical_recording_native_decode width={width} height={height} frames={frames} samples={samples} first_sample={start} first_i420_sha256={frame_digest} frame_digest_list_sha256={frame_digests} source_bytes={} source_sha256={} capture_time=unknown custody=external",
        bytes.len(),
        digest
    );
    Ok(())
}
