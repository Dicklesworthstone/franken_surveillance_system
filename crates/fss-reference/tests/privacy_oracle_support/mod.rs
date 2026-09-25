#![forbid(unsafe_code)]
//! Retained-decode oracle for luma consumers: declare a policy for the fixture sensor, import a
//! frame as a retained file of that sensor and read the fss-bgqkd decode's masked luma digest.
use crate::privacy_live_support::PrivacyDeployment;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use fss_core::{ContentDigest, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::{RecordedDecodeRequest, RecordedFrame};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest, RetainedReadLimits};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The 8x8 block at the origin of a 17x13 frame: the only region the motion frames change.
pub const BLOCK: [u32; 4] = [0, 0, 8, 8];

/// Retains `rectangles` as the fixture sensor's next policy generation (exact preview approval).
pub fn declare(
    p: &mut PrivacyDeployment,
    resolution: [u32; 2],
    rectangles: &[[u32; 4]],
) -> Result<ContentDigest> {
    let policy = PrivacyMaskPolicy::new(p.sensor.clone(), resolution, rectangles)?;
    let preview = preview_mask(&p.deployment, &policy)?;
    Ok(declare_mask(&mut p.deployment, &policy, preview.approval, &p.cx)?.policy_digest)
}

/// Retained decode (fss-bgqkd) of `jpeg` imported for the fixture sensor: its luma digest
/// under the sensor's current policy.
pub fn retained_luma(p: &mut PrivacyDeployment, jpeg: &[u8], name: &str) -> Result<[u8; 32]> {
    let path = p.root.join(format!("retained-{name}.mjpeg"));
    std::fs::write(&path, jpeg)?;
    let request = FileIngestRequest::new(
        path,
        p.sensor.clone(),
        StreamId::parse(format!("stream:privacy-oracle-{name}"))?,
    )
    .with_receive_time(TimestampNs(1_000_000_000));
    let imported = FileIngestAdapter::ingest(request, &p.cx, &mut p.deployment)?;
    let request = RecordedDecodeRequest {
        import_identity: imported.import_identity,
        segment_index: 0,
        interpretation: ComponentInterpretation::Grayscale,
        read_limits: RetainedReadLimits::default(),
        decode_limits: DecodeLimits::default(),
    };
    let frame = RecordedFrame::decode_and_publish(
        &mut p.deployment,
        &request,
        &mut DecodeBudget::new(1_000_000_000),
        &p.cx,
    )?;
    Ok(frame.receipt().codec().luma_sha256)
}

/// A grayscale 17x13 frame, uniform 128 except a `seed`-dependent pattern in [`BLOCK`].
/// Block-aligned at quality 100, so the uniform blocks decode to exactly 128 again.
pub fn block_jpeg(seed: u8) -> Result<Vec<u8>> {
    let mut pixels = vec![128_u8; 17 * 13];
    for y in 0..8_usize {
        for x in 0..8_usize {
            pixels[y * 17 + x] = if (x + y + usize::from(seed)) % 2 == 0 {
                250
            } else {
                5
            };
        }
    }
    Ok(encode_jpeg(
        17,
        13,
        &pixels,
        &JpegConfig {
            quality: 100,
            subsampling: Subsampling::Grayscale,
            ..JpegConfig::default()
        },
    )?)
}
