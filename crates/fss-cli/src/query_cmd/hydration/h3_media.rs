#![forbid(unsafe_code)]
//! Target resolution, pure-Rust media decoding, masked crop/downscale, and receipt sealing for H3.

use std::collections::BTreeSet;

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeError};
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, LedgerAnchor, Plane};
use fss_reference::ReplayCx;
use fss_reference::ingest::privacy_mask::{MASK_FILL_RGB, MaskBinding};
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits as H264DecoderLimits, RecordedH264Range, RecordedH264Request,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as H265DecoderLimits, RecordedH265Range, RecordedH265Request,
};
use fss_reference::ingest::recorded_decode::verify_custody;
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits, VerifiedChunkCache};
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedSource};

use super::h2_provenance::extract_event_provenance;
use super::h3::{H3FrameReceipt, H3HydrationRequest};
use super::{CropBox, H3_RECEIPT_DOMAIN, HydrationError, HydrationTarget, is_valid_sha256};

pub(super) fn resolve_h3_target(
    owner: &ImmutableRetainedSource<'_>,
    request: &H3HydrationRequest,
) -> Result<(ContentDigest, Vec<usize>, String), HydrationError> {
    match &request.target {
        HydrationTarget::Import { import_id } => {
            if !is_valid_sha256(*import_id) {
                return Err(HydrationError::InvalidRequest(
                    "import_id must be a canonical nonzero SHA-256 digest".into(),
                ));
            }
            let segments = if request.segment_indices.is_empty() {
                vec![0]
            } else {
                request.segment_indices.clone()
            };
            Ok((
                *import_id,
                segments,
                format!("import:{}", import_id.to_text()),
            ))
        }
        HydrationTarget::Event {
            event_id,
            revision_digest,
        } => {
            if !is_valid_sha256(*revision_digest) {
                return Err(HydrationError::InvalidRequest(
                    "revision_digest must be a canonical nonzero SHA-256 digest".into(),
                ));
            }
            let snapshot = owner.snapshot();
            let retained = snapshot.event(event_id).ok_or_else(|| {
                HydrationError::NotFound(format!("event {} not found at anchor", event_id.as_str()))
            })?;
            if retained.revision_digest != *revision_digest {
                return Err(HydrationError::AnchorMismatch(
                    "event revision_digest does not match current committed revision".into(),
                ));
            }
            if snapshot.deletions.object(retained.event_root).is_some()
                || snapshot
                    .deletions
                    .object(retained.revision_digest)
                    .is_some()
            {
                return Err(HydrationError::EvidenceDeleted(
                    "event revision metadata is deleted".into(),
                ));
            }
            let (trajs, _) = extract_event_provenance(owner, retained);
            if let Some(first) = trajs.first() {
                let import_id = first.import_identity;
                let segments = if !request.segment_indices.is_empty() {
                    request.segment_indices.clone()
                } else {
                    let mut segs: Vec<usize> = trajs
                        .iter()
                        .filter(|t| t.import_identity == import_id)
                        .flat_map(|t| t.observations.iter().map(|o| o.segment_index as usize))
                        .collect();
                    segs.sort_unstable();
                    segs.dedup();
                    segs.truncate(request.limits.max_h3_frames);
                    segs
                };
                return Ok((
                    import_id,
                    segments,
                    format!("event:{}:{}", event_id.as_str(), revision_digest.to_text()),
                ));
            }
            let cited: BTreeSet<ContentDigest> = retained
                .event
                .evidence
                .iter()
                .filter_map(|e| e.capsule_digest)
                .collect();
            if let Some((import_id, segs)) = find_import_by_capsules(owner, &cited) {
                let segments = if !request.segment_indices.is_empty() {
                    request.segment_indices.clone()
                } else {
                    segs.into_iter()
                        .take(request.limits.max_h3_frames)
                        .collect()
                };
                return Ok((
                    import_id,
                    segments,
                    format!("event:{}:{}", event_id.as_str(), revision_digest.to_text()),
                ));
            }
            Err(HydrationError::NotFound(
                "event carries no retained visual source import or capsule provenance".into(),
            ))
        }
    }
}

fn find_import_by_capsules(
    owner: &ImmutableRetainedSource<'_>,
    cited: &BTreeSet<ContentDigest>,
) -> Option<(ContentDigest, Vec<usize>)> {
    if cited.is_empty() {
        return None;
    }
    for batch in owner.ledger().batches() {
        let Some(rest) = batch.batch_id.as_str().strip_prefix("batch:file-import:") else {
            continue;
        };
        let Some((hex_id, suffix)) = rest.split_once(":c") else {
            continue;
        };
        if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let mut matched = Vec::new();
        for (idx, delta) in batch.deltas.iter().enumerate() {
            if delta.family == "sensor_capsule"
                && delta.plane == Plane::Authority
                && cited.contains(&delta.payload_digest)
            {
                matched.push(idx);
            }
        }
        if !matched.is_empty()
            && let Ok(import_id) = ContentDigest::parse(format!("sha256:{hex_id}"))
        {
            return Some((import_id, matched));
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(super) fn decode_segment_rgb(
    owner: &ImmutableRetainedSource<'_>,
    retained: &RetainedFileImport,
    seg_index: usize,
    capsule: &fss_core::SensorCapsule,
    expected_mask: &MaskBinding,
    read_limits: RetainedReadLimits,
    chunks: &mut VerifiedChunkCache,
    cx: &ReplayCx,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<(Vec<u8>, [u32; 2], u64, u64), HydrationError> {
    match retained.manifest().format.as_str() {
        "mjpeg" => {
            let encoded = retained
                .read_segment_cached(owner, seg_index, read_limits, cx, chunks)
                .map_err(|err| {
                    HydrationError::CustodyFailure(format!("segment custody read failed: {err}"))
                })?;
            verify_custody(capsule, &encoded).map_err(|err| {
                HydrationError::CustodyFailure(format!("custody mismatch: {err}"))
            })?;
            let rgb_limits = RgbDecodeLimits::default();
            let mut budget =
                DecodeBudget::with_cancellation_probe(rgb_limits.rgb_work_bound(), cancelled);
            let decoded = match decode_rgb(
                &encoded,
                capsule.source_digest.bytes(),
                ComponentInterpretation::YCbCr,
                rgb_limits,
                &mut budget,
            ) {
                Ok(img) => img,
                Err(DecodeError::Unsupported) => {
                    let mut gray_budget = DecodeBudget::with_cancellation_probe(
                        rgb_limits.rgb_work_bound(),
                        cancelled,
                    );
                    decode_rgb(
                        &encoded,
                        capsule.source_digest.bytes(),
                        ComponentInterpretation::Grayscale,
                        rgb_limits,
                        &mut gray_budget,
                    )
                    .map_err(|err| {
                        HydrationError::CodecFailure(format!("JPEG decode failed: {err}"))
                    })?
                }
                Err(DecodeError::Cancelled) => return Err(HydrationError::Cancelled),
                Err(err) => {
                    return Err(HydrationError::CodecFailure(format!(
                        "JPEG decode failed: {err}"
                    )));
                }
            };
            Ok((
                decoded.pixels().to_vec(),
                decoded.dimensions(),
                encoded.len() as u64,
                budget.used(),
            ))
        }
        "annexb" | "mp4avc" | "mkvavc" | "flvavc" => {
            let mut range = RecordedH264Range::open(
                owner,
                RecordedH264Request {
                    import_identity: retained.import_identity(),
                    first_segment: 0,
                    segment_count: seg_index + 1,
                    interpretation: ComponentInterpretation::YCbCr,
                    read_limits,
                    decoder_limits: H264DecoderLimits::default(),
                },
                cx,
            )
            .map_err(|err| HydrationError::CodecFailure(format!("H.264 range failed: {err}")))?;
            if range.mask() != expected_mask {
                return Err(HydrationError::AnchorMismatch(
                    "H.264 privacy mask binding mismatch".into(),
                ));
            }
            while let Some(frame) = range.next_frame(owner, cx).map_err(|err| {
                HydrationError::CodecFailure(format!("H.264 decode failed: {err}"))
            })? {
                if frame.segment_index() as usize == seg_index {
                    let rgb = frame.to_rgb().map_err(|err| {
                        HydrationError::CodecFailure(format!("RGB convert failed: {err}"))
                    })?;
                    return Ok((rgb, frame.dimensions(), capsule.source_bytes, 0));
                }
            }
            Err(HydrationError::NotFound(format!(
                "H.264 segment {seg_index} produced no output picture"
            )))
        }
        "hevc" | "mp4hevc" | "mkvhevc" => {
            let mut range = RecordedH265Range::open(
                owner,
                RecordedH265Request {
                    import_identity: retained.import_identity(),
                    first_segment: 0,
                    segment_count: seg_index + 1,
                    interpretation: ComponentInterpretation::YCbCr,
                    read_limits,
                    decoder_limits: H265DecoderLimits::default(),
                },
                cx,
            )
            .map_err(|err| HydrationError::CodecFailure(format!("H.265 range failed: {err}")))?;
            if range.mask() != expected_mask {
                return Err(HydrationError::AnchorMismatch(
                    "H.265 privacy mask binding mismatch".into(),
                ));
            }
            while let Some(frame) = range.next_frame(owner, cx).map_err(|err| {
                HydrationError::CodecFailure(format!("H.265 decode failed: {err}"))
            })? {
                if frame.segment_index() as usize == seg_index {
                    let rgb = frame.to_rgb().map_err(|err| {
                        HydrationError::CodecFailure(format!("RGB convert failed: {err}"))
                    })?;
                    return Ok((rgb, frame.dimensions(), capsule.source_bytes, 0));
                }
            }
            Err(HydrationError::NotFound(format!(
                "H.265 segment {seg_index} produced no output picture"
            )))
        }
        other => Err(HydrationError::CodecFailure(format!(
            "unsupported retained media format for H3 visual hydration: {other}"
        ))),
    }
}

pub(super) fn crop_rgb_and_mask(
    rgb: &[u8],
    allowed: &[u8],
    dims: [u32; 2],
    crop: CropBox,
) -> (Vec<u8>, Vec<u8>) {
    let src_w = dims[0] as usize;
    let cw = crop.width as usize;
    let ch = crop.height as usize;
    let cx = crop.x as usize;
    let cy = crop.y as usize;
    let mut out_rgb = Vec::with_capacity(cw * ch * 3);
    let mut out_allow = Vec::with_capacity(cw * ch);
    for row in 0..ch {
        let src_row = (cy + row) * src_w + cx;
        out_rgb.extend_from_slice(&rgb[src_row * 3..(src_row + cw) * 3]);
        out_allow.extend_from_slice(&allowed[src_row..src_row + cw]);
    }
    (out_rgb, out_allow)
}

pub(super) fn downscale_rgb_masked(
    rgb: &[u8],
    allowed: &[u8],
    dims: [u32; 2],
    max_dimension: u32,
) -> (Vec<u8>, [u32; 2]) {
    let [src_w, src_h] = dims;
    if src_w <= max_dimension && src_h <= max_dimension {
        let mut out = rgb.to_vec();
        for (idx, &is_visible) in allowed.iter().enumerate() {
            if is_visible == 0 {
                let p = idx * 3;
                out[p..p + 3].copy_from_slice(&MASK_FILL_RGB);
            }
        }
        return (out, dims);
    }
    let (dst_w, dst_h) = if src_w >= src_h {
        let h = ((u64::from(src_h) * u64::from(max_dimension) + u64::from(src_w) / 2)
            / u64::from(src_w))
        .max(1) as u32;
        (max_dimension, h)
    } else {
        let w = ((u64::from(src_w) * u64::from(max_dimension) + u64::from(src_h) / 2)
            / u64::from(src_h))
        .max(1) as u32;
        (w, max_dimension)
    };
    let sw = src_w as usize;
    let sh = src_h as usize;
    let dw = dst_w as usize;
    let dh = dst_h as usize;
    let mut out = Vec::with_capacity(dw * dh * 3);
    for dy in 0..dh {
        let y0 = (dy * sh) / dh;
        let y1 = (((dy + 1) * sh) / dh).max(y0 + 1).min(sh);
        for dx in 0..dw {
            let x0 = (dx * sw) / dw;
            let x1 = (((dx + 1) * sw) / dw).max(x0 + 1).min(sw);
            let mut sum = [0_u64; 3];
            let mut count = 0_u64;
            let mut any_masked = false;
            for sy in y0..y1 {
                for sx in x0..x1 {
                    let idx = sy * sw + sx;
                    if allowed[idx] == 0 {
                        any_masked = true;
                        break;
                    }
                    let p = idx * 3;
                    sum[0] += u64::from(rgb[p]);
                    sum[1] += u64::from(rgb[p + 1]);
                    sum[2] += u64::from(rgb[p + 2]);
                    count += 1;
                }
                if any_masked {
                    break;
                }
            }
            if any_masked || count == 0 {
                out.extend_from_slice(&MASK_FILL_RGB);
            } else {
                out.push(((sum[0] + count / 2) / count) as u8);
                out.push(((sum[1] + count / 2) / count) as u8);
                out.push(((sum[2] + count / 2) / count) as u8);
            }
        }
    }
    (out, [dst_w, dst_h])
}

#[allow(clippy::too_many_arguments)]
pub(super) fn seal_h3_frame_receipt(
    anchor: &LedgerAnchor,
    segment_index: usize,
    source_import_id: ContentDigest,
    source_capsule_digest: ContentDigest,
    sensor_id: &str,
    mask_binding: &MaskBinding,
    applied_redaction_transform: &'static str,
    source_dimensions: [u32; 2],
    crop_box: Option<CropBox>,
    output_dimensions: [u32; 2],
    output_bytes: usize,
    output_jpeg_sha256: ContentDigest,
    encoder_receipt_digest: ContentDigest,
) -> H3FrameReceipt {
    let mut enc = CanonicalEncoder::new();
    enc.text(H3_RECEIPT_DOMAIN);
    anchor.encode_canonical(&mut enc);
    enc.u64(segment_index as u64);
    enc.digest(source_import_id);
    enc.digest(source_capsule_digest);
    enc.text(sensor_id);
    enc.text(mask_binding.label());
    enc.digest(mask_binding.digest());
    enc.bool(mask_binding.policy_digest().is_some());
    if let Some(pd) = mask_binding.policy_digest() {
        enc.digest(pd);
    }
    enc.bool(mask_binding.generation().is_some());
    if let Some(generation) = mask_binding.generation() {
        enc.u64(generation);
    }
    enc.text(applied_redaction_transform);
    enc.text("refused");
    enc.u32(source_dimensions[0]);
    enc.u32(source_dimensions[1]);
    enc.bool(crop_box.is_some());
    if let Some(crop) = crop_box {
        enc.u32(crop.x);
        enc.u32(crop.y);
        enc.u32(crop.width);
        enc.u32(crop.height);
    }
    enc.u32(output_dimensions[0]);
    enc.u32(output_dimensions[1]);
    enc.u64(output_bytes as u64);
    enc.digest(output_jpeg_sha256);
    enc.digest(encoder_receipt_digest);
    let receipt_digest = ContentDigest::sha256(&enc.finish());

    H3FrameReceipt {
        receipt_digest,
        segment_index,
        source_import_id,
        source_capsule_digest,
        sensor_id: sensor_id.to_owned(),
        privacy_mask_binding: mask_binding.label(),
        privacy_mask_binding_digest: mask_binding.digest(),
        privacy_mask_policy_digest: mask_binding.policy_digest(),
        privacy_mask_generation: mask_binding.generation(),
        applied_redaction_transform,
        unmasked_access: "refused",
        source_dimensions,
        crop_box,
        width: output_dimensions[0],
        height: output_dimensions[1],
        output_bytes,
        output_jpeg_sha256,
        encoder_receipt_digest,
    }
}
