#![forbid(unsafe_code)]
//! Strict inverse of the retained localization recipe. No serde or implicit defaults.

use super::*;
use crate::ingest::recorded_decode::h264::DecoderLimits as AvcLimits;
use crate::ingest::recorded_decode::h265::DecoderLimits as HevcLimits;
use crate::ingest::recorded_decode::{ComponentInterpretation, DecodeLimits};
use fss_core::{CanonicalDecode, CanonicalDecoder};
use fss_geometry::{PinholeIntrinsics, PoseSolverOptions};
use fss_twin::localization::MatchOptions;
use fss_twin::localization::native::ExtractionOptions;
use fss_twin::rectification::{LensDistortion, LumaRange};

fn invalid() -> RecordedLocalizationError {
    RecordedLocalizationError::RetainedPackage
}
fn hash(e: &mut CanonicalEncoder, value: [u8; 32]) {
    e.digest(sha(value));
}
fn source(e: &mut CanonicalEncoder, source: &RecordedLocalizationSource) {
    let (tag, interpretation) = match source {
        RecordedLocalizationSource::Jpeg(r) => (0, r.interpretation),
        RecordedLocalizationSource::H264 { request, .. } => (1, request.interpretation),
        RecordedLocalizationSource::H265 { request, .. } => (2, request.interpretation),
    };
    e.u8(tag);
    e.digest(source.import_identity());
    e.u64(source.segment() as u64);
    let (start, count) = source.range();
    e.u64(start as u64);
    e.u64(count as u64);
    e.u8(match interpretation {
        ComponentInterpretation::Grayscale => 0,
        ComponentInterpretation::YCbCr => 1,
    });
    let l = source.limits();
    for n in [l.max_source_bytes, l.max_chunk_bytes, l.max_segment_bytes] {
        e.u64(n);
    }
    match source {
        RecordedLocalizationSource::Jpeg(r) => {
            let l = r.decode_limits;
            e.u64(l.maximum_bytes as u64);
            e.u32(l.maximum_dimension);
            e.u64(l.maximum_pixels as u64);
            e.u64(l.maximum_markers as u64);
        }
        RecordedLocalizationSource::H264 { request, .. } => {
            let l = request.decoder_limits;
            e.u32(l.max_width);
            e.u32(l.max_height);
            e.u32(l.max_macroblocks);
            e.u64(l.max_pictures);
            e.u64(l.max_nal_bytes as u64);
            e.u32(l.max_slices_per_picture);
            e.u32(l.max_reference_frames);
        }
        RecordedLocalizationSource::H265 { request, .. } => {
            let l = request.decoder_limits;
            e.u32(l.max_width);
            e.u32(l.max_height);
            e.u64(l.max_luma_samples);
            e.u64(l.max_pictures);
            e.u64(l.max_nal_bytes as u64);
            e.u32(l.max_slices_per_picture);
            e.u32(l.max_dpb_pictures);
        }
    }
}

pub(super) fn encode(r: &Recipe) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.text(PACKAGE_DOMAIN);
    e.text("unactivated_camera_pose_candidates");
    source(&mut e, &r.source);
    for d in [
        r.import_root,
        r.source_manifest,
        r.capsule,
        r.mask_binding,
        r.receipt,
    ] {
        e.digest(d);
    }
    r.source_anchor.encode_canonical(&mut e);
    e.bool(r.decode_root.is_some());
    if let Some(root) = r.decode_root {
        e.digest(root);
    }
    for d in [
        r.twin,
        r.scene,
        r.atlas.package,
        r.atlas.provenance,
        r.atlas.descriptor,
    ] {
        hash(&mut e, d);
    }
    super::super::receipt::mode(&mut e, r.image);
    super::super::receipt::options(&mut e, r.options);
    let bytes = e.finish_checked().map_err(RecordedDecodeError::from)?;
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

struct Reader<'a>(CanonicalDecoder<'a>);
impl Reader<'_> {
    fn byte(&mut self) -> Result<u8> {
        self.0
            .u8()
            .map_err(RecordedDecodeError::from)
            .map_err(Into::into)
    }
    fn u32(&mut self) -> Result<u32> {
        self.0
            .u32()
            .map_err(RecordedDecodeError::from)
            .map_err(Into::into)
    }
    fn u64(&mut self) -> Result<u64> {
        self.0
            .u64()
            .map_err(RecordedDecodeError::from)
            .map_err(Into::into)
    }
    fn digest(&mut self) -> Result<ContentDigest> {
        let value = self.0.digest().map_err(RecordedDecodeError::from)?;
        if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
            return Err(invalid());
        }
        Ok(value)
    }
    fn hash(&mut self) -> Result<[u8; 32]> {
        Ok(self.digest()?.bytes())
    }
    fn float(&mut self) -> Result<f64> {
        let bits = self.u64()?;
        let value = f64::from_bits(bits);
        if !value.is_finite() || bits == (1_u64 << 63) {
            return Err(invalid());
        }
        Ok(value)
    }
    fn usize(&mut self, maximum: usize) -> Result<usize> {
        let n = usize::try_from(self.u64()?).map_err(|_| invalid())?;
        if n > maximum {
            return Err(invalid());
        }
        Ok(n)
    }
    fn camera(&mut self) -> Result<PinholeIntrinsics> {
        let w = self.u32()?;
        let h = self.u32()?;
        if w == 0 || h == 0 || w > 4096 || h > 4096 || u64::from(w) * u64::from(h) > 4_194_304 {
            return Err(invalid());
        }
        Ok(PinholeIntrinsics::new(
            w,
            h,
            self.float()?,
            self.float()?,
            self.float()?,
            self.float()?,
        )?)
    }
    fn image(&mut self) -> Result<RecordedImageMode> {
        match self.byte()? {
            0 => Ok(RecordedImageMode::Pinhole(LocalizationCamera {
                intrinsics: self.camera()?,
                image_domain: self.hash()?,
            })),
            1 => {
                let source = self.camera()?;
                let target = self.camera()?;
                let distortion = match self.byte()? {
                    0 => LensDistortion::Pinhole,
                    1 => LensDistortion::BrownConrady {
                        radial: [self.float()?, self.float()?, self.float()?],
                        tangential: [self.float()?, self.float()?],
                    },
                    2 => LensDistortion::Fisheye {
                        coefficients: [self.float()?, self.float()?, self.float()?, self.float()?],
                    },
                    _ => return Err(invalid()),
                };
                let maximum_radius = self.float()?;
                let source_domain = self.hash()?;
                let calibration = self.hash()?;
                let range = match self.byte()? {
                    0 => LumaRange::Full,
                    1 => LumaRange::Video,
                    _ => return Err(invalid()),
                };
                Ok(RecordedImageMode::Raw(RectificationSpec {
                    source,
                    target,
                    distortion,
                    maximum_radius,
                    source_domain,
                    calibration,
                    range,
                }))
            }
            _ => Err(invalid()),
        }
    }
    fn options(&mut self) -> Result<ImageLocalizationOptions> {
        let extraction = ExtractionOptions {
            threshold: self.byte()?,
            maximum_features: self.usize(512)?,
            separation: u16::try_from(self.u32()?).map_err(|_| invalid())?,
        };
        let matching = MatchOptions {
            maximum_distance: u16::try_from(self.u32()?).map_err(|_| invalid())?,
            ratio_percent: self.byte()?,
        };
        let solving = PoseSolverOptions {
            ransac_trials: self.usize(1024)?,
            refinement_iterations: self.usize(100)?,
            seed: self.u64()?,
            inlier_threshold_px: self.float()?,
            minimum_inliers: self.usize(512)?,
            minimum_inlier_fraction: self.float()?,
            minimum_axis_ratio: self.float()?,
            minimum_image_span: self.float()?,
        };
        let options = ImageLocalizationOptions {
            extraction,
            matching,
            solving,
        };
        validate_options(options)?;
        Ok(options)
    }
    fn source(&mut self) -> Result<RecordedLocalizationSource> {
        let tag = self.byte()?;
        let import_identity = self.digest()?;
        let segment = self.usize(crate::ingest::retained::MAX_RETAINED_ENTRIES)?;
        let first_segment = self.usize(crate::ingest::retained::MAX_RETAINED_ENTRIES)?;
        let segment_count = self.usize(1024)?;
        if segment_count == 0
            || segment < first_segment
            || first_segment
                .checked_add(segment_count)
                .is_none_or(|end| segment >= end)
        {
            return Err(invalid());
        }
        let interpretation = match self.byte()? {
            0 => ComponentInterpretation::Grayscale,
            1 => ComponentInterpretation::YCbCr,
            _ => return Err(invalid()),
        };
        let read_limits = RetainedReadLimits {
            max_source_bytes: self.u64()?,
            max_chunk_bytes: self.u64()?,
            max_segment_bytes: self.u64()?,
        };
        if read_limits.max_source_bytes == 0
            || read_limits.max_chunk_bytes == 0
            || read_limits.max_segment_bytes == 0
            || read_limits.max_chunk_bytes > crate::ingest::retained::MAX_RETAINED_PAYLOAD_BYTES
            || read_limits.max_segment_bytes > crate::ingest::retained::MAX_RETAINED_PAYLOAD_BYTES
        {
            return Err(invalid());
        }
        match tag {
            0 => {
                if segment != first_segment || segment_count != 1 {
                    return Err(invalid());
                }
                let decode_limits = DecodeLimits {
                    maximum_bytes: self.usize(16 * 1024 * 1024)?,
                    maximum_dimension: self.u32()?,
                    maximum_pixels: self.usize(4_194_304)?,
                    maximum_markers: self.usize(4096)?,
                };
                if decode_limits.maximum_bytes == 0
                    || decode_limits.maximum_dimension == 0
                    || decode_limits.maximum_dimension > 4096
                    || decode_limits.maximum_pixels == 0
                    || decode_limits.maximum_markers == 0
                {
                    return Err(invalid());
                }
                Ok(RecordedLocalizationSource::Jpeg(RecordedDecodeRequest {
                    import_identity,
                    segment_index: segment,
                    interpretation,
                    read_limits,
                    decode_limits,
                }))
            }
            1 => {
                let decoder_limits = AvcLimits {
                    max_width: self.u32()?,
                    max_height: self.u32()?,
                    max_macroblocks: self.u32()?,
                    max_pictures: self.u64()?,
                    max_nal_bytes: self.usize(16 * 1024 * 1024)?,
                    max_slices_per_picture: self.u32()?,
                    max_reference_frames: self.u32()?,
                };
                if interpretation != ComponentInterpretation::YCbCr
                    || !(16..=16_384).contains(&decoder_limits.max_width)
                    || !(16..=16_384).contains(&decoder_limits.max_height)
                    || !(1..=1_048_576).contains(&decoder_limits.max_macroblocks)
                    || decoder_limits.max_pictures == 0
                    || decoder_limits.max_nal_bytes < 2
                    || !(1..=65_535).contains(&decoder_limits.max_slices_per_picture)
                    || decoder_limits.max_reference_frames > 16
                {
                    return Err(invalid());
                }
                Ok(RecordedLocalizationSource::H264 {
                    segment,
                    request: RecordedH264Request {
                        import_identity,
                        first_segment,
                        segment_count,
                        interpretation,
                        read_limits,
                        decoder_limits,
                    },
                })
            }
            2 => {
                let decoder_limits = HevcLimits {
                    max_width: self.u32()?,
                    max_height: self.u32()?,
                    max_luma_samples: self.u64()?,
                    max_pictures: self.u64()?,
                    max_nal_bytes: self.usize(16 * 1024 * 1024)?,
                    max_slices_per_picture: self.u32()?,
                    max_dpb_pictures: self.u32()?,
                };
                if interpretation != ComponentInterpretation::YCbCr
                    || !(8..=16_384).contains(&decoder_limits.max_width)
                    || !(8..=16_384).contains(&decoder_limits.max_height)
                    || !(64..=(1 << 28)).contains(&decoder_limits.max_luma_samples)
                    || decoder_limits.max_pictures == 0
                    || decoder_limits.max_nal_bytes < 3
                    || !(1..=65_535).contains(&decoder_limits.max_slices_per_picture)
                    || !(1..=16).contains(&decoder_limits.max_dpb_pictures)
                {
                    return Err(invalid());
                }
                Ok(RecordedLocalizationSource::H265 {
                    segment,
                    request: RecordedH265Request {
                        import_identity,
                        first_segment,
                        segment_count,
                        interpretation,
                        read_limits,
                        decoder_limits,
                    },
                })
            }
            _ => Err(invalid()),
        }
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<Recipe> {
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(invalid());
    }
    let mut d = Reader(CanonicalDecoder::new(bytes));
    if d.0.text().map_err(RecordedDecodeError::from)? != PACKAGE_DOMAIN
        || d.0.text().map_err(RecordedDecodeError::from)? != "unactivated_camera_pose_candidates"
    {
        return Err(invalid());
    }
    let source = d.source()?;
    let import_root = d.digest()?;
    let source_manifest = d.digest()?;
    let capsule = d.digest()?;
    let mask_binding = d.digest()?;
    let receipt = d.digest()?;
    let source_anchor =
        LedgerAnchor::decode_canonical(&mut d.0).map_err(RecordedDecodeError::from)?;
    let decode_root = if d.0.bool().map_err(RecordedDecodeError::from)? {
        Some(d.digest()?)
    } else {
        None
    };
    if matches!(source, RecordedLocalizationSource::Jpeg(_)) != decode_root.is_some() {
        return Err(invalid());
    }
    let twin = d.hash()?;
    let scene = d.hash()?;
    let atlas = ArchiveExpectation {
        package: d.hash()?,
        provenance: d.hash()?,
        descriptor: d.hash()?,
    };
    if atlas.descriptor != fss_twin::localization::native::descriptor_domain() {
        return Err(invalid());
    }
    let image = d.image()?;
    let options = d.options()?;
    d.0.ensure_finished().map_err(RecordedDecodeError::from)?;
    let recipe = Recipe {
        source,
        import_root,
        source_manifest,
        source_anchor,
        capsule,
        mask_binding,
        decode_root,
        receipt,
        twin,
        scene,
        atlas,
        image,
        options,
    };
    if encode(&recipe)? != bytes {
        return Err(invalid());
    }
    Ok(recipe)
}
