#![forbid(unsafe_code)]
//! Bounded recipe encoding. No path, runtime download, code, or ambient default.
//!
//! Version 1 is the recipe of a frame decoded without a privacy mask policy; its bytes are
//! unchanged. Version 2 is identical plus the applied privacy mask policy digest (a trailing
//! marker), so a masked frame's evidence can never be replayed as, or confused with, an
//! unmasked one.
use super::*;
use crate::ingest::privacy_mask::{decode_marker, encode_marker};

const RECIPE_V1: &str = "fss.rgb-source-evidence.recipe.v1";
const RECIPE_V2: &str = "fss.rgb_source_evidence.recipe.v2";
use crate::ingest::rgb_detections::{HeadBoxes, HeadClasses, HeadLayout, HeadScore};

pub(super) fn encode(r: &Recipe) -> Result<Vec<u8>, RgbEvidenceError> {
    let mut e = CanonicalEncoder::new();
    e.text(if r.mask_policy.is_some() {
        RECIPE_V2
    } else {
        RECIPE_V1
    });
    e.digest(r.graph);
    e.digest(r.weights);
    e.text(&r.spec.image_input);
    e.u64(r.spec.preprocess.target_height as u64);
    e.u64(r.spec.preprocess.target_width as u64);
    e.bool(r.spec.preprocess.scale_to_unit);
    if r.spec.preprocess.channel_transform != ChannelTransform::Rgb {
        return Err(RgbEvidenceError::Format);
    }
    e.u8(match r.spec.filter {
        ResizeFilter::Nearest => 0,
        ResizeFilter::Bilinear => 1,
    });
    match r.spec.aspect {
        ResizeAspect::Stretch => e.u8(0),
        ResizeAspect::Letterbox(v) => {
            e.u8(1);
            e.u8(v);
        }
    }
    e.bytes(&r.spec.masked_rgb);
    e.u8(match r.float {
        WeightFloatPolicy::F32Only => 0,
        WeightFloatPolicy::ExpandFloat16 => 1,
    });
    e.u64(r.bindings.len() as u64);
    for (port, name) in &r.bindings {
        e.text(port);
        e.text(name);
    }
    let h = &r.head;
    e.digest(h.model);
    e.text(&h.output_port);
    e.u64(h.labels.len() as u64);
    for label in &h.labels {
        e.text(label);
    }
    e.u8(match h.layout {
        HeadLayout::Rows => 0,
        HeadLayout::Channels => 1,
    });
    e.u8(match h.boxes {
        HeadBoxes::PixelCorners => 0,
        HeadBoxes::PixelCenterSize => 1,
        HeadBoxes::NormalizedCorners => 2,
        HeadBoxes::NormalizedCenterSize => 3,
    });
    e.u8(score(h.class_score));
    e.u8(h.objectness.map_or(0, |s| score(s) + 1));
    e.u8(match h.classes {
        HeadClasses::Best => 0,
        HeadClasses::MultiLabel => 1,
    });
    e.u32(h.minimum_score_ppm);
    e.u32(h.nms_iou_ppm);
    for n in [h.maximum_rows, h.maximum_candidates, h.maximum_detections] {
        e.u64(n as u64);
    }
    let s = r.source;
    for hash in [
        s.encoded_sha256,
        s.exposure,
        s.image_domain,
        s.calibration,
        s.permission_mask,
    ] {
        e.bytes(&hash);
    }
    for n in [s.camera, s.clock, s.capture[0], s.capture[1]] {
        e.u64(n);
    }
    e.u8(match r.interpretation {
        ComponentInterpretation::Grayscale => 0,
        ComponentInterpretation::YCbCr => 1,
    });
    e.u8(match r.availability {
        TrackingAvailability::Available => 0,
        TrackingAvailability::Unobservable => 1,
        TrackingAvailability::Disturbed => 2,
    });
    e.bytes(&r.admission);
    for digest in r.expected {
        e.digest(digest);
    }
    if r.mask_policy.is_some() {
        encode_marker(&mut e, r.mask_policy);
    }
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_RECIPE {
        return Err(RgbEvidenceError::Limit);
    }
    Ok(bytes)
}
fn score(s: HeadScore) -> u8 {
    match s {
        HeadScore::Probability => 0,
        HeadScore::Logit => 1,
    }
}
fn read_score(n: u8) -> Result<HeadScore, RgbEvidenceError> {
    match n {
        0 => Ok(HeadScore::Probability),
        1 => Ok(HeadScore::Logit),
        _ => Err(RgbEvidenceError::Format),
    }
}
fn count(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize, RgbEvidenceError> {
    let n = usize::try_from(d.u64()?).map_err(|_| RgbEvidenceError::Limit)?;
    if n > maximum {
        return Err(RgbEvidenceError::Limit);
    }
    Ok(n)
}
fn text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String, RgbEvidenceError> {
    let s = d.text()?;
    if s.is_empty() || s.len() > maximum || s.chars().any(char::is_control) {
        return Err(RgbEvidenceError::Format);
    }
    Ok(s.to_owned())
}
fn hash(d: &mut CanonicalDecoder<'_>) -> Result<[u8; 32], RgbEvidenceError> {
    let h = d
        .bytes()?
        .try_into()
        .map_err(|_| RgbEvidenceError::Format)?;
    if h == [0; 32] {
        return Err(RgbEvidenceError::Format);
    }
    Ok(h)
}
pub(super) fn decode(bytes: &[u8]) -> Result<Recipe, RgbEvidenceError> {
    if bytes.len() > MAX_RECIPE {
        return Err(RgbEvidenceError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    let masked = match d.text()? {
        RECIPE_V1 => false,
        RECIPE_V2 => true,
        _ => return Err(RgbEvidenceError::Format),
    };
    let graph = d.digest()?;
    let weights = d.digest()?;
    let image_input = text(&mut d, 256)?;
    let height = count(&mut d, 4096)?;
    let width = count(&mut d, 4096)?;
    if height == 0 || width == 0 || height * width > MAX_MASK {
        return Err(RgbEvidenceError::Limit);
    }
    let scale = d.bool()?;
    let filter = match d.u8()? {
        0 => ResizeFilter::Nearest,
        1 => ResizeFilter::Bilinear,
        _ => return Err(RgbEvidenceError::Format),
    };
    let aspect = match d.u8()? {
        0 => ResizeAspect::Stretch,
        1 => ResizeAspect::Letterbox(d.u8()?),
        _ => return Err(RgbEvidenceError::Format),
    };
    let masked_rgb = d
        .bytes()?
        .try_into()
        .map_err(|_| RgbEvidenceError::Format)?;
    let spec = RgbModelSpec {
        image_input,
        preprocess: PreprocessProgram::new(height, width, ChannelTransform::Rgb, scale),
        filter,
        aspect,
        masked_rgb,
    };
    let float = match d.u8()? {
        0 => WeightFloatPolicy::F32Only,
        1 => WeightFloatPolicy::ExpandFloat16,
        _ => return Err(RgbEvidenceError::Format),
    };
    let n = count(&mut d, 256)?;
    let mut bindings = BTreeMap::new();
    let mut previous = None;
    for _ in 0..n {
        let port = text(&mut d, 256)?;
        let name = text(&mut d, 256)?;
        if previous.as_ref().is_some_and(|p: &String| p >= &port) {
            return Err(RgbEvidenceError::Format);
        }
        previous = Some(port.clone());
        bindings.insert(port, name);
    }
    let model = d.digest()?;
    let output_port = text(&mut d, 128)?;
    let n = count(&mut d, 256)?;
    let mut labels = Vec::new();
    labels
        .try_reserve_exact(n)
        .map_err(|_| RgbEvidenceError::Limit)?;
    for _ in 0..n {
        labels.push(text(&mut d, 128)?);
    }
    let layout = match d.u8()? {
        0 => HeadLayout::Rows,
        1 => HeadLayout::Channels,
        _ => return Err(RgbEvidenceError::Format),
    };
    let boxes = match d.u8()? {
        0 => HeadBoxes::PixelCorners,
        1 => HeadBoxes::PixelCenterSize,
        2 => HeadBoxes::NormalizedCorners,
        3 => HeadBoxes::NormalizedCenterSize,
        _ => return Err(RgbEvidenceError::Format),
    };
    let class_score = read_score(d.u8()?)?;
    let objectness = match d.u8()? {
        0 => None,
        1 => Some(HeadScore::Probability),
        2 => Some(HeadScore::Logit),
        _ => return Err(RgbEvidenceError::Format),
    };
    let classes = match d.u8()? {
        0 => HeadClasses::Best,
        1 => HeadClasses::MultiLabel,
        _ => return Err(RgbEvidenceError::Format),
    };
    let head = RgbDetectionSpec {
        model,
        output_port,
        labels,
        layout,
        boxes,
        class_score,
        objectness,
        classes,
        minimum_score_ppm: d.u32()?,
        nms_iou_ppm: d.u32()?,
        maximum_rows: count(&mut d, 32_768)?,
        maximum_candidates: count(&mut d, 4096)?,
        maximum_detections: count(&mut d, 256)?,
    };
    let source = RgbSourceBinding {
        encoded_sha256: hash(&mut d)?,
        exposure: hash(&mut d)?,
        image_domain: hash(&mut d)?,
        calibration: hash(&mut d)?,
        permission_mask: hash(&mut d)?,
        camera: d.u64()?,
        clock: d.u64()?,
        capture: [d.u64()?, d.u64()?],
    };
    let interpretation = match d.u8()? {
        0 => ComponentInterpretation::Grayscale,
        1 => ComponentInterpretation::YCbCr,
        _ => return Err(RgbEvidenceError::Format),
    };
    let availability = match d.u8()? {
        0 => TrackingAvailability::Available,
        1 => TrackingAvailability::Unobservable,
        2 => TrackingAvailability::Disturbed,
        _ => return Err(RgbEvidenceError::Format),
    };
    let admission = hash(&mut d)?;
    let expected = [
        d.digest()?,
        d.digest()?,
        d.digest()?,
        d.digest()?,
        d.digest()?,
        d.digest()?,
        d.digest()?,
    ];
    let mask_policy = if masked {
        Some(decode_marker(&mut d)?.ok_or(RgbEvidenceError::Format)?)
    } else {
        None
    };
    d.ensure_finished()?;
    RgbFrameAdmission::new(
        source,
        availability,
        ContentDigest::new(DigestAlgorithm::Sha256, admission),
    )
    .map_err(computation)?;
    RgbDetectionContract::new(head.clone()).map_err(computation)?;
    let result = Recipe {
        graph,
        weights,
        spec,
        float,
        bindings,
        head,
        source,
        interpretation,
        availability,
        admission,
        expected,
        mask_policy,
    };
    if encode(&result)? != bytes {
        return Err(RgbEvidenceError::Format);
    }
    Ok(result)
}
