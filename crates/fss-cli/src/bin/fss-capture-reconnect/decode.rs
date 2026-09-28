#![forbid(unsafe_code)]
//! Complete native decode with the existing current-sensor privacy authority.
//! One decoder budget belongs to the entire run, never to an individual connection.

use std::collections::BTreeMap;
use std::path::Path;

use fss_cli::agent_json::{object, string};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits};
use fss_codec_mjpeg::http_mjpeg::HttpJpegFrame;
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::ingest::http_camera::HttpCameraDenial;
use fss_reference::ingest::http_replay::check::HttpCheckDecode;
use fss_reference::ingest::privacy_mask::live::{MaskRefusal, MaskedLuma, SensorMask};

use super::privacy;

#[derive(Debug)]
pub(super) struct Options {
    pub mode: HttpCheckDecode,
    pub limits: DecodeLimits,
    pub work: u64,
    pub privacy: privacy::Options,
}
impl Options {
    /// No default sensor, policy or interpretation. This is a pure parse, not a grant.
    pub fn parse(values: &BTreeMap<&str, &str>, root: &Path, maximum_bytes: usize)
        -> Result<Option<Self>, &'static str>
    {
        let mode = match values.get("--decode").copied().unwrap_or("none") {
            "none" => HttpCheckDecode::None,
            "grayscale" => HttpCheckDecode::Grayscale,
            "ycbcr" => HttpCheckDecode::YCbCr,
            _ => return Err("--decode must be none, grayscale or ycbcr"),
        };
        let privacy = privacy::Options::parse(values, mode, root)?;
        if mode == HttpCheckDecode::None {
            if ["--max-decode-work", "--max-dimension", "--max-pixels"].iter().any(|key| values.contains_key(key)) {
                return Err("decode limits require an explicit decode mode");
            }
            return Ok(None);
        }
        let number = |key: &str, default: u64, min: u64, max: u64| -> Result<u64, &'static str> {
            let value = match values.get(key) {
                None => default,
                Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) =>
                    text.parse::<u64>().map_err(|_| "decode integer overflow")?,
                Some(_) => return Err("unsigned decimal decode limit required"),
            };
            if !(min..=max).contains(&value) { return Err("decode limit exceeded"); }
            Ok(value)
        };
        Ok(Some(Self {
            mode,
            limits: DecodeLimits {
                maximum_bytes,
                maximum_dimension: number("--max-dimension", 4096, 1, 4096)? as u32,
                maximum_pixels: number("--max-pixels", 4_194_304, 1, 4_194_304)? as usize,
                ..DecodeLimits::default()
            },
            work: number("--max-decode-work", 1_000_000_000, 0, 1_000_000_000_000_000)?,
            privacy: privacy.ok_or("decoded capture requires a named sensor policy store")?,
        }))
    }
    pub fn encode(&self, e: &mut CanonicalEncoder) {
        e.text("complete-native-luma:current-mask-before-disclosure:one-decode-budget:v1");
        e.text(privacy::label(self.mode));
        e.digest(ContentDigest::new(fss_core::DigestAlgorithm::Sha256, fss_codec_mjpeg::decoder_identity()));
        for value in [self.limits.maximum_bytes as u64, u64::from(self.limits.maximum_dimension),
            self.limits.maximum_pixels as u64, self.limits.maximum_markers as u64, self.work]
        { e.u64(value); }
        self.privacy.encode(e);
    }
    pub fn to_json(&self) -> String {
        object(&[
            ("interpretation", string(privacy::label(self.mode))),
            ("plane", string("luma_only_all_entropy_components_validated")),
            ("decoder_identity", string(&super::byte_digest(fss_codec_mjpeg::decoder_identity()))),
            ("maximum_bytes", self.limits.maximum_bytes.to_string()),
            ("maximum_dimension", self.limits.maximum_dimension.to_string()),
            ("maximum_pixels", self.limits.maximum_pixels.to_string()),
            ("maximum_markers", self.limits.maximum_markers.to_string()),
            ("shared_work", self.work.to_string()), ("privacy", self.privacy.to_json()),
            ("pixels_emitted", "false".into()),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    Native(DecodeError),
    Privacy(MaskRefusal),
    Authority(HttpCameraDenial),
    Configuration,
}
impl Failure {
    pub fn code(self) -> &'static str {
        match self {
            Self::Native(_) => "ERR-CAPTURE-RECONNECT-DECODE-001",
            Self::Privacy(error) => error.stable_id(),
            Self::Authority(_) => "ERR-CAPTURE-RECONNECT-AUTHORITY-001",
            Self::Configuration => "ERR-CAPTURE-RECONNECT-CONFIG-001",
        }
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(e) => write!(f, "native complete-frame decode refused: {e}"),
            Self::Privacy(e) => write!(f, "current sensor privacy refused: {e}"),
            Self::Authority(e) => write!(f, "decode authority refused: {e:?}"),
            Self::Configuration => f.write_str("invalid native decode configuration"),
        }
    }
}
impl std::error::Error for Failure {}

/// The original encoded frame is already reverified against durable custody by the recorder.
/// Only masked planes can leave this owner; errors return neither pixels nor an unmasked digest.
pub(super) struct Decoder {
    interpretation: ComponentInterpretation,
    limits: DecodeLimits,
    work: DecodeBudget<'static>,
    frames: u64,
    pixels: u64,
}
impl Decoder {
    pub fn new(options: &Options) -> Result<Self, Failure> {
        let interpretation = match options.mode {
            HttpCheckDecode::Grayscale => ComponentInterpretation::Grayscale,
            HttpCheckDecode::YCbCr => ComponentInterpretation::YCbCr,
            HttpCheckDecode::None => return Err(Failure::Configuration),
        };
        Ok(Self { interpretation, limits: options.limits, work: DecodeBudget::new(options.work), frames: 0, pixels: 0 })
    }
    pub fn used(&self) -> u64 { self.work.used() }
    pub fn remaining(&self) -> u64 { self.work.remaining() }
    pub fn frames(&self) -> u64 { self.frames }
    pub fn pixels(&self) -> u64 { self.pixels }

    pub fn decode(&mut self, frame: &HttpJpegFrame, sensor: SensorMask<'_>,
        permit: impl FnMut() -> Result<(), HttpCameraDenial>) -> Result<MaskedLuma, Failure>
    {
        // This private worker also allows fixture tests to supply exact native JPEG bytes without
        // inventing a live HTTP receipt. Production always uses HttpJpegFrame::decode.
        let interpretation = self.interpretation;
        let limits = self.limits;
        self.masked(sensor, permit, |work| frame.decode(interpretation, limits, work))
    }
    fn masked(&mut self, sensor: SensorMask<'_>, mut permit: impl FnMut() -> Result<(), HttpCameraDenial>,
        native: impl FnOnce(&mut DecodeBudget<'static>) -> Result<fss_codec_mjpeg::DecodedLuma, DecodeError>)
        -> Result<MaskedLuma, Failure>
    {
        permit().map_err(Failure::Authority)?;
        let mask = sensor.resolve().map_err(|e| Failure::Privacy(e.into()))?;
        let identity = (mask.digest(), mask.generation());
        let image = native(&mut self.work).map_err(Failure::Native)?;
        let dimensions = image.dimensions();
        // Account native reconstruction even if a later mask/resolution/authority check refuses.
        self.pixels += u64::from(dimensions[0]) * u64::from(dimensions[1]);
        permit().map_err(Failure::Authority)?;
        let masked = mask.mask_luma(image).map_err(|e| Failure::Privacy(e.into()))?;
        let current = sensor.resolve().map_err(|e| Failure::Privacy(e.into()))?;
        if (current.digest(), current.generation()) != identity {
            return Err(Failure::Privacy(MaskRefusal::UnmaskedAccess));
        }
        permit().map_err(Failure::Authority)?;
        self.frames += 1;
        Ok(masked)
    }
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
