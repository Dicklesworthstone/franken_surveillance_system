#![forbid(unsafe_code)]
//! Bounded JPEG derivatives from already decoded H.264 pictures.
//!
//! The caller declares the color interpretation and supplies the expected I420
//! digest. A derivative is not evidence of live capture, source custody,
//! physical camera identity, privacy approval, or permission to publish it.

use std::sync::atomic::{AtomicBool, Ordering};

use fss_codec_h264::Picture;
use fss_codec_jpeg_encode::{
    EncodeBudget, EncodeConfig, EncodeError, EncodeLimits, EncodedJpeg, PixelFormat, encode_jpeg,
};
use fss_core::{CanonicalEncoder, ContentDigest, Sha256Hasher};

/// Caller-declared coded-pixel interpretation; the decoder does not expose VUI color metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Color {
    /// BT.601 matrix and full-range luma/chroma, with nearest-cell chroma replication.
    Bt601Full,
    /// BT.601 matrix and limited-range luma/chroma, with nearest-cell chroma replication.
    Bt601Limited,
}

/// Payload-free failure; no partial image is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Dimensions, limits, plane lengths, or requested quality are invalid.
    Configuration,
    /// The supplied expected I420 digest does not match the picture.
    SourceMismatch,
    /// The caller's pixel-conversion allowance is insufficient.
    WorkLimit,
    /// The owner requested cancellation.
    Cancelled,
    /// A bounded allocation failed.
    Allocation,
    /// JPEG encoding refused or exceeded its own independent budget.
    Encode(EncodeError),
    /// Source-checked container parsing or IDR extraction refused.
    Demux,
    /// The bounded H.264 decoder refused the extracted picture.
    Decode,
    /// The first sample did not yield exactly one picture.
    PictureCount,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "video still refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// A complete lossy derivative and its declared interpretation.
#[must_use]
pub struct Still {
    /// The exact decoded I420 planes, hashed in Y, Cb, Cr order.
    source_i420_sha256: [u8; 32],
    /// Explicit color interpretation, not a camera metadata claim.
    color: Color,
    /// Complete JPEG and its pixel, encoder, output, and work receipt.
    jpeg: EncodedJpeg,
    /// Digest binding the declared source, interpretation and encoded output.
    identity: ContentDigest,
}

/// How the exact source root was associated with this still.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provenance {
    /// Source and graph were recovered and checked from the archive.
    RecoveredArchive,
    /// Source was returned by the confirmed publication, without a new archive readback.
    ConfirmedPublication,
}

/// A still bound to a source-checked or confirmed-publication root.
#[must_use]
pub struct ArchivedStill {
    pin: super::archive::UnknownTimePin,
    source: fss_container::flv_avc::SourceKey,
    still: Still,
    identity: ContentDigest,
    provenance: Provenance,
}
impl ArchivedStill {
    /// Previously checked root and retention identity; this is not a live grant.
    pub const fn pin(&self) -> super::archive::UnknownTimePin {
        self.pin
    }
    /// Caller-bound connection and generation claim, not authenticated camera identity.
    pub const fn claimed_source(&self) -> fss_container::flv_avc::SourceKey {
        self.source
    }
    /// The complete JPEG derivative and declared color interpretation.
    pub const fn still(&self) -> &Still {
        &self.still
    }
    /// Digest binding root, retention, source claim and still identity.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Whether the source was recovered or came from the just-confirmed publication.
    pub const fn provenance(&self) -> Provenance {
        self.provenance
    }
}
impl Still {
    /// Digest of the decoded source planes, in Y, Cb, Cr order.
    pub const fn source_i420_sha256(&self) -> [u8; 32] {
        self.source_i420_sha256
    }
    /// The caller-declared color interpretation.
    pub const fn color(&self) -> Color {
        self.color
    }
    /// The complete derivative and encoder receipt.
    pub const fn jpeg(&self) -> &EncodedJpeg {
        &self.jpeg
    }
    /// Canonical derivative identity; this is not a source-custody attestation.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
}

fn rgb(y: u8, cb: u8, cr: u8, color: Color) -> [u8; 3] {
    let cb = i32::from(cb) - 128;
    let cr = i32::from(cr) - 128;
    let (y, rr, gg_cb, gg_cr, bb) = match color {
        Color::Bt601Full => (i32::from(y) * 65_536, 91_881, 22_554, 46_802, 116_130),
        Color::Bt601Limited => (
            (i32::from(y) - 16) * 76_309,
            104_597,
            25_675,
            53_279,
            132_201,
        ),
    };
    let channel = |v: i32| ((v + 32_768).div_euclid(65_536)).clamp(0, 255) as u8;
    [
        channel(y + rr * cr),
        channel(y - gg_cb * cb - gg_cr * cr),
        channel(y + bb * cb),
    ]
}

fn picture_digest(
    picture: &Picture,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<[u8; 32], Error> {
    let mut hash = Sha256Hasher::new();
    for plane in [picture.luma(), picture.cb(), picture.cr()] {
        for chunk in plane.chunks(16 * 1024) {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            hash.update(chunk);
        }
    }
    hash.finalize().map_err(|_| Error::Configuration)
}

/// Decode the first independently decodable sample of a source-checked archive
/// clip and encode its one picture. Caller retains read/export/privacy authority.
/// Cancellation is checked at demux checkpoints and between complete NALs;
/// a single synchronous H.264 NAL decode is not preempted by this function.
pub fn from_archive(
    clip: &super::archive::RecoveredUnknownTimeVideoClip,
    color: Color,
    quality: u8,
    limits: &EncodeLimits,
    pixel_work_limit: u64,
    encode_work_limit: u64,
    cancelled: &AtomicBool,
) -> Result<ArchivedStill, Error> {
    from_archive_with_probe(
        clip,
        color,
        quality,
        limits,
        pixel_work_limit,
        encode_work_limit,
        &|| cancelled.load(Ordering::Acquire),
    )
}

/// Like [`from_archive`], with an owner-supplied cancellation probe suitable
/// for a region-owned blocking worker. The probe does not grant authority.
pub fn from_archive_with_probe(
    clip: &super::archive::RecoveredUnknownTimeVideoClip,
    color: Color,
    quality: u8,
    limits: &EncodeLimits,
    pixel_work_limit: u64,
    encode_work_limit: u64,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<ArchivedStill, Error> {
    from_media(
        clip.bytes(),
        clip.samples(),
        clip.pin(),
        clip.claimed_source(),
        Provenance::RecoveredArchive,
        color,
        quality,
        limits,
        pixel_work_limit,
        encode_work_limit,
        cancelled,
    )
}

/// Derive a still from a sealed confirmed publication while recording continues.
/// The original publication remains with `source`; this does not reread storage.
pub fn from_published_with_probe(
    source: &super::video_owned_sink::PublishedStillSource,
    color: Color,
    quality: u8,
    limits: &EncodeLimits,
    pixel_work_limit: u64,
    encode_work_limit: u64,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<ArchivedStill, Error> {
    use super::video_owned_sink::StillSourceError;
    let media = source
        .checked_media(cancelled)
        .map_err(|error| match error {
            StillSourceError::Mismatch => Error::SourceMismatch,
            StillSourceError::Limit => Error::Configuration,
            StillSourceError::Cancelled => Error::Cancelled,
        })?;
    from_media(
        &media,
        source.samples(),
        source.pin(),
        source.claimed_source(),
        Provenance::ConfirmedPublication,
        color,
        quality,
        limits,
        pixel_work_limit,
        encode_work_limit,
        cancelled,
    )
}

fn from_media(
    media: &[u8],
    samples: usize,
    pin: super::archive::UnknownTimePin,
    source: fss_container::flv_avc::SourceKey,
    provenance: Provenance,
    color: Color,
    quality: u8,
    limits: &EncodeLimits,
    pixel_work_limit: u64,
    encode_work_limit: u64,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<ArchivedStill, Error> {
    use fss_container::demux::{AvcMp4, DemuxError, DemuxLimits};
    let mut check = || {
        if cancelled() {
            Err(DemuxError::Cancelled)
        } else {
            Ok(())
        }
    };
    let demux_error = |error| {
        if error == DemuxError::Cancelled {
            Error::Cancelled
        } else {
            Error::Demux
        }
    };
    let movie =
        AvcMp4::parse_inband_with_checkpoint(media, None, DemuxLimits::default(), &mut check)
            .map_err(demux_error)?;
    if movie.samples().len() != samples || samples == 0 {
        return Err(Error::Demux);
    }
    let annex = movie
        .annex_b_with_checkpoint(0, 1, &mut check)
        .map_err(demux_error)?;
    let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())
        .map_err(|_| Error::Decode)?;
    let mut picture = None;
    for nal in fss_codec_h264::annex_b_nal_units(annex.bytes()) {
        if cancelled() {
            return Err(Error::Cancelled);
        }
        if let Some(frame) = decoder.decode_nal(nal).map_err(|_| Error::Decode)? {
            if picture.replace(frame).is_some() {
                return Err(Error::PictureCount);
            }
        }
        while let Some(frame) = decoder.next_output() {
            if picture.replace(frame).is_some() {
                return Err(Error::PictureCount);
            }
        }
    }
    if cancelled() {
        return Err(Error::Cancelled);
    }
    for frame in decoder.finish().map_err(|_| Error::Decode)? {
        if picture.replace(frame).is_some() {
            return Err(Error::PictureCount);
        }
    }
    let picture = picture.ok_or(Error::PictureCount)?;
    let source_hash = picture_digest(&picture, cancelled)?;
    let still = from_picture_with_probe(
        &picture,
        source_hash,
        color,
        quality,
        limits,
        pixel_work_limit,
        encode_work_limit,
        cancelled,
    )?;
    let mut identity = CanonicalEncoder::new();
    identity.text(match provenance {
        Provenance::RecoveredArchive => "fss.unifi-direct.archived-video-still.v1",
        Provenance::ConfirmedPublication => "fss.unifi-direct.published-video-still.v1",
    });
    identity.digest(pin.root);
    identity.digest(pin.retention);
    identity.u64(source.connection);
    identity.u64(source.generation);
    identity.digest(still.identity());
    let identity = ContentDigest::sha256(
        &identity
            .finish_checked()
            .map_err(|_| Error::Configuration)?,
    );
    Ok(ArchivedStill {
        pin,
        source,
        still,
        identity,
        provenance,
    })
}

/// Encode one full-size picture; no resize, metadata, I/O, or detached work.
///
/// `pixel_work_limit` bounds conversion pixels separately from `encode_work_limit`.
/// Cancellation is checked during hashing, once per converted row, and by the
/// encoder. A matching source digest binds the supplied picture bytes only.
pub fn from_picture(
    picture: &Picture,
    expected_i420_sha256: [u8; 32],
    color: Color,
    quality: u8,
    limits: &EncodeLimits,
    pixel_work_limit: u64,
    encode_work_limit: u64,
    cancelled: &AtomicBool,
) -> Result<Still, Error> {
    from_picture_with_probe(
        picture,
        expected_i420_sha256,
        color,
        quality,
        limits,
        pixel_work_limit,
        encode_work_limit,
        &|| cancelled.load(Ordering::Acquire),
    )
}

/// Like [`from_picture`], with an owner-supplied cancellation probe.
pub fn from_picture_with_probe(
    picture: &Picture,
    expected_i420_sha256: [u8; 32],
    color: Color,
    quality: u8,
    limits: &EncodeLimits,
    pixel_work_limit: u64,
    encode_work_limit: u64,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<Still, Error> {
    limits.validate().map_err(Error::Encode)?;
    let (width, height) = (picture.width() as usize, picture.height() as usize);
    let pixels = width.checked_mul(height).ok_or(Error::Configuration)?;
    let chroma = width
        .div_ceil(2)
        .checked_mul(height.div_ceil(2))
        .ok_or(Error::Configuration)?;
    if width == 0
        || height == 0
        || width > limits.maximum_dimension as usize
        || height > limits.maximum_dimension as usize
        || pixels > limits.maximum_pixels
        || picture.luma().len() != pixels
        || picture.cb().len() != chroma
        || picture.cr().len() != chroma
        || !(1..=100).contains(&quality)
    {
        return Err(Error::Configuration);
    }
    if u64::try_from(pixels).map_err(|_| Error::Configuration)? > pixel_work_limit {
        return Err(Error::WorkLimit);
    }
    let source = picture_digest(picture, cancelled)?;
    if expected_i420_sha256 == [0; 32] || source != expected_i420_sha256 {
        return Err(Error::SourceMismatch);
    }
    let mut packed = Vec::new();
    packed
        .try_reserve_exact(pixels.checked_mul(3).ok_or(Error::Configuration)?)
        .map_err(|_| Error::Allocation)?;
    let stride = width.div_ceil(2);
    let mut rgb_hasher = Sha256Hasher::new();
    for y in 0..height {
        if cancelled() {
            return Err(Error::Cancelled);
        }
        let row_start = packed.len();
        for x in 0..width {
            let c = (y / 2) * stride + x / 2;
            packed.extend_from_slice(&rgb(
                picture.luma()[y * width + x],
                picture.cb()[c],
                picture.cr()[c],
                color,
            ));
        }
        rgb_hasher.update(&packed[row_start..]);
    }
    if cancelled() {
        return Err(Error::Cancelled);
    }
    let rgb_hash = rgb_hasher.finalize().map_err(|_| Error::Configuration)?;
    let mut budget = EncodeBudget::with_cancellation_probe(encode_work_limit, cancelled);
    let jpeg = encode_jpeg(
        picture.width(),
        picture.height(),
        &packed,
        rgb_hash,
        EncodeConfig {
            quality,
            format: PixelFormat::Rgb,
        },
        limits,
        &mut budget,
    )
    .map_err(Error::Encode)?;
    let receipt = jpeg.receipt();
    let mut identity = CanonicalEncoder::new();
    identity.text("fss.unifi-direct.video-still.v1");
    identity.bytes(&source);
    identity.text(match color {
        Color::Bt601Full => "bt601-full-q16-nearest",
        Color::Bt601Limited => "bt601-limited-q16-nearest",
    });
    identity.bytes(&receipt.pixel_sha256);
    identity.bytes(&receipt.encoder);
    identity.bytes(&receipt.encoded_sha256);
    identity.u64(u64::from(picture.width()));
    identity.u64(u64::from(picture.height()));
    identity.u64(u64::from(quality));
    let identity = ContentDigest::sha256(
        &identity
            .finish_checked()
            .map_err(|_| Error::Configuration)?,
    );
    Ok(Still {
        source_i420_sha256: source,
        color,
        jpeg,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use super::{Color, rgb};

    #[test]
    fn explicit_color_ranges_are_distinct_and_match_reference() {
        assert_eq!(rgb(16, 128, 128, Color::Bt601Full), [16, 16, 16]);
        assert_eq!(rgb(16, 128, 128, Color::Bt601Limited), [0, 0, 0]);
        for (y, cb, cr) in [(0, 0, 0), (81, 90, 240), (126, 100, 150), (255, 255, 255)] {
            assert_eq!(
                rgb(y, cb, cr, Color::Bt601Limited),
                crate::ingest::recorded_decode::video_rgb::ycbcr_limited_to_rgb(y, cb, cr)
            );
        }
    }
}
