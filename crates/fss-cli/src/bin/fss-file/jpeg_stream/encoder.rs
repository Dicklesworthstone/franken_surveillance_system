#![forbid(unsafe_code)]
//! Bounded synchronous MJPEG stream core. The caller owns every write and checkpoint.

use std::io::{self, Write};

use fss_codec_jpeg_encode::{
    EncodeBudget, EncodeConfig, EncodeLimits, EncodeReceipt, PixelFormat, encode_jpeg,
};
use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};

pub(crate) const DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const DEFAULT_ENCODE_WORK_UNITS: u64 = 2_000_000_000;
pub(crate) const DEFAULT_QUALITY: u8 = 85;
pub(crate) const FRAME_RECEIPTS_DOMAIN: &str = "fss.file_mjpeg_frame_receipts.v1";
const WRITE_CHUNK: usize = 4096;

fn refused(message: &'static str) -> io::Error {
    io::Error::other(message)
}

/// A complete, ordered local derivation. This grants no custody or delivery authority.
pub(crate) struct StreamReceipt {
    pub bytes: u64,
    pub frames: usize,
    pub digest: ContentDigest,
    pub frame_receipts_digest: ContentDigest,
    pub encoder: ContentDigest,
    pub quality: u8,
    pub work_units: u64,
}

/// Caller-supplied input pins. The runtime adapter obtains both from its sealed decode owner;
/// this pure encoder checks the pixel binding but does not independently load source custody.
pub(crate) struct FrameInput<'a> {
    pub dimensions: [u32; 2],
    pub pixels: &'a [u8],
    pub luma_sha256: [u8; 32],
    pub decode_receipt: ContentDigest,
}

/// At most one complete encoded frame is buffered. A failed frame fences the entire stream.
pub(crate) struct Encoder<W> {
    writer: Option<W>,
    encoder: Option<[u8; 32]>,
    hash: Sha256Hasher,
    receipts: Sha256Hasher,
    maximum: u64,
    maximum_frames: usize,
    bytes: u64,
    frames: usize,
    work_units: u64,
    quality: u8,
    failed: bool,
}

impl<W: Write> Encoder<W> {
    pub(crate) fn new(maximum: u64, maximum_frames: usize, quality: u8) -> io::Result<Self> {
        if maximum == 0
            || maximum > MAX_OUTPUT_BYTES
            || !(1..=1024).contains(&maximum_frames)
            || !(1..=100).contains(&quality)
        {
            return Err(refused("invalid MJPEG export allowance or quality"));
        }
        let mut receipts = Sha256Hasher::new();
        receipts.update(FRAME_RECEIPTS_DOMAIN.as_bytes());
        receipts.update(&[0]);
        Ok(Self {
            writer: None,
            encoder: None,
            hash: Sha256Hasher::new(),
            receipts,
            maximum,
            maximum_frames,
            bytes: 0,
            frames: 0,
            work_units: 0,
            quality,
            failed: false,
        })
    }

    pub(crate) fn frame(
        &mut self,
        input: FrameInput<'_>,
        budget: &mut EncodeBudget<'_>,
        create: impl FnOnce() -> io::Result<W>,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.failed {
            return Err(refused("MJPEG export fenced after an earlier refusal"));
        }
        let result = (|| {
            check()?;
            let remaining = self.maximum.saturating_sub(self.bytes);
            if self.frames >= self.maximum_frames || remaining == 0 {
                return Err(refused("MJPEG export byte or frame allowance exceeded"));
            }
            let mut limits = EncodeLimits::default();
            limits.maximum_output_bytes = limits
                .maximum_output_bytes
                .min(usize::try_from(remaining).map_err(|_| refused("MJPEG byte allowance"))?);
            // The codec returns no bytes on refusal. In particular, a new file is not created
            // until the whole first frame fits both the remaining bytes and shared work.
            let encoded = encode_jpeg(
                input.dimensions[0],
                input.dimensions[1],
                input.pixels,
                input.luma_sha256,
                EncodeConfig {
                    quality: self.quality,
                    format: PixelFormat::Grayscale,
                },
                &limits,
                budget,
            )
            .map_err(io::Error::other)?;
            check()?;
            let receipt = encoded.receipt();
            if self.encoder.is_some_and(|identity| identity != receipt.encoder) {
                return Err(refused("MJPEG encoder generation changed within the stream"));
            }
            if encoded.bytes().len() as u64 > remaining {
                return Err(refused("MJPEG encoder exceeded reserved output allowance"));
            }
            if self.writer.is_none() {
                self.writer = Some(create()?);
            }
            self.write(encoded.bytes(), check)?;
            check()?;
            self.record(input.decode_receipt, &receipt)?;
            self.encoder = Some(receipt.encoder);
            self.frames += 1;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn record(&mut self, decode_receipt: ContentDigest, receipt: &EncodeReceipt) -> io::Result<()> {
        // Fixed-width fields, display order, and an explicit domain bind every encoded frame
        // to its independently supplied, already privacy-screened luma digest.
        self.receipts.update(&(self.frames as u64).to_le_bytes());
        self.receipts.update(&decode_receipt.bytes());
        self.receipts.update(&receipt.pixel_sha256);
        self.receipts.update(&receipt.encoded_sha256);
        self.receipts.update(&receipt.encoder);
        self.receipts.update(&receipt.dimensions[0].to_le_bytes());
        self.receipts.update(&receipt.dimensions[1].to_le_bytes());
        self.receipts.update(&[receipt.quality]);
        self.receipts
            .update(&(receipt.output_bytes as u64).to_le_bytes());
        self.receipts.update(&(receipt.mcus as u64).to_le_bytes());
        self.receipts
            .update(&(receipt.entropy_blocks as u64).to_le_bytes());
        self.receipts.update(&receipt.work_units.to_le_bytes());
        self.work_units = self
            .work_units
            .checked_add(receipt.work_units)
            .ok_or_else(|| refused("MJPEG work accounting overflow"))?;
        Ok(())
    }

    fn write(
        &mut self,
        bytes: &[u8],
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut offset = 0;
        let mut interruptions = 0;
        while offset < bytes.len() {
            check()?;
            let end = (offset + WRITE_CHUNK).min(bytes.len());
            match self
                .writer
                .as_mut()
                .ok_or_else(|| refused("missing MJPEG export writer"))?
                .write(&bytes[offset..end])
            {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) if count <= end - offset => {
                    self.hash.update(&bytes[offset..offset + count]);
                    self.bytes += count as u64;
                    offset += count;
                    interruptions = 0;
                }
                Ok(_) => return Err(refused("writer exceeded supplied slice")),
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interruptions < 7 => {
                    interruptions += 1;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<(W, StreamReceipt)> {
        if self.failed || self.frames == 0 {
            return Err(refused("incomplete MJPEG export"));
        }
        check()?;
        // Reuse the identity already measured and sealed by the codec under the shared
        // work budget. Finalizing the stream performs no additional encoder-source hash.
        let encoder = self.encoder.ok_or_else(|| refused("missing MJPEG encoder identity"))?;
        let mut writer = self
            .writer
            .take()
            .ok_or_else(|| refused("missing MJPEG export writer"))?;
        writer.flush()?;
        check()?;
        let digest = |hash: Sha256Hasher| {
            hash.finalize()
                .map(|value| ContentDigest::new(DigestAlgorithm::Sha256, value))
                .map_err(|_| refused("MJPEG hash length exceeded"))
        };
        Ok((
            writer,
            StreamReceipt {
                bytes: self.bytes,
                frames: self.frames,
                digest: digest(self.hash)?,
                frame_receipts_digest: digest(self.receipts)?,
                encoder: ContentDigest::new(DigestAlgorithm::Sha256, encoder),
                quality: self.quality,
                work_units: self.work_units,
            },
        ))
    }
}
