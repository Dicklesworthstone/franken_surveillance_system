#![forbid(unsafe_code)]
//! Bounded lossless Matroska output. The caller owns the sink and all checkpoints.
//!
//! Payloads are borrowed, tightly packed screened luma. The only stored media state is
//! a fixed-size container configuration and two running hashes. File durability and
//! successful source EOF belong to the runtime adapter, not this synchronous core.

use std::io::{self, Write};

use fss_container::matroska_gray::{GrayMatroskaConfig, PlaybackRate};
use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};

pub(crate) const DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const FRAME_RECEIPTS_DOMAIN: &str = "fss.file_gray_matroska_frame_receipts.v1";
pub(crate) const ENCODER_IDENTITY_DOMAIN: &str = "fss.file_gray_matroska_encoder.v1";
pub(crate) const WORK_MODEL: &str = "logical_sha256_input_bytes";
const WRITE_CHUNK: usize = 4096;
const IMPLEMENTATION_PARTS: [&[u8]; 3] = [
    include_bytes!("encoder.rs"),
    include_bytes!("../../../../../fss-container/src/matroska_gray.rs"),
    include_bytes!("../../../../../fss-container/src/matroska_gray/ebml.rs"),
];

fn refused(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn digest(hash: Sha256Hasher) -> io::Result<ContentDigest> {
    hash.finalize()
        .map(|bytes| ContentDigest::new(DigestAlgorithm::Sha256, bytes))
        .map_err(|_| refused("Matroska hash length exceeded"))
}

fn valid_pin(pin: ContentDigest) -> bool {
    pin.algorithm() == DigestAlgorithm::Sha256
        && !pin.is_laboratory()
        && pin.bytes() != [0; 32]
}

pub(crate) struct FrameInput<'a> {
    pub dimensions: [u32; 2],
    pub pixels: &'a [u8],
    pub luma_sha256: [u8; 32],
    pub decode_receipt: ContentDigest,
}

/// Exact written bytes and ordered derivation; no custody or source-clock authority.
#[derive(Debug)]
pub(crate) struct StreamReceipt {
    pub bytes: u64,
    pub frames: usize,
    pub digest: ContentDigest,
    pub frame_receipts_digest: ContentDigest,
    pub encoder: ContentDigest,
    pub dimensions: [u32; 2],
    pub rate: PlaybackRate,
    pub duration_ns: u64,
    pub hashed_bytes: u64,
}

/// A byte ceiling also bounds linear hashing and output work; no refill or frame buffer.
pub(crate) struct Encoder<W> {
    writer: Option<W>,
    config: Option<GrayMatroskaConfig>,
    rate: PlaybackRate,
    encoder: Option<ContentDigest>,
    hash: Sha256Hasher,
    receipts: Sha256Hasher,
    maximum: u64,
    maximum_frames: usize,
    bytes: u64,
    frames: usize,
    duration_ns: u64,
    hashed_bytes: u64,
    failed: bool,
}

impl<W: Write> Encoder<W> {
    pub(crate) fn new(
        maximum: u64,
        maximum_frames: usize,
        rate: PlaybackRate,
    ) -> io::Result<Self> {
        if maximum == 0 || maximum > MAX_OUTPUT_BYTES || !(1..=1024).contains(&maximum_frames) {
            return Err(refused("invalid Matroska export allowance"));
        }
        let mut receipts = Sha256Hasher::new();
        receipts.update(FRAME_RECEIPTS_DOMAIN.as_bytes());
        receipts.update(&[0]);
        Ok(Self {
            writer: None,
            config: None,
            rate,
            encoder: None,
            hash: Sha256Hasher::new(),
            receipts,
            maximum,
            maximum_frames,
            bytes: 0,
            frames: 0,
            duration_ns: 0,
            hashed_bytes: FRAME_RECEIPTS_DOMAIN.len() as u64 + 1,
            failed: false,
        })
    }

    pub(crate) fn frame(
        &mut self,
        input: FrameInput<'_>,
        create: impl FnOnce() -> io::Result<W>,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.failed {
            return Err(refused("Matroska export fenced after an earlier refusal"));
        }
        let result = self.frame_inner(input, create, check);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn frame_inner(
        &mut self,
        input: FrameInput<'_>,
        create: impl FnOnce() -> io::Result<W>,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        if self.frames >= self.maximum_frames || !valid_pin(input.decode_receipt) {
            return Err(refused("Matroska frame allowance or source receipt refused"));
        }
        let config = GrayMatroskaConfig::new(input.dimensions, self.rate)
            .map_err(io::Error::other)?;
        if self.config.as_ref().is_some_and(|prior| prior.dimensions() != input.dimensions) {
            return Err(refused("Matroska dimensions changed within the stream"));
        }
        let framing = config.frame(self.frames as u64).map_err(io::Error::other)?;
        if input.pixels.len() != framing.payload_bytes() {
            return Err(refused("Matroska luma length mismatch"));
        }
        let initialization = if self.frames == 0 {
            Some(config.initialization().map_err(io::Error::other)?)
        } else {
            None
        };
        let initialization_bytes = initialization.as_ref().map_or(0, |header| header.bytes().len());
        let additional = initialization_bytes
            .checked_add(framing.prefix().len())
            .and_then(|bytes| bytes.checked_add(input.pixels.len()))
            .ok_or_else(|| refused("Matroska output length overflow"))?;
        if additional as u64 > self.maximum.saturating_sub(self.bytes) {
            return Err(refused("Matroska export byte allowance exceeded"));
        }
        // Reserve the complete frame before hashing its input or creating any output.
        let mut pixels = Sha256Hasher::new();
        for chunk in input.pixels.chunks(WRITE_CHUNK) {
            check()?;
            pixels.update(chunk);
            self.charge_hash(chunk.len())?;
        }
        if digest(pixels)?.bytes() != input.luma_sha256 {
            return Err(refused("Matroska luma does not match its independent pin"));
        }
        if self.encoder.is_none() {
            let identity = self.implementation_identity(check)?;
            self.lineage(&identity.bytes())?;
            self.lineage(&self.rate.numerator().to_le_bytes())?;
            self.lineage(&self.rate.denominator().to_le_bytes())?;
            self.lineage(&input.dimensions[0].to_le_bytes())?;
            self.lineage(&input.dimensions[1].to_le_bytes())?;
            self.encoder = Some(identity);
        }
        check()?;
        if self.writer.is_none() {
            self.writer = Some(create()?);
        }
        if let Some(initialization) = initialization {
            self.write(initialization.bytes(), check)?;
        }
        self.write(framing.prefix(), check)?;
        self.write(input.pixels, check)?;
        check()?;
        self.lineage(&(self.frames as u64).to_le_bytes())?;
        self.lineage(&input.decode_receipt.bytes())?;
        self.lineage(&input.luma_sha256)?;
        self.lineage(&(input.pixels.len() as u64).to_le_bytes())?;
        self.lineage(&framing.timestamp_ns().to_le_bytes())?;
        self.lineage(&framing.duration_ns().to_le_bytes())?;
        self.duration_ns = framing.end_ns();
        self.config = Some(config);
        self.frames += 1;
        Ok(())
    }

    fn charge_hash(&mut self, bytes: usize) -> io::Result<()> {
        self.hashed_bytes = self.hashed_bytes.checked_add(bytes as u64)
            .ok_or_else(|| refused("Matroska hash accounting overflow"))?;
        Ok(())
    }

    fn lineage(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.receipts.update(bytes);
        self.charge_hash(bytes.len())
    }

    fn implementation_identity(
        &mut self,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<ContentDigest> {
        let mut identity = Sha256Hasher::new();
        identity.update(ENCODER_IDENTITY_DOMAIN.as_bytes());
        identity.update(&[0]);
        self.charge_hash(ENCODER_IDENTITY_DOMAIN.len() + 1)?;
        for source in IMPLEMENTATION_PARTS {
            identity.update(&(source.len() as u64).to_le_bytes());
            self.charge_hash(8)?;
            for chunk in source.chunks(WRITE_CHUNK) {
                check()?;
                identity.update(chunk);
                self.charge_hash(chunk.len())?;
            }
        }
        digest(identity)
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
            match self.writer.as_mut()
                .ok_or_else(|| refused("missing Matroska output writer"))?
                .write(&bytes[offset..end])
            {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) if count <= end - offset => {
                    self.hash.update(&bytes[offset..offset + count]);
                    self.charge_hash(count)?;
                    self.bytes += count as u64;
                    offset += count;
                    interruptions = 0;
                }
                Ok(_) => return Err(refused("writer exceeded supplied Matroska slice")),
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
            return Err(refused("incomplete Matroska export"));
        }
        check()?;
        let encoder = self.encoder.ok_or_else(|| refused("missing Matroska encoder identity"))?;
        let dimensions = self.config.as_ref()
            .ok_or_else(|| refused("missing Matroska configuration"))?.dimensions();
        let mut writer = self.writer.take().ok_or_else(|| refused("missing Matroska output"))?;
        writer.flush()?;
        check()?;
        let stream_digest = digest(std::mem::replace(&mut self.hash, Sha256Hasher::new()))?;
        self.lineage(&[0xff])?;
        self.lineage(&(self.frames as u64).to_le_bytes())?;
        self.lineage(&self.bytes.to_le_bytes())?;
        self.lineage(&self.duration_ns.to_le_bytes())?;
        self.lineage(&stream_digest.bytes())?;
        let complete_hash_work = self.hashed_bytes.checked_add(8)
            .ok_or_else(|| refused("Matroska hash accounting overflow"))?;
        self.lineage(&complete_hash_work.to_le_bytes())?;
        Ok((writer, StreamReceipt {
            bytes: self.bytes,
            frames: self.frames,
            digest: stream_digest,
            frame_receipts_digest: digest(self.receipts)?,
            encoder,
            dimensions,
            rate: self.rate,
            duration_ns: self.duration_ns,
            hashed_bytes: self.hashed_bytes,
        }))
    }
}
