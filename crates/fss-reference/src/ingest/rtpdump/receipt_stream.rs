#![forbid(unsafe_code)]
//! Bounded export and native re-verification of a complete retained-RTP receipt stream.
//!
//! Verification regenerates every byte from current custody; saved bytes never supply
//! configuration, allocation lengths, picture counts, or successful-decode authority.

use std::io::{self, Read, Write};

use super::recovery::RecoveredRtpImport;
use super::recovery::checked_decode::RtpCustodyDecodeLimits;
use super::recovery::checked_decode::receipt::{
    ReceiptedRtpDecodeStep, RtpFrameReceiptError, RtpFrameReceiptLimits,
};
use super::recovery::decode::{RetainedRtpDecodeRequest, RetainedRtpDecodeStats, RetainedRtpH264Frame};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, Sha256Hasher};

/// Canonical stream domain. Frame receipt encodings inside it remain unchanged.
pub const RTP_RECEIPT_STREAM_DOMAIN: &str = "fss.retained_rtp_h264_receipt_stream.v1";
const IO_CHUNK: usize = 4096;

/// Owner-selected interpretation and independent decode, custody, and encoded-output bounds.
#[derive(Clone, Copy, Debug)]
pub struct RtpReceiptStreamRequest {
    /// Exact parameters and native interpretation; never restored from untrusted saved bytes.
    pub decode: RetainedRtpDecodeRequest,
    /// Cumulative current-custody and progress allowances.
    pub custody: RtpCustodyDecodeLimits,
    /// Per-frame and cumulative canonical receipt allowances.
    pub receipts: RtpFrameReceiptLimits,
    /// Complete stream, including framing and terminal accounting (1 byte..256 MiB).
    pub max_stream_bytes: u64,
}
impl RtpReceiptStreamRequest {
    /// Existing reference bounds with a separate 32 MiB complete-stream allowance.
    pub fn new(decode: RetainedRtpDecodeRequest) -> Self {
        Self {
            decode,
            custody: RtpCustodyDecodeLimits::default(),
            receipts: RtpFrameReceiptLimits::default(),
            max_stream_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Exact accepted stream and native accounting, not a durable-publication or coverage claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpReceiptStreamSummary {
    /// SHA-256 of every accepted stream byte, including the terminal record.
    pub digest: ContentDigest,
    /// Complete encoded length, including framing.
    pub bytes: u64,
    /// Reproduced receiver/decoder interpretation.
    pub recipe: ContentDigest,
    /// Native terminal accounting, with no skipped/refused groups on success.
    pub stats: RetainedRtpDecodeStats,
    /// Point-in-time custody-read cost, separate from encoded output.
    pub custody_read_bytes: u64,
    /// Canonical frame receipt bytes, excluding stream framing.
    pub receipt_bytes: u64,
}

/// Payload-free failure; callers may retain a partial file but must not certify that prefix.
#[derive(Debug)]
pub enum RtpReceiptStreamError {
    /// Current custody, privacy, native decoding, or receipt generation failed.
    Decode(RtpFrameReceiptError),
    /// Complete native enumeration contained refusals, skipped groups, or no frames.
    Incomplete(RetainedRtpDecodeStats),
    /// The explicitly selected byte allowance could not admit the next whole record.
    Limit,
    /// Saved bytes, independent digest, or final EOF differ from native reproduction.
    Mismatch,
    /// I/O failure without disclosing a path or saved payload.
    Io(io::ErrorKind),
    /// Cancellation before another I/O or pixel-consumer boundary.
    Cancelled,
    /// Canonical encoding or hashing failed.
    Encoding,
}
impl std::fmt::Display for RtpReceiptStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RTP receipt stream refused: {self:?}")
    }
}
impl std::error::Error for RtpReceiptStreamError {}
impl From<RtpFrameReceiptError> for RtpReceiptStreamError {
    fn from(error: RtpFrameReceiptError) -> Self {
        Self::Decode(error)
    }
}
impl From<io::Error> for RtpReceiptStreamError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}
type Result<T> = std::result::Result<T, RtpReceiptStreamError>;

/// Re-decode from the inspected root and stream canonical receipts. Writes no deployment
/// state. File creation, authorization, and durable file/directory sync belong to the caller.
pub fn write_receipt_stream(
    retained: &RecoveredRtpImport,
    request: RtpReceiptStreamRequest,
    writer: &mut impl Write,
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<RtpReceiptStreamSummary> {
    write_receipt_stream_with_frames(retained, request, writer, deployment, cx, |_, _| Ok(()))
}

/// The same export with a bounded, synchronous masked-frame consumer (for example PGM output).
/// A consumer refusal stops decoding and leaves no successful stream summary or terminal record.
/// The callback sees only the existing privacy-projected frame, never raw codec output.
pub fn write_receipt_stream_with_frames(
    retained: &RecoveredRtpImport,
    request: RtpReceiptStreamRequest,
    writer: &mut impl Write,
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
    mut consume: impl FnMut(&RetainedRtpH264Frame, &ReplayCx) -> io::Result<()>,
) -> Result<RtpReceiptStreamSummary> {
    checkpoint(cx)?;
    if !(1..=256 * 1024 * 1024).contains(&request.max_stream_bytes) {
        return Err(RtpReceiptStreamError::Limit);
    }
    let mut decoder = retained.decode_h264_receipted(
        request.decode,
        request.custody,
        request.receipts,
        deployment,
        cx,
    )?;
    let mut output = Output {
        writer,
        hash: Sha256Hasher::new(),
        used: 0,
        maximum: request.max_stream_bytes,
    };
    let mut header = CanonicalEncoder::new();
    header.text(RTP_RECEIPT_STREAM_DOMAIN);
    header.u32(1);
    header.digest(retained.root());
    let header = encoded(header)?;
    let mut frames = 0_u64;
    let mut recipe = None;
    loop {
        checkpoint(cx)?;
        match decoder.step(deployment, cx)? {
            ReceiptedRtpDecodeStep::Progress { .. } => {}
            ReceiptedRtpDecodeStep::Frame { frame, receipt } => {
                if recipe.is_some_and(|old| old != receipt.recipe()) {
                    return Err(RtpReceiptStreamError::Encoding);
                }
                let mut prefix = CanonicalEncoder::new();
                prefix.u8(1);
                prefix.u64(frames);
                prefix.u64(receipt.bytes().len() as u64);
                let prefix = encoded(prefix)?;
                let first_header = if frames == 0 { header.as_slice() } else { &[] };
                output.reserve(
                    first_header.len() as u64 + prefix.len() as u64 + receipt.bytes().len() as u64,
                )?;
                checkpoint(cx)?;
                consume(&frame, cx)?;
                output.write(first_header, cx)?;
                output.write(&prefix, cx)?;
                output.write(receipt.bytes(), cx)?;
                frames += 1;
                recipe = Some(receipt.recipe());
            }
            ReceiptedRtpDecodeStep::Ended(stats) => {
                if !stats.complete() || stats.frames as u64 != frames {
                    return Err(RtpReceiptStreamError::Incomplete(stats));
                }
                let recipe = recipe.ok_or(RtpReceiptStreamError::Encoding)?;
                let mut footer = CanonicalEncoder::new();
                footer.u8(2);
                for n in [
                    stats.records,
                    stats.frames,
                    stats.refusals,
                    stats.skipped_groups,
                ] {
                    footer.u64(n as u64);
                }
                footer.bool(stats.input_ended);
                footer.bool(stats.native_finished);
                footer.bool(stats.ended);
                footer.digest(recipe);
                let footer = encoded(footer)?;
                output.reserve(footer.len() as u64)?;
                output.write(&footer, cx)?;
                checkpoint(cx)?;
                output.writer.flush()?;
                checkpoint(cx)?;
                let digest = ContentDigest::new(
                    DigestAlgorithm::Sha256,
                    output
                        .hash
                        .finalize()
                        .map_err(|_| RtpReceiptStreamError::Encoding)?,
                );
                return Ok(RtpReceiptStreamSummary {
                    digest,
                    bytes: output.used,
                    recipe,
                    stats,
                    custody_read_bytes: decoder.read_bytes(),
                    receipt_bytes: decoder.receipt_bytes(),
                });
            }
        }
    }
}

/// Verify a saved stream against fresh native reproduction and an independently supplied hash.
/// Reads at most 4 KiB at once and one final EOF probe. Saved lengths are NEVER parsed or used
/// for allocation. Truncation, trailing data, reordering, substitution, changed masks/recipes,
/// or incomplete fresh decoding cannot verify successfully. This performs no file writes.
pub fn verify_receipt_stream(
    retained: &RecoveredRtpImport,
    request: RtpReceiptStreamRequest,
    saved: &mut impl Read,
    expected: ContentDigest,
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<RtpReceiptStreamSummary> {
    checkpoint(cx)?;
    if expected.algorithm() != DigestAlgorithm::Sha256 {
        return Err(RtpReceiptStreamError::Mismatch);
    }
    let mut compare = Compare {
        reader: saved,
        cx,
        mismatch: false,
    };
    let result = write_receipt_stream(retained, request, &mut compare, deployment, cx);
    if compare.mismatch {
        return Err(RtpReceiptStreamError::Mismatch);
    }
    let summary = result?;
    if summary.digest != expected || read_once(compare.reader, &mut [0_u8; 1], cx)? != 0 {
        return Err(RtpReceiptStreamError::Mismatch);
    }
    checkpoint(cx)?;
    Ok(summary)
}

fn encoded(encoder: CanonicalEncoder) -> Result<Vec<u8>> {
    encoder
        .finish_checked()
        .map_err(|_| RtpReceiptStreamError::Encoding)
}
fn checkpoint(cx: &ReplayCx) -> Result<()> {
    cx.checkpoint("rtpdump:receipt_stream")
        .map_err(|_| RtpReceiptStreamError::Cancelled)
}
struct Output<'a, W> {
    writer: &'a mut W,
    hash: Sha256Hasher,
    used: u64,
    maximum: u64,
}
impl<W: Write> Output<'_, W> {
    fn reserve(&self, bytes: u64) -> Result<()> {
        if bytes > self.maximum.saturating_sub(self.used) {
            return Err(RtpReceiptStreamError::Limit);
        }
        Ok(())
    }
    fn write(&mut self, bytes: &[u8], cx: &ReplayCx) -> Result<()> {
        let mut remaining = bytes;
        let mut interruptions = 0;
        while !remaining.is_empty() {
            checkpoint(cx)?;
            let chunk = &remaining[..remaining.len().min(IO_CHUNK)];
            match self.writer.write(chunk) {
                Ok(0) => return Err(RtpReceiptStreamError::Io(io::ErrorKind::WriteZero)),
                Ok(n) if n <= chunk.len() => {
                    self.hash.update(&chunk[..n]);
                    self.used += n as u64;
                    remaining = &remaining[n..];
                    interruptions = 0;
                }
                Ok(_) => return Err(RtpReceiptStreamError::Io(io::ErrorKind::InvalidData)),
                Err(e) if e.kind() == io::ErrorKind::Interrupted && interruptions < 7 => {
                    interruptions += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
struct Compare<'a, R> {
    reader: &'a mut R,
    cx: &'a ReplayCx,
    mismatch: bool,
}
impl<R: Read> Write for Compare<'_, R> {
    fn write(&mut self, expected: &[u8]) -> io::Result<usize> {
        if self.mismatch {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut buffer = [0_u8; IO_CHUNK];
        let length = expected.len().min(buffer.len());
        let n = read_once(self.reader, &mut buffer[..length], self.cx)?;
        if n == 0 || buffer[..n] != expected[..n] {
            self.mismatch = true;
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn read_once(reader: &mut impl Read, buffer: &mut [u8], cx: &ReplayCx) -> io::Result<usize> {
    for attempt in 0..8 {
        cx.checkpoint("rtpdump:receipt_stream:read")
            .map_err(|_| io::Error::other("receipt verification cancelled"))?;
        match reader.read(buffer) {
            Ok(n) if n <= buffer.len() => return Ok(n),
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && attempt < 7 => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::ErrorKind::Interrupted.into())
}
