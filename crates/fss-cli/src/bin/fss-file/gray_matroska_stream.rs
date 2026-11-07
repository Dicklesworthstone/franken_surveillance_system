#![forbid(unsafe_code)]
//! Current-authority private lossless output, finalized only after owner EOF and sync.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use fss_container::matroska_gray::PlaybackRate;
use fss_reference::ReplayCx;

use super::pgm_stream::private_output::PrivateOutputPath;
#[path = "gray_matroska_stream/encoder.rs"]
mod encoder;
pub(super) use encoder::{
    DEFAULT_OUTPUT_BYTES, FRAME_RECEIPTS_DOMAIN, FrameInput, StreamReceipt, WORK_MODEL,
};
use encoder::Encoder;

fn checkpoint(cx: &ReplayCx) -> io::Result<()> {
    cx.checkpoint("file_cli:gray_matroska_export")
        .map_err(|_| io::Error::other("Matroska export cancelled"))
}

pub(super) struct MatroskaExport {
    path: PrivateOutputPath,
    encoder: Encoder<File>,
    failed: bool,
}

impl MatroskaExport {
    pub(super) fn prepare(
        path: &Path,
        root: &Path,
        maximum: u64,
        maximum_frames: usize,
        rate: PlaybackRate,
        cx: &ReplayCx,
    ) -> io::Result<Self> {
        checkpoint(cx)?;
        Ok(Self {
            path: PrivateOutputPath::prepare(path, root, cx)?,
            encoder: Encoder::new(maximum, maximum_frames, rate)?,
            failed: false,
        })
    }

    pub(super) fn frame(&mut self, input: FrameInput<'_>, cx: &ReplayCx) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("Matroska export is fenced"));
        }
        let result = (|| {
            checkpoint(cx)?;
            self.path.check(cx)?;
            self.encoder.frame(input, || self.path.create(cx), &mut || checkpoint(cx))?;
            self.path.check(cx)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub(super) fn finish(self, cx: &ReplayCx) -> io::Result<StreamReceipt> {
        checkpoint(cx)?;
        if self.failed {
            return Err(io::Error::other("Matroska export is fenced"));
        }
        self.path.check(cx)?;
        let (file, receipt) = self.encoder.finish(&mut || checkpoint(cx))?;
        checkpoint(cx)?;
        self.path.sync(&file, cx)?;
        checkpoint(cx)?;
        Ok(receipt)
    }
}

/// Report only after the runtime owner synced the complete selected output.
pub(super) fn report(receipt: StreamReceipt, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "gray_mkv_sha256={}", receipt.digest)?;
    writeln!(out, "gray_mkv_bytes={}", receipt.bytes)?;
    writeln!(out, "gray_mkv_frames={}", receipt.frames)?;
    writeln!(out, "gray_mkv_frame_receipts_sha256={}", receipt.frame_receipts_digest)?;
    writeln!(out, "gray_mkv_frame_receipts_domain={FRAME_RECEIPTS_DOMAIN}")?;
    writeln!(out, "gray_mkv_encoder_identity={}", receipt.encoder)?;
    writeln!(out, "gray_mkv_width={}", receipt.dimensions[0])?;
    writeln!(out, "gray_mkv_height={}", receipt.dimensions[1])?;
    writeln!(out, "gray_mkv_rate_numerator={}", receipt.rate.numerator())?;
    writeln!(out, "gray_mkv_rate_denominator={}", receipt.rate.denominator())?;
    writeln!(out, "gray_mkv_duration_ns={}", receipt.duration_ns)?;
    writeln!(out, "gray_mkv_hashed_bytes={}", receipt.hashed_bytes)?;
    writeln!(out, "gray_mkv_work_unit_model={WORK_MODEL}")?;
    writeln!(out, "gray_mkv_pixel_format=grayscale_luma")?;
    writeln!(out, "gray_mkv_lossy=false")?;
    writeln!(out, "gray_mkv_exact_luma_preserved=true")?;
    writeln!(out, "gray_mkv_timing=operator_requested_uniform_rate")?;
    writeln!(out, "gray_mkv_source_capture_timing_preserved=false")?;
    writeln!(out, "gray_mkv_published=false")?;
    writeln!(out, "gray_mkv_export_complete=true")?;
    Ok(())
}
