#![forbid(unsafe_code)]
//! Current-authority private MJPEG output over the independently testable streaming core.

use std::fs::File;
use std::io;
use std::path::Path;

use fss_codec_jpeg_encode::EncodeBudget;
use fss_reference::ReplayCx;

use super::pgm_stream::private_output::PrivateOutputPath;
#[path = "jpeg_stream/encoder.rs"]
mod encoder;
pub(super) use encoder::{
    DEFAULT_ENCODE_WORK_UNITS, DEFAULT_OUTPUT_BYTES, DEFAULT_QUALITY, FRAME_RECEIPTS_DOMAIN,
    FrameInput, StreamReceipt,
};
use encoder::Encoder;

fn checkpoint(cx: &ReplayCx) -> io::Result<()> {
    cx.checkpoint("file_cli:mjpeg_export")
        .map_err(|_| io::Error::other("MJPEG export cancelled"))
}

pub(super) struct JpegExport {
    path: PrivateOutputPath,
    encoder: Encoder<File>,
    failed: bool,
}

impl JpegExport {
    pub(super) fn prepare(
        path: &Path,
        root: &Path,
        maximum: u64,
        maximum_frames: usize,
        quality: u8,
        cx: &ReplayCx,
    ) -> io::Result<Self> {
        checkpoint(cx)?;
        let encoder = Encoder::new(maximum, maximum_frames, quality)?;
        Ok(Self {
            path: PrivateOutputPath::prepare(path, root, cx)?,
            encoder,
            failed: false,
        })
    }

    pub(super) fn frame(
        &mut self,
        input: FrameInput<'_>,
        budget: &mut EncodeBudget<'_>,
        cx: &ReplayCx,
    ) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("MJPEG export is fenced"));
        }
        let result = (|| {
            checkpoint(cx)?;
            self.path.check(cx)?;
            self.encoder.frame(
                input,
                budget,
                || self.path.create(cx),
                &mut || checkpoint(cx),
            )?;
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
            return Err(io::Error::other("MJPEG export is fenced"));
        }
        self.path.check(cx)?;
        let (file, receipt) = self.encoder.finish(&mut || checkpoint(cx))?;
        checkpoint(cx)?;
        self.path.sync(&file, cx)?;
        checkpoint(cx)?;
        Ok(receipt)
    }
}
