#![forbid(unsafe_code)]
//! Request-owned PGM output. No range-sized pixel buffer, overwrite, or implicit publication.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};
use fss_reference::ReplayCx;

#[path = "private_output.rs"]
pub(super) mod private_output;
use private_output::PrivateOutputPath;

pub(super) const DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;
const WRITE_CHUNK: usize = 4096;

fn refused(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn checkpoint(cx: &ReplayCx) -> io::Result<()> {
    cx.checkpoint("file_cli:video_export")
        .map_err(|_| refused("video export cancelled"))
}

/// Exact bytes accepted by the writer. Not a media publication or a capture certificate.
pub(super) struct ExportReceipt {
    pub bytes: u64,
    pub frames: usize,
    pub digest: ContentDigest,
}

// Independently testable streaming encoder. An ignored refusal cannot certify a shorter prefix.
struct Encoder<W> {
    writer: W,
    hash: Sha256Hasher,
    maximum: u64,
    maximum_frames: usize,
    bytes: u64,
    frames: usize,
    failed: bool,
}

fn quote(dimensions: [u32; 2], pixels: &[u8]) -> io::Result<(String, u64)> {
    let [width, height] = dimensions;
    let count = u64::from(width) * u64::from(height);
    if width == 0
        || height == 0
        || width > 4096
        || height > 4096
        || count > 4_194_304
        || count != pixels.len() as u64
    {
        return Err(refused("invalid bounded video luma plane"));
    }
    let header = format!("P5\n{width} {height}\n255\n");
    let bytes = count
        .checked_add(header.len() as u64)
        .ok_or_else(|| refused("PGM byte count overflow"))?;
    Ok((header, bytes))
}

impl<W: Write> Encoder<W> {
    fn new(writer: W, maximum: u64, maximum_frames: usize) -> Self {
        Self {
            writer,
            hash: Sha256Hasher::new(),
            maximum,
            maximum_frames,
            bytes: 0,
            frames: 0,
            failed: false,
        }
    }

    fn frame(
        &mut self,
        dimensions: [u32; 2],
        pixels: &[u8],
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.failed {
            return Err(refused("video export fenced after an earlier refusal"));
        }
        let result = (|| {
            check()?;
            let (header, bytes) = quote(dimensions, pixels)?;
            // Reserve a WHOLE frame before its header is written. Byte-limit failures therefore
            // leave complete earlier frames, while genuine I/O failures may leave a partial frame.
            if self.frames >= self.maximum_frames || bytes > self.maximum.saturating_sub(self.bytes)
            {
                return Err(refused("video export byte or frame allowance exceeded"));
            }
            self.write(header.as_bytes(), check)?;
            self.write(pixels, check)?;
            self.frames += 1;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
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
            match self.writer.write(&bytes[offset..end]) {
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

    fn finish(
        mut self,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<(W, ExportReceipt)> {
        if self.failed || self.frames == 0 {
            return Err(refused("incomplete video export"));
        }
        check()?;
        self.writer.flush()?;
        let hash = self
            .hash
            .finalize()
            .map_err(|_| refused("PGM hash length exceeded"))?;
        Ok((
            self.writer,
            ExportReceipt {
                bytes: self.bytes,
                frames: self.frames,
                digest: ContentDigest::new(DigestAlgorithm::Sha256, hash),
            },
        ))
    }
}

/// Prepared path admission; the output file is created only after a whole first frame fits.
/// Linux pins the parent directory for creation. Other targets retain the existing protected
/// directory trust boundary and recheck the canonical parent before/after opening and writing.
pub(super) struct PgmExport {
    path: PrivateOutputPath,
    encoder: Option<Encoder<File>>,
    maximum: u64,
    maximum_frames: usize,
    failed: bool,
}

impl PgmExport {
    pub(super) fn prepare(
        path: &Path,
        root: &Path,
        maximum: u64,
        maximum_frames: usize,
        cx: &ReplayCx,
    ) -> io::Result<Self> {
        checkpoint(cx)?;
        if maximum == 0 || maximum > MAX_OUTPUT_BYTES || !(1..=1024).contains(&maximum_frames) {
            return Err(refused("invalid video export allowance"));
        }
        Ok(Self {
            path: PrivateOutputPath::prepare(path, root, cx)?,
            encoder: None,
            maximum,
            maximum_frames,
            failed: false,
        })
    }

    pub(super) fn frame(
        &mut self,
        dimensions: [u32; 2],
        pixels: &[u8],
        cx: &ReplayCx,
    ) -> io::Result<()> {
        if self.failed {
            return Err(refused("video export is fenced"));
        }
        let result = (|| {
            checkpoint(cx)?;
            self.path.check(cx)?;
            if self.encoder.is_none() {
                let (_, bytes) = quote(dimensions, pixels)?;
                if bytes > self.maximum {
                    return Err(refused("video export byte allowance exceeded"));
                }
                self.encoder = Some(Encoder::new(
                    self.path.create(cx)?,
                    self.maximum,
                    self.maximum_frames,
                ));
            }
            self.encoder
                .as_mut()
                .ok_or_else(|| refused("missing video export writer"))?
                .frame(dimensions, pixels, &mut || checkpoint(cx))?;
            self.path.check(cx)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub(super) fn finish(mut self, cx: &ReplayCx) -> io::Result<ExportReceipt> {
        checkpoint(cx)?;
        if self.failed {
            return Err(refused("video export is fenced"));
        }
        self.path.check(cx)?;
        let encoder = self
            .encoder
            .take()
            .ok_or_else(|| refused("no complete video output"))?;
        let (file, receipt) = encoder.finish(&mut || checkpoint(cx))?;
        checkpoint(cx)?;
        self.path.sync(&file, cx)?;
        checkpoint(cx)?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct ShortWriter {
        bytes: Vec<u8>,
        calls: usize,
        largest: usize,
        limit: Option<usize>,
    }
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            self.largest = self.largest.max(bytes.len());
            if self.limit.is_some_and(|limit| self.bytes.len() >= limit) {
                return Err(refused("injected write failure"));
            }
            let count = bytes
                .len()
                .min(29)
                .min(self.limit.map_or(usize::MAX, |n| n - self.bytes.len()));
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_writes_produce_exact_display_stream_and_incremental_digest() -> io::Result<()> {
        let pixels = vec![17; 128 * 128];
        let mut encoder = Encoder::new(ShortWriter::default(), MAX_OUTPUT_BYTES, 2);
        encoder.frame([128, 128], &pixels, &mut || Ok(()))?;
        encoder.frame([3, 1], &[1, 2, 3], &mut || Ok(()))?;
        let (writer, receipt) = encoder.finish(&mut || Ok(()))?;
        let expected = [
            b"P5\n128 128\n255\n".as_slice(),
            &pixels,
            b"P5\n3 1\n255\n",
            &[1, 2, 3],
        ]
        .concat();
        assert_eq!(writer.bytes, expected);
        assert_eq!(receipt.bytes, expected.len() as u64);
        assert_eq!(receipt.digest, ContentDigest::sha256(&expected));
        assert_eq!(receipt.frames, 2);
        assert!(writer.calls > 100);
        assert!(writer.largest <= WRITE_CHUNK);
        Ok(())
    }

    #[test]
    fn whole_frame_budget_reservation_and_terminal_refusal() -> io::Result<()> {
        let mut encoder = Encoder::new(ShortWriter::default(), 12, 2);
        encoder.frame([1, 1], &[7], &mut || Ok(()))?;
        let before = encoder.writer.bytes.clone();
        assert!(encoder.frame([1, 1], &[8], &mut || Ok(())).is_err());
        assert_eq!(encoder.writer.bytes, before);
        assert!(encoder.frame([1, 1], &[7], &mut || Ok(())).is_err());
        assert!(encoder.finish(&mut || Ok(())).is_err());
        Ok(())
    }

    #[test]
    fn partial_io_failure_never_becomes_a_complete_prefix() {
        let mut encoder = Encoder::new(
            ShortWriter {
                limit: Some(20),
                ..ShortWriter::default()
            },
            100,
            2,
        );
        assert!(encoder.frame([8, 8], &[19; 64], &mut || Ok(())).is_err());
        assert_eq!(encoder.writer.bytes.len(), 20);
        assert_eq!(encoder.frames, 0);
        assert!(encoder.finish(&mut || Ok(())).is_err());
    }

    #[test]
    fn cancellation_is_checked_between_bounded_writes() {
        let mut checks = 0;
        let mut encoder = Encoder::new(ShortWriter::default(), 100_000, 1);
        assert!(
            encoder
                .frame([128, 128], &[5; 16384], &mut || {
                    checks += 1;
                    if checks == 4 {
                        Err(refused("cancelled"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert_eq!(checks, 4);
        assert!(encoder.writer.bytes.len() < 16384);
        assert!(encoder.finish(&mut || Ok(())).is_err());
    }

    #[test]
    fn malformed_dimensions_and_frame_count_refuse_before_new_bytes() -> io::Result<()> {
        for (dimensions, pixels) in [([0, 1], &[][..]), ([1, 1], &[][..]), ([4097, 1], &[][..])] {
            let mut encoder = Encoder::new(ShortWriter::default(), 100, 1);
            assert!(encoder.frame(dimensions, pixels, &mut || Ok(())).is_err());
            assert!(encoder.writer.bytes.is_empty());
        }
        let mut encoder = Encoder::new(ShortWriter::default(), 100, 1);
        encoder.frame([1, 1], &[1], &mut || Ok(()))?;
        assert!(encoder.frame([1, 1], &[1], &mut || Ok(())).is_err());
        assert_eq!(encoder.writer.bytes.len(), 12);
        Ok(())
    }

    #[test]
    fn zero_progress_and_repeated_interruptions_are_bounded() {
        struct Broken {
            calls: usize,
            interrupted: bool,
        }
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.interrupted {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(0)
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        for interrupted in [false, true] {
            let mut encoder = Encoder::new(
                Broken {
                    calls: 0,
                    interrupted,
                },
                100,
                1,
            );
            assert!(encoder.frame([1, 1], &[1], &mut || Ok(())).is_err());
            assert_eq!(encoder.writer.calls, if interrupted { 8 } else { 1 });
            assert!(encoder.finish(&mut || Ok(())).is_err());
        }
    }
}
