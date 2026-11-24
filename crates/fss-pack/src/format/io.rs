#![forbid(unsafe_code)]
//! Bounded safe filesystem I/O helpers (`write_all_bounded`, positional `pread`, and `sync_dir`).

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use crate::error::{PackError, PackIoOperation};
use crate::format::{DurabilityMode, MAX_INTERRUPTED_ATTEMPTS};

/// Writes `buf` completely using a bounded `EINTR` retry loop (no unbounded retries).
pub fn write_all_bounded(file: &mut File, mut buf: &[u8]) -> Result<(), PackError> {
    let mut consecutive_interrupted = 0_u32;
    while !buf.is_empty() {
        match file.write(buf) {
            Ok(0) => {
                return Err(PackError::io(
                    PackIoOperation::Write,
                    io::Error::new(io::ErrorKind::WriteZero, "write returned 0 bytes"),
                ));
            }
            Ok(n) => {
                consecutive_interrupted = 0;
                buf = &buf[n..];
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                consecutive_interrupted += 1;
                if consecutive_interrupted >= MAX_INTERRUPTED_ATTEMPTS {
                    return Err(PackError::InterruptedRetryExhausted {
                        operation: PackIoOperation::Write,
                        attempts: MAX_INTERRUPTED_ATTEMPTS,
                    });
                }
            }
            Err(err) => return Err(PackError::io(PackIoOperation::Write, err)),
        }
    }
    Ok(())
}

/// Reads exactly `buf.len()` bytes at positional `offset` using `pread` on Unix (lock-free).
#[cfg(unix)]
pub fn read_exact_at_bounded(
    file: &File,
    mut offset: u64,
    mut buf: &mut [u8],
) -> Result<(), PackError> {
    use std::os::unix::fs::FileExt;
    let mut consecutive_interrupted = 0_u32;
    while !buf.is_empty() {
        match file.read_at(buf, offset) {
            Ok(0) => {
                return Err(PackError::io(
                    PackIoOperation::Read,
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF in positional read",
                    ),
                ));
            }
            Ok(n) => {
                consecutive_interrupted = 0;
                offset = offset
                    .checked_add(n as u64)
                    .ok_or(PackError::ArithmeticOverflow)?;
                buf = &mut buf[n..];
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                consecutive_interrupted += 1;
                if consecutive_interrupted >= MAX_INTERRUPTED_ATTEMPTS {
                    return Err(PackError::InterruptedRetryExhausted {
                        operation: PackIoOperation::Read,
                        attempts: MAX_INTERRUPTED_ATTEMPTS,
                    });
                }
            }
            Err(err) => return Err(PackError::io(PackIoOperation::Read, err)),
        }
    }
    Ok(())
}

/// Fallback positional read for non-Unix targets.
#[cfg(not(unix))]
pub fn read_exact_at_bounded(file: &File, offset: u64, buf: &mut [u8]) -> Result<(), PackError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut handle = file
        .try_clone()
        .map_err(|err| PackError::io(PackIoOperation::Read, err))?;
    handle
        .seek(SeekFrom::Start(offset))
        .map_err(|err| PackError::io(PackIoOperation::Read, err))?;
    let mut remaining = buf;
    let mut consecutive_interrupted = 0_u32;
    while !remaining.is_empty() {
        match handle.read(remaining) {
            Ok(0) => {
                return Err(PackError::io(
                    PackIoOperation::Read,
                    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF in read"),
                ));
            }
            Ok(n) => {
                consecutive_interrupted = 0;
                remaining = &mut remaining[n..];
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                consecutive_interrupted += 1;
                if consecutive_interrupted >= MAX_INTERRUPTED_ATTEMPTS {
                    return Err(PackError::InterruptedRetryExhausted {
                        operation: PackIoOperation::Read,
                        attempts: MAX_INTERRUPTED_ATTEMPTS,
                    });
                }
            }
            Err(err) => return Err(PackError::io(PackIoOperation::Read, err)),
        }
    }
    Ok(())
}

/// Syncs a directory descriptor to persist file creations and atomic renames using `durability`.
pub fn sync_dir(path: &Path, durability: DurabilityMode) -> Result<(), PackError> {
    #[cfg(unix)]
    {
        let dir = File::open(path).map_err(|err| PackError::io(PackIoOperation::SyncDir, err))?;
        let res = match durability {
            DurabilityMode::Fsync => dir.sync_data(),
            DurabilityMode::FullSync => dir.sync_all(),
        };
        res.map_err(|err| PackError::io(PackIoOperation::SyncDir, err))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, durability);
    }
    Ok(())
}
