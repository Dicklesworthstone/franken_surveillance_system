#![forbid(unsafe_code)]
//! Launcher-owned stdio descriptors for the bounded MCP transport.
//!
//! Pipe and terminal I/O returns `WouldBlock` instead of waiting for a peer. The
//! controller owns all retries, including `Interrupted`, framing and deadlines.
//! Regular redirected files retain ordinary file I/O semantics: `O_NONBLOCK`
//! does not make a storage syscall preemptible. No worker or runtime is created.

use std::io::{self, Read, Write};

#[cfg(unix)]
use std::{
    os::fd::{AsFd, OwnedFd},
    sync::Arc,
};

#[cfg(unix)]
use nix::fcntl::{FcntlArg, OFlag, fcntl};

pub(super) struct Stdio {
    input: Input,
    output: Output,
}

pub(super) struct Input {
    #[cfg(unix)]
    lease: Arc<DescriptorLease>,
}

pub(super) struct Output {
    #[cfg(unix)]
    lease: Arc<DescriptorLease>,
}

impl Stdio {
    /// Clone the launcher's descriptors without taking ownership of fd 0 or 1.
    /// The launching process must exclusively own stdio while this lease lives:
    /// duplicated descriptors share file-status flags with their originals.
    pub(super) fn open() -> io::Result<Self> {
        #[cfg(unix)]
        {
            let input = io::stdin().as_fd().try_clone_to_owned()?;
            let output = io::stdout().as_fd().try_clone_to_owned()?;
            Self::from_owned_fds(input, output)
        }
        #[cfg(not(unix))]
        {
            Err(unsupported())
        }
    }

    /// Both halves retain the shared flag-restoration lease. Dropping one must
    /// not make a surviving half blocking, even if stdin and stdout alias the
    /// same underlying open file description.
    pub(super) fn split(self) -> (Input, Output) {
        (self.input, self.output)
    }

    #[cfg(unix)]
    fn from_owned_fds(input: OwnedFd, output: OwnedFd) -> io::Result<Self> {
        // Sample both originals before changing either: stdin and stdout may
        // be duplicates of the same duplex descriptor.
        let input_flags = flags(&input)?;
        let output_flags = flags(&output)?;
        let mut lease = DescriptorLease {
            input,
            output,
            input_flags,
            output_flags,
            input_changed: false,
            output_changed: false,
        };
        if !input_flags.contains(OFlag::O_NONBLOCK) {
            set_flags(&lease.input, input_flags | OFlag::O_NONBLOCK)?;
            lease.input_changed = true;
        }
        if !output_flags.contains(OFlag::O_NONBLOCK) {
            // On failure, the lease restores any successful input change.
            set_flags(&lease.output, output_flags | OFlag::O_NONBLOCK)?;
            lease.output_changed = true;
        }
        let lease = Arc::new(lease);
        Ok(Self {
            input: Input {
                lease: Arc::clone(&lease),
            },
            output: Output { lease },
        })
    }
}

#[cfg(unix)]
struct DescriptorLease {
    input: OwnedFd,
    output: OwnedFd,
    input_flags: OFlag,
    output_flags: OFlag,
    input_changed: bool,
    output_changed: bool,
}

#[cfg(unix)]
impl Drop for DescriptorLease {
    fn drop(&mut self) {
        // The owned descriptors remain valid during restoration. Drop cannot
        // report an OS refusal; it makes one bounded restoration attempt for
        // each changed descriptor, without hiding an unbounded EINTR loop.
        if self.output_changed {
            let _ = set_flags(&self.output, self.output_flags);
        }
        if self.input_changed {
            let _ = set_flags(&self.input, self.input_flags);
        }
    }
}

#[cfg(unix)]
fn flags(fd: &OwnedFd) -> io::Result<OFlag> {
    fcntl(fd, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_retain)
        .map_err(io::Error::from)
}

#[cfg(unix)]
fn set_flags(fd: &OwnedFd, flags: OFlag) -> io::Result<()> {
    fcntl(fd, FcntlArg::F_SETFL(flags))
        .map(|_| ())
        .map_err(io::Error::from)
}

impl Read for Input {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            nix::unistd::read(&self.lease.input, buffer).map_err(io::Error::from)
        }
        #[cfg(not(unix))]
        {
            let _ = buffer;
            Err(unsupported())
        }
    }
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            nix::unistd::write(&self.lease.output, bytes).map_err(io::Error::from)
        }
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(unsupported())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // There is no userspace buffer. The transport retains every partial
        // frame until the corresponding write calls have accepted all bytes.
        Ok(())
    }
}

#[cfg(not(unix))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "nonblocking MCP stdio is unavailable on this platform",
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs::OpenOptions,
        os::unix::net::UnixStream,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    type Test = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn empty_and_full_pipes_return_would_block_without_losing_bytes() -> Test {
        let (read_fd, write_fd) = nix::unistd::pipe()?;
        let (mut input, mut output) = Stdio::from_owned_fds(read_fd, write_fd)?.split();
        let mut buffer = [0_u8; 16 * 1024];
        let empty = input
            .read(&mut buffer)
            .err()
            .ok_or("empty pipe unexpectedly returned bytes")?;
        assert_eq!(empty.kind(), io::ErrorKind::WouldBlock);
        let payload = [0xa5_u8; 16 * 1024];
        let mut written = 0;
        let mut blocked = false;
        for _ in 0..1024 {
            match output.write(&payload) {
                Ok(count) => {
                    assert!(count > 0);
                    written += count;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert!(blocked, "pipe did not reach the bounded pressure fixture");
        output.flush()?;
        let mut received = 0;
        while received < written {
            let count = input.read(&mut buffer)?;
            assert!(count > 0);
            assert!(buffer[..count].iter().all(|byte| *byte == 0xa5));
            received += count;
        }
        assert_eq!(received, written);
        assert_eq!(output.write(b"after pressure")?, 14);
        assert_eq!(input.read(&mut buffer)?, 14);
        assert_eq!(&buffer[..14], b"after pressure");
        Ok(())
    }

    #[test]
    fn flags_restore_only_after_both_halves_retire() -> Test {
        let (read_fd, write_fd) = nix::unistd::pipe()?;
        let originals = (flags(&read_fd)?, flags(&write_fd)?);
        let (input, output) = Stdio::from_owned_fds(
            read_fd.as_fd().try_clone_to_owned()?,
            write_fd.as_fd().try_clone_to_owned()?,
        )?
        .split();
        assert!(flags(&read_fd)?.contains(OFlag::O_NONBLOCK));
        assert!(flags(&write_fd)?.contains(OFlag::O_NONBLOCK));
        drop(input);
        assert!(flags(&read_fd)?.contains(OFlag::O_NONBLOCK));
        assert!(flags(&write_fd)?.contains(OFlag::O_NONBLOCK));
        drop(output);
        assert_eq!((flags(&read_fd)?, flags(&write_fd)?), originals);
        Ok(())
    }

    #[test]
    fn aliased_duplex_descriptors_preserve_the_true_original_flags() -> Test {
        let (endpoint, mut peer) = UnixStream::pair()?;
        peer.set_read_timeout(Some(Duration::from_secs(1)))?;
        let witness = endpoint.as_fd().try_clone_to_owned()?;
        let original = flags(&witness)?;
        let (input, mut output) = Stdio::from_owned_fds(
            endpoint.as_fd().try_clone_to_owned()?,
            endpoint.as_fd().try_clone_to_owned()?,
        )?
        .split();
        drop(input);
        assert!(flags(&witness)?.contains(OFlag::O_NONBLOCK));
        assert_eq!(output.write(b"still owned")?, 11);
        let mut bytes = [0_u8; 11];
        peer.read_exact(&mut bytes)?;
        assert_eq!(&bytes, b"still owned");
        drop(output);
        assert_eq!(flags(&witness)?, original);
        Ok(())
    }

    #[test]
    fn already_nonblocking_descriptors_keep_their_flags() -> Test {
        let (read_fd, write_fd) = nix::unistd::pipe()?;
        set_flags(&read_fd, flags(&read_fd)? | OFlag::O_NONBLOCK)?;
        set_flags(&write_fd, flags(&write_fd)? | OFlag::O_NONBLOCK)?;
        let originals = (flags(&read_fd)?, flags(&write_fd)?);
        let io = Stdio::from_owned_fds(
            read_fd.as_fd().try_clone_to_owned()?,
            write_fd.as_fd().try_clone_to_owned()?,
        )?;
        drop(io);
        assert_eq!((flags(&read_fd)?, flags(&write_fd)?), originals);
        Ok(())
    }

    #[test]
    fn redirected_regular_files_keep_exact_bytes_and_eof() -> Test {
        let path = std::env::temp_dir().join(format!(
            "fss-mcp-stdio-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        ));
        struct Remove(std::path::PathBuf);
        impl Drop for Remove {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let _remove = Remove(path.clone());
        let input = std::fs::File::open(&path)?;
        let (mut input, mut output) = Stdio::from_owned_fds(input.into(), output.into())?.split();
        output.write_all(b"one\ntwo\n")?;
        output.flush()?;
        let mut bytes = [0_u8; 16];
        assert_eq!(input.read(&mut bytes)?, 8);
        assert_eq!(&bytes[..8], b"one\ntwo\n");
        assert_eq!(input.read(&mut bytes)?, 0);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn output_flag_refusal_restores_the_input_change() -> Test {
        let (read_fd, _write_fd) = nix::unistd::pipe()?;
        let original = flags(&read_fd)?;
        // O_PATH admits F_GETFL but refuses F_SETFL. No processwide standard
        // descriptor is changed while exercising constructor rollback.
        let path_only = nix::fcntl::open(
            ".",
            OFlag::O_PATH | OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )?;
        assert!(Stdio::from_owned_fds(read_fd.as_fd().try_clone_to_owned()?, path_only).is_err());
        assert_eq!(flags(&read_fd)?, original);
        Ok(())
    }
}
