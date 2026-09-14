//! Read-only writer detection for deployment roots.
//!
//! Inspects `/proc/locks` on Linux to detect concurrent writers holding locks on
//! `<root>/LOCK` or `<root>/spool/LOCK` without taking locks or modifying the filesystem.
//! Supports an opt-in shared try-lock probe for non-Linux platforms or direct checking.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use fss_object::SpoolIo;

/// Maximum bytes read from `/proc/locks` (1 MiB cap).
pub const MAX_LOCK_TABLE_BYTES: usize = 1024 * 1024;

/// How a held lock was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterLockBasis {
    /// Observed through `/proc/locks` inspection.
    ProcLocks,
    /// Observed through a shared non-blocking try-lock probe.
    SharedTryLock,
}

impl fmt::Display for WriterLockBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcLocks => write!(f, "proc_locks"),
            Self::SharedTryLock => write!(f, "shared_try_lock"),
        }
    }
}

/// Reason why lock table inspection could not determine writer state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownLockReason {
    /// The `/proc/locks` table does not exist or this platform is unsupported.
    NoLockTable,
    /// The lock table could not be read or opened.
    Unreadable,
    /// The lock table contents could not be parsed.
    ParseError,
    /// The lock table size exceeded [`MAX_LOCK_TABLE_BYTES`].
    OverBudget,
    /// Inode matched but filesystem device did not match.
    DeviceMismatch,
    /// Lock file changed inode or device during inspection.
    LockFileReplaced,
}

impl fmt::Display for UnknownLockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLockTable => write!(f, "no_lock_table"),
            Self::Unreadable => write!(f, "unreadable"),
            Self::ParseError => write!(f, "parse_error"),
            Self::OverBudget => write!(f, "over_budget"),
            Self::DeviceMismatch => write!(f, "device_mismatch"),
            Self::LockFileReplaced => write!(f, "lock_file_replaced"),
        }
    }
}

/// State of writer locks on a deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriterState {
    /// A writer was observed holding an exclusive lock.
    Held {
        /// Verification basis of the observation.
        basis: WriterLockBasis,
        /// PID of the holder from `/proc/locks` (advisory hint).
        pid_hint: Option<u32>,
    },
    /// No writer lock was observed in `/proc/locks` (never reports "none").
    NotObserved {
        /// Observation basis.
        basis: &'static str,
        /// Namespace scope of the observation.
        scope: &'static str,
    },
    /// Shared try-lock probe succeeded, confirming no exclusive holder.
    NotHeld {
        /// Verification basis.
        basis: &'static str,
    },
    /// Lock state could not be reliably determined.
    Unknown {
        /// Reason for indeterminate state.
        reason: UnknownLockReason,
    },
    /// No writer probe was requested or executed.
    NotProbed,
}

impl WriterState {
    /// Standard `NotObserved` state from `/proc/locks` scan.
    #[must_use]
    pub const fn not_observed() -> Self {
        Self::NotObserved {
            basis: "proc_locks",
            scope: "this_host_this_pid_namespace",
        }
    }

    /// Standard `NotHeld` state from opt-in shared try-lock probe.
    #[must_use]
    pub const fn not_held() -> Self {
        Self::NotHeld {
            basis: "shared_try_lock",
        }
    }

    /// Returns whether a writer lock is held.
    #[must_use]
    pub fn is_held(&self) -> bool {
        matches!(self, Self::Held { .. })
    }
}

/// Source capability for reading the system lock table (`/proc/locks`).
pub trait LockTableSource: fmt::Debug + Send + Sync {
    /// Reads up to `max_bytes` of lock table data.
    fn read_lock_table(&self, max_bytes: usize) -> io::Result<String>;
}

/// Host filesystem `/proc/locks` reader.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostLockTableSource;

impl LockTableSource for HostLockTableSource {
    fn read_lock_table(&self, max_bytes: usize) -> io::Result<String> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Read;
            let mut file = fs::File::open("/proc/locks")?;
            let mut buf = Vec::new();
            let cap = (max_bytes as u64).saturating_add(1);
            Read::by_ref(&mut file).take(cap).read_to_end(&mut buf)?;
            if buf.len() > max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "lock table exceeded limit",
                ));
            }
            String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = max_bytes;
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "proc locks not supported on this platform",
            ))
        }
    }
}

/// In-memory lock table source for testing.
#[derive(Clone, Debug)]
pub struct StringLockTableSource(pub String);

impl LockTableSource for StringLockTableSource {
    fn read_lock_table(&self, max_bytes: usize) -> io::Result<String> {
        if self.0.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "lock table exceeded limit",
            ));
        }
        Ok(self.0.clone())
    }
}

/// Decodes Linux `st_dev` into `(major, minor)` device numbers.
#[must_use]
pub fn decode_st_dev(dev: u64) -> (u32, u32) {
    let major = (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32;
    let minor = ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32;
    (major, minor)
}

#[derive(Debug)]
struct ProcLockEntry {
    is_waiter: bool,
    lock_type: String,
    mode: String,
    pid: Option<u32>,
    major: u32,
    minor: u32,
    ino: u64,
}

fn parse_proc_locks_line(line: &str) -> Option<ProcLockEntry> {
    let mut tokens = line.split_whitespace();
    let _ordinal = tokens.next()?;
    let mut next_token = tokens.next()?;
    let mut is_waiter = false;
    if next_token == "->" {
        is_waiter = true;
        next_token = tokens.next()?;
    }
    let lock_type = next_token.to_string();
    let _advisory = tokens.next()?;
    let mode = tokens.next()?.to_string();
    let pid_token = tokens.next()?;
    let pid = pid_token.parse::<u32>().ok();
    let dev_ino = tokens.next()?;
    let mut parts = dev_ino.split(':');
    let maj_str = parts.next()?;
    let min_str = parts.next()?;
    let ino_str = parts.next()?;
    let major = u32::from_str_radix(maj_str, 16).ok()?;
    let minor = u32::from_str_radix(min_str, 16).ok()?;
    let ino = ino_str.parse::<u64>().ok()?;
    Some(ProcLockEntry {
        is_waiter,
        lock_type,
        mode,
        pid,
        major,
        minor,
        ino,
    })
}

/// Options controlling writer detection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WriterDetectionOptions {
    /// Whether to perform an opt-in shared try-lock probe.
    pub probe_shared_lock: bool,
    /// Whether the calling process already holds the publication lock.
    pub self_holds_lock: bool,
}

/// Checks writer state across candidate lock paths on a deployment root.
pub fn detect_writers(
    io: &dyn SpoolIo,
    lock_paths: &[PathBuf],
    lock_table_source: Option<&dyn LockTableSource>,
    options: WriterDetectionOptions,
) -> WriterState {
    if options.probe_shared_lock {
        if options.self_holds_lock {
            return WriterState::NotProbed;
        }
        if let Some(first_lock) = lock_paths.first() {
            return probe_shared_lock(io, first_lock);
        }
        return WriterState::NotProbed;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = io;
        let _ = lock_paths;
        let _ = lock_table_source;
        WriterState::Unknown {
            reason: UnknownLockReason::NoLockTable,
        }
    }

    #[cfg(target_os = "linux")]
    {
        detect_writers_linux(io, lock_paths, lock_table_source)
    }
}

#[cfg(target_os = "linux")]
fn detect_writers_linux(
    io: &dyn SpoolIo,
    lock_paths: &[PathBuf],
    lock_table_source: Option<&dyn LockTableSource>,
) -> WriterState {
    let mut target_stats = Vec::new();
    for path in lock_paths {
        match io.symlink_metadata(path) {
            Ok(meta) => {
                if !meta.file_type().is_file() {
                    return WriterState::Unknown {
                        reason: UnknownLockReason::Unreadable,
                    };
                }
                #[cfg(unix)]
                {
                    let dev = meta.dev();
                    let ino = meta.ino();
                    let (maj, min) = decode_st_dev(dev);
                    target_stats.push((path.clone(), dev, maj, min, ino));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return WriterState::Unknown {
                    reason: UnknownLockReason::Unreadable,
                };
            }
        }
    }

    if target_stats.is_empty() {
        return WriterState::not_observed();
    }

    let default_source = HostLockTableSource;
    let source = match lock_table_source {
        Some(source) => source,
        None => &default_source,
    };
    let table_content = match source.read_lock_table(MAX_LOCK_TABLE_BYTES) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return WriterState::Unknown {
                reason: UnknownLockReason::NoLockTable,
            };
        }
        Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
            return WriterState::Unknown {
                reason: UnknownLockReason::OverBudget,
            };
        }
        Err(_) => {
            return WriterState::Unknown {
                reason: UnknownLockReason::Unreadable,
            };
        }
    };

    let mut held_entry = None;
    let mut device_mismatch = false;

    for line in table_content.lines() {
        let Some(entry) = parse_proc_locks_line(line) else {
            continue;
        };
        for (_, _, target_maj, target_min, target_ino) in &target_stats {
            if entry.ino == *target_ino {
                if entry.major != *target_maj || entry.minor != *target_min {
                    device_mismatch = true;
                } else if !entry.is_waiter && entry.lock_type == "FLOCK" && entry.mode == "WRITE" {
                    held_entry = Some(entry.pid);
                    break;
                }
            }
        }
        if held_entry.is_some() {
            break;
        }
    }

    // Re-stat lock files to confirm they were not replaced during table read
    for (path, orig_dev, _, _, orig_ino) in &target_stats {
        match io.symlink_metadata(path) {
            #[cfg(unix)]
            Ok(re_meta) => {
                if re_meta.dev() != *orig_dev || re_meta.ino() != *orig_ino {
                    return WriterState::Unknown {
                        reason: UnknownLockReason::LockFileReplaced,
                    };
                }
            }
            #[cfg(not(unix))]
            Ok(_) => {}
            Err(_) => {
                return WriterState::Unknown {
                    reason: UnknownLockReason::LockFileReplaced,
                };
            }
        }
    }

    if let Some(pid_hint) = held_entry {
        return WriterState::Held {
            basis: WriterLockBasis::ProcLocks,
            pid_hint,
        };
    }

    if device_mismatch {
        return WriterState::Unknown {
            reason: UnknownLockReason::DeviceMismatch,
        };
    }

    WriterState::not_observed()
}

/// Opt-in probe using a shared non-blocking try-lock on `<root>/LOCK`.
pub fn probe_shared_lock(io: &dyn SpoolIo, lock_path: &Path) -> WriterState {
    match io.symlink_metadata(lock_path) {
        Ok(meta) if !meta.file_type().is_file() => {
            return WriterState::Unknown {
                reason: UnknownLockReason::Unreadable,
            };
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return WriterState::not_held();
        }
        Err(_) => {
            return WriterState::Unknown {
                reason: UnknownLockReason::Unreadable,
            };
        }
    }

    let file = match io.open_read(lock_path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return WriterState::not_held();
        }
        Err(_) => {
            return WriterState::Unknown {
                reason: UnknownLockReason::Unreadable,
            };
        }
    };

    match io.try_lock_shared(&file) {
        Ok(()) => WriterState::not_held(),
        Err(fs::TryLockError::WouldBlock) => WriterState::Held {
            basis: WriterLockBasis::SharedTryLock,
            pid_hint: None,
        },
        Err(fs::TryLockError::Error(_)) => WriterState::Unknown {
            reason: UnknownLockReason::Unreadable,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs::File;
    use std::path::PathBuf;

    use fss_object::HostSpoolIo;

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn test_decode_st_dev() {
        assert_eq!(decode_st_dev(0x0801), (8, 1));
        assert_eq!(decode_st_dev(0x0800), (8, 0));
        assert_eq!(decode_st_dev(0), (0, 0));
    }

    #[test]
    fn test_parse_proc_locks_line() {
        let normal = "1: FLOCK  ADVISORY  WRITE 1234 08:01:654321 0 EOF";
        let entry = parse_proc_locks_line(normal);
        assert!(entry.is_some());
        if let Some(entry) = entry {
            assert!(!entry.is_waiter);
            assert_eq!(entry.lock_type, "FLOCK");
            assert_eq!(entry.mode, "WRITE");
            assert_eq!(entry.pid, Some(1234));
            assert_eq!(entry.major, 8);
            assert_eq!(entry.minor, 1);
            assert_eq!(entry.ino, 654321);
        }

        let waiter = "1: -> FLOCK  ADVISORY  WRITE 5678 08:01:654321 0 EOF";
        let entry2 = parse_proc_locks_line(waiter);
        assert!(entry2.is_some());
        if let Some(entry) = entry2 {
            assert!(entry.is_waiter);
            assert_eq!(entry.lock_type, "FLOCK");
            assert_eq!(entry.mode, "WRITE");
            assert_eq!(entry.pid, Some(5678));
        }

        assert!(parse_proc_locks_line("garbage").is_none());
        assert!(parse_proc_locks_line("").is_none());
    }

    #[test]
    fn test_display_formats() {
        assert_eq!(WriterLockBasis::ProcLocks.to_string(), "proc_locks");
        assert_eq!(
            WriterLockBasis::SharedTryLock.to_string(),
            "shared_try_lock"
        );
        assert_eq!(UnknownLockReason::NoLockTable.to_string(), "no_lock_table");
        assert_eq!(UnknownLockReason::Unreadable.to_string(), "unreadable");
        assert_eq!(UnknownLockReason::ParseError.to_string(), "parse_error");
        assert_eq!(UnknownLockReason::OverBudget.to_string(), "over_budget");
        assert_eq!(
            UnknownLockReason::DeviceMismatch.to_string(),
            "device_mismatch"
        );
        assert_eq!(
            UnknownLockReason::LockFileReplaced.to_string(),
            "lock_file_replaced"
        );

        let not_obs = WriterState::not_observed();
        assert!(!not_obs.is_held());
        let not_held = WriterState::not_held();
        assert!(!not_held.is_held());
        let held = WriterState::Held {
            basis: WriterLockBasis::ProcLocks,
            pid_hint: Some(42),
        };
        assert!(held.is_held());
    }

    #[test]
    fn test_detect_writers_probe_options() -> TestResult {
        let io = HostSpoolIo;
        let non_existent = PathBuf::from("/tmp/fss-nonexistent-lock-probe-test");

        // Self holds lock suppresses probe
        let state = detect_writers(
            &io,
            std::slice::from_ref(&non_existent),
            None,
            WriterDetectionOptions {
                probe_shared_lock: true,
                self_holds_lock: true,
            },
        );
        assert_eq!(state, WriterState::NotProbed);

        // Empty lock paths with probe suppresses probe
        let state2 = detect_writers(
            &io,
            &[],
            None,
            WriterDetectionOptions {
                probe_shared_lock: true,
                self_holds_lock: false,
            },
        );
        assert_eq!(state2, WriterState::NotProbed);

        // Probe non-existent file gives NotHeld
        let state3 = detect_writers(
            &io,
            &[non_existent],
            None,
            WriterDetectionOptions {
                probe_shared_lock: true,
                self_holds_lock: false,
            },
        );
        assert_eq!(state3, WriterState::not_held());
        Ok(())
    }

    #[test]
    fn test_detect_writers_proc_locks_source() -> TestResult {
        let io = HostSpoolIo;
        let temp_dir = std::env::temp_dir();
        let lock_file_path = temp_dir.join(format!("fss-test-lock-{}", std::process::id()));
        let _file = File::create(&lock_file_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::symlink_metadata(&lock_file_path)?;
            let (maj, min) = decode_st_dev(meta.dev());
            let ino = meta.ino();

            // Match case
            let table_held = format!(
                "1: FLOCK ADVISORY WRITE 4242 {:02x}:{:02x}:{} 0 EOF\n",
                maj, min, ino
            );
            let source_held = StringLockTableSource(table_held);
            let state_held = detect_writers(
                &io,
                std::slice::from_ref(&lock_file_path),
                Some(&source_held),
                WriterDetectionOptions::default(),
            );
            assert_eq!(
                state_held,
                WriterState::Held {
                    basis: WriterLockBasis::ProcLocks,
                    pid_hint: Some(4242),
                }
            );

            // Waiter-only case does not count as holder
            let table_waiter = format!(
                "1: -> FLOCK ADVISORY WRITE 9999 {:02x}:{:02x}:{} 0 EOF\n",
                maj, min, ino
            );
            let source_waiter = StringLockTableSource(table_waiter);
            let state_waiter = detect_writers(
                &io,
                std::slice::from_ref(&lock_file_path),
                Some(&source_waiter),
                WriterDetectionOptions::default(),
            );
            assert_eq!(state_waiter, WriterState::not_observed());

            // Device mismatch case
            let table_dev_mismatch = format!("1: FLOCK ADVISORY WRITE 4242 99:99:{} 0 EOF\n", ino);
            let source_dev_mismatch = StringLockTableSource(table_dev_mismatch);
            let state_dev_mismatch = detect_writers(
                &io,
                std::slice::from_ref(&lock_file_path),
                Some(&source_dev_mismatch),
                WriterDetectionOptions::default(),
            );
            assert_eq!(
                state_dev_mismatch,
                WriterState::Unknown {
                    reason: UnknownLockReason::DeviceMismatch,
                }
            );
        }

        let _ = std::fs::remove_file(&lock_file_path);
        Ok(())
    }
}
