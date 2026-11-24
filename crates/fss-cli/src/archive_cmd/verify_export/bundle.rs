#![forbid(unsafe_code)]
//! Read-only, bounded custody of one independently pinned copied export.
//!
//! This input boundary verifies file bytes and report consistency. The CLI adapter must
//! separately invoke the native recording verifier with the caller's trusted scope. Neither
//! step reconstructs the original archive catalog or grants current disclosure authority.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::Path;

use fss_core::json_input::{self, Value};
use fss_core::{ContentDigest, DigestAlgorithm};

#[path = "bundle/format.rs"]
mod format;
#[path = "bundle/io.rs"]
mod io;

pub(crate) const MAX_WINDOWS: usize = 4096;
pub(crate) const MAX_FILES: usize = MAX_WINDOWS * 6 + 3;
pub(crate) const MAX_IO_CALLS: u64 = 4_000_000;
pub(crate) const MAX_READ_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
pub(crate) const EXPORT_COMPLETION_SCHEMA: &str = "fss.local_archive_export_completion.v2";
const MAX_REQUEST_BYTES: usize = 4096;

/// A payload-free refusal of copied-export verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportVerificationError {
    /// No published completion or request exists; pending bytes are not completion.
    Incomplete,
    /// The completion bytes differ from the independently supplied identity.
    CompletionPinMismatch,
    /// A report, request or descriptor is malformed or contradicts its closed format.
    InvalidReport,
    /// The report differs from the caller's explicit codec or recording/clock scope.
    ScopeMismatch,
    /// A required file is absent from the copied bundle.
    MissingFile,
    /// The directory contains an undeclared name or inconsistent file inventory.
    InventoryMismatch,
    /// A symlink, nonregular file, parent traversal or unsupported path was encountered.
    UnsafePath,
    /// File bytes, manifest closure, native source reconstruction or playback disagree.
    Integrity,
    /// An observed directory, name, file identity or file contents changed during the read.
    Changed,
    /// A finite request resource dimension was exhausted.
    Limit(&'static str),
    /// The caller cancelled before complete verification.
    Cancelled,
    /// The caller's deadline expired before complete verification.
    Deadline,
    /// This host cannot provide the required safe file-open and identity checks.
    UnsupportedPlatform,
    /// A host read failed; no private path or payload is included.
    Io(std::io::ErrorKind),
}
impl std::fmt::Display for ExportVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "copied export verification refused: {self:?}")
    }
}
impl std::error::Error for ExportVerificationError {}
pub(crate) type Result<T> = std::result::Result<T, ExportVerificationError>;

/// Explicit request-owned cancellation/deadline admission at every bounded I/O step.
pub(crate) trait Clock {
    fn check(&self) -> Result<()>;
}

/// Caller-supplied interpretation. Stored metadata may only agree with these values.
#[derive(Clone, Debug)]
pub(crate) struct Scope {
    pub codec: &'static str,
    pub sensor: String,
    pub stream: String,
    pub generation: u64,
    pub anchor: ContentDigest,
    pub receive_clock: ContentDigest,
    pub decode_clock: ContentDigest,
    pub time_scale: u32,
    pub namespace: ContentDigest,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub windows: usize,
    pub files: usize,
    pub file_bytes: u64,
    pub read_bytes: u64,
    pub io_calls: u64,
    pub window_bytes: usize,
}
impl Limits {
    fn validate(self) -> Result<()> {
        if self.windows == 0
            || self.windows > MAX_WINDOWS
            || self.files == 0
            || self.files > MAX_FILES
            || self.file_bytes == 0
            || self.file_bytes > MAX_READ_BYTES
            || self.read_bytes == 0
            || self.read_bytes > MAX_READ_BYTES
            || self.io_calls == 0
            || self.io_calls > MAX_IO_CALLS
            || self.window_bytes == 0
            || self.window_bytes > 64 * 1024 * 1024
        {
            return Err(ExportVerificationError::Limit("invalid_limits"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct FileDescriptor {
    name: String,
    bytes: u64,
    digest: ContentDigest,
}

#[derive(Clone, Debug)]
pub(crate) struct Window {
    pub ordinal: usize,
    pub root: ContentDigest,
    pub requested: Range<u64>,
    pub returned: Range<u64>,
    pub bytes: u64,
    files: Vec<FileDescriptor>,
}

/// One window's exact copied objects. Native recording semantics are not yet established.
pub(crate) struct WindowBytes {
    pub window: Window,
    pub source: Vec<u8>,
    pub initialization: Vec<u8>,
    pub media: Vec<u8>,
    pub index: Vec<u8>,
    pub manifest: Vec<u8>,
}

struct Document {
    request_digest: Option<ContentDigest>,
    snapshot: ContentDigest,
    query: Range<u64>,
    windows: Vec<Window>,
    recording_bytes: u64,
    exported_bytes: u64,
}

/// Complete point-in-time copied-file accounting. It is not an archive/coverage certificate.
pub(crate) struct Receipt {
    pub completion: ContentDigest,
    pub request_observation: ContentDigest,
    request_pinned: bool,
    pub snapshot_claim: ContentDigest,
    pub query: Range<u64>,
    pub windows: usize,
    pub recording_bytes: u64,
    pub file_bytes: u64,
    pub files: usize,
    pub charged_read_bytes: u64,
    pub io_calls: u64,
    pub pending_copy_present: bool,
}

impl Receipt {
    pub fn request_binding(&self) -> &'static str {
        if self.request_pinned {
            "sha256_pinned_by_completion_v2"
        } else {
            "semantic_consistency_only_unpinned_by_completion_v1"
        }
    }
}

pub(crate) struct Bundle<'a> {
    reader: io::Reader<'a>,
    document: Document,
    completion: ContentDigest,
    request_observation: ContentDigest,
    next: usize,
    pending: bool,
    observed: BTreeMap<String, ContentDigest>,
    limits: Limits,
}
impl<'a> Bundle<'a> {
    pub fn open(
        root: &Path,
        completion: ContentDigest,
        scope: &Scope,
        limits: Limits,
        clock: &'a dyn Clock,
    ) -> Result<Self> {
        limits.validate()?;
        if completion.algorithm() != DigestAlgorithm::Sha256 {
            return Err(ExportVerificationError::CompletionPinMismatch);
        }
        let mut reader = io::Reader::open(root, limits, clock)?;
        if !reader.contains("COMPLETE.json") || !reader.contains("REQUEST.json") {
            return Err(ExportVerificationError::Incomplete);
        }
        let completion_bytes = reader.read(
            "COMPLETE.json",
            json_input::MAX_ARCHIVE_EXPORT_REPORT_BYTES,
            None,
        )?;
        if digest(&completion_bytes)? != completion {
            return Err(ExportVerificationError::CompletionPinMismatch);
        }
        clock.check()?;
        let text = std::str::from_utf8(&completion_bytes)
            .map_err(|_| ExportVerificationError::InvalidReport)?;
        let value = json_input::parse_archive_export_report(text)
            .map_err(|_| ExportVerificationError::InvalidReport)?;
        let document = format::document(&value, scope, limits)?;
        drop(value);
        clock.check()?;
        let request = reader.read("REQUEST.json", MAX_REQUEST_BYTES, None)?;
        let request_observation = digest(&request)?;
        if document
            .request_digest
            .is_some_and(|pin| pin != request_observation)
        {
            return Err(ExportVerificationError::Integrity);
        }
        format::request(&request, &document, scope, limits)?;
        let mut expected = BTreeSet::from(["COMPLETE.json".to_owned(), "REQUEST.json".to_owned()]);
        let mut exported = request.len() as u64;
        for window in &document.windows {
            for file in &window.files {
                if !expected.insert(file.name.clone()) {
                    return Err(ExportVerificationError::InvalidReport);
                }
                exported = exported
                    .checked_add(file.bytes)
                    .ok_or(ExportVerificationError::Limit("file_bytes"))?;
                reader.require_length(&file.name, file.bytes)?;
            }
        }
        if exported != document.exported_bytes {
            return Err(ExportVerificationError::InvalidReport);
        }
        let pending = reader.contains("COMPLETE.json.pending");
        if pending {
            expected.insert("COMPLETE.json.pending".to_owned());
        }
        reader.require_inventory(&expected)?;
        let mut observed = BTreeMap::from([
            ("COMPLETE.json".to_owned(), completion),
            ("REQUEST.json".to_owned(), request_observation),
        ]);
        if pending {
            let bytes = reader.read(
                "COMPLETE.json.pending",
                json_input::MAX_ARCHIVE_EXPORT_REPORT_BYTES,
                Some(completion_bytes.len() as u64),
            )?;
            if bytes != completion_bytes {
                return Err(ExportVerificationError::Integrity);
            }
            observed.insert("COMPLETE.json.pending".to_owned(), completion);
        }
        Ok(Self {
            reader,
            document,
            completion,
            request_observation,
            next: 0,
            pending,
            observed,
            limits,
        })
    }

    pub fn next_window(&mut self) -> Result<Option<WindowBytes>> {
        self.reader.check()?;
        let Some(window) = self.document.windows.get(self.next).cloned() else {
            return Ok(None);
        };
        let mut parts = Vec::with_capacity(6);
        for file in &window.files {
            let bytes = self
                .reader
                .read(&file.name, self.limits.window_bytes, Some(file.bytes))?;
            if digest(&bytes)? != file.digest {
                return Err(ExportVerificationError::Integrity);
            }
            self.observed.insert(file.name.clone(), file.digest);
            parts.push(bytes);
        }
        let mut parts = parts.into_iter();
        let mut part = || parts.next().ok_or(ExportVerificationError::InvalidReport);
        let source = part()?;
        let initialization = part()?;
        let media = part()?;
        let index = part()?;
        let manifest = part()?;
        let playback = part()?;
        if playback.get(..initialization.len()) != Some(initialization.as_slice())
            || playback.get(initialization.len()..) != Some(media.as_slice())
        {
            return Err(ExportVerificationError::Integrity);
        }
        self.reader.check()?;
        self.next += 1;
        Ok(Some(WindowBytes {
            window,
            source,
            initialization,
            media,
            index,
            manifest,
        }))
    }

    /// Re-read every admitted file under the SAME allowance, then recheck the closed inventory.
    /// This detects observed drift; it does not freeze a concurrently mutable filesystem.
    pub fn finish(mut self) -> Result<Receipt> {
        if self.next != self.document.windows.len() {
            return Err(ExportVerificationError::Incomplete);
        }
        for (name, expected) in &self.observed {
            let cap = if name.starts_with("COMPLETE.json") {
                json_input::MAX_ARCHIVE_EXPORT_REPORT_BYTES
            } else if name == "REQUEST.json" {
                MAX_REQUEST_BYTES
            } else {
                self.limits.window_bytes
            };
            let bytes = self.reader.read(name, cap, None)?;
            if digest(&bytes)? != *expected {
                return Err(ExportVerificationError::Changed);
            }
        }
        self.reader.recheck_inventory()?;
        Ok(Receipt {
            completion: self.completion,
            request_observation: self.request_observation,
            request_pinned: self.document.request_digest.is_some(),
            snapshot_claim: self.document.snapshot,
            query: self.document.query,
            windows: self.next,
            recording_bytes: self.document.recording_bytes,
            file_bytes: self.reader.file_bytes(),
            files: self.observed.len(),
            charged_read_bytes: self.reader.charged_read_bytes(),
            io_calls: self.reader.io_calls(),
            pending_copy_present: self.pending,
        })
    }
}

fn digest(bytes: &[u8]) -> Result<ContentDigest> {
    ContentDigest::try_sha256(bytes).map_err(|_| ExportVerificationError::Limit("hash_bytes"))
}

#[cfg(all(test, target_os = "linux"))]
#[path = "bundle/tests.rs"]
mod tests;

#[cfg(all(test, not(target_os = "linux")))]
mod unsupported_tests {
    use super::*;

    #[test]
    fn unsupported_host_refuses_before_reading_or_checking_an_unowned_path() {
        struct NoRead;
        impl Clock for NoRead {
            fn check(&self) -> Result<()> {
                panic!("unsupported host must perform no I/O admission")
            }
        }
        let limits = Limits {
            windows: 1,
            files: 9,
            file_bytes: 1,
            read_bytes: 1,
            io_calls: 1,
            window_bytes: 1,
        };
        assert!(matches!(
            io::Reader::open(Path::new("/unowned/absent"), limits, &NoRead),
            Err(ExportVerificationError::UnsupportedPlatform)
        ));
    }
}
