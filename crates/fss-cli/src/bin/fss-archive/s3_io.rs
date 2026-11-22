#![forbid(unsafe_code)]
//! Bounded native filesystem authority for one explicitly requested S3 upload.
//!
//! Journal metadata may inspect its exact ancestors and fsync its parent, as required by
//! FileUploadJournal's namespace protocol. File contents and mutations stay inside the journal.
//! Source and credential inputs are separate exact regular files. The source is preloaded before
//! any provider effect, so an upload never rereads a mutable pathname between its parts.
//! This synchronous adapter supports Linux x86_64/aarch64, whose no-follow/nonblocking opens
//! are also used by the native journal inspector. Other platforms fail closed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{DirEntry, File, FileType, Metadata, OpenOptions, ReadDir, TryLockError};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use fss_core::{BudgetVector, RegionKind, RegionState, RegionTree, RuntimeGrant, TimestampNs};
use fss_object::{HostSpoolIo, SpoolIo};
use fss_runtime::authority::AuthorityCx;

pub(super) const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_CREDENTIAL_BYTES: u64 = 8192;
const MAX_JOURNAL_CALL_BYTES: u64 = 17 * 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;
const MAX_HANDLES: usize = 4096;

pub(super) struct ScopedS3Io {
    journal_root: PathBuf,
    source: PathBuf,
    credentials: PathBuf,
    started: Instant,
    origin: TimestampNs,
    state: Mutex<State>,
}

struct State {
    authority: AuthorityCx,
    tree: RegionTree,
    last_now: TimestampNs,
    charged_ms: u64,
    handles: BTreeMap<i64, Handle>,
    source_identity: Option<Identity>,
    credential_identity: Option<Identity>,
}

#[derive(Clone)]
struct Handle {
    path: PathBuf,
    identity: Identity,
    writable: bool,
    lockable: bool,
    locked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    identity: Identity,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl std::fmt::Debug for ScopedS3Io {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScopedS3Io(exact files, bounded journal, owned authority)")
    }
}

// Erase partially read secret material on every error path. Successful credential bytes move
// directly to S3Credentials::from_lines, whose owner erases them after parsing and at drop.
struct ReadBuffer(Vec<u8>);
impl Drop for ReadBuffer {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl ScopedS3Io {
    pub(super) fn new(
        journal_root: PathBuf,
        source: PathBuf,
        credentials: PathBuf,
        mut authority: AuthorityCx,
        tree: RegionTree,
        started: Instant,
        origin: TimestampNs,
    ) -> io::Result<Self> {
        if !cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "scoped archive filesystem is unsupported on this platform",
            ));
        }
        for path in [&journal_root, &source, &credentials] {
            validate_path(path)?;
        }
        if source == credentials
            || source.starts_with(&journal_root)
            || credentials.starts_with(&journal_root)
            || journal_root.starts_with(&source)
            || journal_root.starts_with(&credentials)
            || authority.kind() != RegionKind::Process
            || authority.is_cancel_requested(&tree).map_err(|_| denied())?
        {
            return Err(denied());
        }
        let node = tree.get(authority.region()).map_err(|_| denied())?;
        if origin < node.created_at || node.authority.deadline.is_none() {
            return Err(denied());
        }
        // Intersections preserve any restrictions already held by the supplied authority.
        let mut grants = authority.grants().clone();
        for (grant, path) in [
            (RuntimeGrant::ObjectStage, &journal_root),
            (RuntimeGrant::ReadMedia, &source),
            (RuntimeGrant::AdapterAuth, &credentials),
        ] {
            let resource = resource(path)?;
            authority
                .require_grant_for(grant, resource)
                .map_err(|_| denied())?;
            grants = grants.with_scope(grant, BTreeSet::from([resource.to_owned()]));
        }
        authority.narrow_grants(grants).map_err(|_| denied())?;
        let result = Self {
            journal_root,
            source,
            credentials,
            started,
            origin,
            state: Mutex::new(State {
                authority,
                tree,
                last_now: origin,
                charged_ms: 0,
                handles: BTreeMap::new(),
                source_identity: None,
                credential_identity: None,
            }),
        };
        result.check()?;
        Ok(result)
    }

    fn now(&self) -> io::Result<TimestampNs> {
        let elapsed = i128::try_from(self.started.elapsed().as_nanos()).map_err(|_| denied())?;
        self.origin
            .0
            .checked_add(elapsed)
            .map(TimestampNs)
            .ok_or_else(denied)
    }

    fn admit(
        &self,
        grant: RuntimeGrant,
        scope: &Path,
        bytes: u64,
        operations: u64,
    ) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| denied())?;
        let now = self.now()?;
        let node = state
            .tree
            .get(state.authority.region())
            .map_err(|_| denied())?;
        if now < state.last_now
            || now < node.created_at
            || node
                .authority
                .deadline
                .is_none_or(|deadline| now >= deadline)
            || state
                .authority
                .is_cancel_requested(&state.tree)
                .map_err(|_| denied())?
        {
            return Err(denied());
        }
        state
            .authority
            .require_grant_for(grant, resource(scope)?)
            .map_err(|_| denied())?;
        let elapsed_ns = now.0.checked_sub(self.origin.0).ok_or_else(denied)?;
        let elapsed_ms = u64::try_from(elapsed_ns)
            .map_err(|_| denied())?
            .div_ceil(1_000_000);
        let mut cost = BudgetVector::ZERO;
        cost.bytes = bytes;
        cost.storage_operations = operations;
        cost.latency_ms = elapsed_ms
            .checked_sub(state.charged_ms)
            .ok_or_else(denied)?;
        let State {
            authority, tree, ..
        } = &mut *state;
        authority
            .budget_mut(tree)
            .map_err(|_| denied())?
            .spend_vector(&cost)
            .map_err(|_| limit())?;
        state.last_now = now;
        state.charged_ms = elapsed_ms;
        Ok(())
    }

    fn journal(&self, bytes: u64, operations: u64) -> io::Result<()> {
        self.admit(
            RuntimeGrant::ObjectStage,
            &self.journal_root,
            bytes,
            operations,
        )
    }

    pub(super) fn check(&self) -> io::Result<()> {
        self.journal(0, 0)
    }

    pub(super) fn consumed(&self) -> io::Result<BudgetVector> {
        let state = self.state.lock().map_err(|_| denied())?;
        Ok(*state.authority.budget().consumed())
    }

    /// The journal must be dropped first so its already-held lock has been released.
    /// Deadline/cancellation cannot prohibit draining an owner which has stopped admission.
    pub(super) fn finalize(&self) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| denied())?;
        if state.handles.values().any(|handle| handle.locked) {
            return Err(denied());
        }
        let now = self.now()?;
        if now < state.last_now {
            return Err(denied());
        }
        let State {
            authority, tree, ..
        } = &mut *state;
        let current = tree.get(authority.region()).map_err(|_| denied())?.state;
        if current == RegionState::Closed {
            return Ok(());
        }
        if current == RegionState::Active {
            authority
                .request_cancellation(tree, now)
                .map_err(|_| denied())?;
        }
        if tree.get(authority.region()).map_err(|_| denied())?.state == RegionState::DrainRequested
        {
            authority.begin_drain(tree, now).map_err(|_| denied())?;
        }
        authority.finalize(tree, now).map_err(|_| denied())?;
        Ok(())
    }

    /// Full finite source snapshot. Refuses the advertised length before allocating its buffer.
    pub(super) fn read_source(&self, expected_bytes: u64) -> io::Result<Vec<u8>> {
        if expected_bytes > MAX_SOURCE_BYTES {
            return Err(limit());
        }
        self.read_exact_file(
            &self.source,
            RuntimeGrant::ReadMedia,
            Some(expected_bytes),
            MAX_SOURCE_BYTES,
            false,
        )
    }

    pub(super) fn read_credentials(&self) -> io::Result<Vec<u8>> {
        self.read_exact_file(
            &self.credentials,
            RuntimeGrant::AdapterAuth,
            None,
            MAX_CREDENTIAL_BYTES,
            true,
        )
    }

    fn read_exact_file(
        &self,
        path: &Path,
        grant: RuntimeGrant,
        expected: Option<u64>,
        maximum: u64,
        private: bool,
    ) -> io::Result<Vec<u8>> {
        let named = self.inspect(path, grant, path, false)?.ok_or_else(denied)?;
        let before = stamp(&named)?;
        if before.len > maximum || expected.is_some_and(|length| length != before.len) {
            return Err(limit());
        }
        if private {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if named.mode() & 0o077 != 0 {
                    return Err(denied());
                }
            }
        }
        self.admit(grant, path, 0, 1)?;
        let mut options = nofollow_options()?;
        let mut file = options.read(true).open(path).map_err(native)?;
        self.admit(grant, path, 0, 1)?;
        if stamp(&file.metadata().map_err(native)?)? != before {
            return Err(changed());
        }
        {
            let mut state = self.state.lock().map_err(|_| denied())?;
            let other = if private {
                state.source_identity
            } else {
                state.credential_identity
            };
            if other == Some(before.identity) {
                return Err(denied());
            }
            if private {
                state.credential_identity = Some(before.identity);
            } else {
                state.source_identity = Some(before.identity);
            }
        }
        let capacity = before.len.checked_add(1).ok_or_else(limit)?;
        // Reserve the complete read plus the EOF probe before allocation or payload I/O.
        self.admit(grant, path, capacity, 0)?;
        let mut bytes = buffer(capacity)?;
        let read = self.read_chunks(&mut file, &mut bytes.0, grant, path)?;
        if read as u64 != before.len {
            return Err(changed());
        }
        self.admit(grant, path, 0, 1)?;
        if stamp(&file.metadata().map_err(native)?)? != before {
            return Err(changed());
        }
        let after = self
            .inspect(path, grant, path, false)?
            .ok_or_else(changed)?;
        if stamp(&after)? != before {
            return Err(changed());
        }
        self.admit(grant, path, 0, 0)?;
        bytes.0.truncate(read);
        Ok(std::mem::take(&mut bytes.0))
    }

    fn read_chunks(
        &self,
        file: &mut File,
        bytes: &mut [u8],
        grant: RuntimeGrant,
        scope: &Path,
    ) -> io::Result<usize> {
        let mut offset = 0;
        let mut interrupted = 0;
        while offset < bytes.len() {
            let end = offset.saturating_add(READ_CHUNK).min(bytes.len());
            self.admit(grant, scope, 0, 1)?;
            match file.read(&mut bytes[offset..end]) {
                Ok(0) => break,
                Ok(count) => {
                    offset += count;
                    interrupted = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 8 => {
                    interrupted += 1;
                }
                Err(error) => return Err(native(error)),
            }
            self.admit(grant, scope, 0, 0)?;
        }
        self.admit(grant, scope, 0, 0)?;
        Ok(offset)
    }

    // Inspect each exact lexical component, charging before every metadata operation.
    // Only the final component may be absent when admitting creation.
    fn inspect(
        &self,
        path: &Path,
        grant: RuntimeGrant,
        scope: &Path,
        missing_leaf: bool,
    ) -> io::Result<Option<Metadata>> {
        validate_absolute(path)?;
        let ancestors: Vec<_> = path.ancestors().collect();
        for (index, ancestor) in ancestors.iter().rev().enumerate() {
            self.admit(grant, scope, 0, 1)?;
            let final_component = index + 1 == ancestors.len();
            let metadata = match HostSpoolIo.symlink_metadata(ancestor) {
                Ok(metadata) => metadata,
                Err(error)
                    if final_component
                        && missing_leaf
                        && error.kind() == io::ErrorKind::NotFound =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(native(error)),
            };
            if metadata.file_type().is_symlink() || (!final_component && !metadata.is_dir()) {
                return Err(denied());
            }
            if final_component {
                self.admit(grant, scope, 0, 0)?;
                return Ok(Some(metadata));
            }
        }
        Err(denied())
    }

    fn journal_path(&self, path: &Path, ancestors: bool) -> io::Result<()> {
        validate_absolute(path)?;
        if !path.starts_with(&self.journal_root)
            && !(ancestors && self.journal_root.starts_with(path))
        {
            return Err(denied());
        }
        self.check()
    }

    fn inspect_journal(
        &self,
        path: &Path,
        ancestors: bool,
        missing: bool,
    ) -> io::Result<Option<Metadata>> {
        self.journal_path(path, ancestors)?;
        self.inspect(path, RuntimeGrant::ObjectStage, &self.journal_root, missing)
    }

    fn register(&self, file: &File, path: &Path, writable: bool, lockable: bool) -> io::Result<()> {
        self.journal(0, 1)?;
        let opened = identity(&file.metadata().map_err(native)?)?;
        let named = self
            .inspect_journal(path, false, false)?
            .ok_or_else(changed)?;
        if identity(&named)? != opened {
            return Err(changed());
        }
        let key = descriptor(file)?;
        let mut state = self.state.lock().map_err(|_| denied())?;
        if state.handles.get(&key).is_some_and(|old| old.locked)
            || (!state.handles.contains_key(&key) && state.handles.len() >= MAX_HANDLES)
        {
            return Err(limit());
        }
        state.handles.insert(
            key,
            Handle {
                path: path.to_path_buf(),
                identity: opened,
                writable,
                lockable,
                locked: false,
            },
        );
        Ok(())
    }

    fn handle(&self, file: &File, write: bool) -> io::Result<Handle> {
        let key = descriptor(file)?;
        let handle = self
            .state
            .lock()
            .map_err(|_| denied())?
            .handles
            .get(&key)
            .cloned()
            .ok_or_else(denied)?;
        if write && !handle.writable {
            return Err(denied());
        }
        self.journal(0, 1)?;
        if identity(&file.metadata().map_err(native)?)? != handle.identity {
            return Err(changed());
        }
        // A reused descriptor or replaced pathname never inherits the earlier handle's scope.
        let named = self
            .inspect_journal(&handle.path, false, false)?
            .ok_or_else(changed)?;
        if identity(&named)? != handle.identity {
            return Err(changed());
        }
        Ok(handle)
    }

    fn mark_locked(&self, file: &File, locked: bool) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| denied())?;
        let handle = state
            .handles
            .get_mut(&descriptor(file)?)
            .ok_or_else(denied)?;
        handle.locked = locked;
        Ok(())
    }

    fn lock_file(&self, file: &File, shared: bool) -> Result<(), TryLockError> {
        let handle = self.handle(file, false).map_err(TryLockError::Error)?;
        if !handle.lockable {
            return Err(TryLockError::Error(denied()));
        }
        self.journal(0, 1).map_err(TryLockError::Error)?;
        if shared {
            HostSpoolIo.try_lock_shared(file)?;
        } else {
            HostSpoolIo.try_lock(file)?;
        }
        if let Err(error) = self.mark_locked(file, true).and_then(|()| self.check()) {
            if HostSpoolIo.unlock(file).is_ok() {
                let _ = self.mark_locked(file, false);
            }
            return Err(TryLockError::Error(error));
        }
        Ok(())
    }
}

impl SpoolIo for ScopedS3Io {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        // The journal contract requires an existing parent, never ambient parent creation.
        if path != self.journal_root {
            return Err(denied());
        }
        if let Some(metadata) = self.inspect_journal(path, false, true)? {
            return if metadata.is_dir() {
                Ok(())
            } else {
                Err(denied())
            };
        }
        self.journal(0, 1)?;
        HostSpoolIo.create_dir(path).map_err(native)?;
        self.check()
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        self.inspect_journal(path, false, true)?;
        self.journal(0, 1)?;
        HostSpoolIo.create_dir(path).map_err(native)?;
        self.check()
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.symlink_metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.inspect_journal(path, true, false)?.ok_or_else(denied)
    }
    fn open_lock(&self, path: &Path) -> io::Result<File> {
        if self
            .inspect_journal(path, false, true)?
            .is_some_and(|metadata| !metadata.is_file())
        {
            return Err(denied());
        }
        self.journal(0, 1)?;
        let mut options = nofollow_options()?;
        let file = options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(native)?;
        self.register(&file, path, true, true)?;
        Ok(file)
    }
    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        self.lock_file(file, false)
    }
    fn try_lock_shared(&self, file: &File) -> Result<(), TryLockError> {
        self.lock_file(file, true)
    }
    fn unlock(&self, file: &File) -> io::Result<()> {
        // Releasing admitted ownership needs no new grant, time, or budget.
        let key = descriptor(file)?;
        let handle = self
            .state
            .lock()
            .map_err(|_| denied())?
            .handles
            .get(&key)
            .cloned()
            .ok_or_else(denied)?;
        if !handle.lockable || identity(&file.metadata().map_err(native)?)? != handle.identity {
            return Err(denied());
        }
        HostSpoolIo.unlock(file).map_err(native)?;
        self.mark_locked(file, false)
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        let metadata = self
            .inspect_journal(path, false, false)?
            .ok_or_else(denied)?;
        if !metadata.is_dir() {
            return Err(denied());
        }
        self.journal(0, 1)?;
        let entries = HostSpoolIo.read_dir(path).map_err(native)?;
        self.check()?;
        Ok(entries)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        if let Err(error) = self.journal(0, 1) {
            return Some(Err(error));
        }
        match HostSpoolIo.next_dir_entry(entries) {
            Some(Ok(entry)) => Some(self.journal_path(&entry.path(), false).map(|()| entry)),
            Some(Err(error)) => Some(Err(native(error))),
            None => match self.check() {
                Ok(()) => None,
                Err(error) => Some(Err(error)),
            },
        }
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.journal_path(&entry.path(), false)?;
        self.journal(0, 1)?;
        let kind = HostSpoolIo.entry_file_type(entry).map_err(native)?;
        self.check()?;
        Ok(kind)
    }
    fn create_new(&self, path: &Path) -> io::Result<File> {
        self.inspect_journal(path, false, true)?;
        self.journal(0, 1)?;
        let mut options = nofollow_options()?;
        let file = options
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(native)?;
        self.register(&file, path, true, false)?;
        Ok(file)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.handle(file, true)?;
        if bytes.len() as u64 > MAX_JOURNAL_CALL_BYTES {
            return Err(limit());
        }
        self.journal(bytes.len() as u64, 1)?;
        let count = HostSpoolIo.write(file, bytes).map_err(native)?;
        self.check()?;
        Ok(count)
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.handle(file, true)?;
        self.journal(0, 1)?;
        HostSpoolIo.sync_file(file).map_err(native)?;
        self.check()
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        let metadata = self
            .inspect_journal(path, false, false)?
            .ok_or_else(denied)?;
        let expected = identity(&metadata)?;
        self.journal(0, 1)?;
        let mut options = nofollow_options()?;
        let file = options.read(true).open(path).map_err(native)?;
        self.register(&file, path, false, false)?;
        self.journal(0, 1)?;
        if identity(&file.metadata().map_err(native)?)? != expected {
            return Err(changed());
        }
        Ok(file)
    }
    fn read_bounded(&self, file: &mut File, bound: u64) -> io::Result<Vec<u8>> {
        self.handle(file, false)?;
        if bound > MAX_JOURNAL_CALL_BYTES {
            return Err(limit());
        }
        self.journal(bound, 0)?;
        let mut bytes = buffer(bound)?;
        let count = self.read_chunks(
            file,
            &mut bytes.0,
            RuntimeGrant::ObjectStage,
            &self.journal_root,
        )?;
        self.handle(file, false)?;
        bytes.0.truncate(count);
        Ok(std::mem::take(&mut bytes.0))
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inspect_journal(from, false, false)?;
        self.inspect_journal(to, false, true)?;
        self.journal(0, 1)?;
        HostSpoolIo.rename(from, to).map_err(native)?;
        self.check()
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.inspect_journal(path, false, false)?;
        self.journal(0, 1)?;
        HostSpoolIo.remove_file(path).map_err(native)?;
        self.check()
    }
    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        if !path.starts_with(&self.journal_root) && self.journal_root.parent() != Some(path) {
            return Err(denied());
        }
        let metadata = self
            .inspect_journal(path, true, false)?
            .ok_or_else(denied)?;
        if !metadata.is_dir() {
            return Err(denied());
        }
        self.journal(0, 1)?;
        HostSpoolIo.sync_directory(path).map_err(native)?;
        self.check()
    }
    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inspect_journal(from, false, false)?;
        self.inspect_journal(to, false, true)?;
        self.journal(0, 1)?;
        HostSpoolIo.hard_link(from, to).map_err(native)?;
        self.check()
    }
}

fn validate_absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.components().count() > 64
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || resource(path)?.len() > 4096
        || resource(path)?.chars().any(char::is_control)
    {
        return Err(denied());
    }
    Ok(())
}

fn validate_path(path: &Path) -> io::Result<()> {
    validate_absolute(path)?;
    if path.file_name().is_none() {
        return Err(denied());
    }
    Ok(())
}

fn resource(path: &Path) -> io::Result<&str> {
    path.to_str().ok_or_else(denied)
}

fn identity(metadata: &Metadata) -> io::Result<Identity> {
    if !metadata.is_file() {
        return Err(denied());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Identity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Err(denied())
    }
}

fn stamp(metadata: &Metadata) -> io::Result<Stamp> {
    let identity = identity(metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Stamp {
            identity,
            len: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = identity;
        Err(denied())
    }
}

fn descriptor(file: &File) -> io::Result<i64> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        Ok(i64::from(file.as_raw_fd()))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(denied())
    }
}

fn nofollow_options() -> io::Result<OpenOptions> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let nofollow = if cfg!(target_arch = "x86_64") {
            0o400_000
        } else {
            0o100_000
        };
        let mut options = OpenOptions::new();
        options.custom_flags(nofollow | 0o4_000).mode(0o600);
        Ok(options)
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        Err(denied())
    }
}

fn buffer(length: u64) -> io::Result<ReadBuffer> {
    let length = usize::try_from(length).map_err(|_| limit())?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| limit())?;
    bytes.resize(length, 0);
    Ok(ReadBuffer(bytes))
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "scoped archive filesystem authority refused",
    )
}
fn limit() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "scoped archive filesystem limit exceeded",
    )
}
fn changed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "scoped archive input changed")
}
fn native(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), "scoped archive filesystem operation failed")
}

#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use fss_core::{ContentDigest, OperationId, RegionId, RootAuthoritySpec};
    use fss_object::upload_journal::{FileUploadJournal, UploadJournalLimits};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> io::Result<Self> {
            for _ in 0..16 {
                let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("fss-s3-io-{}-{ordinal}", std::process::id(),));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::other("fixture directory exhausted"))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn owner(directory: &Directory, bytes: u64) -> TestResult<ScopedS3Io> {
        owner_with_source(directory, directory.0.join("source"), bytes)
    }

    fn owner_with_source(
        directory: &Directory,
        source: PathBuf,
        bytes: u64,
    ) -> TestResult<ScopedS3Io> {
        let budget = BudgetVector::builder()
            .bytes(bytes)
            .storage_operations(20_000)
            .latency_ms(60_000)
            .build()?;
        let (authority, tree) = AuthorityCx::root(
            RootAuthoritySpec {
                trace_id: "trace:s3-filesystem-test".into(),
                operation_id: OperationId::parse("operation:s3-filesystem-test")?,
                principal: "principal:owner".into(),
                capabilities: [
                    RuntimeGrant::ObjectStage,
                    RuntimeGrant::ReadMedia,
                    RuntimeGrant::AdapterAuth,
                ]
                .into_iter()
                .map(|grant| grant.as_str().to_owned())
                .collect(),
                deadline: Some(TimestampNs(60_000_000_000)),
                priority: 10,
                budgets: budget,
                privacy_scope: "privacy:owner".into(),
                retention_scope: "retention:explicit-upload".into(),
                anchor_universe: ContentDigest::sha256(b"s3-filesystem-test"),
                generation: 1,
            },
            RegionId::new("region:s3-filesystem-test")?,
            RegionKind::Process,
            budget,
            TimestampNs(0),
        )?;
        Ok(ScopedS3Io::new(
            directory.0.join("journal"),
            source,
            directory.0.join("credentials"),
            authority,
            tree,
            Instant::now(),
            TimestampNs(0),
        )?)
    }

    #[test]
    fn source_size_and_byte_budget_refuse_before_payload_allocation_or_read() -> TestResult {
        let directory = Directory::new()?;
        std::fs::write(directory.0.join("source"), b"abc")?;
        let sized = owner(&directory, 1024)?;
        assert!(sized.read_source(4).is_err());
        assert_eq!(sized.consumed()?.bytes, 0);
        let bounded = owner(&directory, 3)?;
        assert!(bounded.read_source(3).is_err()); // needs three bytes and one EOF probe
        assert_eq!(bounded.consumed()?.bytes, 0);
        assert!(bounded.consumed()?.storage_operations > 0);
        Ok(())
    }

    #[test]
    fn fully_preloaded_source_survives_later_path_replacement() -> TestResult {
        let directory = Directory::new()?;
        let source = directory.0.join("source");
        std::fs::write(&source, b"abc")?;
        let io = owner(&directory, 1024)?;
        let retained = io.read_source(3)?;
        let replacement = directory.0.join("replacement");
        std::fs::write(&replacement, b"changed")?;
        std::fs::rename(&replacement, &source)?;
        assert_eq!(retained, b"abc");
        assert_eq!(io.consumed()?.bytes, 4);
        assert!(io.read_source(3).is_err());
        io.finalize()?;
        assert!(io.read_source(7).is_err());
        Ok(())
    }

    #[test]
    fn symlink_ancestors_special_sources_and_foreign_handles_are_refused() -> TestResult {
        use std::os::unix::fs::symlink;
        let directory = Directory::new()?;
        let target = directory.0.join("target");
        std::fs::create_dir(&target)?;
        std::fs::write(target.join("source"), b"a")?;
        symlink(&target, directory.0.join("link"))?;
        let symlinked = owner_with_source(&directory, directory.0.join("link/source"), 1024)?;
        assert!(symlinked.read_source(1).is_err());
        assert_eq!(symlinked.consumed()?.bytes, 0);
        let special = owner_with_source(&directory, target.clone(), 1024)?;
        assert!(special.read_source(0).is_err());
        let io = owner(&directory, 1024)?;
        let mut foreign = File::open(target.join("source"))?;
        assert!(io.read_bounded(&mut foreign, 1).is_err());
        assert!(io.create_new(&directory.0.join("outside")).is_err());
        assert!(!directory.0.join("outside").exists());
        assert_eq!(io.consumed()?.bytes, 0);
        Ok(())
    }

    #[test]
    fn credentials_require_private_permissions_and_a_distinct_file_identity() -> TestResult {
        let directory = Directory::new()?;
        let credential_path = directory.0.join("credentials");
        std::fs::write(&credential_path, b"fixture-access\nfixture-secret\n")?;
        std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o644))?;
        let io = owner(&directory, 1024)?;
        assert!(io.read_credentials().is_err());
        assert_eq!(io.consumed()?.bytes, 0);
        std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::hard_link(&credential_path, directory.0.join("source"))?;
        let source_len = std::fs::metadata(&credential_path)?.len();
        let mut preload = io.read_source(source_len)?;
        preload.fill(0);
        assert!(io.read_credentials().is_err());
        assert_eq!(
            format!("{io:?}"),
            "ScopedS3Io(exact files, bounded journal, owned authority)"
        );
        Ok(())
    }

    #[test]
    fn expired_owner_stops_io_but_can_finalize() -> TestResult {
        let directory = Directory::new()?;
        std::fs::write(directory.0.join("source"), b"a")?;
        let mut io = owner(&directory, 1024)?;
        io.started = Instant::now()
            .checked_sub(Duration::from_secs(61))
            .ok_or("test clock")?;
        assert!(io.read_source(1).is_err());
        assert_eq!(io.consumed()?.bytes, 0);
        io.finalize()?;
        assert!(io.check().is_err());
        Ok(())
    }

    #[test]
    fn native_journal_parent_sync_is_scoped_and_lock_release_precedes_finalize() -> TestResult {
        let directory = Directory::new()?;
        let io = Arc::new(owner(&directory, 1024 * 1024)?);
        let capability: Arc<dyn SpoolIo> = io.clone();
        let journal = FileUploadJournal::create(
            directory.0.join("journal"),
            UploadJournalLimits::default(),
            capability,
        )?;
        assert!(io.finalize().is_err());
        assert!(
            io.sync_directory(directory.0.parent().ok_or("fixture parent")?)
                .is_err()
        );
        drop(journal);
        io.finalize()?;
        assert!(io.check().is_err());
        assert!(io.consumed()?.storage_operations > 0);
        Ok(())
    }
}
