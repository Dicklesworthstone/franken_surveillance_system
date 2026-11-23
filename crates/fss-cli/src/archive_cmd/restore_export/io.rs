#![forbid(unsafe_code)]
//! Private, descriptor-anchored destination with one nonrenewable publication allowance.

use crate::archive_cmd::{ArchiveCommandError, MAX_REPORT_BYTES};
use fss_core::ContentDigest;
use fss_object::{HostSpoolIo, SpoolIo};
use fss_publication::ScopedPublicationIo;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, DirEntry, File, FileType, Metadata, OpenOptions, ReadDir, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

type Result<T> = std::result::Result<T, ArchiveCommandError>;
type Permit = dyn Fn() -> bool + Send + Sync;
const CHUNK: usize = 64 * 1024;
const MAX_COMPONENTS: usize = 256;
const MAX_HANDLES: usize = 256;
const DEADLINE: u8 = 1;
const BYTES: u8 = 2;
const OPERATIONS: u8 = 3;
const SCOPE: u8 = 4;
const INITIALIZATION: u8 = 5;

struct Budget {
    maximum_bytes: u64,
    remaining_bytes: AtomicU64,
    maximum_operations: u64,
    remaining_operations: AtomicU64,
    failure: AtomicU8,
    initialization_error: Mutex<Option<io::ErrorKind>>,
    permit: Arc<Permit>,
}
impl Budget {
    fn refuse(&self, reason: u8) -> io::Error {
        let _ = self
            .failure
            .compare_exchange(0, reason, Ordering::AcqRel, Ordering::Acquire);
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restore destination admission refused",
        )
    }
    fn check(&self) -> io::Result<()> {
        if self.failure.load(Ordering::Acquire) != 0 {
            return Err(self.refuse(self.failure.load(Ordering::Acquire)));
        }
        if !(self.permit)() {
            return Err(self.refuse(DEADLINE));
        }
        Ok(())
    }
    fn operation(&self) -> io::Result<()> {
        self.check()?;
        self.remaining_operations
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .map_err(|_| self.refuse(OPERATIONS))?;
        Ok(())
    }
    fn call<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        self.operation()?;
        let result = operation();
        self.check()?;
        result.map_err(|error| {
            #[cfg(unix)]
            if matches!(
                error.raw_os_error(),
                Some(nix::libc::ELOOP | nix::libc::ENOTDIR)
            ) {
                return self.refuse(SCOPE);
            }
            error
        })
    }
    fn reserve(&self, bytes: u64) -> io::Result<()> {
        self.check()?;
        self.remaining_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_sub(bytes)
            })
            .map(|_| ())
            .map_err(|_| self.refuse(BYTES))
    }
    fn error(&self, operation: &'static str, error: io::Error) -> ArchiveCommandError {
        match self.failure.load(Ordering::Acquire) {
            DEADLINE => ArchiveCommandError::Deadline,
            BYTES => ArchiveCommandError::RestoreBudget("local_bytes"),
            OPERATIONS => ArchiveCommandError::RestoreBudget("local_operations"),
            SCOPE => ArchiveCommandError::OutputScope,
            INITIALIZATION => ArchiveCommandError::Io {
                operation: "pin created restore destination",
                kind: self
                    .initialization_error
                    .lock()
                    .ok()
                    .and_then(|kind| *kind)
                    .unwrap_or(io::ErrorKind::Other),
            },
            _ if error.kind() == io::ErrorKind::AlreadyExists => ArchiveCommandError::OutputExists,
            _ => ArchiveCommandError::Io {
                operation,
                kind: error.kind(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    directory: bool,
}
fn identity(metadata: &Metadata) -> io::Result<Identity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        Ok(Identity {
            device: metadata.dev(),
            inode: metadata.ino(),
            directory: metadata.is_dir(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(io::ErrorKind::Unsupported.into())
    }
}
fn private(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}
fn descriptor(file: &File) -> io::Result<i32> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        Ok(file.as_raw_fd())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        Err(io::ErrorKind::Unsupported.into())
    }
}
fn descriptor_path(file: &File) -> io::Result<PathBuf> {
    Ok(PathBuf::from(format!(
        "/proc/self/fd/{}",
        descriptor(file)?
    )))
}
fn options(directory: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(
            nix::libc::O_NOFOLLOW
                | nix::libc::O_NONBLOCK
                | if directory { nix::libc::O_DIRECTORY } else { 0 },
        );
    }
    #[cfg(not(unix))]
    let _ = directory;
    options
}
fn mkdir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

#[derive(Clone)]
struct Directory {
    name: Option<OsString>,
    file: Arc<File>,
    identity: Identity,
}
fn open_directory(
    budget: &Budget,
    path: &Path,
    name: Option<OsString>,
    require_private: bool,
) -> io::Result<Directory> {
    let named = budget.call(|| fs::symlink_metadata(path))?;
    if !named.is_dir() || (require_private && !private(&named)) {
        return Err(budget.refuse(SCOPE));
    }
    let file = budget.call(|| options(true).open(path))?;
    let opened = budget.call(|| file.metadata())?;
    let after = budget.call(|| fs::symlink_metadata(path))?;
    let expected = identity(&named).map_err(|_| budget.refuse(SCOPE))?;
    if identity(&opened).ok() != Some(expected)
        || identity(&after).ok() != Some(expected)
        || (require_private && (!private(&opened) || !private(&after)))
    {
        return Err(budget.refuse(SCOPE));
    }
    Ok(Directory {
        name,
        file: Arc::new(file),
        identity: expected,
    })
}
fn absolute(budget: &Budget, path: &Path) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > 4096
        || path.components().count() > MAX_COMPONENTS
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(budget.refuse(SCOPE));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        budget.call(std::env::current_dir)?.join(path)
    };
    if absolute.as_os_str().as_encoded_bytes().len() > 4096
        || absolute.components().count() > MAX_COMPONENTS
    {
        return Err(budget.refuse(SCOPE));
    }
    Ok(absolute
        .components()
        .filter(|part| !matches!(part, Component::CurDir))
        .collect())
}
fn ancestors(budget: &Budget, path: &Path) -> io::Result<Vec<Directory>> {
    let mut directories = vec![open_directory(budget, Path::new("/"), None, false)?];
    for part in path.components() {
        if let Component::Normal(name) = part {
            let parent = directories.last().ok_or_else(|| budget.refuse(SCOPE))?;
            let at = descriptor_path(&parent.file)?.join(name);
            directories.push(open_directory(budget, &at, Some(name.to_owned()), false)?);
        }
    }
    Ok(directories)
}
fn check_chain(
    budget: &Budget,
    directories: &[Directory],
    first_path: &Path,
    require_private: bool,
) -> io::Result<()> {
    for (index, directory) in directories.iter().enumerate() {
        let path = if index == 0 {
            first_path.to_path_buf()
        } else {
            descriptor_path(&directories[index - 1].file)?.join(
                directory
                    .name
                    .as_ref()
                    .ok_or_else(|| budget.refuse(SCOPE))?,
            )
        };
        let named = budget
            .call(|| fs::symlink_metadata(&path))
            .map_err(|_| budget.refuse(SCOPE))?;
        let opened = budget
            .call(|| directory.file.metadata())
            .map_err(|_| budget.refuse(SCOPE))?;
        if identity(&named).ok() != Some(directory.identity)
            || identity(&opened).ok() != Some(directory.identity)
            || (require_private && (!private(&named) || !private(&opened)))
        {
            return Err(budget.refuse(SCOPE));
        }
    }
    Ok(())
}

#[derive(Clone)]
struct Handle {
    path: PathBuf,
    identity: Identity,
    writable: bool,
}
struct Resolved {
    logical: PathBuf,
    path: PathBuf,
    directories: Vec<Directory>,
}

pub(super) struct RestoreIo {
    root: PathBuf,
    parents: Vec<Directory>,
    directory: Mutex<Option<Directory>>,
    listings: Mutex<BTreeMap<PathBuf, Directory>>,
    handles: Mutex<BTreeMap<i32, Handle>>,
    locks: Mutex<BTreeSet<i32>>,
    budget: Budget,
    completion_visible: AtomicBool,
    completion_durable: AtomicBool,
}
impl std::fmt::Debug for RestoreIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreIo")
            .field("bytes", &self.bytes())
            .field("operations", &self.operations())
            .finish_non_exhaustive()
    }
}
impl RestoreIo {
    pub(super) fn create(
        output: &Path,
        protected: &[&Path],
        maximum_bytes: u64,
        maximum_operations: u64,
        permit: Arc<Permit>,
    ) -> Result<Arc<Self>> {
        let budget = Budget {
            maximum_bytes,
            remaining_bytes: AtomicU64::new(maximum_bytes),
            maximum_operations,
            remaining_operations: AtomicU64::new(maximum_operations),
            failure: AtomicU8::new(0),
            initialization_error: Mutex::new(None),
            permit,
        };
        let prepare = || -> io::Result<(PathBuf, Vec<Directory>)> {
            if !cfg!(all(target_os = "linux", target_env = "gnu")) {
                return Err(io::ErrorKind::Unsupported.into());
            }
            if maximum_bytes == 0 {
                return Err(budget.refuse(BYTES));
            }
            if maximum_operations == 0 {
                return Err(budget.refuse(OPERATIONS));
            }
            let root = absolute(&budget, output)?;
            // Path::components normalizes trailing dots. Refuse a terminal dot spelling
            // instead of silently selecting its parent as the newly created destination.
            if output
                .as_os_str()
                .as_encoded_bytes()
                .rsplit(|byte| *byte == b'/')
                .find(|part| !part.is_empty())
                .is_none_or(|leaf| leaf == b"." || leaf == b"..")
            {
                return Err(budget.refuse(SCOPE));
            }
            let parent = root.parent().ok_or_else(|| budget.refuse(SCOPE))?;
            if root.file_name().is_none() || protected.len() > 16 {
                return Err(budget.refuse(SCOPE));
            }
            let parents = ancestors(&budget, parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let metadata = budget.call(|| {
                    parents
                        .last()
                        .ok_or_else(|| budget.refuse(SCOPE))?
                        .file
                        .metadata()
                })?;
                if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
                    return Err(budget.refuse(SCOPE));
                }
            }
            for protected in protected {
                let protected = absolute(&budget, protected)?;
                let chain = ancestors(&budget, &protected)?;
                let protected_identity = chain.last().ok_or_else(|| budget.refuse(SCOPE))?.identity;
                if root.starts_with(&protected)
                    || protected.starts_with(&root)
                    || parents
                        .iter()
                        .any(|directory| directory.identity == protected_identity)
                {
                    return Err(budget.refuse(SCOPE));
                }
                check_chain(&budget, &chain, Path::new("/"), false)?;
            }
            check_chain(&budget, &parents, Path::new("/"), false)?;
            let parent = parents.last().ok_or_else(|| budget.refuse(SCOPE))?;
            let target = descriptor_path(&parent.file)?
                .join(root.file_name().ok_or_else(|| budget.refuse(SCOPE))?);
            match budget.call(|| fs::symlink_metadata(&target)) {
                Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            Ok((root, parents))
        };
        let (root, parents) =
            prepare().map_err(|error| budget.error("prepare restore destination", error))?;
        let owner = Arc::new(Self {
            root,
            parents,
            directory: Mutex::new(None),
            listings: Mutex::new(BTreeMap::new()),
            handles: Mutex::new(BTreeMap::new()),
            locks: Mutex::new(BTreeSet::new()),
            budget,
            completion_visible: AtomicBool::new(false),
            completion_durable: AtomicBool::new(false),
        });
        let create = || -> io::Result<()> {
            check_chain(&owner.budget, &owner.parents, Path::new("/"), false)?;
            let target = owner.root_path()?;
            owner.budget.operation()?;
            // Any failure after successful creation is retained by the returned owner.
            mkdir(&target)
        };
        create().map_err(|error| owner.budget.error("create restore destination", error))?;
        let pin = (|| -> io::Result<()> {
            let directory = open_directory(&owner.budget, &owner.root_path()?, None, true)?;
            let mut entries = owner
                .budget
                .call(|| fs::read_dir(descriptor_path(&directory.file)?))?;
            owner.budget.operation()?;
            let first = entries.next().transpose()?;
            owner.budget.check()?;
            if first.is_some() {
                return Err(owner.budget.refuse(SCOPE));
            }
            check_chain(
                &owner.budget,
                std::slice::from_ref(&directory),
                &owner.root_path()?,
                true,
            )?;
            *owner
                .directory
                .lock()
                .map_err(|_| owner.budget.refuse(SCOPE))? = Some(directory);
            check_chain(&owner.budget, &owner.parents, Path::new("/"), false)
        })();
        if let Err(error) = pin {
            if let Ok(mut kind) = owner.budget.initialization_error.lock() {
                *kind = Some(error.kind());
            }
            let _ = owner.budget.refuse(INITIALIZATION);
        }
        // Even a failed pin returns the created owner. It cannot adopt another directory:
        // its refusal is latched, and boundary never initializes a missing root descriptor.
        Ok(owner)
    }
    pub(super) fn root(&self) -> &Path {
        &self.root
    }
    pub(super) fn bytes(&self) -> u64 {
        self.budget.maximum_bytes - self.budget.remaining_bytes.load(Ordering::Acquire)
    }
    pub(super) fn operations(&self) -> u64 {
        self.budget.maximum_operations - self.budget.remaining_operations.load(Ordering::Acquire)
    }
    pub(super) fn completion_visible(&self) -> bool {
        self.completion_visible.load(Ordering::Acquire)
    }
    pub(super) fn completion_durable(&self) -> bool {
        self.completion_durable.load(Ordering::Acquire)
    }
    /// Read the first recorded refusal without a clock probe, filesystem work or new charge.
    pub(super) fn failure(&self) -> Option<ArchiveCommandError> {
        (self.budget.failure.load(Ordering::Acquire) != 0).then(|| {
            self.budget.error(
                "restore destination admission",
                io::ErrorKind::PermissionDenied.into(),
            )
        })
    }
    pub(super) fn check(&self) -> Result<()> {
        self.boundary()
            .map(|_| ())
            .map_err(|error| self.budget.error("check restore destination", error))
    }
    fn root_path(&self) -> io::Result<PathBuf> {
        let parent = self
            .parents
            .last()
            .ok_or_else(|| self.budget.refuse(SCOPE))?;
        Ok(descriptor_path(&parent.file)?.join(
            self.root
                .file_name()
                .ok_or_else(|| self.budget.refuse(SCOPE))?,
        ))
    }
    fn boundary(&self) -> io::Result<Directory> {
        self.budget.check()?;
        check_chain(&self.budget, &self.parents, Path::new("/"), false)?;
        let path = self.root_path()?;
        let pinned = self
            .directory
            .lock()
            .map_err(|_| self.budget.refuse(SCOPE))?;
        let directory = pinned
            .as_ref()
            .ok_or_else(|| self.budget.refuse(SCOPE))?
            .clone();
        check_chain(&self.budget, std::slice::from_ref(&directory), &path, true)?;
        self.budget.check()?;
        Ok(directory)
    }
    fn logical(&self, path: &Path) -> io::Result<PathBuf> {
        if !path.is_absolute()
            || path.as_os_str().as_encoded_bytes().len() > 4096
            || path.components().count() > MAX_COMPONENTS
            || path.components().any(|p| {
                matches!(
                    p,
                    Component::ParentDir | Component::CurDir | Component::Prefix(_)
                )
            })
        {
            return Err(self.budget.refuse(SCOPE));
        }
        if path.starts_with(&self.root) {
            return Ok(path.to_path_buf());
        }
        let listings = self
            .listings
            .lock()
            .map_err(|_| self.budget.refuse(SCOPE))?;
        for (logical, directory) in listings.iter() {
            if let Ok(relative) = path.strip_prefix(descriptor_path(&directory.file)?) {
                return Ok(logical.join(relative));
            }
        }
        Err(self.budget.refuse(SCOPE))
    }
    fn resolve(&self, path: &Path) -> io::Result<Resolved> {
        let root = self.boundary()?;
        let logical = self.logical(path)?;
        let relative = logical
            .strip_prefix(&self.root)
            .map_err(|_| self.budget.refuse(SCOPE))?;
        let mut directories = vec![root];
        let parts: Vec<_> = relative.components().collect();
        for part in parts.iter().take(parts.len().saturating_sub(1)) {
            let Component::Normal(name) = part else {
                return Err(self.budget.refuse(SCOPE));
            };
            let parent = directories
                .last()
                .ok_or_else(|| self.budget.refuse(SCOPE))?;
            let at = descriptor_path(&parent.file)?.join(name);
            directories.push(open_directory(
                &self.budget,
                &at,
                Some((*name).to_owned()),
                true,
            )?);
        }
        let path = if let Some(Component::Normal(name)) = parts.last() {
            descriptor_path(
                &directories
                    .last()
                    .ok_or_else(|| self.budget.refuse(SCOPE))?
                    .file,
            )?
            .join(name)
        } else {
            self.root_path()?
        };
        Ok(Resolved {
            logical,
            path,
            directories,
        })
    }
    fn settled(&self, resolved: &Resolved) -> io::Result<()> {
        self.boundary()?;
        check_chain(
            &self.budget,
            &resolved.directories,
            &self.root_path()?,
            true,
        )
    }
    fn at<T>(&self, path: &Path, operation: impl FnOnce(&Path) -> io::Result<T>) -> io::Result<T> {
        let resolved = self.resolve(path)?;
        let result = self.budget.call(|| operation(&resolved.path));
        self.settled(&resolved)?;
        result
    }
    fn inspect(&self, path: &Path) -> io::Result<Metadata> {
        let metadata = self.at(path, |at| fs::symlink_metadata(at))?;
        if identity(&metadata).is_err() || !private(&metadata) {
            return Err(self.budget.refuse(SCOPE));
        }
        Ok(metadata)
    }
    fn register(&self, file: &File, path: PathBuf, writable: bool) -> io::Result<()> {
        let metadata = self.budget.call(|| file.metadata())?;
        let expected = identity(&metadata).map_err(|_| self.budget.refuse(SCOPE))?;
        if expected.directory || !private(&metadata) {
            return Err(self.budget.refuse(SCOPE));
        }
        let mut handles = self.handles.lock().map_err(|_| self.budget.refuse(SCOPE))?;
        let descriptor = descriptor(file)?;
        if handles.len() >= MAX_HANDLES && !handles.contains_key(&descriptor) {
            return Err(self.budget.refuse(OPERATIONS));
        }
        handles.insert(
            descriptor,
            Handle {
                path,
                identity: expected,
                writable,
            },
        );
        Ok(())
    }
    fn file(&self, file: &File, write: bool) -> io::Result<Metadata> {
        self.boundary()?;
        let handle = self
            .handles
            .lock()
            .map_err(|_| self.budget.refuse(SCOPE))?
            .get(&descriptor(file)?)
            .cloned()
            .ok_or_else(|| self.budget.refuse(SCOPE))?;
        let opened = self.budget.call(|| file.metadata())?;
        let named = self.inspect(&handle.path)?;
        if (write && !handle.writable)
            || identity(&opened).ok() != Some(handle.identity)
            || identity(&named).ok() != Some(handle.identity)
            || !private(&opened)
        {
            return Err(self.budget.refuse(SCOPE));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if write && opened.nlink() != 1 {
                return Err(self.budget.refuse(SCOPE));
            }
        }
        Ok(opened)
    }
    fn open_file(&self, path: &Path, writable: bool, create: bool) -> io::Result<File> {
        let logical = self.logical(path)?;
        let file = self.at(path, |at| {
            let mut options = options(false);
            options.write(writable).create_new(create);
            options.open(at)
        })?;
        self.register(&file, logical, writable)?;
        self.file(&file, writable)?;
        Ok(file)
    }
    fn lock(&self, file: &File, shared: bool) -> std::result::Result<(), TryLockError> {
        let metadata = self.file(file, false).map_err(TryLockError::Error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(TryLockError::Error(self.budget.refuse(SCOPE)));
            }
        }
        #[cfg(not(unix))]
        let _ = metadata;
        self.budget.operation().map_err(TryLockError::Error)?;
        let acquired = if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        };
        if let Err(error) = acquired {
            self.budget.check().map_err(TryLockError::Error)?;
            return Err(error);
        }
        let settled = (|| {
            self.budget.check()?;
            self.file(file, false)?;
            self.locks
                .lock()
                .map_err(|_| self.budget.refuse(SCOPE))?
                .insert(descriptor(file)?);
            Ok(())
        })();
        if let Err(error) = settled {
            let _ = HostSpoolIo.unlock(file);
            return Err(TryLockError::Error(error));
        }
        Ok(())
    }
    pub(super) fn write_completion(&self, bytes: &[u8]) -> Result<ContentDigest> {
        let write = || -> io::Result<ContentDigest> {
            if bytes.is_empty() || bytes.len() > MAX_REPORT_BYTES {
                return Err(self.budget.refuse(BYTES));
            }
            if self.completion_visible() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            let reservation = (bytes.len() as u64)
                .checked_mul(3)
                .and_then(|n| n.checked_add(2))
                .ok_or_else(|| self.budget.refuse(BYTES))?;
            if reservation > self.budget.remaining_bytes.load(Ordering::Acquire) {
                return Err(self.budget.refuse(BYTES));
            }
            let pending = self.root.join("RESTORE_COMPLETE.json.pending");
            let complete = self.root.join("RESTORE_COMPLETE.json");
            let mut file = self.create_new(&pending)?;
            let mut offset = 0;
            let mut interrupted = 0;
            while offset < bytes.len() {
                match self.write(&mut file, &bytes[offset..]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(count) => {
                        offset += count;
                        interrupted = 0;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 7 => {
                        interrupted += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
            self.sync_file(&file)?;
            self.budget.call(|| file.seek(SeekFrom::Start(0)))?;
            if self.read_bounded(&mut file, bytes.len() as u64 + 1)? != bytes {
                return Err(self.budget.refuse(SCOPE));
            }
            let digest = ContentDigest::try_sha256(bytes).map_err(|_| self.budget.refuse(BYTES))?;
            let from = self.resolve(&pending)?;
            let to = self.resolve(&complete)?;
            self.budget.operation()?;
            let linked = fs::hard_link(&from.path, &to.path);
            if linked.is_ok() {
                self.completion_visible.store(true, Ordering::Release);
            }
            self.budget.check()?;
            linked?;
            self.settled(&from)?;
            self.settled(&to)?;
            self.sync_directory(&self.root)?;
            let parent = self
                .parents
                .last()
                .ok_or_else(|| self.budget.refuse(SCOPE))?;
            self.budget.call(|| parent.file.sync_all())?;
            self.boundary()?;
            self.file(&file, false)?;
            if identity(&self.inspect(&complete)?).ok() != identity(&self.file(&file, false)?).ok()
            {
                return Err(self.budget.refuse(SCOPE));
            }
            self.budget.call(|| file.seek(SeekFrom::Start(0)))?;
            if self.read_bounded(&mut file, bytes.len() as u64 + 1)? != bytes {
                return Err(self.budget.refuse(SCOPE));
            }
            self.completion_durable.store(true, Ordering::Release);
            Ok(digest)
        };
        write().map_err(|error| self.budget.error("publish restore completion", error))
    }
}

impl ScopedPublicationIo for RestoreIo {
    fn check_scope(&self, root: &Path) -> io::Result<()> {
        if root != self.root {
            return Err(self.budget.refuse(SCOPE));
        }
        self.boundary().map(|_| ())
    }
}
impl SpoolIo for RestoreIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        let logical = self.logical(path)?;
        self.boundary()?;
        let mut current = self.root.clone();
        for part in logical
            .strip_prefix(&self.root)
            .map_err(|_| self.budget.refuse(SCOPE))?
            .components()
        {
            current.push(part);
            match self.create_dir(&current) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if !self.inspect(&current)?.is_dir() {
                        return Err(self.budget.refuse(SCOPE));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        self.at(path, mkdir)
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.inspect(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.inspect(path)
    }
    fn open_lock(&self, path: &Path) -> io::Result<File> {
        match self.open_file(path, true, true) {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.open_file(path, true, false)
            }
            Err(error) => Err(error),
        }
    }
    fn try_lock(&self, file: &File) -> std::result::Result<(), TryLockError> {
        self.lock(file, false)
    }
    fn try_lock_shared(&self, file: &File) -> std::result::Result<(), TryLockError> {
        self.lock(file, true)
    }
    fn unlock(&self, file: &File) -> io::Result<()> {
        // Releasing an admitted lock never requires renewed time or resource authority.
        let fd = descriptor(file)?;
        let admitted = self
            .locks
            .lock()
            .map_err(|_| io::Error::from(io::ErrorKind::Other))?
            .remove(&fd);
        if !admitted {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        HostSpoolIo.unlock(file)
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        let resolved = self.resolve(path)?;
        let directory = open_directory(&self.budget, &resolved.path, None, true)?;
        let logical = resolved.logical.clone();
        let mut listings = self
            .listings
            .lock()
            .map_err(|_| self.budget.refuse(SCOPE))?;
        if listings.len() >= MAX_HANDLES && !listings.contains_key(&logical) {
            return Err(self.budget.refuse(OPERATIONS));
        }
        let pinned = listings.entry(logical).or_insert(directory);
        let named = self.budget.call(|| fs::symlink_metadata(&resolved.path))?;
        if identity(&named).ok() != Some(pinned.identity) {
            return Err(self.budget.refuse(SCOPE));
        }
        let entries = self
            .budget
            .call(|| fs::read_dir(descriptor_path(&pinned.file)?))?;
        drop(listings);
        self.settled(&resolved)?;
        Ok(entries)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        let next = (|| {
            self.boundary()?;
            self.budget.operation()?;
            let entry = entries.next().transpose()?;
            self.budget.check()?;
            if let Some(entry) = &entry {
                self.logical(&entry.path())?;
            }
            Ok(entry)
        })();
        match next {
            Ok(entry) => entry.map(Ok),
            Err(error) => Some(Err(error)),
        }
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        Ok(self.inspect(&entry.path())?.file_type())
    }
    fn create_new(&self, path: &Path) -> io::Result<File> {
        self.open_file(path, true, true)
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.open_file(path, false, false)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.file(file, true)?;
        let bytes = &bytes[..bytes.len().min(CHUNK)];
        self.budget.reserve(bytes.len() as u64)?;
        let result = self.budget.call(|| file.write(bytes));
        if let Ok(count) = result {
            self.budget
                .remaining_bytes
                .fetch_add((bytes.len() - count) as u64, Ordering::AcqRel);
        }
        self.file(file, true)?;
        result
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.file(file, false)?;
        self.budget.call(|| file.sync_all())?;
        self.file(file, false).map(|_| ())
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        let before = self.file(file, false)?;
        // Pin the observed size plus EOF before allocating. The account is shared by every
        // Arc user; a concurrent read cannot allocate against this same reservation. A size
        // change is refused below, and this call never reads beyond its reserved allowance.
        let reservation = limit.min(before.len().saturating_add(1));
        self.budget.reserve(reservation)?;
        let capacity = usize::try_from(before.len().min(reservation))
            .map_err(|_| self.budget.refuse(BYTES))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| self.budget.refuse(BYTES))?;
        let mut scratch = [0_u8; CHUNK];
        let mut interrupted = 0;
        while (bytes.len() as u64) < reservation {
            let take = (reservation - bytes.len() as u64).min(CHUNK as u64) as usize;
            match self.budget.call(|| file.read(&mut scratch[..take])) {
                Ok(count) => {
                    if count == 0 {
                        break;
                    }
                    bytes
                        .try_reserve(count)
                        .map_err(|_| self.budget.refuse(BYTES))?;
                    bytes.extend_from_slice(&scratch[..count]);
                    interrupted = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 7 => {
                    interrupted += 1;
                }
                Err(error) => return Err(error),
            }
        }
        let after = self.file(file, false)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(self.budget.refuse(SCOPE));
            }
        }
        // Only a fully completed, identity/stamp-checked read returns its unused allowance.
        // Any earlier failure retains the whole reservation because effects may be unknown.
        self.budget
            .remaining_bytes
            .fetch_add(reservation - bytes.len() as u64, Ordering::AcqRel);
        Ok(bytes)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inspect(from)?;
        let from = self.resolve(from)?;
        let to = self.resolve(to)?;
        if from.logical == self.root || to.logical == self.root {
            return Err(self.budget.refuse(SCOPE));
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let result = self.budget.call(|| {
            use nix::fcntl::{RenameFlags, renameat2};
            let source = from
                .directories
                .last()
                .ok_or_else(|| self.budget.refuse(SCOPE))?;
            let target = to
                .directories
                .last()
                .ok_or_else(|| self.budget.refuse(SCOPE))?;
            renameat2(
                source.file.as_ref(),
                from.path
                    .file_name()
                    .ok_or_else(|| self.budget.refuse(SCOPE))?,
                target.file.as_ref(),
                to.path
                    .file_name()
                    .ok_or_else(|| self.budget.refuse(SCOPE))?,
                RenameFlags::RENAME_NOREPLACE,
            )
            .map_err(io::Error::from)
        });
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        let result = Err(io::Error::from(io::ErrorKind::Unsupported));
        self.settled(&from)?;
        self.settled(&to)?;
        result
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.inspect(path)?;
        self.at(path, |at| fs::remove_file(at))
    }
    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        let resolved = self.resolve(path)?;
        let directory = open_directory(&self.budget, &resolved.path, None, true)?;
        self.budget.call(|| directory.file.sync_all())?;
        self.settled(&resolved)
    }
    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inspect(from)?;
        let from = self.resolve(from)?;
        let to = self.resolve(to)?;
        let result = self.budget.call(|| fs::hard_link(&from.path, &to.path));
        self.settled(&from)?;
        self.settled(&to)?;
        result
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;
    use fss_object::{ObjectManifest, SpoolLimits};
    use fss_publication::{LocalPublicationLimits, LocalRootPublisher, SlotName};
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::sync::Weak;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn parent(label: &str) -> io::Result<PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "fss-restore-io-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        mkdir(&path)?;
        Ok(path)
    }
    fn limits() -> LocalPublicationLimits {
        LocalPublicationLimits::new(
            16,
            32,
            16,
            128,
            SpoolLimits::new(128, 1024 * 1024, 4096, 256),
        )
    }
    fn create(root: &Path) -> Result<Arc<RestoreIo>> {
        RestoreIo::create(root, &[], 4 * 1024 * 1024, 200_000, Arc::new(|| true))
    }

    #[test]
    fn real_native_owner_migrates_holds_publishes_and_cold_reopens_before_completion() -> TestResult
    {
        let root = parent("native")?.join("restored");
        let io = create(&root)?;
        io.check()?;
        let mut publisher = LocalRootPublisher::open_scoped(io.root(), limits(), io.clone())?;
        let leaf = publisher.stage_object(b"independently verified original bytes")?;
        let manifest = ObjectManifest::new("restored-recording-fixture", [leaf], None)?;
        let slot = SlotName::parse("restored-window")?;
        let receipt = publisher.publish(&slot, &manifest)?;
        assert_eq!(receipt.root, manifest.root());
        let first_operations = io.operations();
        let first_bytes = io.bytes();
        drop(publisher);
        let publisher = LocalRootPublisher::open_scoped(io.root(), limits(), io.clone())?;
        assert_eq!(
            publisher.root(&slot).ok_or("missing restored root")?.root,
            manifest.root()
        );
        assert_eq!(
            publisher.spool().read(leaf)?,
            b"independently verified original bytes"
        );
        assert!(io.operations() > first_operations);
        assert!(io.bytes() > first_bytes);
        drop(publisher);
        let completion = b"{\"complete\":true,\"original_catalog_reconstructed\":false}\n";
        assert_eq!(
            io.write_completion(completion)?,
            ContentDigest::sha256(completion)
        );
        assert!(io.completion_visible());
        assert!(io.completion_durable());
        assert_eq!(fs::read(root.join("RESTORE_COMPLETE.json"))?, completion);
        assert_eq!(fs::metadata(&root)?.mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(root.join("RESTORE_COMPLETE.json"))?.mode() & 0o777,
            0o600
        );
        assert!(matches!(
            io.write_completion(b"replacement"),
            Err(ArchiveCommandError::OutputExists)
        ));
        assert_eq!(fs::read(root.join("RESTORE_COMPLETE.json"))?, completion);
        Ok(())
    }

    #[test]
    fn revocation_is_latched_and_native_locks_still_release() -> TestResult {
        let root = parent("revocation")?.join("restored");
        let live = Arc::new(AtomicBool::new(true));
        let current = live.clone();
        let io = RestoreIo::create(
            &root,
            &[],
            4 * 1024 * 1024,
            200_000,
            Arc::new(move || current.load(Ordering::Acquire)),
        )?;
        let mut publisher = LocalRootPublisher::open_scoped(io.root(), limits(), io.clone())?;
        let leaf = publisher.stage_object(b"retained before revocation")?;
        live.store(false, Ordering::Release);
        assert!(publisher.spool().read(leaf).is_err());
        assert!(matches!(io.check(), Err(ArchiveCommandError::Deadline)));
        let operations = io.operations();
        let bytes = io.bytes();
        assert!(matches!(io.failure(), Some(ArchiveCommandError::Deadline)));
        assert_eq!(io.operations(), operations);
        assert_eq!(io.bytes(), bytes);
        live.store(true, Ordering::Release);
        assert!(publisher.stage_object(b"refused after revocation").is_err());
        assert!(matches!(io.check(), Err(ArchiveCommandError::Deadline)));
        drop(publisher);
        // A separately admitted owner can take both locks after the denied owner retires.
        assert_eq!(
            LocalRootPublisher::open(&root, limits())?
                .spool()
                .read(leaf)?,
            b"retained before revocation"
        );
        Ok(())
    }

    #[test]
    fn operation_refusal_precedes_creation_and_byte_refusal_preserves_partial_owner() -> TestResult
    {
        let directory = parent("budgets")?;
        let absent = directory.join("not-created");
        assert!(matches!(
            RestoreIo::create(&absent, &[], 1024, 1, Arc::new(|| true)),
            Err(ArchiveCommandError::RestoreBudget("local_operations"))
        ));
        assert!(!absent.exists());
        let root = directory.join("created");
        let io = RestoreIo::create(&root, &[], 64, 200_000, Arc::new(|| true))?;
        let mut publisher = LocalRootPublisher::open_scoped(io.root(), limits(), io.clone())?;
        assert!(publisher.stage_object(&[0x42; 256]).is_err());
        assert!(matches!(
            io.check(),
            Err(ArchiveCommandError::RestoreBudget("local_bytes"))
        ));
        assert!(io.bytes() <= 64);
        assert!(!io.completion_visible());
        assert!(!io.completion_durable());
        Ok(())
    }

    #[test]
    fn protected_inputs_symlink_parents_and_replaced_roots_are_never_adopted() -> TestResult {
        let directory = parent("paths")?;
        let input = directory.join("input");
        mkdir(&input)?;
        let nested = input.join("nested");
        assert!(matches!(
            RestoreIo::create(&nested, &[&input], 1024, 10_000, Arc::new(|| true)),
            Err(ArchiveCommandError::OutputScope)
        ));
        assert!(!nested.exists());
        let alias = directory.join("alias");
        symlink(&input, &alias)?;
        assert!(matches!(
            RestoreIo::create(&alias.join("nested"), &[], 1024, 10_000, Arc::new(|| true)),
            Err(ArchiveCommandError::OutputScope)
        ));
        let dotted = directory.join("unexpected").join(".");
        assert!(matches!(
            RestoreIo::create(&dotted, &[], 1024, 10_000, Arc::new(|| true)),
            Err(ArchiveCommandError::OutputScope)
        ));
        assert!(!directory.join("unexpected").exists());
        let root = directory.join("restored");
        let io = create(&root)?;
        fs::rename(&root, directory.join("original-root"))?;
        mkdir(&root)?;
        assert!(matches!(io.check(), Err(ArchiveCommandError::OutputScope)));
        assert!(io.create_new(&root.join("refused")).is_err());
        assert!(!root.join("refused").exists());
        Ok(())
    }

    #[test]
    fn whole_read_reservation_refuses_before_consuming_bytes_and_never_refills_the_account()
    -> TestResult {
        let root = parent("read-reservation")?.join("restored");
        let io = RestoreIo::create(&root, &[], 80, 100_000, Arc::new(|| true))?;
        let mut file = io.create_new(&root.join("payload"))?;
        assert_eq!(io.write(&mut file, &[0x41; 32])?, 32);
        file.seek(SeekFrom::Start(0))?;
        assert_eq!(io.read_bounded(&mut file, 4096)?, vec![0x41; 32]);
        assert_eq!(io.bytes(), 64);
        file.seek(SeekFrom::Start(0))?;
        assert!(io.read_bounded(&mut file, 4096).is_err());
        assert_eq!(file.stream_position()?, 0);
        assert_eq!(io.bytes(), 64);
        assert!(matches!(
            io.check(),
            Err(ArchiveCommandError::RestoreBudget("local_bytes"))
        ));
        Ok(())
    }

    #[test]
    fn native_rename_never_replaces_an_existing_file_or_directory() -> TestResult {
        let root = parent("no-replace")?.join("restored");
        let io = create(&root)?;
        for (name, payload) in [
            ("source", b"source".as_slice()),
            ("target", b"target".as_slice()),
        ] {
            let mut file = io.create_new(&root.join(name))?;
            assert_eq!(io.write(&mut file, payload)?, payload.len());
        }
        assert_eq!(
            io.rename(&root.join("source"), &root.join("target"))
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(root.join("source"))?, b"source");
        assert_eq!(fs::read(root.join("target"))?, b"target");
        io.create_dir(&root.join("directory-source"))?;
        io.create_dir(&root.join("directory-target"))?;
        assert_eq!(
            io.rename(
                &root.join("directory-source"),
                &root.join("directory-target")
            )
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        io.check()?;
        Ok(())
    }

    #[test]
    fn expiry_after_mkdir_returns_the_created_owner_with_a_latched_refusal() -> TestResult {
        let root = parent("pin-expiry")?.join("restored");
        let observed = root.clone();
        // Test-only phase trigger: the production permit is the caller's live operation clock.
        let io = RestoreIo::create(
            &root,
            &[],
            1024,
            10_000,
            Arc::new(move || !observed.exists()),
        )?;
        assert!(root.is_dir());
        assert!(matches!(io.check(), Err(ArchiveCommandError::Deadline)));
        assert!(io.create_new(&root.join("refused")).is_err());
        assert_eq!(fs::read_dir(&root)?.count(), 0);
        Ok(())
    }

    #[test]
    fn expiry_after_completion_link_reports_visibility_without_durability() -> TestResult {
        let root = parent("completion-cut")?.join("restored");
        let observed = Arc::new(Mutex::new(None::<Weak<RestoreIo>>));
        let probe = observed.clone();
        let permit: Arc<Permit> = Arc::new(move || {
            probe
                .lock()
                .ok()
                .and_then(|owner| owner.as_ref().and_then(Weak::upgrade))
                .is_none_or(|owner| !owner.completion_visible())
        });
        let io = RestoreIo::create(&root, &[], 1024 * 1024, 100_000, permit)?;
        *observed.lock().map_err(|_| "phase trigger poisoned")? = Some(Arc::downgrade(&io));
        let completion = b"{\"complete\":true}\n";
        assert!(matches!(
            io.write_completion(completion),
            Err(ArchiveCommandError::Deadline)
        ));
        assert!(io.completion_visible());
        assert!(!io.completion_durable());
        assert_eq!(fs::read(root.join("RESTORE_COMPLETE.json"))?, completion);
        Ok(())
    }
}
