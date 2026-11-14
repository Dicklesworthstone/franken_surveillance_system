#![forbid(unsafe_code)]
//! Descriptor-anchored, read-only Linux bundle access with one cumulative allowance.

use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Component, PathBuf};

use super::*;

const CHUNK: usize = 64 * 1024;
const MAX_INTERRUPTS: usize = 8;
const MAX_COMPONENTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    len: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
    directory: bool,
}
impl Stamp {
    fn read(metadata: &Metadata) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !metadata.file_type().is_file() && !metadata.file_type().is_dir() {
                return Err(ExportVerificationError::UnsafePath);
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                len: metadata.len(),
                mode: metadata.mode(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                directory: metadata.file_type().is_dir(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(ExportVerificationError::UnsupportedPlatform)
        }
    }
    fn same_identity(self, other: Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.directory == other.directory
    }
}

struct Directory {
    name: Option<OsString>,
    file: File,
    stamp: Stamp,
}

struct Budget<'a> {
    clock: &'a dyn Clock,
    limits: Limits,
    reads: u64,
    calls: u64,
}
impl Budget<'_> {
    fn operation(&mut self) -> Result<()> {
        self.clock.check()?;
        if self.calls >= self.limits.io_calls {
            return Err(ExportVerificationError::Limit("io_calls"));
        }
        self.calls += 1;
        Ok(())
    }
    fn reserve_read(&mut self, bytes: u64) -> Result<()> {
        self.clock.check()?;
        if bytes > self.limits.read_bytes.saturating_sub(self.reads) {
            return Err(ExportVerificationError::Limit("read_bytes"));
        }
        // Includes the bounded EOF probe. A failed read conservatively retains its reservation.
        self.reads += bytes;
        Ok(())
    }
}

pub(super) struct Reader<'a> {
    directories: Vec<Directory>,
    root_stamp: Option<Stamp>,
    inventory: BTreeMap<String, Stamp>,
    file_bytes: u64,
    budget: Budget<'a>,
}
impl<'a> Reader<'a> {
    pub fn open(root: &Path, limits: Limits, clock: &'a dyn Clock) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(ExportVerificationError::UnsupportedPlatform);
        }
        let mut reader = Self {
            directories: Vec::new(),
            root_stamp: None,
            inventory: BTreeMap::new(),
            file_bytes: 0,
            budget: Budget {
                clock,
                limits,
                reads: 0,
                calls: 0,
            },
        };
        clock.check()?;
        if root.as_os_str().as_encoded_bytes().len() > 4096 || root.as_os_str().is_empty() {
            return Err(ExportVerificationError::UnsafePath);
        }
        let root = if root.is_absolute() {
            root.to_path_buf()
        } else {
            reader.budget.operation()?;
            std::env::current_dir().map_err(host)?.join(root)
        };
        if root.components().count() > MAX_COMPONENTS
            || root
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(ExportVerificationError::UnsafePath);
        }
        reader.open_directory(Path::new("/"), None)?;
        for component in root.components() {
            if let Component::Normal(name) = component {
                let parent = reader.directory_path()?;
                reader.open_directory(&parent.join(name), Some(name.to_owned()))?;
            }
        }
        reader.check_directories()?;
        reader.budget.operation()?;
        let metadata = reader
            .directories
            .last()
            .ok_or(ExportVerificationError::UnsafePath)?
            .file
            .metadata()
            .map_err(host)?;
        reader.root_stamp = Some(Stamp::read(&metadata)?);
        let inventory = reader.scan()?;
        let mut total = 0_u64;
        for stamp in inventory.values() {
            total = total
                .checked_add(stamp.len)
                .ok_or(ExportVerificationError::Limit("file_bytes"))?;
            if total > limits.file_bytes {
                return Err(ExportVerificationError::Limit("file_bytes"));
            }
        }
        reader.inventory = inventory;
        reader.file_bytes = total;
        Ok(reader)
    }

    fn open_directory(&mut self, path: &Path, name: Option<OsString>) -> Result<()> {
        self.budget.operation()?;
        let named = Stamp::read(&fs::symlink_metadata(path).map_err(host)?)?;
        if !named.directory {
            return Err(ExportVerificationError::UnsafePath);
        }
        self.budget.operation()?;
        let file = options(true).open(path).map_err(host)?;
        self.budget.operation()?;
        let opened = Stamp::read(&file.metadata().map_err(host)?)?;
        self.budget.operation()?;
        let after = Stamp::read(&fs::symlink_metadata(path).map_err(host)?)?;
        if !named.same_identity(opened) || !opened.same_identity(after) {
            return Err(ExportVerificationError::Changed);
        }
        self.directories.push(Directory {
            name,
            file,
            stamp: opened,
        });
        Ok(())
    }

    fn directory_path(&self) -> Result<PathBuf> {
        descriptor_path(
            &self
                .directories
                .last()
                .ok_or(ExportVerificationError::UnsafePath)?
                .file,
        )
    }

    fn check_directories(&mut self) -> Result<()> {
        for index in 0..self.directories.len() {
            self.budget.operation()?;
            let opened = Stamp::read(&self.directories[index].file.metadata().map_err(host)?)?;
            if !opened.same_identity(self.directories[index].stamp) {
                return Err(ExportVerificationError::Changed);
            }
            let path = if index == 0 {
                PathBuf::from("/")
            } else {
                descriptor_path(&self.directories[index - 1].file)?.join(
                    self.directories[index]
                        .name
                        .as_ref()
                        .ok_or(ExportVerificationError::UnsafePath)?,
                )
            };
            self.budget.operation()?;
            let named = Stamp::read(&fs::symlink_metadata(path).map_err(changed_host)?)?;
            if !opened.same_identity(named) {
                return Err(ExportVerificationError::Changed);
            }
            if index + 1 == self.directories.len()
                && self.root_stamp.is_some_and(|initial| initial != opened)
            {
                return Err(ExportVerificationError::Changed);
            }
        }
        Ok(())
    }

    fn scan(&mut self) -> Result<BTreeMap<String, Stamp>> {
        self.check_directories()?;
        let root = self.directory_path()?;
        self.budget.operation()?;
        let mut entries = fs::read_dir(&root).map_err(host)?;
        let mut found = BTreeMap::new();
        loop {
            self.budget.operation()?;
            let Some(entry) = entries.next() else { break };
            let entry = entry.map_err(host)?;
            if found.len() >= self.budget.limits.files {
                return Err(ExportVerificationError::Limit("files"));
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ExportVerificationError::UnsafePath)?;
            if name.is_empty()
                || name.len() > 160
                || name.contains('/')
                || name.contains('\\')
                || name == "."
                || name == ".."
            {
                return Err(ExportVerificationError::UnsafePath);
            }
            self.budget.operation()?;
            let stamp = Stamp::read(&fs::symlink_metadata(root.join(&name)).map_err(host)?)?;
            if stamp.directory {
                return Err(ExportVerificationError::UnsafePath);
            }
            if found.insert(name, stamp).is_some() {
                return Err(ExportVerificationError::Changed);
            }
        }
        self.check_directories()?;
        Ok(found)
    }

    pub fn check(&self) -> Result<()> {
        self.budget.clock.check()
    }
    pub fn contains(&self, name: &str) -> bool {
        self.inventory.contains_key(name)
    }
    pub fn file_bytes(&self) -> u64 {
        self.file_bytes
    }
    pub fn charged_read_bytes(&self) -> u64 {
        self.budget.reads
    }
    pub fn io_calls(&self) -> u64 {
        self.budget.calls
    }

    pub fn require_length(&self, name: &str, bytes: u64) -> Result<()> {
        let stamp = self
            .inventory
            .get(name)
            .ok_or(ExportVerificationError::MissingFile)?;
        if stamp.len != bytes {
            return Err(ExportVerificationError::Integrity);
        }
        Ok(())
    }
    pub fn require_inventory(&self, expected: &BTreeSet<String>) -> Result<()> {
        if expected
            .iter()
            .any(|name| !self.inventory.contains_key(name))
        {
            return Err(ExportVerificationError::MissingFile);
        }
        if !self.inventory.keys().eq(expected.iter()) {
            return Err(ExportVerificationError::InventoryMismatch);
        }
        Ok(())
    }
    pub fn recheck_inventory(&mut self) -> Result<()> {
        if self.scan()? != self.inventory {
            return Err(ExportVerificationError::Changed);
        }
        Ok(())
    }

    pub fn read(&mut self, name: &str, cap: usize, expected_len: Option<u64>) -> Result<Vec<u8>> {
        self.check_directories()?;
        let expected = *self
            .inventory
            .get(name)
            .ok_or(ExportVerificationError::MissingFile)?;
        if expected.len > cap as u64 {
            return Err(ExportVerificationError::Limit("file_read_bytes"));
        }
        if expected_len.is_some_and(|len| len != expected.len) {
            return Err(ExportVerificationError::Integrity);
        }
        let path = self.directory_path()?.join(name);
        self.budget.operation()?;
        let named = Stamp::read(&fs::symlink_metadata(&path).map_err(changed_host)?)?;
        if named != expected {
            return Err(ExportVerificationError::Changed);
        }
        self.budget.operation()?;
        let mut file = options(false).open(&path).map_err(host)?;
        self.budget.operation()?;
        if Stamp::read(&file.metadata().map_err(host)?)? != expected {
            return Err(ExportVerificationError::Changed);
        }
        self.budget.reserve_read(
            expected
                .len
                .checked_add(1)
                .ok_or(ExportVerificationError::Limit("read_bytes"))?,
        )?;
        let length = usize::try_from(expected.len)
            .map_err(|_| ExportVerificationError::Limit("file_read_bytes"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ExportVerificationError::Limit("allocation"))?;
        bytes.resize(length, 0);
        let mut offset = 0;
        let mut interrupted = 0;
        while offset < length {
            self.budget.operation()?;
            let end = length.min(offset.saturating_add(CHUNK));
            match file.read(&mut bytes[offset..end]) {
                Ok(0) => return Err(ExportVerificationError::Changed),
                Ok(count) => {
                    offset += count;
                    interrupted = 0;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::Interrupted
                        && interrupted + 1 < MAX_INTERRUPTS =>
                {
                    interrupted += 1;
                }
                Err(error) => return Err(host(error)),
            }
        }
        let mut probe = [0_u8; 1];
        let mut interrupted = 0;
        loop {
            self.budget.operation()?;
            match file.read(&mut probe) {
                Ok(0) => break,
                Ok(_) => return Err(ExportVerificationError::Changed),
                Err(error)
                    if error.kind() == std::io::ErrorKind::Interrupted
                        && interrupted + 1 < MAX_INTERRUPTS =>
                {
                    interrupted += 1;
                }
                Err(error) => return Err(host(error)),
            }
        }
        self.budget.operation()?;
        let opened = Stamp::read(&file.metadata().map_err(host)?)?;
        self.budget.operation()?;
        let named = Stamp::read(&fs::symlink_metadata(&path).map_err(changed_host)?)?;
        if opened != expected || named != expected {
            return Err(ExportVerificationError::Changed);
        }
        self.check_directories()?;
        Ok(bytes)
    }
}

fn host(error: std::io::Error) -> ExportVerificationError {
    ExportVerificationError::Io(error.kind())
}
fn changed_host(error: std::io::Error) -> ExportVerificationError {
    if error.kind() == std::io::ErrorKind::NotFound {
        ExportVerificationError::Changed
    } else {
        host(error)
    }
}
fn descriptor_path(file: &File) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        Ok(PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        Err(ExportVerificationError::UnsupportedPlatform)
    }
}
fn options(directory: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            nix::libc::O_NOFOLLOW
                | nix::libc::O_NONBLOCK
                | if directory { nix::libc::O_DIRECTORY } else { 0 },
        );
    }
    #[cfg(not(unix))]
    let _ = directory;
    options
}
