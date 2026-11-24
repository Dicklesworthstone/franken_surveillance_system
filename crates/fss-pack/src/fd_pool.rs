#![forbid(unsafe_code)]
//! Strict bounded LRU open-pack file descriptor cache (`FdPool`).
//!
//! Concurrent readers obtain an `Arc<File>` from the pool and execute lock-free positional
//! reads (`pread` via `FileExt::read_at` on Unix) outside the pool mutex, so sealed pack
//! readers never block active pack appends or each other.
//!
//! When the cache reaches `max_open_packs`, the least-recently-used handle is evicted and
//! dropped *before* opening the replacement file so thousands of packfiles never exhaust
//! per-process file descriptor limits (`EMFILE`).

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::error::{PackError, PackIoOperation};
use crate::format::{PackId, read_exact_at_bounded};

/// Default maximum open packfile handles cached concurrently on macOS.
#[cfg(target_os = "macos")]
pub const DEFAULT_MAX_OPEN_PACKS: usize = 48;

/// Default maximum open packfile handles cached concurrently on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_MAX_OPEN_PACKS: usize = 256;

#[derive(Debug)]
struct CachedHandle {
    tick: u64,
    file: Arc<File>,
}

#[derive(Debug, Default)]
struct LruState {
    next_tick: u64,
    entries: HashMap<PackId, CachedHandle>,
    lru_order: BTreeMap<u64, PackId>,
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl LruState {
    fn touch_existing(&mut self, pack_id: PackId) -> Option<Arc<File>> {
        let entry = self.entries.get_mut(&pack_id)?;
        let old_tick = entry.tick;
        self.lru_order.remove(&old_tick);
        self.next_tick = self.next_tick.wrapping_add(1);
        let new_tick = self.next_tick;
        entry.tick = new_tick;
        self.lru_order.insert(new_tick, pack_id);
        self.hits = self.hits.saturating_add(1);
        Some(Arc::clone(&entry.file))
    }

    fn evict_one_if_at_capacity(&mut self, max_open_packs: usize) -> Option<Arc<File>> {
        if self.entries.len() < max_open_packs {
            return None;
        }
        let (_, victim_id) = self.lru_order.pop_first()?;
        let removed = self.entries.remove(&victim_id)?;
        self.evictions = self.evictions.saturating_add(1);
        Some(removed.file)
    }

    fn insert(
        &mut self,
        pack_id: PackId,
        file: Arc<File>,
        max_open_packs: usize,
    ) -> Vec<Arc<File>> {
        let mut evicted = Vec::new();
        if let Some(existing) = self.entries.get_mut(&pack_id) {
            let old_tick = existing.tick;
            self.lru_order.remove(&old_tick);
            self.next_tick = self.next_tick.wrapping_add(1);
            let new_tick = self.next_tick;
            existing.tick = new_tick;
            existing.file = file;
            self.lru_order.insert(new_tick, pack_id);
            return evicted;
        }
        while self.entries.len() >= max_open_packs {
            if let Some(old_file) = self.evict_one_if_at_capacity(max_open_packs) {
                evicted.push(old_file);
            } else {
                break;
            }
        }
        self.next_tick = self.next_tick.wrapping_add(1);
        let new_tick = self.next_tick;
        self.lru_order.insert(new_tick, pack_id);
        self.entries.insert(
            pack_id,
            CachedHandle {
                tick: new_tick,
                file,
            },
        );
        evicted
    }
}

/// Snapshot of [`FdPool`] cache statistics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdPoolStats {
    /// Currently open cached packfile handles.
    pub open_count: usize,
    /// Configured upper bound on cached open packfile handles.
    pub max_open_packs: usize,
    /// Cumulative cache hits.
    pub hits: u64,
    /// Cumulative cache misses requiring `File::open`.
    pub misses: u64,
    /// Cumulative LRU evictions.
    pub evictions: u64,
}

/// Bounded LRU open-file descriptor pool for immutable packfile reads.
#[derive(Debug)]
pub struct FdPool {
    packs_dir: PathBuf,
    max_open_packs: usize,
    state: Mutex<LruState>,
}

impl FdPool {
    /// Creates a new bounded LRU pool rooted at `packs_dir`.
    pub fn new(packs_dir: PathBuf, max_open_packs: usize) -> Result<Self, PackError> {
        if max_open_packs == 0 {
            return Err(PackError::InvalidConfig {
                detail: "max_open_packs must be at least 1".to_owned(),
            });
        }
        Ok(Self {
            packs_dir,
            max_open_packs,
            state: Mutex::new(LruState::default()),
        })
    }

    /// Returns the configured maximum open packfile handles.
    #[must_use]
    pub const fn max_open_packs(&self) -> usize {
        self.max_open_packs
    }

    /// Returns the current number of cached open packfile handles.
    #[must_use]
    pub fn open_count(&self) -> usize {
        self.state.lock().map_or(0, |guard| guard.entries.len())
    }

    /// Returns the total number of LRU evictions performed so far.
    #[must_use]
    pub fn eviction_count(&self) -> u64 {
        self.state.lock().map_or(0, |guard| guard.evictions)
    }

    /// Returns a point-in-time snapshot of pool statistics.
    #[must_use]
    pub fn stats(&self) -> FdPoolStats {
        match self.state.lock() {
            Ok(guard) => FdPoolStats {
                open_count: guard.entries.len(),
                max_open_packs: self.max_open_packs,
                hits: guard.hits,
                misses: guard.misses,
                evictions: guard.evictions,
            },
            Err(_) => FdPoolStats {
                open_count: 0,
                max_open_packs: self.max_open_packs,
                hits: 0,
                misses: 0,
                evictions: 0,
            },
        }
    }

    /// Obtains an `Arc<File>` handle for `pack_id`, evicting the LRU handle before opening on miss.
    pub fn get_or_open(&self, pack_id: PackId) -> Result<Arc<File>, PackError> {
        let evicted_before_open = {
            let mut guard = self.state.lock().map_err(|_| PackError::LockPoisoned)?;
            if let Some(handle) = guard.touch_existing(pack_id) {
                return Ok(handle);
            }
            guard.misses = guard.misses.saturating_add(1);
            // Evict before opening so OS FD count stays strictly <= max_open_packs.
            guard.evict_one_if_at_capacity(self.max_open_packs)
        };
        // Drop evicted FD explicitly prior to opening the replacement file.
        drop(evicted_before_open);

        let path = self.packs_dir.join(pack_id.file_name());
        let opened =
            Arc::new(File::open(&path).map_err(|err| PackError::io(PackIoOperation::Open, err))?);

        let extra_evicted = {
            let mut guard = self.state.lock().map_err(|_| PackError::LockPoisoned)?;
            if let Some(existing) = guard.touch_existing(pack_id) {
                // Another concurrent reader raced and inserted the same pack first.
                return Ok(existing);
            }
            guard.insert(pack_id, Arc::clone(&opened), self.max_open_packs)
        };
        drop(extra_evicted);
        Ok(opened)
    }

    /// Performs a lock-free positional read of `buf.len()` bytes from `pack_id` at `offset`.
    pub fn read_exact_at(
        &self,
        pack_id: PackId,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), PackError> {
        let file = self.get_or_open(pack_id)?;
        read_exact_at_bounded(&file, offset, buf)
    }

    /// Removes a specific pack handle from the cache if present.
    pub fn invalidate(&self, pack_id: PackId) {
        let removed = if let Ok(mut guard) = self.state.lock() {
            if let Some(entry) = guard.entries.remove(&pack_id) {
                guard.lru_order.remove(&entry.tick);
                Some(entry.file)
            } else {
                None
            }
        } else {
            None
        };
        drop(removed);
    }

    /// Drops all cached file handles immediately.
    pub fn clear(&self) {
        let drained: Vec<Arc<File>> = if let Ok(mut guard) = self.state.lock() {
            guard.lru_order.clear();
            guard.entries.drain().map(|(_, entry)| entry.file).collect()
        } else {
            Vec::new()
        };
        drop(drained);
    }
}
