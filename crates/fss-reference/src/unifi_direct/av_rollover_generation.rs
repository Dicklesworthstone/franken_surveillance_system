#![forbid(unsafe_code)]
//! Bounded in-memory planning for fresh A/V rollover stores.
//!
//! Planning performs no filesystem or camera I/O. It retains the same shared
//! replay authorities across generations, so cancellation is not reset. The
//! caller must persist generation choices and establish custody independence;
//! a directory collision is a refusal, not permission to reuse old history.

use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_object::{SpoolIo, effect_journal::EffectJournalLimits};

use super::{
    archive,
    av_rollover_supplies::{self, SwitchCustody, SwitchInput, Worker},
};
use crate::ReplayCx;

const DOMAIN: &str = "fss.unifi_av_rollover_generation.v1";

mod bootstrap;
mod retained;
mod worker;
pub use bootstrap::{
    BootstrapCompletion, BootstrapInputs, BootstrapMode, BootstrapOutcome, BootstrapRetirement,
    BootstrapStage, BootstrapStartError, BootstrapStorage, BootstrapWorker,
};
pub use retained::{
    BindRefusal, CreatorObservation, DiscoverError, DiscoverRefusal, InventoryCursor,
    InventoryDisposition, InventoryEntry, InventoryError, InventoryPage, OpenSwitchesError,
    OpenSwitchesRefusal, OpenedSwitches, ReservationError, ReservationRefusal, ReservedPlan,
};
pub use worker::{
    ReservationCompletion, ReservationInputs, ReservationOutcome, ReservationRequest,
    ReservationRetirement, ReservationStartError, ReservationWorker,
};

/// Explicit bounded authority and storage policy for a series of generations.
pub struct Configuration {
    /// Short caller-selected namespace within both parent directories.
    pub namespace: String,
    /// Non-laboratory SHA-256 identity bound into each pin-custody scope.
    pub scope_seed: ContentDigest,
    /// First nonzero generation to allocate.
    pub first: u64,
    /// Maximum number of workers that may be planned by this owner.
    pub count: u64,
    /// Shared, caller-bound creation authority for publication stores.
    pub journal_replay: Arc<ReplayCx>,
    /// Shared, caller-bound creation authority for pin custody.
    pub pin_replay: Arc<ReplayCx>,
    /// Filesystem capability for publication stores.
    pub journal_io: Arc<dyn SpoolIo>,
    /// Filesystem capability for pin custody.
    pub pin_io: Arc<dyn SpoolIo>,
    /// Limits for each publication and switch journal.
    pub journal_limits: EffectJournalLimits,
    /// Limits for each pin-retainer journal.
    pub pin_limits: EffectJournalLimits,
    /// Read authority for the eventual confirmed-graph replay.
    pub read: Arc<dyn archive::ReadAuthority + Send + Sync>,
    /// Bounds on that confirmed A/V graph.
    pub object_limits: archive::StagedAvLimits,
    /// Bounded replay work for one rollover.
    pub work_limit: u64,
}

/// Exact generation identity to retain for collision handling and recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Caller-authorized monotonically increasing generation.
    pub generation: u64,
    /// Fresh successor directory, not yet created.
    pub journal_root: PathBuf,
    /// Fresh pin-custody directory, not yet created.
    pub pin_root: PathBuf,
    /// Domain-separated scope bound to the selected seed and generation.
    pub pin_scope: ContentDigest,
}

/// Invalid configuration or a bounded encoding failure; no I/O was started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Names, limits, roots, scope, or generation bounds were invalid.
    Configuration,
    /// The stable identity could not be encoded.
    Encoding,
}

/// One bounded series of fresh store creators.
#[must_use = "retain the next generation and shared authorities"]
pub struct Plan {
    config: Configuration,
    next: u64,
    remaining: u64,
}

fn safe_parent(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn valid_limits(limits: EffectJournalLimits) -> bool {
    (1..=65_536).contains(&limits.max_records)
        && (1..=512 * 1024).contains(&limits.max_record_bytes)
        && (1..=1024 * 1024 * 1024).contains(&limits.max_total_bytes)
        && limits.max_read_bytes > 0
}

impl Plan {
    /// Validate a series without starting work or consuming an invalid config.
    pub fn new(config: Configuration) -> Result<Self, Configuration> {
        let name = config.namespace.as_bytes();
        let valid = (1..=32).contains(&name.len())
            && name
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
            && config.scope_seed.algorithm() == DigestAlgorithm::Sha256
            && !config.scope_seed.is_laboratory()
            && config.scope_seed.bytes() != [0; 32]
            && config.first > 0
            && (1..=1_000_000).contains(&config.count)
            && config.first.checked_add(config.count - 1).is_some()
            && safe_parent(config.journal_replay.root_dir())
            && safe_parent(config.pin_replay.root_dir())
            && valid_limits(config.journal_limits)
            && valid_limits(config.pin_limits)
            && (1..=8192).contains(&config.object_limits.max_objects)
            && config.object_limits.max_object_bytes > 0
            && (1..=256 * 1024 * 1024).contains(&config.object_limits.max_total_bytes)
            && (1..=100_000_000_000).contains(&config.work_limit);
        if !valid {
            return Err(config);
        }
        let next = config.first;
        let remaining = config.count;
        Ok(Self {
            config,
            next,
            remaining,
        })
    }

    /// Number of unplanned generations left under this explicit bound.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Explicitly authorize another bounded series after this one is exhausted.
    /// The caller must account for all previously returned workers and custody
    /// before renewal. A refusal leaves the old plan unchanged and performs no I/O.
    pub fn extend(&mut self, count: u64) -> Result<(), Error> {
        if self.remaining != 0 || !(1..=1_000_000).contains(&count) {
            return Err(Error::Configuration);
        }
        let first = self.next.checked_add(1).ok_or(Error::Configuration)?;
        first.checked_add(count - 1).ok_or(Error::Configuration)?;
        self.next = first;
        self.remaining = count;
        Ok(())
    }

    /// Construct the next exclusive creator and identity without any I/O.
    /// A refusal leaves the generation counter unchanged.
    pub fn next_worker(&mut self) -> Result<Option<(Identity, Worker)>, Error> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let generation = self.next;
        let next = if self.remaining > 1 {
            Some(generation.checked_add(1).ok_or(Error::Configuration)?)
        } else {
            None
        };
        let identity = self.identity_for(generation)?;
        let journal_root = identity.journal_root.clone();
        let pin_root = identity.pin_root.clone();
        let pin_scope = identity.pin_scope;
        let custody = SwitchCustody {
            root: pin_root,
            replay: self.config.pin_replay.clone(),
            io: self.config.pin_io.clone(),
            limits: self.config.pin_limits,
            scope: pin_scope,
        };
        let inputs = av_rollover_supplies::Inputs {
            root: journal_root,
            replay: self.config.journal_replay.clone(),
            io: self.config.journal_io.clone(),
            journal_limits: self.config.journal_limits,
            switch: SwitchInput::Create(custody),
            read: self.config.read.clone(),
            object_limits: self.config.object_limits,
            work_limit: self.config.work_limit,
        };
        let worker = Worker::new(inputs).map_err(|_| Error::Configuration)?;
        self.remaining -= 1;
        if let Some(next) = next {
            self.next = next;
        }
        Ok(Some((identity, worker)))
    }

    fn identity_for(&self, generation: u64) -> Result<Identity, Error> {
        let name = &self.config.namespace;
        let journal_root = self
            .config
            .journal_replay
            .root_dir()
            .join(format!("fss-av-{name}-{generation:016x}"));
        let pin_root = self
            .config
            .pin_replay
            .root_dir()
            .join(format!("fss-pin-{name}-{generation:016x}"));
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DOMAIN);
        encoder.text(name);
        encoder.digest(self.config.scope_seed);
        encoder.u64(generation);
        let bytes = encoder.finish_checked().map_err(|_| Error::Encoding)?;
        let pin_scope = ContentDigest::sha256(&bytes);
        Ok(Identity {
            generation,
            journal_root,
            pin_root,
            pin_scope,
        })
    }
}
