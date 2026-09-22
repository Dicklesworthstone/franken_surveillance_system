#![forbid(unsafe_code)]
//! Source-closed recipe custody through the existing root-last publisher, not a new store.
use super::*;
use fss_core::CanonicalEncode;
use fss_geometry::WorkBudget;
use fss_object::{ObjectManifest, MAX_MANIFEST_CHILDREN};
use fss_publication::{LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher,
    PublishCancellation, PublishCutPoint, SlotName};

/// Version-one manifest family. This is a retained reconstruction recipe, NOT a recording.
pub const RECORDING_RECIPE_KIND: &str = "rtsp_recording_recipe_v1";

/// Independently admitted storage work/allocation ceilings, never loaded as authority from disk.
#[derive(Clone, Copy, Debug)]
pub struct RecipeStorageLimits {
    /// Maximum direct source roots. One additional direct reference is needed for recipe metadata.
    pub max_source_roots: usize,
    /// Maximum allocation admitted for the actual publisher's object reads, at most 32 MiB.
    pub max_spool_object_bytes: usize,
}
impl Default for RecipeStorageLimits {
    fn default() -> Self {
        Self { max_source_roots: MAX_MANIFEST_CHILDREN.saturating_sub(1), max_spool_object_bytes: 32 * 1024 * 1024 }
    }
}
impl RecipeStorageLimits {
    fn check(self, p: &LocalRootPublisher, archive: &DatagramArchive) -> Result<(), RecordingRecipeError> {
        if self.max_source_roots >= MAX_MANIFEST_CHILDREN || self.max_spool_object_bytes == 0
            || self.max_spool_object_bytes > 32 * 1024 * 1024
            || archive.records().len() > self.max_source_roots
            || archive.records().len().saturating_add(1) > p.limits().max_children
            || p.limits().spool.max_object_bytes > self.max_spool_object_bytes {
            return Err(RecordingRecipeError::Limit);
        }
        if p.is_poisoned() { return Err(DatagramArchiveError::NotDurable.into()); }
        Ok(())
    }
}

/// Exact auxiliary publication identity to pin independently before I/O. Neither this value nor
/// its checksum grants source access, asserts durability, or certifies successful reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingRecipePin {
    /// Deterministic recipe route, with no caller-selected filename or endpoint text.
    pub slot: SlotName,
    /// Complete manifest root, committing every source root and the exact recipe metadata.
    pub root: ContentDigest,
    /// Canonical recipe identity, separate from its graph root.
    pub recipe: ContentDigest,
    /// Exact source observation prefix, not a complete-stream claim.
    pub source: DatagramPin,
}

/// Successful local recipe custody. No recording, indexing, replication or coverage is implied.
#[derive(Debug)]
pub struct RecordingRecipePublication {
    /// Exact original pre-publication pin.
    pub pin: RecordingRecipePin,
    /// Existing publisher's actual receipt; preserves Published versus AlreadyPublished.
    pub local: LocalPublicationReceipt,
}

/// Borrows existing source/recipe metadata only. Original media is not copied into another
/// journal, serialized into the recipe, or reacquired from a camera on a missing-source error.
#[must_use]
pub struct PreparedRecordingRecipe<'a> {
    recipe: &'a RecordingRecipe,
    archive: &'a DatagramArchive,
    pin: RecordingRecipePin,
    manifest: ObjectManifest,
    limits: RecipeStorageLimits,
}
impl std::fmt::Debug for PreparedRecordingRecipe<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRecordingRecipe").field("pin", &self.pin).finish_non_exhaustive()
    }
}
impl<'a> PreparedRecordingRecipe<'a> {
    /// Reverify every required original now and construct its complete immutable graph.
    /// This validates custody and recipe structure, NOT that its timing decisions will execute.
    pub fn prepare(recipe: &'a RecordingRecipe, archive: &'a DatagramArchive, p: &LocalRootPublisher,
        limits: RecipeStorageLimits, cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>)
        -> Result<Self, RecordingRecipeError> {
        limits.check(p, archive)?;
        if recipe.source() != archive.pin() { return Err(RecordingRecipeError::Mismatch); }
        probe(cancel, budget)?;
        if recipe.canonical_bytes().len() > p.limits().spool.max_object_bytes {
            return Err(RecordingRecipeError::Limit);
        }
        verify_sources(archive, p, cancel, budget)?;
        let manifest = manifest(recipe, archive, budget)?;
        if manifest.canonical_bytes().len() > p.limits().spool.max_object_bytes {
            return Err(RecordingRecipeError::Limit);
        }
        let pin = RecordingRecipePin { slot: slot(recipe.identity())?, root: manifest.root(),
            recipe: recipe.identity(), source: recipe.source() };
        probe(cancel, budget)?;
        Ok(Self { recipe, archive, pin, manifest, limits })
    }
    /// Candidate to keep independently when lost replies or whole-store rollback matter.
    pub fn pin(&self) -> &RecordingRecipePin { &self.pin }
    /// Revalidate all original custody before staging the recipe and publishing the graph root.
    /// On error the plan is unchanged and remains borrowed; a committing error still requires
    /// the existing publisher's explicit reconciliation. No automatic cleanup or retry occurs.
    pub fn publish(&self, p: &mut LocalRootPublisher, cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>) -> Result<RecordingRecipePublication, RecordingRecipeError> {
        self.limits.check(p, self.archive)?;
        verify_sources(self.archive, p, cancel, budget)?;
        budget.charge(self.recipe.canonical_bytes().len() as u64 * 8 + 4096)
            .map_err(DatagramArchiveError::Work)?;
        // Allocate the returned metadata BEFORE any possibly committing storage operation.
        let pin = self.pin.clone();
        probe(cancel, budget)?;
        let digest = p.stage_object(self.recipe.canonical_bytes()).map_err(DatagramArchiveError::Publication)?;
        if digest != self.recipe.identity() { return Err(RecordingRecipeError::Mismatch); }
        probe(cancel, budget)?;
        let local = p.publish_cancellable(&self.pin.slot, &self.manifest, cancel)
            .map_err(DatagramArchiveError::Publication)?;
        if local.root != self.pin.root || local.claims.local != LocalPublicationState::Durable {
            return Err(DatagramArchiveError::NotDurable.into());
        }
        // No cancellation probe after commit: return the actual durable receipt instead of
        // losing it through a later refusal. Downstream disclosure still needs current authority.
        Ok(RecordingRecipePublication { pin, local })
    }
}

/// Recover exact instructions plus their complete source closure. The pin and source scope must
/// be independently accepted; root/metadata decoding supplies no new authority or latest lookup.
/// A corrupt, missing, superseded or tombstoned required original refuses the entire load.
pub fn load_recording_recipe(p: &LocalRootPublisher, pin: &RecordingRecipePin, archive: &DatagramArchive,
    recipe_limits: RecordingRecipeLimits, storage_limits: RecipeStorageLimits,
    cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>)
    -> Result<RecordingRecipe, RecordingRecipeError> {
    recipe_limits.validate()?;
    storage_limits.check(p, archive)?;
    if pin.source != archive.pin() || pin.slot != slot(pin.recipe)? {
        return Err(RecordingRecipeError::Mismatch);
    }
    if p.is_broken_slot(&pin.slot) || p.root(&pin.slot).is_none_or(|r|
        r.root != pin.root || r.state != LocalPublicationState::Durable) {
        return Err(DatagramArchiveError::NotDurable.into());
    }
    let root_bytes = object(p, pin.root, storage_limits.max_spool_object_bytes, cancel, budget)?;
    let stored = ObjectManifest::from_canonical_bytes(&root_bytes).map_err(|_| RecordingRecipeError::Mismatch)?;
    if stored.root() != pin.root || stored.kind() != RECORDING_RECIPE_KIND
        || stored.metadata_digest() != Some(pin.recipe) {
        return Err(RecordingRecipeError::Mismatch);
    }
    let bytes = object(p, pin.recipe, recipe_limits.max_bytes, cancel, budget)?;
    budget.charge(bytes.len() as u64 * 4).map_err(DatagramArchiveError::Work)?;
    let recipe = RecordingRecipe::from_canonical_bytes(&bytes, archive, recipe_limits)?;
    if recipe.identity() != pin.recipe || manifest(&recipe, archive, budget)? != stored {
        return Err(RecordingRecipeError::Mismatch);
    }
    verify_sources(archive, p, cancel, budget)?;
    probe(cancel, budget)?;
    Ok(recipe)
}
fn manifest(recipe: &RecordingRecipe, archive: &DatagramArchive, budget: &mut WorkBudget<'_>)
    -> Result<ObjectManifest, RecordingRecipeError> {
    budget.charge(archive.records().len() as u64 * 128 + 1024).map_err(DatagramArchiveError::Work)?;
    let mut children = Vec::new();
    children.try_reserve_exact(archive.records().len()).map_err(|_| RecordingRecipeError::Limit)?;
    children.extend(archive.records().iter().map(|record| record.pin.head));
    // ObjectManifest owns canonical sorting, duplicate checks and the metadata-child rule.
    ObjectManifest::new(RECORDING_RECIPE_KIND, children, Some(recipe.identity()))
        .map_err(|_| RecordingRecipeError::Mismatch)
}
fn slot(recipe: ContentDigest) -> Result<SlotName, RecordingRecipeError> {
    let text = recipe.to_text();
    let hex = text.strip_prefix("sha256:").ok_or(RecordingRecipeError::Mismatch)?;
    SlotName::parse(&format!("fssrr1-{hex}")).map_err(|_| RecordingRecipeError::Mismatch)
}
fn probe(cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<(), RecordingRecipeError> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
        return Err(DatagramArchiveError::Cancelled.into());
    }
    budget.charge(0).map_err(DatagramArchiveError::Work)?; Ok(())
}
fn verify_sources(archive: &DatagramArchive, p: &LocalRootPublisher, cancel: &dyn PublishCancellation,
    budget: &mut WorkBudget<'_>) -> Result<(), RecordingRecipeError> {
    for record in archive.records() {
        probe(cancel, budget)?;
        let actual = archive.read(record.pin.datagrams, p, cancel, budget)?;
        if actual.record() != *record { return Err(RecordingRecipeError::Mismatch); }
    }
    probe(cancel, budget)
}
fn object(p: &LocalRootPublisher, digest: ContentDigest, maximum: usize,
    cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<Vec<u8>, RecordingRecipeError> {
    probe(cancel, budget)?;
    // Charge the actual spool's allocating read ceiling BEFORE I/O, not the untrusted payload size.
    budget.charge(p.limits().spool.max_object_bytes as u64 * 3 + p.limits().max_tombstones as u64 + 1)
        .map_err(DatagramArchiveError::Work)?;
    if p.tombstones().any(|d| *d == digest) { return Err(DatagramArchiveError::Tombstoned.into()); }
    let bytes = p.spool().read(digest).map_err(DatagramArchiveError::Spool)?;
    if bytes.len() > maximum { return Err(RecordingRecipeError::Limit); }
    probe(cancel, budget)?; Ok(bytes)
}

/// Complete native reconstruction and root-last result publication for local operators.
pub mod operation;
