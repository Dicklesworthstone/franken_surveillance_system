#![forbid(unsafe_code)]
//! Differential contract: [`LocalRootPublisher`] over a real on-disk staging spool against the
//! in-memory reference `InMemoryObjectStore::publish_manifest` (FSS-018, fss-x4a.7.6).
//!
//! Both implementations receive the identical operation sequence. After every step the suite
//! asserts that they reach the same verdict class and hold the same visible-root set. Where the
//! local publisher's contract legitimately differs from the content-addressed oracle, the
//! difference is one of the mapping rows below; each row is asserted where it applies and is
//! never skipped.
//!
//! | ID | Local publisher | In-memory oracle | Why they differ |
//! |----|-----------------|------------------|-----------------|
//! | M1 | `Published` into a new slot for a root already visible elsewhere | `AlreadyPublished` | the oracle is content-addressed and has no slots: a root is visible or not |
//! | M2 | `SlotConflict` for a different root in an occupied slot | the root's content verdict: `Published`, or `AlreadyPublished` when already visible | the oracle has no slots; a root it accepts this way is tracked as oracle-only until a local slot holds it |
//! | M3 | corrupt manifest body: `ReferenceBlocked { Corrupt }` | `DigestCollision(root)` | the oracle's `stage` compares its corrupted stored bytes with the canonical body and reports a collision rather than corruption (oracle classification, reported as a divergence) |
//! | M4 | `Visible` and `Durable` | visible (a single state) | the oracle has no directory fsync; in a fault-free run every local root must be `Durable` |
//! | M5 | tombstoning an object reachable from a visible root is refused | the tombstone is applied and every reaching manifest is unpublished | deleting a visible closure belongs to the local deletion-closure owner, never to a silent unpublish |
//! | M6 | tombstoning an object absent from the spool is recorded | `Missing` | a local tombstone is a durable, custody-independent record; an oracle tombstone is a state of a stored object |
//!
//! The seeded generator never emits an M5 or M6 operation, because each forks the two histories
//! permanently; dedicated tests assert those two rows directly.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord};
use fss_object::{InMemoryObjectStore, ObjectError, ObjectLimits, ObjectManifest, SpoolLimits};
use fss_publication::{
    BlockReason, LOCAL_TOMBSTONES_DIR, LocalPublicationError, LocalPublicationLimits,
    LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher, PublishOutcome,
    ReferenceRole, SlotName, TombstoneOutcome,
};

type TestResult = Result<(), Box<dyn Error>>;

const WITNESS_BYTES: &[u8] = b"owner-deletion-authorization";

/// Returns a not-yet-existing directory owned by exactly one test, named after that test.
fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("local_publication_differential")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(64, 16, 64, 256, SpoolLimits::new(256, 1 << 22, 4096, 256))
}

fn slot(name: &str) -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(name)?)
}

fn flip_last_byte(path: &Path) -> TestResult {
    let mut bytes = fs::read(path)?;
    let last = bytes.last_mut().ok_or("cannot corrupt an empty file")?;
    *last ^= 0x01;
    fs::write(path, bytes)?;
    Ok(())
}

fn tombstone_record(
    object: ContentDigest,
    witness: ContentDigest,
) -> Result<TombstoneRecord, Box<dyn Error>> {
    Ok(TombstoneRecord::new(
        ObjectId::parse("object:clip-segment:1")?,
        Generation(2),
        Generation(1),
        TombstoneReason::Deleted,
        Some(witness),
        object,
    )?)
}

// ---------------------------------------------------------------------------------------------
// Verdict classes and the mapping
// ---------------------------------------------------------------------------------------------

/// Why a reference blocks publication, in either implementation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Block {
    Missing,
    NotVerified,
    Corrupt,
    Tombstoned,
}

/// Implementation-neutral verdict class of one step.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Verdict {
    Published,
    AlreadyPublished,
    Blocked(Block),
    SlotConflict,
    TombstoneRecorded,
    TombstoneAlreadyRecorded,
    TombstoneRefusedReachable,
    /// Any outcome outside the verdict vocabulary; it never matches a mapping row.
    Unexpected(String),
}

/// Which row of the module-level mapping justified a publish step.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Mapping {
    /// Same verdict class, same visible-root effect.
    Identical,
    M1NewSlotForVisibleRoot,
    M2ConflictAcceptedByOracle,
    M2ConflictAlreadyVisibleInOracle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Counts {
    child_count: usize,
    closure_object_count: usize,
}

#[derive(Clone, Debug)]
struct PublishStep {
    local: Verdict,
    memory: Verdict,
    local_counts: Option<Counts>,
    memory_counts: Option<Counts>,
    visible_in_memory_before: bool,
}

fn classify_block(reason: &BlockReason) -> Verdict {
    match reason {
        BlockReason::Missing => Verdict::Blocked(Block::Missing),
        BlockReason::NotVerified => Verdict::Blocked(Block::NotVerified),
        BlockReason::Corrupt => Verdict::Blocked(Block::Corrupt),
        BlockReason::Tombstoned => Verdict::Blocked(Block::Tombstoned),
        other => Verdict::Unexpected(format!("local block reason {other:?}")),
    }
}

fn classify_local_publish(
    result: &Result<LocalPublicationReceipt, LocalPublicationError>,
) -> (Verdict, Option<Counts>) {
    match result {
        Ok(receipt) => (
            match receipt.outcome {
                PublishOutcome::Published => Verdict::Published,
                PublishOutcome::AlreadyPublished => Verdict::AlreadyPublished,
            },
            Some(Counts {
                child_count: receipt.child_count,
                closure_object_count: receipt.closure_object_count,
            }),
        ),
        Err(LocalPublicationError::ReferenceBlocked { reason, .. }) => {
            (classify_block(reason), None)
        }
        Err(LocalPublicationError::SlotConflict { .. }) => (Verdict::SlotConflict, None),
        Err(error) => (Verdict::Unexpected(format!("local {error}")), None),
    }
}

fn classify_memory_publish(
    result: &Result<fss_object::PublicationReceipt, ObjectError>,
    root: ContentDigest,
    visible_before: bool,
    corrupted: &BTreeSet<ContentDigest>,
) -> (Verdict, Option<Counts>) {
    match result {
        Ok(receipt) => (
            // The oracle's receipt does not say whether the root was new; visibility before the
            // call does.
            if visible_before {
                Verdict::AlreadyPublished
            } else {
                Verdict::Published
            },
            Some(Counts {
                child_count: receipt.child_count,
                closure_object_count: receipt.closure_object_count,
            }),
        ),
        Err(ObjectError::Missing(_)) => (Verdict::Blocked(Block::Missing), None),
        Err(ObjectError::NotVerified(_)) => (Verdict::Blocked(Block::NotVerified), None),
        Err(ObjectError::Corrupt(_)) => (Verdict::Blocked(Block::Corrupt), None),
        Err(ObjectError::Tombstoned(_)) => (Verdict::Blocked(Block::Tombstoned), None),
        // M3: the oracle reports a corrupted stored manifest body as a digest collision.
        Err(ObjectError::DigestCollision(digest))
            if *digest == root && corrupted.contains(digest) =>
        {
            (Verdict::Blocked(Block::Corrupt), None)
        }
        Err(error) => (Verdict::Unexpected(format!("in-memory {error}")), None),
    }
}

/// Applies the mapping table to one publish step; any unlisted pair is a divergence.
fn check_publish_mapping(step: &PublishStep) -> Result<Mapping, String> {
    let before = step.visible_in_memory_before;
    let mapping = match (&step.local, &step.memory) {
        (Verdict::Published, Verdict::Published) if !before => Mapping::Identical,
        (Verdict::AlreadyPublished, Verdict::AlreadyPublished) if before => Mapping::Identical,
        (Verdict::Blocked(local), Verdict::Blocked(memory)) if local == memory => {
            Mapping::Identical
        }
        (Verdict::Published, Verdict::AlreadyPublished) if before => {
            Mapping::M1NewSlotForVisibleRoot
        }
        (Verdict::SlotConflict, Verdict::Published) if !before => {
            Mapping::M2ConflictAcceptedByOracle
        }
        (Verdict::SlotConflict, Verdict::AlreadyPublished) if before => {
            Mapping::M2ConflictAlreadyVisibleInOracle
        }
        (local, memory) => {
            return Err(format!(
                "divergent verdicts: local {local:?}, in-memory {memory:?}, visible in oracle before: {before}"
            ));
        }
    };
    if step.local_counts.is_some()
        && step.memory_counts.is_some()
        && step.local_counts != step.memory_counts
    {
        return Err(format!(
            "divergent receipts: local {:?}, in-memory {:?}",
            step.local_counts, step.memory_counts
        ));
    }
    Ok(mapping)
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// Drives both implementations with identical operations and checks the mapping after each.
struct Harness {
    local: LocalRootPublisher,
    memory: InMemoryObjectStore,
    witness: ContentDigest,
    /// Every manifest submitted to either implementation, by root.
    manifests: BTreeMap<ContentDigest, ObjectManifest>,
    /// Slot to root, updated only from local `Published` verdicts.
    slots: BTreeMap<SlotName, ContentDigest>,
    /// Roots the oracle holds visible only because of M2, derived from verdicts, never observed.
    memory_only: BTreeSet<ContentDigest>,
    /// Objects whose stored bytes were corrupted in both implementations.
    corrupted: BTreeSet<ContentDigest>,
    /// Objects tombstoned in both implementations.
    tombstoned: BTreeSet<ContentDigest>,
    trace: Vec<String>,
}

impl Harness {
    fn open(root: &Path) -> Result<Self, Box<dyn Error>> {
        let mut harness = Self {
            local: LocalRootPublisher::open(root, limits())?,
            memory: InMemoryObjectStore::new(ObjectLimits::new(1024, 1 << 24)),
            witness: ContentDigest::sha256(WITNESS_BYTES),
            manifests: BTreeMap::new(),
            slots: BTreeMap::new(),
            memory_only: BTreeSet::new(),
            corrupted: BTreeSet::new(),
            tombstoned: BTreeSet::new(),
            trace: Vec::new(),
        };
        harness.witness = harness.stage(WITNESS_BYTES)?;
        harness.trace.clear();
        Ok(harness)
    }

    fn stage(&mut self, bytes: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
        let local = self.local.stage_object(bytes)?;
        let memory = self.memory.put_verified(bytes)?;
        if local != memory {
            return Err(format!("stage digests differ: local {local}, in-memory {memory}").into());
        }
        self.trace.push(format!("stage {local}"));
        self.check_invariants()?;
        Ok(local)
    }

    fn corrupt(&mut self, digest: ContentDigest) -> TestResult {
        flip_last_byte(&self.local.spool().object_path(digest))?;
        self.memory.corrupt_for_test(digest)?;
        self.corrupted.insert(digest);
        self.trace.push(format!("corrupt {digest}"));
        self.check_invariants()
    }

    fn publish(
        &mut self,
        slot_name: &SlotName,
        manifest: &ObjectManifest,
    ) -> Result<(PublishStep, Mapping), Box<dyn Error>> {
        let root = manifest.root();
        self.manifests.insert(root, manifest.clone());
        let visible_in_memory_before = self.memory_visible().contains(&root);
        let local_result = self.local.publish(slot_name, manifest);
        let memory_result = self.memory.publish_manifest(manifest.clone());
        let (local, local_counts) = classify_local_publish(&local_result);
        let (memory, memory_counts) = classify_memory_publish(
            &memory_result,
            root,
            visible_in_memory_before,
            &self.corrupted,
        );
        let step = PublishStep {
            local,
            memory,
            local_counts,
            memory_counts,
            visible_in_memory_before,
        };
        let mapping = check_publish_mapping(&step)
            .map_err(|divergence| format!("{divergence} (slot {slot_name}, root {root})"))?;
        if step.local == Verdict::Published {
            self.slots.insert(slot_name.clone(), root);
            self.memory_only.remove(&root);
        }
        if mapping == Mapping::M2ConflictAcceptedByOracle {
            self.memory_only.insert(root);
        }
        self.trace.push(format!(
            "publish {slot_name} {root} local={:?} memory={:?} mapping={mapping:?}",
            step.local, step.memory
        ));
        self.check_invariants()?;
        Ok((step, mapping))
    }

    /// Tombstones `object` in both implementations and returns (local, in-memory) verdicts.
    fn tombstone(&mut self, object: ContentDigest) -> Result<(Verdict, Verdict), Box<dyn Error>> {
        let record = tombstone_record(object, self.witness)?;
        let already = self.memory.is_tombstoned(object);
        let local = match self.local.record_tombstone(record.clone()) {
            Ok(TombstoneOutcome::Recorded) => Verdict::TombstoneRecorded,
            Ok(TombstoneOutcome::AlreadyRecorded) => Verdict::TombstoneAlreadyRecorded,
            Err(LocalPublicationError::TombstoneBlockedByVisibleRoot { .. }) => {
                Verdict::TombstoneRefusedReachable
            }
            Err(error) => Verdict::Unexpected(format!("local {error}")),
        };
        let memory = match self.memory.tombstone(object, record) {
            Ok(()) if already => Verdict::TombstoneAlreadyRecorded,
            Ok(()) => Verdict::TombstoneRecorded,
            Err(ObjectError::Missing(_)) => Verdict::Blocked(Block::Missing),
            Err(error) => Verdict::Unexpected(format!("in-memory {error}")),
        };
        if local != memory {
            return Err(format!(
                "divergent tombstone verdicts for {object}: local {local:?}, in-memory {memory:?}"
            )
            .into());
        }
        if local == Verdict::TombstoneRecorded {
            self.tombstoned.insert(object);
        }
        self.trace
            .push(format!("tombstone {object} verdict={local:?}"));
        self.check_invariants()?;
        Ok((local, memory))
    }

    fn local_visible(&self) -> BTreeSet<ContentDigest> {
        self.local
            .visible_roots()
            .map(|visible| visible.root)
            .collect()
    }

    /// Roots the oracle holds visible, among every manifest this harness ever submitted.
    fn memory_visible(&self) -> BTreeSet<ContentDigest> {
        self.manifests
            .keys()
            .copied()
            .filter(|root| {
                !matches!(
                    self.memory.published_manifest(*root),
                    Err(ObjectError::ManifestNotPublished(_))
                )
            })
            .collect()
    }

    /// Objects the oracle reaches from its visible roots, descending only into visible manifests.
    fn memory_reachable(&self) -> BTreeSet<ContentDigest> {
        let visible = self.memory_visible();
        let mut seen = BTreeSet::new();
        let mut pending: Vec<ContentDigest> = visible.iter().copied().collect();
        while let Some(digest) = pending.pop() {
            if !seen.insert(digest) {
                continue;
            }
            if visible.contains(&digest)
                && let Some(manifest) = self.manifests.get(&digest)
            {
                pending.extend(manifest.children().iter().copied());
            }
        }
        seen
    }

    fn check_invariants(&self) -> TestResult {
        let local_slots: BTreeMap<SlotName, ContentDigest> = self
            .local
            .visible_roots()
            .map(|visible| (visible.slot.clone(), visible.root))
            .collect();
        if local_slots != self.slots {
            return Err(format!(
                "local slots {local_slots:?} differ from verdict-derived slots {:?}",
                self.slots
            )
            .into());
        }
        // M4: every local root of a fault-free run is Durable; the oracle has one visible state.
        if let Some(visible) = self
            .local
            .visible_roots()
            .find(|visible| visible.state != LocalPublicationState::Durable)
        {
            return Err(format!("fault-free local root is not durable: {visible:?}").into());
        }
        let local_set = self.local_visible();
        if !local_set.is_disjoint(&self.memory_only) {
            return Err("an oracle-only root is also visible locally".into());
        }
        let expected: BTreeSet<ContentDigest> =
            local_set.union(&self.memory_only).copied().collect();
        let memory_set = self.memory_visible();
        if memory_set != expected {
            return Err(format!(
                "divergent visible roots: in-memory {memory_set:?}, local {local_set:?} plus M2 oracle-only {:?}",
                self.memory_only
            )
            .into());
        }
        if self.memory.published_manifest_count() != memory_set.len() {
            return Err("the oracle holds a visible root this harness never submitted".into());
        }
        Ok(())
    }
}

fn expect_mapping(
    (step, mapping): (PublishStep, Mapping),
    local: Verdict,
    memory: Verdict,
    expected: Mapping,
) -> Result<PublishStep, Box<dyn Error>> {
    if step.local != local || step.memory != memory || mapping != expected {
        return Err(format!(
            "expected local {local:?} / in-memory {memory:?} via {expected:?}, got {:?} / {:?} via {mapping:?}",
            step.local, step.memory
        )
        .into());
    }
    Ok(step)
}

// ---------------------------------------------------------------------------------------------
// Targeted differential scenarios
// ---------------------------------------------------------------------------------------------

#[test]
fn differential_publish_matches_the_oracle() -> TestResult {
    let mut h = Harness::open(&fresh_root("differential_publish_matches_the_oracle")?)?;
    let first = h.stage(b"clip-segment-0001")?;
    let second = h.stage(b"clip-segment-0002")?;
    let metadata = h.stage(b"event-metadata-v1")?;
    let manifest = ObjectManifest::new("event_archive", [first, second], Some(metadata))?;
    let step = expect_mapping(
        h.publish(&slot("event-0001")?, &manifest)?,
        Verdict::Published,
        Verdict::Published,
        Mapping::Identical,
    )?;
    assert_eq!(
        step.local_counts,
        Some(Counts {
            child_count: 3,
            closure_object_count: 4,
        })
    );
    assert_eq!(h.local_visible(), BTreeSet::from([manifest.root()]));
    Ok(())
}

#[test]
fn differential_nested_publication_descends_into_visible_child_manifests() -> TestResult {
    let mut h = Harness::open(&fresh_root(
        "differential_nested_publication_descends_into_visible_child_manifests",
    )?)?;
    let first = h.stage(b"clip-segment-0001")?;
    let second = h.stage(b"clip-segment-0002")?;
    let third = h.stage(b"clip-segment-0003")?;
    let child = ObjectManifest::new("event_clip", [first, second], None)?;
    expect_mapping(
        h.publish(&slot("clip")?, &child)?,
        Verdict::Published,
        Verdict::Published,
        Mapping::Identical,
    )?;
    let parent = ObjectManifest::new("event_archive", [child.root(), third], None)?;
    let step = expect_mapping(
        h.publish(&slot("archive")?, &parent)?,
        Verdict::Published,
        Verdict::Published,
        Mapping::Identical,
    )?;
    // The closure is {parent, child, first, second, third}: descent reaches the visible child.
    assert_eq!(
        step.memory_counts,
        Some(Counts {
            child_count: 2,
            closure_object_count: 5,
        })
    );
    assert_eq!(step.local_counts, step.memory_counts);
    Ok(())
}

#[test]
fn differential_missing_child_blocks_both() -> TestResult {
    let mut h = Harness::open(&fresh_root("differential_missing_child_blocks_both")?)?;
    let first = h.stage(b"clip-segment-0001")?;
    let missing = ContentDigest::sha256(b"never-staged");
    let manifest = ObjectManifest::new("event_archive", [first, missing], None)?;
    expect_mapping(
        h.publish(&slot("event-0001")?, &manifest)?,
        Verdict::Blocked(Block::Missing),
        Verdict::Blocked(Block::Missing),
        Mapping::Identical,
    )?;
    assert!(h.local_visible().is_empty());
    assert_eq!(h.local.spool().state(manifest.root()), None);
    assert_eq!(h.memory.state(manifest.root()), None);

    // Staging the missing child in both makes the identical retry publish in both.
    assert_eq!(h.stage(b"never-staged")?, missing);
    expect_mapping(
        h.publish(&slot("event-0001")?, &manifest)?,
        Verdict::Published,
        Verdict::Published,
        Mapping::Identical,
    )?;
    Ok(())
}

#[test]
fn differential_corrupt_child_blocks_both() -> TestResult {
    let mut h = Harness::open(&fresh_root("differential_corrupt_child_blocks_both")?)?;
    let first = h.stage(b"clip-segment-0001")?;
    let second = h.stage(b"clip-segment-0002")?;
    let manifest = ObjectManifest::new("event_archive", [first, second], None)?;
    h.corrupt(second)?;
    expect_mapping(
        h.publish(&slot("event-0001")?, &manifest)?,
        Verdict::Blocked(Block::Corrupt),
        Verdict::Blocked(Block::Corrupt),
        Mapping::Identical,
    )?;
    assert!(h.local_visible().is_empty());
    assert_eq!(h.local.spool().state(manifest.root()), None);
    assert_eq!(h.memory.state(manifest.root()), None);
    Ok(())
}

#[test]
fn differential_corrupt_grandchild_behind_a_visible_child_manifest_blocks_both() -> TestResult {
    let mut h = Harness::open(&fresh_root(
        "differential_corrupt_grandchild_behind_a_visible_child_manifest_blocks_both",
    )?)?;
    let first = h.stage(b"clip-segment-0001")?;
    let second = h.stage(b"clip-segment-0002")?;
    let third = h.stage(b"clip-segment-0003")?;
    let child = ObjectManifest::new("event_clip", [first, second], None)?;
    h.publish(&slot("clip")?, &child)?;
    h.corrupt(first)?;
    let parent = ObjectManifest::new("event_archive", [child.root(), third], None)?;
    expect_mapping(
        h.publish(&slot("archive")?, &parent)?,
        Verdict::Blocked(Block::Corrupt),
        Verdict::Blocked(Block::Corrupt),
        Mapping::Identical,
    )?;
    assert_eq!(h.local_visible(), BTreeSet::from([child.root()]));
    let error = h
        .local
        .publish(&slot("archive")?, &parent)
        .err()
        .ok_or("a corrupt grandchild must block the parent")?;
    assert_eq!(
        error,
        LocalPublicationError::ReferenceBlocked {
            object: first,
            role: ReferenceRole::Descendant,
            reason: BlockReason::Corrupt,
        }
    );
    Ok(())
}

#[test]
fn differential_tombstoned_child_blocks_both() -> TestResult {
    let mut h = Harness::open(&fresh_root("differential_tombstoned_child_blocks_both")?)?;
    let first = h.stage(b"clip-segment-0001")?;
    let second = h.stage(b"clip-segment-0002")?;
    let manifest = ObjectManifest::new("event_archive", [first, second], None)?;
    assert_eq!(
        h.tombstone(second)?,
        (Verdict::TombstoneRecorded, Verdict::TombstoneRecorded)
    );
    assert_eq!(
        h.tombstone(second)?,
        (
            Verdict::TombstoneAlreadyRecorded,
            Verdict::TombstoneAlreadyRecorded
        )
    );
    expect_mapping(
        h.publish(&slot("event-0001")?, &manifest)?,
        Verdict::Blocked(Block::Tombstoned),
        Verdict::Blocked(Block::Tombstoned),
        Mapping::Identical,
    )?;
    assert!(h.local_visible().is_empty());
    Ok(())
}

#[test]
fn differential_republishing_the_same_root_is_idempotent_in_both() -> TestResult {
    let mut h = Harness::open(&fresh_root(
        "differential_republishing_the_same_root_is_idempotent_in_both",
    )?)?;
    let first = h.stage(b"clip-segment-0001")?;
    let second = h.stage(b"clip-segment-0002")?;
    let manifest = ObjectManifest::new("event_archive", [first, second], None)?;
    let slot_name = slot("event-0001")?;
    let published = expect_mapping(
        h.publish(&slot_name, &manifest)?,
        Verdict::Published,
        Verdict::Published,
        Mapping::Identical,
    )?;
    let objects_local = h.local.spool().object_count();
    let objects_memory = h.memory.object_count();
    let again = expect_mapping(
        h.publish(&slot_name, &manifest)?,
        Verdict::AlreadyPublished,
        Verdict::AlreadyPublished,
        Mapping::Identical,
    )?;
    assert_eq!(again.local_counts, published.local_counts);
    assert_eq!(h.local.spool().object_count(), objects_local);
    assert_eq!(h.memory.object_count(), objects_memory);

    // M1: the same root into a second slot is a new local root but already visible in the oracle.
    expect_mapping(
        h.publish(&slot("event-0001-copy")?, &manifest)?,
        Verdict::Published,
        Verdict::AlreadyPublished,
        Mapping::M1NewSlotForVisibleRoot,
    )?;
    assert_eq!(h.memory.published_manifest_count(), 1);
    assert_eq!(h.local.visible_roots().count(), 2);
    Ok(())
}

#[test]
fn differential_conflicting_root_for_a_slot_follows_mapping_m2() -> TestResult {
    let mut h = Harness::open(&fresh_root(
        "differential_conflicting_root_for_a_slot_follows_mapping_m2",
    )?)?;
    let first = h.stage(b"clip-segment-0001")?;
    let second = h.stage(b"clip-segment-0002")?;
    let manifest = ObjectManifest::new("event_archive", [first, second], None)?;
    let rival = ObjectManifest::new("event_archive", [first], None)?;
    let slot_name = slot("event-0001")?;
    h.publish(&slot_name, &manifest)?;

    // M2: the slot refuses the rival locally; the slot-less oracle accepts its content.
    expect_mapping(
        h.publish(&slot_name, &rival)?,
        Verdict::SlotConflict,
        Verdict::Published,
        Mapping::M2ConflictAcceptedByOracle,
    )?;
    assert_eq!(h.memory_only, BTreeSet::from([rival.root()]));
    assert_eq!(h.local_visible(), BTreeSet::from([manifest.root()]));
    assert_eq!(h.local.spool().state(rival.root()), None);

    // A second conflict with the same rival: already visible in the oracle.
    let other_slot = slot("event-0002")?;
    let other = ObjectManifest::new("event_clip", [second], None)?;
    h.publish(&other_slot, &other)?;
    expect_mapping(
        h.publish(&other_slot, &rival)?,
        Verdict::SlotConflict,
        Verdict::AlreadyPublished,
        Mapping::M2ConflictAlreadyVisibleInOracle,
    )?;

    // Publishing the rival into a free slot reconciles: M1, and it is no longer oracle-only.
    expect_mapping(
        h.publish(&slot("event-0003")?, &rival)?,
        Verdict::Published,
        Verdict::AlreadyPublished,
        Mapping::M1NewSlotForVisibleRoot,
    )?;
    assert!(h.memory_only.is_empty());
    Ok(())
}

#[test]
fn mapping_m3_corrupt_manifest_body_is_a_collision_in_the_oracle() -> TestResult {
    let mut h = Harness::open(&fresh_root(
        "mapping_m3_corrupt_manifest_body_is_a_collision_in_the_oracle",
    )?)?;
    let first = h.stage(b"clip-segment-0001")?;
    let second = h.stage(b"clip-segment-0002")?;
    let manifest = ObjectManifest::new("event_archive", [first, second], None)?;
    let root = manifest.root();
    let slot_name = slot("event-0001")?;
    h.publish(&slot_name, &manifest)?;
    h.corrupt(root)?;

    // The exact raw outcomes behind M3.
    assert_eq!(
        h.memory.publish_manifest(manifest.clone()),
        Err(ObjectError::DigestCollision(root))
    );
    assert_eq!(
        h.local.publish(&slot_name, &manifest).err(),
        Some(LocalPublicationError::ReferenceBlocked {
            object: root,
            role: ReferenceRole::ManifestBody,
            reason: BlockReason::Corrupt,
        })
    );

    // Same slot and a fresh slot both classify as Corrupt on each side.
    expect_mapping(
        h.publish(&slot_name, &manifest)?,
        Verdict::Blocked(Block::Corrupt),
        Verdict::Blocked(Block::Corrupt),
        Mapping::Identical,
    )?;
    expect_mapping(
        h.publish(&slot("event-0002")?, &manifest)?,
        Verdict::Blocked(Block::Corrupt),
        Verdict::Blocked(Block::Corrupt),
        Mapping::Identical,
    )?;
    // Both still hold the root visible: corruption is detected, never silently unpublished.
    assert_eq!(h.local_visible(), BTreeSet::from([root]));
    Ok(())
}

#[test]
fn mapping_m5_tombstoning_a_reachable_object_refuses_locally_and_cascades_in_the_oracle()
-> TestResult {
    let mut h = Harness::open(&fresh_root(
        "mapping_m5_tombstoning_a_reachable_object_refuses_locally_and_cascades_in_the_oracle",
    )?)?;
    let first = h.stage(b"clip-segment-0001")?;
    let second = h.stage(b"clip-segment-0002")?;
    let third = h.stage(b"clip-segment-0003")?;
    let child = ObjectManifest::new("event_clip", [first, second], None)?;
    let parent = ObjectManifest::new("event_archive", [child.root(), third], None)?;
    h.publish(&slot("clip")?, &child)?;
    h.publish(&slot("archive")?, &parent)?;
    let record = tombstone_record(first, h.witness)?;

    let local = h.local.record_tombstone(record.clone());
    let memory = h.memory.tombstone(first, record);
    assert_eq!(
        local,
        Err(LocalPublicationError::TombstoneBlockedByVisibleRoot {
            object: first,
            slot: slot("archive")?,
        }),
        "the first slot in slot order whose transitive closure reaches the object is named"
    );
    assert_eq!(memory, Ok(()));

    // The mapping: local keeps both roots; the oracle unpublished every manifest reaching `first`.
    let both = BTreeSet::from([child.root(), parent.root()]);
    assert_eq!(h.local_visible(), both);
    assert!(h.memory_visible().is_empty());
    assert_eq!(
        h.memory
            .published_manifests_with_tombstoned_closure()
            .into_iter()
            .collect::<BTreeSet<_>>(),
        both
    );
    assert!(h.memory.is_tombstoned(first));
    assert!(
        fs::read_dir(h.local.root_dir().join(LOCAL_TOMBSTONES_DIR))?
            .next()
            .is_none()
    );
    Ok(())
}

#[test]
fn mapping_m6_tombstoning_an_absent_object_records_locally_and_is_missing_in_the_oracle()
-> TestResult {
    let mut h = Harness::open(&fresh_root(
        "mapping_m6_tombstoning_an_absent_object_records_locally_and_is_missing_in_the_oracle",
    )?)?;
    let absent_bytes = b"not-yet-staged";
    let absent = ContentDigest::sha256(absent_bytes);
    let record = tombstone_record(absent, h.witness)?;
    assert_eq!(
        h.local.record_tombstone(record.clone()),
        Ok(TombstoneOutcome::Recorded)
    );
    assert_eq!(
        h.memory.tombstone(absent, record),
        Err(ObjectError::Missing(absent))
    );

    // The histories fork: local custody stays tombstoned for publication; the oracle has no
    // tombstone, so a later stage and publish succeed there.
    assert_eq!(h.local.stage_object(absent_bytes)?, absent);
    assert_eq!(h.memory.put_verified(absent_bytes)?, absent);
    let manifest = ObjectManifest::new("event_archive", [absent], None)?;
    assert_eq!(
        h.local.publish(&slot("event-0001")?, &manifest).err(),
        Some(LocalPublicationError::ReferenceBlocked {
            object: absent,
            role: ReferenceRole::Child,
            reason: BlockReason::Tombstoned,
        })
    );
    assert!(h.memory.publish_manifest(manifest).is_ok());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Seeded multi-step scenario generator
// ---------------------------------------------------------------------------------------------

/// SplitMix64: the only randomness in this suite, local to each scenario and fully seeded.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        let bound = bound.max(1) as u64;
        usize::try_from(self.next_u64() % bound).unwrap_or(0)
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> Option<T> {
        if items.is_empty() {
            return None;
        }
        items.get(self.below(items.len())).cloned()
    }
}

#[derive(Clone, Copy, Debug)]
enum OpKind {
    PublishFresh,
    PublishWithMissingChild,
    Republish,
    PublishVisibleRootIntoNewSlot,
    ConflictingRoot,
    CorruptObject,
    Tombstone,
    StageLateLeaf,
}

const OP_KINDS: [OpKind; 8] = [
    OpKind::PublishFresh,
    OpKind::PublishWithMissingChild,
    OpKind::Republish,
    OpKind::PublishVisibleRootIntoNewSlot,
    OpKind::ConflictingRoot,
    OpKind::CorruptObject,
    OpKind::Tombstone,
    OpKind::StageLateLeaf,
];

const SLOT_POOL: usize = 6;
const EARLY_LEAVES: usize = 6;
const LATE_LEAVES: usize = 4;
const KINDS: [&str; 3] = ["event_archive", "event_clip", "bundle"];

struct Scenario {
    harness: Harness,
    rng: SplitMix64,
    slots: Vec<SlotName>,
    staged: Vec<ContentDigest>,
    unstaged: Vec<Vec<u8>>,
    local_verdicts: BTreeSet<Verdict>,
    mappings: BTreeSet<Mapping>,
}

impl Scenario {
    fn new(root: &Path, seed: u64) -> Result<Self, Box<dyn Error>> {
        let mut harness = Harness::open(root)?;
        let mut staged = Vec::new();
        for index in 0..EARLY_LEAVES {
            staged.push(harness.stage(format!("leaf-{index}").as_bytes())?);
        }
        let unstaged = (0..LATE_LEAVES)
            .map(|index| format!("late-leaf-{index}").into_bytes())
            .collect();
        let mut slots = Vec::new();
        for index in 0..SLOT_POOL {
            slots.push(slot(&format!("slot-{index}"))?);
        }
        Ok(Self {
            harness,
            rng: SplitMix64::new(seed),
            slots,
            staged,
            unstaged,
            local_verdicts: BTreeSet::new(),
            mappings: BTreeSet::new(),
        })
    }

    fn free_slots(&self) -> Vec<SlotName> {
        self.slots
            .iter()
            .filter(|name| !self.harness.slots.contains_key(*name))
            .cloned()
            .collect()
    }

    fn occupied_slots(&self) -> Vec<(SlotName, ContentDigest)> {
        self.harness
            .slots
            .iter()
            .map(|(name, root)| (name.clone(), *root))
            .collect()
    }

    fn visible_roots(&self) -> Vec<ContentDigest> {
        self.harness.local_visible().into_iter().collect()
    }

    fn clean_leaves(&self) -> Vec<ContentDigest> {
        self.staged
            .iter()
            .copied()
            .filter(|leaf| {
                !self.harness.corrupted.contains(leaf) && !self.harness.tombstoned.contains(leaf)
            })
            .collect()
    }

    fn choose_children(
        &mut self,
        pool: &[ContentDigest],
        at_most: usize,
    ) -> BTreeSet<ContentDigest> {
        let wanted = 1 + self.rng.below(at_most);
        let mut children = BTreeSet::new();
        for _ in 0..wanted {
            if let Some(child) = self.rng.pick(pool) {
                children.insert(child);
            }
        }
        children
    }

    fn manifest(
        &mut self,
        kind: &str,
        mut children: BTreeSet<ContentDigest>,
        pool: &[ContentDigest],
    ) -> Result<ObjectManifest, Box<dyn Error>> {
        let metadata = if self.rng.below(4) == 0 {
            self.rng
                .pick(pool)
                .filter(|digest| !children.contains(digest))
        } else {
            None
        };
        if let Some(metadata) = metadata {
            children.remove(&metadata);
        }
        Ok(ObjectManifest::new(kind, children, metadata)?)
    }

    fn record(&mut self, outcome: (PublishStep, Mapping)) {
        self.local_verdicts.insert(outcome.0.local);
        self.mappings.insert(outcome.1);
    }

    /// Runs `kind` if it applies to the current state; returns whether it ran.
    fn try_op(&mut self, kind: OpKind) -> Result<bool, Box<dyn Error>> {
        match kind {
            OpKind::PublishFresh => {
                let Some(slot_name) = self.rng.pick(&self.free_slots()) else {
                    return Ok(false);
                };
                let mut pool = self.staged.clone();
                pool.extend(self.visible_roots());
                let children = self.choose_children(&pool, 3);
                let kind_name = self.rng.pick(&KINDS).unwrap_or("bundle");
                let manifest = self.manifest(kind_name, children, &pool)?;
                let outcome = self.harness.publish(&slot_name, &manifest)?;
                self.record(outcome);
            }
            OpKind::PublishWithMissingChild => {
                let Some(slot_name) = self.rng.pick(&self.free_slots()) else {
                    return Ok(false);
                };
                let Some(missing) = self.rng.pick(&self.unstaged) else {
                    return Ok(false);
                };
                let mut children = self.choose_children(&self.staged.clone(), 2);
                children.insert(ContentDigest::sha256(&missing));
                let manifest = ObjectManifest::new("event_archive", children, None)?;
                let outcome = self.harness.publish(&slot_name, &manifest)?;
                self.record(outcome);
            }
            OpKind::Republish => {
                let Some((slot_name, root)) = self.rng.pick(&self.occupied_slots()) else {
                    return Ok(false);
                };
                let manifest = self
                    .harness
                    .manifests
                    .get(&root)
                    .cloned()
                    .ok_or("an occupied slot names an unknown manifest")?;
                let outcome = self.harness.publish(&slot_name, &manifest)?;
                self.record(outcome);
            }
            OpKind::PublishVisibleRootIntoNewSlot => {
                let Some(slot_name) = self.rng.pick(&self.free_slots()) else {
                    return Ok(false);
                };
                let Some(root) = self.rng.pick(&self.visible_roots()) else {
                    return Ok(false);
                };
                let manifest = self
                    .harness
                    .manifests
                    .get(&root)
                    .cloned()
                    .ok_or("a visible root names an unknown manifest")?;
                let outcome = self.harness.publish(&slot_name, &manifest)?;
                self.record(outcome);
            }
            OpKind::ConflictingRoot => {
                let Some((slot_name, _)) = self.rng.pick(&self.occupied_slots()) else {
                    return Ok(false);
                };
                let clean = self.clean_leaves();
                if clean.is_empty() {
                    return Ok(false);
                }
                let children = self.choose_children(&clean, 2);
                // The "rival" kind is never used by another operation, so the root differs from
                // every slot's root.
                let rival = ObjectManifest::new("rival", children, None)?;
                let outcome = self.harness.publish(&slot_name, &rival)?;
                self.record(outcome);
            }
            OpKind::CorruptObject => {
                let mut candidates = self.staged.clone();
                candidates.extend(self.visible_roots());
                candidates.retain(|digest| {
                    !self.harness.corrupted.contains(digest)
                        && !self.harness.tombstoned.contains(digest)
                });
                let Some(target) = self.rng.pick(&candidates) else {
                    return Ok(false);
                };
                self.harness.corrupt(target)?;
            }
            OpKind::Tombstone => {
                // M5 is excluded here: only objects the oracle cannot reach are tombstoned.
                let reachable = self.harness.memory_reachable();
                let candidates: Vec<ContentDigest> = self
                    .staged
                    .iter()
                    .copied()
                    .filter(|leaf| !reachable.contains(leaf))
                    .collect();
                let Some(target) = self.rng.pick(&candidates) else {
                    return Ok(false);
                };
                let (local, _) = self.harness.tombstone(target)?;
                self.local_verdicts.insert(local);
            }
            OpKind::StageLateLeaf => {
                if self.unstaged.is_empty() {
                    return Ok(false);
                }
                let bytes = self.unstaged.remove(0);
                let digest = self.harness.stage(&bytes)?;
                self.staged.push(digest);
            }
        }
        Ok(true)
    }

    fn step(&mut self) -> TestResult {
        let start = self.rng.below(OP_KINDS.len());
        for offset in 0..OP_KINDS.len() {
            let kind = OP_KINDS
                .get((start + offset) % OP_KINDS.len())
                .copied()
                .ok_or("operation index out of range")?;
            if self.try_op(kind)? {
                return Ok(());
            }
        }
        Err("no operation applies to the scenario state".into())
    }
}

struct ScenarioOutcome {
    trace: Vec<String>,
    local_verdicts: BTreeSet<Verdict>,
    mappings: BTreeSet<Mapping>,
}

fn run_scenario(root: &Path, seed: u64, steps: usize) -> Result<ScenarioOutcome, Box<dyn Error>> {
    let mut scenario = Scenario::new(root, seed)?;
    for index in 0..steps {
        scenario
            .step()
            .map_err(|error| format!("seed {seed:#x} step {index}: {error}"))?;
    }
    Ok(ScenarioOutcome {
        trace: scenario.harness.trace,
        local_verdicts: scenario.local_verdicts,
        mappings: scenario.mappings,
    })
}

const GENERATOR_SEEDS: [u64; 5] = [
    0x0018_7006,
    0x0000_0001,
    0x5EED_0002,
    0x5EED_0003,
    0xDEAD_BEEF,
];
const GENERATOR_STEPS: usize = 40;

#[test]
fn seeded_generator_keeps_both_implementations_in_lockstep() -> TestResult {
    let mut local_verdicts = BTreeSet::new();
    let mut mappings = BTreeSet::new();
    for seed in GENERATOR_SEEDS {
        let root = fresh_root(&format!("seeded_generator_{seed:016x}"))?;
        let outcome = run_scenario(&root, seed, GENERATOR_STEPS)?;
        let fingerprint = ContentDigest::sha256(outcome.trace.join("\n").as_bytes());
        eprintln!(
            "{{\"suite\":\"local_publication_differential\",\"scenario\":\"seeded_generator\",\"seed\":{seed},\"steps\":{GENERATOR_STEPS},\"fingerprint\":\"{fingerprint}\",\"repro\":\"cargo +nightly-2026-08-31 test -p fss-publication --test local_publication_differential seeded_generator\"}}"
        );
        local_verdicts.extend(outcome.local_verdicts);
        mappings.extend(outcome.mappings);
    }

    // The generator must actually exercise every case the differential claims to cover.
    for required in [
        Verdict::Published,
        Verdict::AlreadyPublished,
        Verdict::Blocked(Block::Missing),
        Verdict::Blocked(Block::Corrupt),
        Verdict::Blocked(Block::Tombstoned),
        Verdict::SlotConflict,
        Verdict::TombstoneRecorded,
    ] {
        assert!(
            local_verdicts.contains(&required),
            "no seed produced {required:?}; seen {local_verdicts:?}"
        );
    }
    for required in [
        Mapping::Identical,
        Mapping::M1NewSlotForVisibleRoot,
        Mapping::M2ConflictAcceptedByOracle,
    ] {
        assert!(
            mappings.contains(&required),
            "no seed exercised {required:?}; seen {mappings:?}"
        );
    }
    Ok(())
}

#[test]
fn seeded_generator_is_deterministic() -> TestResult {
    let seed = GENERATOR_SEEDS[0];
    let left = run_scenario(
        &fresh_root("seeded_generator_is_deterministic_left")?,
        seed,
        GENERATOR_STEPS,
    )?;
    let right = run_scenario(
        &fresh_root("seeded_generator_is_deterministic_right")?,
        seed,
        GENERATOR_STEPS,
    )?;
    assert_eq!(left.trace, right.trace);
    assert_eq!(left.trace.len(), EARLY_LEAVES + GENERATOR_STEPS);
    Ok(())
}
