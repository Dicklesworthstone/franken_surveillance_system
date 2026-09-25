#![forbid(unsafe_code)]
//! Read-only closure walk: every retained derivative reachable from one import.
//!
//! The deployment is modelled as *units* that hold objects: every authority batch of the ledger
//! (its children, delta payloads and witnesses, expanded through every manifest they contain) and
//! every visible publication root (its manifest, expanded the same way). Root-reachability and
//! deletion batches are not units: the first are summaries of roots, the second are this
//! module's own records.
//!
//! A unit *references* a digest when it holds it, names it as a payload/witness identity, or when
//! one of its objects embeds it, either as raw SHA-256 bytes or as 64 lowercase hex digits. The
//! walk scans every retained object once for embedded digests of the candidate universe (all spool
//! objects, all unit identities, all import identities).
//!
//! Starting from the import's own units and the import identity as the only key, the walk adds
//! every unit that references a key, then makes keys of every identity and object that only
//! closure content units publish or hold, until nothing changes. Objects some unit
//! outside the closure also holds are retained (`shared_with_retained_authority`); objects held by
//! authority-history units (event revisions, tamper status, alert outcomes) are retained
//! (`authority_history`). Spool objects no unit holds are attributed when they reference a key or
//! are referenced by deletable content; the rest are counted as unattributed, never deleted.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use fss_core::{
    CanonicalDecode, CaptureInterval, ContentDigest, DigestAlgorithm, EffectState, EventHypothesis,
    EvidenceDeltaBatch, LedgerAnchor, ObjectId, OperationReceipt, Plane,
};
use fss_object::ObjectManifest;
use fss_publication::{ROOT_REACHABILITY_FAMILY, ROOT_RETRACTION_FAMILY, SlotName};

use super::index::DeletionIndex;
use super::plan::{
    ClosureUnit, DeletableObject, DeletionCompletion, DeletionPlan, EventReference, Finding,
    ObjectTombstone, RetainedObject, RootRetraction, Unattributed,
};
use super::{DeletionError, STAGE_DELETION_SCAN};
use crate::reference_deployment::{
    FAMILY_ALERT_EFFECT_OUTCOME, FAMILY_DELETION_COMPLETION, FAMILY_DELETION_RECORD,
    FAMILY_DELETION_TOMBSTONE, FAMILY_EVENT_REVISION, FAMILY_PRIVACY_MASK_POLICY,
    FAMILY_SENSOR_TAMPER_STATUS,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Families whose batches are authority history: kept, never deleted, never a source of keys.
const AUTHORITY_HISTORY_FAMILIES: &[&str] = &[
    FAMILY_EVENT_REVISION,
    FAMILY_SENSOR_TAMPER_STATUS,
    FAMILY_ALERT_EFFECT_OUTCOME,
    FAMILY_PRIVACY_MASK_POLICY,
];
/// Families this module owns; their batches are never units.
const DELETION_FAMILIES: &[&str] = &[
    FAMILY_DELETION_RECORD,
    FAMILY_DELETION_TOMBSTONE,
    FAMILY_DELETION_COMPLETION,
    ROOT_RETRACTION_FAMILY,
];
const IMPORT_BATCH_PREFIX: &str = "batch:file-import:";
const IMPORT_SLOT_PREFIX: &str = "slot:fi-";
const HOLD_EXPANSION_LIMIT: usize = 1 << 20;

fn sha(bytes: [u8; 32]) -> ContentDigest {
    ContentDigest::new(DigestAlgorithm::Sha256, bytes)
}

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_hex(text: &str) -> Option<ContentDigest> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, pair) in text.as_bytes().chunks(2).enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out[index] = (high << 4) | low;
    }
    Some(sha(out))
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Stable derivative kind of a unit, from its registered identity prefix.
fn unit_kind(id: &str) -> &'static str {
    const KINDS: &[(&str, &str)] = &[
        ("batch:file-import:", "import_custody"),
        ("slot:fi-", "import_custody"),
        ("batch:recorded-decode:", "decoded_frames"),
        ("slot:fd-", "decoded_frames"),
        ("batch:coverage:", "coverage_record"),
        ("batch:package-detection:", "package_detection_record"),
        ("slot:pd-", "package_detection_record"),
        ("batch:model-run:", "model_run"),
        ("slot:mi-", "model_run"),
        ("slot:rw-", "event_provenance"),
        ("slot:rc-", "event_provenance"),
        ("slot:pe-", "event_provenance"),
        ("batch:event:", "event_revision"),
        ("batch:alert-outcome:", "alert_outcome"),
        ("slot:rgbe1-", "rgb_evidence"),
    ];
    KINDS
        .iter()
        .find(|(prefix, _)| id.starts_with(prefix))
        .map_or(
            if id.starts_with("slot:") {
                "other_root"
            } else {
                "other_derived"
            },
            |(_, kind)| *kind,
        )
}

/// One holder of objects.
#[derive(Debug)]
struct Unit {
    id: String,
    authority: bool,
    /// Objects held (spool objects only), expanded through contained manifests.
    members: BTreeSet<ContentDigest>,
    /// Payload/witness/root identities the unit publishes (objects or not).
    identities: BTreeSet<ContentDigest>,
    /// Everything the unit references (sorted; the smallest match is the recorded `via`).
    refs: BTreeSet<ContentDigest>,
    batch: Option<usize>,
    slot: Option<(SlotName, ContentDigest)>,
}

/// Who wrote one ledger object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Writer {
    /// A unit of this scan.
    Unit(usize),
    /// A unit an earlier committed deletion already removed.
    Deleted,
    /// A batch that is not a unit (root reachability, deletion records).
    Other,
}

#[derive(Debug, Default)]
struct ObjectInfo {
    bytes: u64,
    refs: BTreeSet<ContentDigest>,
    manifest_children: Vec<ContentDigest>,
}

#[derive(Debug)]
struct EventRevision {
    unit: usize,
    object_id: String,
    root: ContentDigest,
    revision_digest: ContentDigest,
    anchor: LedgerAnchor,
}

/// The scanned deployment, reusable for the closure of every import.
#[derive(Debug)]
pub(super) struct Universe {
    site_lineage: String,
    anchor: LedgerAnchor,
    effect_journal_root: ContentDigest,
    units: Vec<Unit>,
    objects: BTreeMap<ContentDigest, ObjectInfo>,
    holders: BTreeMap<ContentDigest, Vec<usize>>,
    /// Units that publish each identity (payload, witness or root).
    identity_holders: BTreeMap<ContentDigest, Vec<usize>>,
    unheld: BTreeSet<ContentDigest>,
    staging: (u64, u64),
    broken_slots: Vec<String>,
    /// Completed imports (manifest batch present) and their seed units.
    imports: BTreeMap<ContentDigest, Vec<usize>>,
    /// Ledger object id -> who wrote it.
    writers: BTreeMap<String, Vec<Writer>>,
    /// Committed deletions whose completion record is not durable yet.
    incomplete_deletions: Vec<ContentDigest>,
    current: BTreeMap<String, (u64, String, Plane, CaptureInterval, ContentDigest)>,
    events: Vec<EventRevision>,
    batch_digests: Vec<ContentDigest>,
    operations: Vec<OperationReceipt>,
    batch_entries_max: usize,
}

/// Scans `bytes` for embedded SHA-256 digests of the universe (raw or lowercase hex).
pub(super) fn embedded(
    bytes: &[u8],
    universe: &HashSet<[u8; 32]>,
    prefix: &[u64],
    out: &mut BTreeSet<ContentDigest>,
) {
    if bytes.len() >= 32 {
        for start in 0..=bytes.len() - 32 {
            let key = (usize::from(bytes[start]) << 16)
                | (usize::from(bytes[start + 1]) << 8)
                | usize::from(bytes[start + 2]);
            if prefix[key >> 6] & (1_u64 << (key & 63)) == 0 {
                continue;
            }
            let mut window = [0_u8; 32];
            window.copy_from_slice(&bytes[start..start + 32]);
            if universe.contains(&window) {
                out.insert(sha(window));
            }
        }
    }
    let mut run = 0_usize;
    for index in 0..=bytes.len() {
        let is_hex = bytes.get(index).is_some_and(|b| hex_value(*b).is_some());
        if is_hex {
            run += 1;
            continue;
        }
        if run >= 64 {
            let start = index - run;
            for offset in start..=index - 64 {
                let window = &bytes[offset..offset + 64];
                if let Some(digest) = std::str::from_utf8(window).ok().and_then(parse_hex)
                    && universe.contains(&digest.bytes())
                {
                    out.insert(digest);
                }
            }
        }
        run = 0;
    }
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), DeletionError> {
    cx.checkpoint(stage)
        .map_err(|_| DeletionError::Cancelled { stage })
}

impl Universe {
    /// Reads and scans the whole deployment once. Writes nothing.
    pub(super) fn scan(
        deployment: &ReferenceDeployment,
        index: &DeletionIndex,
        cx: &ReplayCx,
    ) -> Result<Self, DeletionError> {
        let ledger = deployment.ledger();
        let publisher = deployment.publisher();
        let spool = publisher.spool();
        let batches: &[EvidenceDeltaBatch] = ledger.batches();

        let mut units: Vec<Unit> = Vec::new();
        let mut writers: BTreeMap<String, Vec<Writer>> = BTreeMap::new();
        let mut events = Vec::new();
        for (position, batch) in batches.iter().enumerate() {
            let excluded = batch.deltas.iter().any(|delta| {
                DELETION_FAMILIES.contains(&delta.family.as_str())
                    || delta.family == ROOT_REACHABILITY_FAMILY
            });
            let deleted = !excluded && index.unit_deleted(batch.batch_id.as_str());
            let writer = if deleted {
                Writer::Deleted
            } else if excluded {
                Writer::Other
            } else {
                Writer::Unit(units.len())
            };
            for delta in &batch.deltas {
                writers
                    .entry(delta.object_id.as_str().to_owned())
                    .or_default()
                    .push(writer);
            }
            if excluded || deleted {
                continue;
            }
            let mut identities = BTreeSet::new();
            let mut direct: BTreeSet<ContentDigest> = batch.children.iter().copied().collect();
            for delta in &batch.deltas {
                identities.insert(delta.payload_digest);
                direct.insert(delta.payload_digest);
                if let Some(witness) = delta.witness_digest {
                    identities.insert(witness);
                    direct.insert(witness);
                }
                if delta.family == FAMILY_EVENT_REVISION
                    && let Some(witness) = delta.witness_digest
                {
                    events.push(EventRevision {
                        unit: units.len(),
                        object_id: delta.object_id.as_str().to_owned(),
                        root: delta.payload_digest,
                        revision_digest: witness,
                        anchor: batch.new_anchor.clone(),
                    });
                }
            }
            let authority = batch
                .deltas
                .iter()
                .any(|delta| AUTHORITY_HISTORY_FAMILIES.contains(&delta.family.as_str()));
            units.push(Unit {
                id: batch.batch_id.as_str().to_owned(),
                authority,
                members: direct,
                identities,
                refs: BTreeSet::new(),
                batch: Some(position),
                slot: None,
            });
        }
        let mut broken_slots: Vec<String> = publisher
            .broken_slots()
            .map(|slot| slot.as_str().to_owned())
            .collect();
        broken_slots.sort();
        let mut visible: Vec<(SlotName, ContentDigest)> = publisher
            .visible_roots()
            .map(|root| (root.slot.clone(), root.root))
            .collect();
        visible.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
        for (slot, root) in visible {
            if index.unit_deleted(&format!("slot:{}", slot.as_str())) {
                continue;
            }
            let mut direct: BTreeSet<ContentDigest> = publisher
                .root_children(&slot)
                .map(|children| children.iter().copied().collect())
                .unwrap_or_default();
            direct.insert(root);
            units.push(Unit {
                id: format!("slot:{}", slot.as_str()),
                authority: false,
                members: direct,
                identities: BTreeSet::from([root]),
                refs: BTreeSet::new(),
                batch: None,
                slot: Some((slot, root)),
            });
        }

        // Completed imports: the manifest batch names the identity.
        let mut imports: BTreeMap<ContentDigest, Vec<usize>> = BTreeMap::new();
        for unit in &units {
            if let Some(rest) = unit.id.strip_prefix(IMPORT_BATCH_PREFIX)
                && let Some(identity) = rest.strip_suffix(":manifest").and_then(parse_hex)
            {
                imports.entry(identity).or_default();
            }
        }
        for (identity, seeds) in &mut imports {
            let hex_id = hex(*identity);
            let batch_prefix = format!("{IMPORT_BATCH_PREFIX}{hex_id}:");
            let slot_id = format!("{IMPORT_SLOT_PREFIX}{hex_id}");
            for (index, unit) in units.iter().enumerate() {
                if unit.id.starts_with(&batch_prefix) || unit.id == slot_id {
                    seeds.push(index);
                }
            }
        }

        // Candidate universe of embedded references.
        let spool_digests: Vec<ContentDigest> = spool.digests().collect();
        let mut universe: HashSet<[u8; 32]> = HashSet::new();
        for digest in spool_digests
            .iter()
            .chain(units.iter().flat_map(|unit| unit.identities.iter()))
            .chain(imports.keys())
        {
            if digest.algorithm() == DigestAlgorithm::Sha256 {
                universe.insert(digest.bytes());
            }
        }
        let mut prefix = vec![0_u64; (1 << 24) / 64];
        for bytes in &universe {
            let key = (usize::from(bytes[0]) << 16)
                | (usize::from(bytes[1]) << 8)
                | usize::from(bytes[2]);
            prefix[key >> 6] |= 1_u64 << (key & 63);
        }

        let mut objects: BTreeMap<ContentDigest, ObjectInfo> = BTreeMap::new();
        let mut records: BTreeSet<ContentDigest> = BTreeSet::new();
        for digest in &spool_digests {
            checkpoint(cx, STAGE_DELETION_SCAN)?;
            let mut info = ObjectInfo::default();
            if let Ok(bytes) = spool.read(*digest) {
                if DeletionPlan::is_plan_bytes(&bytes)
                    || DeletionCompletion::is_completion_bytes(&bytes)
                {
                    records.insert(*digest);
                    continue;
                }
                info.bytes = bytes.len() as u64;
                embedded(&bytes, &universe, &prefix, &mut info.refs);
                info.refs.remove(digest);
                if let Ok(manifest) = ObjectManifest::from_canonical_bytes(&bytes) {
                    info.manifest_children = manifest.children().to_vec();
                }
            }
            objects.insert(*digest, info);
        }

        // Expand members through contained manifests; compute refs and holders.
        let mut holders: BTreeMap<ContentDigest, Vec<usize>> = BTreeMap::new();
        let mut identity_holders: BTreeMap<ContentDigest, Vec<usize>> = BTreeMap::new();
        for (index, unit) in units.iter_mut().enumerate() {
            for identity in &unit.identities {
                identity_holders.entry(*identity).or_default().push(index);
            }
            let mut pending: Vec<ContentDigest> = unit.members.iter().copied().collect();
            let mut members = BTreeSet::new();
            while let Some(digest) = pending.pop() {
                if members.len() > HOLD_EXPANSION_LIMIT {
                    return Err(DeletionError::Bound {
                        limit: "unit_members",
                    });
                }
                let Some(info) = objects.get(&digest) else {
                    continue;
                };
                if members.insert(digest) {
                    pending.extend(info.manifest_children.iter().copied());
                }
            }
            let mut refs: BTreeSet<ContentDigest> = unit.identities.clone();
            for member in &members {
                refs.insert(*member);
                if let Some(info) = objects.get(member) {
                    refs.extend(info.refs.iter().copied());
                }
                holders.entry(*member).or_default().push(index);
            }
            unit.members = members;
            unit.refs = refs;
        }
        let unheld: BTreeSet<ContentDigest> = objects
            .keys()
            .filter(|digest| !holders.contains_key(digest) && !records.contains(digest))
            .copied()
            .collect();
        let staging = spool
            .orphaned_staging()
            .fold((0_u64, 0_u64), |(n, b), orphan| {
                (n.saturating_add(1), b.saturating_add(orphan.bytes))
            });
        let current = ledger
            .current()
            .objects
            .iter()
            .map(|(id, revision)| {
                (
                    id.as_str().to_owned(),
                    (
                        revision.generation,
                        revision.family.clone(),
                        revision.plane,
                        revision.validity,
                        revision.payload_digest,
                    ),
                )
            })
            .collect();
        Ok(Self {
            site_lineage: deployment.site_lineage().to_owned(),
            anchor: ledger.current().anchor.clone(),
            effect_journal_root: deployment.effects().last_root(),
            units,
            objects,
            holders,
            identity_holders,
            unheld,
            staging,
            broken_slots,
            imports,
            writers,
            incomplete_deletions: index
                .entries()
                .iter()
                .filter(|entry| !entry.is_complete())
                .map(|entry| entry.plan_digest)
                .collect(),
            current,
            events,
            batch_digests: batches.iter().map(|batch| batch.batch_digest).collect(),
            operations: deployment.effects().operations().cloned().collect(),
            batch_entries_max: deployment.limits().batch_entries_max,
        })
    }

    /// Completed import identities, ascending.
    pub(super) fn imports(&self) -> impl Iterator<Item = &ContentDigest> {
        self.imports.keys()
    }

    /// The sealed plan of `import` against this scan. Reads event revisions from `deployment`.
    pub(super) fn plan(
        &self,
        deployment: &ReferenceDeployment,
        import: ContentDigest,
    ) -> Result<DeletionPlan, DeletionError> {
        let seeds = self
            .imports
            .get(&import)
            .ok_or(DeletionError::UnknownImport(import))?;
        let mut via: Vec<Option<ContentDigest>> = vec![None; self.units.len()];
        for seed in seeds {
            via[*seed] = Some(import);
        }
        let mut keys: HashSet<ContentDigest> = HashSet::from([import]);
        loop {
            for (index, unit) in self.units.iter().enumerate() {
                if via[index].is_none() || unit.authority {
                    continue;
                }
                // An identity another retained unit also publishes or holds (two imports of the
                // same file share their custody manifest) never becomes a key.
                for identity in &unit.identities {
                    if self.exclusive_identity(*identity, &via) {
                        keys.insert(*identity);
                    }
                }
                for member in &unit.members {
                    if self.exclusive(*member, &via) {
                        keys.insert(*member);
                    }
                }
            }
            let mut changed = false;
            for (index, unit) in self.units.iter().enumerate() {
                if via[index].is_some() {
                    continue;
                }
                if let Some(key) = unit.refs.iter().find(|r| keys.contains(r)) {
                    via[index] = Some(*key);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        let in_closure = |index: usize| via[index].is_some();
        let mut deletable: BTreeSet<ContentDigest> = BTreeSet::new();
        let mut retained: BTreeMap<ContentDigest, &'static str> = BTreeMap::new();
        for (index, unit) in self.units.iter().enumerate() {
            if !in_closure(index) {
                continue;
            }
            for member in &unit.members {
                if !unit.authority && self.exclusive(*member, &via) {
                    deletable.insert(*member);
                } else {
                    let authority = self.holders.get(member).is_some_and(|holders| {
                        holders
                            .iter()
                            .any(|h| in_closure(*h) && self.units[*h].authority)
                    });
                    retained.insert(
                        *member,
                        if authority {
                            "authority_history"
                        } else {
                            "shared_with_retained_authority"
                        },
                    );
                }
            }
        }
        for digest in &deletable {
            retained.remove(digest);
        }

        // Unheld spool objects: attributed through references, never guessed.
        let mut attributed: BTreeMap<ContentDigest, ContentDigest> = BTreeMap::new();
        loop {
            let mut changed = false;
            for digest in &self.unheld {
                if attributed.contains_key(digest) {
                    continue;
                }
                let Some(info) = self.objects.get(digest) else {
                    continue;
                };
                let referrer = info
                    .refs
                    .iter()
                    .find(|r| keys.contains(r) || attributed.contains_key(r))
                    .copied()
                    .or_else(|| {
                        deletable
                            .iter()
                            .chain(attributed.keys())
                            .find(|holder| {
                                self.objects
                                    .get(holder)
                                    .is_some_and(|holder_info| holder_info.refs.contains(digest))
                            })
                            .copied()
                    });
                if let Some(referrer) = referrer {
                    attributed.insert(*digest, referrer);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut units: Vec<ClosureUnit> = Vec::new();
        for (index, unit) in self.units.iter().enumerate() {
            if let Some(key) = via[index] {
                units.push(ClosureUnit {
                    id: unit.id.clone(),
                    kind: unit_kind(&unit.id).to_owned(),
                    class: if unit.authority {
                        "authority_history".to_owned()
                    } else {
                        "deletable_content".to_owned()
                    },
                    via: key,
                });
            }
        }
        for (digest, referrer) in &attributed {
            deletable.insert(*digest);
            units.push(ClosureUnit {
                id: format!("object:{digest}"),
                kind: "staging_leftover".to_owned(),
                class: "deletable_content".to_owned(),
                via: *referrer,
            });
        }
        units.sort();

        let unattributed = self
            .unheld
            .iter()
            .filter(|digest| !attributed.contains_key(digest))
            .fold(
                Unattributed {
                    staging_files: self.staging.0,
                    staging_bytes: self.staging.1,
                    ..Unattributed::default()
                },
                |mut total, digest| {
                    total.objects = total.objects.saturating_add(1);
                    total.object_bytes = total
                        .object_bytes
                        .saturating_add(self.objects.get(digest).map_or(0, |info| info.bytes));
                    total
                },
            );

        // Ledger tombstones: objects whose every writer is closure content.
        let mut tombstones = Vec::new();
        let mut candidates: BTreeSet<&str> = BTreeSet::new();
        for (index, unit) in self.units.iter().enumerate() {
            if in_closure(index)
                && !unit.authority
                && let Some(batch) = unit.batch
                && let Some(batch) = deployment.ledger().batches().get(batch)
            {
                candidates.extend(batch.deltas.iter().map(|delta| delta.object_id.as_str()));
            }
        }
        for object_id in candidates {
            let exclusive = self.writers.get(object_id).is_some_and(|writers| {
                writers.iter().all(|writer| match writer {
                    Writer::Unit(w) => in_closure(*w) && !self.units[*w].authority,
                    Writer::Deleted => true,
                    Writer::Other => false,
                })
            });
            if !exclusive {
                continue;
            }
            if let Some((generation, family, plane, validity, _)) = self.current.get(object_id)
                && family != FAMILY_DELETION_TOMBSTONE
            {
                tombstones.push(ObjectTombstone {
                    object_id: object_id.to_owned(),
                    prior_generation: *generation,
                    plane: *plane,
                    validity: *validity,
                });
            }
        }

        let import_object = format!("object:file-import:{}", hex(import));
        let validity = self
            .current
            .get(&import_object)
            .map(|(_, _, _, validity, _)| *validity)
            .ok_or(DeletionError::UnknownImport(import))?;

        let mut blockers: Vec<Finding> = self
            .broken_slots
            .iter()
            .map(|slot| Finding {
                kind: "broken_root_unclassified".to_owned(),
                subject: format!("slot:{slot}"),
                detail: "a root record failed verification on open; its closure cannot be \
                         classified, so no deletion can prove completeness"
                    .to_owned(),
            })
            .collect();
        blockers.extend(self.incomplete_deletions.iter().map(|plan| {
            Finding {
                kind: "incomplete_deletion".to_owned(),
                subject: plan.to_text(),
                detail:
                    "an earlier deletion record is durable but its completion is not; rerun its \
                     commit first"
                        .to_owned(),
            }
        }));
        let mut retractions = Vec::new();
        for (index, unit) in self.units.iter().enumerate() {
            let (true, Some((slot, root))) = (in_closure(index), &unit.slot) else {
                continue;
            };
            let object_id = fss_publication::root_reachability_object_id(slot).map_err(|_| {
                DeletionError::Bound {
                    limit: "slot_ledger_identity",
                }
            })?;
            let current = self.current.get(object_id.as_str());
            let prior_generation = match current {
                None => None,
                Some((generation, family, _, _, payload))
                    if family == ROOT_REACHABILITY_FAMILY && payload == root =>
                {
                    Some(*generation)
                }
                Some(_) => {
                    blockers.push(Finding {
                        kind: "root_claim_conflict".to_owned(),
                        subject: format!("slot:{}", slot.as_str()),
                        detail: "the ledger names a different root or family for this slot"
                            .to_owned(),
                    });
                    continue;
                }
            };
            retractions.push(RootRetraction {
                slot: slot.as_str().to_owned(),
                root: *root,
                prior_generation,
                validity: current.map_or(validity, |(_, _, _, validity, _)| *validity),
            });
        }

        // Events whose history is retained; effects that reference them.
        let mut events: BTreeMap<String, u64> = BTreeMap::new();
        let mut unknown_copies = vec![
            Finding {
                kind: "original_input_file".to_owned(),
                subject: import.to_text(),
                detail: "the file this import was read from lies outside the deployment, which \
                         never owned it; it is not deleted"
                    .to_owned(),
            },
            Finding {
                kind: "unrecorded_operator_exports".to_owned(),
                subject: import.to_text(),
                detail: "report, event, receipt, image and segment exports written by operator \
                         commands are not recorded by the deployment and cannot be enumerated \
                         or deleted"
                    .to_owned(),
            },
        ];
        let mut matched: BTreeSet<(String, String)> = BTreeSet::new();
        for revision in &self.events {
            if !in_closure(revision.unit) {
                continue;
            }
            let latest = self
                .current
                .get(&revision.object_id)
                .map_or(0, |(generation, _, _, _, _)| *generation);
            events.insert(revision.object_id.clone(), latest);
            let Some(hypothesis) = read_event(deployment, revision.root) else {
                continue;
            };
            for operation in &self.operations {
                if operation.intent.effect_class != "alert.dispatch" {
                    continue;
                }
                let bound = self.batch_digests.iter().enumerate().any(|(index, head)| {
                    crate::alert::alert_precondition_digest_parts(
                        revision.revision_digest,
                        &revision.anchor,
                        hypothesis.state,
                        hypothesis.decision_path.fingerprint,
                        index as u64 + 1,
                        *head,
                    ) == operation.intent.precondition_digest
                });
                if bound {
                    matched.insert((
                        operation.intent.operation_id.as_str().to_owned(),
                        revision.object_id.clone(),
                    ));
                }
            }
        }
        for (operation_id, event) in &matched {
            let Some(operation) = self
                .operations
                .iter()
                .find(|op| op.intent.operation_id.as_str() == operation_id)
            else {
                continue;
            };
            let state = operation.state;
            if matches!(
                state,
                EffectState::Prepared | EffectState::Committed | EffectState::Indeterminate
            ) {
                blockers.push(Finding {
                    kind: "open_effect".to_owned(),
                    subject: operation_id.clone(),
                    detail: format!(
                        "alert.dispatch in state {} references {event}; reconcile or cancel it \
                         before deleting its evidence",
                        state.as_str()
                    ),
                });
            }
            if !matches!(state, EffectState::Prepared | EffectState::Cancelled) {
                unknown_copies.push(Finding {
                    kind: "alert_dispatch".to_owned(),
                    subject: operation_id.clone(),
                    detail: format!(
                        "an alert about {event} may have been transmitted to an external relay \
                         (state {}); copies there cannot be enumerated or deleted",
                        state.as_str()
                    ),
                });
            }
        }
        if tombstones.len() + retractions.len() + 1 > self.batch_entries_max {
            blockers.push(Finding {
                kind: "tombstone_batch_bound".to_owned(),
                subject: import.to_text(),
                detail: "the tombstone batch would exceed the deployment's batch entry bound"
                    .to_owned(),
            });
        }
        blockers.sort();
        unknown_copies.sort();

        let deletable: Vec<DeletableObject> = deletable
            .iter()
            .map(|digest| DeletableObject {
                digest: *digest,
                bytes: self.objects.get(digest).map_or(0, |info| info.bytes),
            })
            .collect();
        let retained: Vec<RetainedObject> = retained
            .into_iter()
            .map(|(digest, reason)| RetainedObject {
                digest,
                reason: reason.to_owned(),
            })
            .collect();
        tombstones.sort_by(|left, right| left.object_id.cmp(&right.object_id));
        retractions.sort_by(|left, right| left.slot.cmp(&right.slot));
        let (scanned_objects, scanned_bytes) =
            self.objects.values().fold((0_u64, 0_u64), |(n, b), info| {
                (n.saturating_add(1), b.saturating_add(info.bytes))
            });
        let _ = ObjectId::parse(DeletionPlan::record_object_id(import))?;
        Ok(DeletionPlan {
            site_lineage: self.site_lineage.clone(),
            import_identity: import,
            basis_anchor: self.anchor.clone(),
            effect_journal_root: self.effect_journal_root,
            validity,
            scanned_objects,
            scanned_bytes,
            units,
            deletable,
            retained,
            tombstones,
            retractions,
            events: events
                .into_iter()
                .map(|(object_id, latest_revision)| EventReference {
                    object_id,
                    latest_revision,
                })
                .collect(),
            blockers,
            unknown_copies,
            unattributed,
        })
    }

    /// Whether every unit publishing or holding `digest` is closure content.
    fn exclusive_identity(&self, digest: ContentDigest, via: &[Option<ContentDigest>]) -> bool {
        self.identity_holders
            .get(&digest)
            .into_iter()
            .flatten()
            .chain(self.holders.get(&digest).into_iter().flatten())
            .all(|h| via[*h].is_some() && !self.units[*h].authority)
    }

    /// Whether every unit holding `digest` is closure content.
    fn exclusive(&self, digest: ContentDigest, via: &[Option<ContentDigest>]) -> bool {
        self.holders.get(&digest).is_some_and(|holders| {
            holders
                .iter()
                .all(|h| via[*h].is_some() && !self.units[*h].authority)
        })
    }
}

/// The retained event revision behind `root` (a manifest whose metadata is the event bytes).
fn read_event(deployment: &ReferenceDeployment, root: ContentDigest) -> Option<EventHypothesis> {
    let spool = deployment.publisher().spool();
    let manifest = ObjectManifest::from_canonical_bytes(&spool.read(root).ok()?).ok()?;
    let payload = manifest
        .metadata_digest()
        .or_else(|| manifest.children().first().copied())?;
    EventHypothesis::from_canonical_bytes(&spool.read(payload).ok()?).ok()
}
