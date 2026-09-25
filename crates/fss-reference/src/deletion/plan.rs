#![forbid(unsafe_code)]
//! The sealed, canonical deletion plan and the deletion-completion record.
//!
//! Both are exact canonical byte strings (`fss.canonical.v1` framing) whose SHA-256 is their
//! identity. The plan is retained in custody as the payload of the deletion record; it names
//! digests, identities and sizes of the content it deletes, never the content itself.

use std::collections::BTreeSet;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, LedgerAnchor, Plane,
};

use super::DeletionError;

/// Canonical plan domain (`SCHEMA-DOMAIN-DELETION-PLAN-001`).
pub const DELETION_PLAN_DOMAIN: &str = "fss.deletion_plan.v1";
/// Exact approval domain (`SCHEMA-DOMAIN-DELETION-APPROVAL-001`).
pub const DELETION_APPROVAL_DOMAIN: &str = "fss.deletion_approval.v1";
/// Canonical completion domain (`SCHEMA-DOMAIN-DELETION-COMPLETION-001`).
pub const DELETION_COMPLETION_DOMAIN: &str = "fss.deletion_completion.v1";
/// Removal mechanism named by every plan and completion record: the spool file is unlinked from
/// the local filesystem. It is not cryptographic erasure (the spool is not encrypted).
pub const DELETION_MECHANISM: &str = "filesystem_unlink";
/// Hard ceiling on one canonical plan or completion record.
pub const MAX_DELETION_RECORD_BYTES: usize = 32 * 1024 * 1024;
/// Hard ceiling on any one list of a plan.
pub const MAX_DELETION_LIST_ENTRIES: usize = 131_072;
/// What a local deletion never proves, stated in every plan and completion record.
pub const DELETION_OUT_OF_SCOPE: &[&str] = &[
    "cryptographic_erasure:spool_not_encrypted",
    "filesystem_level_recovery",
    "backups_snapshots_and_replicas_outside_the_deployment",
    "storage_device_remanence",
];

/// One unit of the closure: a ledger batch or a visible publication root.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClosureUnit {
    /// `batch:...` batch identity or `slot:<name>` for a visible root.
    pub id: String,
    /// Stable derivative kind (`import_custody`, `decoded_frames`, `coverage_record`, ...).
    pub kind: String,
    /// `deletable_content` or `authority_history`.
    pub class: String,
    /// The retained reference that made the unit reachable from the import.
    pub via: ContentDigest,
}

/// One spool object the plan removes.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeletableObject {
    /// Object digest.
    pub digest: ContentDigest,
    /// Payload bytes (0 when the stored bytes are already corrupt and unreadable).
    pub bytes: u64,
}

/// One closure object the plan keeps, with the reason.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetainedObject {
    /// Object digest.
    pub digest: ContentDigest,
    /// `shared_with_retained_authority` or `authority_history`.
    pub reason: String,
}

/// Successor generation appended for one ledger object whose content is deleted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectTombstone {
    /// Ledger object identity.
    pub object_id: String,
    /// Current (last) generation, which the tombstone succeeds.
    pub prior_generation: u64,
    /// Owning plane (unchanged).
    pub plane: Plane,
    /// Validity of the current revision (unchanged).
    pub validity: CaptureInterval,
}

/// Retraction of one visible root's reachability claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRetraction {
    /// Slot name.
    pub slot: String,
    /// Root visible at planning time.
    pub root: ContentDigest,
    /// Current generation of the slot's reachability object, when the ledger names one.
    pub prior_generation: Option<u64>,
    /// Validity of the retraction delta.
    pub validity: CaptureInterval,
}

/// An event whose committed revisions reference deleted evidence; its history is retained.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EventReference {
    /// Ledger event object identity (`object:event:<id>`).
    pub object_id: String,
    /// Latest committed revision.
    pub latest_revision: u64,
}

/// A typed blocker or unknown copy.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Finding {
    /// Stable kind.
    pub kind: String,
    /// Subject identity.
    pub subject: String,
    /// Bounded explanation.
    pub detail: String,
}

/// Spool material the plan cannot attribute to any import; named, never deleted by this plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Unattributed {
    /// Orphaned staging files (partial writes).
    pub staging_files: u64,
    /// Their bytes.
    pub staging_bytes: u64,
    /// Indexed objects no retained unit holds and no closure reference reaches.
    pub objects: u64,
    /// Their bytes.
    pub object_bytes: u64,
}

/// The sealed deletion plan of one retained import (`CAP-DELETE-PREPARE-001`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionPlan {
    /// Site lineage.
    pub site_lineage: String,
    /// Deleted import identity.
    pub import_identity: ContentDigest,
    /// Authority head the plan was computed at; any later commit makes it stale.
    pub basis_anchor: LedgerAnchor,
    /// Effect-journal record root at planning time.
    pub effect_journal_root: ContentDigest,
    /// Validity of the deletion record (the import's own validity).
    pub validity: CaptureInterval,
    /// Spool objects read and scanned for retained references.
    pub scanned_objects: u64,
    /// Their bytes.
    pub scanned_bytes: u64,
    /// Units of the closure, sorted.
    pub units: Vec<ClosureUnit>,
    /// Objects removed, sorted by digest.
    pub deletable: Vec<DeletableObject>,
    /// Closure objects kept, sorted by digest.
    pub retained: Vec<RetainedObject>,
    /// Ledger tombstones, sorted by object identity.
    pub tombstones: Vec<ObjectTombstone>,
    /// Root retractions, sorted by slot.
    pub retractions: Vec<RootRetraction>,
    /// Events referencing deleted evidence, sorted.
    pub events: Vec<EventReference>,
    /// Blockers, sorted; a plan with any blocker is never committed.
    pub blockers: Vec<Finding>,
    /// Copies this deployment cannot delete or enumerate, sorted.
    pub unknown_copies: Vec<Finding>,
    /// Material outside the closure that cannot be attributed.
    pub unattributed: Unattributed,
}

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn invalid() -> DeletionError {
    DeletionError::Contract(ContractError::InvalidIdentifier)
}

fn encode_list<T>(
    e: &mut CanonicalEncoder,
    items: &[T],
    mut item: impl FnMut(&mut CanonicalEncoder, &T),
) {
    e.u64(items.len() as u64);
    for value in items {
        item(e, value);
    }
}

fn count(d: &mut CanonicalDecoder<'_>, minimum: usize) -> Result<usize, DeletionError> {
    let n = usize::try_from(d.u64()?).map_err(|_| invalid())?;
    if n > MAX_DELETION_LIST_ENTRIES || n > d.remaining() / minimum.max(1) {
        return Err(invalid());
    }
    Ok(n)
}

fn sha(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, DeletionError> {
    let value = d.digest()?;
    if value.algorithm() != DigestAlgorithm::Sha256 {
        return Err(ContractError::UnsupportedDigestAlgorithm.into());
    }
    Ok(value)
}

fn plane(text: &str) -> Result<Plane, DeletionError> {
    match text {
        "authority" => Ok(Plane::Authority),
        "cognition" => Ok(Plane::Cognition),
        "effect" => Ok(Plane::Effect),
        _ => Err(invalid()),
    }
}

fn encode_finding(e: &mut CanonicalEncoder, f: &Finding) {
    e.text(&f.kind);
    e.text(&f.subject);
    e.text(&f.detail);
}

fn decode_findings(d: &mut CanonicalDecoder<'_>) -> Result<Vec<Finding>, DeletionError> {
    let n = count(d, 24)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(Finding {
            kind: d.text()?.to_owned(),
            subject: d.text()?.to_owned(),
            detail: d.text()?.to_owned(),
        });
    }
    Ok(out)
}

fn strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

impl DeletionPlan {
    /// Exact canonical bytes; the plan identity is their SHA-256.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DeletionError> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.canonical.v1");
        e.text(DELETION_PLAN_DOMAIN);
        e.text(&self.site_lineage);
        e.digest(self.import_identity);
        self.basis_anchor.encode_canonical(&mut e);
        e.digest(self.effect_journal_root);
        self.validity.encode_canonical(&mut e);
        e.u64(self.scanned_objects);
        e.u64(self.scanned_bytes);
        encode_list(&mut e, &self.units, |e, u| {
            e.text(&u.id);
            e.text(&u.kind);
            e.text(&u.class);
            e.digest(u.via);
        });
        encode_list(&mut e, &self.deletable, |e, o| {
            e.digest(o.digest);
            e.u64(o.bytes);
        });
        encode_list(&mut e, &self.retained, |e, o| {
            e.digest(o.digest);
            e.text(&o.reason);
        });
        encode_list(&mut e, &self.tombstones, |e, t| {
            e.text(&t.object_id);
            e.u64(t.prior_generation);
            e.text(t.plane.as_str());
            t.validity.encode_canonical(e);
        });
        encode_list(&mut e, &self.retractions, |e, r| {
            e.text(&r.slot);
            e.digest(r.root);
            match r.prior_generation {
                Some(generation) => {
                    e.bool(true);
                    e.u64(generation);
                }
                None => e.bool(false),
            }
            r.validity.encode_canonical(e);
        });
        encode_list(&mut e, &self.events, |e, ev| {
            e.text(&ev.object_id);
            e.u64(ev.latest_revision);
        });
        encode_list(&mut e, &self.blockers, encode_finding);
        encode_list(&mut e, &self.unknown_copies, encode_finding);
        e.u64(self.unattributed.staging_files);
        e.u64(self.unattributed.staging_bytes);
        e.u64(self.unattributed.objects);
        e.u64(self.unattributed.object_bytes);
        e.text(DELETION_MECHANISM);
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_DELETION_RECORD_BYTES {
            return Err(DeletionError::Bound {
                limit: "deletion_record_bytes",
            });
        }
        Ok(bytes)
    }

    /// Plan identity.
    pub fn digest(&self) -> Result<ContentDigest, DeletionError> {
        Ok(ContentDigest::sha256(&self.canonical_bytes()?))
    }

    /// Whether `bytes` begin with the canonical plan framing (used to keep deletion records out of
    /// the reference scan).
    #[must_use]
    pub fn is_plan_bytes(bytes: &[u8]) -> bool {
        let mut d = CanonicalDecoder::new(bytes);
        matches!(d.text(), Ok("fss.canonical.v1")) && matches!(d.text(), Ok(DELETION_PLAN_DOMAIN))
    }

    /// Decodes exact canonical bytes after checking their digest; fails closed on anything else.
    pub fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self, DeletionError> {
        if bytes.len() > MAX_DELETION_RECORD_BYTES {
            return Err(DeletionError::Bound {
                limit: "deletion_record_bytes",
            });
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(ContractError::DigestMismatch.into());
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != "fss.canonical.v1" || d.text()? != DELETION_PLAN_DOMAIN {
            return Err(invalid());
        }
        let site_lineage = d.text()?.to_owned();
        let import_identity = sha(&mut d)?;
        let basis_anchor = LedgerAnchor::decode_canonical(&mut d)?;
        let effect_journal_root = sha(&mut d)?;
        let validity = CaptureInterval::decode_canonical(&mut d)?;
        let scanned_objects = d.u64()?;
        let scanned_bytes = d.u64()?;
        let n = count(&mut d, 57)?;
        let mut units = Vec::with_capacity(n);
        for _ in 0..n {
            units.push(ClosureUnit {
                id: d.text()?.to_owned(),
                kind: d.text()?.to_owned(),
                class: d.text()?.to_owned(),
                via: sha(&mut d)?,
            });
        }
        let n = count(&mut d, 41)?;
        let mut deletable = Vec::with_capacity(n);
        for _ in 0..n {
            deletable.push(DeletableObject {
                digest: sha(&mut d)?,
                bytes: d.u64()?,
            });
        }
        let n = count(&mut d, 41)?;
        let mut retained = Vec::with_capacity(n);
        for _ in 0..n {
            retained.push(RetainedObject {
                digest: sha(&mut d)?,
                reason: d.text()?.to_owned(),
            });
        }
        let n = count(&mut d, 48)?;
        let mut tombstones = Vec::with_capacity(n);
        for _ in 0..n {
            tombstones.push(ObjectTombstone {
                object_id: d.text()?.to_owned(),
                prior_generation: d.u64()?,
                plane: plane(d.text()?)?,
                validity: CaptureInterval::decode_canonical(&mut d)?,
            });
        }
        let n = count(&mut d, 50)?;
        let mut retractions = Vec::with_capacity(n);
        for _ in 0..n {
            let slot = d.text()?.to_owned();
            let root = sha(&mut d)?;
            let prior_generation = if d.bool()? { Some(d.u64()?) } else { None };
            retractions.push(RootRetraction {
                slot,
                root,
                prior_generation,
                validity: CaptureInterval::decode_canonical(&mut d)?,
            });
        }
        let n = count(&mut d, 16)?;
        let mut events = Vec::with_capacity(n);
        for _ in 0..n {
            events.push(EventReference {
                object_id: d.text()?.to_owned(),
                latest_revision: d.u64()?,
            });
        }
        let blockers = decode_findings(&mut d)?;
        let unknown_copies = decode_findings(&mut d)?;
        let unattributed = Unattributed {
            staging_files: d.u64()?,
            staging_bytes: d.u64()?,
            objects: d.u64()?,
            object_bytes: d.u64()?,
        };
        if d.text()? != DELETION_MECHANISM {
            return Err(invalid());
        }
        d.ensure_finished()?;
        let plan = Self {
            site_lineage,
            import_identity,
            basis_anchor,
            effect_journal_root,
            validity,
            scanned_objects,
            scanned_bytes,
            units,
            deletable,
            retained,
            tombstones,
            retractions,
            events,
            blockers,
            unknown_copies,
            unattributed,
        };
        let digests: Vec<ContentDigest> = plan.deletable.iter().map(|o| o.digest).collect();
        let tombstone_ids: Vec<&str> = plan
            .tombstones
            .iter()
            .map(|t| t.object_id.as_str())
            .collect();
        let slots: Vec<&str> = plan.retractions.iter().map(|r| r.slot.as_str()).collect();
        if !strictly_sorted(&plan.units)
            || !strictly_sorted(&digests)
            || !strictly_sorted(&plan.retained)
            || !strictly_sorted(&tombstone_ids)
            || !strictly_sorted(&slots)
            || !strictly_sorted(&plan.events)
            || plan.canonical_bytes()? != bytes
        {
            return Err(ContractError::NonCanonicalOrdering.into());
        }
        Ok(plan)
    }

    /// Exact approval digest of this plan for `principal` (`CAP-DELETE-COMMIT-001`).
    pub fn approval_digest(&self, principal: &str) -> Result<ContentDigest, DeletionError> {
        approval_digest(self.digest()?, &self.site_lineage, principal)
    }

    /// Bytes the plan removes.
    #[must_use]
    pub fn deletable_bytes(&self) -> u64 {
        self.deletable
            .iter()
            .fold(0_u64, |total, object| total.saturating_add(object.bytes))
    }

    /// Digests the plan removes.
    #[must_use]
    pub fn deleted_set(&self) -> BTreeSet<ContentDigest> {
        self.deletable.iter().map(|o| o.digest).collect()
    }

    /// Batch identity of the deletion record (tombstone batch).
    #[must_use]
    pub fn record_batch_id(plan_digest: ContentDigest) -> String {
        format!("batch:deletion:{}", hex(plan_digest))
    }

    /// Batch identity of the deletion-completion record.
    #[must_use]
    pub fn completion_batch_id(plan_digest: ContentDigest) -> String {
        format!("batch:deletion:{}:complete", hex(plan_digest))
    }

    /// Ledger object identity of the import's deletion record.
    #[must_use]
    pub fn record_object_id(import_identity: ContentDigest) -> String {
        format!("object:deletion:{}", hex(import_identity))
    }
}

/// Exact approval digest over a plan digest, the site and the approving principal.
pub fn approval_digest(
    plan_digest: ContentDigest,
    site_lineage: &str,
    principal: &str,
) -> Result<ContentDigest, DeletionError> {
    let mut e = CanonicalEncoder::new();
    e.text(DELETION_APPROVAL_DOMAIN);
    e.digest(plan_digest);
    e.text(site_lineage);
    e.text(principal);
    Ok(ContentDigest::sha256(&e.finish_checked()?))
}

/// The deletion-completion record (`PUB-DELETE-001`), appended last.
///
/// Deterministic from the plan and the verified absence of every removed name, so an interrupted
/// commit that resumes appends byte-identical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionCompletion {
    /// Sealed plan.
    pub plan_digest: ContentDigest,
    /// Deleted import.
    pub import_identity: ContentDigest,
    /// Objects unlinked, every name verified absent from the spool afterwards.
    pub objects_unlinked: u64,
    /// Their bytes.
    pub bytes_unlinked: u64,
    /// Roots retracted, every record verified absent afterwards.
    pub roots_retracted: u64,
    /// Ledger objects tombstoned by the deletion record.
    pub ledger_objects_tombstoned: u64,
    /// Closure objects retained (shared with retained authority, or authority history).
    pub objects_retained: u64,
    /// Events whose history is retained with evidence handles resolving to `deleted`.
    pub events_with_deleted_evidence: u64,
    /// Blockers at commit (always empty: a blocked plan is refused before any write).
    pub blocked: Vec<Finding>,
    /// Copies this deployment could not delete or enumerate; not proven deleted.
    pub not_proven: Vec<Finding>,
}

impl DeletionCompletion {
    /// Builds the record of a fully applied plan.
    pub fn of(plan: &DeletionPlan) -> Result<Self, DeletionError> {
        Ok(Self {
            plan_digest: plan.digest()?,
            import_identity: plan.import_identity,
            objects_unlinked: plan.deletable.len() as u64,
            bytes_unlinked: plan.deletable_bytes(),
            roots_retracted: plan.retractions.len() as u64,
            ledger_objects_tombstoned: plan.tombstones.len() as u64,
            objects_retained: plan.retained.len() as u64,
            events_with_deleted_evidence: plan.events.len() as u64,
            blocked: plan.blockers.clone(),
            not_proven: plan.unknown_copies.clone(),
        })
    }

    /// Exact canonical bytes; identity is their SHA-256.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DeletionError> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.canonical.v1");
        e.text(DELETION_COMPLETION_DOMAIN);
        e.digest(self.plan_digest);
        e.digest(self.import_identity);
        e.u64(self.objects_unlinked);
        e.u64(self.bytes_unlinked);
        e.u64(self.roots_retracted);
        e.u64(self.ledger_objects_tombstoned);
        e.u64(self.objects_retained);
        e.u64(self.events_with_deleted_evidence);
        encode_list(&mut e, &self.blocked, encode_finding);
        encode_list(&mut e, &self.not_proven, encode_finding);
        e.text(DELETION_MECHANISM);
        e.bool(false);
        e.u64(DELETION_OUT_OF_SCOPE.len() as u64);
        for item in DELETION_OUT_OF_SCOPE {
            e.text(item);
        }
        Ok(e.finish_checked()?)
    }

    /// Completion identity.
    pub fn digest(&self) -> Result<ContentDigest, DeletionError> {
        Ok(ContentDigest::sha256(&self.canonical_bytes()?))
    }

    /// Whether `bytes` begin with the canonical completion framing.
    #[must_use]
    pub fn is_completion_bytes(bytes: &[u8]) -> bool {
        let mut d = CanonicalDecoder::new(bytes);
        matches!(d.text(), Ok("fss.canonical.v1"))
            && matches!(d.text(), Ok(DELETION_COMPLETION_DOMAIN))
    }

    /// Decodes exact canonical bytes after checking their digest.
    pub fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self, DeletionError> {
        if bytes.len() > MAX_DELETION_RECORD_BYTES {
            return Err(DeletionError::Bound {
                limit: "deletion_record_bytes",
            });
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(ContractError::DigestMismatch.into());
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != "fss.canonical.v1" || d.text()? != DELETION_COMPLETION_DOMAIN {
            return Err(invalid());
        }
        let record = Self {
            plan_digest: sha(&mut d)?,
            import_identity: sha(&mut d)?,
            objects_unlinked: d.u64()?,
            bytes_unlinked: d.u64()?,
            roots_retracted: d.u64()?,
            ledger_objects_tombstoned: d.u64()?,
            objects_retained: d.u64()?,
            events_with_deleted_evidence: d.u64()?,
            blocked: decode_findings(&mut d)?,
            not_proven: decode_findings(&mut d)?,
        };
        if d.text()? != DELETION_MECHANISM || d.bool()? {
            return Err(invalid());
        }
        let n = count(&mut d, 8)?;
        if n != DELETION_OUT_OF_SCOPE.len() {
            return Err(invalid());
        }
        for item in DELETION_OUT_OF_SCOPE {
            if d.text()? != *item {
                return Err(invalid());
            }
        }
        d.ensure_finished()?;
        if record.canonical_bytes()? != bytes {
            return Err(ContractError::NonCanonicalOrdering.into());
        }
        Ok(record)
    }
}
