#![forbid(unsafe_code)]
//! Deletion holds: owner-placed, approval-gated authority that blocks deletion planning.
//!
//! A hold names one scope and a reason: an import (`import:sha256:...`), a sensor (`sensor:ID`,
//! covering every import whose capsules name the sensor) or an event (`event:ID`, covering every
//! import whose deletion closure reaches the event's revisions). It is retained as authority in
//! the reserved `deletion_hold` ledger family, one object per hold
//! (`object:deletion-hold:<hold id hex>`): generation 1 is the placement record
//! (`fss.deletion_hold.v1`, whose SHA-256 is the hold identity), generation 2 the release record
//! (`fss.deletion_hold_release.v1`). Nothing is ever erased: a released hold keeps both records.
//!
//! Lifecycle, mirroring privacy masks: a preview computes the canonical record and its exact
//! approval (`fss.deletion_hold_approval.v1`), bound to the authority head the preview was
//! computed at, and writes nothing. Only that approval retains it; an approval previewed against
//! an older head is stale, and re-presenting the approval that already retained a record writes
//! nothing.
//!
//! A hold is *active* until it is released or, when it names `expires_at_ns`, until the
//! deployment's **evidence clock** reaches that time. The evidence clock is the latest committed
//! evidence time: the largest bounded validity end of any ledger delta (open-ended standing
//! declarations such as mask policies carry no evidence time). It is not wall time: it advances
//! only when evidence is committed, so an idle deployment never expires a hold, and equal
//! committed bytes always give equal answers.
//!
//! Every active hold covering an import is a deletion-plan blocker (`active_hold`); a hold record
//! that cannot be read is a blocker too (`hold_unreadable`), never silently skipped. Because a
//! plan binds the authority head, a hold placed (or released) after planning makes the plan
//! stale, and `delete commit` recomputes the plan, so it revalidates every hold.

use std::collections::BTreeSet;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContractError, EvidenceDelta, ObjectId, Plane, SensorCapsule,
    SensorId, TimestampNs,
};

use super::DeletionError;
use super::index::DeletionIndex;
use super::plan::{DeletionPlan, Finding};
use crate::reference_deployment::{FAMILY_DELETION_HOLD, FAMILY_SENSOR_CAPSULE};
use crate::{ReferenceDeployment, ReplayCx};

/// Canonical placement record domain (`SCHEMA-DOMAIN-DELETION-HOLD-001`).
pub const HOLD_DOMAIN: &str = "fss.deletion_hold.v1";
/// Canonical release record domain (`SCHEMA-DOMAIN-DELETION-HOLD-RELEASE-001`).
pub const HOLD_RELEASE_DOMAIN: &str = "fss.deletion_hold_release.v1";
/// Exact place/release approval domain (`SCHEMA-DOMAIN-DELETION-HOLD-APPROVAL-001`).
pub const HOLD_APPROVAL_DOMAIN: &str = "fss.deletion_hold_approval.v1";
/// Longest hold reason, in bytes.
pub const MAX_HOLD_REASON_BYTES: usize = 512;
/// Hard ceiling on one hold record.
pub const MAX_HOLD_RECORD_BYTES: usize = 4096;

const HOLD_MAGIC: &[u8] = b"FSSHLD01";
const RELEASE_MAGIC: &[u8] = b"FSSHLR01";
const RECORD_VERSION: u32 = 1;
const OBJECT_PREFIX: &str = "object:deletion-hold:";
const IMPORT_BATCH_PREFIX: &str = "batch:file-import:";

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn refused(reason: &'static str) -> DeletionError {
    DeletionError::HoldRequest(reason)
}

fn damaged() -> DeletionError {
    DeletionError::RecordMismatch
}

/// What one hold covers: the deletion scope ([`super::scope`]), the same notion a scoped
/// deletion plan uses.
pub use super::scope::DeletionScope as HoldScope;

/// The owner's placement request, before it is bound to the authority head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldRequest {
    /// What the hold covers.
    pub scope: HoldScope,
    /// Why (1..=512 bytes, no control characters).
    pub reason: String,
    /// Evidence-clock time at which the hold stops blocking (not wall time), if any.
    pub expires_at_ns: Option<u64>,
    /// Placing principal (an audit label, not remote authentication).
    pub principal: String,
}

/// The canonical placement record; its digest is the hold identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldRecord {
    /// Site lineage.
    pub site_lineage: String,
    /// The request.
    pub request: HoldRequest,
    /// Authority commit sequence the record (and its approval) was computed at.
    pub basis_sequence: u64,
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= MAX_HOLD_REASON_BYTES
        && !reason.chars().any(char::is_control)
}

impl HoldRecord {
    /// Exact canonical bytes (the retained payload).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(HOLD_MAGIC);
        e.u32(RECORD_VERSION);
        e.text(HOLD_DOMAIN);
        e.text(&self.site_lineage);
        self.request.scope.encode(&mut e);
        e.text(&self.request.reason);
        match self.request.expires_at_ns {
            None => e.u8(0),
            Some(at) => {
                e.u8(1);
                e.u64(at);
            }
        }
        e.text(&self.request.principal);
        e.u64(self.basis_sequence);
        e.finish()
    }

    /// Hold identity (SHA-256 of [`Self::to_bytes`]).
    #[must_use]
    pub fn hold_id(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Decodes exact retained bytes against their identity; non-canonical input fails.
    pub fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self, DeletionError> {
        if bytes.len() > MAX_HOLD_RECORD_BYTES || ContentDigest::sha256(bytes) != expected {
            return Err(damaged());
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != HOLD_MAGIC || d.u32()? != RECORD_VERSION || d.text()? != HOLD_DOMAIN {
            return Err(damaged());
        }
        let site_lineage = d.text()?.to_owned();
        let scope = HoldScope::decode(&mut d)?;
        let reason = d.text()?.to_owned();
        let expires_at_ns = match d.u8()? {
            0 => None,
            1 => Some(d.u64()?),
            _ => return Err(damaged()),
        };
        let principal = d.text()?.to_owned();
        let basis_sequence = d.u64()?;
        d.ensure_finished()?;
        let record = Self {
            site_lineage,
            request: HoldRequest {
                scope,
                reason,
                expires_at_ns,
                principal,
            },
            basis_sequence,
        };
        if !valid_reason(&record.request.reason) || record.to_bytes() != bytes {
            return Err(damaged());
        }
        Ok(record)
    }
}

/// The canonical release record of one hold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseRecord {
    /// Site lineage.
    pub site_lineage: String,
    /// Released hold.
    pub hold_id: ContentDigest,
    /// Releasing principal.
    pub principal: String,
    /// Authority commit sequence the record (and its approval) was computed at.
    pub basis_sequence: u64,
}

impl ReleaseRecord {
    /// Exact canonical bytes (the retained payload).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(RELEASE_MAGIC);
        e.u32(RECORD_VERSION);
        e.text(HOLD_RELEASE_DOMAIN);
        e.text(&self.site_lineage);
        e.digest(self.hold_id);
        e.text(&self.principal);
        e.u64(self.basis_sequence);
        e.finish()
    }

    /// Record digest.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Decodes exact retained bytes against their identity; non-canonical input fails.
    pub fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self, DeletionError> {
        if bytes.len() > MAX_HOLD_RECORD_BYTES || ContentDigest::sha256(bytes) != expected {
            return Err(damaged());
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != RELEASE_MAGIC
            || d.u32()? != RECORD_VERSION
            || d.text()? != HOLD_RELEASE_DOMAIN
        {
            return Err(damaged());
        }
        let record = Self {
            site_lineage: d.text()?.to_owned(),
            hold_id: d.digest()?,
            principal: d.text()?.to_owned(),
            basis_sequence: d.u64()?,
        };
        d.ensure_finished()?;
        if record.to_bytes() != bytes {
            return Err(damaged());
        }
        Ok(record)
    }
}

/// Exact approval of placing (`release = false`) or releasing (`release = true`) the record
/// whose digest is `record`.
#[must_use]
pub fn hold_approval_digest(release: bool, record: ContentDigest) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(HOLD_APPROVAL_DOMAIN);
    e.u8(u8::from(release) + 1);
    e.digest(record);
    ContentDigest::sha256(&e.finish())
}

/// Ledger object of one hold.
pub fn hold_object_id(hold_id: ContentDigest) -> Result<ObjectId, ContractError> {
    ObjectId::parse(format!("{OBJECT_PREFIX}{}", hex(hold_id)))
}

/// Lifecycle state of one retained hold at one evidence-clock time.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HoldState {
    /// Blocks deletion of everything it covers.
    Active,
    /// Its expiry is at or before the evidence clock; it no longer blocks.
    Expired,
    /// A release record is retained; it no longer blocks.
    Released,
}

impl HoldState {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Released => "released",
        }
    }
}

/// One retained hold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedHold {
    /// Hold identity.
    pub hold_id: ContentDigest,
    /// Placement record.
    pub record: HoldRecord,
    /// Release record digest and record, when released.
    pub release: Option<(ContentDigest, ReleaseRecord)>,
    /// State at the evidence clock of the read.
    pub state: HoldState,
}

/// Every hold of a deployment at one evidence-clock time.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HoldRegistry {
    /// Evidence-clock time the states were evaluated at (ns; not wall time).
    pub evidence_clock_ns: u64,
    /// Readable holds, sorted by identity.
    pub holds: Vec<RetainedHold>,
    /// Ledger objects of the hold family whose records cannot be read or verified. They block
    /// every deletion (fail closed) until repaired.
    pub unreadable: Vec<String>,
}

/// The deployment's evidence clock: the largest bounded validity end of any committed ledger
/// delta (ns, never negative). Open-ended standing declarations (validity ending at
/// `i64::MAX`, such as privacy-mask policies) carry no evidence time. Not wall time.
#[must_use]
pub fn evidence_clock(deployment: &ReferenceDeployment) -> TimestampNs {
    let open_ended = i128::from(i64::MAX);
    let latest = deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| batch.deltas.iter())
        .map(|delta| delta.validity.latest.0)
        .filter(|latest| *latest < open_ended)
        .max()
        .unwrap_or(0);
    TimestampNs(latest.max(0))
}

fn clock_ns(clock: TimestampNs) -> u64 {
    u64::try_from(clock.0).unwrap_or(0)
}

fn state(record: &HoldRecord, released: bool, clock: u64) -> HoldState {
    if released {
        HoldState::Released
    } else if record.request.expires_at_ns.is_some_and(|at| at <= clock) {
        HoldState::Expired
    } else {
        HoldState::Active
    }
}

/// Reads every retained hold and its state at the current evidence clock. A hold object whose
/// records cannot be read, verified or ordered is listed as unreadable, never skipped.
pub fn hold_registry(deployment: &ReferenceDeployment) -> HoldRegistry {
    let clock = clock_ns(evidence_clock(deployment));
    let mut generations: std::collections::BTreeMap<
        String,
        Vec<(u64, Option<u64>, ContentDigest)>,
    > = std::collections::BTreeMap::new();
    for delta in deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| batch.deltas.iter())
        .filter(|delta| delta.family == FAMILY_DELETION_HOLD)
    {
        generations
            .entry(delta.object_id.as_str().to_owned())
            .or_default()
            .push((
                delta.new_generation,
                delta.prior_generation,
                delta.payload_digest,
            ));
    }
    let spool = deployment.publisher().spool();
    let mut registry = HoldRegistry {
        evidence_clock_ns: clock,
        ..HoldRegistry::default()
    };
    for (object, mut entries) in generations {
        entries.sort_unstable();
        let read = || -> Result<RetainedHold, DeletionError> {
            let hold_id = match entries.first() {
                Some((1, None, digest)) => *digest,
                _ => return Err(damaged()),
            };
            if hold_object_id(hold_id)?.as_str() != object {
                return Err(damaged());
            }
            let record = HoldRecord::decode(&spool.read(hold_id)?, hold_id)?;
            if record.site_lineage != deployment.site_lineage() {
                return Err(damaged());
            }
            let release = match entries.get(1..) {
                Some([]) | None => None,
                Some([(2, Some(1), digest)]) => {
                    let release = ReleaseRecord::decode(&spool.read(*digest)?, *digest)?;
                    if release.hold_id != hold_id
                        || release.site_lineage != deployment.site_lineage()
                    {
                        return Err(damaged());
                    }
                    Some((*digest, release))
                }
                Some(_) => return Err(damaged()),
            };
            Ok(RetainedHold {
                hold_id,
                state: state(&record, release.is_some(), clock),
                record,
                release,
            })
        };
        match read() {
            Ok(hold) => registry.holds.push(hold),
            Err(_) => registry.unreadable.push(object),
        }
    }
    registry.holds.sort_by_key(|hold| hold.hold_id);
    registry
}

/// Sensors named by the capsules of `import` (its `file_import` batches), or `None` when a
/// capsule cannot be read.
pub(super) fn import_sensors(
    deployment: &ReferenceDeployment,
    import: ContentDigest,
) -> Option<BTreeSet<SensorId>> {
    let prefix = format!("{IMPORT_BATCH_PREFIX}{}:", hex(import));
    let spool = deployment.publisher().spool();
    let mut sensors = BTreeSet::new();
    for batch in deployment
        .ledger()
        .batches()
        .iter()
        .filter(|batch| batch.batch_id.as_str().starts_with(&prefix))
    {
        for delta in batch
            .deltas
            .iter()
            .filter(|delta| delta.family == FAMILY_SENSOR_CAPSULE)
        {
            let bytes = spool.read(delta.payload_digest).ok()?;
            if ContentDigest::sha256(&bytes) != delta.payload_digest {
                return None;
            }
            sensors.insert(SensorCapsule::from_canonical_bytes(&bytes).ok()?.sensor_id);
        }
    }
    Some(sensors)
}

/// How one hold covers one import, or `None` when it does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Coverage {
    /// The hold names the import.
    Import,
    /// The hold names a sensor of the import's capsules.
    Sensor,
    /// The hold names an event whose revisions the import's closure reaches.
    Event,
    /// A sensor hold exists but the import's capsules cannot be read to decide.
    Unresolved,
}

impl Coverage {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Sensor => "sensor",
            Self::Event => "event",
            Self::Unresolved => "unresolved",
        }
    }
}

/// Every hold that covers `import`, given the ledger event objects (`object:event:<id>`) its
/// closure reaches, with the coverage and state; plus the unreadable hold objects.
pub fn covering_holds(
    deployment: &ReferenceDeployment,
    import: ContentDigest,
    closure_events: &BTreeSet<String>,
) -> (HoldRegistry, Vec<(RetainedHold, Coverage)>) {
    let registry = hold_registry(deployment);
    let mut sensors: Option<Option<BTreeSet<SensorId>>> = None;
    let mut covering = Vec::new();
    for hold in &registry.holds {
        let coverage = match &hold.record.request.scope {
            HoldScope::Import(digest) => (*digest == import).then_some(Coverage::Import),
            HoldScope::Event(event) => closure_events
                .contains(&format!("object:event:{}", event.as_str()))
                .then_some(Coverage::Event),
            HoldScope::Sensor(sensor) => {
                match sensors.get_or_insert_with(|| import_sensors(deployment, import)) {
                    Some(set) => set.contains(sensor).then_some(Coverage::Sensor),
                    None => Some(Coverage::Unresolved),
                }
            }
        };
        if let Some(coverage) = coverage {
            covering.push((hold.clone(), coverage));
        }
    }
    (registry, covering)
}

/// Every hold covering any member import of `plan` (given the events its closure reaches), once
/// per hold with its first coverage in member order, plus the unreadable hold objects. For an
/// import-scope plan this is exactly [`covering_holds`] of its import.
pub fn covering_plan_holds(
    deployment: &ReferenceDeployment,
    plan: &DeletionPlan,
) -> (HoldRegistry, Vec<(RetainedHold, Coverage)>) {
    let events: BTreeSet<String> = plan.events.iter().map(|e| e.object_id.clone()).collect();
    let mut registry = HoldRegistry::default();
    let mut covering: Vec<(RetainedHold, Coverage)> = Vec::new();
    for import in &plan.imports {
        let (read, found) = covering_holds(deployment, *import, &events);
        registry = read;
        for (hold, coverage) in found {
            if !covering.iter().any(|(seen, _)| seen.hold_id == hold.hold_id) {
                covering.push((hold, coverage));
            }
        }
    }
    (registry, covering)
}

/// Deletion-plan blockers of `import`: every active covering hold (`active_hold`; a sensor hold
/// that cannot be decided counts as covering) and every unreadable hold (`hold_unreadable`).
pub(super) fn blockers(
    deployment: &ReferenceDeployment,
    import: ContentDigest,
    closure_events: &BTreeSet<String>,
) -> Vec<Finding> {
    let (registry, covering) = covering_holds(deployment, import, closure_events);
    let mut out: Vec<Finding> = registry
        .unreadable
        .iter()
        .map(|object| Finding {
            kind: "hold_unreadable".to_owned(),
            subject: object.clone(),
            detail: "a deletion hold record cannot be read or verified; no deletion can prove it \
                     is not held"
                .to_owned(),
        })
        .collect();
    for (hold, coverage) in covering {
        if hold.state != HoldState::Active {
            continue;
        }
        let request = &hold.record.request;
        let expiry = request.expires_at_ns.map_or_else(
            || "it has no expiry".to_owned(),
            |at| {
                format!(
                    "it expires at evidence time {at} ns (evidence clock now {} ns; not wall time)",
                    registry.evidence_clock_ns
                )
            },
        );
        out.push(Finding {
            kind: "active_hold".to_owned(),
            subject: hold.hold_id.to_text(),
            detail: format!(
                "deletion hold on {} covers this import via its {} (reason: {}); release it \
                 (fss-event hold release) or wait until {expiry}",
                request.scope.text(),
                coverage.as_str(),
                request.reason
            ),
        });
    }
    out
}

/// Retention state of one place or release call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldStatus {
    /// Previewed only; nothing is retained.
    Proposed,
    /// Retained by this call.
    Retained,
    /// This exact approval was already retained; nothing was written.
    AlreadyRetained,
    /// (release) The hold is already released; nothing was written.
    AlreadyReleased,
}

impl HoldStatus {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Retained => "retained",
            Self::AlreadyRetained => "already_retained",
            Self::AlreadyReleased => "already_released",
        }
    }
}

/// Result of a place preview or placement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldPlacement {
    /// Status.
    pub status: HoldStatus,
    /// Hold identity (of the retained hold when already retained).
    pub hold_id: ContentDigest,
    /// The placement record.
    pub record: HoldRecord,
    /// Its exact approval.
    pub approval: ContentDigest,
    /// Evidence clock at the call (ns; not wall time).
    pub evidence_clock_ns: u64,
}

fn validate(
    deployment: &ReferenceDeployment,
    request: &HoldRequest,
    clock: u64,
) -> Result<(), DeletionError> {
    if !valid_reason(&request.reason) {
        return Err(request_error_reason());
    }
    fss_core::PrincipalId::parse(&request.principal)
        .map_err(|_| refused("invalid principal identity"))?;
    if request.expires_at_ns.is_some_and(|at| at <= clock) {
        return Err(refused(
            "the expiry is at or before the deployment's evidence clock; the hold would never \
             block",
        ));
    }
    match &request.scope {
        HoldScope::Import(import) => {
            let index = DeletionIndex::read(deployment)?;
            if let Some(entry) = index.import(*import) {
                return Err(DeletionError::EvidenceDeleted {
                    import: *import,
                    plan: entry.plan_digest,
                });
            }
            let manifest = format!("{IMPORT_BATCH_PREFIX}{}:manifest", hex(*import));
            if !deployment
                .ledger()
                .batches()
                .iter()
                .any(|batch| batch.batch_id.as_str() == manifest)
            {
                return Err(DeletionError::UnknownImport(*import));
            }
        }
        HoldScope::Event(event) => {
            let object = format!("object:event:{}", event.as_str());
            if !deployment
                .ledger()
                .current()
                .objects
                .keys()
                .any(|id| id.as_str() == object)
            {
                return Err(refused("no committed event has this identity"));
            }
        }
        HoldScope::Sensor(_) => {}
    }
    Ok(())
}

const fn request_error_reason() -> DeletionError {
    DeletionError::HoldRequest("a hold reason is 1..512 bytes of text without control characters")
}

/// Previews placing `request`: the canonical record bound to the current authority head and its
/// exact approval. Writes nothing.
pub fn preview_hold(
    deployment: &ReferenceDeployment,
    request: &HoldRequest,
) -> Result<HoldPlacement, DeletionError> {
    let clock = clock_ns(evidence_clock(deployment));
    validate(deployment, request, clock)?;
    let record = HoldRecord {
        site_lineage: deployment.site_lineage().to_owned(),
        request: request.clone(),
        basis_sequence: deployment.current_anchor().commit_sequence,
    };
    if record.to_bytes().len() > MAX_HOLD_RECORD_BYTES {
        return Err(request_error_reason());
    }
    let hold_id = record.hold_id();
    Ok(HoldPlacement {
        status: HoldStatus::Proposed,
        hold_id,
        approval: hold_approval_digest(false, hold_id),
        record,
        evidence_clock_ns: clock,
    })
}

/// Places `request` under its exact approval (`deletion_hold` generation 1). Re-presenting the
/// approval that already placed a hold writes nothing; any other mismatch is stale.
pub fn place_hold(
    deployment: &mut ReferenceDeployment,
    request: &HoldRequest,
    approval: ContentDigest,
    cx: &ReplayCx,
) -> Result<HoldPlacement, DeletionError> {
    let registry = hold_registry(deployment);
    if let Some(hold) = registry
        .holds
        .iter()
        .find(|hold| hold_approval_digest(false, hold.hold_id) == approval)
    {
        return Ok(HoldPlacement {
            status: HoldStatus::AlreadyRetained,
            hold_id: hold.hold_id,
            approval,
            record: hold.record.clone(),
            evidence_clock_ns: registry.evidence_clock_ns,
        });
    }
    let preview = preview_hold(deployment, request)?;
    if preview.approval != approval {
        return Err(DeletionError::HoldApprovalStale(approval));
    }
    cx.checkpoint("deletion:hold_place")
        .map_err(|_| DeletionError::Cancelled {
            stage: "deletion:hold_place",
        })?;
    let bytes = preview.record.to_bytes();
    let payload = deployment.stage_payload(&bytes)?;
    if payload != preview.hold_id {
        return Err(damaged());
    }
    let clock = TimestampNs(i128::from(preview.evidence_clock_ns));
    let delta = EvidenceDelta {
        delta_id: format!("delta:deletion-hold:{}", hex(preview.hold_id)),
        family: FAMILY_DELETION_HOLD.to_owned(),
        object_id: hold_object_id(preview.hold_id)?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(clock, clock)?,
        plane: Plane::Authority,
        payload_digest: payload,
        witness_digest: None,
        operation_id: None,
    };
    let batch = BatchId::parse(format!("batch:deletion-hold:{}", hex(preview.hold_id)))?;
    deployment.append_deletion_batch(batch, vec![delta], vec![payload], cx)?;
    cx.checkpoint_post_commit("deletion:hold_placed");
    Ok(HoldPlacement {
        status: HoldStatus::Retained,
        ..preview
    })
}

/// Result of a release preview or release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldRelease {
    /// Status.
    pub status: HoldStatus,
    /// The hold.
    pub hold: RetainedHold,
    /// Release record digest and its exact approval (`None` when already released).
    pub release: Option<(ReleaseRecord, ContentDigest)>,
    /// Evidence clock at the call (ns; not wall time).
    pub evidence_clock_ns: u64,
}

/// Previews releasing `hold_id` for `principal`. Writes nothing.
pub fn preview_release(
    deployment: &ReferenceDeployment,
    hold_id: ContentDigest,
    principal: &str,
) -> Result<HoldRelease, DeletionError> {
    fss_core::PrincipalId::parse(principal).map_err(|_| refused("invalid principal identity"))?;
    let registry = hold_registry(deployment);
    let object = hold_object_id(hold_id)?;
    if registry.unreadable.iter().any(|o| o == object.as_str()) {
        return Err(damaged());
    }
    let hold = registry
        .holds
        .into_iter()
        .find(|hold| hold.hold_id == hold_id)
        .ok_or_else(|| refused("no retained deletion hold has this identity"))?;
    if hold.release.is_some() {
        return Ok(HoldRelease {
            status: HoldStatus::AlreadyReleased,
            hold,
            release: None,
            evidence_clock_ns: registry.evidence_clock_ns,
        });
    }
    let record = ReleaseRecord {
        site_lineage: deployment.site_lineage().to_owned(),
        hold_id,
        principal: principal.to_owned(),
        basis_sequence: deployment.current_anchor().commit_sequence,
    };
    let approval = hold_approval_digest(true, record.digest());
    Ok(HoldRelease {
        status: HoldStatus::Proposed,
        hold,
        release: Some((record, approval)),
        evidence_clock_ns: registry.evidence_clock_ns,
    })
}

/// Releases `hold_id` under its exact approval (`deletion_hold` generation 2). The placement
/// record is kept; re-presenting the approval that released it writes nothing.
pub fn release_hold(
    deployment: &mut ReferenceDeployment,
    hold_id: ContentDigest,
    principal: &str,
    approval: ContentDigest,
    cx: &ReplayCx,
) -> Result<HoldRelease, DeletionError> {
    let preview = preview_release(deployment, hold_id, principal)?;
    let Some((record, expected)) = preview.release.clone() else {
        let already = preview
            .hold
            .release
            .as_ref()
            .is_some_and(|(digest, _)| hold_approval_digest(true, *digest) == approval);
        return if already {
            Ok(HoldRelease {
                status: HoldStatus::AlreadyRetained,
                ..preview
            })
        } else {
            Err(DeletionError::HoldApprovalStale(approval))
        };
    };
    if expected != approval {
        return Err(DeletionError::HoldApprovalStale(approval));
    }
    cx.checkpoint("deletion:hold_release")
        .map_err(|_| DeletionError::Cancelled {
            stage: "deletion:hold_release",
        })?;
    let payload = deployment.stage_payload(&record.to_bytes())?;
    if payload != record.digest() {
        return Err(damaged());
    }
    let clock = TimestampNs(i128::from(preview.evidence_clock_ns));
    let delta = EvidenceDelta {
        delta_id: format!("delta:deletion-hold-release:{}", hex(hold_id)),
        family: FAMILY_DELETION_HOLD.to_owned(),
        object_id: hold_object_id(hold_id)?,
        prior_generation: Some(1),
        new_generation: 2,
        validity: CaptureInterval::new(clock, clock)?,
        plane: Plane::Authority,
        payload_digest: payload,
        witness_digest: None,
        operation_id: None,
    };
    let batch = BatchId::parse(format!("batch:deletion-hold-release:{}", hex(hold_id)))?;
    deployment.append_deletion_batch(batch, vec![delta], vec![payload], cx)?;
    cx.checkpoint_post_commit("deletion:hold_released");
    let mut hold = preview.hold;
    hold.release = Some((payload, record.clone()));
    hold.state = HoldState::Released;
    Ok(HoldRelease {
        status: HoldStatus::Retained,
        hold,
        release: Some((record, approval)),
        evidence_clock_ns: preview.evidence_clock_ns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn record(scope: &str, expires_at_ns: Option<u64>) -> Result<HoldRecord, DeletionError> {
        Ok(HoldRecord {
            site_lineage: "site:holds".to_owned(),
            request: HoldRequest {
                scope: HoldScope::parse(scope)?,
                reason: "litigation hold".to_owned(),
                expires_at_ns,
                principal: "principal:local-operator".to_owned(),
            },
            basis_sequence: 7,
        })
    }

    #[test]
    fn scopes_parse_exactly_and_round_trip_their_spelling() -> TestResult {
        let import = ContentDigest::sha256(b"import").to_text();
        for (text, kind) in [
            (format!("import:{import}"), "import"),
            ("sensor:sensor:alpha".to_owned(), "sensor"),
            ("event:event:e1".to_owned(), "event"),
        ] {
            let scope = HoldScope::parse(&text)?;
            assert_eq!(scope.text(), text);
            assert_eq!(scope.kind(), kind);
        }
        for bad in [
            "camera:alpha",
            "import:md5:00",
            "import:sha256:zz",
            "sensor:",
            "event:",
            "",
        ] {
            assert!(
                matches!(HoldScope::parse(bad), Err(DeletionError::HoldRequest(_))),
                "{bad}"
            );
        }
        Ok(())
    }

    #[test]
    fn records_are_canonical_and_bound_to_their_identity() -> TestResult {
        for (scope, expiry) in [
            (
                format!("import:{}", ContentDigest::sha256(b"i").to_text()),
                None,
            ),
            ("sensor:sensor:alpha".to_owned(), Some(5)),
            ("event:event:e1".to_owned(), Some(u64::MAX)),
        ] {
            let hold = record(&scope, expiry)?;
            let bytes = hold.to_bytes();
            assert_eq!(HoldRecord::decode(&bytes, hold.hold_id())?, hold);
            // Another identity, a truncation or trailing bytes are refused.
            assert!(HoldRecord::decode(&bytes, ContentDigest::sha256(b"other")).is_err());
            let short = &bytes[..bytes.len() - 1];
            assert!(HoldRecord::decode(short, ContentDigest::sha256(short)).is_err());
            let long = [bytes.as_slice(), &[0]].concat();
            assert!(HoldRecord::decode(&long, ContentDigest::sha256(&long)).is_err());
        }
        // Every field is bound: another basis is another hold.
        let mut moved = record("sensor:sensor:alpha", None)?;
        let before = moved.hold_id();
        moved.basis_sequence += 1;
        assert_ne!(moved.hold_id(), before);
        // A record with an invalid reason never decodes.
        let mut empty = record("sensor:sensor:alpha", None)?;
        empty.request.reason = String::new();
        let bytes = empty.to_bytes();
        assert!(HoldRecord::decode(&bytes, ContentDigest::sha256(&bytes)).is_err());

        let release = ReleaseRecord {
            site_lineage: "site:holds".to_owned(),
            hold_id: before,
            principal: "principal:local-operator".to_owned(),
            basis_sequence: 9,
        };
        assert_eq!(
            ReleaseRecord::decode(&release.to_bytes(), release.digest())?,
            release
        );
        // A placement record is never a release record, and the approvals are distinct.
        assert!(ReleaseRecord::decode(&moved.to_bytes(), moved.hold_id()).is_err());
        assert_ne!(
            hold_approval_digest(false, release.digest()),
            hold_approval_digest(true, release.digest())
        );
        Ok(())
    }

    #[test]
    fn expiry_is_measured_on_the_evidence_clock_and_release_wins() -> TestResult {
        let hold = record("sensor:sensor:alpha", Some(100))?;
        assert_eq!(state(&hold, false, 99), HoldState::Active);
        assert_eq!(state(&hold, false, 100), HoldState::Expired);
        assert_eq!(state(&hold, true, 0), HoldState::Released);
        let open = record("sensor:sensor:alpha", None)?;
        assert_eq!(state(&open, false, u64::MAX), HoldState::Active);
        Ok(())
    }
}
