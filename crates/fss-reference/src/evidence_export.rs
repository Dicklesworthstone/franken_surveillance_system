#![forbid(unsafe_code)]
//! Approval-gated redacted P5 event evidence exports.
//!
//! The export root contains only one redacted metadata record. Raw media, source/device identity,
//! zone/track identifiers, model tensors, and live archive roots are never manifest children.
//! Existing event/source custody is referenced by digest text only.

use crate::{ReferenceDeployment, ReferenceError, ReplayCx};
use fss_core::region::ContextAuthority;
use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, EventId, EventKind, EventState, EvidenceClass,
    EvidenceDelta, EvidenceEdgeRelation, LedgerAnchor, ObjectId, Plane, PrincipalId, TimestampNs,
};
use fss_object::{ObjectError, ObjectManifest, SpoolError};
use fss_publication::SlotName;
use std::fmt;

/// Capability to preview a redacted event export (`CAP-EXPORT-PREPARE-001`).
pub const CAP_EXPORT_PREPARE: &str = "CAP-EXPORT-PREPARE-001";
/// Capability to commit an exactly approved export (`CAP-EXPORT-COMMIT-001`).
pub const CAP_EXPORT_COMMIT: &str = "CAP-EXPORT-COMMIT-001";
/// Authority-ledger delta family that retains committed export records.
pub const FAMILY_EVIDENCE_EXPORT: &str = "evidence_export";
/// Reserved ledger object namespace of export records.
pub const EXPORT_OBJECT_PREFIX: &str = "object:evidence-export:";
/// Canonical digest domain of an export record.
pub const EXPORT_DOMAIN: &str = "fss.evidence_export.v1";
/// Canonical digest domain of an export approval.
pub const EXPORT_APPROVAL_DOMAIN: &str = "fss.evidence_export_approval.v1";
/// The only export profile: redacted event summary, no raw media.
pub const EXPORT_PROFILE: &str = "event-summary-redacted-v1";
/// Upper bound on one encoded export record.
pub const MAX_EXPORT_RECORD_BYTES: usize = 64 * 1024;
/// Upper bound on the recipient label.
pub const MAX_RECIPIENT_BYTES: usize = 256;
/// Upper bound on the stated purpose.
pub const MAX_PURPOSE_BYTES: usize = 512;
/// Maximum authority batches examined during verified export readback.
pub const MAX_EXPORT_LEDGER_BATCHES: usize = 65_536;
const POLICY: &[u8] = b"fss.evidence_export.policy.v1:event-summary-redacted-v1:no-raw-media:no-source-device-identities:no-zone-track-identifiers:hashed-failure-domains:exact-current-event:recipient-purpose-expiry:root-last:strong-approval";

#[derive(Clone, Debug, Eq, PartialEq)]
struct EvidenceSummary {
    digest: ContentDigest,
    class: EvidenceClass,
    relation: EvidenceEdgeRelation,
    supports: bool,
    failure_domain_digest: ContentDigest,
}

/// Owner request to export one exact event revision to a named recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventExportRequest {
    /// Event to export.
    pub event_id: EventId,
    /// Revision the owner reviewed; any other current revision is stale.
    pub expected_revision: ContentDigest,
    /// Recipient label (bounded, no control characters).
    pub recipient: String,
    /// Stated purpose (bounded, no control characters).
    pub purpose: String,
    /// Export expiry bound into the record.
    pub expires_at: TimestampNs,
}
impl EventExportRequest {
    /// Refuses a malformed or unbounded request before any read.
    pub fn validate(&self) -> Result<(), ExportError> {
        if self.expected_revision.algorithm() != DigestAlgorithm::Sha256
            || self.expected_revision.bytes() == [0; 32]
            || self.recipient.trim().is_empty()
            || self.recipient.len() > MAX_RECIPIENT_BYTES
            || self.recipient.chars().any(char::is_control)
            || self.purpose.trim().is_empty()
            || self.purpose.len() > MAX_PURPOSE_BYTES
            || self.purpose.chars().any(char::is_control)
        {
            return Err(ExportError::InvalidRequest(
                "invalid revision, recipient, or purpose",
            ));
        }
        Ok(())
    }
}

/// The single redacted metadata record an export root contains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventExportRecord {
    request: EventExportRequest,
    principal: String,
    site: String,
    event_root: ContentDigest,
    event_anchor: LedgerAnchor,
    event_revision: u64,
    event_state: EventState,
    event_kind: EventKind,
    event_interval: CaptureInterval,
    uncertainty_reason: Option<String>,
    probability_bits: [u64; 2],
    evidence: Vec<EvidenceSummary>,
    model_receipts: Vec<ContentDigest>,
    policy_generation: ContentDigest,
    decision_fingerprint: ContentDigest,
    decision_abstained: bool,
    zone_count: u64,
    track_count: u64,
}
impl EventExportRecord {
    /// The approved request.
    pub fn request(&self) -> &EventExportRequest {
        &self.request
    }
    /// The approving principal.
    pub fn principal(&self) -> &str {
        &self.principal
    }
    /// The deployment site lineage.
    pub fn site(&self) -> &str {
        &self.site
    }
    /// Digest of the exported event revision.
    pub fn event_root(&self) -> ContentDigest {
        self.event_root
    }
    /// Ledger anchor the event was read at.
    pub fn event_anchor(&self) -> &LedgerAnchor {
        &self.event_anchor
    }
    /// Number of redacted evidence summaries.
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }
    /// Canonical record bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSEXP01");
        e.u32(1);
        e.text(EXPORT_DOMAIN);
        e.text(self.request.event_id.as_str());
        e.digest(self.request.expected_revision);
        e.text(&self.request.recipient);
        e.text(&self.request.purpose);
        e.i128(self.request.expires_at.0);
        e.text(&self.principal);
        e.text(&self.site);
        e.digest(self.event_root);
        self.event_anchor.encode_canonical(&mut e);
        e.u64(self.event_revision);
        e.u8(self.event_state.to_u8());
        e.u8(self.event_kind.to_u8());
        self.event_interval.encode_canonical(&mut e);
        e.bool(self.uncertainty_reason.is_some());
        if let Some(v) = &self.uncertainty_reason {
            e.text(v);
        }
        e.u64(self.probability_bits[0]);
        e.u64(self.probability_bits[1]);
        e.u64(self.evidence.len() as u64);
        for item in &self.evidence {
            e.digest(item.digest);
            e.u8(fss_core::evidence_class_to_u8(item.class));
            e.u8(item.relation.to_u8());
            e.bool(item.supports);
            e.digest(item.failure_domain_digest);
        }
        e.u64(self.model_receipts.len() as u64);
        for d in &self.model_receipts {
            e.digest(*d);
        }
        e.digest(self.policy_generation);
        e.digest(self.decision_fingerprint);
        e.bool(self.decision_abstained);
        e.u64(self.zone_count);
        e.u64(self.track_count);
        e.text(EXPORT_PROFILE);
        e.finish()
    }
    /// Record digest (the export's identity).
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }
    /// Root-last manifest whose only child is the record.
    pub fn manifest(&self) -> Result<ObjectManifest, ExportError> {
        Ok(ObjectManifest::new(EXPORT_PROFILE, [self.digest()], None)?)
    }
    /// Publication slot derived from the record digest.
    pub fn slot(&self) -> Result<SlotName, ExportError> {
        SlotName::parse(&format!("export-{}", hex(self.digest())))
            .map_err(|_| ExportError::InvalidRequest("export slot identity"))
    }
    fn object_id(&self) -> Result<ObjectId, ExportError> {
        Ok(ObjectId::parse(format!(
            "{EXPORT_OBJECT_PREFIX}{}",
            hex(self.digest())
        ))?)
    }
    fn batch_id(&self) -> Result<BatchId, ExportError> {
        Ok(BatchId::parse(format!(
            "batch:evidence-export:{}",
            hex(self.digest())
        ))?)
    }
    fn delta(&self) -> Result<EvidenceDelta, ExportError> {
        Ok(EvidenceDelta {
            delta_id: format!("delta:evidence-export:{}", hex(self.digest())),
            family: FAMILY_EVIDENCE_EXPORT.to_owned(),
            object_id: self.object_id()?,
            prior_generation: None,
            new_generation: 1,
            validity: self.event_interval,
            plane: Plane::Authority,
            payload_digest: self.manifest()?.root(),
            witness_digest: Some(self.digest()),
            operation_id: None,
        })
    }
    fn children(&self) -> Result<Vec<ContentDigest>, ExportError> {
        let mut v = vec![self.digest(), self.manifest()?.root()];
        v.sort_unstable();
        v.dedup();
        Ok(v)
    }
    /// Strictly decode and verify a retained canonical export record.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, ExportError> {
        if bytes.len() > MAX_EXPORT_RECORD_BYTES || ContentDigest::sha256(bytes) != expected {
            return Err(ExportError::CustodyMismatch);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSEXP01" || d.u32()? != 1 || d.text()? != EXPORT_DOMAIN {
            return Err(ExportError::CustodyMismatch);
        }
        let request = EventExportRequest {
            event_id: EventId::parse(d.text()?)?,
            expected_revision: d.digest()?,
            recipient: d.text()?.to_owned(),
            purpose: d.text()?.to_owned(),
            expires_at: TimestampNs(d.i128()?),
        };
        let principal = d.text()?.to_owned();
        let site = d.text()?.to_owned();
        let event_root = d.digest()?;
        let event_anchor = LedgerAnchor::decode_canonical(&mut d)?;
        let event_revision = d.u64()?;
        let event_state = EventState::from_u8(d.u8()?)?;
        let event_kind = EventKind::from_u8(d.u8()?)?;
        let event_interval = CaptureInterval::decode_canonical(&mut d)?;
        let uncertainty_reason = if d.bool()? {
            Some(d.text()?.to_owned())
        } else {
            None
        };
        let probability_bits = [d.u64()?, d.u64()?];
        let evidence_len = usize::try_from(d.u64()?).map_err(|_| ExportError::Limit)?;
        if evidence_len > fss_core::MAX_EVIDENCE_COUNT {
            return Err(ExportError::Limit);
        }
        let mut evidence = Vec::with_capacity(evidence_len);
        for _ in 0..evidence_len {
            evidence.push(EvidenceSummary {
                digest: d.digest()?,
                class: fss_core::evidence_class_from_u8(d.u8()?)?,
                relation: EvidenceEdgeRelation::from_u8(d.u8()?)?,
                supports: d.bool()?,
                failure_domain_digest: d.digest()?,
            });
        }
        let model_len = usize::try_from(d.u64()?).map_err(|_| ExportError::Limit)?;
        if model_len > fss_core::MAX_MODEL_RECEIPTS_COUNT {
            return Err(ExportError::Limit);
        }
        let mut model_receipts = Vec::with_capacity(model_len);
        for _ in 0..model_len {
            model_receipts.push(d.digest()?);
        }
        let policy_generation = d.digest()?;
        let decision_fingerprint = d.digest()?;
        let decision_abstained = d.bool()?;
        let zone_count = d.u64()?;
        let track_count = d.u64()?;
        if d.text()? != EXPORT_PROFILE {
            return Err(ExportError::CustodyMismatch);
        }
        d.ensure_finished()?;
        let record = Self {
            request,
            principal,
            site,
            event_root,
            event_anchor,
            event_revision,
            event_state,
            event_kind,
            event_interval,
            uncertainty_reason,
            probability_bits,
            evidence,
            model_receipts,
            policy_generation,
            decision_fingerprint,
            decision_abstained,
            zone_count,
            track_count,
        };
        record.validate()?;
        if record.to_bytes() != bytes {
            return Err(ExportError::CustodyMismatch);
        }
        Ok(record)
    }
    fn validate(&self) -> Result<(), ExportError> {
        self.request.validate()?;
        PrincipalId::parse(&self.principal)?;
        crate::reference_deployment::validate_site_lineage(&self.site)?;
        let lower = f64::from_bits(self.probability_bits[0]);
        let upper = f64::from_bits(self.probability_bits[1]);
        if self.principal.len() > 256
            || self.site.len() > 256
            || self.event_revision == 0
            || self.event_root.algorithm() != DigestAlgorithm::Sha256
            || self.event_root.bytes() == [0; 32]
            || self.zone_count > fss_core::MAX_ZONES_COUNT as u64
            || self.track_count > fss_core::MAX_TRACKS_COUNT as u64
            || self.request.expires_at <= self.event_interval.latest
            || !lower.is_finite()
            || !upper.is_finite()
            || !(0.0..=1.0).contains(&lower)
            || !(0.0..=1.0).contains(&upper)
            || lower > upper
            || self.evidence.iter().any(|item| {
                item.digest.algorithm() != DigestAlgorithm::Sha256
                    || item.digest.bytes() == [0; 32]
                    || item.failure_domain_digest.algorithm() != DigestAlgorithm::Sha256
                    || item.failure_domain_digest.bytes() == [0; 32]
                    || item.supports != item.relation.required_supports_flag()
            })
        {
            return Err(ExportError::CustodyMismatch);
        }
        Ok(())
    }
    /// Redacted JSON projection for the recipient.
    pub fn to_redacted_json(&self) -> String {
        let lower = f64::from_bits(self.probability_bits[0]);
        let upper = f64::from_bits(self.probability_bits[1]);
        let evidence = self.evidence.iter().map(|item| format!(
            "{{\"digest\":{},\"class\":{},\"relation\":{},\"supports\":{},\"failure_domain_digest\":{}}}",
            json(&item.digest.to_text()), json(fss_core::evidence_class_as_str(item.class)),
            json(item.relation.as_str()), item.supports, json(&item.failure_domain_digest.to_text())
        )).collect::<Vec<_>>().join(",");
        let models = self
            .model_receipts
            .iter()
            .map(|d| json(&d.to_text()))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"schema\":{},\"profile\":{},\"export_digest\":{},\"recipient\":{},\"purpose\":{},\"expires_at_ns\":{},\"site\":{},\"event_id\":{},\"event_revision\":{},\"event_revision_digest\":{},\"event_root\":{},\"event_anchor_sequence\":{},\"state\":{},\"kind\":{},\"capture_earliest_ns\":{},\"capture_latest_ns\":{},\"uncertainty_reason\":{},\"probability\":[{},{}],\"zone_count\":{},\"track_count\":{},\"evidence\":[{}],\"model_receipts\":[{}],\"policy_generation\":{},\"decision_fingerprint\":{},\"decision_abstained\":{},\"raw_media_included\":false,\"source_device_identities_included\":false,\"zone_track_identifiers_included\":false,\"live_archive_namespace_exposed\":false}}",
            json(EXPORT_DOMAIN),
            json(EXPORT_PROFILE),
            json(&self.digest().to_text()),
            json(&self.request.recipient),
            json(&self.request.purpose),
            self.request.expires_at.0,
            json(&self.site),
            json(self.request.event_id.as_str()),
            self.event_revision,
            json(&self.request.expected_revision.to_text()),
            json(&self.event_root.to_text()),
            self.event_anchor.commit_sequence,
            json(self.event_state.as_str()),
            json(self.event_kind.as_str()),
            self.event_interval.earliest.0,
            self.event_interval.latest.0,
            self.uncertainty_reason
                .as_ref()
                .map_or_else(|| "null".to_owned(), |v| json(v)),
            lower,
            upper,
            self.zone_count,
            self.track_count,
            evidence,
            models,
            json(&self.policy_generation.to_text()),
            json(&self.decision_fingerprint.to_text()),
            self.decision_abstained
        )
    }
}

/// A read-only export preview and the approval it requires.
#[derive(Clone, Debug)]
pub struct EventExportPreview {
    record: EventExportRecord,
    root: ContentDigest,
    already_committed: bool,
}
impl EventExportPreview {
    /// The record that would be published.
    pub fn record(&self) -> &EventExportRecord {
        &self.record
    }
    /// The manifest root that would be published.
    pub fn root(&self) -> ContentDigest {
        self.root
    }
    /// True when this exact export is already retained.
    pub fn already_committed(&self) -> bool {
        self.already_committed
    }
    /// Exact approval digest over policy, record and root.
    pub fn approval(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(EXPORT_APPROVAL_DOMAIN);
        e.digest(ContentDigest::sha256(POLICY));
        e.digest(self.record.digest());
        e.digest(self.root);
        ContentDigest::sha256(&e.finish())
    }
}

/// Outcome of a committed export.
#[derive(Clone, Debug)]
pub struct EventExportReceipt {
    /// The approved preview.
    pub preview: EventExportPreview,
    /// Authority anchor after the commit.
    pub anchor: LedgerAnchor,
    /// False when an identical export was already retained.
    pub published: bool,
}

/// Why no export was previewed or committed.
#[derive(Debug)]
pub enum ExportError {
    /// Malformed or out-of-bounds request.
    InvalidRequest(&'static str),
    /// The principal lacks the export capability.
    Unauthorized,
    /// The event's current revision differs from the reviewed one.
    StaleRevision,
    /// The approval does not name the current exact preview.
    StaleApproval,
    /// Retained custody differs from the record being exported.
    CustodyMismatch,
    /// A declared bound was exhausted.
    Limit,
    /// Cooperative cancellation.
    Cancelled,
    /// Canonical contract refusal.
    Contract(ContractError),
    /// Deployment refusal.
    Reference(Box<ReferenceError>),
    /// Object manifest refusal.
    Object(ObjectError),
    /// Spool refusal.
    Spool(SpoolError),
}
impl ExportError {
    /// Registered stable error identity.
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "ERR-EXPORT-REQUEST-001",
            Self::Unauthorized => "ERR-AUTH-DENIED-001",
            Self::StaleRevision => "ERR-EXPORT-REVISION-STALE-001",
            Self::StaleApproval => "ERR-EXPORT-APPROVAL-STALE-001",
            Self::CustodyMismatch => "ERR-EXPORT-CUSTODY-001",
            Self::Limit => "ERR-EXPORT-BOUND-001",
            Self::Cancelled => "ERR-EXPORT-CANCELLED-001",
            _ => "ERR-EXPORT-STORAGE-001",
        }
    }
}
impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(v) => write!(f, "invalid evidence export: {v}"),
            Self::Unauthorized => f.write_str("evidence export authority denied"),
            Self::StaleRevision => {
                f.write_str("event revision changed; preview the current revision")
            }
            Self::StaleApproval => f.write_str("export approval does not match this exact package"),
            Self::CustodyMismatch => f.write_str("export or event custody mismatch"),
            Self::Limit => f.write_str("evidence export bound exceeded"),
            Self::Cancelled => f.write_str("evidence export cancelled before commit"),
            Self::Contract(e) => write!(f, "export contract: {e}"),
            Self::Reference(e) => write!(f, "export authority: {e}"),
            Self::Object(e) => write!(f, "export manifest: {e}"),
            Self::Spool(e) => write!(f, "export custody: {e}"),
        }
    }
}
impl std::error::Error for ExportError {}
impl From<ContractError> for ExportError {
    fn from(v: ContractError) -> Self {
        Self::Contract(v)
    }
}
impl From<fss_core::EventDecodeError> for ExportError {
    fn from(v: fss_core::EventDecodeError) -> Self {
        match v {
            fss_core::EventDecodeError::Contract(c) => Self::Contract(c),
            _ => Self::CustodyMismatch,
        }
    }
}
impl From<ReferenceError> for ExportError {
    fn from(v: ReferenceError) -> Self {
        Self::Reference(Box::new(v))
    }
}
impl From<ObjectError> for ExportError {
    fn from(v: ObjectError) -> Self {
        Self::Object(v)
    }
}
impl From<SpoolError> for ExportError {
    fn from(v: SpoolError) -> Self {
        Self::Spool(v)
    }
}

fn hex(d: ContentDigest) -> String {
    d.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn json(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn probability_bits(v: f64) -> u64 {
    if v == 0.0 {
        0.0f64.to_bits()
    } else {
        v.to_bits()
    }
}
fn failure_domain_digest(v: &str) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.evidence_export.failure_domain.v1");
    e.text(v);
    ContentDigest::sha256(&e.finish())
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), ExportError> {
    cx.checkpoint(stage).map_err(|_| ExportError::Cancelled)
}
fn authorize(
    d: &ReferenceDeployment,
    a: &ContextAuthority,
    cx: &ReplayCx,
    cap: &str,
) -> Result<(), ExportError> {
    a.validate()?;
    checkpoint(cx, "evidence_export:authority")?;
    if !a.has_capability(cap)
        || a.cancellation_reason.is_some()
        || cx.root_dir() != d.root()
        || a.anchor_universe != ContentDigest::sha256(d.site_lineage().as_bytes())
        || a.principal.len() > 256
        || d.site_lineage().len() > 256
    {
        return Err(ExportError::Unauthorized);
    }
    Ok(())
}
fn verify_custody(d: &ReferenceDeployment, record: &EventExportRecord) -> Result<(), ExportError> {
    let slot = record.slot()?;
    let manifest = record.manifest()?;
    let visible = d
        .publisher()
        .root(&slot)
        .ok_or(ExportError::CustodyMismatch)?;
    if visible.root != manifest.root() {
        return Err(ExportError::CustodyMismatch);
    }
    if d.publisher().spool().read(record.digest())? != record.to_bytes() {
        return Err(ExportError::CustodyMismatch);
    }
    Ok(())
}

/// Read-only preview of an export of the current exact event revision.
pub fn preview_export(
    deployment: &ReferenceDeployment,
    request: &EventExportRequest,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<EventExportPreview, ExportError> {
    authorize(deployment, authority, cx, CAP_EXPORT_PREPARE)?;
    request.validate()?;
    let (event, receipt) = deployment.current_event_authority(&request.event_id)?;
    if event.revision_digest() != request.expected_revision {
        return Err(ExportError::StaleRevision);
    }
    if request.expires_at <= event.interval.latest {
        return Err(ExportError::InvalidRequest(
            "expiry must be later than the event interval",
        ));
    }
    let evidence = event
        .evidence
        .iter()
        .map(|item| EvidenceSummary {
            digest: item.digest,
            class: item.class,
            relation: item.relation,
            supports: item.supports,
            failure_domain_digest: failure_domain_digest(&item.failure_domain),
        })
        .collect();
    let record = EventExportRecord {
        request: request.clone(),
        principal: authority.principal.clone(),
        site: deployment.site_lineage().to_owned(),
        event_root: receipt.event_root,
        event_anchor: receipt.authority_anchor,
        event_revision: event.revision,
        event_state: event.state,
        event_kind: event.kind,
        event_interval: event.interval,
        uncertainty_reason: event.uncertainty_reason.clone(),
        probability_bits: [
            probability_bits(event.probability.lower),
            probability_bits(event.probability.upper),
        ],
        evidence,
        model_receipts: event.model_receipts.clone(),
        policy_generation: event.decision_path.policy_generation,
        decision_fingerprint: event.decision_path.fingerprint,
        decision_abstained: event.decision_path.abstained,
        zone_count: event.zone_ids.len() as u64,
        track_count: event.track_ids.len() as u64,
    };
    record.validate()?;
    if record.to_bytes().len() > MAX_EXPORT_RECORD_BYTES {
        return Err(ExportError::Limit);
    }
    let root = record.manifest()?.root();
    let already_committed = match deployment
        .ledger()
        .current()
        .objects
        .get(&record.object_id()?)
    {
        None => false,
        Some(current)
            if current.family == FAMILY_EVIDENCE_EXPORT
                && current.generation == 1
                && current.payload_digest == root =>
        {
            verify_custody(deployment, &record)?;
            true
        }
        Some(_) => return Err(ExportError::CustodyMismatch),
    };
    checkpoint(cx, "evidence_export:prepared")?;
    Ok(EventExportPreview {
        record,
        root,
        already_committed,
    })
}

/// Verified cold readback of one committed export authority root.
///
/// This verifies the reserved authority delta, redacted root manifest, canonical record bytes,
/// and derived identities. It never follows event/source custody or executes a model.
pub fn read_export(
    deployment: &ReferenceDeployment,
    export_root: ContentDigest,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<(EventExportRecord, LedgerAnchor), ExportError> {
    authorize(deployment, authority, cx, CAP_EXPORT_PREPARE)?;
    if export_root.algorithm() != DigestAlgorithm::Sha256 || export_root.bytes() == [0; 32] {
        return Err(ExportError::InvalidRequest(
            "nonzero SHA-256 export root required",
        ));
    }
    if deployment.ledger().batches().len() > MAX_EXPORT_LEDGER_BATCHES {
        return Err(ExportError::Limit);
    }
    let mut found = None;
    for batch in deployment.ledger().batches() {
        checkpoint(cx, "evidence_export:readback")?;
        for delta in &batch.deltas {
            if delta.family != FAMILY_EVIDENCE_EXPORT || delta.payload_digest != export_root {
                continue;
            }
            if found.is_some()
                || delta.new_generation != 1
                || delta.prior_generation.is_some()
                || delta.plane != Plane::Authority
                || !delta.object_id.as_str().starts_with(EXPORT_OBJECT_PREFIX)
            {
                return Err(ExportError::CustodyMismatch);
            }
            let witness = delta.witness_digest.ok_or(ExportError::CustodyMismatch)?;
            found = Some((delta.object_id.clone(), witness, batch.new_anchor.clone()));
        }
    }
    let (object_id, record_digest, anchor) = found.ok_or(ExportError::CustodyMismatch)?;
    let manifest_bytes = deployment.publisher().spool().read(export_root)?;
    let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)?;
    if manifest.root() != export_root
        || manifest.kind() != EXPORT_PROFILE
        || manifest.metadata_digest().is_some()
        || manifest.children() != [record_digest]
    {
        return Err(ExportError::CustodyMismatch);
    }
    let bytes = deployment.publisher().spool().read(record_digest)?;
    let record = EventExportRecord::from_bytes(&bytes, record_digest)?;
    if record.object_id()? != object_id || record.manifest()? != manifest {
        return Err(ExportError::CustodyMismatch);
    }
    verify_custody(deployment, &record)?;
    checkpoint(cx, "evidence_export:readback_complete")?;
    Ok((record, anchor))
}

/// Commits an exactly approved export root-last and retains its record.
pub fn commit_export(
    deployment: &mut ReferenceDeployment,
    request: &EventExportRequest,
    approval: ContentDigest,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<EventExportReceipt, ExportError> {
    authorize(deployment, authority, cx, CAP_EXPORT_COMMIT)?;
    let preview = preview_export(deployment, request, authority, cx)?;
    if preview.approval() != approval {
        return Err(ExportError::StaleApproval);
    }
    if preview.already_committed {
        return Ok(EventExportReceipt {
            anchor: deployment.current_anchor().clone(),
            preview,
            published: false,
        });
    }
    checkpoint(cx, "evidence_export:revalidated")?;
    let bytes = preview.record.to_bytes();
    let slot = preview.record.slot()?;
    let manifest = preview.record.manifest()?;
    if let Some(root) = deployment.publisher().root(&slot) {
        if root.root != manifest.root() {
            return Err(ExportError::CustodyMismatch);
        }
        verify_custody(deployment, &preview.record)?;
    } else {
        // Stage the record's own `EXPORT_PROFILE` manifest. `stage_and_publish` would name the
        // manifest after the slot, which is a different root than the approved one and is
        // refused by readback's profile check.
        let publisher = deployment.publisher_mut();
        let digest = publisher
            .stage_object(&bytes)
            .map_err(ReferenceError::from)?;
        // `stage_object` re-reads and rehashes before returning the digest.
        if digest != preview.record.digest() {
            return Err(ExportError::CustodyMismatch);
        }
        checkpoint(cx, "evidence_export:record_staged")?;
        let staged = publisher
            .stage_manifest(&slot, &manifest)
            .map_err(ReferenceError::from)?;
        if staged != manifest.root() {
            return Err(ExportError::CustodyMismatch);
        }
    }
    deployment.publish_and_commit(&slot, &manifest, preview.record.event_interval, cx)?;
    checkpoint(cx, "evidence_export:root_published")?;
    let anchor = deployment.append_evidence_export_batch(
        preview.record.batch_id()?,
        vec![preview.record.delta()?],
        preview.record.children()?,
        cx,
    )?;
    cx.checkpoint_post_commit("evidence_export:committed");
    Ok(EventExportReceipt {
        preview,
        anchor,
        published: true,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn request_and_failure_domain_projection_are_bounded() {
        let mut request = EventExportRequest {
            event_id: EventId::parse("event:export-test").expect("event"),
            expected_revision: ContentDigest::sha256(b"revision"),
            recipient: "recipient:case-7".into(),
            purpose: "Owner-authorized incident review".into(),
            expires_at: TimestampNs(100),
        };
        assert!(request.validate().is_ok());
        request.purpose = "x".repeat(MAX_PURPOSE_BYTES + 1);
        assert!(request.validate().is_err());
        assert_eq!(
            failure_domain_digest("sensor:a"),
            failure_domain_digest("sensor:a")
        );
        assert_ne!(
            failure_domain_digest("sensor:a"),
            failure_domain_digest("sensor:b")
        );
    }
}
