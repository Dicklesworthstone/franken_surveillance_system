#![forbid(unsafe_code)]
//! Source-retained ONVIF vendor event and analytics imports (a bounded FSS-046 subset).
//!
//! An owner supplies complete XML or authorizes native PullPoint acquisition, with exact
//! device/profile generation pins. Raw source, the deterministic vendor-cognition
//! projection, and its owner binding share one immutable root. Only custody enters
//! authority: camera timestamps, labels, false values and empty responses establish
//! neither physical truth nor coverage, absence, identity or effect permission.

mod record;
mod source;

pub use source::PullPointAcquisition;

use std::fmt;

use fss_core::{
    CanonicalEncode, CaptureInterval, ContentDigest, ContractError, DigestAlgorithm, LedgerAnchor,
    Plane, ProvenanceClass, SensorId,
};
use fss_object::ObjectManifest;
use fss_publication::{LocalPublicationState, SlotName};

use super::wire::{EventDocument, WireError, parse_event_document, parse_metadata_document};
use crate::deletion::DeletionIndex;
use crate::{ReferenceDeployment, ReplayCx};

/// Original event-only recipe compatibility domain; never reinterpreted as analytics.
pub const RECIPE_DOMAIN_V1: &str = "fss.onvif_vendor_event_import.v1";
/// Original event-only projection compatibility domain.
pub const PROJECTION_DOMAIN_V1: &str = "fss.onvif_vendor_event_projection.v1";
/// Frozen event-only interpretation, including opaque VideoAnalytics sections.
pub const PARSER_GENERATION_V1: &str = "gen:fss1:onvif-vendor-events-v1";
/// Current recipe compatibility domain, binding events and vendor analytics.
pub const RECIPE_DOMAIN: &str = "fss.onvif_vendor_event_import.v2";
/// Current retained vendor-cognition projection compatibility domain.
pub const PROJECTION_DOMAIN: &str = "fss.onvif_vendor_event_projection.v2";
/// Current immutable interpretation; old imports always retain their original generation.
pub const PARSER_GENERATION: &str = "gen:fss1:onvif-vendor-analytics-v2";
/// Native PullPoint custody domain; file-import v1 and v2 encodings remain unchanged.
pub const PULLPOINT_RECIPE_DOMAIN: &str = "fss.onvif_vendor_event_pullpoint.v1";

/// Exact interpretation selected before parsing and permanently bound into custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interpretation {
    /// Frozen event-only projection. VideoAnalytics remains explicitly opaque.
    EventsV1,
    /// Events plus bounded vendor frame, object, shape and class claims.
    AnalyticsV2,
}

impl Interpretation {
    /// Immutable parser generation recorded by this interpretation.
    pub const fn parser_generation(self) -> &'static str {
        match self {
            Self::EventsV1 => PARSER_GENERATION_V1,
            Self::AnalyticsV2 => PARSER_GENERATION,
        }
    }
    /// Canonical recipe domain for this interpretation.
    pub const fn recipe_domain(self) -> &'static str {
        match self {
            Self::EventsV1 => RECIPE_DOMAIN_V1,
            Self::AnalyticsV2 => RECIPE_DOMAIN,
        }
    }
    /// Canonical vendor-cognition projection domain for this interpretation.
    pub const fn projection_domain(self) -> &'static str {
        match self {
            Self::EventsV1 => PROJECTION_DOMAIN_V1,
            Self::AnalyticsV2 => PROJECTION_DOMAIN,
        }
    }
    /// Parse with the exact frozen rules. V1 never validates opaque analytics as V2.
    pub fn parse(self, source: &[u8]) -> Result<EventDocument, WireError> {
        match self {
            Self::EventsV1 => parse_event_document(source),
            Self::AnalyticsV2 => parse_metadata_document(source),
        }
    }
}
/// Complete source XML byte ceiling, shared with the ONVIF wire parser.
pub const MAX_SOURCE_BYTES: usize = super::wire::MAX_SOAP_BYTES;
/// Hard canonical recipe allocation ceiling.
pub const MAX_RECIPE_BYTES: usize = 4096;
/// Hard retained projection allocation ceiling.
pub const MAX_PROJECTION_BYTES: usize = 1024 * 1024;
/// Bound on the history searched for the exact custody publication.
pub const MAX_HISTORY_BATCHES: usize = 65_536;
/// Bound on ledger deltas examined while validating an import.
pub const MAX_HISTORY_DELTAS: usize = 1_048_576;
/// Last cancellable stage before immutable root publication.
pub const STAGE_METADATA_PUBLISH: &str = "onvif_metadata:publish";

/// Owner-supplied attribution, independent of anything asserted by the source XML.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceBinding {
    /// Stable enrolled sensor label; owner attribution does not authenticate the camera.
    pub sensor_id: SensorId,
    /// Exact owner-declared device/firmware/configuration generation.
    pub device_generation: ContentDigest,
    /// Exact owner-declared media/analytics profile configuration generation.
    pub profile_generation: ContentDigest,
    /// Original ONVIF profile token; a token alone is not a generation.
    pub profile_token: String,
    /// Explicit local receive interval. Vendor UtcTime is never substituted for it.
    pub receive_interval: CaptureInterval,
}

impl fmt::Debug for SourceBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceBinding")
            .field("sensor_id", &self.sensor_id)
            .field("device_generation", &self.device_generation)
            .field("profile_generation", &self.profile_generation)
            .field("profile_token", &"[redacted]")
            .field("receive_interval", &self.receive_interval)
            .finish()
    }
}

impl SourceBinding {
    /// Validate bounded labels, digest algorithms and explicit receive-time ordering.
    pub fn validate(&self) -> Result<(), MetadataError> {
        if self.sensor_id.as_str().len() > 256
            || !record::valid_label(&self.profile_token)
            || self.device_generation.algorithm() != DigestAlgorithm::Sha256
            || self.profile_generation.algorithm() != DigestAlgorithm::Sha256
            || self.receive_interval.earliest.0 < 0
            || self.receive_interval.latest < self.receive_interval.earliest
        {
            return Err(MetadataError::InvalidBinding);
        }
        CaptureInterval::new(self.receive_interval.earliest, self.receive_interval.latest)?;
        Ok(())
    }
}

/// A failure never grants coverage, source authentication or a successful partial import.
#[derive(Debug)]
pub enum MetadataError {
    /// Missing, malformed or overlong owner attribution.
    InvalidBinding,
    /// The context is invalid or belongs to a different deployment.
    Authority,
    /// A hard byte, projection or history work bound was exceeded.
    Limit,
    /// The source is outside the supported bounded ONVIF event subset.
    Wire(WireError),
    /// The immutable import/root cannot be found in current custody.
    Unavailable,
    /// A committed deletion denies this import or one of its required source objects, even
    /// before interrupted unlinking finishes. A new owner binding cannot restore deleted bytes.
    EvidenceDeleted {
        /// Requested immutable import identity.
        identity: ContentDigest,
        /// Verified deletion plan that denies custody.
        plan: ContentDigest,
    },
    /// Retained bytes, source pins, projection, root or ledger disagree.
    Custody,
    /// Explicit cancellation; an interrupted publication must be inspected before retry.
    Cancelled,
    /// A canonical contract rejected the input.
    Contract(ContractError),
    /// The owning deployment failed or reported an indeterminate publication.
    Deployment(Box<crate::ReferenceError>),
    /// The owning content-addressed spool refused a bounded read.
    Storage(fss_object::SpoolError),
}

impl MetadataError {
    /// Stable operator error identity; no source text, item values or paths are exposed.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidBinding | Self::Contract(_) => "ERR-ONVIF-METADATA-BINDING-001",
            Self::Authority => "ERR-ONVIF-METADATA-AUTHORITY-001",
            Self::Limit => "ERR-ONVIF-METADATA-LIMIT-001",
            Self::Wire(_) => "ERR-ONVIF-METADATA-WIRE-001",
            Self::Unavailable => "ERR-ONVIF-METADATA-UNAVAILABLE-001",
            Self::EvidenceDeleted { .. } => "ERR-EVIDENCE-DELETED-001",
            Self::Custody | Self::Storage(_) => "ERR-ONVIF-METADATA-CUSTODY-001",
            Self::Cancelled => "ERR-ONVIF-METADATA-CANCELLED-001",
            Self::Deployment(_) => "ERR-ONVIF-METADATA-PUBLICATION-001",
        }
    }
}
impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for MetadataError {}
impl From<ContractError> for MetadataError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<WireError> for MetadataError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}
impl From<crate::ReferenceError> for MetadataError {
    fn from(error: crate::ReferenceError) -> Self {
        Self::Deployment(Box::new(error))
    }
}
impl From<fss_object::SpoolError> for MetadataError {
    fn from(error: fss_object::SpoolError) -> Self {
        Self::Storage(error)
    }
}

/// A source-retained vendor-cognition document with verified custody.
#[derive(Clone)]
pub struct RetainedMetadata {
    identity: ContentDigest,
    root: ContentDigest,
    recipe: record::Recipe,
    document: EventDocument,
    anchor: LedgerAnchor,
}
impl fmt::Debug for RetainedMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedMetadata")
            .field("identity", &self.identity)
            .field("root", &self.root)
            .field("source_digest", &self.recipe.source)
            .field("notification_count", &self.document.notifications.len())
            .field(
                "analytics_frame_count",
                &self.document.analytics_frames.len(),
            )
            .field("interpretation", &self.recipe.interpretation)
            .finish()
    }
}

impl RetainedMetadata {
    /// Reopen solely from retained source and canonical custody; never read the original file,
    /// repair missing evidence, or silently substitute an expected publication root.
    pub fn open(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<Self, MetadataError> {
        admit(deployment, cx, "onvif_metadata:open")?;
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(|_| MetadataError::Custody)?;
        if identity.algorithm() != DigestAlgorithm::Sha256 {
            return Err(MetadataError::InvalidBinding);
        }
        let deletions = DeletionIndex::read(deployment).map_err(|_| MetadataError::Custody)?;
        check_deleted(&deletions, identity, [identity])?;
        let slot = slot(identity)?;
        if deployment.publisher().is_broken_slot(&slot) {
            return Err(MetadataError::Custody);
        }
        let visible = deployment
            .publisher()
            .root(&slot)
            .ok_or(MetadataError::Unavailable)?;
        if visible.state != LocalPublicationState::Durable
            || expected_root.is_some_and(|expected| expected != visible.root)
        {
            return Err(MetadataError::Custody);
        }
        check_deleted(&deletions, identity, [visible.root])?;
        deployment
            .publisher()
            .require_durable_record(&slot)
            .map_err(|_| MetadataError::Custody)?;
        let encoded = read(deployment, identity, MAX_RECIPE_BYTES, cx)?;
        let recipe = record::decode(&encoded)?;
        if recipe.site != deployment.site_lineage() {
            return Err(MetadataError::Custody);
        }
        let manifest = manifest(identity, &recipe)?;
        let root = manifest.root();
        check_deleted(
            &deletions,
            identity,
            std::iter::once(root).chain(manifest.children().iter().copied()),
        )?;
        if visible.root != root
            || read(deployment, root, MAX_RECIPE_BYTES, cx)? != manifest.canonical_bytes()
        {
            return Err(MetadataError::Custody);
        }
        let source = read(deployment, recipe.source, recipe.source_bytes, cx)?;
        if source.len() != recipe.source_bytes {
            return Err(MetadataError::Custody);
        }
        checkpoint(cx, "onvif_metadata:parse_retained")?;
        let document = if recipe.acquisition.is_some() {
            super::wire::parse_pull_messages_response(&source)?
        } else {
            recipe.interpretation.parse(&source)?
        };
        if let Some(acquisition) = &recipe.acquisition {
            let subscription = read(
                deployment,
                acquisition.subscription_source,
                acquisition.subscription_source_bytes,
                cx,
            )?;
            acquisition.validate_sources(&source, &subscription)?;
        }
        let projection = record::projection(&document, recipe.interpretation)?;
        if ContentDigest::sha256(&projection) != recipe.projection
            || read(deployment, recipe.projection, MAX_PROJECTION_BYTES, cx)? != projection
        {
            return Err(MetadataError::Custody);
        }
        let anchor = check_publication(deployment, &slot, &manifest, &recipe.binding, cx)?;
        deployment
            .publisher()
            .require_durable_record(&slot)
            .map_err(|_| MetadataError::Custody)?;
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(|_| MetadataError::Custody)?;
        checkpoint(cx, "onvif_metadata:verified")?;
        Ok(Self {
            identity,
            root,
            recipe,
            document,
            anchor,
        })
    }

    /// Immutable import identity; it binds site, owner pins, source and interpretation.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact durable root containing source, recipe and projection.
    pub const fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// Digest of the complete original XML, including unsupported fields.
    pub const fn source_digest(&self) -> ContentDigest {
        self.recipe.source
    }
    /// Exact original XML length.
    pub const fn source_bytes(&self) -> usize {
        self.recipe.source_bytes
    }
    /// Digest of the deterministic retained vendor-cognition projection.
    pub const fn projection_digest(&self) -> ContentDigest {
        self.recipe.projection
    }
    /// The retained interpretation, never the process's current default parser.
    pub const fn interpretation(&self) -> Interpretation {
        self.recipe.interpretation
    }
    /// Exact generation used to reconstruct this import, including legacy v1 imports.
    pub const fn parser_generation(&self) -> &'static str {
        self.recipe.interpretation.parser_generation()
    }
    /// Explicit operator attribution and receive interval.
    pub fn binding(&self) -> &SourceBinding {
        &self.recipe.binding
    }
    /// Acquisition mode retained in the immutable recipe.
    pub fn source_mode(&self) -> &'static str {
        if self.recipe.acquisition.is_some() {
            "onvif_pullpoint"
        } else {
            "owner_supplied_file"
        }
    }
    /// Native acquisition witness, absent for an owner-supplied file.
    pub fn pullpoint_acquisition(&self) -> Option<&PullPointAcquisition> {
        self.recipe.acquisition.as_ref()
    }
    /// Parsed claims, preserving original notification order and repeated occurrences.
    /// Values can contain private vendor data; callers must apply their disclosure policy.
    pub fn document(&self) -> &EventDocument {
        &self.document
    }
    /// Original custody-publication anchor, stable across retries and unrelated commits.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Vendor labels always belong to the cognition plane.
    pub const fn plane(&self) -> Plane {
        Plane::Cognition
    }
    /// Retention proves the bytes, not the truth or authenticated origin of their claims.
    pub const fn provenance(&self) -> ProvenanceClass {
        ProvenanceClass::VendorClaimed
    }
    /// Source-generation-scoped claim identity for conservative duplicate comparison.
    ///
    /// The receive interval is excluded so backfilled identical claims can compare equal.
    /// Opaque content prevents that inference: if any unsupported content was retained,
    /// the digest also includes the whole source digest and original occurrence index.
    /// This identity never deletes or coalesces the original ordered notifications.
    pub fn notification_digest(&self, index: usize) -> Result<ContentDigest, MetadataError> {
        let notification = self
            .document
            .notifications
            .get(index)
            .ok_or(MetadataError::InvalidBinding)?;
        record::notification_identity(
            &self.recipe,
            notification,
            index,
            match self.recipe.interpretation {
                Interpretation::EventsV1 => self.document.unsupported_sections != 0,
                Interpretation::AnalyticsV2 => self.document.has_unsupported_content(),
            },
        )
    }

    /// Source- and occurrence-bound analytics frame identity.
    ///
    /// Repeated vendor object IDs or timestamps never assert track/person continuity.
    /// Each retained frame remains addressable even when its typed claims are identical.
    pub fn analytics_frame_digest(&self, index: usize) -> Result<ContentDigest, MetadataError> {
        let frame = self
            .document
            .analytics_frames
            .get(index)
            .ok_or(MetadataError::InvalidBinding)?;
        record::analytics_frame_identity(&self.recipe, frame, index)
    }
}

/// Parse and retain one complete owner-attributed document with analytics v2 semantics.
///
/// Parsing and canonical encoding finish before staging. Exact retries revalidate existing
/// custody, resume the existing root-to-ledger commit if needed, and never repair corrupted
/// source as an undocumented side effect. This publishes no event hypothesis or effect.
pub fn retain(
    deployment: &mut ReferenceDeployment,
    binding: SourceBinding,
    source: &[u8],
    cx: &ReplayCx,
) -> Result<RetainedMetadata, MetadataError> {
    retain_with_interpretation(deployment, binding, source, Interpretation::AnalyticsV2, cx)
}

/// Retain with an explicit interpretation, including exact retry of pre-v2 imports.
///
/// Reinterpreting an existing source as v2 produces a separate immutable import; it
/// never replaces v1 evidence, changes a prior digest, or upgrades its claims.
pub fn retain_with_interpretation(
    deployment: &mut ReferenceDeployment,
    binding: SourceBinding,
    source: &[u8],
    interpretation: Interpretation,
    cx: &ReplayCx,
) -> Result<RetainedMetadata, MetadataError> {
    retain_inner(deployment, binding, source, interpretation, None, None, cx)
}

/// Retain a native PullPoint response and its exact subscription source.
///
/// This live lane preserves the event-only projection and never silently selects
/// the current analytics import default. Both complete SOAP bodies and the owner
/// acquisition witness are immutable children of the same custody root.
pub fn retain_pullpoint(
    deployment: &mut ReferenceDeployment,
    binding: SourceBinding,
    source: &[u8],
    acquisition: PullPointAcquisition,
    subscription_source: &[u8],
    cx: &ReplayCx,
) -> Result<RetainedMetadata, MetadataError> {
    acquisition.validate_sources(source, subscription_source)?;
    retain_inner(
        deployment,
        binding,
        source,
        Interpretation::EventsV1,
        Some(acquisition),
        Some(subscription_source),
        cx,
    )
}

fn retain_inner(
    deployment: &mut ReferenceDeployment,
    binding: SourceBinding,
    source: &[u8],
    interpretation: Interpretation,
    acquisition: Option<PullPointAcquisition>,
    subscription_source: Option<&[u8]>,
    cx: &ReplayCx,
) -> Result<RetainedMetadata, MetadataError> {
    admit(deployment, cx, "onvif_metadata:admit")?;
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| MetadataError::Custody)?;
    let history_deltas = history_work(deployment)?;
    // Reserve room for one publication before any staging, including its cold-reader budget.
    if deployment.ledger().batches().len() >= MAX_HISTORY_BATCHES
        || history_deltas >= MAX_HISTORY_DELTAS
    {
        return Err(MetadataError::Limit);
    }
    binding.validate()?;
    if !record::valid_label(deployment.site_lineage()) {
        return Err(MetadataError::InvalidBinding);
    }
    if source.is_empty() || source.len() > MAX_SOURCE_BYTES {
        return Err(MetadataError::Limit);
    }
    if acquisition.is_some() != subscription_source.is_some()
        || acquisition.is_some() && interpretation != Interpretation::EventsV1
    {
        return Err(MetadataError::InvalidBinding);
    }
    let document = if acquisition.is_some() {
        super::wire::parse_pull_messages_response(source)?
    } else {
        interpretation.parse(source)?
    };
    let projection = record::projection(&document, interpretation)?;
    let recipe = record::Recipe {
        interpretation,
        site: deployment.site_lineage().to_owned(),
        binding,
        source: ContentDigest::sha256(source),
        source_bytes: source.len(),
        projection: ContentDigest::sha256(&projection),
        acquisition,
    };
    let encoded = record::encode(&recipe)?;
    if record::decode(&encoded)? != recipe {
        return Err(MetadataError::Custody);
    }
    let identity = ContentDigest::sha256(&encoded);
    let slot = slot(identity)?;
    let manifest = manifest(identity, &recipe)?;
    let manifest_bytes = manifest.canonical_bytes();
    let deletions = DeletionIndex::read(deployment).map_err(|_| MetadataError::Custody)?;
    // Check before every stage/retry, including a fresh identity using a previously deleted
    // source, projection or native subscription response. The complete manifest closure is
    // denied from the durable deletion record, before any stage or retry can restore bytes.
    check_deleted(
        &deletions,
        identity,
        std::iter::once(manifest.root()).chain(manifest.children().iter().copied()),
    )?;
    if deployment.publisher().is_broken_slot(&slot) {
        return Err(MetadataError::Custody);
    }
    if let Some(existing) = deployment.publisher().root(&slot) {
        if existing.root != manifest.root() {
            return Err(MetadataError::Custody);
        }
        if existing.state == LocalPublicationState::Durable {
            deployment
                .publisher()
                .require_durable_record(&slot)
                .map_err(|_| MetadataError::Custody)?;
        }
        let mut retained_objects = vec![
            (identity, encoded.as_slice()),
            (recipe.source, source),
            (recipe.projection, projection.as_slice()),
            (manifest.root(), manifest_bytes.as_slice()),
        ];
        if let (Some(acquisition), Some(subscription)) = (&recipe.acquisition, subscription_source)
        {
            retained_objects.push((acquisition.subscription_source, subscription));
        }
        for (digest, bytes) in retained_objects {
            if read(deployment, digest, bytes.len(), cx)? != bytes {
                return Err(MetadataError::Custody);
            }
        }
        // An already ledgered root must satisfy the same exact custody contract
        // as a cold open. A durable root awaiting its first ledger link can resume.
        match check_publication(deployment, &slot, &manifest, &recipe.binding, cx) {
            Ok(_) | Err(MetadataError::Unavailable) => {}
            Err(error) => return Err(error),
        }
    } else {
        let object = format!("object:local-root:{}", slot.as_str());
        if deployment.ledger().batches().iter().any(|batch| {
            batch
                .deltas
                .iter()
                .any(|delta| delta.object_id.as_str() == object)
        }) {
            // A missing previously published root is evidence loss, not a fresh import.
            return Err(MetadataError::Custody);
        }
        checkpoint(cx, "onvif_metadata:stage")?;
        let mut objects = vec![encoded.as_slice(), source, projection.as_slice()];
        if let Some(subscription) = subscription_source {
            objects.push(subscription);
        }
        let staged = deployment.stage_and_publish(&slot, &objects, cx)?;
        if staged.manifest != manifest {
            return Err(MetadataError::Custody);
        }
    }
    checkpoint(cx, STAGE_METADATA_PUBLISH)?;
    let receipt =
        deployment.publish_and_commit(&slot, &manifest, recipe.binding.receive_interval, cx)?;
    // The publisher verified the canonical closure and durably linked its exact root.
    // Do not begin cancellable read work after a successful commit.
    let retained = RetainedMetadata {
        identity,
        root: receipt.root,
        recipe,
        document,
        anchor: receipt.anchor,
    };
    cx.checkpoint_post_commit("onvif_metadata:committed");
    Ok(retained)
}

fn admit(
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
    stage: &'static str,
) -> Result<(), MetadataError> {
    if cx.root_dir() != deployment.root() {
        return Err(MetadataError::Authority);
    }
    checkpoint(cx, stage)
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), MetadataError> {
    if !cx.io_authority().is_valid() {
        return Err(MetadataError::Authority);
    }
    cx.checkpoint(stage).map_err(|_| MetadataError::Cancelled)
}
fn check_deleted(
    deletions: &DeletionIndex,
    identity: ContentDigest,
    objects: impl IntoIterator<Item = ContentDigest>,
) -> Result<(), MetadataError> {
    let unit = format!("slot:onvif-metadata-{}", &identity.to_text()[7..]);
    let entry = deletions
        .import(identity)
        .or_else(|| {
            objects
                .into_iter()
                .find_map(|digest| deletions.object(digest))
        })
        .or_else(|| {
            // A closure can remove this publication as another import's derivative without
            // listing its identity as a scope member, even when history preserves some bytes.
            deletions.entries().iter().find(|entry| {
                entry
                    .plan
                    .units
                    .iter()
                    .any(|member| member.id == unit && member.class == "deletable_content")
            })
        });
    if let Some(entry) = entry {
        return Err(MetadataError::EvidenceDeleted {
            identity,
            plan: entry.plan_digest,
        });
    }
    Ok(())
}

fn slot(identity: ContentDigest) -> Result<SlotName, MetadataError> {
    SlotName::parse(&format!("onvif-metadata-{}", &identity.to_text()[7..]))
        .map_err(|_| MetadataError::InvalidBinding)
}
fn manifest(
    identity: ContentDigest,
    recipe: &record::Recipe,
) -> Result<ObjectManifest, MetadataError> {
    let mut children = vec![identity, recipe.source, recipe.projection];
    if let Some(acquisition) = &recipe.acquisition {
        children.push(acquisition.subscription_source);
    }
    children.sort_unstable();
    children.dedup();
    ObjectManifest::new(slot(identity)?.as_str(), children, None)
        .map_err(crate::ReferenceError::from)
        .map_err(Into::into)
}
fn read(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    maximum: usize,
    cx: &ReplayCx,
) -> Result<Vec<u8>, MetadataError> {
    checkpoint(cx, "onvif_metadata:read")?;
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(digest, maximum)?;
    if ContentDigest::sha256(&bytes) != digest {
        return Err(MetadataError::Custody);
    }
    Ok(bytes)
}
fn history_work(deployment: &ReferenceDeployment) -> Result<usize, MetadataError> {
    if deployment.ledger().batches().len() > MAX_HISTORY_BATCHES {
        return Err(MetadataError::Limit);
    }
    let mut work = 0_usize;
    for batch in deployment.ledger().batches() {
        work = work
            .checked_add(batch.deltas.len())
            .ok_or(MetadataError::Limit)?;
        if work > MAX_HISTORY_DELTAS {
            return Err(MetadataError::Limit);
        }
    }
    Ok(work)
}

fn check_publication(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    expected: &ObjectManifest,
    binding: &SourceBinding,
    cx: &ReplayCx,
) -> Result<LedgerAnchor, MetadataError> {
    if deployment.ledger().batches().len() > MAX_HISTORY_BATCHES {
        return Err(MetadataError::Limit);
    }
    let object = format!("object:local-root:{}", slot.as_str());
    let mut work = 0_usize;
    for batch in deployment.ledger().batches().iter().rev() {
        checkpoint(cx, "onvif_metadata:history")?;
        work = work
            .checked_add(batch.deltas.len())
            .ok_or(MetadataError::Limit)?;
        if work > MAX_HISTORY_DELTAS {
            return Err(MetadataError::Limit);
        }
        for delta in &batch.deltas {
            if delta.object_id.as_str() != object {
                continue;
            }
            let mut closure: Vec<_> = deployment
                .publisher()
                .root_closure(slot)
                .ok_or(MetadataError::Custody)?
                .into_iter()
                .filter(|digest| *digest != expected.root())
                .collect();
            closure.sort_unstable();
            if batch.batch_id.as_str() != format!("batch:local-root:{}", slot.as_str())
                || batch.deltas.len() != 1
                || delta.family != "local_root_reachability"
                || delta.delta_id != format!("delta:local-root:{}", slot.as_str())
                || delta.plane != Plane::Authority
                || delta.prior_generation.is_some()
                || delta.new_generation != 1
                || delta.payload_digest != expected.root()
                || delta.witness_digest.is_some()
                || delta.operation_id.is_some()
                || delta.validity != binding.receive_interval
                || batch.children != closure
            {
                return Err(MetadataError::Custody);
            }
            return Ok(batch.new_anchor.clone());
        }
    }
    Err(MetadataError::Unavailable)
}
