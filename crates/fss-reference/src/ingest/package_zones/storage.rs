#![forbid(unsafe_code)]
//! Approved, root-last cognition retention and exact selected cold reconstruction.

use super::*;
use fss_core::{BatchId, CanonicalEncoder, EvidenceDelta, ObjectId, Plane};
use fss_publication::SlotName;
use std::collections::BTreeSet;

const MAX_LEDGER_BATCHES: usize = 65_536;
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn slot(digest: ContentDigest) -> Result<SlotName> {
    SlotName::parse(&format!("pz-{}", hex(digest))).map_err(source)
}
fn batch_id(digest: ContentDigest) -> Result<BatchId> {
    BatchId::parse(format!("batch:package-zones:{}", hex(digest))).map_err(source)
}
fn object_id(digest: ContentDigest) -> Result<ObjectId> {
    ObjectId::parse(format!("object:package-zones:{}", hex(digest))).map_err(source)
}
pub(super) fn check_history_bound(deployment: &ReferenceDeployment) -> Result<()> {
    if deployment.ledger().batches().len() > MAX_LEDGER_BATCHES {
        return Err(PackageZoneError::Limit);
    }
    Ok(())
}
pub(super) fn check_scope(deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<()> {
    if deployment.root() != cx.root_dir() {
        return Err(PackageZoneError::AuthorityChanged);
    }
    deployment.ledger().verify_durable_head().map_err(source)?;
    Ok(())
}
pub(super) fn approval(
    principal: &str,
    report: ContentDigest,
    root: ContentDigest,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(PACKAGE_ZONE_APPROVAL_DOMAIN);
    e.text(principal);
    e.digest(report);
    e.digest(root);
    ContentDigest::sha256(&e.finish())
}
pub(super) fn manifest(
    analysis: &PackageAnalysisReport,
    digest: ContentDigest,
    config: &PackageZoneConfig,
    privacy: &MaskBinding,
) -> Result<ObjectManifest> {
    let record = analysis.retained().record();
    let mut children = BTreeSet::from([
        analysis.digest(),
        analysis.retained().root(),
        record.import_root,
        ContentDigest::sha256(&wire::config_bytes(config)),
    ]);
    children.extend(record.frames.iter().map(|frame| frame.capsule_digest));
    if let Some(policy) = privacy.policy_digest() {
        children.insert(policy);
    }
    ObjectManifest::new("package-zones-v1", children, Some(digest)).map_err(source)
}
fn read(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    maximum: usize,
) -> Result<Vec<u8>> {
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(digest, maximum)
        .map_err(source)?;
    if ContentDigest::sha256(&bytes) != digest {
        return Err(PackageZoneError::Mismatch);
    }
    Ok(bytes)
}
fn children(report: &PackageZoneReport) -> Vec<ContentDigest> {
    let mut result = report.manifest.children().to_vec();
    result.push(report.provenance_root());
    result.sort_unstable();
    result.dedup();
    result
}
fn delta(report: &PackageZoneReport) -> Result<EvidenceDelta> {
    let first = report
        .frames
        .first()
        .ok_or(PackageZoneError::Mismatch)?
        .capture;
    let interval = report
        .frames
        .iter()
        .fold(first, |old, frame| CaptureInterval {
            earliest: old.earliest.min(frame.capture.earliest),
            latest: old.latest.max(frame.capture.latest),
        });
    Ok(EvidenceDelta {
        delta_id: format!("delta:package-zones:{}", hex(report.digest)),
        family: PACKAGE_ZONE_FAMILY.into(),
        object_id: object_id(report.digest)?,
        prior_generation: None,
        new_generation: 1,
        validity: interval,
        plane: Plane::Cognition,
        payload_digest: report.digest,
        witness_digest: Some(report.provenance_root()),
        operation_id: None,
    })
}
pub(super) fn check_detection(
    deployment: &ReferenceDeployment,
    analysis: &PackageAnalysisReport,
) -> Result<()> {
    let record = analysis.retained().record();
    let object = ObjectId::parse(format!(
        "object:package-detection:{}",
        hex(record.report_digest)
    ))
    .map_err(source)?;
    let current = deployment
        .ledger()
        .current()
        .objects
        .get(&object)
        .ok_or(PackageZoneError::Unavailable)?;
    if current.family != super::super::package_event::PACKAGE_DETECTION_FAMILY
        || current.generation != 1
        || current.payload_digest != analysis.retained().record_digest()
    {
        return Err(PackageZoneError::Unavailable);
    }
    Ok(())
}
pub(super) fn existing(
    deployment: &ReferenceDeployment,
    report: &PackageZoneReport,
) -> Result<Option<LedgerAnchor>> {
    let target = batch_id(report.digest)?;
    let Some(batch) = deployment
        .ledger()
        .batches()
        .iter()
        .find(|batch| batch.batch_id == target)
    else {
        return Ok(None);
    };
    let current = deployment
        .ledger()
        .current()
        .objects
        .get(&object_id(report.digest)?)
        .ok_or(PackageZoneError::Unavailable)?;
    if current.family != PACKAGE_ZONE_FAMILY
        || current.generation != 1
        || current.payload_digest != report.digest
    {
        return Err(PackageZoneError::Unavailable);
    }
    if batch.deltas != [delta(report)?]
        || batch.children != children(report)
        || batch.batch_digest != batch.computed_digest()
        || !batch.is_canonically_ordered()
        || batch.new_anchor.site_lineage != report.site
        || deployment
            .publisher()
            .root(&slot(report.digest)?)
            .is_none_or(|root| root.root != report.provenance_root())
        || read(deployment, report.provenance_root(), 64 * 1024)?
            != report.manifest.canonical_bytes()
        || read(deployment, report.digest, MAX_PACKAGE_ZONE_REPORT_BYTES)? != report.bytes
        || read(
            deployment,
            report.analysis.digest(),
            super::super::package_event::MAX_PACKAGE_ANALYSIS_BYTES,
        )? != report.analysis.encoded()
        || read(
            deployment,
            ContentDigest::sha256(&wire::config_bytes(&report.config)),
            4096,
        )? != wire::config_bytes(&report.config)
    {
        return Err(PackageZoneError::Mismatch);
    }
    Ok(Some(batch.new_anchor.clone()))
}

impl PackageZoneReport {
    /// Rebuild from the exact selected retained recipe and compare every byte. This is a cold
    /// source-verified read, not metadata-only inspection, and never runs the neural model.
    pub fn open(
        deployment: &ReferenceDeployment,
        digest: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "package_zones:open")?;
        check_scope(deployment, cx)?;
        check_history_bound(deployment)?;
        let current = deployment
            .ledger()
            .current()
            .objects
            .get(&object_id(digest)?)
            .ok_or(PackageZoneError::Unavailable)?;
        if current.family != PACKAGE_ZONE_FAMILY
            || current.generation != 1
            || current.payload_digest != digest
        {
            return Err(PackageZoneError::Unavailable);
        }
        let bytes = read(deployment, digest, MAX_PACKAGE_ZONE_REPORT_BYTES)?;
        let recipe = wire::recipe(&bytes)?;
        if recipe.site != deployment.site_lineage() {
            return Err(PackageZoneError::AuthorityChanged);
        }
        let report = Self::analyze(
            deployment,
            recipe.detection,
            &recipe.label,
            recipe.tracking,
            recipe.config,
            cx,
        )?;
        if report.digest != digest
            || report.bytes != bytes
            || report.analysis.digest() != recipe.analysis
            || report.retention.is_none()
        {
            return Err(PackageZoneError::Mismatch);
        }
        Ok(report)
    }
    fn revalidate(&self, deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<()> {
        check_scope(deployment, cx)?;
        if self.root.as_path() != deployment.root()
            || self.site != deployment.site_lineage()
            || self.principal != cx.io_authority().principal()
        {
            return Err(PackageZoneError::AuthorityChanged);
        }
        let report = Self::analyze(
            deployment,
            self.analysis.retained().record().report_digest,
            self.analysis.label(),
            self.analysis.config(),
            self.config.clone(),
            cx,
        )?;
        if report.bytes != self.bytes
            || report.provenance_root() != self.provenance_root()
            || report.approval != self.approval
        {
            return Err(PackageZoneError::Mismatch);
        }
        Ok(())
    }
    /// Retain only this freshly revalidated proposal and the exact original principal's approval.
    /// Returns true for an already committed exact retry. Missing retained proof is never healed
    /// from transient in-memory bytes. A cancelled root prefix carries no cognition authority.
    pub fn retain(
        &mut self,
        deployment: &mut ReferenceDeployment,
        approved: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<bool> {
        checkpoint(cx, "package_zones:retain")?;
        if approved != self.approval {
            return Err(PackageZoneError::StaleApproval);
        }
        self.revalidate(deployment, cx)?;
        if let Some(anchor) = existing(deployment, self)? {
            self.retention = Some(anchor);
            return Ok(true);
        }
        let config = wire::config_bytes(&self.config);
        for bytes in [
            self.bytes.as_slice(),
            self.analysis.encoded(),
            config.as_slice(),
        ] {
            checkpoint(cx, "package_zones:stage")?;
            let digest = deployment.stage_payload(bytes).map_err(source)?;
            deployment
                .publisher_mut()
                .verify_object(digest)
                .map_err(source)?;
        }
        let target = slot(self.digest)?;
        let existing_root = deployment.publisher().root(&target).map(|root| root.root);
        if existing_root.is_some_and(|root| root != self.provenance_root()) {
            return Err(PackageZoneError::Mismatch);
        }
        for digest in self.manifest.children() {
            checkpoint(cx, "package_zones:closure")?;
            deployment
                .publisher_mut()
                .verify_object(*digest)
                .map_err(source)?;
        }
        if existing_root.is_none() {
            deployment
                .publisher_mut()
                .stage_manifest(&target, &self.manifest)
                .map_err(source)?;
        }
        let evidence = delta(self)?;
        deployment
            .publish_and_commit(&target, &self.manifest, evidence.validity, cx)
            .map_err(source)?;
        checkpoint(cx, STAGE_PACKAGE_ZONES_COMMIT)?;
        self.revalidate(deployment, cx)?;
        let anchor = deployment
            .append_batch(batch_id(self.digest)?, vec![evidence], children(self), cx)
            .map_err(source)?;
        self.retention = Some(anchor);
        cx.checkpoint_post_commit("package_zones:retained");
        Ok(false)
    }
}
