#![forbid(unsafe_code)]
//! Exact committed report declarations and metadata-only native custody checks.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalDecoder, EvidenceDelta, EvidenceDeltaBatch, ObjectId, Plane};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::*;
use crate::agent_follow::snapshot_anchor_token;
use crate::ingest::package_event::{
    MAX_PACKAGE_ANALYSIS_BYTES, PACKAGE_DETECTION_RECORD_DOMAIN, PackageDetectionRecord,
};
use crate::ingest::package_zones::{
    MAX_PACKAGE_ZONE_REPORT_BYTES, PACKAGE_ZONE_REPORT_DOMAIN, PACKAGE_ZONE_SCREENED_REPORT_DOMAIN,
};
use crate::retained_source::{ImmutableRetainedSource, RetainedSource};

fn invalid<T>() -> Result<T, ReportCatalogError> {
    Err(ReportCatalogError::InvalidRecord)
}

fn selected_family(family: &str, object: &str) -> Option<ReportCatalogFamily> {
    let family = ReportCatalogFamily::parse(family).ok()?;
    if family == ReportCatalogFamily::ModelInvocationReceipt
        && !object.starts_with("object:model-run")
    {
        // executor_activity also retains model_invocation_receipt, under the distinct
        // executor-receipt/executor-result namespace and a different canonical schema.
        return None;
    }
    Some(family)
}

fn selected_declaration(
    batch: &EvidenceDeltaBatch,
    delta: &EvidenceDelta,
) -> Option<ReportCatalogFamily> {
    selected_family(&delta.family, delta.object_id.as_str()).or_else(|| {
        // A malformed would-be native declaration cannot evade verification by changing its
        // object prefix while retaining a native batch or delta identity.
        (delta.family == FAMILY_MODEL_INVOCATION_RECEIPT
            && (batch.batch_id.as_str().starts_with("batch:model-run")
                || delta.delta_id.starts_with("delta:model-run")))
        .then_some(ReportCatalogFamily::ModelInvocationReceipt)
    })
}

pub(super) fn query(
    root: &Path,
    request: &ReportCatalogRequest,
    limits: ReportCatalogLimits,
    cx: &ReplayCx,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentReportCatalogQuery, ReportCatalogError> {
    request.validate()?;
    limits.validate()?;
    if root != cx.root_dir() || request.principal.as_str() != cx.io_authority().principal() {
        return Err(ReportCatalogError::Unauthorized);
    }
    if cancelled() || cx.checkpoint("report_catalog:open").is_err() {
        return Err(ReportCatalogError::Cancelled);
    }
    let owner = ImmutableRetainedSource::open_cancellable(root, limits.read, cx, cancelled)
        .map_err(ReportCatalogError::Source)?;
    let anchor = snapshot_anchor_token(owner.snapshot());
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|pin| pin.as_str() != anchor)
    {
        return Err(ReportCatalogError::AnchorChanged);
    }
    let ledger = owner.ledger();
    if ledger.current().objects.len() > limits.max_objects
        || ledger.batches().len() > limits.max_objects
    {
        return Err(ReportCatalogError::OverBudget);
    }
    let expected_count = ledger
        .current()
        .objects
        .iter()
        .filter(|(id, value)| selected_family(&value.family, id.as_str()).is_some())
        .count();
    if expected_count > limits.max_reports {
        return Err(ReportCatalogError::OverBudget);
    }

    // Build the complete current index before reading payloads or applying user predicates.
    // Matching a family alone cannot smuggle an arbitrary object into the native report set.
    let mut current = BTreeMap::new();
    for batch in ledger.batches() {
        if cancelled() || cx.checkpoint("report_catalog:index").is_err() {
            return Err(ReportCatalogError::Cancelled);
        }
        for delta in &batch.deltas {
            let Some(family) = selected_declaration(batch, delta) else {
                continue;
            };
            let revision = ledger
                .current()
                .objects
                .get(&delta.object_id)
                .ok_or(ReportCatalogError::InvalidRecord)?;
            if revision.family != delta.family || revision.generation != delta.new_generation {
                continue;
            }
            if revision.payload_digest != delta.payload_digest
                || revision.validity != delta.validity
                || revision.plane != Plane::Cognition
                || delta.plane != Plane::Cognition
                || delta.prior_generation.is_some()
                || delta.new_generation != 1
                || delta.operation_id.is_some()
                || batch.deltas.len() != 1
                || batch.batch_digest != batch.computed_digest()
                || !batch.is_canonically_ordered()
                || batch.new_anchor.site_lineage != owner.site_lineage()
                || current
                    .insert(delta.object_id.clone(), (family, batch, delta))
                    .is_some()
            {
                return invalid();
            }
            if current.len() > limits.max_reports {
                return Err(ReportCatalogError::OverBudget);
            }
        }
    }
    if current.len() != expected_count {
        return invalid();
    }
    let mut rows = Vec::with_capacity(current.len());
    for (_, (family, batch, delta)) in current {
        if cancelled() || cx.checkpoint("report_catalog:metadata").is_err() {
            return Err(ReportCatalogError::Cancelled);
        }
        rows.push(match family {
            ReportCatalogFamily::PackageDetectionRecord => detection(&owner, batch, delta)?,
            ReportCatalogFamily::PackageZoneReport => zone(&owner, batch, delta)?,
            ReportCatalogFamily::ModelInvocationReceipt => model_run(&owner, batch, delta, cx)
                .map_err(|error| {
                    if cancelled() || cx.is_cancelled() {
                        ReportCatalogError::Cancelled
                    } else {
                        error
                    }
                })?,
        });
    }
    rows.sort_by_key(|row| (row.family, row.report_digest));
    if !rows.windows(2).all(|pair| {
        (pair[0].family, pair[0].report_digest) < (pair[1].family, pair[1].report_digest)
    }) {
        return invalid();
    }
    let mut result = result::compile(owner.snapshot().clone(), request, &limits, rows)?;
    if cancelled() || cx.checkpoint("report_catalog:complete").is_err() {
        return Err(ReportCatalogError::Cancelled);
    }
    owner.revalidate().map_err(ReportCatalogError::Source)?;
    // No callback, source operation or further metadata read follows final revalidation.
    result.read_usage = owner.usage();
    Ok(result)
}

fn manifest(
    source: &dyn RetainedSource,
    batch: &EvidenceDeltaBatch,
    delta: &EvidenceDelta,
) -> Result<ObjectManifest, ReportCatalogError> {
    let root = delta
        .witness_digest
        .ok_or(ReportCatalogError::InvalidRecord)?;
    let bytes = source
        .read_object_bounded(root, 1024 * 1024)
        .map_err(ReportCatalogError::Source)?;
    let manifest = ObjectManifest::from_canonical_bytes(&bytes)
        .map_err(|_| ReportCatalogError::InvalidRecord)?;
    let mut children = manifest.children().to_vec();
    children.push(root);
    children.sort_unstable();
    children.dedup();
    if manifest.root() != root
        || manifest.canonical_bytes() != bytes
        || manifest.metadata_digest() != Some(delta.payload_digest)
        || batch.children != children
    {
        return invalid();
    }
    Ok(manifest)
}

fn check_identity(
    batch: &EvidenceDeltaBatch,
    delta: &EvidenceDelta,
    native: &str,
    digest: ContentDigest,
) -> Result<(), ReportCatalogError> {
    let identity = hex(digest);
    let object = ObjectId::parse(format!("object:{native}:{identity}"))
        .map_err(|_| ReportCatalogError::InvalidRecord)?;
    if batch.batch_id.as_str() != format!("batch:{native}:{identity}")
        || delta.delta_id != format!("delta:{native}:{identity}")
        || delta.object_id != object
    {
        return invalid();
    }
    Ok(())
}

fn detection(
    source: &dyn RetainedSource,
    batch: &EvidenceDeltaBatch,
    delta: &EvidenceDelta,
) -> Result<ReportCatalogRow, ReportCatalogError> {
    let bytes = source
        .read_object_bounded(delta.payload_digest, MAX_PACKAGE_ANALYSIS_BYTES)
        .map_err(ReportCatalogError::Source)?;
    let record =
        PackageDetectionRecord::decode(&bytes).map_err(|_| ReportCatalogError::InvalidRecord)?;
    check_identity(batch, delta, "package-detection", record.report_digest)?;
    source
        .refuse_deleted_import(record.import_identity)
        .map_err(ReportCatalogError::Source)?;
    let publication_slot = format!("pd-{}", hex(record.report_digest));
    let slot = SlotName::parse(&publication_slot).map_err(|_| ReportCatalogError::InvalidRecord)?;
    let mut children = BTreeSet::from([record.report_digest, record.import_root]);
    children.extend(record.frames.iter().map(|frame| frame.capsule_digest));
    children.remove(&delta.payload_digest);
    let expected = ObjectManifest::new(&publication_slot, children, Some(delta.payload_digest))
        .map_err(|_| ReportCatalogError::InvalidRecord)?;
    let manifest = manifest(source, batch, delta)?;
    let first = record
        .frames
        .first()
        .ok_or(ReportCatalogError::InvalidRecord)?
        .capture;
    let validity = record
        .frames
        .iter()
        .fold(first, |interval, frame| CaptureInterval {
            earliest: interval.earliest.min(frame.capture.earliest),
            latest: interval.latest.max(frame.capture.latest),
        });
    if manifest != expected || validity != delta.validity {
        return invalid();
    }
    // This is the retained detector JSON, not image, video or original source bytes. The
    // returned report handle must resolve even though source reconstruction is not performed.
    source
        .read_object_bounded(record.report_digest, MAX_PACKAGE_ANALYSIS_BYTES)
        .map_err(ReportCatalogError::Source)?;
    source
        .check_publication(&slot, manifest.root(), manifest.children().len())
        .map_err(ReportCatalogError::Source)?;
    Ok(ReportCatalogRow {
        family: ReportCatalogFamily::PackageDetectionRecord,
        report_digest: record.report_digest,
        record_digest: delta.payload_digest,
        provenance_root: manifest.root(),
        publication_slot,
        schema: PACKAGE_DETECTION_RECORD_DOMAIN.to_owned(),
        validity,
        committed_sequence: batch.new_anchor.commit_sequence,
        model_run: None,
    })
}

fn zone(
    source: &dyn RetainedSource,
    batch: &EvidenceDeltaBatch,
    delta: &EvidenceDelta,
) -> Result<ReportCatalogRow, ReportCatalogError> {
    check_identity(batch, delta, "package-zones", delta.payload_digest)?;
    let manifest = manifest(source, batch, delta)?;
    let (magic, version, schema) = match manifest.kind() {
        "package-zones-v1" => (b"FSSPZNR1".as_slice(), 1, PACKAGE_ZONE_REPORT_DOMAIN),
        "package-zones-v2" => (
            b"FSSPZNR2".as_slice(),
            2,
            PACKAGE_ZONE_SCREENED_REPORT_DOMAIN,
        ),
        _ => return invalid(),
    };
    let bytes = source
        .read_object_bounded(delta.payload_digest, MAX_PACKAGE_ZONE_REPORT_BYTES)
        .map_err(ReportCatalogError::Source)?;
    let mut decoder = CanonicalDecoder::new(&bytes);
    // Verify the declared native format and site, without introducing a second zone-report
    // semantic decoder. Its native reader later reconstructs every report/source byte.
    if decoder
        .bytes()
        .map_err(|_| ReportCatalogError::InvalidRecord)?
        != magic
        || decoder
            .u32()
            .map_err(|_| ReportCatalogError::InvalidRecord)?
            != version
        || decoder
            .text()
            .map_err(|_| ReportCatalogError::InvalidRecord)?
            != schema
        || decoder
            .text()
            .map_err(|_| ReportCatalogError::InvalidRecord)?
            != source.site_lineage()
    {
        return invalid();
    }
    let publication_slot = format!("pz-{}", hex(delta.payload_digest));
    let slot = SlotName::parse(&publication_slot).map_err(|_| ReportCatalogError::InvalidRecord)?;
    source
        .check_publication(&slot, manifest.root(), manifest.children().len())
        .map_err(ReportCatalogError::Source)?;
    Ok(ReportCatalogRow {
        family: ReportCatalogFamily::PackageZoneReport,
        report_digest: delta.payload_digest,
        record_digest: delta.payload_digest,
        provenance_root: manifest.root(),
        publication_slot,
        schema: schema.to_owned(),
        validity: delta.validity,
        committed_sequence: batch.new_anchor.commit_sequence,
        model_run: None,
    })
}

fn model_run(
    source: &dyn RetainedSource,
    batch: &EvidenceDeltaBatch,
    delta: &EvidenceDelta,
    cx: &ReplayCx,
) -> Result<ReportCatalogRow, ReportCatalogError> {
    let metadata = RecordedInferenceMetadata::read(source, delta.payload_digest, cx)
        .map_err(|_| ReportCatalogError::InvalidRecord)?;
    if metadata.authority_anchor != batch.new_anchor {
        return invalid();
    }
    Ok(ReportCatalogRow {
        family: ReportCatalogFamily::ModelInvocationReceipt,
        // A semantic run key is not a retained proof blob. Both generic handles name the
        // actual receipt; the native lookup key is explicit inside the typed model_run block.
        report_digest: metadata.record_digest,
        record_digest: metadata.record_digest,
        provenance_root: metadata.publication_root,
        publication_slot: metadata.publication_slot.to_string(),
        schema: crate::ingest::inference::RECORDED_INFERENCE_DOMAIN.to_owned(),
        validity: metadata.validity,
        committed_sequence: metadata.authority_anchor.commit_sequence,
        model_run: Some(metadata),
    })
}
