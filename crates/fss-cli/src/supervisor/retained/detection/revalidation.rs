#![forbid(unsafe_code)]
//! Current source validation of one exact historical direct-detector inventory.

use std::collections::BTreeMap;

use fss_core::{CanonicalEncoder, ContentDigest, LedgerAnchor};
use fss_reference::{ReferenceDeployment, ReplayCx};

use crate::agent_json::{object, string};

use super::super::MAX_RETAINED_DISCOVERY_CATALOG_EVENTS;
use super::{
    Discovery, Error, HealthGuard, Result, RetainedDetectionRequest, RetainedDetectionSource,
    catalog, checkpoint, compute_source_health, finish, history, read_metadata, revalidate_history,
    sha, verify_native,
};

/// Bounded validation of historical sources under fresh authority, with no new advice or payload.
#[derive(Clone, Debug)]
pub struct RetainedDetectionValidation {
    request_digest: ContentDigest,
    inventory_digest: ContentDigest,
    basis: LedgerAnchor,
    ledger_root: ContentDigest,
    effect_root: ContentDigest,
    metadata_sources: usize,
    native_sources: usize,
    history_scan_units: usize,
    reserved_bytes: u64,
    read_attempts: u64,
    maximum_report_bytes: usize,
    digest: ContentDigest,
}

impl RetainedDetectionValidation {
    /// Exact current authority bracketing native source validation.
    pub const fn basis(&self) -> &LedgerAnchor {
        &self.basis
    }
    /// Receipt binds exact inventory, current authority and measured read reservations.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Stored-envelope read-byte reservations consumed during validation.
    pub const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }
    /// Stored-object read attempts consumed during validation.
    pub const fn read_attempts(&self) -> u64 {
        self.read_attempts
    }

    fn fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "schema",
                string("fss.retained_detection_source_validation.v1"),
            ),
            ("request_digest", string(&self.request_digest.to_text())),
            (
                "source_inventory_digest",
                string(&self.inventory_digest.to_text()),
            ),
            ("site_lineage", string(&self.basis.site_lineage)),
            (
                "current_authority_root",
                string(&self.basis.state_root.to_text()),
            ),
            ("ledger_root", string(&self.ledger_root.to_text())),
            ("effect_root", string(&self.effect_root.to_text())),
            ("metadata_sources", self.metadata_sources.to_string()),
            ("native_sources", self.native_sources.to_string()),
            (
                "metadata_history_scan_units",
                self.history_scan_units.to_string(),
            ),
            ("reserved_bytes", self.reserved_bytes.to_string()),
            ("read_attempts", self.read_attempts.to_string()),
            ("journal_observations", "2".to_owned()),
            (
                "open_recovery_and_filesystem_metadata_included",
                "false".to_owned(),
            ),
            ("complete_current_catalog", "false".to_owned()),
            ("effects_authorized", "false".to_owned()),
            ("supports_absence_claim", "false".to_owned()),
        ]
    }

    /// Complete metadata-only validation projection; an oversized result refuses intact.
    pub fn to_json(&self) -> Result<String> {
        let mut fields = self.fields();
        fields.push(("receipt_digest", string(&self.digest.to_text())));
        let json = object(&fields);
        if json.len() > self.maximum_report_bytes {
            return Err(Error::Limit(
                "complete detector source-validation report bytes",
            ));
        }
        Ok(json)
    }
}

pub(super) fn inventory_digest(
    sources: &[RetainedDetectionSource],
    maximum: usize,
) -> Result<ContentDigest> {
    if sources.len() > maximum {
        return Err(Error::Limit("historical detector source inventory"));
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.retained_detection_source_inventory.v1");
    encoder.u64(sources.len() as u64);
    let mut previous = None;
    for source in sources {
        if !sha(source.report_digest)
            || !sha(source.record_digest)
            || !sha(source.detection_root)
            || previous.is_some_and(|old| old >= source.report_digest)
            || source
                .health_digest
                .is_some_and(|digest| !source.source_verified || !sha(digest))
        {
            return Err(Error::Plan(
                "sorted unique historical detector source roots",
            ));
        }
        encoder.digest(source.report_digest);
        encoder.digest(source.record_digest);
        encoder.digest(source.detection_root);
        encoder.bool(source.source_verified);
        match source.health_digest {
            Some(digest) => {
                encoder.bool(true);
                encoder.digest(digest);
            }
            None => encoder.bool(false),
        }
        previous = Some(source.report_digest);
    }
    finish(encoder)
}

/// Revalidate every disclosed native report at an explicitly selected current authority root.
///
/// The caller must bind this inventory to the original result. Native-verified generation
/// exclusions retain source checks. Metadata-only scope exclusions retain metadata checks only.
/// New reports are never added to the historical payload and no inference is performed.
pub fn revalidate_detection_sources(
    deployment: &mut ReferenceDeployment,
    request: &RetainedDetectionRequest,
    sources: &[RetainedDetectionSource],
    cx: &ReplayCx,
) -> Result<RetainedDetectionValidation> {
    let inventory_digest = inventory_digest(sources, request.maximum_catalog_reports())?;
    let (initial, roots) = history(deployment, request, cx)?;
    let limits = request.template().spec().limits;
    let before = deployment
        .publisher_mut()
        .tighten_read_budget(limits.max_read_bytes, limits.max_read_attempts)
        .map_err(Error::ReadBudget)?;
    let mut work = Discovery::default();
    let mut health = HealthGuard::read(deployment, &limits, cx)?;
    // The original report bound applies to its historical inventory. Newly published reports
    // do not consume that old slot allowance or get silently added; the global metadata bound
    // still limits this complete no-source-read catalog observation.
    let current: BTreeMap<_, _> = catalog(
        deployment,
        MAX_RETAINED_DISCOVERY_CATALOG_EVENTS,
        &mut work,
        cx,
    )?
    .into_iter()
    .map(|pin| (pin.source.report_digest, pin))
    .collect();
    let mut native_sources = 0_usize;
    for source in sources {
        checkpoint(cx)?;
        let pin = current.get(&source.report_digest).ok_or(Error::Selection(
            "historical native detector publication unavailable",
        ))?;
        if pin.source.record_digest != source.record_digest
            || pin.source.detection_root != source.detection_root
        {
            return Err(Error::Selection(
                "historical native detector publication changed",
            ));
        }
        let record = read_metadata(deployment, pin, cx)?;
        if source.source_verified {
            verify_native(deployment, source, &record, cx)?;
            let (_, current_health) =
                compute_source_health(deployment, request, &record, &mut health, cx)?;
            if current_health != source.health_digest {
                return Err(Error::Selection(
                    "historical native detector health context changed",
                ));
            }
            native_sources += 1;
        }
    }
    revalidate_history(deployment, request, &initial, &roots, cx)?;
    let after = deployment.publisher().spool().read_budget_usage();
    let mut validation = RetainedDetectionValidation {
        request_digest: request.digest(),
        inventory_digest,
        basis: roots.0,
        ledger_root: roots.1,
        effect_root: roots.2,
        metadata_sources: sources.len(),
        native_sources,
        history_scan_units: work.history_scan_units,
        reserved_bytes: after.used_bytes - before.used_bytes,
        read_attempts: after.used_read_attempts - before.used_read_attempts,
        maximum_report_bytes: limits.max_report_bytes,
        digest: ContentDigest::sha256(b"unsealed detector source validation"),
    };
    let unsigned = object(&validation.fields());
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.retained_detection_source_validation_receipt.v1");
    encoder.bytes(unsigned.as_bytes());
    validation.digest = finish(encoder)?;
    validation.to_json()?;
    checkpoint(cx)?;
    Ok(validation)
}
