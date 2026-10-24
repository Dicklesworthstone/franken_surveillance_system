#![forbid(unsafe_code)]
//! Revalidate a historical discovery inventory under explicit current authority.
//!
//! The inventory preserves metadata-only exclusions and every native-opened source, including
//! generation exclusions. This verifies continued disclosure of a historical result; it does
//! not claim a complete current catalog, repeat a likelihood update, or grant effect authority.

use std::collections::BTreeMap;

use fss_core::{CanonicalEncoder, ContentDigest, EventId, LedgerAnchor};
use fss_reference::agent_orient::{DeploymentHistory, OrientLimits};
use fss_reference::ingest::package_event::{PackageEvent, PackageEventError};
use fss_reference::{ReferenceDeployment, ReplayCx};

use crate::agent_json::{object, string};

use super::{
    Discovery, RetainedDiscoveryReport, RetainedDiscoveryRequest, checkpoint, finish,
    history_scan_units, package_error,
};
use super::super::{Error, Result, RetainedSupervisorPlan};

/// An exact event revision disclosed by the original discovery report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedDiscoverySource {
    /// Current-event identity at original discovery.
    pub event_id: EventId,
    /// Exact original metadata revision root, never silently replaced on retry.
    pub event_root: ContentDigest,
    /// True requires the native source owner again, including for generation exclusions.
    /// False preserves only the original metadata-only verification claim.
    pub source_verified: bool,
}

impl RetainedDiscoveryRequest {
    /// Bind the unchanged finite discovery scope to an explicitly supplied authority root.
    /// This grants no session, source, privacy, generation-change, or effect authority.
    pub fn for_authority(&self, expected_authority_root: ContentDigest) -> Result<Self> {
        let mut spec = self.template().spec().clone();
        spec.expected_authority_root = expected_authority_root;
        Self::new(RetainedSupervisorPlan::new(spec)?, self.maximum_catalog_events())
    }
}

impl RetainedDiscoveryReport {
    /// Complete sorted revision inventory behind this report, including all exclusions.
    /// A native-verified source cannot be downgraded by another exclusion for the same event.
    pub fn source_inventory(&self) -> Result<Vec<RetainedDiscoverySource>> {
        let mut inventory = BTreeMap::<EventId, RetainedDiscoverySource>::new();
        let mut include = |event_id: &EventId, event_root: ContentDigest, native: bool| {
            if let Some(old) = inventory.get_mut(event_id) {
                if old.event_root != event_root {
                    return Err(Error::Selection("discovery inventory revision conflict"));
                }
                old.source_verified |= native;
            } else {
                inventory.insert(event_id.clone(), RetainedDiscoverySource {
                    event_id: event_id.clone(),
                    event_root,
                    source_verified: native,
                });
            }
            Ok(())
        };
        for pin in &self.selected_plan().spec().events {
            include(&pin.event_id, pin.expected_event_root, true)?;
        }
        for exclusion in &self.discovery.exclusions {
            include(
                &exclusion.event_id,
                exclusion.event_root,
                exclusion.source_verified,
            )?;
        }
        if inventory.len() != self.discovery.metadata_reads
            || inventory.len() > self.request.maximum_catalog_events()
        {
            return Err(Error::Selection("incomplete discovery source inventory"));
        }
        Ok(inventory.into_values().collect())
    }
}

/// Bounded current validation of an exact historical inventory, not a fresh supervisor result.
#[derive(Clone, Debug)]
pub struct RetainedDiscoveryValidation {
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

impl RetainedDiscoveryValidation {
    /// Current deployment authority bracketed around every source read.
    pub const fn basis(&self) -> &LedgerAnchor {
        &self.basis
    }

    /// Receipt binds current authority, original source roots, verification classes and read cost.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Stored-envelope reservations actually consumed during this validation.
    pub const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    /// Stored-object read attempts actually consumed during this validation.
    pub const fn read_attempts(&self) -> u64 {
        self.read_attempts
    }

    /// Complete bounded validation metadata, with no source payload or fresh event inference.
    pub fn to_json(&self) -> Result<String> {
        let mut fields = self.fields();
        fields.push(("receipt_digest", string(&self.digest.to_text())));
        let rendered = object(&fields);
        if rendered.len() > self.maximum_report_bytes {
            return Err(Error::Limit("complete source revalidation report bytes"));
        }
        Ok(rendered)
    }

    fn fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("schema", string("fss.retained_supervisor_source_validation.v1")),
            ("request_digest", string(&self.request_digest.to_text())),
            ("source_inventory_digest", string(&self.inventory_digest.to_text())),
            ("site_lineage", string(&self.basis.site_lineage)),
            ("current_authority_root", string(&self.basis.state_root.to_text())),
            ("ledger_root", string(&self.ledger_root.to_text())),
            ("effect_root", string(&self.effect_root.to_text())),
            ("metadata_sources", self.metadata_sources.to_string()),
            ("native_sources", self.native_sources.to_string()),
            ("metadata_history_scan_units", self.history_scan_units.to_string()),
            ("reserved_bytes", self.reserved_bytes.to_string()),
            ("read_attempts", self.read_attempts.to_string()),
            ("journal_observations", "2".to_owned()),
            ("open_recovery_and_filesystem_metadata_included", "false".to_owned()),
            ("complete_current_catalog", "false".to_owned()),
            ("effects_authorized", "false".to_owned()),
            ("supports_absence_claim", "false".to_owned()),
        ]
    }
}

fn inventory_digest(
    sources: &[RetainedDiscoverySource],
    maximum: usize,
) -> Result<ContentDigest> {
    if sources.len() > maximum {
        return Err(Error::Limit("historical discovery source inventory"));
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.retained_supervisor_source_inventory.v1");
    encoder.u64(sources.len() as u64);
    let mut previous: Option<&EventId> = None;
    for source in sources {
        if !source.event_id.as_str().starts_with("event:package:")
            || !super::super::sha(source.event_root)
            || previous.is_some_and(|old| old >= &source.event_id)
        {
            return Err(Error::Plan("sorted unique historical discovery source roots"));
        }
        encoder.text(source.event_id.as_str());
        encoder.digest(source.event_root);
        encoder.bool(source.source_verified);
        previous = Some(&source.event_id);
    }
    finish(encoder)
}

/// Verify every original source against the explicitly pinned current deployment.
/// The caller must bind this complete inventory to its original report; this function verifies
/// the supplied inventory without asserting that it includes new events or complete coverage.
pub fn revalidate_retained_discovery_sources(
    deployment: &mut ReferenceDeployment,
    request: &RetainedDiscoveryRequest,
    sources: &[RetainedDiscoverySource],
    cx: &ReplayCx,
) -> Result<RetainedDiscoveryValidation> {
    let inventory_digest = inventory_digest(sources, request.maximum_catalog_events())?;
    checkpoint(cx)?;
    let spec = request.template().spec();
    if deployment.site_lineage() != spec.site_lineage
        || deployment.current_anchor().state_root != spec.expected_authority_root
        || cx.root_dir() != deployment.root()
    {
        return Err(Error::Authority);
    }
    let limits = OrientLimits {
        max_journal_bytes: spec.limits.max_journal_bytes,
        ..OrientLimits::default()
    };
    let initial = DeploymentHistory::read(deployment.root(), &limits)
        .map_err(|_| Error::History)?;
    let roots = initial.roots_at(initial.head()).ok_or(Error::History)?;
    if roots.0 != *deployment.current_anchor()
        || initial.site_lineage() != spec.site_lineage
        || initial.replay_objects_root()
            != deployment.root().join(&deployment.layout_report().objects_relpath)
    {
        return Err(Error::Authority);
    }
    checkpoint(cx)?;
    let before = deployment.publisher_mut()
        .tighten_read_budget(spec.limits.max_read_bytes, spec.limits.max_read_attempts)
        .map_err(Error::ReadBudget)?;
    let mut work = Discovery::default();
    let per_source = history_scan_units(deployment, &mut work, cx)?;
    let total_work = per_source.checked_mul(sources.len())
        .filter(|units| *units <= super::MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS)
        .ok_or(Error::Limit("source revalidation metadata history work"))?;
    let mut native_sources = 0_usize;
    for source in sources {
        checkpoint(cx)?;
        let (metadata, receipt) = deployment
            .current_event_authority(&source.event_id)
            .map_err(|error| package_error(PackageEventError::from(error)))?;
        if receipt.event_root != source.event_root {
            return Err(Error::Selection("historical discovery source revision changed"));
        }
        if source.source_verified {
            let native = PackageEvent::open(deployment, &source.event_id, cx)
                .map_err(package_error)?;
            if native.root() != source.event_root || native.event() != &metadata {
                return Err(Error::Selection("historical native source revision changed"));
            }
            native_sources += 1;
        }
    }
    checkpoint(cx)?;
    let current = DeploymentHistory::read(deployment.root(), &limits)
        .map_err(|_| Error::History)?;
    if current.head() != initial.head()
        || current.roots_at(current.head()) != Some(roots.clone())
        || current.site_lineage() != initial.site_lineage()
        || current.replay_objects_root() != initial.replay_objects_root()
    {
        return Err(Error::Authority);
    }
    let after = deployment.publisher().spool().read_budget_usage();
    let mut result = RetainedDiscoveryValidation {
        request_digest: request.digest(),
        inventory_digest,
        basis: roots.0,
        ledger_root: roots.1,
        effect_root: roots.2,
        metadata_sources: sources.len(),
        native_sources,
        history_scan_units: total_work,
        reserved_bytes: after.used_bytes - before.used_bytes,
        read_attempts: after.used_read_attempts - before.used_read_attempts,
        maximum_report_bytes: spec.limits.max_report_bytes,
        digest: ContentDigest::sha256(b"unsealed retained source validation"),
    };
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.retained_supervisor_source_validation_receipt.v1");
    encoder.bytes(object(&result.fields()).as_bytes());
    result.digest = finish(encoder)?;
    result.to_json()?;
    checkpoint(cx)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_binds_native_verification_and_rejects_duplicates_or_reordering()
        -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let first = RetainedDiscoverySource {
            event_id: EventId::parse("event:package:first")?,
            event_root: ContentDigest::sha256(b"first revision"),
            source_verified: false,
        };
        let second = RetainedDiscoverySource {
            event_id: EventId::parse("event:package:second")?,
            event_root: ContentDigest::sha256(b"second revision"),
            source_verified: true,
        };
        let original = inventory_digest(&[first.clone(), second.clone()], 2)?;
        let mut native = first.clone();
        native.source_verified = true;
        assert_ne!(original, inventory_digest(&[native, second.clone()], 2)?);
        assert!(inventory_digest(&[second.clone(), first.clone()], 2).is_err());
        assert!(inventory_digest(&[first.clone(), first.clone()], 2).is_err());
        assert!(inventory_digest(&[first, second], 1).is_err());
        Ok(())
    }
}
