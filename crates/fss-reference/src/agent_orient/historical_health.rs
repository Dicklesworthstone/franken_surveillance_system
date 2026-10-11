#![forbid(unsafe_code)]
//! Bounded, read-only projection of retained historical sensor-health diagnostics.
//!
//! A cell describes what one immutable heuristic receipt recorded. It does not describe a
//! sensor's present condition, establish tamper, or certify absence. Receipt identities never
//! collapse to a latest-per-sensor value: a later `no_findings` receipt leaves every earlier
//! finding visible. This reader verifies retained metadata against the selected committed
//! prefix; it never opens a mutable deployment, reads media or trace payloads, or runs native
//! perception. Current deletion authority still fences every metadata read.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BudgetVector, CompressionLossClass, CompressionTransform, CompressionTransformKind,
    ContentDigest, ContractError, EvidenceDeltaBatch, ExpansionHandle, KnowledgeCell,
    KnowledgeCellParams, KnowledgeState, ProvenanceClass,
};

use crate::deletion::DeletionIndex;
use crate::ingest::historical_health::{
    FAMILY_HISTORICAL_HEALTH, HistoricalHealthError, HistoricalHealthRecord, read_retained_at,
};
use crate::situation_sections::{SourceOmission, SourceOmissions};

use super::{AttentionItem, DeploymentReadError, cell, corrupt};

/// Stable per-receipt claim prefix. The suffix is the complete canonical receipt digest.
pub const CLAIM_HISTORICAL_HEALTH_PREFIX: &str = "claim:historical-sensor-health:";
/// Registered source-omission class for diagnostic finding runs and derivation details.
pub const SOURCE_CLASS_HISTORICAL_HEALTH_DETAIL: &str = "historical_sensor_health_detail";
/// Maximum diagnostic receipts in one orientation. Overflow refuses rather than truncates.
pub const MAX_HISTORICAL_HEALTH_RECORDS: usize = 128;
/// Maximum metadata-object reads for one receipt, independent of event and coverage reads.
pub const MAX_HISTORICAL_HEALTH_READS_PER_RECORD: usize = 16;
/// Maximum metadata bytes across all historical diagnostics in one orientation.
pub const MAX_HISTORICAL_HEALTH_METADATA_BYTES: usize = 16 * 1024 * 1024;

/// A committed deletion affecting one exact diagnostic dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalHealthDeletion {
    /// Exact object or import identity whose retained bytes are unavailable.
    pub unavailable_digest: ContentDigest,
    /// Retained plan proving the current deletion authority.
    pub deletion_plan: ContentDigest,
    /// Whether the deletion authority was committed by the selected historical prefix.
    /// Bytes remain fenced when false: custody is current even for an earlier snapshot.
    pub authority_in_prefix: bool,
}

/// Availability of historical diagnostic metadata, separate from the physical sensor state.
#[derive(Clone, Debug)]
pub enum HistoricalHealthMetadata {
    /// Exact receipt and its committed provenance metadata were read and verified.
    Retained {
        /// Immutable historical heuristic output; no native derivation was rerun.
        record: HistoricalHealthRecord,
        /// Committed canonical provenance root verified by the metadata reader.
        provenance_root: ContentDigest,
        /// Known current source/trace deletions. The retained output is still historical, but
        /// a deleted dependency cannot be offered as an available replay or expansion.
        deleted_dependencies: Vec<HistoricalHealthDeletion>,
    },
    /// A committed deletion fences the receipt or metadata required to verify its contents.
    /// No result, sensor identity or capture scope is inferred from the absent bytes.
    Deleted(HistoricalHealthDeletion),
}

impl PartialEq for HistoricalHealthMetadata {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Retained {
                    record: left,
                    provenance_root: left_root,
                    deleted_dependencies: left_deleted,
                },
                Self::Retained {
                    record: right,
                    provenance_root: right_root,
                    deleted_dependencies: right_deleted,
                },
            ) => {
                left_root == right_root
                    && left_deleted == right_deleted
                    && left.to_bytes() == right.to_bytes()
            }
            (Self::Deleted(left), Self::Deleted(right)) => left == right,
            _ => false,
        }
    }
}

/// One committed diagnostic, retained independently of every other receipt for its sensor.
#[derive(Clone, Debug, PartialEq)]
pub struct RetainedHistoricalHealth {
    /// Exact canonical receipt digest named by the committed diagnostic delta.
    pub receipt_digest: ContentDigest,
    /// Publication position, fixed even when later unrelated commits advance the head.
    pub committed_sequence: u64,
    /// Retained historical metadata or its explicit current deletion boundary.
    pub metadata: HistoricalHealthMetadata,
    /// Metadata-object reads performed for this receipt; media and trace reads are always zero.
    pub metadata_reads: u64,
    /// Metadata bytes read for this receipt, included in the deployment read cost.
    pub metadata_bytes: u64,
}

impl RetainedHistoricalHealth {
    /// Stable claim identity, independent of current ledger position or later clean screens.
    #[must_use]
    pub fn claim_id(&self) -> String {
        format!("{CLAIM_HISTORICAL_HEALTH_PREFIX}{}", self.receipt_digest)
    }

    /// Exact retained diagnostic handle; it is a reference, not a statement of availability.
    #[must_use]
    pub fn receipt_handle(&self) -> String {
        format!("fss://proof/{}", self.receipt_digest)
    }
}

/// Whether a semantic claim belongs to the registered historical diagnostic projection.
/// An arbitrary string sharing the prefix is not a diagnostic identity.
#[must_use]
pub fn is_historical_health_claim(claim: &str) -> bool {
    claim
        .strip_prefix(CLAIM_HISTORICAL_HEALTH_PREFIX)
        .is_some_and(|digest| {
            ContentDigest::parse(digest).is_ok_and(|parsed| parsed.to_text() == digest)
        })
}

/// Reads all committed diagnostic metadata at this prefix under independent inventory, read
/// count and byte bounds. Missing or corrupt committed metadata fails closed; only an exact
/// committed deletion becomes an unavailable row. Nothing is silently skipped as no findings.
pub(super) fn read_inventory(
    batches: &[EvidenceDeltaBatch],
    deletions: &DeletionIndex,
    max_object_bytes: usize,
    mut read: impl FnMut(ContentDigest, usize) -> Result<Vec<u8>, DeploymentReadError>,
) -> Result<Vec<RetainedHistoricalHealth>, DeploymentReadError> {
    let mut receipts = BTreeMap::new();
    for batch in batches {
        for delta in &batch.deltas {
            if delta.family != FAMILY_HISTORICAL_HEALTH {
                continue;
            }
            if receipts.len() >= MAX_HISTORICAL_HEALTH_RECORDS {
                return Err(corrupt(format!(
                    "historical sensor-health inventory exceeds the read bound \
                     {MAX_HISTORICAL_HEALTH_RECORDS}; no truncated diagnostic view was produced"
                )));
            }
            if receipts
                .insert(delta.payload_digest, batch.new_anchor.commit_sequence)
                .is_some()
            {
                return Err(corrupt(
                    "historical sensor-health receipt is committed more than once",
                ));
            }
        }
    }

    let deletion_authorities: BTreeSet<_> = batches
        .iter()
        .flat_map(|batch| &batch.deltas)
        .filter(|delta| delta.family == crate::reference_deployment::FAMILY_DELETION_RECORD)
        .map(|delta| delta.payload_digest)
        .collect();
    let mut retained = Vec::with_capacity(receipts.len());
    let mut total_bytes = 0_usize;
    for (receipt_digest, committed_sequence) in receipts {
        if let Some(entry) = deletions.object(receipt_digest) {
            retained.push(RetainedHistoricalHealth {
                receipt_digest,
                committed_sequence,
                metadata: HistoricalHealthMetadata::Deleted(HistoricalHealthDeletion {
                    unavailable_digest: receipt_digest,
                    deletion_plan: entry.plan_digest,
                    authority_in_prefix: deletion_authorities.contains(&entry.plan_digest),
                }),
                metadata_reads: 0,
                metadata_bytes: 0,
            });
            continue;
        }

        let mut metadata_reads = 0_usize;
        let mut metadata_bytes = 0_usize;
        let mut deleted = None;
        let mut read_error = None;
        let report = read_retained_at(batches, receipt_digest, |digest, requested_max| {
            if let Some(entry) = deletions.object(digest) {
                deleted = Some(HistoricalHealthDeletion {
                    unavailable_digest: digest,
                    deletion_plan: entry.plan_digest,
                    authority_in_prefix: deletion_authorities.contains(&entry.plan_digest),
                });
                return Err(HistoricalHealthError::Unavailable);
            }
            if metadata_reads >= MAX_HISTORICAL_HEALTH_READS_PER_RECORD {
                read_error = Some(corrupt(format!(
                    "historical sensor-health receipt {receipt_digest} exceeds the metadata \
                     read bound {MAX_HISTORICAL_HEALTH_READS_PER_RECORD}"
                )));
                return Err(HistoricalHealthError::Unavailable);
            }
            let remaining = MAX_HISTORICAL_HEALTH_METADATA_BYTES.saturating_sub(total_bytes);
            let max = requested_max.min(max_object_bytes).min(remaining);
            if max == 0 {
                read_error = Some(corrupt(format!(
                    "historical sensor-health metadata exceeds the aggregate byte bound \
                     {MAX_HISTORICAL_HEALTH_METADATA_BYTES}"
                )));
                return Err(HistoricalHealthError::Unavailable);
            }
            metadata_reads += 1;
            match read(digest, max) {
                Ok(bytes) if bytes.len() <= max => {
                    metadata_bytes += bytes.len();
                    total_bytes += bytes.len();
                    Ok(bytes)
                }
                Ok(_) => {
                    read_error = Some(corrupt(
                        "historical sensor-health metadata reader exceeded its byte bound",
                    ));
                    Err(HistoricalHealthError::Unavailable)
                }
                Err(error) => {
                    read_error = Some(error);
                    Err(HistoricalHealthError::Unavailable)
                }
            }
        });

        let metadata = match report {
            Ok(report) => {
                let mut deleted_dependencies = BTreeMap::new();
                for digest in [
                    report.record.import_root(),
                    report.record.manifest_digest(),
                    report.record.trace_digest(),
                ] {
                    if let Some(entry) = deletions.object(digest) {
                        deleted_dependencies.insert(digest, entry.plan_digest);
                    }
                }
                let identity = report.record.import_identity();
                if let Some(entry) = deletions.import(identity) {
                    deleted_dependencies.insert(identity, entry.plan_digest);
                }
                HistoricalHealthMetadata::Retained {
                    record: report.record,
                    provenance_root: report.provenance_root,
                    deleted_dependencies: deleted_dependencies
                        .into_iter()
                        .map(
                            |(unavailable_digest, deletion_plan)| HistoricalHealthDeletion {
                                unavailable_digest,
                                deletion_plan,
                                authority_in_prefix: deletion_authorities.contains(&deletion_plan),
                            },
                        )
                        .collect(),
                }
            }
            Err(error) => {
                if let Some(error) = read_error {
                    return Err(error);
                }
                if let Some(deleted) = deleted {
                    HistoricalHealthMetadata::Deleted(deleted)
                } else {
                    return Err(corrupt(format!(
                        "historical sensor-health receipt {receipt_digest}: {error}"
                    )));
                }
            }
        };
        retained.push(RetainedHistoricalHealth {
            receipt_digest,
            committed_sequence,
            metadata,
            metadata_reads: metadata_reads as u64,
            metadata_bytes: metadata_bytes as u64,
        });
    }
    Ok(retained)
}

pub(super) struct HistoricalHealthProjection {
    pub cells: Vec<KnowledgeCell>,
    pub proof_roots: BTreeSet<ContentDigest>,
    pub reference_handles: BTreeSet<String>,
    pub unknown: Vec<String>,
    pub at_risk: Vec<String>,
    pub degradation: Vec<String>,
    pub source: SourceOmissions,
    pub attention: Option<AttentionItem>,
}

/// Uses the existing KnowledgeCell/context-pack/evidence carriers. The knowledge state is about
/// the literal retained output or deletion record, never a physical health determination.
pub(super) fn project(
    retained: &[RetainedHistoricalHealth],
) -> Result<HistoricalHealthProjection, ContractError> {
    let mut projection = HistoricalHealthProjection {
        cells: Vec::new(),
        proof_roots: BTreeSet::new(),
        reference_handles: BTreeSet::new(),
        unknown: Vec::new(),
        at_risk: Vec::new(),
        degradation: Vec::new(),
        source: SourceOmissions::default(),
        attention: None,
    };
    if retained.is_empty() {
        return Ok(projection);
    }
    let mut suspected = 0_usize;
    let mut incomplete = 0_usize;
    let mut unavailable = 0_usize;
    let mut attention_handle = None;
    for item in retained {
        projection.reference_handles.insert(item.receipt_handle());
        let mut evidence = BTreeSet::new();
        let statement = match &item.metadata {
            HistoricalHealthMetadata::Retained {
                record,
                provenance_root,
                deleted_dependencies,
            } => {
                evidence.insert(item.receipt_digest);
                evidence.insert(*provenance_root);
                let summary = record.summary();
                if record.status() == "suspected_degradation" {
                    suspected += 1;
                }
                if !summary.complete() {
                    incomplete += 1;
                }
                if summary.publication_blocked() && attention_handle.is_none() {
                    attention_handle = Some(item.receipt_handle());
                }
                let findings = summary
                    .findings()
                    .iter()
                    .map(|run| run.finding.as_str())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ");
                let custody = if deleted_dependencies.is_empty() {
                    // One output byte is a conservative token ceiling. The allowance covers
                    // the CLI envelope, exact command and a maximum-length absolute root.
                    // Hydration also validates deployment custody, so price the CLI's full
                    // storage-operation authority rather than only this projection's reads.
                    let max_report_bytes = record.to_json().len() as u64 + 16 * 1024;
                    projection.source.handles.push(ExpansionHandle {
                        handle: item.receipt_handle(),
                        purpose: format!(
                            "Historical heuristic diagnostic metadata and exact finding runs: \
                             `fss-event health read --root ABS_DIR --site SITE \
                             --diagnostic-digest {} --max-metadata-bytes \
                             {MAX_HISTORICAL_HEALTH_METADATA_BYTES} --max-report-bytes \
                             {max_report_bytes}`. This read does not rerun native perception \
                             or establish current health.",
                            item.receipt_digest
                        ),
                        estimated_cost: BudgetVector::builder()
                            .tokens(max_report_bytes)
                            .bytes(MAX_HISTORICAL_HEALTH_METADATA_BYTES as u64 + max_report_bytes)
                            .storage_operations(65_536)
                            .build()
                            .map_err(|_| ContractError::BudgetExhausted)?,
                    });
                    "Source and trace were not read or natively revalidated.".to_owned()
                } else {
                    unavailable += 1;
                    evidence.extend(deleted_dependencies.iter().map(|entry| entry.deletion_plan));
                    if attention_handle.is_none() {
                        attention_handle = Some(item.receipt_handle());
                    }
                    let committed = deleted_dependencies
                        .iter()
                        .filter(|deletion| deletion.authority_in_prefix)
                        .count();
                    format!(
                        "Source or trace is deleted; the retained output does not prove \
                         available evidence or native replay. Of {} deletion boundaries, \
                         {committed} were authoritative by this snapshot's committed prefix; \
                         every boundary fences current bytes even at an earlier prefix.",
                        deleted_dependencies.len(),
                    )
                };
                let capture = record.capture_scope();
                format!(
                    "Historical heuristic sensor-health receipt {} reports {} for sensor {}, \
                     stream {}, import {}, source root {}; requested first segment {}, segment \
                     count {}; capture hull [{}, {}] ns is {} (scope={}, time_reliable={}), not \
                     continuous coverage. Historical privacy binding {}, generation={}. \
                     Screened {} frame(s), {} sample(s); complete={}; {} finding run(s) [{}]. \
                     Trace reference {}. {custody} This is a literal retained result, not a \
                     current health, tamper or certified-absence claim; no_findings clears no \
                     earlier receipt. Metadata read: {} object(s), {} byte(s).",
                    item.receipt_digest,
                    record.status(),
                    record.sensor_id(),
                    record.stream_id(),
                    record.import_identity(),
                    record.import_root(),
                    record.first_segment(),
                    record.segment_count(),
                    capture.earliest.0,
                    capture.latest.0,
                    record.capture_time_label(),
                    record.capture_scope_semantics(),
                    record.time_reliable(),
                    record.privacy_digest(),
                    record
                        .privacy_generation()
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    summary.frames_screened(),
                    summary.samples_screened(),
                    summary.complete(),
                    summary.findings().len(),
                    if findings.is_empty() {
                        "none"
                    } else {
                        &findings
                    },
                    record.trace_digest(),
                    item.metadata_reads,
                    item.metadata_bytes,
                )
            }
            HistoricalHealthMetadata::Deleted(deletion) => {
                unavailable += 1;
                evidence.insert(deletion.deletion_plan);
                if attention_handle.is_none() {
                    attention_handle = Some(format!("fss://proof/{}", deletion.deletion_plan));
                }
                format!(
                    "Historical sensor-health diagnostic {} was committed at sequence {}, but \
                     metadata {} is unavailable under committed deletion plan {}. Its result, \
                     source scope and physical sensor condition are unknown; unavailable is not \
                     no_findings and clears no earlier diagnostic. The deletion authority is {}; \
                     current bytes remain fenced at either historical position.",
                    item.receipt_digest,
                    item.committed_sequence,
                    deletion.unavailable_digest,
                    deletion.deletion_plan,
                    if deletion.authority_in_prefix {
                        "within this snapshot's committed prefix"
                    } else {
                        "later than this snapshot's committed prefix"
                    },
                )
            }
        };
        projection.proof_roots.extend(evidence.iter().copied());
        projection.cells.push(cell(KnowledgeCellParams {
            claim_id: item.claim_id(),
            statement,
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: evidence.into_iter().collect(),
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?);
    }
    projection.degradation.push(format!(
        "Historical sensor-health projection verifies retained metadata only; original native \
         derivations are not rerun. Read bounds: {MAX_HISTORICAL_HEALTH_RECORDS} receipts, \
         {MAX_HISTORICAL_HEALTH_READS_PER_RECORD} metadata reads per receipt, \
         {MAX_HISTORICAL_HEALTH_METADATA_BYTES} aggregate metadata bytes."
    ));
    if suspected > 0 || incomplete > 0 || unavailable > 0 {
        let risk = format!(
            "Historical heuristic diagnostics: {suspected} suspected_degradation; {incomplete} \
             incomplete screens; {unavailable} deleted metadata/source. Current sensor health, \
             outage, tamper, continuous coverage and certified absence are unproved; \
             no_findings clears no earlier finding."
        );
        projection.at_risk.push(risk.clone());
        projection.attention = attention_handle.map(|handle| AttentionItem {
            item_id: "attention:historical-sensor-health".to_owned(),
            kind: "historical_sensor_health",
            priority_class: "normal",
            mission_relevance: 1.0,
            decision_impact: 1.0,
            reason: risk,
            handle,
        });
    } else {
        projection.unknown.push(
            "Historical heuristic diagnostics do not establish current sensor health, outage, \
             tamper, continuous coverage or certified absence; no_findings clears no earlier \
             finding."
                .to_owned(),
        );
    }
    if !projection.source.handles.is_empty() {
        projection.source.omissions.push(SourceOmission {
            class: SOURCE_CLASS_HISTORICAL_HEALTH_DETAIL.to_owned(),
            omitted_count: projection.source.handles.len() as u64,
            transform: CompressionTransform {
                kind: CompressionTransformKind::Summarize,
                scope: "retained historical heuristic sensor-health diagnostics".to_owned(),
                loss_class: CompressionLossClass::DecisionPreserving,
                details: Some(
                    "Each receipt keeps its literal status, source scope, completeness, finding \
                     classes and exact evidence identity; full finding runs and derivation \
                     metadata hydrate through its priced handle. Later no_findings does not \
                     replace or clear any earlier receipt."
                        .to_owned(),
                ),
            },
        });
    }
    Ok(projection)
}

#[cfg(test)]
mod tests;
