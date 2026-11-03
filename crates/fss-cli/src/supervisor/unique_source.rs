#![forbid(unsafe_code)]
//! Explicit caller-declared source-once strategy and complete supervisor projection.

use std::collections::BTreeMap;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_fusion::{
    Calibration, EProcessConfig, EProcessStepOutcome, FusionError, FusionOutcome, FusionQuery,
    MAX_EVIDENCE, Observability, RegimeResetReason, SequentialEProcess, SourceDisposition,
    UNIQUE_SOURCE_STEP_SCHEMA, UniqueSourceEProcess, UniqueSourceError, UniqueSourceStepOutcome,
};

use super::{
    SupervisorError, SupervisorReport, array, integer, nullable, object, string, unsigned,
};

/// Explicit supervisor profile; default and transcript-only reports are unchanged.
pub const UNIQUE_SOURCE_SUPERVISOR_SCHEMA: &str = "fss.unique_source_supervisor_report.v1";
/// Independent profile configuration, including before any observation executes.
pub const UNIQUE_SOURCE_SUPERVISOR_CONFIG_DOMAIN: &str = "fss.supervisor.unique_source_config.v1";
/// Tagged raw sensor/label/score facts, per-step input and bounded lifetime raw-source inventory.
pub const UNIQUE_SOURCE_SUPERVISOR_RAW_DOMAIN: &str = "fss.supervisor.unique_source_raw.v1";
/// Complete deterministic source-once supervisor result.
pub const UNIQUE_SOURCE_SUPERVISOR_RECEIPT_DOMAIN: &str = "fss.supervisor.unique_source_receipt.v1";

pub(super) type Bindings = BTreeMap<String, Option<ContentDigest>>;
pub(super) type RawInputs = BTreeMap<String, ContentDigest>;

fn canonical_source(source: ContentDigest) -> ContentDigest {
    ContentDigest::new(source.algorithm(), source.bytes())
}

/// Hash exact caller facts before score binning or alias formatting can discard distinctions.
pub(super) fn raw_item_digest(sensor: &str, label: &str, score_ppm: u32) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(UNIQUE_SOURCE_SUPERVISOR_RAW_DOMAIN);
    e.tag(0);
    e.digest(ContentDigest::sha256(sensor.as_bytes()));
    e.digest(ContentDigest::sha256(label.as_bytes()));
    e.u32(score_ppm);
    ContentDigest::sha256(&e.finish())
}

fn raw_inventory_digest(
    limit: usize,
    seen: &BTreeMap<ContentDigest, ContentDigest>,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(UNIQUE_SOURCE_SUPERVISOR_RAW_DOMAIN);
    e.tag(2);
    e.u32(limit as u32);
    e.u32(seen.len() as u32);
    let mut digest = ContentDigest::sha256(&e.finish());
    for (source, item) in seen {
        let mut e = CanonicalEncoder::new();
        e.tag(3);
        e.digest(digest);
        e.digest(*source);
        e.digest(*item);
        digest = ContentDigest::sha256(&e.finish());
    }
    digest
}

/// One accepted profile step plus its exact original detector score/label input commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniqueSourceSupervisorStep {
    outcome: UniqueSourceStepOutcome,
    raw_input_digest: Option<ContentDigest>,
}

impl UniqueSourceSupervisorStep {
    /// Complete core source admission and numerical transcript.
    #[must_use]
    pub const fn outcome(&self) -> &UniqueSourceStepOutcome {
        &self.outcome
    }

    /// Exact numeric-source caller facts; absent when this window executed a numerical reset.
    #[must_use]
    pub const fn raw_input_digest(&self) -> Option<ContentDigest> {
        self.raw_input_digest
    }
}

pub(super) enum Accumulator {
    Legacy(SequentialEProcess),
    Unique {
        process: UniqueSourceEProcess,
        raw_seen: BTreeMap<ContentDigest, ContentDigest>,
        steps: Vec<UniqueSourceSupervisorStep>,
    },
}

impl Accumulator {
    pub(super) fn new(
        hypothesis: &str,
        config: EProcessConfig,
        limit: Option<usize>,
    ) -> Result<Self, SupervisorError> {
        match limit {
            None => SequentialEProcess::new(hypothesis, config)
                .map(Self::Legacy)
                .map_err(SupervisorError::Fusion),
            Some(limit) => Ok(Self::Unique {
                process: UniqueSourceEProcess::new(hypothesis, config, limit)
                    .map_err(SupervisorError::UniqueSource)?,
                raw_seen: BTreeMap::new(),
                steps: Vec::new(),
            }),
        }
    }

    pub(super) const fn is_unique(&self) -> bool {
        matches!(self, Self::Unique { .. })
    }

    pub(super) fn numerical(&self) -> &SequentialEProcess {
        match self {
            Self::Legacy(process) => process,
            Self::Unique { process, .. } => process.accumulator(),
        }
    }

    pub(super) fn observe_step(
        &mut self,
        query: &FusionQuery,
        bindings: &Bindings,
        raw: &RawInputs,
    ) -> Result<(FusionOutcome, EProcessStepOutcome), SupervisorError> {
        let Self::Unique {
            process,
            raw_seen,
            steps,
        } = self
        else {
            let Self::Legacy(process) = self else {
                unreachable!()
            };
            return process.observe_step(query).map_err(SupervisorError::Fusion);
        };
        if query.evidence.len() > MAX_EVIDENCE || raw.len() > MAX_EVIDENCE {
            return Err(SupervisorError::UniqueSource(
                UniqueSourceError::InvalidBindings,
            ));
        }
        let numeric: Vec<_> = query
            .evidence
            .iter()
            .filter(|item| {
                matches!(item.observability, Observability::Observed)
                    && matches!(item.calibration, Calibration::Calibrated { .. })
            })
            .collect();
        if raw.len() != numeric.len() || numeric.iter().any(|item| !raw.contains_key(&item.id)) {
            return Err(SupervisorError::UniqueSource(
                UniqueSourceError::InvalidBindings,
            ));
        }
        let mut additions = BTreeMap::new();
        let mut e = CanonicalEncoder::new();
        e.text(UNIQUE_SOURCE_SUPERVISOR_RAW_DOMAIN);
        e.tag(1);
        e.u32(raw.len() as u32);
        for (alias, fingerprint) in raw {
            let source = bindings
                .get(alias)
                .and_then(|value| *value)
                .map(canonical_source)
                .ok_or(SupervisorError::UniqueSource(
                    UniqueSourceError::InvalidBindings,
                ))?;
            if raw_seen
                .get(&source)
                .or_else(|| additions.get(&source))
                .is_some_and(|old| old != fingerprint)
            {
                return Err(SupervisorError::UniqueSource(
                    UniqueSourceError::ConflictingSource { source },
                ));
            }
            if !raw_seen.contains_key(&source) {
                additions.insert(source, *fingerprint);
            }
            e.digest(ContentDigest::sha256(alias.as_bytes()));
            e.digest(source);
            e.digest(*fingerprint);
        }
        if raw_seen.len() + additions.len() > process.source_limit() {
            return Err(SupervisorError::UniqueSource(
                UniqueSourceError::SourceCapacity {
                    limit: process.source_limit(),
                    existing: raw_seen.len(),
                    additional: additions.len(),
                },
            ));
        }
        let raw_input_digest = ContentDigest::sha256(&e.finish());
        // Raw facts are staged above; only a complete core admission commits either inventory.
        let (fusion, outcome) = process
            .observe_step(query, bindings)
            .map_err(SupervisorError::UniqueSource)?;
        raw_seen.extend(additions);
        let step = outcome.step().clone();
        steps.push(UniqueSourceSupervisorStep {
            outcome,
            raw_input_digest: Some(raw_input_digest),
        });
        Ok((fusion, step))
    }

    pub(super) fn reset_regime(&mut self, reason: RegimeResetReason) -> EProcessStepOutcome {
        match self {
            Self::Legacy(process) => process.reset_regime(reason),
            Self::Unique { process, steps, .. } => {
                let outcome = process.reset_regime(reason);
                let step = outcome.step().clone();
                steps.push(UniqueSourceSupervisorStep {
                    outcome,
                    raw_input_digest: None,
                });
                step
            }
        }
    }

    pub(super) fn finish_unique(
        self,
        report: SupervisorReport,
    ) -> Result<UniqueSourceSupervisorReport, SupervisorError> {
        let Self::Unique {
            process,
            raw_seen,
            steps,
        } = self
        else {
            return Err(SupervisorError::Fusion(FusionError::InvalidInput(
                "source-once profile not selected".to_owned(),
            )));
        };
        if steps.len() != report.window_records.len()
            || raw_seen.len() != process.sources_seen()
            || process.accumulator().hypothesis_id() != report.hypothesis_id
            || steps
                .iter()
                .zip(&report.window_records)
                .any(|(step, window)| step.outcome.step() != &window.step_outcome)
        {
            return Err(SupervisorError::Fusion(FusionError::InvalidInput(
                "source-once report/transition binding".to_owned(),
            )));
        }
        let config = *process.accumulator().config();
        let limit = process.source_limit();
        let mut e = CanonicalEncoder::new();
        e.text(UNIQUE_SOURCE_SUPERVISOR_CONFIG_DOMAIN);
        e.digest(ContentDigest::sha256(report.hypothesis_id.as_bytes()));
        e.i128(i128::from(config.alert_threshold_mban));
        e.i128(i128::from(config.floor_mban));
        e.i128(i128::from(config.ceiling_mban));
        e.u32(config.min_independent_clusters);
        e.u32(limit as u32);
        let configuration_digest = ContentDigest::sha256(&e.finish());
        let source_inventory_digest = process.inventory_digest();
        let raw_source_inventory_digest = raw_inventory_digest(limit, &raw_seen);
        let mut e = CanonicalEncoder::new();
        e.text(UNIQUE_SOURCE_SUPERVISOR_RECEIPT_DOMAIN);
        e.text(UNIQUE_SOURCE_SUPERVISOR_SCHEMA);
        e.digest(report.transcript_digest);
        e.digest(configuration_digest);
        e.u32(limit as u32);
        e.u32(process.sources_seen() as u32);
        e.digest(source_inventory_digest);
        e.digest(raw_source_inventory_digest);
        e.u64(steps.len() as u64);
        let mut receipt_digest = ContentDigest::sha256(&e.finish());
        for step in &steps {
            let mut e = CanonicalEncoder::new();
            e.digest(receipt_digest);
            e.digest(step.outcome.digest());
            match step.raw_input_digest {
                Some(raw) => {
                    e.bool(true);
                    e.digest(raw);
                }
                None => e.bool(false),
            }
            receipt_digest = ContentDigest::sha256(&e.finish());
        }
        Ok(UniqueSourceSupervisorReport {
            report,
            config,
            source_limit: limit,
            sources_seen: process.sources_seen(),
            configuration_digest,
            source_inventory_digest,
            raw_source_inventory_digest,
            steps,
            receipt_digest,
        })
    }
}

/// Complete explicitly selected caller-declared source-once supervisor result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniqueSourceSupervisorReport {
    report: SupervisorReport,
    config: EProcessConfig,
    source_limit: usize,
    sources_seen: usize,
    configuration_digest: ContentDigest,
    source_inventory_digest: ContentDigest,
    raw_source_inventory_digest: ContentDigest,
    steps: Vec<UniqueSourceSupervisorStep>,
    receipt_digest: ContentDigest,
}

impl UniqueSourceSupervisorReport {
    /// Original report representation of the profile's actual numerical trajectory.
    #[must_use]
    pub const fn report(&self) -> &SupervisorReport {
        &self.report
    }
    /// Complete numerical configuration, independently bound even for zero transitions.
    #[must_use]
    pub const fn config(&self) -> EProcessConfig {
        self.config
    }
    /// Selected lifetime source allowance.
    #[must_use]
    pub const fn source_limit(&self) -> usize {
        self.source_limit
    }
    /// Distinct consumed declared numeric sources, including earlier regimes.
    #[must_use]
    pub const fn sources_seen(&self) -> usize {
        self.sources_seen
    }
    /// Hypothesis, complete numerical configuration and source allowance commitment.
    #[must_use]
    pub const fn configuration_digest(&self) -> ContentDigest {
        self.configuration_digest
    }
    /// Complete core lifetime source inventory.
    #[must_use]
    pub const fn source_inventory_digest(&self) -> ContentDigest {
        self.source_inventory_digest
    }
    /// Exact raw sensor, label and score commitments for every consumed source.
    #[must_use]
    pub const fn raw_source_inventory_digest(&self) -> ContentDigest {
        self.raw_source_inventory_digest
    }
    /// Every accepted observation/reset window, with no omitted transition.
    #[must_use]
    pub fn steps(&self) -> &[UniqueSourceSupervisorStep] {
        &self.steps
    }
    /// Complete profile receipt; source custody and statistical qualification remain unverified.
    #[must_use]
    pub const fn receipt_digest(&self) -> ContentDigest {
        self.receipt_digest
    }

    /// Renders the explicit complete source-once profile, never relabeling default output.
    #[must_use]
    pub fn to_json(&self) -> String {
        let steps: Vec<_> = self
            .steps
            .iter()
            .zip(&self.report.window_records)
            .map(|(step, window)| {
                object(&[
                    ("window_index", unsigned(window.window_index)),
                    ("timestamp_ns", unsigned(window.timestamp_ns)),
                    (
                        "raw_input_digest",
                        nullable(
                            step.raw_input_digest
                                .map(|digest| string(&digest.to_text())),
                        ),
                    ),
                    ("source_receipt", step_json(&step.outcome)),
                ])
            })
            .collect();
        object(&[
            ("schema", string(UNIQUE_SOURCE_SUPERVISOR_SCHEMA)),
            ("source_identity_basis", string("caller_declared_digest")),
            ("report", self.report.to_json()),
            (
                "eprocess_config",
                object(&[
                    (
                        "alert_threshold_mban",
                        integer(i128::from(self.config.alert_threshold_mban)),
                    ),
                    ("floor_mban", integer(i128::from(self.config.floor_mban))),
                    (
                        "ceiling_mban",
                        integer(i128::from(self.config.ceiling_mban)),
                    ),
                    (
                        "min_independent_clusters",
                        unsigned(u64::from(self.config.min_independent_clusters)),
                    ),
                ]),
            ),
            (
                "configuration_digest",
                string(&self.configuration_digest.to_text()),
            ),
            ("source_limit", unsigned(self.source_limit as u64)),
            ("sources_seen", unsigned(self.sources_seen as u64)),
            (
                "source_inventory_digest",
                string(&self.source_inventory_digest.to_text()),
            ),
            (
                "raw_source_inventory_digest",
                string(&self.raw_source_inventory_digest.to_text()),
            ),
            ("unique_source_steps", array(&steps)),
            ("receipt_digest", string(&self.receipt_digest.to_text())),
        ])
    }
}

fn step_json(step: &UniqueSourceStepOutcome) -> String {
    let rows: Vec<_> = step
        .admissions()
        .iter()
        .map(|row| {
            object(&[
                ("evidence_id", string(row.evidence_id())),
                (
                    "source_digest",
                    nullable(row.source_digest().map(|digest| string(&digest.to_text()))),
                ),
                ("item_digest", string(&row.item_digest().to_text())),
                (
                    "disposition",
                    string(match row.disposition() {
                        SourceDisposition::Admitted => "admitted",
                        SourceDisposition::AlreadyAdmitted => "already_admitted",
                        SourceDisposition::NonNumeric => "non_numeric",
                    }),
                ),
                (
                    "first_admitted_step",
                    nullable(row.first_admitted_step().map(unsigned)),
                ),
            ])
        })
        .collect();
    object(&[
        ("schema", string(UNIQUE_SOURCE_STEP_SCHEMA)),
        (
            "previous_receipt_digest",
            nullable(step.previous().map(|digest| string(&digest.to_text()))),
        ),
        (
            "submitted_query_digest",
            nullable(
                step.submitted_query_digest()
                    .map(|digest| string(&digest.to_text())),
            ),
        ),
        (
            "effective_query_digest",
            nullable(
                step.effective_query_digest()
                    .map(|digest| string(&digest.to_text())),
            ),
        ),
        ("source_limit", unsigned(step.source_limit() as u64)),
        ("sources_seen", unsigned(step.sources_seen() as u64)),
        (
            "inventory_digest",
            string(&step.inventory_digest().to_text()),
        ),
        ("admissions", array(&rows)),
        (
            "fusion_transcript",
            super::transcript::fusion_transcript_json(&step.step().transcript),
        ),
        ("receipt_digest", string(&step.digest().to_text())),
    ])
}
