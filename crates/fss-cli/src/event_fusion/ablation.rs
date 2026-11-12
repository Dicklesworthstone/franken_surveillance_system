#![forbid(unsafe_code)]
//! Source-loss explanations retain the exact native report snapshot that supplied the query.
//! This owner performs no new source read, source freshness check, publication or policy change.

use super::*;
use crate::fusion_json::{MAX_ABLATION_REPORT_BYTES, fusion_ablation_json};
use crate::json_output::{object, string};
use fss_fusion::{AblationTarget, FusionAblation};

const DOMAIN: &str = "fss.event_class_fusion.ablation.v1";
/// Historical native report projection; not current source revalidation or new event authority.
pub const EVENT_FUSION_ABLATION_SCHEMA: &str = "fss.event_class_fusion_ablation.v1";

/// Immutable candidate-specific counterfactual, bound to its original native source snapshot.
#[derive(Clone, Debug)]
pub struct EventFusionAblation {
    source_report: EventFusionReport,
    source_projection_digest: ContentDigest,
    candidate: ContentDigest,
    candidate_binding: ContentDigest,
    native_proposal: ContentDigest,
    native_provenance: ContentDigest,
    explanation: FusionAblation,
    digest: ContentDigest,
}

impl EventFusionReport {
    /// Explain simultaneous sensor/domain loss for one candidate in this historical report.
    ///
    /// The original source, score/calibration links, authority basis and native event proposal
    /// remain attached. This method does not reopen the source or establish that the report's
    /// authority basis is still current. A source-loss explanation cannot change the native
    /// approval, publish an event, activate a policy or prepare an effect.
    pub fn explain_ablation(
        &self,
        candidate: ContentDigest,
        targets: &[AblationTarget],
        cx: &ReplayCx,
    ) -> Result<EventFusionAblation> {
        checkpoint(cx)?;
        let selected = self
            .results
            .iter()
            .find(|row| row.candidate == candidate)
            .ok_or(EventFusionError::Scope)?;
        let explanation =
            fss_fusion::ablate(&selected.query, targets).map_err(|_| EventFusionError::Profile)?;
        if explanation.baseline().query_digest != selected.outcome.query_digest
            || explanation.baseline().decision_digest != selected.outcome.decision_digest
        {
            return Err(EventFusionError::Evidence);
        }
        checkpoint(cx)?;
        let source_projection_digest = ContentDigest::sha256(self.to_json()?.as_bytes());
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DOMAIN);
        encoder.digest(self.digest);
        encoder.digest(source_projection_digest);
        encoder.digest(self.profile.digest);
        encoder.digest(self.context);
        encoder.digest(self.package);
        self.basis.encode_canonical(&mut encoder);
        encoder.digest(selected.candidate);
        encoder.digest(selected.binding_digest);
        encoder.digest(selected.native_proposal);
        encoder.digest(selected.native_provenance);
        encoder.digest(explanation.digest());
        let output = EventFusionAblation {
            source_report: self.clone(),
            source_projection_digest,
            candidate: selected.candidate,
            candidate_binding: selected.binding_digest,
            native_proposal: selected.native_proposal,
            native_provenance: selected.native_provenance,
            explanation,
            digest: digest(encoder)?,
        };
        output.to_json()?;
        checkpoint(cx)?;
        Ok(output)
    }
}

impl EventFusionAblation {
    /// Exact historical report; its native source and score links are unchanged.
    #[must_use]
    pub const fn source_report(&self) -> &EventFusionReport {
        &self.source_report
    }
    /// Native candidate selected from that report.
    #[must_use]
    pub const fn candidate(&self) -> ContentDigest {
        self.candidate
    }
    /// Complete pure numerical explanation and affected inventories.
    #[must_use]
    pub const fn explanation(&self) -> &FusionAblation {
        &self.explanation
    }
    /// Exact enclosing source/authority/score snapshot and counterfactual receipt binding.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Complete bounded JSON. The original native report is included for source and raw-score
    /// provenance; the projected query is a separate replayable hypothetical input.
    pub fn to_json(&self) -> Result<String> {
        let json = object(&[
            ("schema", string(EVENT_FUSION_ABLATION_SCHEMA)),
            ("source_scope", string("historical_native_report_snapshot")),
            ("candidate", string(&self.candidate.to_text())),
            (
                "candidate_binding_digest",
                string(&self.candidate_binding.to_text()),
            ),
            ("native_proposal", string(&self.native_proposal.to_text())),
            (
                "native_provenance_root",
                string(&self.native_provenance.to_text()),
            ),
            ("source_report", self.source_report.to_json()?),
            (
                "source_projection_digest",
                string(&self.source_projection_digest.to_text()),
            ),
            (
                "ablation",
                fusion_ablation_json(&self.explanation).ok_or(EventFusionError::Limit)?,
            ),
            ("explanation_digest", string(&self.digest.to_text())),
            ("source_basis_revalidated", "false".to_owned()),
            ("event_policy_changed", "false".to_owned()),
            ("published", "false".to_owned()),
            ("effect_authority", "false".to_owned()),
        ]);
        if json.len().saturating_add(1) > MAX_ABLATION_REPORT_BYTES {
            return Err(EventFusionError::Limit);
        }
        Ok(json)
    }
}
