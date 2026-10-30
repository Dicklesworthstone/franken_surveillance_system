#![forbid(unsafe_code)]
//! Exact native-to-case custody inside the same bounded cognitive response.

use fss_reference::agent_session::checkpoint::journal::coordination::investigations::ProbeCitationReceipt;
use fss_reference::deployment_session::probe::case::{ProbeCaseInspection, ProbeCaseLink};

use super::*;

/// Only native owner-produced sealed outcomes can supply a successful case linkage.
pub(in crate::probe_cmd) enum CaseProjection<'a> {
    Linked(&'a ProbeCaseLink),
    Inspected(&'a ProbeCaseInspection),
}

impl CaseProjection<'_> {
    pub(in crate::probe_cmd) fn append_recovery(
        &self,
        completed: &mut Vec<String>,
        proof: &mut Vec<ContentDigest>,
    ) {
        let (receipt, root) = match self {
            Self::Linked(link) => (Some(link.receipt()), Some(link.journal_root())),
            Self::Inspected(inspected) => {
                proof.push(inspected.journal_root());
                (
                    inspected.inspection().receipt(),
                    inspected.inspection().citation_root(),
                )
            }
        };
        if let Some(receipt) = receipt {
            let target = receipt.target();
            let custody = receipt.custody();
            proof.extend([
                receipt.digest(),
                receipt.revision().digest(),
                custody.digest(),
                custody.native_root(),
                custody.pending_receipt(),
                custody.payload_digest(),
            ]);
            if let Some(root) = root {
                proof.push(root);
            }
            completed.push(format!("Definitely retained case link {}; commit {}; case {}; predecessor {}; revision {}.", receipt.digest(), optional(root), target.case_id, target.expected, receipt.revision().digest()));
            completed.push(format!("Linked hypothesis {}; operator side {}; native payload {}; citation-time pending receipt {}. No assessment/ACK was implied; historical lookup does not establish current delivery status.", target.hypothesis, if target.contradicts { "contradiction" } else { "support" }, custody.payload_digest(), custody.pending_receipt()));
        } else {
            completed.push("Exact historical link lookup completed without a matching committed citation; this does not prove that no native work or pending publication occurred.".to_owned());
        }
    }

    #[allow(clippy::too_many_arguments)] // the outer envelope and required pack share explicit fields
    pub(in crate::probe_cmd) fn append(
        &self,
        args: &ProbeArgs,
        propositions: &mut Vec<EnvelopeProposition>,
        proof: &mut Vec<ContentDigest>,
        handles: &mut Vec<EvidenceHandle>,
        completed: &mut Vec<String>,
        not_observable: &mut Vec<String>,
        omissions: &mut Vec<String>,
    ) -> Result<()> {
        let action = args
            .case
            .as_ref()
            .ok_or(RenderError("case projection target missing"))?;
        let target = action.target();
        let (receipt, citation_root, inspected_root, historical, receipt_bytes) = match self {
            Self::Linked(link) => (
                Some(link.receipt()),
                Some(link.journal_root()),
                None,
                false,
                None,
            ),
            Self::Inspected(inspection) => {
                let inspected = inspection.inspection();
                (
                    inspected.receipt(),
                    inspected.citation_root(),
                    Some(inspected.inspected_root()),
                    true,
                    Some(inspected.receipt_bytes()),
                )
            }
        };
        if receipt.is_some_and(|receipt| receipt.target() != target) {
            return Err(RenderError("case projection substituted its exact target").into());
        }
        if let Some(root) = inspected_root {
            proof.push(root);
        }
        let status = if historical {
            "historical link inspection; no native work or relink"
        } else {
            "exact native-to-case citation committed; no assessment or ACK"
        };
        completed.push(status.to_owned());
        if let Some(receipt) = receipt {
            let root = citation_root.ok_or(RenderError("committed case citation root missing"))?;
            append_receipt(receipt, root, historical, propositions, proof, handles)?;
        } else {
            propositions.push(proposition("case-citation-absent", format!(
                "No committed link at inspected prefix {} for case {}, predecessor {}, hypothesis {}, subscription {}, side {}. This does not prove no source attempt or pending publication occurred. Inspect native progress; a new link requires an explicitly selected subscription-state digest.",
                optional(inspected_root), target.case_id, target.expected, target.hypothesis,
                args.request.subscription_id, if target.contradicts { "contradiction" } else { "support" },
            ), KnowledgeState::Known, &inspected_root.into_iter().collect::<Vec<_>>()));
        }
        if let Some(bytes) = receipt_bytes {
            propositions.push(proposition("case-citation-read", format!(
                "Historical citation lookup admitted {bytes} complete record/revision bytes at {}. The original source-work session and native receipt are historical; the current reader receives no source revalidation, refund, implicit ACK or authority renewal.",
                optional(inspected_root),
            ), KnowledgeState::Known, &inspected_root.into_iter().collect::<Vec<_>>()));
        }
        not_observable.push("A case citation records explicit operator-selected support or contradiction; it does not assess a hypothesis or prove physical truth. Historical inspection does not establish current source availability.".to_owned());
        omissions.push("This projection carries exact case-link custody and revision identities. Full case state remains available through the existing case inspect owner; no case assessment is substituted or inferred.".to_owned());
        Ok(())
    }
}

fn append_receipt(
    receipt: &ProbeCitationReceipt,
    citation_root: ContentDigest,
    historical: bool,
    propositions: &mut Vec<EnvelopeProposition>,
    proof: &mut Vec<ContentDigest>,
    handles: &mut Vec<EvidenceHandle>,
) -> Result<()> {
    let target = receipt.target();
    let custody = receipt.custody();
    let revision = receipt.revision().digest();
    let digest = receipt.digest();
    proof.extend([
        digest,
        custody.digest(),
        citation_root,
        revision,
        target.expected,
        custody.native_root(),
    ]);
    // These exact receipt metadata were reconstructed by the live owner, not inferred from an
    // opaque source digest. probe-citation can read them again under current case-reader grants.
    add_handle(handles, digest, "retained_probe_case_citation");
    propositions.push(proposition("case-linked", format!(
        "{} case citation {}; journal {}; case {}; predecessor {}; resulting revision {}; hypothesis {}; operator side {}; cited native payload {}. {} Citation does not change hypothesis assessment.",
        if historical { "Historical" } else { "Committed" }, digest, citation_root, target.case_id,
        target.expected, revision, target.hypothesis, if target.contradicts { "contradiction" } else { "support" }, custody.payload_digest(),
        if historical { "Report was pending at citation time; current delivery status is not established by this lookup." } else { "This citation neither ACKs nor discards the pending report." },
    ), KnowledgeState::Known, &[digest, revision, target.expected, custody.payload_digest()]));
    propositions.push(proposition("case-native-custody", format!(
        "Native owner custody {}; original principal {}; session {}; subscription {}; request {}; configuration {}; post-native state {}; native journal {}; pending receipt {}; report receipt {}; payload {} bytes {}; original report anchor {}; revalidation head {}; ledger {}; effects {}; observed {} ns; replayed={}; lifetime attempts {}; cumulative windows {:?}; privacy {}; native hypothesis {}. Journal replay verifies exact retained association and adjacent native Publish/Release. Recipe/hypothesis semantics and validation are native-owner assertions, not independently re-executed source proof.",
        custody.digest(), custody.principal().as_str(), custody.session().as_str(), custody.subscription_id(), custody.request_digest(),
        custody.configuration_digest(), custody.subscription_digest(), custody.native_root(), custody.pending_receipt(),
        custody.report_receipt(), custody.payload_digest(), custody.payload_bytes(), custody.report_anchor().state_root,
        custody.head().anchor.state_root, custody.head().ledger_root, custody.head().effect_root, custody.observed_at().0,
        custody.replayed(), custody.attempts_reserved(), custody.active_window_count(), custody.privacy_class(), custody.native_hypothesis(),
    ), KnowledgeState::Known, &[custody.digest(), custody.native_root(), custody.pending_receipt(), custody.report_receipt(), custody.payload_digest()]));
    if let Some(validation) = custody.validation() {
        propositions.push(proposition("case-native-validation", format!(
            "Historical native validation {}; authority {}; reserved source bytes {}; indexed reads {}. Recorded successful native-owner custody at citation time; no present availability assertion.",
            validation.receipt, validation.basis.state_root, validation.reserved_bytes, validation.read_attempts,
        ), KnowledgeState::Known, &[custody.digest(), validation.receipt]));
    }
    Ok(())
}
