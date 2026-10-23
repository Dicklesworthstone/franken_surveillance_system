#![forbid(unsafe_code)]
//! Explicit historical metadata reads over the existing authority/effect-prefix token.
//!
//! Historical reads never restore old source permissions. `snapshot_at` applies deletion
//! records from the entire current history, and callers expose only the existing metadata
//! projections. Ordinary head reads retain their original behavior and identities.

use std::path::Path;

use fss_core::{
    CanonicalEncoder, ContentDigest, EnvelopeProposition, ExplainQuestion, ExplainReceipt,
    KnowledgeState,
};
use fss_reference::agent_follow::{AnchorToken, history_anchor_token, resolve_anchor};
use fss_reference::agent_orient::{
    DeploymentHistory, DeploymentReadError, DeploymentSnapshot, OrientLimits, read_deployment,
};

use crate::error::{CliError, ExitIdentity};

use super::{evidence, execution_diagnostic, read_refusal, take};

/// Exact selected prefix and the full history against which it was verified.
#[derive(Clone, Debug)]
pub(crate) struct HistoricalScope {
    pub(crate) selected: AnchorToken,
    pub(crate) head: AnchorToken,
    head_root: ContentDigest,
}

impl HistoricalScope {
    pub(crate) fn encode_request(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("historical_at");
        encoder.text(self.selected.as_str());
        encoder.text("verified_head");
        encoder.text(self.head.as_str());
    }

    pub(crate) fn warning(&self) -> String {
        "Historical metadata only. Current deletion restrictions apply; reorient at the current head before operational decisions.".to_owned()
    }

    pub(crate) fn statement(&self) -> String {
        format!(
            "Historical metadata at {}; verified against retained history head {}. Event \
             hypotheses, coverage, effects and obligations describe the selected prefix, not \
             current operational state. Current deletion records still apply. No source-media \
             disclosure, old permission restoration or effect authority is granted. Reorient \
             at the current head before making an operational decision.",
            self.selected.as_str(),
            self.head.as_str(),
        )
    }

    pub(crate) fn proposition(&self) -> EnvelopeProposition {
        EnvelopeProposition {
            id: "claim:read:historical-scope".to_owned(),
            statement: self.statement(),
            state: KnowledgeState::Known,
            provenance: "derived".to_owned(),
            evidence: vec![self.head_root.to_text()],
        }
    }

    /// Same semantic UTF-8 byte/4 estimate as the existing explanation support projection.
    pub(crate) fn context_tokens(&self) -> u64 {
        self.context_bytes().div_ceil(4)
    }

    fn context_bytes(&self) -> u64 {
        let p = self.proposition();
        (p.id.len()
            + p.statement.len()
            + p.state.as_str().len()
            + p.provenance.len()
            + p.evidence.iter().map(String::len).sum::<usize>()
            + self.warning().len()) as u64
    }

    /// Price and bind the historical qualifier without widening the caller's context budget.
    pub(super) fn augment(&self, support: &mut evidence::SupportReview) -> Result<(), ()> {
        let receipt = ExplainReceipt::compile(
            ExplainQuestion::Why,
            support.receipt.subject(),
            vec![
                support.receipt.receipt_digest(),
                self.head_root,
                ContentDigest::sha256(self.statement().as_bytes()),
            ],
            Vec::new(),
            0,
        )
        .map_err(|_| ())?;
        let pointers = [self.head_root.to_text(), receipt.receipt_digest().to_text()];
        let cost = " Historical scope is priced as semantic UTF-8 bytes/4.";
        let extra_bytes = self.context_bytes()
            + cost.len() as u64
            + pointers.iter().map(|p| p.len() as u64).sum::<u64>();
        let tokens = support
            .consumed
            .tokens
            .checked_add(extra_bytes.div_ceil(4))
            .ok_or(())?;
        if tokens > support.requested.tokens {
            return Err(());
        }
        support.propositions.insert(0, self.proposition());
        support.warnings.push(self.warning());
        support.proof_pointers.extend(pointers);
        support.receipt = receipt;
        support.consumed.tokens = tokens;
        support.cost_statement.push_str(cost);
        Ok(())
    }

    /// Freshly verify the same selected prefix and the full current deletion/authority basis.
    /// Any head advance during a custody walk makes that walk unfit to answer this request.
    pub(crate) fn recheck(&self, root: &Path) -> Result<DeploymentSnapshot, DeploymentReadError> {
        let unavailable = || DeploymentReadError::Unreadable {
            reason: "historical custody authority changed during the check".to_owned(),
        };
        let history = DeploymentHistory::read(root, &OrientLimits::default())?;
        if history_anchor_token(&history, history.head()).as_ref() != Some(&self.head) {
            return Err(unavailable());
        }
        let position = resolve_anchor(&history, &self.selected).map_err(|_| unavailable())?;
        history.snapshot_at(position)
    }
}

/// Parse the same exact token spelling used by follow. No numeric-offset dialect is added.
pub(crate) fn parse(
    command: &str,
    values: &[(String, String, usize)],
) -> Result<Option<AnchorToken>, CliError> {
    take(values, "--at")
        .map(|(_, value, index)| {
            AnchorToken::parse(value).ok_or_else(|| CliError::MalformedValue {
                option: "--at".to_owned(),
                value: value.clone(),
                reason: "expected an exact retained authority/effect-history anchor token"
                    .to_owned(),
                command: Some(command.to_owned()),
                index: *index,
            })
        })
        .transpose()
}

pub(crate) fn read(
    command: &str,
    root: &Path,
    limits: &OrientLimits,
    at: Option<&AnchorToken>,
) -> Result<(DeploymentSnapshot, Option<HistoricalScope>), (String, ExitIdentity)> {
    let Some(at) = at else {
        return read_deployment(root, limits)
            .map(|snapshot| (snapshot, None))
            .map_err(|error| read_refusal(command, root, &error));
    };
    let history = DeploymentHistory::read(root, limits)
        .map_err(|error| read_refusal(command, root, &error))?;
    // Refuse foreign, unknown, forged and future tokens before selecting any source object.
    let unavailable = || {
        (
            execution_diagnostic(
                command,
                root,
                "ERR-AGENT-RESNAPSHOT-001",
                ExitIdentity::AGENT_REFUSED,
            ),
            ExitIdentity::AGENT_REFUSED,
        )
    };
    let position = resolve_anchor(&history, at).map_err(|_| unavailable())?;
    let head = history_anchor_token(&history, history.head()).ok_or_else(unavailable)?;
    let (_, head_root, _) = history.roots_at(history.head()).ok_or_else(unavailable)?;
    let snapshot = history
        .snapshot_at(position)
        .map_err(|error| read_refusal(command, root, &error))?;
    Ok((
        snapshot,
        Some(HistoricalScope {
            selected: at.clone(),
            head,
            head_root,
        }),
    ))
}
