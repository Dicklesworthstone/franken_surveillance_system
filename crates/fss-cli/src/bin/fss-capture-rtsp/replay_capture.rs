#![forbid(unsafe_code)]
//! Request/acknowledgement custody over the exact durable AVC recording prefix.

use fss_cli::agent_json::{object, string};
use fss_core::ContentDigest;
use fss_publication::{LocalPublicationState, LocalRootPublisher, SlotName};
use fss_reference::rtsp::client::replay::{ReplayAcceptance, ReplayWindow};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording_replay::{
    MAX_REPLAY_WINDOWS, ReplayReceipt, ReplayRequest, ReplayTermination, ReplayWindowProof,
    publish_replay_receipt, replay_slot,
};

use super::{Failure, Options, Owner};

pub(super) struct CaptureReplay {
    request: ReplayRequest,
    acceptance: Option<ReplayAcceptance>,
    pending: Option<ReplayWindowProof>,
    windows: Vec<ReplayWindowProof>,
    durable_windows: usize,
    receipt: Option<(String, ContentDigest)>,
    unsettled: bool,
    receipt_failed: bool,
}

impl CaptureReplay {
    pub(super) fn new(request: ReplayRequest) -> Self {
        Self {
            request,
            acceptance: None,
            pending: None,
            windows: Vec::new(),
            durable_windows: 0,
            receipt: None,
            unsettled: false,
            receipt_failed: false,
        }
    }

    pub(super) fn window(&self) -> ReplayWindow {
        self.request.window()
    }

    pub(super) fn unsettled(&self) -> bool {
        self.unsettled
    }

    pub(super) fn accept(&mut self, acceptance: ReplayAcceptance) -> Result<(), Failure> {
        if self.acceptance.is_some() || acceptance.requested() != self.request.window() {
            return Err(Failure::ReplayAcknowledgement);
        }
        self.acceptance = Some(acceptance);
        Ok(())
    }

    pub(super) fn prepare_window(
        &mut self,
        slot: SlotName,
        recording: &PreparedRecording,
    ) -> Result<(), Failure> {
        if self.acceptance.is_none() || self.pending.is_some() {
            return Err(Failure::State);
        }
        if self.windows.len() >= MAX_REPLAY_WINDOWS {
            return Err(Failure::WorkBudget);
        }
        // Reserve before retaining another descriptor. Original media is not copied.
        self.windows.try_reserve(1).map_err(|_| Failure::WorkBudget)?;
        self.pending = Some(
            ReplayWindowProof::from_avc(slot, recording).map_err(|_| Failure::State)?,
        );
        Ok(())
    }

    pub(super) fn durable(&mut self, root: ContentDigest) -> Result<(), Failure> {
        let pending = self.pending.take().ok_or(Failure::State)?;
        if pending.root() != root || self.windows.len() >= MAX_REPLAY_WINDOWS {
            return Err(Failure::State);
        }
        self.windows.push(pending);
        self.durable_windows = self.windows.len();
        Ok(())
    }

    pub(super) fn acknowledgement_json(&self) -> String {
        let Some(acceptance) = self.acceptance else {
            return "null".into();
        };
        object(&[
            ("state", string("playing")),
            ("play_cseq", acceptance.cseq().to_string()),
            ("requested_range", string(&acceptance.requested().to_string())),
            ("acknowledged_range", string(&acceptance.acknowledged().to_string())),
            ("time_basis", string("recorder_assertion")),
            ("rate_control", string("no")),
            ("historical_frame_time", string("unknown")),
            ("complete_interval_retrieval", "false".into()),
        ])
    }

    pub(super) fn report(&self) -> String {
        object(&[
            ("source", string("recorder_replay")),
            ("request_identity", string(&self.request.digest().to_text())),
            ("requested_range", string(&self.request.window().to_string())),
            ("acknowledgement", self.acknowledgement_json()),
            ("durable_windows", self.durable_windows.to_string()),
            (
                "receipt_state",
                string(if self.unsettled {
                    "indeterminate"
                } else if self.receipt.is_some() {
                    "durable"
                } else if self.receipt_failed {
                    "publication_refused"
                } else {
                    "not_published"
                }),
            ),
            (
                "receipt",
                self.receipt.as_ref().map_or_else(
                    || "null".into(),
                    |(slot, root)| {
                        object(&[("slot", string(slot)), ("root", string(&root.to_text()))])
                    },
                ),
            ),
            ("historical_frame_time", string("unknown")),
            ("complete_interval_retrieval", "false".into()),
            ("upstream_retention_known", "false".into()),
            ("automatic_live_fallback", "false".into()),
        ])
    }

    pub(super) fn publish(
        &mut self,
        options: &Options,
        publisher: &mut LocalRootPublisher,
        owner: &Owner<'_, '_>,
        capture_result: &Result<(), Failure>,
        publication_complete: bool,
    ) -> Result<Option<String>, Failure> {
        let Some(acceptance) = self.acceptance else {
            return if capture_result.is_ok() {
                Err(Failure::ReplayAcknowledgement)
            } else {
                Ok(None)
            };
        };
        let result = (|| {
            owner.begin_drain()?;
            owner.storage_check()?;
            // Supervised single capture admits the complete outer approval before
            // delegating its nested capture digest. Retain the caller's exact
            // approval, including the watchdog policy, in the durable companion.
            let approval = match owner.supervision {
                Some(supervision) => supervision.approval(),
                None => options.digest().map_err(|_| Failure::Configuration)?,
            };
            let receipt = ReplayReceipt::prepare(
                self.request.clone(),
                options.catalog_scope().clone(),
                approval,
                acceptance,
                std::mem::take(&mut self.windows),
                termination(capture_result),
                publication_complete,
            )
            .map_err(|_| Failure::State)?;
            let slot = replay_slot(receipt.scope(), receipt.request().digest())
                .map_err(|_| Failure::State)?;
            self.unsettled = true;
            let published = match publish_replay_receipt(&receipt, publisher, owner) {
                Ok(published) => published,
                Err(_) => {
                    self.unsettled = publisher.is_poisoned() || publisher.root(&slot).is_some();
                    return Err(Failure::Storage);
                }
            };
            if published.claims.local != LocalPublicationState::Durable {
                return Err(Failure::Storage);
            }
            self.receipt = Some((published.slot.as_str().to_owned(), published.root));
            self.unsettled = false;
            owner.storage_check()?;
            Ok(Some(object(&[
                ("slot", string(published.slot.as_str())),
                ("root", string(&published.root.to_text())),
                ("request_identity", string(&self.request.digest().to_text())),
                ("requested_range", string(&acceptance.requested().to_string())),
                ("acknowledged_range", string(&acceptance.acknowledged().to_string())),
                ("play_cseq", acceptance.cseq().to_string()),
                ("windows", self.durable_windows.to_string()),
                ("publication_complete", publication_complete.to_string()),
                ("historical_frame_time", string("unknown")),
                ("complete_interval_retrieval", "false".into()),
                ("durable", "true".into()),
            ])))
        })();
        self.receipt_failed = result.is_err();
        result
    }
}

fn termination(result: &Result<(), Failure>) -> ReplayTermination {
    match result {
        Ok(()) => ReplayTermination::RequestedStop,
        Err(Failure::Shortfall) => ReplayTermination::InputEnded,
        Err(Failure::ProgressStalled) => ReplayTermination::ProgressStalled,
        Err(Failure::Deadline) => ReplayTermination::Deadline,
        Err(Failure::WorkBudget) => ReplayTermination::Budget,
        Err(Failure::Authority | Failure::Approval) => ReplayTermination::Authority,
        Err(Failure::Storage | Failure::Root) => ReplayTermination::Storage,
        Err(Failure::Output) => ReplayTermination::Output,
        Err(Failure::Protocol | Failure::ReplayAcknowledgement | Failure::ReplayRejected(_)) => {
            ReplayTermination::ProtocolFailure
        }
        Err(_) => ReplayTermination::SourceFailure,
    }
}
