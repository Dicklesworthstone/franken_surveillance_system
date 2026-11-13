#![forbid(unsafe_code)]
//! Retained generation admission for a managed audio/video provisioning session.
//! This is not a restart supervisor or proof of custody independence.

use super::{recording_provision as provision, recording_rollover as session};

fn supplies_required(step: &provision::Step) -> bool {
    matches!(
        step,
        provision::Step::Managed(session::ManagedStep::SuppliesRequired { .. })
    )
}

include!("retained_provision_shared.rs");

/// Refusal to bind a selected A/V stream preserves its original owners.
#[must_use = "retain or reconcile all returned recording and bootstrap owners"]
pub enum SelectedRefusal<'scope, 'task, IO> {
    /// The bootstrap was not unstarted; selection was not attempted.
    Bootstrap {
        /// Original selected stream and its storage.
        selected: super::recording_session::SelectedRecording<'scope, 'task, IO>,
        /// Original audio allowance.
        audio: super::recording_session::AudioAllowancePolicy,
        /// Original bootstrap owner.
        bootstrap: super::av_rollover_generation::BootstrapWorker,
    },
    /// Recording selection refused without consuming the bootstrap.
    Recording {
        /// The exact selection refusal and returned recording owners.
        recording: super::recording_session::SelectedRefusal<'scope, 'task, IO>,
        /// Original audio allowance.
        audio: super::recording_session::AudioAllowancePolicy,
        /// Original bootstrap owner.
        bootstrap: super::av_rollover_generation::BootstrapWorker,
    },
    /// The managed session was constructed, but bootstrap binding refused.
    Managed {
        /// Managed session with the selected recording and audio allowance.
        managed: session::ManagedSession<'scope, 'task, IO>,
        /// Original bootstrap owner.
        bootstrap: super::av_rollover_generation::BootstrapWorker,
    },
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> RetainedSession<'scope, 'task, IO> {
    /// Bind a selected A/V stream to retained generation provisioning without
    /// I/O. Every refusal returns the selected or managed owner and bootstrap.
    pub fn begin_selected(
        selected: super::recording_session::SelectedRecording<'scope, 'task, IO>,
        audio: super::recording_session::AudioAllowancePolicy,
        bootstrap: super::av_rollover_generation::BootstrapWorker,
    ) -> Result<Self, SelectedRefusal<'scope, 'task, IO>> {
        if !bootstrap.is_unstarted() {
            return Err(SelectedRefusal::Bootstrap {
                selected,
                audio,
                bootstrap,
            });
        }
        let recording = match super::recording_session::Session::begin_selected(selected) {
            Ok(recording) => recording,
            Err(recording) => {
                return Err(SelectedRefusal::Recording {
                    recording,
                    audio,
                    bootstrap,
                });
            }
        };
        let managed = session::ManagedSession::new(recording, audio);
        Self::with_bootstrap(managed, bootstrap)
            .map_err(|(managed, bootstrap)| SelectedRefusal::Managed { managed, bootstrap })
    }
}
