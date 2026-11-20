#![forbid(unsafe_code)]
//! A stopped HTTP A/V recording's tail-to-successor transition.
//!
//! The owner publishes each retained original source range before admitting a
//! successor and keeps both archive generations and the original effect in
//! caller custody. The caller drives bounded steps and retains each returned
//! publication receipt. This is not a background service, device identity
//! proof, camera-setting retry, capture-continuity claim, or retention policy.

use std::{future::Future, time::Duration};

use asupersync::{Cx, time::timeout_at};
use fss_container::flv_avc::SourceKey;
use fss_core::ContentDigest;
use fss_packet::extended_flv::{
    self,
    stream::{Framer, SearchMode},
};
use fss_runtime::execution::TaskCx;

use super::{
    media_av_archive as archive, media_av_bootstrap as bootstrap, media_av_startup as startup,
    media_reaccept,
};
use crate::unifi_direct::{
    av_owned_sink, av_recovered_startup,
    av_unknown_worker_guard::BootstrapResources,
    av_worker, listener, media_reconnect,
    metered::MeteredClock,
    recording, recording_storage, retirement_source,
    source_coordinator::{ArchiveAdmission, Coordinator},
    source_worker,
};

/// Old A/V and clock owners retained separately from its archived source tail.
#[must_use = "retain and reconcile the predecessor archive"]
pub struct Previous {
    /// Original A/V archive worker.
    pub av: av_worker::UnknownTimeWorker,
    /// The caller-selected sender-clock hypothesis, not physical time.
    pub origin: crate::unifi_direct::av_recording::SenderClockOrigin,
    /// Original connection and generation claim.
    pub key: SourceKey,
    /// Original caller-supplied camera claim.
    pub camera_claim: ContentDigest,
}

/// A failed setup retains all owners at the exact refusal point.
#[must_use = "retain and reconcile all returned owners"]
pub enum BeginRefusal<'scope, 'task, 'policy> {
    /// Recording is not stopped and drained, or its old archive is unsettled.
    NotReady {
        /// Original recording owners.
        parts: archive::Parts,
        /// Original listener.
        listener: listener::Listener<'scope, 'task, 'policy>,
    },
    /// Media reaccept refused while preserving the camera effect and source.
    Bridge {
        /// Original media refusal and its owners.
        refusal: media_reaccept::CreateRefusal<'scope, 'task, 'policy>,
        /// Original source worker.
        source: source_worker::Worker,
        /// Original A/V archive owners.
        previous: Previous,
    },
    /// Retired source ranges could not be planned.
    TailPlan {
        /// Listener and original camera effect.
        bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
        /// Original source worker.
        source: source_worker::Worker,
        /// Original A/V archive owners.
        previous: Previous,
        /// Unchanged retired source and refusal reason.
        refusal: retirement_source::Refusal,
    },
    /// Tail plan could not be attached to the original source worker.
    TailDriver {
        /// Listener and original camera effect.
        bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
        /// Exact source worker and checked tail plan.
        parts: retirement_source::DriverParts,
        /// Original A/V archive owners.
        previous: Previous,
    },
    /// An internal ownership invariant failed before the tail was extracted.
    TailMissing {
        /// Listener, effect and any retained tail.
        bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
        /// Original source worker.
        source: source_worker::Worker,
        /// Original A/V archive owners.
        previous: Previous,
    },
}

/// Refusal before a new accept wait starts; inputs remain caller-owned.
#[must_use]
pub enum AcceptRefusal {
    /// Old-tail publication has not completed successfully.
    TailNotPublished(media_reconnect::Inputs),
    /// The bounded listener refused its admission.
    Bridge(media_reconnect::Refusal),
}

/// Explicit source and network bounds for one automatically prepared accept.
#[derive(Clone, Copy, Debug)]
pub struct SuccessorConfig {
    /// FLV candidate bounds.
    pub flv: extended_flv::Limits,
    /// Maximum buffered FLV bytes.
    pub max_buffer: usize,
    /// Explicit candidate-selection policy for this camera profile.
    pub search: SearchMode,
    /// Per-connection source and MP4 bounds.
    pub recorder: recording::Limits,
    /// Select the in-band AVC sample entry when explicitly required.
    pub inband: bool,
    /// Optional claimed dimensions that the recorder must enforce.
    pub expected_dimensions: Option<[u32; 2]>,
    /// Maximum bytes read in a single source step.
    pub chunk_bytes: usize,
    /// Maximum bytes received from this connection.
    pub max_bytes: u64,
    /// Finite listener wait.
    pub wait: Duration,
}

/// Why automatic successor preparation or admission stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutoError {
    /// Invalid source bounds or a recorder configuration was refused.
    Configuration,
    /// Connection or generation identity could not be advanced.
    KeyExhausted,
    /// The bounded listener refused or timed out.
    Admission(media_reconnect::Error),
}

/// One bounded automatic decision; every tail completion remains caller-owned.
#[must_use]
pub enum AutoStep {
    /// One old-source archival decision, including any publication receipt.
    Tail(retirement_source::DriverStep),
    /// One successor socket was accepted under the stated source claim.
    Accepted(SourceKey),
    /// A previously accepted successor is ready for bootstrap.
    Ready(SourceKey),
    /// A dropped accept wait needs explicit acknowledgment before retry.
    Interrupted,
    /// Old-source publication requires reconciliation.
    TailFenced,
    /// Preparation or the bounded accept stopped with this classification.
    Refused(AutoError),
}

/// A finite, caller-driven transition; no task escapes this owner.
#[must_use = "retain or recover the effect, old archives and source tail"]
pub struct Transition<'scope, 'task, 'policy> {
    bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
    tail: retirement_source::Driver,
    previous: Previous,
    tail_finished: bool,
    tail_fenced: bool,
}

struct PreparedReuse<'scope, 'task, 'policy> {
    bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
    tail: retirement_source::DriverParts,
    av: Box<av_worker::UnknownTimeRetirement>,
    origin: crate::unifi_direct::av_recording::SenderClockOrigin,
    key: SourceKey,
    camera_claim: ContentDigest,
}

struct PreparedReuseSource<'scope, 'task, 'policy> {
    bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
    tail: retirement_source::DriverParts,
    previous: Previous,
}

/// Immediate reuse or a bounded verification of existing rollover history.
#[must_use = "drive verification or retain all returned owners"]
pub enum BeginReuse<'scope, 'task, 'policy> {
    /// No rollover history needed verification.
    Ready(Box<ReusedReady<'scope, 'task, 'policy>>),
    /// Rollover custody must be checked on the blocking worker.
    Verify(Box<ReuseVerification<'scope, 'task, 'policy>>),
}

/// One custody-verification decision. A completion remains caller-owned.
#[must_use]
pub enum VerifyStep {
    /// Task, clock or wait bounds did not match; no work was started.
    Configuration,
    /// The blocking custody check was admitted.
    Started,
    /// Admission was refused; the original worker remains owned.
    StartRefused(av_recovered_startup::StartError),
    /// The exact worker is still running after the bounded wait.
    Running,
    /// The exact drained verification result.
    Completed(av_recovered_startup::Completion),
    /// A verified check is ready to transfer.
    Ready,
    /// A refusal, cancellation or uncertain result requires reconciliation.
    Stopped,
}

/// Owns all previous-generation resources while rollover history is checked.
#[must_use = "join or retain the verification and all original owners"]
pub struct ReuseVerification<'scope, 'task, 'policy> {
    bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
    tail: retirement_source::DriverParts,
    sink: av_owned_sink::UnknownTimeOwnedSink,
    origin: crate::unifi_direct::av_recording::SenderClockOrigin,
    key: SourceKey,
    camera_claim: ContentDigest,
    worker: av_recovered_startup::Worker,
    started: bool,
    start_refused: bool,
    verified: bool,
    stopped: bool,
}

/// An unfinished verification retains its exact source, effect and worker.
#[must_use = "retain or reconcile the verification owner"]
pub enum VerifyFinishRefusal<'scope, 'task, 'policy> {
    /// The check is not successfully drained or its worker remains busy.
    NotReady(Box<ReuseVerification<'scope, 'task, 'policy>>),
    /// Verified resources could not be attached; the exact refusal owns them.
    Reuse(Box<ReuseRefusal<'scope, 'task, 'policy>>),
}

/// Complete recoverable verification state, including any active worker.
#[must_use = "drain the worker and reconcile each returned owner"]
pub struct VerificationParts<'scope, 'task, 'policy> {
    /// Original listener, camera effect and accepted successor.
    pub bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
    /// Old source archive worker and completed tail plan.
    pub tail: retirement_source::DriverParts,
    /// Old connection's finished muxer.
    pub sink: av_owned_sink::UnknownTimeOwnedSink,
    /// Caller-supplied sender-clock hypothesis.
    pub origin: crate::unifi_direct::av_recording::SenderClockOrigin,
    /// Caller-supplied previous source claim.
    pub key: SourceKey,
    /// Caller-supplied camera claim, not physical identity.
    pub camera_claim: ContentDigest,
    /// Exact custody verification worker, possibly still running.
    pub worker: av_recovered_startup::Worker,
    /// Whether the worker was admitted and has not yet been joined.
    pub started: bool,
    /// Whether worker admission was refused.
    pub start_refused: bool,
    /// Whether successful verification was observed.
    pub verified: bool,
    /// Whether a failed or uncertain outcome stopped this owner.
    pub stopped: bool,
}

fn retirement_from_resources(
    sink: av_owned_sink::UnknownTimeOwnedSink,
    resources: Box<BootstrapResources>,
    fenced: bool,
) -> Box<av_worker::UnknownTimeRetirement> {
    let BootstrapResources {
        deployment,
        journal,
        keeper,
        replay,
        authority,
        limits,
        work_limit,
        rollover_custody,
    } = *resources;
    Box::new(av_worker::UnknownTimeRetirement {
        parts: av_worker::UnknownTimeParts {
            sink,
            deployment,
            journal,
            keeper,
            replay,
            authority,
            limits,
            work_limit,
        },
        fenced,
        rollover_custody,
    })
}

impl<'scope, 'task, 'policy> ReuseVerification<'scope, 'task, 'policy> {
    /// Recover all owners, including an active blocking attempt.
    pub fn into_parts(self: Box<Self>) -> VerificationParts<'scope, 'task, 'policy> {
        let Self {
            bridge,
            tail,
            sink,
            origin,
            key,
            camera_claim,
            worker,
            started,
            start_refused,
            verified,
            stopped,
        } = *self;
        VerificationParts {
            bridge,
            tail,
            sink,
            origin,
            key,
            camera_claim,
            worker,
            started,
            start_refused,
            verified,
            stopped,
        }
    }

    /// Explicitly permit a new admission after a definite start refusal.
    pub fn authorize_start_retry(&mut self) -> bool {
        if self.start_refused && !self.started && !self.stopped && !self.verified {
            self.start_refused = false;
            true
        } else {
            false
        }
    }

    /// Request cancellation; the running worker must still be joined.
    pub fn abort(&self) {
        self.worker.abort();
    }

    /// Start or join exactly one verification without blocking the async task.
    pub async fn step<'s, 't>(
        &mut self,
        task: &'s TaskCx<'t>,
        cx: &'s Cx,
        clock: MeteredClock<'s, 't>,
        wait: Duration,
        admission: ArchiveAdmission<'_>,
    ) -> VerifyStep {
        if wait.is_zero()
            || wait > Duration::from_secs(30)
            || !self.bridge.matches_context(task, cx, clock)
        {
            return VerifyStep::Configuration;
        }
        if self.stopped || self.start_refused {
            return VerifyStep::Stopped;
        }
        if self.verified {
            return VerifyStep::Ready;
        }
        if !self.started {
            return match self
                .worker
                .start(task, cx, clock, admission.resource, admission.cost)
            {
                Ok(()) => {
                    self.started = true;
                    VerifyStep::Started
                }
                Err(error) => {
                    self.start_refused = true;
                    VerifyStep::StartRefused(error)
                }
            };
        }
        match timeout_at(cx.now() + wait, self.worker.join()).await {
            Err(_) => VerifyStep::Running,
            Ok(None) => {
                self.stopped = true;
                VerifyStep::Stopped
            }
            Ok(Some(done)) => {
                self.started = false;
                self.verified = done.runtime.is_ok()
                    && matches!(&done.outcome, av_recovered_startup::Outcome::Verified);
                self.stopped = !self.verified;
                VerifyStep::Completed(done)
            }
        }
    }

    /// Transfer only an observed, drained verification to successor bootstrap.
    #[inline(never)]
    pub fn finish(
        self: Box<Self>,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
        supplied_unverified_audio: Option<[u8; 2]>,
    ) -> Result<
        Box<ReusedReady<'scope, 'task, 'policy>>,
        Box<VerifyFinishRefusal<'scope, 'task, 'policy>>,
    > {
        if !self.verified || self.started || self.stopped || self.start_refused {
            return Err(Box::new(VerifyFinishRefusal::NotReady(self)));
        }
        let Self {
            bridge,
            tail,
            sink,
            origin,
            key,
            camera_claim,
            worker,
            started,
            start_refused,
            verified,
            stopped,
        } = *self;
        let retirement = match worker.retire() {
            Ok(retirement) => retirement,
            Err(worker) => {
                return Err(Box::new(VerifyFinishRefusal::NotReady(Box::new(Self {
                    bridge,
                    tail,
                    sink,
                    origin,
                    key,
                    camera_claim,
                    worker,
                    started,
                    start_refused,
                    verified,
                    stopped,
                }))));
            }
        };
        let av = retirement_from_resources(sink, retirement.resources, retirement.fenced);
        if av.fenced
            || av.rollover_custody.as_ref().is_none_or(|custody| {
                !custody.startup_verified(&av.parts.journal, &av.parts.keeper)
            })
        {
            return Err(Box::new(VerifyFinishRefusal::Reuse(Box::new(
                ReuseRefusal::AvUnsettled {
                    bridge,
                    tail,
                    av,
                    origin,
                    key,
                    camera_claim,
                },
            ))));
        }
        Transition::attach_reused(
            Box::new(PreparedReuse {
                bridge,
                tail,
                av,
                origin,
                key,
                camera_claim,
            }),
            retention,
            policy,
            supplied_unverified_audio,
        )
        .map_err(|refusal| Box::new(VerifyFinishRefusal::Reuse(refusal)))
    }
}

/// All owners needed to inspect or resume a stopped transition.
#[must_use = "retain the bridge, tail and predecessor archive"]
pub struct Parts<'scope, 'task, 'policy> {
    /// Listener, effect and any accepted successor.
    pub bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
    /// Old source archive worker and remaining plan.
    pub tail: retirement_source::Driver,
    /// Old A/V archive owners.
    pub previous: Previous,
    /// The source driver reported no remaining held source or active work.
    pub tail_finished: bool,
    /// A publication or task outcome requires reconciliation.
    pub tail_fenced: bool,
}

/// Completed transition. Publication receipts returned during tail driving
/// remain caller-owned, and neither this value nor a new bootstrap proves
/// that the successor is the original physical camera.
#[must_use = "retain both generations and reconcile the effect"]
pub struct Ready<'scope, 'task, 'policy> {
    /// Successor source ready for A/V bootstrap.
    pub bootstrap: bootstrap::Driver,
    /// Listener for subsequent explicitly supervised connections.
    pub listener: listener::Listener<'scope, 'task, 'policy>,
    /// Old source worker, terminal facts and any pending audio observation.
    pub tail: retirement_source::Driver,
    /// Old A/V archive worker and source identity.
    pub previous: Previous,
    /// Any source tails not already transferred to the tail driver.
    pub retired: std::collections::VecDeque<media_reconnect::Retired>,
    /// Number of reserved successor accept attempts.
    pub attempts: usize,
    /// Original finite accept-attempt limit.
    pub max_attempts: usize,
    /// Most recently reserved source claim.
    pub last: Option<SourceKey>,
}

/// A successor connected to its own source and A/V archive resources.
#[must_use = "retain both archive generations and reconcile the effect"]
pub struct RecordingReady<'scope, 'task, 'policy> {
    /// Successor bootstrap and exclusive source and A/V archive owners.
    pub startup: startup::Driver,
    /// Listener for subsequent explicitly supervised connections.
    pub listener: listener::Listener<'scope, 'task, 'policy>,
    /// Previous source worker and terminal observations.
    pub tail: retirement_source::Driver,
    /// Previous A/V archive owners.
    pub previous: Previous,
    /// Any original tails not transferred to the tail driver.
    pub retired: std::collections::VecDeque<media_reconnect::Retired>,
    /// Number of reserved successor accept attempts.
    pub attempts: usize,
    /// Original finite accept-attempt limit.
    pub max_attempts: usize,
    /// Most recently reserved source claim.
    pub last: Option<SourceKey>,
}

/// The old source and muxer retained when existing archives are reused.
#[must_use = "retain the previous source observations and muxer state"]
pub struct ReusedPrevious {
    /// Previous source key and sender-clock claim.
    pub key: SourceKey,
    /// Previous sender-clock hypothesis, not a physical capture time.
    pub origin: crate::unifi_direct::av_recording::SenderClockOrigin,
    /// Previous camera claim, not independent authentication.
    pub camera_claim: ContentDigest,
    /// Old source's terminal facts and any pending audio observation.
    pub source_plan: retirement_source::Plan,
    /// Old connection's finished muxer and original configuration.
    pub sink: av_owned_sink::UnknownTimeOwnedSink,
}

/// New recording startup and retained old connection after archive reuse.
#[must_use = "retain both source generations and reconcile the camera effect"]
pub struct ReusedReady<'scope, 'task, 'policy> {
    /// Successor source and the existing source/A/V archive owners.
    pub startup: startup::Driver,
    /// Retained listener.
    pub listener: listener::Listener<'scope, 'task, 'policy>,
    /// Old source and muxer not transferred to the new recorder.
    pub previous: ReusedPrevious,
    /// Any untransferred original tails.
    pub retired: std::collections::VecDeque<media_reconnect::Retired>,
    /// Accept attempts reserved during this transition.
    pub attempts: usize,
    /// Original finite attempt limit.
    pub max_attempts: usize,
    /// Most recently reserved source claim.
    pub last: Option<SourceKey>,
}

/// A failed archive-reuse handoff retains all owners and uncertainty.
#[must_use = "retain the effect, source and archive owners"]
pub enum ReuseRefusal<'scope, 'task, 'policy> {
    /// The old tail or new connection has not completed its transition.
    NotReady(Box<Transition<'scope, 'task, 'policy>>),
    /// Tail worker is still running; its exact owner remains intact.
    TailBusy {
        /// The retained effect and listener.
        bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
        /// Old source worker and plan.
        tail: retirement_source::Driver,
        /// Old A/V owner and source claims.
        previous: Previous,
    },
    /// Source archive is not idle, settled, or bound to the requested retention.
    SourceUnsettled {
        /// The retained effect and listener.
        bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
        /// Old source worker and plan.
        tail: retirement_source::DriverParts,
        /// Old A/V owner and source claims.
        previous: Previous,
    },
    /// Old A/V worker could not be retired without losing ownership.
    AvBusy {
        /// The retained effect and listener.
        bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
        /// Old source worker and plan.
        tail: retirement_source::DriverParts,
        /// Old A/V owner and source claims.
        previous: Previous,
    },
    /// A/V publication or rollover custody requires reconciliation.
    AvUnsettled {
        /// The retained effect and listener.
        bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
        /// Old source worker and plan.
        tail: retirement_source::DriverParts,
        /// Retired A/V worker, including its exact custody.
        av: Box<av_worker::UnknownTimeRetirement>,
        /// Old sender-clock hypothesis.
        origin: crate::unifi_direct::av_recording::SenderClockOrigin,
        /// Old source claim.
        key: SourceKey,
        /// Old camera claim.
        camera_claim: ContentDigest,
    },
    /// The accepted connection could not be transferred after retirement.
    Bridge {
        /// Original effect, listener and candidate connection.
        bridge: media_reaccept::Reaccept<'scope, 'task, 'policy>,
        /// Old source worker and plan.
        tail: retirement_source::DriverParts,
        /// Retired old A/V worker and custody.
        av: Box<av_worker::UnknownTimeRetirement>,
        /// Old sender-clock hypothesis.
        origin: crate::unifi_direct::av_recording::SenderClockOrigin,
        /// Old source claim.
        key: SourceKey,
        /// Old camera claim.
        camera_claim: ContentDigest,
    },
    /// Fresh bootstrap rejected the source or reused archive bindings.
    Attach {
        /// Original connected source, effect and reused archive owners.
        refusal: Box<startup::AttachRefusal>,
        /// Original listener.
        listener: listener::Listener<'scope, 'task, 'policy>,
        /// Preserved old source and muxer.
        previous: ReusedPrevious,
        /// Untransferred source tails.
        retired: std::collections::VecDeque<media_reconnect::Retired>,
        /// Attempts reserved before attachment.
        attempts: usize,
        /// Original finite attempt limit.
        max_attempts: usize,
        /// Most recently reserved source claim.
        last: Option<SourceKey>,
    },
}

/// A failed successor archive attachment preserves every original owner.
#[must_use = "retain the recording, storage, listener and effect owners"]
pub enum FinishRecordingRefusal<'scope, 'task, 'policy> {
    /// A successor is not yet accepted or the old tail is not published.
    NotReady {
        /// Unchanged transition and its original owners.
        transition: Transition<'scope, 'task, 'policy>,
        /// Original, unattached successor archive resources.
        storage: recording_storage::Created,
    },
    /// Successor bootstrap rejected the connected source or archive binding.
    Attach {
        /// Refused source, effect, storage and original policy.
        refusal: Box<startup::AttachRefusal>,
        /// Original listener.
        listener: listener::Listener<'scope, 'task, 'policy>,
        /// Original source-tail owner.
        tail: retirement_source::Driver,
        /// Original A/V archive owner.
        previous: Previous,
        /// Any untransferred source tails.
        retired: std::collections::VecDeque<media_reconnect::Retired>,
        /// Number of reserved attempts.
        attempts: usize,
        /// Original finite accept-attempt limit.
        max_attempts: usize,
        /// Most recently reserved source claim.
        last: Option<SourceKey>,
    },
}

/// A failed final handoff retains every original owner.
#[must_use = "retain all returned owners"]
pub enum FinishRefusal<'scope, 'task, 'policy> {
    /// Tail is not confirmed or a successor has not been accepted.
    NotReady(Transition<'scope, 'task, 'policy>),
    /// Successor A/V attachment refused without losing the connection.
    Attach {
        /// The refused new connection and any supplied audio claim.
        refusal: bootstrap::AttachRefusal,
        /// Retained listener.
        listener: listener::Listener<'scope, 'task, 'policy>,
        /// Old archived source and terminal observations.
        tail: retirement_source::Driver,
        /// Old A/V archive owners.
        previous: Previous,
        /// Untransferred tails, if any.
        retired: std::collections::VecDeque<media_reconnect::Retired>,
        /// Number of reserved attempts.
        attempts: usize,
        /// Original finite accept-attempt limit.
        max_attempts: usize,
        /// Most recently reserved source claim.
        last: Option<SourceKey>,
    },
}

impl<'scope, 'task, 'policy> Transition<'scope, 'task, 'policy> {
    /// Join the stopped recording, its listener and its exact source tail.
    /// Pending A/V output or an unsealed prefix must be resolved first.
    pub fn new(
        parts: archive::Parts,
        listener: listener::Listener<'scope, 'task, 'policy>,
        max_attempts: usize,
    ) -> Result<Self, BeginRefusal<'scope, 'task, 'policy>> {
        if !parts.halted
            || !parts.prefix_sealed
            || parts.source_armed
            || parts.source.status() != source_worker::Status::Idle
            || !parts.source.ready_for_start()
            || parts.av_state != archive::ArchiveState::Idle
            || !parts.av.is_idle()
            || parts.first_segment.is_some()
            || parts.rollover_need.is_some()
            || parts.connected.pipeline.source_key() != parts.key
            || parts.connected.camera_claim() != parts.camera_claim
        {
            return Err(BeginRefusal::NotReady { parts, listener });
        }
        let archive::Parts {
            connected,
            source,
            av,
            origin,
            key,
            camera_claim,
            ..
        } = parts;
        let previous = Previous {
            av,
            origin,
            key,
            camera_claim,
        };
        let mut bridge = match media_reaccept::Reaccept::new(listener, connected, max_attempts, 1) {
            Ok(bridge) => bridge,
            Err(refusal) => {
                return Err(BeginRefusal::Bridge {
                    refusal,
                    source,
                    previous,
                });
            }
        };
        let retired = match bridge.take_retired() {
            Some(retired) => retired,
            None => {
                return Err(BeginRefusal::TailMissing {
                    bridge,
                    source,
                    previous,
                });
            }
        };
        let plan = match retirement_source::Plan::new(retired.pipeline) {
            Ok(plan) => plan,
            Err(refusal) => {
                return Err(BeginRefusal::TailPlan {
                    bridge,
                    source,
                    previous,
                    refusal,
                });
            }
        };
        let tail = match retirement_source::Driver::begin(source, plan, key, camera_claim) {
            Ok(tail) => tail,
            Err(parts) => {
                return Err(BeginRefusal::TailDriver {
                    bridge,
                    parts,
                    previous,
                });
            }
        };
        Ok(Self {
            bridge,
            tail,
            previous,
            tail_finished: false,
            tail_fenced: false,
        })
    }

    /// Inspect the exact unarchived ranges and terminal observations.
    pub fn tail_plan(&self) -> &retirement_source::Plan {
        self.tail.plan()
    }

    /// Enable bounded batching before publication starts.
    pub fn enable_batching(&mut self, max_records: usize, max_bytes: usize) -> bool {
        !self.tail_finished
            && !self.tail_fenced
            && self.tail.enable_batching(max_records, max_bytes)
    }

    /// Drive one old-source publication step. The caller must retain returned
    /// completions and receipts. Failed or indeterminate results fence reaccept.
    pub async fn step_tail<'s, 't>(
        &mut self,
        task: &'s TaskCx<'t>,
        cx: &'s Cx,
        clock: MeteredClock<'s, 't>,
        admission: ArchiveAdmission<'_>,
    ) -> retirement_source::DriverStep {
        if !self.bridge.matches_context(task, cx, clock) {
            return retirement_source::DriverStep::StartRefused(av_worker::StartError::Context);
        }
        if self.tail_fenced || self.tail_finished {
            return retirement_source::DriverStep::Halted;
        }
        let step = self.tail.step(task, cx, clock, admission).await;
        match &step {
            retirement_source::DriverStep::Finished => self.tail_finished = true,
            retirement_source::DriverStep::Completed(done) => {
                if done.runtime.is_err()
                    || !matches!(
                        done.outcome,
                        source_worker::Outcome::Publication(
                            source_worker::Publication::Published { .. }
                        )
                    )
                {
                    self.tail_fenced = true;
                }
            }
            retirement_source::DriverStep::OfferRefused
            | retirement_source::DriverStep::StartRefused(_)
            | retirement_source::DriverStep::RetryRequired
            | retirement_source::DriverStep::Unavailable
            | retirement_source::DriverStep::Halted => self.tail_fenced = true,
            _ => (),
        }
        step
    }

    /// Reserve a successor accept only after the old tail has been published.
    pub fn accept_next(
        &mut self,
        inputs: media_reconnect::Inputs,
        chunk_bytes: usize,
        max_bytes: u64,
        wait: Duration,
    ) -> Result<impl Future<Output = Result<(), media_reconnect::Error>> + '_, AcceptRefusal> {
        if !self.tail_finished || self.tail_fenced {
            return Err(AcceptRefusal::TailNotPublished(inputs));
        }
        self.bridge
            .accept_next(inputs, chunk_bytes, max_bytes, wait)
            .map_err(AcceptRefusal::Bridge)
    }

    /// Acknowledge a cancelled accept without making any remote-outcome claim.
    pub fn acknowledge_interrupted(&mut self) -> Option<SourceKey> {
        self.bridge.acknowledge_interrupted()
    }

    /// Drive the next tail-publication or successor-accept decision. Each
    /// attempted connection gets a fresh monotonically advanced source key.
    /// Timeouts and denied peers are surfaced; the caller decides whether to
    /// poll again within the original finite attempt budget. Dropping a wait
    /// fences it until explicitly acknowledged. This performs no camera write.
    pub async fn step_auto<'s, 't>(
        &mut self,
        task: &'s TaskCx<'t>,
        cx: &'s Cx,
        clock: MeteredClock<'s, 't>,
        admission: ArchiveAdmission<'_>,
        config: SuccessorConfig,
    ) -> AutoStep {
        if !self.bridge.matches_context(task, cx, clock) {
            return AutoStep::Refused(AutoError::Configuration);
        }
        if self.tail_fenced {
            return AutoStep::TailFenced;
        }
        if !self.tail_finished {
            return AutoStep::Tail(self.step_tail(task, cx, clock, admission).await);
        }
        if self.bridge.interrupted() {
            return AutoStep::Interrupted;
        }
        let Some(last) = self.bridge.last_reserved() else {
            return AutoStep::Refused(AutoError::KeyExhausted);
        };
        if self.bridge.has_active() {
            return AutoStep::Ready(last);
        }
        let (Some(connection), Some(generation)) = (
            last.connection.checked_add(1),
            last.generation.checked_add(1),
        ) else {
            return AutoStep::Refused(AutoError::KeyExhausted);
        };
        let key = SourceKey {
            connection,
            generation,
        };
        let framer = match Framer::with_mode(config.flv, config.max_buffer, config.search) {
            Ok(framer) => framer,
            Err(_) => return AutoStep::Refused(AutoError::Configuration),
        };
        let recorder = if config.inband {
            recording::Recorder::new_inband(key, config.recorder)
        } else {
            recording::Recorder::new(key, config.recorder)
        };
        let mut recorder = match recorder {
            Ok(recorder) => recorder,
            Err(_) => return AutoStep::Refused(AutoError::Configuration),
        };
        if config
            .expected_dimensions
            .is_some_and(|expected| recorder.require_dimensions(expected).is_err())
        {
            return AutoStep::Refused(AutoError::Configuration);
        }
        let wait = match self.bridge.accept_next(
            media_reconnect::Inputs { framer, recorder },
            config.chunk_bytes,
            config.max_bytes,
            config.wait,
        ) {
            Ok(wait) => wait,
            Err(refusal) => return AutoStep::Refused(AutoError::Admission(refusal.reason)),
        };
        match wait.await {
            Ok(()) => AutoStep::Accepted(key),
            Err(reason) => AutoStep::Refused(AutoError::Admission(reason)),
        }
    }

    /// Recover all owners, including any active tail publication.
    pub fn into_parts(self) -> Parts<'scope, 'task, 'policy> {
        Parts {
            bridge: self.bridge,
            tail: self.tail,
            previous: self.previous,
            tail_finished: self.tail_finished,
            tail_fenced: self.tail_fenced,
        }
    }

    /// Reuse settled source and A/V archives for a successor without creating
    /// new storage. Local custody checks do not prove independent durability.
    /// Active rollover custody is returned for separate reconciliation.
    pub fn finish_reusing(
        self: Box<Self>,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
        supplied_unverified_audio: Option<[u8; 2]>,
    ) -> Result<Box<ReusedReady<'scope, 'task, 'policy>>, Box<ReuseRefusal<'scope, 'task, 'policy>>>
    {
        let source = self.prepare_reuse_source(retention)?;
        let prepared = Self::retire_reuse_av(source, retention, false)?;
        Self::attach_reused(prepared, retention, policy, supplied_unverified_audio)
    }

    /// Prepare reuse, requiring a drained blocking verification when rollover
    /// custody exists. No new storage or camera write is performed here.
    #[inline(never)]
    pub fn begin_reusing(
        self: Box<Self>,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
        supplied_unverified_audio: Option<[u8; 2]>,
    ) -> Result<BeginReuse<'scope, 'task, 'policy>, Box<ReuseRefusal<'scope, 'task, 'policy>>> {
        let source = self.prepare_reuse_source(retention)?;
        let prepared = Self::retire_reuse_av(source, retention, true)?;
        if prepared.av.rollover_custody.is_none() {
            return Self::attach_reused(prepared, retention, policy, supplied_unverified_audio)
                .map(BeginReuse::Ready);
        }
        Self::prepare_custody_verification(prepared).map(BeginReuse::Verify)
    }

    #[inline(never)]
    fn prepare_custody_verification(
        prepared: Box<PreparedReuse<'scope, 'task, 'policy>>,
    ) -> Result<
        Box<ReuseVerification<'scope, 'task, 'policy>>,
        Box<ReuseRefusal<'scope, 'task, 'policy>>,
    > {
        let PreparedReuse {
            bridge,
            tail,
            av,
            origin,
            key,
            camera_claim,
        } = *prepared;
        let av_worker::UnknownTimeRetirement {
            parts,
            fenced,
            rollover_custody,
        } = *av;
        let av_worker::UnknownTimeParts {
            sink,
            deployment,
            journal,
            keeper,
            replay,
            authority,
            limits,
            work_limit,
        } = parts;
        let resources = Box::new(BootstrapResources {
            deployment,
            journal,
            keeper,
            replay,
            authority,
            limits,
            work_limit,
            rollover_custody,
        });
        let worker = match av_recovered_startup::Worker::new(resources) {
            Ok(worker) => worker,
            Err(resources) => {
                return Err(Box::new(ReuseRefusal::AvUnsettled {
                    bridge,
                    tail,
                    av: retirement_from_resources(sink, resources, fenced),
                    origin,
                    key,
                    camera_claim,
                }));
            }
        };
        Ok(Box::new(ReuseVerification {
            bridge,
            tail,
            sink,
            origin,
            key,
            camera_claim,
            worker,
            started: false,
            start_refused: false,
            verified: false,
            stopped: false,
        }))
    }

    #[inline(never)]
    fn prepare_reuse_source(
        self: Box<Self>,
        retention: ContentDigest,
    ) -> Result<
        Box<PreparedReuseSource<'scope, 'task, 'policy>>,
        Box<ReuseRefusal<'scope, 'task, 'policy>>,
    > {
        if !self.tail_finished
            || self.tail_fenced
            || !self.bridge.has_active()
            || self.bridge.last_reserved().is_none()
        {
            return Err(Box::new(ReuseRefusal::NotReady(self)));
        }
        let Self {
            bridge,
            tail,
            previous,
            ..
        } = *self;
        let tail = match tail.into_parts() {
            Ok(tail) => tail,
            Err(tail) => {
                return Err(Box::new(ReuseRefusal::TailBusy {
                    bridge,
                    tail,
                    previous,
                }));
            }
        };
        if !tail.plan.is_empty()
            || tail.armed
            || tail.halted
            || tail.key != previous.key
            || tail.camera_claim != previous.camera_claim
            || !tail.worker.ready_for_start()
            || !tail.worker.matches_retention(retention)
        {
            return Err(Box::new(ReuseRefusal::SourceUnsettled {
                bridge,
                tail,
                previous,
            }));
        }
        Ok(Box::new(PreparedReuseSource {
            bridge,
            tail,
            previous,
        }))
    }

    #[inline(never)]
    fn retire_reuse_av(
        source: Box<PreparedReuseSource<'scope, 'task, 'policy>>,
        retention: ContentDigest,
        allow_custody: bool,
    ) -> Result<Box<PreparedReuse<'scope, 'task, 'policy>>, Box<ReuseRefusal<'scope, 'task, 'policy>>>
    {
        let PreparedReuseSource {
            bridge,
            tail,
            previous,
        } = *source;
        let Previous {
            av,
            origin,
            key,
            camera_claim,
        } = previous;
        let av = match av.retire() {
            Ok(av) => Box::new(av),
            Err(av) => {
                return Err(Box::new(ReuseRefusal::AvBusy {
                    bridge,
                    tail,
                    previous: Previous {
                        av,
                        origin,
                        key,
                        camera_claim,
                    },
                }));
            }
        };
        if av.fenced
            || (!allow_custody && av.rollover_custody.is_some())
            || av.parts.sink.has_pending()
            || av.parts.sink.source_key() != key
            || av.parts.sink.retention() != retention
            || av
                .parts
                .journal
                .confirmed()
                .is_none_or(|pin| pin.retention != retention)
            || !av.parts.journal.locally_settled(&av.parts.keeper)
            || av.parts.deployment.publisher().is_poisoned()
        {
            return Err(Box::new(ReuseRefusal::AvUnsettled {
                bridge,
                tail,
                av,
                origin,
                key,
                camera_claim,
            }));
        }
        Ok(Box::new(PreparedReuse {
            bridge,
            tail,
            av,
            origin,
            key,
            camera_claim,
        }))
    }

    #[inline(never)]
    fn attach_reused(
        prepared: Box<PreparedReuse<'scope, 'task, 'policy>>,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
        supplied_unverified_audio: Option<[u8; 2]>,
    ) -> Result<Box<ReusedReady<'scope, 'task, 'policy>>, Box<ReuseRefusal<'scope, 'task, 'policy>>>
    {
        let PreparedReuse {
            bridge,
            tail,
            av,
            origin,
            key,
            camera_claim,
        } = *prepared;
        let connected = match bridge.finish() {
            Ok(connected) => connected,
            Err(bridge) => {
                return Err(Box::new(ReuseRefusal::Bridge {
                    bridge,
                    tail,
                    av,
                    origin,
                    key,
                    camera_claim,
                }));
            }
        };
        let media_reaccept::Connected {
            connected,
            listener,
            retired,
            attempts,
            max_attempts,
            last,
            ..
        } = connected;
        let next_key = connected.pipeline.source_key();
        let retirement_source::DriverParts {
            worker,
            plan: source_plan,
            ..
        } = tail;
        let av_worker::UnknownTimeRetirement {
            parts,
            rollover_custody,
            ..
        } = *av;
        let av_worker::UnknownTimeParts {
            sink,
            deployment,
            journal,
            keeper,
            replay,
            authority,
            limits,
            work_limit,
        } = parts;
        let previous = ReusedPrevious {
            key,
            origin,
            camera_claim,
            source_plan,
            sink,
        };
        let storage = recording_storage::Created {
            coordinator: Coordinator::new(worker, next_key, camera_claim),
            av: Box::new(
                crate::unifi_direct::av_unknown_worker_guard::BootstrapResources {
                    deployment,
                    journal,
                    keeper,
                    replay,
                    authority,
                    limits,
                    work_limit,
                    rollover_custody,
                },
            ),
        };
        match startup::Driver::attach_with_unverified_audio(
            connected,
            storage,
            retention,
            policy,
            camera_claim,
            supplied_unverified_audio,
        ) {
            Ok(startup) => Ok(Box::new(ReusedReady {
                startup,
                listener,
                previous,
                retired,
                attempts,
                max_attempts,
                last,
            })),
            Err(refusal) => Err(Box::new(ReuseRefusal::Attach {
                refusal,
                listener,
                previous,
                retired,
                attempts,
                max_attempts,
                last,
            })),
        }
    }

    /// Attach the accepted successor to independently provisioned archive
    /// resources. The normal A/V startup checks source key, camera claim,
    /// retention and worker state before reading any successor bytes.
    pub fn finish_recording(
        self,
        storage: recording_storage::Created,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
        supplied_unverified_audio: Option<[u8; 2]>,
    ) -> Result<
        RecordingReady<'scope, 'task, 'policy>,
        FinishRecordingRefusal<'scope, 'task, 'policy>,
    > {
        if !self.tail_finished || self.tail_fenced || !self.bridge.has_active() {
            return Err(FinishRecordingRefusal::NotReady {
                transition: self,
                storage,
            });
        }
        let Self {
            bridge,
            tail,
            previous,
            ..
        } = self;
        let connected = match bridge.finish() {
            Ok(connected) => connected,
            Err(bridge) => {
                return Err(FinishRecordingRefusal::NotReady {
                    transition: Self {
                        bridge,
                        tail,
                        previous,
                        tail_finished: true,
                        tail_fenced: false,
                    },
                    storage,
                });
            }
        };
        let media_reaccept::Connected {
            connected,
            listener,
            retired,
            attempts,
            max_attempts,
            last,
            ..
        } = connected;
        match startup::Driver::attach_with_unverified_audio(
            connected,
            storage,
            retention,
            policy,
            previous.camera_claim,
            supplied_unverified_audio,
        ) {
            Ok(startup) => Ok(RecordingReady {
                startup,
                listener,
                tail,
                previous,
                retired,
                attempts,
                max_attempts,
                last,
            }),
            Err(refusal) => Err(FinishRecordingRefusal::Attach {
                refusal,
                listener,
                tail,
                previous,
                retired,
                attempts,
                max_attempts,
                last,
            }),
        }
    }

    /// Attach A/V bootstrap to the accepted successor, retaining the old archive.
    pub fn finish(
        self,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
        supplied_unverified_audio: Option<[u8; 2]>,
    ) -> Result<Ready<'scope, 'task, 'policy>, FinishRefusal<'scope, 'task, 'policy>> {
        if !self.tail_finished || self.tail_fenced || !self.bridge.has_active() {
            return Err(FinishRefusal::NotReady(self));
        }
        let Self {
            bridge,
            tail,
            previous,
            ..
        } = self;
        let connected = match bridge.finish() {
            Ok(connected) => connected,
            Err(bridge) => {
                return Err(FinishRefusal::NotReady(Self {
                    bridge,
                    tail,
                    previous,
                    tail_finished: true,
                    tail_fenced: false,
                }));
            }
        };
        let media_reaccept::Connected {
            connected,
            listener,
            retired,
            attempts,
            max_attempts,
            last,
            ..
        } = connected;
        match bootstrap::Driver::attach_with_unverified_audio(
            connected,
            retention,
            policy,
            supplied_unverified_audio,
        ) {
            Ok(bootstrap) => Ok(Ready {
                bootstrap,
                listener,
                tail,
                previous,
                retired,
                attempts,
                max_attempts,
                last,
            }),
            Err(refusal) => Err(FinishRefusal::Attach {
                refusal,
                listener,
                tail,
                previous,
                retired,
                attempts,
                max_attempts,
                last,
            }),
        }
    }
}
