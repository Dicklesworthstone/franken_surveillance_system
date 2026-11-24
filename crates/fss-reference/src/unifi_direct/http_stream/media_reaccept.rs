#![forbid(unsafe_code)]
//! Reaccept a stopped HTTP-started media connection without reissuing its
//! camera-setting effect. Prior readback and admission are historical claims;
//! a new socket is not proof of camera identity, continuity or authorization
//! to skip independent source validation. Archive owners and previously
//! transferred records remain with the caller throughout the transition.

use std::{collections::VecDeque, future::Future, time::Duration};

use fss_container::flv_avc::SourceKey;
use fss_core::ContentDigest;
use fss_runtime::effect::CommittedEffect;

use super::{ReadbackObservation, media};
use crate::unifi_direct::{camera_api::VideoSerializers, listener, media_reconnect};

/// Original camera-setting effect and its historical readback.
#[must_use = "retain the committed effect and reconcile its outcome"]
pub struct EffectCustody {
    /// Caller-supplied camera claim, not an authenticated identity.
    pub camera_claim: ContentDigest,
    /// The original, still-unsettled camera-setting effect.
    pub permit: CommittedEffect,
    /// Private readback from the original start, not a fresh observation.
    pub readback: VideoSerializers,
    /// Historical comparison made before the original connection.
    pub comparison: ReadbackObservation,
}

/// Refusal retains the listener, effect, and all source owners.
#[must_use = "retain the original owners and reconcile the effect"]
#[allow(clippy::large_enum_variant)]
pub enum CreateRefusal<'scope, 'task, 'policy> {
    /// The old pipeline has not stopped or the listener binding differs.
    NotStoppedOrBound {
        /// Original bound listener.
        listener: listener::Listener<'scope, 'task, 'policy>,
        /// Original connected stream and effect.
        connected: media::Connected,
    },
    /// A stopped pipeline was retired, but bounded-owner creation failed.
    Bounded {
        /// Original listener and complete retired source.
        refusal: media_reconnect::CreateRefusal<'scope, 'task, 'policy>,
        /// Original camera effect and historical observations.
        effect: EffectCustody,
    },
}

/// Caller-supervised transfer of a stopped HTTP connection to a new socket.
#[must_use = "finish or recover the listener, effect and all source tails"]
pub struct Reaccept<'scope, 'task, 'policy> {
    inner: media_reconnect::Reaccept<'scope, 'task, 'policy>,
    effect: EffectCustody,
    listener_addr: std::net::SocketAddrV4,
}

/// New connection plus every listener and source owner retained by the bridge.
#[must_use = "archive or retain all returned tails and reconcile the effect"]
pub struct Connected<'scope, 'task, 'policy> {
    /// New pipeline carrying the original unresolved camera effect.
    pub connected: media::Connected,
    /// Bound listener for subsequent supervised connections.
    pub listener: listener::Listener<'scope, 'task, 'policy>,
    /// Tails not already transferred to the caller.
    pub retired: VecDeque<media_reconnect::Retired>,
    /// Most recently reserved connection claim.
    pub last: Option<SourceKey>,
    /// Number of reserved accept attempts.
    pub attempts: usize,
    /// Original finite accept-attempt limit.
    pub max_attempts: usize,
    /// Original finite retained-tail limit.
    pub max_retired: usize,
}

/// Recoverable owners when the transition is abandoned before connection.
#[must_use = "retain the listener, effect and every source owner"]
pub struct Parts<'scope, 'task, 'policy> {
    /// Listener and all media custody.
    pub media: media_reconnect::Parts<'scope, 'task, 'policy>,
    /// Original effect and historical observations.
    pub effect: EffectCustody,
}

/// Listener-independent media and original camera-effect custody.
#[must_use = "retain media custody and reconcile the original effect"]
pub struct Detached {
    /// Live pipeline, source tails, and exact bounded-accept state.
    pub media: media_reconnect::Detached,
    /// Original unresolved effect and historical observations.
    pub effect: EffectCustody,
}

impl<'scope, 'task, 'policy> Parts<'scope, 'task, 'policy> {
    /// Return the listener to its scope while preserving all other owners.
    /// This does not settle the effect, drain a pipeline, or permit a retry.
    pub fn split_listener(self) -> (listener::Listener<'scope, 'task, 'policy>, Detached) {
        let Self { media, effect } = self;
        let (listener, media) = media.split_listener();
        (listener, Detached { media, effect })
    }
}

impl<'scope, 'task, 'policy> Reaccept<'scope, 'task, 'policy> {
    /// Retire the stopped source and retain the original effect. Matching a
    /// listener address and task is not proof that the new peer is the same
    /// physical camera. A prior error's returned record remains caller-owned.
    #[allow(clippy::result_large_err)]
    pub fn new(
        listener: listener::Listener<'scope, 'task, 'policy>,
        connected: media::Connected,
        max_attempts: usize,
        max_retired: usize,
    ) -> Result<Self, CreateRefusal<'scope, 'task, 'policy>> {
        if !connected.pipeline.is_stopped()
            || listener.local_addr() != connected.listener_addr
            || !listener.owns_pipeline_task(&connected.pipeline)
        {
            return Err(CreateRefusal::NotStoppedOrBound {
                listener,
                connected,
            });
        }
        let listener_addr = listener.local_addr();
        let detached = connected.into_parts();
        let key = detached.pipeline.source_key();
        let effect = EffectCustody {
            camera_claim: detached.camera_claim,
            permit: detached.permit,
            readback: detached.readback,
            comparison: detached.comparison,
        };
        let previous = media_reconnect::Retired {
            key,
            pipeline: detached.pipeline.retire(),
        };
        let inner = match media_reconnect::Reaccept::new(
            listener,
            Some(previous),
            max_attempts,
            max_retired,
        ) {
            Ok(inner) => inner,
            Err(refusal) => return Err(CreateRefusal::Bounded { refusal, effect }),
        };
        Ok(Self {
            inner,
            effect,
            listener_addr,
        })
    }

    /// Transfer one prior original-source tail for explicit archival.
    pub fn take_retired(&mut self) -> Option<media_reconnect::Retired> {
        self.inner.take_retired()
    }

    /// Whether an accepted successor is ready to transfer.
    pub fn has_active(&self) -> bool {
        self.inner.has_active()
    }

    /// Most recently reserved connection claim.
    pub fn last_reserved(&self) -> Option<SourceKey> {
        self.inner.last_reserved()
    }

    /// Whether a dropped accept wait still needs explicit acknowledgment.
    pub fn interrupted(&self) -> bool {
        self.inner.interrupted()
    }

    pub(super) fn matches_context<'s, 't>(
        &self,
        task: &fss_runtime::execution::TaskCx<'t>,
        cx: &asupersync::Cx,
        clock: crate::unifi_direct::metered::MeteredClock<'s, 't>,
    ) -> bool {
        self.inner.matches_context(task, cx, clock)
    }

    /// Reserve a bounded accept; admission is rechecked by the listener.
    #[allow(clippy::result_large_err)]
    pub fn accept_next(
        &mut self,
        inputs: media_reconnect::Inputs,
        chunk_bytes: usize,
        max_bytes: u64,
        wait: Duration,
    ) -> Result<
        impl Future<Output = Result<(), media_reconnect::Error>> + '_,
        media_reconnect::Refusal,
    > {
        self.inner.accept_next(inputs, chunk_bytes, max_bytes, wait)
    }

    /// Acknowledge an interrupted wait without asserting its remote outcome.
    pub fn acknowledge_interrupted(&mut self) -> Option<SourceKey> {
        self.inner.acknowledge_interrupted()
    }

    /// Recover all owners without claiming that a new stream was obtained.
    pub fn into_parts(self) -> Parts<'scope, 'task, 'policy> {
        Parts {
            media: self.inner.into_parts(),
            effect: self.effect,
        }
    }

    /// Transfer an accepted pipeline into the HTTP media owner. The old
    /// readback remains historical; fresh peer and media checks still apply.
    #[allow(clippy::result_large_err)]
    pub fn finish(self) -> Result<Connected<'scope, 'task, 'policy>, Self> {
        let Self {
            inner,
            effect,
            listener_addr,
        } = self;
        let (pipeline, parts) = match inner.take_active_parts() {
            Ok(extracted) => extracted,
            Err(inner) => {
                return Err(Self {
                    inner,
                    effect,
                    listener_addr,
                });
            }
        };
        let connected = media::Connected::from_reaccept(
            media::Detached {
                camera_claim: effect.camera_claim,
                permit: effect.permit,
                readback: effect.readback,
                comparison: effect.comparison,
                pipeline,
            },
            listener_addr,
        );
        Ok(Connected {
            connected,
            listener: parts.listener,
            retired: parts.retired,
            last: parts.last,
            attempts: parts.attempts,
            max_attempts: parts.max_attempts,
            max_retired: parts.max_retired,
        })
    }
}
