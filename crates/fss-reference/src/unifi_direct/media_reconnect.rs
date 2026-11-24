#![forbid(unsafe_code)]
//! Bounded, source-preserving reacceptance on an existing media listener.
//!
//! This owner sends no camera request. Each accepted socket has a distinct
//! caller-supplied source key; retired tails remain owned until transferred.
//! Neither acceptance nor source-key ordering proves device identity, camera
//! settings, durable archival, continuous coverage, or permission to retry an
//! indeterminate camera effect. The caller must establish those separately.

use std::{collections::VecDeque, time::Duration};

use fss_container::flv_avc::SourceKey;
use fss_packet::extended_flv::stream::Framer;

use super::{listener, pipeline, recording};

const MAX_ATTEMPTS: usize = 128;
const MAX_RETIRED: usize = 16;

/// One retired connection and all bytes still owned by its pipeline.
#[must_use = "archive or otherwise account for the complete retired source"]
pub struct Retired {
    /// Caller-supplied source identity, not an authenticated camera identity.
    pub key: SourceKey,
    /// Original unparsed and unfinished source, including local socket state.
    pub pipeline: pipeline::Retirement,
}

/// Caller-owned inputs returned intact when admission fails before waiting.
#[must_use]
pub struct Inputs {
    /// An unused, zero-offset framer.
    pub framer: Framer,
    /// A recorder that has not received source records.
    pub recorder: recording::Recorder,
}

/// Why a bounded accept could not proceed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An attempt is in flight or was dropped and not yet acknowledged.
    Waiting,
    /// An accepted pipeline must be retired before another accept.
    Active,
    /// Retired-source capacity is full; transfer custody before accepting.
    RetiredCapacity,
    /// The caller's finite attempt budget has been exhausted.
    AttemptLimit,
    /// An input already held source, or accept bounds were invalid.
    Configuration,
    /// The connection identity did not advance or generation moved backward.
    SourceOrder,
    /// The existing listener refused or timed out; no accepted pipeline escaped.
    Listener(listener::Error),
}

/// Failed admission returns the original inputs before starting a wait.
#[must_use]
pub struct Refusal {
    /// Payload-free reason.
    pub reason: Error,
    /// Original inputs when refusal happened before starting the wait.
    pub inputs: Option<Inputs>,
}

/// Refusal to create a reaccept owner retains its original listener and tail.
#[must_use]
pub struct CreateRefusal<'scope, 'task, 'policy> {
    /// Original bound listener.
    pub listener: listener::Listener<'scope, 'task, 'policy>,
    /// Previous source, if supplied.
    pub previous: Option<Retired>,
}

/// Explicitly bounded owner of a listener, one live pipeline and source tails.
#[must_use = "retain or explicitly transfer the listener, live pipeline, and tails"]
pub struct Reaccept<'scope, 'task, 'policy> {
    listener: listener::Listener<'scope, 'task, 'policy>,
    active: Option<pipeline::Pipeline>,
    retired: VecDeque<Retired>,
    last: Option<SourceKey>,
    waiting: bool,
    attempts: usize,
    max_attempts: usize,
    max_retired: usize,
}

/// Complete ownership returned when this bounded owner is stopped.
#[must_use = "account for the listener, any live pipeline and all source tails"]
pub struct Parts<'scope, 'task, 'policy> {
    /// Original bound listener.
    pub listener: listener::Listener<'scope, 'task, 'policy>,
    /// A pipeline that was not yet retired.
    pub active: Option<pipeline::Pipeline>,
    /// Every source tail not already transferred by the caller.
    pub retired: VecDeque<Retired>,
    /// Most recently reserved caller-supplied source identity.
    pub last: Option<SourceKey>,
    /// A dropped accept wait was not explicitly acknowledged.
    pub interrupted: bool,
    /// Number of reserved accept attempts.
    pub attempts: usize,
    /// Original finite accept-attempt limit.
    pub max_attempts: usize,
    /// Original finite retained-tail limit.
    pub max_retired: usize,
}

/// Recoverable media custody separated from the scoped listener.
///
/// Detaching does not drain a live pipeline, resolve an interrupted accept,
/// or establish any camera identity or recording continuity.
#[must_use = "account for the live pipeline, interrupted wait and every source tail"]
pub struct Detached {
    /// A pipeline that was not yet retired.
    pub active: Option<pipeline::Pipeline>,
    /// Every source tail not already transferred by the caller.
    pub retired: VecDeque<Retired>,
    /// Most recently reserved caller-supplied source identity.
    pub last: Option<SourceKey>,
    /// A dropped accept wait was not explicitly acknowledged.
    pub interrupted: bool,
    /// Number of reserved accept attempts.
    pub attempts: usize,
    /// Original finite accept-attempt limit.
    pub max_attempts: usize,
    /// Original finite retained-tail limit.
    pub max_retired: usize,
}

impl<'scope, 'task, 'policy> Parts<'scope, 'task, 'policy> {
    /// Separate the scoped listener from every non-scoped media owner.
    /// No work is drained and no retry is authorized by this transfer.
    pub fn split_listener(self) -> (listener::Listener<'scope, 'task, 'policy>, Detached) {
        let Self {
            listener,
            active,
            retired,
            last,
            interrupted,
            attempts,
            max_attempts,
            max_retired,
        } = self;
        (
            listener,
            Detached {
                active,
                retired,
                last,
                interrupted,
                attempts,
                max_attempts,
                max_retired,
            },
        )
    }
}

impl<'scope, 'task, 'policy> Reaccept<'scope, 'task, 'policy> {
    /// Adopt a bound listener and optionally its caller-retained predecessor.
    /// The supplied predecessor and its key are claims, not durability proof.
    #[allow(clippy::result_large_err)]
    pub fn new(
        listener: listener::Listener<'scope, 'task, 'policy>,
        previous: Option<Retired>,
        max_attempts: usize,
        max_retired: usize,
    ) -> Result<Self, CreateRefusal<'scope, 'task, 'policy>> {
        if !(1..=MAX_ATTEMPTS).contains(&max_attempts)
            || !(1..=MAX_RETIRED).contains(&max_retired)
            || previous
                .as_ref()
                .is_some_and(|p| p.key.connection == 0 || p.key.generation == 0)
        {
            return Err(CreateRefusal { listener, previous });
        }
        let mut retired = VecDeque::new();
        if retired.try_reserve_exact(max_retired).is_err() {
            return Err(CreateRefusal { listener, previous });
        }
        let last = previous.as_ref().map(|p| p.key);
        if let Some(previous) = previous {
            retired.push_back(previous);
        }
        Ok(Self {
            listener,
            active: None,
            retired,
            last,
            waiting: false,
            attempts: 0,
            max_attempts,
            max_retired,
        })
    }

    /// Number of reserved attempts, including interrupted and refused waits.
    pub fn attempts(&self) -> usize {
        self.attempts
    }

    /// Last reserved source claim, including an interrupted wait.
    pub fn last_reserved(&self) -> Option<SourceKey> {
        self.last
    }

    pub(crate) fn matches_context<'s, 't>(
        &self,
        task: &fss_runtime::execution::TaskCx<'t>,
        cx: &asupersync::Cx,
        clock: super::metered::MeteredClock<'s, 't>,
    ) -> bool {
        self.listener.matches_context(task, cx, clock)
    }

    /// Whether a wait was dropped before it returned to this owner.
    pub fn interrupted(&self) -> bool {
        self.waiting
    }

    /// Acknowledge a dropped accept wait; its source key remains reserved and
    /// no accepted pipeline or remote outcome is asserted. No I/O occurs.
    pub fn acknowledge_interrupted(&mut self) -> Option<SourceKey> {
        if !self.waiting {
            return None;
        }
        self.waiting = false;
        self.last
    }

    /// Borrow the sole accepted pipeline; the owner retains its socket.
    pub fn active_mut(&mut self) -> Option<&mut pipeline::Pipeline> {
        self.active.as_mut()
    }

    /// Whether this owner has an accepted pipeline ready to transfer.
    pub fn has_active(&self) -> bool {
        self.active.is_some()
    }

    /// Retire the live pipeline without discarding its held source bytes.
    pub fn retire_active(&mut self) -> bool {
        let Some(active) = self.active.take() else {
            return false;
        };
        let key = active.source_key();
        self.retired.push_back(Retired {
            key,
            pipeline: active.retire(),
        });
        true
    }

    /// Transfer one original tail to the caller for archival or reconciliation.
    pub fn take_retired(&mut self) -> Option<Retired> {
        self.retired.pop_front()
    }

    /// Reserve one new peer wait without issuing any camera control write.
    /// A dropped wait fences this owner until acknowledged; the attempted key
    /// and budget remain consumed. Previously transferred records are still
    /// the caller's responsibility. New connections do not establish continuity.
    #[allow(clippy::result_large_err)]
    pub fn accept_next(
        &mut self,
        inputs: Inputs,
        chunk_bytes: usize,
        max_bytes: u64,
        wait: Duration,
    ) -> Result<impl std::future::Future<Output = Result<(), Error>> + '_, Refusal> {
        let key = inputs.recorder.source_key();
        let reason = if self.waiting {
            Some(Error::Waiting)
        } else if self.active.is_some() {
            Some(Error::Active)
        } else if self.retired.len() >= self.max_retired {
            Some(Error::RetiredCapacity)
        } else if self.attempts >= self.max_attempts {
            Some(Error::AttemptLimit)
        } else if !inputs.recorder.is_pristine()
            || inputs.framer.next_offset() != 0
            || inputs.framer.buffered_len() != 0
            || !listener::valid_accept_config(chunk_bytes, max_bytes, wait)
        {
            Some(Error::Configuration)
        } else if self.last.is_some_and(|last| {
            key.connection <= last.connection || key.generation < last.generation
        }) {
            Some(Error::SourceOrder)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(Refusal {
                reason,
                inputs: Some(inputs),
            });
        }
        self.waiting = true;
        self.attempts += 1;
        self.last = Some(key);
        Ok(async move {
            let result = self
                .listener
                .accept_next(inputs.framer, inputs.recorder, chunk_bytes, max_bytes, wait)
                .await;
            self.waiting = false;
            match result {
                Ok(pipeline) => {
                    self.active = Some(pipeline);
                    Ok(())
                }
                Err(reason) => Err(Error::Listener(reason)),
            }
        })
    }

    /// Take the accepted pipeline and remaining parts, returning `self` unchanged if none is active.
    #[allow(clippy::result_large_err)]
    pub(crate) fn take_active_parts(
        mut self,
    ) -> Result<(pipeline::Pipeline, Parts<'scope, 'task, 'policy>), Self> {
        let Some(pipeline) = self.active.take() else {
            return Err(self);
        };
        Ok((pipeline, self.into_parts()))
    }

    /// Stop this owner without implicitly discarding a pipeline or source tail.
    pub fn into_parts(self) -> Parts<'scope, 'task, 'policy> {
        Parts {
            listener: self.listener,
            active: self.active,
            retired: self.retired,
            last: self.last,
            interrupted: self.waiting,
            attempts: self.attempts,
            max_attempts: self.max_attempts,
            max_retired: self.max_retired,
        }
    }
}
