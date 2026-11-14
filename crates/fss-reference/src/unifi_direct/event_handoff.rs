#![forbid(unsafe_code)]
//! Custody-preserving handoff of supervisor camera events to an archive worker.
//!
//! The supplied connection and camera identifiers are caller claims. Handoff
//! does not authenticate the sender, establish capture time, or prove storage.

use fss_container::flv_avc::SourceKey;
use fss_core::ContentDigest;

use super::{
    av_unknown_worker_guard::{Advance, Drive, SessionEvent, Step},
    av_worker, event_worker, supervisor,
};

/// Original session context, including any unrelated archive completion.
#[must_use]
pub enum Origin {
    /// The supervisor returned this event directly.
    Source,
    /// The event arrived while an A/V archive attempt was being driven.
    Control {
        /// Independently drained A/V completion, if present.
        completion: Option<av_worker::UnknownTimeCompletion>,
    },
}

/// The outcome of transferring an event; acceptance does not imply publication.
#[must_use]
pub enum Result {
    /// The worker owns the exact event; the caller retains its original context.
    Accepted {
        /// Context to process independently of event publication.
        origin: Origin,
    },
    /// The worker returned the unchanged event and its original context.
    Refused {
        /// Context to process independently of the refusal.
        origin: Origin,
        /// Worker refusal containing the unchanged input.
        refusal: event_worker::OfferRefusal,
    },
    /// No camera event was found; the complete session event is returned.
    Unhandled(SessionEvent),
}

/// Offer an exact camera event without blocking or inferring identity.
pub fn offer(
    worker: &mut event_worker::Worker,
    event: SessionEvent,
    key: SourceKey,
    camera_claim: ContentDigest,
) -> Result {
    let (frame, origin) = match event {
        SessionEvent::Advance(Advance::Source(Step::Supervisor(
            supervisor::Step::CameraEvent(frame),
        ))) => (frame, Origin::Source),
        SessionEvent::Advance(Advance::Archive(Drive::Control {
            step: supervisor::Step::CameraEvent(frame),
            completion,
        })) => (frame, Origin::Control { completion }),
        other => return Result::Unhandled(other),
    };
    match worker.offer(event_worker::Input::Original {
        frame,
        key,
        camera_claim,
    }) {
        Ok(()) => Result::Accepted { origin },
        Err(refusal) => Result::Refused { origin, refusal },
    }
}
