#![forbid(unsafe_code)]
//! Transfer separately returned source records to a bounded archive worker.
//!
//! The caller supplies the connection and camera claims and retains any
//! unrelated session event, archive completion, or refused source. A
//! successful offer is custody transfer, not proof of publication.

use fss_container::flv_avc::SourceKey;
use fss_core::ContentDigest;

use super::{
    av_unknown_worker_guard::{Advance, Drive, SessionEvent, Step},
    av_worker, pipeline, recording, source_worker, supervisor,
};

/// The original event context, including any unrelated archive completion.
#[must_use]
pub enum Origin {
    /// Source result yielded by the supervisor.
    Source,
    /// Source result observed while an A/V archive operation was driven.
    Control {
        /// A separately drained A/V publication, if one completed.
        completion: Option<av_worker::UnknownTimeCompletion>,
    },
}

/// Ownership after an attempted handoff; no publication is implied.
#[must_use]
pub enum Result {
    /// The worker now owns the exact original source.
    Accepted {
        /// Why the source was returned without a corresponding sample.
        disposition: recording::SourceDisposition,
        /// Original event context, still owned by the caller.
        origin: Origin,
    },
    /// The worker refused the unchanged source and returned its ownership.
    Refused {
        /// Original event context, still owned by the caller.
        origin: Origin,
        /// Refusal reason and unchanged input.
        refusal: source_worker::OfferRefusal,
    },
    /// No supported separately returned source was found; event is unchanged.
    Unhandled(SessionEvent),
}

/// Offer a supported session event without I/O or inferred source identity.
///
/// `key` and `camera_claim` are caller-supplied claims, not authenticated
/// camera identity. On refusal, the original record remains in the refusal.
pub fn offer(
    worker: &mut source_worker::Worker,
    event: SessionEvent,
    key: SourceKey,
    camera_claim: ContentDigest,
) -> Result {
    let (record, disposition, origin) = match event {
        SessionEvent::Advance(Advance::Source(Step::Supervisor(supervisor::Step::Media(
            pipeline::Step::Recording(recording::Push::Source {
                record,
                disposition,
            }),
        )))) => (record, disposition, Origin::Source),
        SessionEvent::Advance(Advance::Archive(Drive::Control {
            step:
                supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {
                    record,
                    disposition,
                })),
            completion,
        })) => (record, disposition, Origin::Control { completion }),
        other => return Result::Unhandled(other),
    };
    match worker.offer(source_worker::Input::Original {
        record,
        key,
        disposition,
        camera_claim,
    }) {
        Ok(()) => Result::Accepted {
            disposition,
            origin,
        },
        Err(refusal) => Result::Refused { origin, refusal },
    }
}
