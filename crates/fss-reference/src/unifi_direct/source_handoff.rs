#![forbid(unsafe_code)]
//! Transfer separately returned source records to a bounded archive worker.
//!
//! The caller supplies the connection and camera claims and retains any
//! unrelated session event, archive completion, or refused source. A
//! successful offer is custody transfer, not proof of publication.

use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};

use fss_container::flv_avc::SourceKey;
use fss_core::ContentDigest;

use super::{
    av_unknown_worker_guard::{Advance, Drive as ArchiveDrive, SessionEvent, Step},
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

/// One control step while a separately owned source publication is running.
/// Every completion and control result remains owned by the caller.
#[must_use]
pub enum Drive {
    /// No source publication is running; the supplied control future was not polled.
    NotRunning,
    /// Publication completed before the control future was polled.
    Completed(source_worker::Completion),
    /// One control step completed, with a publication completion if available.
    Control {
        /// Original controller result; no event, permit or source is discarded.
        step: supervisor::Step,
        /// Source publication outcome observed after that control step.
        completion: Option<source_worker::Completion>,
    },
}

/// Service a bounded control future while a source publication drains.
///
/// Supply `Guard::service_control`, not a future that reads more camera media;
/// the worker may own the only pending original source. Dropping this future
/// leaves the worker and its exact pending source owned by the caller. A
/// completion is returned intact and is not itself proof of publication.
pub async fn drive_control<F>(worker: &mut source_worker::Worker, control: F) -> Drive
where
    F: Future<Output = supervisor::Step>,
{
    if !worker.is_running() {
        return Drive::NotRunning;
    }
    if let Some(completion) = poll_worker_once(worker).await {
        return Drive::Completed(completion);
    }
    let step = control.await;
    let completion = poll_worker_once(worker).await;
    Drive::Control { step, completion }
}

async fn poll_worker_once(worker: &mut source_worker::Worker) -> Option<source_worker::Completion> {
    poll_fn(|cx| {
        let mut join = pin!(worker.join());
        Poll::Ready(match join.as_mut().poll(cx) {
            Poll::Ready(result) => result,
            Poll::Pending => None,
        })
    })
    .await
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
        SessionEvent::Advance(Advance::Archive(ArchiveDrive::Control {
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
