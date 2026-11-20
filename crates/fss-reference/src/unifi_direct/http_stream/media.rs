#![forbid(unsafe_code)]
//! Bounded startup from an already bound native listener and an already
//! authenticated camera HTTP owner. A connection is not an authenticated camera
//! or valid media; downstream framing, source custody and recording are separate.
//! Dropping a pending call can lose its in-memory permit after commitment: retain
//! the journal and reconcile rather than issuing a new effect automatically.

use super::{Plan, Preconditions, ReadbackChange, ReadbackObservation, checkpoint::Anchored};
use crate::unifi_direct::{
    camera_api::{
        HandoffError, HandoffResponseObservation, HandoffWrite, SerializerAuthority,
        VideoSerializers,
    },
    camera_http, ingress, listener,
    pipeline::{NameProbeError, Pipeline, ProbeError},
    recording::Recorder,
};
use asupersync::io::{AsyncRead, AsyncWrite};
use fss_core::{ContentDigest, TimestampNs};
use fss_packet::extended_flv::stream::{Framer, NameProbeOwner};
use fss_runtime::{effect::CommittedEffect, execution::TaskCx};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

/// Caller-owned inputs for one bounded attempt. Identity, listener routing,
/// checkpoint/key custody, lease and peer admission require independent checks.
pub struct Request<'a> {
    /// Exact camera-local start plan.
    pub plan: &'a Plan,
    /// Fresh camera/session/listener/lease claims.
    pub current: Preconditions,
    /// The full serializer baseline bound into the plan.
    pub baseline: &'a VideoSerializers,
    /// Live separately anchored checkpoint receipt for this plan.
    pub checkpoint: &'a Anchored,
    /// Live authority rechecked during every write and flush.
    pub authority: &'a dyn SerializerAuthority,
    /// Bound applied independently to each exchange and to accept.
    pub wait: Duration,
    /// Fresh caller-owned FLV framer, consumed by the accept attempt.
    pub framer: Framer,
    /// Fresh recorder and source key, consumed by the accept attempt.
    pub recorder: Recorder,
    /// Maximum bytes per source read.
    pub chunk_bytes: usize,
    /// Maximum total accepted source bytes.
    pub max_bytes: u64,
}

/// Payload-free indication of where the startup stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// The start operation, listener, or media bounds failed preflight.
    Preflight,
    /// The dispatcher refused before claiming its permit.
    Dispatch(HandoffError),
    /// A partial write or cancellation may have changed the camera.
    IndeterminateWrite,
    /// The HTTP response could not be read or was refused.
    Response(camera_http::Error),
    /// The response was received, but the caller could not retain its claim.
    /// The permit and bounded response shape remain available for reconciliation.
    ResponseCustody {
        /// Payload-free untrusted response shape.
        observation: HandoffResponseObservation,
        /// Whether cancellation, admission, or persistent custody failed.
        reason: ResponseCustodyError,
    },
    /// A required full serializer readback failed.
    Readback(camera_http::Error),
    /// The retained baseline and fresh readback could not be compared.
    Comparison(super::Error),
    /// The readback did not match the requested target-only change.
    UnexpectedReadback(ReadbackObservation),
    /// The bound listener did not accept an admitted connection.
    Accept(listener::Error),
}

/// Why the caller could not retain a received camera response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseCustodyError {
    /// Cancellation or time admission prevented custody.
    Cancelled,
    /// Storage authority or budget was refused.
    Authority,
    /// Persistence failed or its outcome requires inspection.
    Storage,
}

/// Synchronous caller-owned custody of an untrusted HTTP response claim. The
/// caller must bound or offload blocking work, preserve the supplied permit on
/// failure, and not treat this claim as verified effect or permission to retry.
pub type ResponseRecorder<'a> = dyn FnMut(&mut CommittedEffect, HandoffResponseObservation) -> Result<(), ResponseCustodyError>
    + 'a;

/// Retained committed effect and optional private readback after refusal.
/// `may_have_written` is not proof of a remote outcome; reconcile the journal.
#[must_use = "retain the permit and reconcile any potentially written effect"]
pub struct Refusal {
    /// Where startup stopped.
    pub failure: Failure,
    /// The same committed permit returned by the dispatcher.
    pub permit: CommittedEffect,
    /// Whether a request could have reached the camera.
    pub may_have_written: bool,
    /// Full private readback if it was received before refusal.
    pub readback: Option<VideoSerializers>,
}
impl std::fmt::Debug for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpMediaRefusal")
            .field("failure", &self.failure)
            .field("may_have_written", &self.may_have_written)
            .finish_non_exhaustive()
    }
}

/// A TCP connection associated with an original matching camera readback.
/// After reaccept the readback is historical. Its bytes, identity,
/// high-resolution profile and durable recording remain unverified.
#[must_use = "retain or explicitly retire the media pipeline and reconcile the effect"]
pub struct Connected {
    camera_claim: ContentDigest,
    pub(super) listener_addr: SocketAddrV4,
    /// Claimed permit retained for independent effect reconciliation.
    pub(super) permit: CommittedEffect,
    /// Full private serializer readback.
    pub(super) readback: VideoSerializers,
    /// Redacted comparison to the baseline and requested serializer fields.
    pub(super) comparison: ReadbackObservation,
    /// Fresh task-bound pipeline for independent media validation and custody.
    pub(super) pipeline: Pipeline,
}

impl Connected {
    pub(super) fn from_reaccept(detached: Detached, listener_addr: SocketAddrV4) -> Self {
        Self {
            camera_claim: detached.camera_claim,
            listener_addr,
            permit: detached.permit,
            readback: detached.readback,
            comparison: detached.comparison,
            pipeline: detached.pipeline,
        }
    }
    /// The camera claim bound to the dispatched start, not authenticated identity.
    pub fn camera_claim(&self) -> ContentDigest {
        self.camera_claim
    }

    /// The original readback comparison; after reaccept it may be stale.
    pub fn comparison(&self) -> ReadbackObservation {
        self.comparison
    }

    /// Install a source-preserving stream-name probe before processing media.
    pub fn begin_name_probe(&mut self, probe: NameProbeOwner) -> Result<(), NameProbeOwner> {
        self.pipeline.begin_name_probe(probe)
    }

    /// Recover and explicitly abandon an installed stream-name probe.
    pub fn take_name_probe(&mut self) -> Option<NameProbeOwner> {
        self.pipeline.take_name_probe()
    }

    /// Probe the initial FLV header while retaining its original bytes.
    pub async fn probe_header_step(
        &mut self,
        task: &TaskCx<'_>,
        cx: &asupersync::Cx,
        now: TimestampNs,
    ) -> Result<ingress::HeaderProbe, ProbeError> {
        self.pipeline.probe_header_step(task, cx, now).await
    }

    /// Advance the installed stream-name probe while retaining source bytes.
    pub async fn probe_name_step(
        &mut self,
        task: &TaskCx<'_>,
        cx: &asupersync::Cx,
        now: TimestampNs,
    ) -> Result<ingress::NameProbeStep, NameProbeError> {
        self.pipeline.probe_name_step(task, cx, now).await
    }

    /// Transfer all owners; a detached pipeline cannot be reattached as this
    /// connected stream without performing a new startup.
    pub fn into_parts(self) -> Detached {
        Detached {
            camera_claim: self.camera_claim,
            permit: self.permit,
            readback: self.readback,
            comparison: self.comparison,
            pipeline: self.pipeline,
        }
    }
}

/// Complete stream and effect custody after detaching the startup owner.
#[must_use = "account for the media and reconcile the camera effect"]
pub struct Detached {
    /// Camera claim bound to the start, not authenticated identity.
    pub camera_claim: ContentDigest,
    /// Committed setting effect requiring reconciliation.
    pub permit: CommittedEffect,
    /// Full private serializer readback.
    pub readback: VideoSerializers,
    /// Redacted readback comparison.
    pub comparison: ReadbackObservation,
    /// The admitted source pipeline.
    pub pipeline: Pipeline,
}

/// Send one already committed start and attach one admitted connection. The
/// listener and HTTP owner remain borrowed by the caller; no retry, restore,
/// effect settlement, storage publication or media validation occurs here.
pub async fn start<IO: AsyncRead + AsyncWrite + Unpin>(
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    listener: &mut listener::Listener<'_, '_, '_>,
    request: Request<'_>,
    permit: CommittedEffect,
    authorize_observation: impl Fn(Ipv4Addr, u64) -> bool,
) -> Result<Connected, Refusal> {
    start_with_response(
        http,
        listener,
        request,
        permit,
        authorize_observation,
        &mut |_, _| Ok(()),
    )
    .await
}

/// Start with caller-owned response custody, before reading settings or media.
/// A custody refusal retains the exact permit and redacted response shape;
/// it never triggers an automatic retry or restore.
pub async fn start_with_response<IO: AsyncRead + AsyncWrite + Unpin>(
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    listener: &mut listener::Listener<'_, '_, '_>,
    request: Request<'_>,
    permit: CommittedEffect,
    authorize_observation: impl Fn(Ipv4Addr, u64) -> bool,
    record_response: &mut ResponseRecorder<'_>,
) -> Result<Connected, Refusal> {
    if request.plan.operation() != super::Operation::Start
        || request.current.listener != listener.local_addr()
        || !http.matches_media_listener(listener)
        || !listener::valid_accept_config(request.chunk_bytes, request.max_bytes, request.wait)
    {
        return Err(Refusal {
            failure: Failure::Preflight,
            permit,
            may_have_written: false,
            readback: None,
        });
    }
    let mut permit = match http
        .dispatch_serializer(
            request.plan,
            request.current,
            request.baseline,
            Some(request.checkpoint),
            permit,
            request.authority,
            request.wait,
        )
        .await
    {
        Err(refusal) => {
            return Err(Refusal {
                failure: Failure::Dispatch(refusal.reason),
                permit: refusal.permit,
                may_have_written: false,
                readback: None,
            });
        }
        Ok(HandoffWrite::Indeterminate { permit }) => {
            return Err(Refusal {
                failure: Failure::IndeterminateWrite,
                permit,
                may_have_written: true,
                readback: None,
            });
        }
        Ok(HandoffWrite::Written { permit }) => permit,
    };
    let response = match http
        .read_serializer_response_observed(&permit, request.wait)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return Err(Refusal {
                failure: Failure::Response(error),
                permit,
                may_have_written: true,
                readback: None,
            });
        }
    };
    if let Err(reason) = record_response(&mut permit, response) {
        return Err(Refusal {
            failure: Failure::ResponseCustody {
                observation: response,
                reason,
            },
            permit,
            may_have_written: true,
            readback: None,
        });
    }
    let (_, readback) = match http.settings_serializers(request.wait).await {
        Ok(value) => value,
        Err(error) => {
            return Err(Refusal {
                failure: Failure::Readback(error),
                permit,
                may_have_written: true,
                readback: None,
            });
        }
    };
    let comparison =
        match request
            .plan
            .observe_readback(request.baseline, &readback, authorize_observation)
        {
            Ok(value) => value,
            Err(error) => {
                return Err(Refusal {
                    failure: Failure::Comparison(error),
                    permit,
                    may_have_written: true,
                    readback: Some(readback),
                });
            }
        };
    if comparison.change != ReadbackChange::TargetTrackOnly || !comparison.requested_fields_match {
        return Err(Refusal {
            failure: Failure::UnexpectedReadback(comparison),
            permit,
            may_have_written: true,
            readback: Some(readback),
        });
    }
    match listener
        .accept_next(
            request.framer,
            request.recorder,
            request.chunk_bytes,
            request.max_bytes,
            request.wait,
        )
        .await
    {
        Ok(pipeline) => Ok(Connected {
            camera_claim: request.current.camera,
            listener_addr: listener.local_addr(),
            permit,
            readback,
            comparison,
            pipeline,
        }),
        Err(error) => Err(Refusal {
            failure: Failure::Accept(error),
            permit,
            may_have_written: true,
            readback: Some(readback),
        }),
    }
}
