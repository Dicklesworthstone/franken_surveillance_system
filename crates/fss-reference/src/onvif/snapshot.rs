#![forbid(unsafe_code)]
//! One owner-scoped Media1 snapshot: profiles, URI negotiation, and bounded JPEG GET.
//!
//! An advertised URI never grants a new peer or origin. The caller owns every clock,
//! wait, cancellation and authority check. This credential-free lane neither redirects
//! nor retries authentication. A framed JPEG is source evidence, not a continuity,
//! decoded-scene, device identity or ONVIF Profile T conformance claim.

use super::client::{ClientError, OnvifContext};
use super::http::{
    HttpDenial, HttpError, HttpExchange, HttpLimits, HttpOperation, HttpProgress, HttpResponse,
    HttpRoute, HttpTotals,
};
use super::wire::{self, MediaProfile, SnapshotUri, SoapRequest};
use crate::ingest::mjpeg::{MjpegLimits, split_jpeg_stream};
use fss_core::ContentDigest;
use std::fmt;

/// Hard source allocation ceiling, independently bounded from SOAP responses.
pub const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum complete network-session lease.
pub const MAX_TIMEOUT_NS: u64 = 60_000_000_000;

/// Explicit authority and whole-session limits for a single snapshot.
#[derive(Clone)]
pub struct SnapshotPlan {
    /// Independently approved Media1 service route and pinned literal peer.
    pub media: HttpRoute,
    /// Exact requested video profile, or the first advertised video profile.
    pub profile_token: Option<String>,
    /// Maximum complete JPEG source, 1..=64 MiB.
    pub max_source_bytes: usize,
    /// Absolute deadline in the owner's monotonic domain, at most 60 seconds away.
    pub deadline_ns: u64,
    /// Clock/progress ceiling for the entire three-exchange session, 1..=100000.
    pub max_steps: u32,
}

impl fmt::Debug for SnapshotPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotPlan")
            .field("media", &self.media)
            .field("explicit_profile", &self.profile_token.is_some())
            .field("max_source_bytes", &self.max_source_bytes)
            .field("deadline_ns", &self.deadline_ns)
            .field("max_steps", &self.max_steps)
            .finish()
    }
}

/// One exact fetched source. The caller must retain and verify these bytes before
/// claiming durable custody. Device-provided expiry is metadata, not trusted time.
pub struct Snapshot {
    /// Selected advertised video profile; not a decoded-image assertion.
    pub profile: MediaProfile,
    /// Returned same-origin URI; its path/query may contain bearer tokens.
    pub uri: SnapshotUri,
    /// Exact transfer-decoded body, never a re-encoded or concatenated image.
    pub jpeg: Vec<u8>,
    /// Digest of exactly `jpeg`.
    pub source_digest: ContentDigest,
    /// Observed socket work across the three complete exchanges.
    pub network: HttpTotals,
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("bytes", &self.jpeg.len())
            .field("source_digest", &self.source_digest)
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

/// Negotiate and fetch exactly one framed JPEG under the approved service origin.
/// Auth challenges and redirects fail closed; no credential callback is reached.
pub fn capture(plan: &SnapshotPlan, cx: &impl OnvifContext) -> Result<Snapshot, ClientError> {
    if !(1..=MAX_SOURCE_BYTES).contains(&plan.max_source_bytes)
        || !(1..=100_000).contains(&plan.max_steps)
    {
        return Err(ClientError::Budget);
    }
    if let Some(token) = &plan.profile_token {
        wire::get_snapshot_uri_request(token)?;
    }
    let mut progress = Progress::default();
    let now = progress.now(plan, cx)?;
    if plan.deadline_ns.saturating_sub(now) > MAX_TIMEOUT_NS {
        return Err(ClientError::Deadline);
    }
    let response = soap(plan, &wire::get_profiles_request(), cx, &mut progress)?;
    let profiles = wire::parse_profiles(soap_body(&response)?)?;
    let profile = match plan.profile_token.as_deref() {
        Some(token) => profiles.into_iter().find(|profile| profile.token == token),
        None => profiles.into_iter().find(|profile| profile.video.is_some()),
    }
    .filter(|profile| profile.video.is_some())
    .ok_or(ClientError::Profile)?;
    drop(response);
    let response = soap(
        plan,
        &wire::get_snapshot_uri_request(&profile.token)?,
        cx,
        &mut progress,
    )?;
    let uri = wire::parse_snapshot_uri(soap_body(&response)?)?;
    drop(response);
    let route = plan
        .media
        .snapshot(&uri.uri)
        .map_err(|_| ClientError::Scope)?;
    let limits = HttpLimits {
        body_bytes: plan.max_source_bytes,
        wire_bytes: (plan.max_source_bytes * 2).max(65536),
        io_bytes: 16384,
        io_calls: 100_000,
        ..HttpLimits::default()
    };
    let now = progress.now(plan, cx)?;
    let exchange = HttpExchange::connect_snapshot(route.clone(), limits, now, plan.deadline_ns, cx)
        .map_err(transport_error)?;
    let response = progress.finish_exchange(plan, cx, exchange)?;
    status(&response)?;
    if response
        .content_type()
        .is_some_and(|value| !mime(value, "image/jpeg"))
    {
        return Err(ClientError::Unsupported);
    }
    let jpeg = response.into_body();
    let limits = MjpegLimits {
        max_input_bytes: plan.max_source_bytes,
        max_frame_bytes: plan.max_source_bytes,
        max_frames: 1,
        ..MjpegLimits::default()
    };
    let now = progress.now(plan, cx)?;
    cx.checkpoint(&route, HttpOperation::Parse, now, plan.deadline_ns)
        .map_err(denial_error)?;
    let scan = split_jpeg_stream(&jpeg, &limits, None).map_err(|_| ClientError::Unsupported)?;
    if scan.frames.len() != 1
        || !scan.omissions.is_empty()
        || !scan.findings.is_empty()
        || scan.frames[0].start_offset != 0
        || scan.frames[0].end_offset != jpeg.len()
        || scan.frames[0].sof.is_none()
        || !scan.frames[0].has_eoi
        || scan.frames[0].is_truncated
    {
        return Err(ClientError::Unsupported);
    }
    let source_digest = ContentDigest::sha256(&jpeg);
    let now = progress.now(plan, cx)?;
    cx.checkpoint(&route, HttpOperation::Release, now, plan.deadline_ns)
        .map_err(denial_error)?;
    Ok(Snapshot {
        profile,
        uri,
        jpeg,
        source_digest,
        network: progress.network,
    })
}

#[derive(Default)]
struct Progress {
    last_ns: u64,
    steps: u32,
    network: HttpTotals,
}

impl Progress {
    fn now(&mut self, plan: &SnapshotPlan, cx: &impl OnvifContext) -> Result<u64, ClientError> {
        self.steps = self.steps.checked_add(1).ok_or(ClientError::Budget)?;
        if self.steps > plan.max_steps {
            return Err(ClientError::Budget);
        }
        let now = cx.now_ns()?;
        if now < self.last_ns {
            return Err(ClientError::Clock);
        }
        if now >= plan.deadline_ns {
            return Err(ClientError::Deadline);
        }
        self.last_ns = now;
        Ok(now)
    }

    fn finish_exchange(
        &mut self,
        plan: &SnapshotPlan,
        cx: &impl OnvifContext,
        mut exchange: HttpExchange,
    ) -> Result<HttpResponse, ClientError> {
        loop {
            let now = self.now(plan, cx)?;
            match exchange.step(now, cx).map_err(transport_error)? {
                HttpProgress::Advanced => {}
                HttpProgress::Pending => cx.wait(plan.deadline_ns)?,
                HttpProgress::Complete => {
                    let now = self.now(plan, cx)?;
                    let response = exchange.take_response(now, cx).map_err(transport_error)?;
                    let totals = exchange.totals();
                    self.network.io_calls += totals.io_calls;
                    self.network.read_calls += totals.read_calls;
                    self.network.write_calls += totals.write_calls;
                    self.network.sent_bytes += totals.sent_bytes;
                    self.network.received_bytes += totals.received_bytes;
                    return Ok(response);
                }
            }
        }
    }
}

fn soap(
    plan: &SnapshotPlan,
    request: &SoapRequest,
    cx: &impl OnvifContext,
    progress: &mut Progress,
) -> Result<HttpResponse, ClientError> {
    let now = progress.now(plan, cx)?;
    let exchange = HttpExchange::connect(
        plan.media.clone(),
        request,
        None,
        HttpLimits::default(),
        now,
        plan.deadline_ns,
        cx,
    )
    .map_err(transport_error)?;
    progress.finish_exchange(plan, cx, exchange)
}

fn status(response: &HttpResponse) -> Result<(), ClientError> {
    match response.status() {
        200 => Ok(()),
        401 => Err(ClientError::AuthenticationRequired),
        code => Err(ClientError::HttpStatus(code)),
    }
}

fn soap_body(response: &HttpResponse) -> Result<&[u8], ClientError> {
    status(response)?;
    if response
        .content_type()
        .is_some_and(|value| !mime(value, "application/soap+xml") && !mime(value, "text/xml"))
    {
        return Err(ClientError::Unsupported);
    }
    Ok(response.body())
}

fn mime(value: &str, expected: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
}

fn denial_error(denial: HttpDenial) -> ClientError {
    match denial {
        HttpDenial::Cancelled => ClientError::Cancelled,
        HttpDenial::Deadline => ClientError::Deadline,
        HttpDenial::Budget => ClientError::Budget,
        HttpDenial::Unauthorized | HttpDenial::Revoked => ClientError::Authority,
    }
}

fn transport_error(error: HttpError) -> ClientError {
    match error {
        HttpError::Denied(denial) => denial_error(denial),
        HttpError::Deadline => ClientError::Deadline,
        HttpError::ClockReversed => ClientError::Clock,
        other => ClientError::Http(other),
    }
}
