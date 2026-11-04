#![forbid(unsafe_code)]
//! Pure approval binding and JSON rendering for one explicitly selected site probe.
//!
//! This module performs no filesystem, credential, clock or network access. The
//! native adapter consumes this exact plan only after the same approval check.

use fss_core::{BudgetVector, CanonicalEncode, CanonicalEncoder, ContentDigest, PrincipalId};
use fss_packet::avc::{AvcAssemblyLimits, AvcSyntaxLimits};
use fss_packet::hevc::{HevcAssemblyLimits, HevcConfigurationLimits};
use fss_packet::jpeg::{JPEG_RECONSTRUCTION_PROFILE, JpegLimits};
use fss_packet::{H264Limits, H265Limits, PacketLimits, StreamKey};
use fss_reference::rtsp::client::ClientConfig;
use fss_reference::rtsp::framed::{
    MAX_WIRE_BODY, MAX_WIRE_BUFFER, MAX_WIRE_CHUNK, MAX_WIRE_HEADERS, WIRE_LIFETIME_NS,
};
use fss_reference::rtsp::selection::{
    MAX_SELECTION_BYTES, MAX_SELECTION_MEDIA, MAX_SELECTION_PAYLOADS,
};
use fss_reference::rtsp::tcp::{TcpBinding, TcpLimits, TcpSecurityPolicy};
use fss_reference::site::probe_observation::{
    MAX_PROBE_PICTURES, MAX_PROBE_RTP_BYTES, MAX_PROBE_RTP_PACKETS,
};
use fss_reference::site::{ProbeCodec, SiteManifest, SiteProbeReceipt, SourceKind};

use crate::json_output::{array, object, string};

/// Successful output projection. Neither form includes raw media or credential bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeOutput {
    /// Existing receipt array accepted directly by site planning.
    Receipts,
    /// Receipt array plus explicit native session accounting and omissions.
    Session,
}

impl ProbeOutput {
    /// Stable command-line, preview and canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Receipts => "receipts",
            Self::Session => "session",
        }
    }
}

/// One explicit source selection and bounded observation, before any network work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteProbeOptions {
    /// Exact source identifier from the manifest.
    pub source: String,
    /// Explicit codec; probing does not select a fallback.
    pub codec: ProbeCodec,
    /// Original SDP media ordinal.
    pub media_index: usize,
    /// Optional exact RTP payload: dynamic 96..127, or static 26 for JPEG.
    pub payload_type: Option<u8>,
    /// Even RTP channel offered with its consecutive RTCP channel.
    pub rtp_channel: u8,
    /// Minimum native syntax-confirmed picture groups before closing the session.
    /// Atomic RTP aggregation may confirm more, within the hard native picture bound.
    pub observe_frames: u32,
    /// Complete operation deadline, including authentication and TEARDOWN.
    pub timeout_ms: u64,
    /// Audit principal; does not authenticate an identity.
    pub principal: String,
    /// Requested successful output projection, independently bound into approval.
    pub output: ProbeOutput,
    /// Exact separately supplied preview digest. None means no network or secrets.
    pub approve: Option<ContentDigest>,
}

const PLAN_ERROR: &str = "ERR-SITE-PROBE-PLAN-001";
const APPROVAL_ERROR: &str = "ERR-SITE-PROBE-APPROVAL-001";
const POLICY: &str = "site-native-probe:v1:one-source:rtsp-nvr:explicit-avc-hevc:\
exact-plaintext-route:source-specific-ingress:learn-one-ssrc:options-describe-setup-play:\
native-syntax-confirmed-prefix:minimum-picture-target:explicit-unverified-tail-omission:\
progressive-only:constant-90khz-cadence:teardown-ack-required:declared-working-reservation:\
no-decoded-pixels:no-source-retention:no-archive:no-rights-grant:no-retry:no-redirect";
const JPEG_POLICY: &str = "site-native-probe:v1:one-source:rtsp-nvr:explicit-jpeg:\
exact-plaintext-route:source-specific-ingress:learn-one-ssrc:options-describe-setup-play:\
native-rfc2435-whole-frame-prefix:minimum-picture-target:explicit-unfinished-fragment-omission:\
constant-90khz-cadence:teardown-ack-required:declared-working-reservation:\
no-entropy-decode:no-decoded-pixels:no-source-retention:no-archive:no-rights-grant:no-retry:no-redirect";
pub(crate) const MAX_STEPS: u64 = fss_reference::site::live_probe::MAX_PROBE_STEPS;
pub(crate) const MAX_IO_CALLS: u64 = MAX_STEPS;
pub(crate) const MAX_RECEIVED_BYTES: u64 = MAX_PROBE_RTP_BYTES + 256 * 1024;
pub(crate) const MAX_SENT_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_REQUEST_BYTES: usize = 16 * 1024;
pub(crate) const SOCKET_CHUNK_BYTES: usize = MAX_WIRE_CHUNK;
pub(crate) const WAIT_QUANTUM_NS: u64 = 1_000_000;
pub(crate) const MAX_CREDENTIAL_BYTES: usize = 256 + 1 + 1024 + 1;
pub(crate) const MAX_SECRET_IO_CALLS: usize = 16;
/// Conservative logical native working reservation, not measured allocator/RSS usage.
pub(crate) const MEMORY_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const STORAGE_OPERATIONS: u64 = MAX_STEPS * 64;
const REQUEST_TIMEOUT_NS: u64 = 5_000_000_000;
const DEFAULT_SESSION_SECONDS: u32 = 60;

fn policy(codec: ProbeCodec) -> &'static str {
    match codec {
        ProbeCodec::Avc | ProbeCodec::Hevc => POLICY,
        ProbeCodec::Jpeg => JPEG_POLICY,
    }
}

impl SiteProbeOptions {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if self.source.is_empty()
            || self.source.len() > 128
            || !self
                .source
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            || self.media_index > 63
            || self.rtp_channel % 2 != 0
            || self.payload_type.is_some_and(|p| {
                !(96..=127).contains(&p) && !(self.codec == ProbeCodec::Jpeg && p == 26)
            })
            || !(3..=MAX_PROBE_PICTURES).contains(&self.observe_frames)
            || !(100..=60_000).contains(&self.timeout_ms)
            || self.principal.len() > 256
            || PrincipalId::parse(&self.principal).is_err()
        {
            return Err(PLAN_ERROR);
        }
        Ok(())
    }
}

pub(crate) struct ProbePlan<'a> {
    pub(super) manifest: &'a SiteManifest,
    pub(super) options: &'a SiteProbeOptions,
    pub(super) source_index: usize,
    pub(super) approval: ContentDigest,
    pub(super) binding: TcpBinding,
    pub(super) protocol: ClientConfig,
    pub(super) transport: TcpLimits,
    pub(super) allowance: BudgetVector,
    observer_limits_digest: ContentDigest,
}

impl<'a> ProbePlan<'a> {
    pub(super) fn new(
        manifest: &'a SiteManifest,
        options: &'a SiteProbeOptions,
    ) -> Result<Self, &'static str> {
        manifest.validate().map_err(|_| PLAN_ERROR)?;
        options.validate()?;
        let source_index = manifest
            .sources
            .iter()
            .position(|source| source.source_id == options.source)
            .ok_or(PLAN_ERROR)?;
        let source = &manifest.sources[source_index];
        if !matches!(source.kind, SourceKind::Rtsp | SourceKind::NvrChannel)
            || !source.owner_authorized
            || !source.plaintext
        {
            return Err(PLAN_ERROR);
        }
        let manifest_digest = manifest.digest().map_err(|_| PLAN_ERROR)?;
        // Use the same stable stream/site/source identity as the site capture compiler.
        // Distinct cameras must not inherit one ingress merely because they share a manifest.
        let mut identity = CanonicalEncoder::new();
        identity.text("fss.site_source_identity.v1");
        identity.text("stream");
        identity.text(&manifest.site_id);
        identity.text(&source.source_id);
        let stream = ContentDigest::sha256(&identity.finish_checked().map_err(|_| PLAN_ERROR)?);
        let ingress = u128::from_be_bytes(stream.bytes()[..16].try_into().map_err(|_| PLAN_ERROR)?);
        if ingress == 0 {
            return Err(PLAN_ERROR);
        }
        let binding = TcpBinding::new(
            StreamKey {
                ingress,
                generation: source.generation,
                ssrc: 0,
            },
            source.peer,
            &source.authority,
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )
        .map_err(|_| PLAN_ERROR)?
        .with_auto_ssrc();
        let timeout_ns = options
            .timeout_ms
            .checked_mul(1_000_000)
            .ok_or(PLAN_ERROR)?;
        let protocol = ClientConfig {
            presentation_uri: format!(
                "rtsp://{}{}",
                source.authority,
                source.presentation.as_deref().ok_or(PLAN_ERROR)?
            ),
            control_root_uri: format!(
                "rtsp://{}{}",
                source.authority,
                source.control_root.as_deref().ok_or(PLAN_ERROR)?
            ),
            media_index: options.media_index,
            channels: (options.rtp_channel, options.rtp_channel + 1),
            response_timeout_ns: timeout_ns.min(REQUEST_TIMEOUT_NS),
            default_session_timeout_seconds: DEFAULT_SESSION_SECONDS,
        };
        let transport = TcpLimits {
            max_received_bytes: MAX_RECEIVED_BYTES,
            max_sent_bytes: MAX_SENT_BYTES,
            max_io_calls: MAX_IO_CALLS,
            max_request_bytes: MAX_REQUEST_BYTES,
            chunk_bytes: SOCKET_CHUNK_BYTES,
            connect_timeout_ns: timeout_ns.min(REQUEST_TIMEOUT_NS),
        };
        // Validate the actual protocol grammar before presenting or accepting approval.
        let codec = match options.codec {
            ProbeCodec::Avc => fss_reference::rtsp::client::ClientCodec::H264,
            ProbeCodec::Hevc => fss_reference::rtsp::client::ClientCodec::H265,
            ProbeCodec::Jpeg => fss_reference::rtsp::client::ClientCodec::Jpeg,
        };
        let _ = match options.payload_type {
            None => {
                fss_reference::rtsp::client::RtspClientSession::with_codec(protocol.clone(), codec)
            }
            Some(payload) => {
                fss_reference::rtsp::client::RtspClientSession::with_codec_and_payload_type(
                    protocol.clone(),
                    codec,
                    payload,
                )
            }
        }
        .map_err(|_| PLAN_ERROR)?;
        transport.validate().map_err(|_| PLAN_ERROR)?;
        let allowance = BudgetVector::builder()
            .bytes(MEMORY_BYTES)
            .network_bytes(
                MAX_RECEIVED_BYTES
                    .checked_add(MAX_SENT_BYTES)
                    .ok_or(PLAN_ERROR)?,
            )
            .storage_operations(STORAGE_OPERATIONS)
            .latency_ms(options.timeout_ms)
            .build()
            .map_err(|_| PLAN_ERROR)?;
        let observer_limits_digest = observer_limits_digest(options.codec)?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.site_probe_plan.v1");
        encoder.text(policy(options.codec));
        encoder.digest(manifest_digest);
        encoder.u64(source_index as u64);
        encoder.digest(stream);
        encoder.bytes(&ingress.to_be_bytes());
        encoder.u64(source.generation);
        encoder.text("ssrc:learn-once");
        encoder.text("transport:owner-approved-plaintext");
        encoder.text(options.codec.as_str());
        encoder.u64(options.media_index as u64);
        match options.payload_type {
            None => encoder.tag(0),
            Some(payload) => {
                encoder.tag(1);
                encoder.u8(payload);
            }
        }
        encoder.u8(options.rtp_channel);
        encoder.u8(protocol.channels.1);
        encoder.u32(options.observe_frames);
        encoder.u64(options.timeout_ms);
        encoder.text(&options.principal);
        encoder.text(options.output.as_str());
        encoder.u64(MAX_STEPS);
        encoder.u64(transport.max_received_bytes);
        encoder.u64(transport.max_sent_bytes);
        encoder.u64(transport.max_io_calls);
        encoder.u64(transport.max_request_bytes as u64);
        encoder.u64(transport.chunk_bytes as u64);
        encoder.u64(transport.connect_timeout_ns);
        encoder.u64(protocol.response_timeout_ns);
        encoder.u32(protocol.default_session_timeout_seconds);
        encoder.u64(MAX_CREDENTIAL_BYTES as u64);
        encoder.u64(MAX_SECRET_IO_CALLS as u64);
        encoder.u64(WAIT_QUANTUM_NS);
        encoder.u64(crate::site_cmd::MAX_SITE_OUTPUT_BYTES as u64);
        encoder.digest(observer_limits_digest);
        allowance.encode_canonical(&mut encoder);
        let approval = ContentDigest::sha256(&encoder.finish_checked().map_err(|_| PLAN_ERROR)?);
        Ok(Self {
            manifest,
            options,
            source_index,
            approval,
            binding,
            protocol,
            transport,
            allowance,
            observer_limits_digest,
        })
    }

    /// Check only the caller's exact approval selection; this grants no rights.
    /// False keeps the request in preview mode, while a mismatch is a refusal.
    pub(super) fn check_approval(&self) -> Result<bool, &'static str> {
        match self.options.approve {
            None => Ok(false),
            Some(approval) if approval == self.approval => Ok(true),
            Some(_) => Err(APPROVAL_ERROR),
        }
    }

    pub(super) fn preview(&self) -> Result<String, &'static str> {
        let source = &self.manifest.sources[self.source_index];
        let auth = source.authentication.as_ref().map_or_else(
            || "null".to_owned(),
            |auth| {
                object(&[
                    (
                        "credential_file",
                        string(auth.credential_file.to_str().unwrap_or("")),
                    ),
                    (
                        "realm_digest",
                        string(&ContentDigest::sha256(auth.realm.as_bytes()).to_text()),
                    ),
                    ("legacy_md5", auth.legacy_md5.to_string()),
                    ("legacy_no_qop", auth.legacy_no_qop.to_string()),
                ])
            },
        );
        Ok(object(&[
            ("schema", string("fss.site_probe_plan.v1")),
            ("status", string("requires_approval")),
            ("policy", string(policy(self.options.codec))),
            ("approval", string(&self.approval.to_text())),
            (
                "manifest_digest",
                string(&self.manifest.digest().map_err(|_| PLAN_ERROR)?.to_text()),
            ),
            ("site_id", string(&self.manifest.site_id)),
            ("source_id", string(&source.source_id)),
            ("source_index", self.source_index.to_string()),
            ("source_generation", source.generation.to_string()),
            ("ingress", string(&self.binding.key().ingress.to_string())),
            ("ssrc_policy", string("learn_once")),
            ("peer", string(&source.peer.to_string())),
            ("authority", string(&source.authority)),
            (
                "presentation",
                string(source.presentation.as_deref().ok_or(PLAN_ERROR)?),
            ),
            (
                "control_root",
                string(source.control_root.as_deref().ok_or(PLAN_ERROR)?),
            ),
            ("codec", string(self.options.codec.as_str())),
            ("media_index", self.options.media_index.to_string()),
            (
                "payload_type",
                self.options
                    .payload_type
                    .map_or_else(|| "null".to_owned(), |p| p.to_string()),
            ),
            ("rtp_channel", self.options.rtp_channel.to_string()),
            ("observe_frames", self.options.observe_frames.to_string()),
            (
                "observe_frames_meaning",
                string("minimum_native_picture_groups"),
            ),
            ("max_observed_frames", MAX_PROBE_PICTURES.to_string()),
            (
                "unverified_tail_policy",
                string("count_and_omit_after_confirmed_prefix"),
            ),
            ("output", string(self.options.output.as_str())),
            ("timeout_ms", self.options.timeout_ms.to_string()),
            ("principal", string(&self.options.principal)),
            ("authentication", auth),
            (
                "commands",
                array(&["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"].map(string)),
            ),
            ("max_received_bytes", MAX_RECEIVED_BYTES.to_string()),
            ("max_sent_bytes", MAX_SENT_BYTES.to_string()),
            ("max_io_calls", MAX_IO_CALLS.to_string()),
            ("max_steps", MAX_STEPS.to_string()),
            (
                "max_request_bytes",
                self.transport.max_request_bytes.to_string(),
            ),
            ("chunk_bytes", self.transport.chunk_bytes.to_string()),
            (
                "connect_timeout_ns",
                self.transport.connect_timeout_ns.to_string(),
            ),
            (
                "response_timeout_ns",
                self.protocol.response_timeout_ns.to_string(),
            ),
            (
                "default_session_timeout_seconds",
                self.protocol.default_session_timeout_seconds.to_string(),
            ),
            ("max_rtp_packets", MAX_PROBE_RTP_PACKETS.to_string()),
            ("max_rtp_bytes", MAX_PROBE_RTP_BYTES.to_string()),
            ("wait_quantum_ns", WAIT_QUANTUM_NS.to_string()),
            ("max_credential_bytes", MAX_CREDENTIAL_BYTES.to_string()),
            ("max_secret_io_calls", MAX_SECRET_IO_CALLS.to_string()),
            (
                "observer_limits_digest",
                string(&self.observer_limits_digest.to_text()),
            ),
            (
                "runtime_allowance",
                crate::agent_json::budget(&self.allowance),
            ),
            (
                "reservation_basis",
                string("declared_logical_working_bound_not_measured_rss"),
            ),
            ("device_contacted", "false".to_owned()),
            ("credentials_read", "false".to_owned()),
            ("source_retained", "false".to_owned()),
            ("capture_authorized", "false".to_owned()),
            ("rights_verdict_verified", "false".to_owned()),
            ("teardown_ack_required", "true".to_owned()),
        ]))
    }
}

/// Bind the exact public native defaults used by the shared syntax observer.
/// This is a configuration identity, not a decoder or complete-picture certificate.
fn observer_limits_digest(codec: ProbeCodec) -> Result<ContentDigest, &'static str> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.site_probe_native_observer_limits.v1");
    encoder.text(codec.as_str());
    encoder.u32(MAX_PROBE_PICTURES);
    encoder.u32(MAX_PROBE_RTP_PACKETS);
    encoder.u64(MAX_PROBE_RTP_BYTES);
    for value in [
        MAX_WIRE_CHUNK as u64,
        MAX_WIRE_HEADERS as u64,
        MAX_WIRE_BODY as u64,
        MAX_WIRE_BUFFER as u64,
        WIRE_LIFETIME_NS,
        MAX_SELECTION_BYTES as u64,
        MAX_SELECTION_MEDIA as u64,
        MAX_SELECTION_PAYLOADS as u64,
    ] {
        encoder.u64(value);
    }
    let packets = PacketLimits::default();
    encoder.u64(packets.max_packet_bytes as u64);
    encoder.u64(packets.max_extension_bytes as u64);
    encoder.u64(packets.max_rtcp_packets as u64);
    match codec {
        ProbeCodec::Avc => {
            let packet = H264Limits::default();
            encoder.u64(packet.max_nal_bytes as u64);
            encoder.u64(packet.max_packet_nals as u64);
            encoder.u64(packet.max_fragment_packets as u64);
            encoder.u64(packet.max_pending_age_ns);
            let syntax = AvcSyntaxLimits::default();
            encoder.u64(syntax.max_nal_bytes as u64);
            encoder.u64(syntax.max_parameter_set_bytes as u64);
            encoder.u32(syntax.max_width);
            encoder.u32(syntax.max_height);
            encoder.u64(syntax.max_luma_samples);
            encoder.u32(syntax.max_reference_frames);
            encoder.u64(syntax.max_slice_identity_bits as u64);
            let assembly = AvcAssemblyLimits::default();
            encoder.u64(assembly.max_nals as u64);
            encoder.u64(assembly.max_bytes as u64);
            encoder.u64(assembly.max_age_ns);
        }
        ProbeCodec::Hevc => {
            let packet = H265Limits::default();
            encoder.u64(packet.max_nal_bytes as u64);
            encoder.u64(packet.max_packet_nals as u64);
            encoder.u64(packet.max_fragment_packets as u64);
            encoder.u64(packet.max_pending_age_ns);
            let configuration = HevcConfigurationLimits::default();
            encoder.u64(configuration.max_parameter_bytes as u64);
            encoder.u32(configuration.max_width);
            encoder.u32(configuration.max_height);
            encoder.u64(configuration.max_luma_samples);
            let assembly = HevcAssemblyLimits::default();
            encoder.u64(assembly.max_nals as u64);
            encoder.u64(assembly.max_bytes as u64);
            encoder.u64(assembly.max_source_spans as u64);
            encoder.u64(assembly.max_age_ns);
            // Shared full-SPS validation's fixed RBSP ceiling and progressive-only policy.
            encoder.text("native-hevc-full-sps:rbsp-16384:progressive-only:v1");
        }
        ProbeCodec::Jpeg => {
            let jpeg = JpegLimits::default();
            encoder.u64(jpeg.max_frame_bytes as u64);
            encoder.u64(jpeg.max_fragment_packets as u64);
            encoder.u64(jpeg.max_pending_age_ns);
            encoder.u64(jpeg.max_cached_quantizers as u64);
            encoder.u32(u32::from(jpeg.max_dimension));
            encoder.text(JPEG_RECONSTRUCTION_PROFILE);
        }
    }
    Ok(ContentDigest::sha256(
        &encoder.finish_checked().map_err(|_| PLAN_ERROR)?,
    ))
}

pub(super) fn receipt_json(receipt: &SiteProbeReceipt) -> String {
    let parameters: Vec<_> = receipt
        .parameter_set_digests
        .iter()
        .map(|digest| string(&digest.to_text()))
        .collect();
    object(&[
        (
            "schema",
            string(fss_reference::site::SITE_PROBE_RECEIPT_SCHEMA),
        ),
        ("site_id", string(&receipt.site_id)),
        ("source_id", string(&receipt.source_id)),
        (
            "manifest_digest",
            string(&receipt.manifest_digest.to_text()),
        ),
        ("source_generation", receipt.source_generation.to_string()),
        ("peer", string(&receipt.peer.to_string())),
        ("authority", string(&receipt.authority)),
        ("presentation", string(&receipt.presentation)),
        ("control_root", string(&receipt.control_root)),
        ("media_index", receipt.media_index.to_string()),
        ("rtp_channel", receipt.rtp_channel.to_string()),
        ("rtcp_channel", receipt.rtcp_channel.to_string()),
        ("sdp_digest", string(&receipt.sdp_digest.to_text())),
        ("codec", string(receipt.codec.as_str())),
        ("payload_type", receipt.payload_type.to_string()),
        ("ssrc", receipt.ssrc.to_string()),
        (
            "frame_duration_ticks",
            receipt.frame_duration_ticks.to_string(),
        ),
        ("clock_rate_hz", receipt.clock_rate_hz.to_string()),
        ("observed_frames", receipt.observed_frames.to_string()),
        (
            "first_rtp_timestamp",
            receipt.first_rtp_timestamp.to_string(),
        ),
        ("last_rtp_timestamp", receipt.last_rtp_timestamp.to_string()),
        ("parameter_set_digests", array(&parameters)),
        ("server_identity", string(&receipt.server_identity)),
    ])
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
