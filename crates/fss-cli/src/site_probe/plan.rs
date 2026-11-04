#![forbid(unsafe_code)]
//! Pure approval binding and JSON rendering for one explicitly selected site probe.
//!
//! This module performs no filesystem, credential, clock or network access. The
//! native adapter consumes this exact plan only after the same approval check.

use fss_core::{CanonicalEncoder, ContentDigest, PrincipalId};
use fss_packet::StreamKey;
use fss_reference::rtsp::client::ClientConfig;
use fss_reference::rtsp::tcp::{TcpBinding, TcpLimits, TcpSecurityPolicy};
use fss_reference::site::probe_observation::{MAX_PROBE_PICTURES, MAX_PROBE_RTP_BYTES};
use fss_reference::site::{ProbeCodec, SiteManifest, SiteProbeReceipt, SourceKind};

use crate::json_output::{array, object, string};

/// One explicit source selection and bounded observation, before any network work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteProbeOptions {
    /// Exact source identifier from the manifest.
    pub source: String,
    /// Explicit codec; probing does not select a fallback.
    pub codec: ProbeCodec,
    /// Original SDP media ordinal.
    pub media_index: usize,
    /// Optional exact dynamic RTP payload selection.
    pub payload_type: Option<u8>,
    /// Even RTP channel offered with its consecutive RTCP channel.
    pub rtp_channel: u8,
    /// Marked picture boundaries required before closing the session.
    pub observe_frames: u32,
    /// Complete operation deadline, including authentication and TEARDOWN.
    pub timeout_ms: u64,
    /// Audit principal; does not authenticate an identity.
    pub principal: String,
    /// Exact separately supplied preview digest. None means no network or secrets.
    pub approve: Option<ContentDigest>,
}

const PLAN_ERROR: &str = "ERR-SITE-PROBE-PLAN-001";
const APPROVAL_ERROR: &str = "ERR-SITE-PROBE-APPROVAL-001";
const POLICY: &str = "site-native-probe:v1:one-source:rtsp-nvr:explicit-avc-hevc:\
exact-route:options-describe-setup-play:strict-rtp-cadence:teardown-ack-required:\
no-source-retention:no-rights-grant:no-retry";
pub(crate) const MAX_STEPS: u64 = fss_reference::site::live_probe::MAX_PROBE_STEPS;
pub(crate) const MAX_IO_CALLS: u64 = MAX_STEPS;
pub(crate) const MAX_RECEIVED_BYTES: u64 = MAX_PROBE_RTP_BYTES + 256 * 1024;
pub(crate) const MAX_SENT_BYTES: u64 = 64 * 1024;

impl SiteProbeOptions {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if self.source.is_empty()
            || self.source.len() > 128
            || !self
                .source
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            || !matches!(self.codec, ProbeCodec::Avc | ProbeCodec::Hevc)
            || self.media_index > 63
            || self.rtp_channel % 2 != 0
            || self.payload_type.is_some_and(|p| !(96..=127).contains(&p))
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
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.site_probe_plan.v1");
        encoder.text(POLICY);
        encoder.digest(manifest.digest().map_err(|_| PLAN_ERROR)?);
        encoder.u64(source_index as u64);
        encoder.text(options.codec.as_str());
        encoder.u64(options.media_index as u64);
        match options.payload_type {
            None => encoder.tag(0),
            Some(p) => {
                encoder.tag(1);
                encoder.u8(p);
            }
        }
        encoder.u8(options.rtp_channel);
        encoder.u32(options.observe_frames);
        encoder.u64(options.timeout_ms);
        encoder.text(&options.principal);
        for limit in [MAX_STEPS, MAX_IO_CALLS, MAX_RECEIVED_BYTES, MAX_SENT_BYTES] {
            encoder.u64(limit);
        }
        let approval = ContentDigest::sha256(&encoder.finish_checked().map_err(|_| PLAN_ERROR)?);
        let id = manifest.digest().map_err(|_| PLAN_ERROR)?.bytes();
        let ingress = u128::from_be_bytes(id[..16].try_into().map_err(|_| PLAN_ERROR)?).max(1);
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
        let timeout_ns = options.timeout_ms * 1_000_000;
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
            response_timeout_ns: timeout_ns.min(5_000_000_000),
            default_session_timeout_seconds: 60,
        };
        let transport = TcpLimits {
            max_received_bytes: MAX_RECEIVED_BYTES,
            max_sent_bytes: MAX_SENT_BYTES,
            max_io_calls: MAX_IO_CALLS,
            max_request_bytes: 16 * 1024,
            chunk_bytes: 4096,
            connect_timeout_ns: timeout_ns.min(5_000_000_000),
        };
        // Validate the actual protocol grammar before presenting or accepting approval.
        let codec = match options.codec {
            ProbeCodec::Avc => fss_reference::rtsp::client::ClientCodec::H264,
            ProbeCodec::Hevc => fss_reference::rtsp::client::ClientCodec::H265,
            ProbeCodec::Jpeg => return Err(PLAN_ERROR),
        };
        fss_reference::rtsp::client::RtspClientSession::with_codec(protocol.clone(), codec)
            .map_err(|_| PLAN_ERROR)?;
        Ok(Self {
            manifest,
            options,
            source_index,
            approval,
            binding,
            protocol,
            transport,
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
            ("policy", string(POLICY)),
            ("approval", string(&self.approval.to_text())),
            (
                "manifest_digest",
                string(&self.manifest.digest().map_err(|_| PLAN_ERROR)?.to_text()),
            ),
            ("site_id", string(&self.manifest.site_id)),
            ("source_id", string(&source.source_id)),
            ("source_index", self.source_index.to_string()),
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
            ("device_contacted", "false".to_owned()),
            ("credentials_read", "false".to_owned()),
            ("source_retained", "false".to_owned()),
            ("capture_authorized", "false".to_owned()),
            ("rights_verdict_verified", "false".to_owned()),
            ("teardown_ack_required", "true".to_owned()),
        ]))
    }
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
