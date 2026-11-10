#![forbid(unsafe_code)]
//! Protected recorder discovery for one separately approved native replay capture.
//! Full observed information stays private; URI lifetime and source coverage stay unknown.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Component, PathBuf};

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_reference::onvif::client::recording::RecordingReplay;
use fss_reference::onvif::client::{RtspScope, validate_stream_uri};
use fss_reference::onvif::wire::{
    MAX_RECORDING_INFORMATION_BYTES, RecordingInformation, RecordingRangeAssessment,
};
use fss_reference::rtsp::client::{replay::ReplayWindow, validated_uri_parts};
use fss_reference::rtsp::recording_replay::{OnvifReplaySource, ReplayCodec};

use crate::json_input::{self, Value};
use crate::json_output::{object, string};
use crate::onvif_plan::ProtectedOnvifInput;

/// Closed private replay schema, separate from live Media1/Media2 handoffs.
pub const ONVIF_REPLAY_HANDOFF_SCHEMA: &str = "fss.onvif_recording_replay_handoff.v1";
/// Full canonical information is hex encoded in bounded chunks, never truncated.
pub const MAX_ONVIF_REPLAY_HANDOFF_BYTES: usize = 2 * MAX_RECORDING_INFORMATION_BYTES + 8192;
/// Payload-free protected-selection refusal.
pub const ERR_ONVIF_REPLAY_HANDOFF: &str = "ERR-ONVIF-REPLAY-HANDOFF-001";
/// Payload-free capture-side protected-input refusal.
pub const ERR_CAPTURE_ONVIF_REPLAY: &str = "ERR-CAPTURE-ONVIF-REPLAY-HANDOFF-001";
/// Exact outer approval domain.
pub const ONVIF_REPLAY_APPROVAL_DOMAIN: &str = "fss.rtsp_from_onvif_replay_plan.v1";
const POLICY: &str = "protected-onvif-recording:explicit-window-and-codec:unknown-uri-lifetime:separate-native-capture-approval:exact-file-revalidation:no-live-fallback:v1";
const INFORMATION_CHUNK_BYTES: usize = 16 * 1024;
const MAX_ARGUMENTS: usize = 128;

/// Exact private selection. Deliberately has no Debug/Display implementation.
pub struct ReplayHandoff {
    onboarding_plan: ContentDigest,
    services_digest: ContentDigest,
    services_observation_digest: ContentDigest,
    information: RecordingInformation,
    window: ReplayWindow,
    codec: ReplayCodec,
    peer: SocketAddr,
    authority: String,
    uri: String,
    uri_observation: ContentDigest,
}

impl ReplayHandoff {
    /// Construct from the selected native observation and independent operator choices.
    pub fn from_selected(
        selected: &RecordingReplay,
        onboarding_plan: ContentDigest,
        window: ReplayWindow,
        codec: ReplayCodec,
    ) -> Result<Self, &'static str> {
        let result = Self {
            onboarding_plan,
            services_digest: selected.services.digest().map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)?,
            services_observation_digest: selected.services.response_body_digest,
            information: selected.information.clone(),
            window,
            codec,
            peer: selected.peer,
            authority: selected.authority.clone(),
            uri: selected.uri.clone(),
            uri_observation: selected.uri_response_digest,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), &'static str> {
        if !valid_digest(self.onboarding_plan)
            || !valid_digest(self.services_digest)
            || !valid_digest(self.services_observation_digest)
            || !valid_digest(self.uri_observation)
            || self.uri.len() > 2048
        {
            return Err(ERR_ONVIF_REPLAY_HANDOFF);
        }
        self.information.canonical_bytes().map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)?;
        self.information.validate_requested_window(self.window).map_err(|error| error.code())?;
        validate_stream_uri(&self.uri, &RtspScope {
            peer: self.peer,
            authority: self.authority.clone(),
        }).map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)?;
        Ok(())
    }

    /// Exact requested protocol range, never clipped to advertised extrema.
    #[must_use]
    pub const fn window(&self) -> ReplayWindow { self.window }
    /// Explicit owner codec; descriptions and tokens never choose it.
    #[must_use]
    pub const fn codec(&self) -> ReplayCodec { self.codec }
    /// Exact selected recording identity without exposing the token.
    #[must_use]
    pub fn recording_token_digest(&self) -> ContentDigest {
        ContentDigest::sha256(self.information.token.as_bytes())
    }
    /// Complete canonical information identity, including advertised and unknown bounds.
    pub fn information_digest(&self) -> Result<ContentDigest, &'static str> {
        self.information.digest().map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)
    }
    /// Advertised containment is never media coverage.
    pub fn range_assessment(&self) -> Result<&'static str, &'static str> {
        match self.information.validate_requested_window(self.window).map_err(|error| error.code())? {
            RecordingRangeAssessment::WithinAdvertisedBounds => Ok("within_advertised_bounds"),
            RecordingRangeAssessment::Unknown => Ok("unknown"),
        }
    }
    fn presentation(&self) -> Result<&str, &'static str> {
        validated_uri_parts(&self.uri)
            .map(|(_, path)| path)
            .map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)
    }

    /// Exact private output. Complete canonical information is embedded and checked on read.
    pub fn render(&self) -> Result<String, &'static str> {
        self.validate()?;
        let information = self.information.canonical_bytes().map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)?;
        let chunks: Vec<_> = information.chunks(INFORMATION_CHUNK_BYTES)
            .map(|chunk| string(&hex(chunk))).collect();
        let result = object(&[
            ("schema", string(ONVIF_REPLAY_HANDOFF_SCHEMA)),
            ("onboarding_plan", string(&self.onboarding_plan.to_text())),
            ("services_digest", string(&self.services_digest.to_text())),
            ("services_response_digest", string(&self.services_observation_digest.to_text())),
            ("recording_token_digest", string(&self.recording_token_digest().to_text())),
            ("information_digest", string(&self.information_digest()?.to_text())),
            ("information_canonical_hex", format!("[{}]", chunks.join(","))),
            ("uri_response_digest", string(&self.uri_observation.to_text())),
            ("requested_range", string(&self.window.to_string())),
            ("advertised_range_assessment", string(self.range_assessment()?)),
            ("codec", string(self.codec.as_str())),
            ("peer", string(&self.peer.to_string())),
            ("authority", string(&self.authority)),
            ("uri", string(&self.uri)),
            ("uri_lifetime_basis", string("unknown")),
            ("capture_authorized", "false".into()),
            ("source_evidence", "false".into()),
        ]) + "\n";
        if result.len() > MAX_ONVIF_REPLAY_HANDOFF_BYTES {
            return Err(ERR_ONVIF_REPLAY_HANDOFF);
        }
        Ok(result)
    }

    /// Strict complete decoder. Inventory and live handoffs cannot pass this contract.
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_ONVIF_REPLAY_HANDOFF_BYTES {
            return Err(ERR_ONVIF_REPLAY_HANDOFF);
        }
        let input = json_input::parse(
            std::str::from_utf8(bytes).map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)?
        ).map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)?;
        let fields = input.object().ok_or(ERR_ONVIF_REPLAY_HANDOFF)?;
        const FIELDS: &[&str] = &[
            "schema", "onboarding_plan", "services_digest", "services_response_digest",
            "recording_token_digest", "information_digest", "information_canonical_hex",
            "uri_response_digest", "requested_range", "advertised_range_assessment",
            "codec", "peer", "authority", "uri", "uri_lifetime_basis",
            "capture_authorized", "source_evidence",
        ];
        if fields.len() != FIELDS.len() || fields.keys().any(|key| !FIELDS.contains(&key.as_str())) {
            return Err(ERR_ONVIF_REPLAY_HANDOFF);
        }
        let text = |key: &str| fields.get(key).and_then(Value::text).ok_or(ERR_ONVIF_REPLAY_HANDOFF);
        if text("schema")? != ONVIF_REPLAY_HANDOFF_SCHEMA
            || text("uri_lifetime_basis")? != "unknown"
            || ["capture_authorized", "source_evidence"].iter().any(|key| {
                fields.get(*key).and_then(Value::boolean) != Some(false)
            })
        {
            return Err(ERR_ONVIF_REPLAY_HANDOFF);
        }
        let chunks = fields.get("information_canonical_hex")
            .and_then(Value::array).ok_or(ERR_ONVIF_REPLAY_HANDOFF)?;
        if chunks.is_empty()
            || chunks.len() > MAX_RECORDING_INFORMATION_BYTES.div_ceil(INFORMATION_CHUNK_BYTES)
        {
            return Err(ERR_ONVIF_REPLAY_HANDOFF);
        }
        let mut canonical = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            let chunk = chunk.text().ok_or(ERR_ONVIF_REPLAY_HANDOFF)?;
            if chunk.is_empty() || chunk.len() > 2 * INFORMATION_CHUNK_BYTES
                || !chunk.len().is_multiple_of(2)
                || (index + 1 != chunks.len() && chunk.len() != 2 * INFORMATION_CHUNK_BYTES)
            {
                return Err(ERR_ONVIF_REPLAY_HANDOFF);
            }
            for pair in chunk.as_bytes().chunks_exact(2) {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => Ok(byte - b'0'),
                    b'a'..=b'f' => Ok(byte - b'a' + 10),
                    _ => Err(ERR_ONVIF_REPLAY_HANDOFF),
                };
                canonical.push(digit(pair[0])? * 16 + digit(pair[1])?);
            }
        }
        if canonical.len() > MAX_RECORDING_INFORMATION_BYTES {
            return Err(ERR_ONVIF_REPLAY_HANDOFF);
        }
        let information = RecordingInformation::from_canonical_bytes(&canonical)
            .map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)?;
        let window = ReplayWindow::parse(text("requested_range")?).map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)?;
        if window.to_string() != text("requested_range")? {
            return Err(ERR_ONVIF_REPLAY_HANDOFF);
        }
        let result = Self {
            onboarding_plan: parse_digest(text("onboarding_plan")?)?,
            services_digest: parse_digest(text("services_digest")?)?,
            services_observation_digest: parse_digest(text("services_response_digest")?)?,
            information,
            window,
            codec: match text("codec")? {
                "avc" => ReplayCodec::Avc,
                "hevc" => ReplayCodec::Hevc,
                _ => return Err(ERR_ONVIF_REPLAY_HANDOFF),
            },
            peer: text("peer")?.parse().map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)?,
            authority: text("authority")?.into(),
            uri: text("uri")?.into(),
            uri_observation: parse_digest(text("uri_response_digest")?)?,
        };
        result.validate()?;
        if result.information_digest()? != parse_digest(text("information_digest")?)?
            || result.recording_token_digest() != parse_digest(text("recording_token_digest")?)?
            || result.range_assessment()? != text("advertised_range_assessment")?
        {
            return Err(ERR_ONVIF_REPLAY_HANDOFF);
        }
        Ok(result)
    }
}

fn valid_digest(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && !digest.is_laboratory() && digest.bytes() != [0; 32]
}

/// Parse a canonical nonzero production SHA-256 without reflecting private input.
pub fn parse_digest(text: &str) -> Result<ContentDigest, &'static str> {
    let digest = ContentDigest::parse(text).map_err(|_| ERR_ONVIF_REPLAY_HANDOFF)?;
    if !valid_digest(digest) || digest.to_text() != text {
        return Err(ERR_ONVIF_REPLAY_HANDOFF);
    }
    Ok(digest)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Exact protected path and original-byte identity, without capture permission.
#[derive(Clone, Eq, PartialEq)]
pub struct OnvifReplaySourceSpec {
    /// Absolute protected path reopened and revalidated by the actual input owner.
    pub source: PathBuf,
    /// Complete file identity independently copied from the selected producer result.
    pub expected: ContentDigest,
}

/// Resolved private arguments and typed observation for the native capture owner.
pub struct PreparedOnvifReplaySelection {
    source: OnvifReplaySource,
    arguments: Vec<OsString>,
}

impl PreparedOnvifReplaySelection {
    /// Immutable provenance without URI/token disclosure.
    #[must_use]
    pub fn source_binding(&self) -> &OnvifReplaySource { &self.source }
    /// Actual private lease fingerprint, also inside the native request.
    #[must_use]
    pub fn file_identity(&self) -> ContentDigest { self.source.file_identity() }
    /// Borrow exact route-bearing arguments only for the native parser.
    pub fn with_capture_arguments<T>(&self, prepare: impl FnOnce(&[OsString]) -> T) -> T {
        prepare(&self.arguments)
    }
}

impl OnvifReplaySourceSpec {
    fn validate(&self) -> Result<(), &'static str> {
        let path = self.source.to_str().ok_or(ERR_CAPTURE_ONVIF_REPLAY)?;
        if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control)
            || !self.source.is_absolute() || self.source.file_name().is_none()
            || self.source.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || path.split('/').any(|part| matches!(part, "." | ".."))
            || !valid_digest(self.expected)
        {
            return Err(ERR_CAPTURE_ONVIF_REPLAY);
        }
        Ok(())
    }

    /// Compose one native replay. Discovery cannot supply source/clock identities, credentials,
    /// limits, destinations or the independently selected SDP control subtree.
    pub fn prepare(
        &self,
        input: ProtectedOnvifInput<'_>,
        native_args: &[OsString],
    ) -> Result<PreparedOnvifReplaySelection, &'static str> {
        self.validate()?;
        if input.bytes.len() > MAX_ONVIF_REPLAY_HANDOFF_BYTES
            || ContentDigest::sha256(input.bytes) != self.expected
            || native_args.len() > MAX_ARGUMENTS || !native_args.len().is_multiple_of(2)
            || native_args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err(ERR_CAPTURE_ONVIF_REPLAY);
        }
        let handoff = ReplayHandoff::parse(input.bytes)?;
        let mut seen = BTreeSet::new();
        for pair in native_args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or(ERR_CAPTURE_ONVIF_REPLAY)?;
            if pair[1].to_str().is_none_or(str::is_empty) || !seen.insert(key)
                || matches!(key, "--onvif-source" | "--onvif-digest" | "--approve" | "--capture-mode"
                    | "--peer" | "--authority" | "--presentation" | "--codec"
                    | "--replay-start" | "--replay-end" | "--recover")
            {
                return Err(ERR_CAPTURE_ONVIF_REPLAY);
            }
        }
        let mut arguments = Vec::with_capacity(native_args.len() + 12);
        for pair in native_args.as_chunks::<2>().0 {
            if pair[0] == "--onvif-control-root-digest" {
                if seen.contains("--control-root") {
                    return Err(ERR_CAPTURE_ONVIF_REPLAY);
                }
                let root = crate::onvif_plan::resolve_control_root(
                    handoff.presentation()?, pair[1].to_str().ok_or(ERR_CAPTURE_ONVIF_REPLAY)?,
                )?;
                arguments.extend([OsString::from("--control-root"), OsString::from(root)]);
            } else {
                arguments.extend_from_slice(pair);
            }
        }
        for (key, value) in [
            ("--peer", handoff.peer.to_string()),
            ("--authority", handoff.authority.clone()),
            ("--presentation", handoff.presentation()?.to_owned()),
            ("--codec", handoff.codec.as_str().into()),
            ("--replay-start", handoff.window.start().to_string()),
            ("--replay-end", handoff.window.end().to_string()),
        ] {
            arguments.extend([OsString::from(key), OsString::from(value)]);
        }
        let source = OnvifReplaySource::new(
            handoff.onboarding_plan,
            self.expected,
            ContentDigest::sha256(input.fingerprint),
            handoff.services_digest,
            handoff.services_observation_digest,
            handoff.recording_token_digest(),
            handoff.information_digest()?,
            ContentDigest::sha256(handoff.uri.as_bytes()),
            handoff.uri_observation,
        ).map_err(|_| ERR_CAPTURE_ONVIF_REPLAY)?;
        Ok(PreparedOnvifReplaySelection { source, arguments })
    }

    /// Outer approval binds actual protected-file observation and the full native plan.
    pub fn approval(
        &self,
        identity: ContentDigest,
        native: ContentDigest,
    ) -> Result<ContentDigest, &'static str> {
        self.validate()?;
        if !valid_digest(identity) || !valid_digest(native) {
            return Err(ERR_CAPTURE_ONVIF_REPLAY);
        }
        let mut out = CanonicalEncoder::new();
        out.text(ONVIF_REPLAY_APPROVAL_DOMAIN);
        out.text(POLICY);
        out.text(self.source.to_str().ok_or(ERR_CAPTURE_ONVIF_REPLAY)?);
        out.digest(self.expected);
        out.digest(identity);
        out.digest(native);
        Ok(ContentDigest::sha256(&out.finish_checked().map_err(|_| ERR_CAPTURE_ONVIF_REPLAY)?))
    }

    /// Redacted wrapper around a native preview that already hides private URI paths.
    pub fn preview(
        &self,
        identity: ContentDigest,
        native: ContentDigest,
        private_native_preview: &str,
    ) -> Result<String, &'static str> {
        Ok(object(&[
            ("schema", string(ONVIF_REPLAY_APPROVAL_DOMAIN)),
            ("phase", string("planned")),
            ("approval", string(&self.approval(identity, native)?.to_text())),
            ("policy", string(POLICY)),
            ("onvif_digest", string(&self.expected.to_text())),
            ("onvif_file_identity", string(&identity.to_text())),
            ("native_capture", private_native_preview.into()),
            ("uri_lifetime_basis", string("unknown")),
            ("effects", string("protected-file-and-destination-inspection-only")),
        ]))
    }
}

/// Redacted source provenance for native previews and independently pinned cold inspection.
pub fn source_json(source: &OnvifReplaySource) -> String {
    object(&[
        ("kind", string("onvif_recording_selection")),
        ("onboarding_plan", string(&source.onboarding_plan().to_text())),
        ("handoff_digest", string(&source.handoff_digest().to_text())),
        ("file_identity", string(&source.file_identity().to_text())),
        ("services_digest", string(&source.services_digest().to_text())),
        ("services_response_digest", string(&source.services_observation_digest().to_text())),
        ("recording_token_digest", string(&source.recording_token_digest().to_text())),
        ("information_digest", string(&source.information_digest().to_text())),
        ("uri_digest", string(&source.uri_digest().to_text())),
        ("uri_response_digest", string(&source.uri_observation_digest().to_text())),
        ("uri_lifetime_basis", string("unknown")),
        ("source_coverage_asserted", "false".into()),
    ])
}
