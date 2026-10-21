#![forbid(unsafe_code)]
//! Private operator input for the existing RTSP capture owner, never source evidence.

use std::net::SocketAddr;

use fss_cli::agent_json::{object, string};
use fss_cli::json_input;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::onvif::client::{RtspScope, SelectedStream, validate_stream_uri};
use fss_reference::onvif::wire::VideoEncoding;
use fss_reference::rtsp::client::validated_uri_parts;

const ERROR: &str = "ERR-ONVIF-HANDOFF-001";
pub(crate) const SCHEMA: &str = "fss.onvif_rtsp_handoff.v1";

pub(crate) fn digest(text: &str) -> Result<ContentDigest, &'static str> {
    let digest = ContentDigest::parse(text).map_err(|_| ERROR)?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err(ERROR);
    }
    Ok(digest)
}

/// No Debug/Display: the exact URI can carry an opaque query capability.
pub(crate) struct Handoff {
    pub(crate) onboarding_plan: ContentDigest,
    pub(crate) profile_digest: ContentDigest,
    pub(crate) peer: SocketAddr,
    pub(crate) authority: String,
    pub(crate) uri: String,
    pub(crate) codec: String,
}
impl Handoff {
    pub(crate) fn from_selected(
        selected: &SelectedStream,
        plan: ContentDigest,
    ) -> Result<Self, &'static str> {
        // The protocol owner has already classified timeout and invalidation flags.
        // The handoff records the stable subset only; it cannot extend an expiring URI.
        if !selected.stream.is_stable()
            || selected.profile.video.as_ref().map(|video| video.encoding)
                != Some(VideoEncoding::H264)
        {
            return Err(ERROR);
        }
        let result = Self {
            onboarding_plan: plan,
            profile_digest: ContentDigest::sha256(selected.profile.token.as_bytes()),
            peer: selected.peer,
            authority: selected.authority.clone(),
            uri: selected.stream.uri.clone(),
            codec: "avc".into(),
        };
        result.validate()?;
        Ok(result)
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.codec != "avc" || self.uri.len() > 2048 {
            return Err(ERROR);
        }
        validate_stream_uri(
            &self.uri,
            &RtspScope {
                peer: self.peer,
                authority: self.authority.clone(),
            },
        )
        .map_err(|_| ERROR)?;
        Ok(())
    }

    pub(crate) fn presentation(&self) -> Result<&str, &'static str> {
        validated_uri_parts(&self.uri)
            .map(|(_, path)| path)
            .map_err(|_| ERROR)
    }

    pub(crate) fn render(&self) -> Result<String, &'static str> {
        self.validate()?;
        Ok(object(&[
            ("schema", string(SCHEMA)),
            ("onboarding_plan", string(&self.onboarding_plan.to_text())),
            ("profile_digest", string(&self.profile_digest.to_text())),
            ("peer", string(&self.peer.to_string())),
            ("authority", string(&self.authority)),
            ("uri", string(&self.uri)),
            ("codec", string(&self.codec)),
            ("invalid_after_connect", "false".into()),
            ("invalid_after_reboot", "false".into()),
            ("timeout", string("PT0S")),
            ("capture_authorized", "false".into()),
            ("source_evidence", "false".into()),
        ]) + "\n")
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > 8192 {
            return Err(ERROR);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| ERROR)?;
        let value = json_input::parse(text).map_err(|_| ERROR)?;
        let fields = value.object().ok_or(ERROR)?;
        const FIELDS: &[&str] = &[
            "schema",
            "onboarding_plan",
            "profile_digest",
            "peer",
            "authority",
            "uri",
            "codec",
            "invalid_after_connect",
            "invalid_after_reboot",
            "timeout",
            "capture_authorized",
            "source_evidence",
        ];
        if fields.len() != FIELDS.len() || fields.keys().any(|key| !FIELDS.contains(&key.as_str()))
        {
            return Err(ERROR);
        }
        let text = |key: &str| {
            fields
                .get(key)
                .and_then(json_input::Value::text)
                .ok_or(ERROR)
        };
        if text("schema")? != SCHEMA || text("timeout")? != "PT0S" {
            return Err(ERROR);
        }
        for key in [
            "invalid_after_connect",
            "invalid_after_reboot",
            "capture_authorized",
            "source_evidence",
        ] {
            if fields.get(key).and_then(json_input::Value::boolean) != Some(false) {
                return Err(ERROR);
            }
        }
        let result = Self {
            onboarding_plan: digest(text("onboarding_plan")?)?,
            profile_digest: digest(text("profile_digest")?)?,
            peer: text("peer")?.parse().map_err(|_| ERROR)?,
            authority: text("authority")?.into(),
            uri: text("uri")?.into(),
            codec: text("codec")?.into(),
        };
        result.validate()?;
        Ok(result)
    }
}
