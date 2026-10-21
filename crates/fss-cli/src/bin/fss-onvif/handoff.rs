#![forbid(unsafe_code)]
//! Private operator input for the existing RTSP capture owner, never source evidence.

use std::net::SocketAddr;

use fss_cli::agent_json::{object, string};
use fss_cli::json_input;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::onvif::client::{
    RtspScope, SelectedStream, StreamValidity, validate_stream_uri,
};
use fss_reference::onvif::wire::VideoEncoding;
use fss_reference::rtsp::client::validated_uri_parts;

const ERROR: &str = "ERR-ONVIF-HANDOFF-001";
const MEDIA1_SCHEMA: &str = "fss.onvif_rtsp_handoff.v1";
const MEDIA2_SCHEMA: &str = "fss.onvif_rtsp_handoff.v2";

#[derive(Clone, Copy, PartialEq, Eq)]
enum UriValidity {
    /// The Media1 response supplied false invalidation flags and a zero timeout.
    Media1Stable,
    /// Media2 defines an indefinitely valid URI and supplies no invalidation fields.
    Media2Indefinite,
}

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
    validity: UriValidity,
}
impl Handoff {
    pub(crate) fn from_selected(
        selected: &SelectedStream,
        plan: ContentDigest,
    ) -> Result<Self, &'static str> {
        // The protocol owner classifies Media1's observed invalidation fields
        // separately from Media2's contractual validity. Never synthesize device
        // observations for the latter, or extend an expiring Media1 URI.
        if !selected.stream.is_stable() {
            return Err(ERROR);
        }
        let validity = match &selected.stream.validity {
            StreamValidity::Media1 { .. } => UriValidity::Media1Stable,
            StreamValidity::Media2Indefinite => UriValidity::Media2Indefinite,
        };
        let codec = match selected.profile.video.as_ref().map(|video| video.encoding) {
            Some(VideoEncoding::H264) => "avc",
            Some(VideoEncoding::H265) if validity == UriValidity::Media2Indefinite => "hevc",
            _ => return Err(ERROR),
        };
        let result = Self {
            onboarding_plan: plan,
            profile_digest: ContentDigest::sha256(selected.profile.token.as_bytes()),
            peer: selected.peer,
            authority: selected.authority.clone(),
            uri: selected.stream.uri.clone(),
            codec: codec.into(),
            validity,
        };
        result.validate()?;
        Ok(result)
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if !matches!(self.codec.as_str(), "avc" | "hevc")
            || (self.validity == UriValidity::Media1Stable && self.codec != "avc")
            || self.uri.len() > 2048
        {
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
        let mut fields = vec![
            (
                "schema",
                string(match self.validity {
                    UriValidity::Media1Stable => MEDIA1_SCHEMA,
                    UriValidity::Media2Indefinite => MEDIA2_SCHEMA,
                }),
            ),
            ("onboarding_plan", string(&self.onboarding_plan.to_text())),
            ("profile_digest", string(&self.profile_digest.to_text())),
            ("peer", string(&self.peer.to_string())),
            ("authority", string(&self.authority)),
            ("uri", string(&self.uri)),
            ("codec", string(&self.codec)),
        ];
        match self.validity {
            UriValidity::Media1Stable => fields.extend([
                ("invalid_after_connect", "false".into()),
                ("invalid_after_reboot", "false".into()),
                ("timeout", string("PT0S")),
            ]),
            UriValidity::Media2Indefinite => fields.extend([
                ("media_version", string("media2")),
                (
                    "uri_validity",
                    object(&[("basis", string("media2_indefinite_contract"))]),
                ),
            ]),
        }
        fields.extend([
            ("capture_authorized", "false".into()),
            ("source_evidence", "false".into()),
        ]);
        Ok(object(&fields) + "\n")
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > 8192 {
            return Err(ERROR);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| ERROR)?;
        let value = json_input::parse(text).map_err(|_| ERROR)?;
        let fields = value.object().ok_or(ERROR)?;
        const MEDIA1_FIELDS: &[&str] = &[
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
        const MEDIA2_FIELDS: &[&str] = &[
            "schema",
            "onboarding_plan",
            "profile_digest",
            "peer",
            "authority",
            "uri",
            "codec",
            "media_version",
            "uri_validity",
            "capture_authorized",
            "source_evidence",
        ];
        let text = |key: &str| {
            fields
                .get(key)
                .and_then(json_input::Value::text)
                .ok_or(ERROR)
        };
        let allowed = match text("schema")? {
            MEDIA1_SCHEMA => MEDIA1_FIELDS,
            MEDIA2_SCHEMA => MEDIA2_FIELDS,
            _ => return Err(ERROR),
        };
        if fields.len() != allowed.len()
            || fields.keys().any(|key| !allowed.contains(&key.as_str()))
        {
            return Err(ERROR);
        }
        let validity = match text("schema")? {
            MEDIA1_SCHEMA => {
                if text("timeout")? != "PT0S"
                    || ["invalid_after_connect", "invalid_after_reboot"]
                        .iter()
                        .any(|key| {
                            fields.get(*key).and_then(json_input::Value::boolean) != Some(false)
                        })
                {
                    return Err(ERROR);
                }
                UriValidity::Media1Stable
            }
            MEDIA2_SCHEMA => {
                let validity = fields
                    .get("uri_validity")
                    .and_then(json_input::Value::object)
                    .ok_or(ERROR)?;
                if text("media_version")? != "media2"
                    || validity.len() != 1
                    || validity.get("basis").and_then(json_input::Value::text)
                        != Some("media2_indefinite_contract")
                {
                    return Err(ERROR);
                }
                UriValidity::Media2Indefinite
            }
            _ => return Err(ERROR),
        };
        for key in ["capture_authorized", "source_evidence"] {
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
            validity,
        };
        result.validate()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(validity: UriValidity, codec: &str) -> Handoff {
        Handoff {
            onboarding_plan: ContentDigest::sha256(b"onboarding-plan"),
            profile_digest: ContentDigest::sha256(b"selected-profile"),
            peer: "127.0.0.1:8554".parse().unwrap(),
            authority: "127.0.0.1:8554".into(),
            uri: "rtsp://127.0.0.1:8554/camera?cap=opaque%2Btoken".into(),
            codec: codec.into(),
            validity,
        }
    }

    #[test]
    fn media1_handoff_remains_compatible_and_cannot_gain_hevc_or_expiry() {
        let rendered = source(UriValidity::Media1Stable, "avc").render().unwrap();
        assert!(rendered.contains(MEDIA1_SCHEMA));
        assert_eq!(
            Handoff::parse(rendered.as_bytes())
                .unwrap()
                .render()
                .unwrap(),
            rendered
        );
        for (before, after) in [
            ("\"codec\":\"avc\"", "\"codec\":\"hevc\""),
            (
                "\"invalid_after_connect\":false",
                "\"invalid_after_connect\":true",
            ),
            (
                "\"invalid_after_reboot\":false",
                "\"invalid_after_reboot\":true",
            ),
            ("\"timeout\":\"PT0S\"", "\"timeout\":\"PT60S\""),
        ] {
            assert!(rendered.contains(before));
            assert!(Handoff::parse(rendered.replace(before, after).as_bytes()).is_err());
        }
    }

    #[test]
    fn media2_handoff_preserves_uri_bytes_and_contractual_validity_for_both_codecs() {
        for codec in ["avc", "hevc"] {
            let original = source(UriValidity::Media2Indefinite, codec);
            let rendered = original.render().unwrap();
            assert!(rendered.contains(MEDIA2_SCHEMA));
            assert!(
                rendered.contains("\"uri_validity\":{\"basis\":\"media2_indefinite_contract\"}")
            );
            assert!(!rendered.contains("invalid_after"));
            assert!(!rendered.contains("timeout"));
            let parsed = Handoff::parse(rendered.as_bytes()).unwrap();
            assert_eq!(parsed.uri, original.uri);
            assert_eq!(parsed.codec, codec);
            assert_eq!(parsed.presentation().unwrap(), "/camera?cap=opaque%2Btoken");
            assert_eq!(parsed.render().unwrap(), rendered);
            assert!(Handoff::parse(rendered.replace("%2B", "%2F").as_bytes()).is_err());
        }
    }

    #[test]
    fn media2_handoff_refuses_ambiguous_validity_and_claimed_capture_authority() {
        let rendered = source(UriValidity::Media2Indefinite, "hevc")
            .render()
            .unwrap();
        for (before, after) in [
            (
                "\"media_version\":\"media2\"",
                "\"media_version\":\"media1\"",
            ),
            ("media2_indefinite_contract", "device_observed_stable"),
            ("\"codec\":\"hevc\"", "\"codec\":\"jpeg\""),
            (
                "\"capture_authorized\":false",
                "\"capture_authorized\":true",
            ),
            ("\"source_evidence\":false", "\"source_evidence\":true"),
            (
                "\"basis\":\"media2_indefinite_contract\"",
                "\"basis\":\"media2_indefinite_contract\",\"timeout\":\"PT0S\"",
            ),
            (
                "\"source_evidence\":false",
                "\"source_evidence\":false,\"invalid_after_connect\":false",
            ),
        ] {
            assert!(rendered.contains(before));
            assert!(Handoff::parse(rendered.replace(before, after).as_bytes()).is_err());
        }
    }
}
