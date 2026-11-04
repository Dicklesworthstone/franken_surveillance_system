#![forbid(unsafe_code)]
//! Offline measurement of pinned native RTSP/RTP evidence into a site probe receipt.
//! All file authority is explicit and bounded. No device or credential is accessed.

use std::path::{Path, PathBuf};

use fss_core::json_input::MAX_INPUT_BYTES;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::site::{
    ProbeCodec, SITE_PROBE_RECEIPT_SCHEMA, SiteProbeReceipt, parse_manifest,
};
use fss_reference::site_probe::{
    MAX_DESCRIBE_RESPONSE_BYTES, MAX_PROBE_RTPDUMP_BYTES, MeasuredProbe, ProbeSelection,
    measure_probe,
};

use crate::agent_json::{array, object, string, strings};
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{collect_options, take};
use crate::site_cmd::{InputAuthority, MAX_SITE_OUTPUT_BYTES, refusal};
use crate::token::ArgToken;

/// Complete operator report for measurements derived from supplied protocol bytes.
pub const SITE_PROBE_OBSERVATION_SCHEMA: &str = "fss.site_probe_observation.v1";

/// Explicit local input pins and selection. Paths are absent from diagnostic formatting.
#[derive(Clone, Eq, PartialEq)]
pub struct ProbeFileArgs {
    /// Exact existing site declaration to read.
    pub manifest: PathBuf,
    /// SHA-256 of the complete manifest file, independently supplied.
    pub manifest_digest: ContentDigest,
    /// Source identity within the validated manifest.
    pub source_id: String,
    /// Complete native DESCRIBE response, including headers and body.
    pub describe_response: PathBuf,
    /// SHA-256 of the exact complete response bytes.
    pub describe_digest: ContentDigest,
    /// Existing bounded RTPdump source trace.
    pub rtp_dump: PathBuf,
    /// SHA-256 of the exact complete trace bytes.
    pub rtp_dump_digest: ContentDigest,
    /// Explicit selected codec; never guessed from a vendor name.
    pub codec: ProbeCodec,
    /// Explicit selected SDP media index, default zero.
    pub media_index: usize,
    /// Proposed interleaved RTP channel, default zero; not observed from RTPdump.
    pub rtp_channel: u8,
}

impl std::fmt::Debug for ProbeFileArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeFileArgs")
            .field("manifest_digest", &self.manifest_digest)
            .field("describe_digest", &self.describe_digest)
            .field("rtp_dump_digest", &self.rtp_dump_digest)
            .field("codec", &self.codec)
            .field("media_index", &self.media_index)
            .field("rtp_channel", &self.rtp_channel)
            .finish_non_exhaustive()
    }
}

impl ProbeFileArgs {
    pub(crate) fn input_scopes(&self) -> [(&Path, usize); 3] {
        [
            (&self.manifest, MAX_INPUT_BYTES),
            (&self.describe_response, MAX_DESCRIBE_RESPONSE_BYTES),
            (&self.rtp_dump, MAX_PROBE_RTPDUMP_BYTES),
        ]
    }
}

/// Parse the bounded site probe-file grammar without reading any input.
pub fn parse(tokens: &[ArgToken]) -> Result<ProbeFileArgs, CliError> {
    const COMMAND: &str = "site probe-file";
    let options = tokens.get(1..).ok_or_else(|| CliError::MissingValue {
        option: "site".to_owned(),
        command: Some(COMMAND.to_owned()),
        expected: "probe-file followed by explicit pinned inputs".to_owned(),
    })?;
    let values = collect_options(
        COMMAND,
        options,
        &[
            "--manifest",
            "--manifest-digest",
            "--source",
            "--describe-response",
            "--describe-digest",
            "--rtp-dump",
            "--rtp-dump-digest",
            "--codec",
            "--media-index",
            "--rtp-channel",
        ],
    )?;
    let required = |name: &str| -> Result<&str, CliError> {
        take(&values, name)
            .map(|(_, value, _)| value.as_str())
            .ok_or_else(|| CliError::MissingValue {
                option: name.to_owned(),
                command: Some(COMMAND.to_owned()),
                expected: "an explicit pinned probe input".to_owned(),
            })
    };
    let invalid = |name: &str, reason: &str| CliError::MalformedValue {
        option: name.to_owned(),
        value: "[redacted]".to_owned(),
        reason: reason.to_owned(),
        command: Some(COMMAND.to_owned()),
        index: take(&values, name).map_or(0, |(_, _, index)| *index),
    };
    let pin = |name: &str| -> Result<ContentDigest, CliError> {
        let text = required(name)?;
        ContentDigest::parse(text)
            .ok()
            .filter(|digest| {
                digest.algorithm() == DigestAlgorithm::Sha256
                    && !digest.is_laboratory()
                    && digest.to_text() == text
            })
            .ok_or_else(|| invalid(name, "a canonical SHA-256 digest is required"))
    };
    let number = |name: &str, maximum: usize| -> Result<usize, CliError> {
        match take(&values, name) {
            None => Ok(0),
            Some((_, text, _)) => text
                .parse::<usize>()
                .ok()
                .filter(|value| *value <= maximum && value.to_string() == *text)
                .ok_or_else(|| invalid(name, "a bounded canonical unsigned integer is required")),
        }
    };
    let codec = match required("--codec")? {
        "avc" => ProbeCodec::Avc,
        "hevc" => ProbeCodec::Hevc,
        "jpeg" => ProbeCodec::Jpeg,
        _ => return Err(invalid("--codec", "codec must be avc, hevc or jpeg")),
    };
    let rtp_channel = number("--rtp-channel", 254)? as u8;
    if !rtp_channel.is_multiple_of(2) {
        return Err(invalid(
            "--rtp-channel",
            "an even RTP channel below 255 is required",
        ));
    }
    Ok(ProbeFileArgs {
        manifest: PathBuf::from(required("--manifest")?),
        manifest_digest: pin("--manifest-digest")?,
        source_id: required("--source")?.to_owned(),
        describe_response: PathBuf::from(required("--describe-response")?),
        describe_digest: pin("--describe-digest")?,
        rtp_dump: PathBuf::from(required("--rtp-dump")?),
        rtp_dump_digest: pin("--rtp-dump-digest")?,
        codec,
        media_index: number("--media-index", 63)?,
        rtp_channel,
    })
}

fn read_pinned(
    authority: &mut InputAuthority,
    path: &Path,
    expected: ContentDigest,
) -> Result<Vec<u8>, (&'static str, &'static str)> {
    let bytes = authority.read(path).map_err(|code| {
        (
            code,
            "a named probe input could not be read within its bound",
        )
    })?;
    if ContentDigest::sha256(&bytes) != expected {
        return Err((
            "ERR-SITE-PROBE-INPUT-PIN-001",
            "probe input differs from its independent byte pin",
        ));
    }
    Ok(bytes)
}

/// Measure exactly the named inputs and return a complete receipt or a non-disclosing error.
#[must_use]
pub fn execute(args: &ProbeFileArgs) -> (String, ExitIdentity) {
    let result = (|| -> Result<String, (&'static str, &'static str)> {
        let mut authority = InputAuthority::for_inputs(&args.input_scopes());
        let manifest_bytes = read_pinned(&mut authority, &args.manifest, args.manifest_digest)?;
        let describe_bytes = read_pinned(
            &mut authority,
            &args.describe_response,
            args.describe_digest,
        )?;
        let rtp_bytes = read_pinned(&mut authority, &args.rtp_dump, args.rtp_dump_digest)?;
        let manifest = parse_manifest(&manifest_bytes).map_err(|_| {
            (
                "ERR-SITE-PROBE-MANIFEST-001",
                "probe manifest contract refused",
            )
        })?;
        let selection = ProbeSelection {
            codec: args.codec,
            media_index: args.media_index,
            rtp_channel: args.rtp_channel,
        };
        let measured = measure_probe(
            &manifest,
            &args.source_id,
            &selection,
            &describe_bytes,
            &rtp_bytes,
        )
        .map_err(|error| (error.code(), error.reason()))?;
        let report = render(&measured, args.manifest_digest);
        if report.len() > MAX_SITE_OUTPUT_BYTES {
            return Err((
                "ERR-SITE-OUTPUT-BOUND-001",
                "complete probe report exceeds its output bound",
            ));
        }
        Ok(report)
    })();
    match result {
        Ok(output) => (output, ExitIdentity::SUCCESS),
        Err((code, reason)) => refusal(code, reason, None),
    }
}

fn digest(value: ContentDigest) -> String {
    string(&value.to_text())
}

/// The exact registered receipt shape, suitable for the existing site plan --probes input.
fn receipt(value: &SiteProbeReceipt) -> String {
    object(&[
        ("schema", string(SITE_PROBE_RECEIPT_SCHEMA)),
        ("site_id", string(&value.site_id)),
        ("source_id", string(&value.source_id)),
        ("manifest_digest", digest(value.manifest_digest)),
        ("source_generation", value.source_generation.to_string()),
        ("peer", string(&value.peer.to_string())),
        ("authority", string(&value.authority)),
        ("presentation", string(&value.presentation)),
        ("control_root", string(&value.control_root)),
        ("media_index", value.media_index.to_string()),
        ("rtp_channel", value.rtp_channel.to_string()),
        ("rtcp_channel", value.rtcp_channel.to_string()),
        ("sdp_digest", digest(value.sdp_digest)),
        ("codec", string(value.codec.as_str())),
        ("payload_type", value.payload_type.to_string()),
        ("ssrc", value.ssrc.to_string()),
        (
            "frame_duration_ticks",
            value.frame_duration_ticks.to_string(),
        ),
        ("clock_rate_hz", value.clock_rate_hz.to_string()),
        ("observed_frames", value.observed_frames.to_string()),
        ("first_rtp_timestamp", value.first_rtp_timestamp.to_string()),
        ("last_rtp_timestamp", value.last_rtp_timestamp.to_string()),
        (
            "parameter_set_digests",
            strings(value.parameter_set_digests.iter().map(|d| d.to_text())),
        ),
        ("server_identity", string(&value.server_identity)),
    ])
}

fn render(value: &MeasuredProbe, manifest_input_digest: ContentDigest) -> String {
    let observed = value.receipt();
    object(&[
        ("schema", string(SITE_PROBE_OBSERVATION_SCHEMA)),
        ("status", string("measured")),
        (
            "measurement_basis",
            string("offline_describe_response_and_rtpdump"),
        ),
        ("evidence_digest", digest(value.evidence_digest())),
        ("manifest_digest", digest(observed.manifest_digest)),
        ("manifest_input_digest", digest(manifest_input_digest)),
        ("describe_response_digest", digest(value.describe_digest())),
        ("rtp_dump_digest", digest(value.rtp_dump_digest())),
        ("sdp_digest", digest(observed.sdp_digest)),
        (
            "server_header_digest",
            value
                .server_header_digest()
                .map_or_else(|| "null".to_owned(), digest),
        ),
        ("source_id", string(&observed.source_id)),
        ("rtp_packets", value.rtp_packets().to_string()),
        ("rtcp_packets", value.rtcp_packets().to_string()),
        ("observed_frames", observed.observed_frames.to_string()),
        (
            "channel_basis",
            string("operator_selected_not_measured_from_rtpdump"),
        ),
        ("receipts", array(&[receipt(observed)])),
        ("device_contacted", "false".to_owned()),
        ("credentials_read", "false".to_owned()),
        ("origin_authenticated", "false".to_owned()),
        ("current_liveness_verified", "false".to_owned()),
        ("custody_verified", "false".to_owned()),
        ("clock_synchronized", "false".to_owned()),
        ("rights_verdict_verified", "false".to_owned()),
        ("capture_authorized", "false".to_owned()),
        ("media_bytes_returned", "false".to_owned()),
    ])
}
