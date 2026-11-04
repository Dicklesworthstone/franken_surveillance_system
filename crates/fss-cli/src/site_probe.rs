#![forbid(unsafe_code)]
//! An exact, separately approved native RTSP probe for one manifest source.
//!
//! Previewing reads only the manifest. Execution borrows the existing private
//! credential lease and request-owned runtime; it retains no media or raw wire.
//! Successful stdout is a receipt array directly usable by `fss site plan`.

mod native;
mod plan;

use std::path::PathBuf;

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::site::{ProbeCodec, SiteManifest};

use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{collect_options, take};
use crate::token::ArgToken;

pub(crate) use plan::ProbePlan;
pub use plan::SiteProbeOptions;

/// Parse the exact operator grammar without opening any path or socket.
pub fn parse_probe_args(tokens: &[ArgToken]) -> Result<(PathBuf, SiteProbeOptions), CliError> {
    let command = "site probe";
    let values = collect_options(
        command,
        tokens.get(1..).unwrap_or(&[]),
        &[
            "--manifest",
            "--source",
            "--codec",
            "--media-index",
            "--payload-type",
            "--rtp-channel",
            "--observe-frames",
            "--timeout-ms",
            "--principal",
            "--approve",
        ],
    )?;
    let required = |name: &str| -> Result<String, CliError> {
        take(&values, name)
            .map(|(_, value, _)| value.clone())
            .ok_or_else(|| CliError::MissingValue {
                option: name.to_owned(),
                command: Some(command.to_owned()),
                expected: format!("a value for {name}"),
            })
    };
    let malformed = |name: &str, reason: &str| CliError::MalformedValue {
        option: name.to_owned(),
        value: "[invalid selection]".to_owned(),
        reason: reason.to_owned(),
        command: Some(command.to_owned()),
        index: take(&values, name).map_or(0, |(_, _, index)| *index),
    };
    let number = |name: &str, default: u64| -> Result<u64, CliError> {
        let Some((_, text, _)) = take(&values, name) else {
            return Ok(default);
        };
        match text.parse::<u64>() {
            Ok(value) if value.to_string() == *text => Ok(value),
            _ => Err(malformed(
                name,
                "canonical unsigned decimal integer required",
            )),
        }
    };
    let codec = match required("--codec")?.as_str() {
        "avc" => ProbeCodec::Avc,
        "hevc" => ProbeCodec::Hevc,
        _ => {
            return Err(malformed(
                "--codec",
                "native probe supports explicit avc or hevc",
            ));
        }
    };
    let media_index = usize::try_from(number("--media-index", 0)?)
        .map_err(|_| malformed("--media-index", "media index out of range"))?;
    let rtp_channel = u8::try_from(number("--rtp-channel", 0)?)
        .map_err(|_| malformed("--rtp-channel", "channel out of range"))?;
    let observe_frames = u32::try_from(number("--observe-frames", 6)?)
        .map_err(|_| malformed("--observe-frames", "frame count out of range"))?;
    let payload_type = if take(&values, "--payload-type").is_some() {
        Some(
            u8::try_from(number("--payload-type", 0)?)
                .map_err(|_| malformed("--payload-type", "payload type out of range"))?,
        )
    } else {
        None
    };
    let approve = take(&values, "--approve")
        .map(|(_, text, _)| {
            let digest = ContentDigest::parse(text)
                .map_err(|_| malformed("--approve", "exact SHA-256 approval required"))?;
            if digest.algorithm() != DigestAlgorithm::Sha256
                || digest.is_laboratory()
                || digest.to_text() != *text
            {
                return Err(malformed(
                    "--approve",
                    "exact canonical SHA-256 approval required",
                ));
            }
            Ok(digest)
        })
        .transpose()?;
    let options = SiteProbeOptions {
        source: required("--source")?,
        codec,
        media_index,
        payload_type,
        rtp_channel,
        observe_frames,
        timeout_ms: number("--timeout-ms", 10_000)?,
        principal: take(&values, "--principal").map_or_else(
            || "principal:local-operator".to_owned(),
            |(_, value, _)| value.clone(),
        ),
        approve,
    };
    options.validate().map_err(|_| malformed("site probe", "bounded source, codec, media, channel, frame, timeout and principal selection required"))?;
    Ok((PathBuf::from(required("--manifest")?), options))
}

#[cfg(test)]
#[test]
fn empty_public_probe_parse_refuses_without_panicking() {
    assert!(parse_probe_args(&[]).is_err());
}

/// Preview or perform one bounded probe. Only an exact preview digest opens the
/// native boundary. Successful receipt arrays contain private route metadata.
pub fn execute_probe(
    manifest: &SiteManifest,
    options: &SiteProbeOptions,
) -> (String, ExitIdentity) {
    let plan = match ProbePlan::new(manifest, options) {
        Ok(plan) => plan,
        Err(code) => {
            return native::refusal(
                code,
                native::Facts::default(),
                ExitIdentity::MALFORMED_VALUE,
            );
        }
    };
    match plan.check_approval() {
        Ok(false) => match plan.preview() {
            Ok(preview) => (preview, ExitIdentity::SUCCESS),
            Err(code) => native::refusal(
                code,
                native::Facts::default(),
                ExitIdentity::MALFORMED_VALUE,
            ),
        },
        Err(code) => native::refusal(
            code,
            native::Facts::default(),
            ExitIdentity::MALFORMED_VALUE,
        ),
        Ok(true) => native::execute(&plan),
    }
}
