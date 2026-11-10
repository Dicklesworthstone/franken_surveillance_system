#![forbid(unsafe_code)]
//! Strict bounded CLI projection of the native review request; no implicit scope or media mode.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_core::{CaptureInterval, ContentDigest, PrincipalId, SensorId, TimestampNs};
use fss_reference::review_media::ReviewMediaRequest;
use fss_reference::review_media::grant::ReviewAccessRequest;
use fss_reference::review_media::render::{ReviewMovieLimits, ReviewMovieRequest};

use super::super::{digest, text};

pub(super) struct Options {
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub action: Action,
}

pub(super) enum Action {
    Publish {
        request: Box<ReviewMediaRequest>,
        approval: Option<ContentDigest>,
    },
    Show {
        root: ContentDigest,
    },
    Read {
        root: ContentDigest,
        attested_now: CaptureInterval,
        output: PathBuf,
        approval: Option<ContentDigest>,
    },
    DeliveryShow {
        identity: ContentDigest,
    },
    Revoke {
        root: ContentDigest,
        approval: Option<ContentDigest>,
    },
}

fn number(values: &BTreeMap<String, OsString>, key: &str) -> Result<u64, String> {
    let raw = text(values, key)?;
    raw.parse::<u64>()
        .ok()
        .filter(|number| number.to_string() == raw)
        .ok_or_else(|| format!("{key} requires a canonical unsigned decimal u64"))
}

fn timestamp(value: &str) -> Result<TimestampNs, String> {
    value
        .parse::<i128>()
        .ok()
        .filter(|number| number.to_string() == value)
        .map(TimestampNs)
        .ok_or_else(|| "time requires a canonical signed decimal i128".into())
}

fn interval(value: &str) -> Result<CaptureInterval, String> {
    let (earliest, latest) = value
        .split_once(':')
        .ok_or("current time requires EARLIEST:LATEST")?;
    CaptureInterval::new(timestamp(earliest)?, timestamp(latest)?)
        .map_err(|_| "inverted current-time interval".into())
}

pub(super) fn parse(args: &[OsString]) -> Result<Options, String> {
    let command = args
        .first()
        .and_then(|value| value.to_str())
        .ok_or("explicit review action required")?;
    let extra: &[&str] = match command {
        "review" => &[
            "--import-identity",
            "--expected-import-root",
            "--sensor",
            "--movie-start-tick",
            "--movie-end-tick",
            "--privacy-digest",
            "--recipient",
            "--purpose",
            "--issued-at-ns",
            "--expires-at-ns",
            "--max-media-bytes",
            "--approve",
        ],
        "review-show" => &["--review-root"],
        "review-delivery-show" => &["--delivery-id"],
        "review-read" => &["--review-root", "--attested-now-ns", "--out", "--approve"],
        "review-revoke" => &["--review-root", "--approve"],
        _ => return Err("unknown review action".into()),
    };
    if args.len() > 1 + 2 * (3 + extra.len()) || args.len() % 2 != 1 {
        return Err("review action exceeds argument bound or lacks a value".into());
    }
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !matches!(key, "--root" | "--site" | "--principal") && !extra.contains(&key) {
            return Err("unknown or inapplicable review option".into());
        }
        let value = &pair[1];
        if value.is_empty()
            || value.as_encoded_bytes().len() > 4096
            || value.to_str().is_some_and(|value| value.starts_with("--"))
        {
            return Err("empty, overbound or missing review option value".into());
        }
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err("duplicate review option".into());
        }
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = match values.get("--principal") {
        Some(_) => text(&values, "--principal")?,
        None if matches!(command, "review-read" | "review-delivery-show") => {
            return Err("review-read requires the explicit recipient --principal".into());
        }
        None => "principal:local-operator",
    }
    .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    let approval = values
        .contains_key("--approve")
        .then(|| text(&values, "--approve").and_then(digest))
        .transpose()?;
    let action = if command == "review" {
        let import_identity = digest(text(&values, "--import-identity")?)?;
        let movie_start_tick = number(&values, "--movie-start-tick")?;
        let movie_end_tick = number(&values, "--movie-end-tick")?;
        let maximum_media_bytes = number(&values, "--max-media-bytes")?;
        let access = ReviewAccessRequest {
            import_identity,
            import_root: digest(text(&values, "--expected-import-root")?)?,
            sensor: SensorId::parse(text(&values, "--sensor")?).map_err(|_| "invalid sensor")?,
            movie_start_tick,
            movie_end_tick,
            expected_privacy: digest(text(&values, "--privacy-digest")?)?,
            recipient: PrincipalId::parse(text(&values, "--recipient")?)
                .map_err(|_| "invalid recipient principal")?,
            purpose: text(&values, "--purpose")?.to_owned(),
            issued_at: timestamp(text(&values, "--issued-at-ns")?)?,
            expires_at: timestamp(text(&values, "--expires-at-ns")?)?,
            maximum_media_bytes,
        };
        access.validate().map_err(|error| error.to_string())?;
        Action::Publish {
            request: Box::new(ReviewMediaRequest {
                movie: ReviewMovieRequest {
                    import_identity,
                    movie_start_tick,
                    movie_end_tick,
                    limits: ReviewMovieLimits {
                        max_output_bytes: maximum_media_bytes,
                        ..ReviewMovieLimits::default()
                    },
                },
                access,
            }),
            approval,
        }
    } else if command == "review-delivery-show" {
        Action::DeliveryShow {
            identity: digest(text(&values, "--delivery-id")?)?,
        }
    } else {
        let root = digest(text(&values, "--review-root")?)?;
        match command {
            "review-show" => Action::Show { root },
            "review-revoke" => Action::Revoke { root, approval },
            "review-read" => Action::Read {
                root,
                attested_now: interval(text(&values, "--attested-now-ns")?)?,
                output: PathBuf::from(values.get("--out").ok_or("required option --out")?),
                approval,
            },
            _ => return Err("unknown review action".into()),
        }
    };
    Ok(Options {
        root,
        site,
        principal,
        action,
    })
}
