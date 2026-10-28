#![forbid(unsafe_code)]
//! Pure, explicitly authorized bounded subscription plan. No secrets or I/O.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use fss_core::{CanonicalEncoder, ContentDigest, SensorId};
use fss_reference::onvif::client::DigestConfig;
use fss_reference::onvif::http::{HttpLimits, HttpRoute};
use fss_reference::onvif::pullpoint::{PullPointConfig, route_in_service_root};

use super::super::authentication::AuthPlan;
use super::super::{ARGUMENT_ERROR, clean_absolute, digest, text};

pub(super) const HELP: &str = "fss-onvif-metadata capture [options]
  --root ABSOLUTE_DIR --site SITE --sensor SENSOR
  --device-generation sha256:HEX --profile-generation sha256:HEX --profile TOKEN
  --peer IP:PORT --authority HOST[:PORT] --events-path /onvif/events
  --service-root /onvif --owner-authorized yes --plaintext yes --subscribe yes
  --receive-origin-ns N
  [--principal ID] [--generation 1] [--max-pulls 4] [--poll-seconds 5]
  [--message-limit 128] [--lifetime-seconds 120] [--timeout-ms 30000]
  [--max-steps 100000]
  [--credential-file /PRIVATE_FILE --auth-realm EXACT_REALM]
  [--legacy-md5 yes] [--legacy-no-qop yes]

Creates one finite device-event PullPoint subscription, retains complete event responses,
then attempts Unsubscribe within the original deadline. No automatic reconnect.
The peer is a literal IP; authority and service subtree remain independently pinned.
Only explicit plaintext HTTP with optional HTTP Digest is supported in this lane.
Native capture requires Linux entropy, including anonymous capture. Credentials use a
private-file lease: username newline password newline.
--receive-origin-ns is the operator-declared epoch at monotonic request start.
Camera timestamps remain unverified vendor claims. Empty polls establish no coverage.
Profile pins are owner attribution; this subscription does not request a profile filter.
The deadline bounds network and batch admission; an admitted synchronous publication
can finish after expiry, and its known durable handles are still reported.
Output lists each definitely retained import/root and the final cleanup state.
Inspect an import separately to reveal its private values. Incomplete/indeterminate
capture or cleanup returns a nonzero exit code while preserving known durable handles.
";

pub(super) struct Plan {
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub sensor: SensorId,
    pub device_generation: ContentDigest,
    pub profile_generation: ContentDigest,
    pub profile: String,
    pub receive_origin_ns: i128,
    pub approval: ContentDigest,
    pub credentials: Option<PathBuf>,
    pub config: PullPointConfig,
}

fn unsigned(
    values: &BTreeMap<String, OsString>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, &'static str> {
    let value = values.get(key).map_or(Ok(default), |value| {
        value
            .to_str()
            .ok_or(ARGUMENT_ERROR)?
            .parse::<u64>()
            .map_err(|_| ARGUMENT_ERROR)
    })?;
    if !(min..=max).contains(&value) {
        return Err(ARGUMENT_ERROR);
    }
    Ok(value)
}

impl Plan {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > 64
            || args.len() % 2 != 0
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err(ARGUMENT_ERROR);
        }
        let mut values = BTreeMap::new();
        for pair in args.chunks_exact(2) {
            let key = pair[0].to_str().ok_or(ARGUMENT_ERROR)?;
            if !matches!(
                key,
                "--root"
                    | "--site"
                    | "--principal"
                    | "--sensor"
                    | "--device-generation"
                    | "--profile-generation"
                    | "--profile"
                    | "--peer"
                    | "--authority"
                    | "--events-path"
                    | "--service-root"
                    | "--owner-authorized"
                    | "--plaintext"
                    | "--subscribe"
                    | "--receive-origin-ns"
                    | "--generation"
                    | "--max-pulls"
                    | "--poll-seconds"
                    | "--message-limit"
                    | "--lifetime-seconds"
                    | "--timeout-ms"
                    | "--max-steps"
                    | "--credential-file"
                    | "--auth-realm"
                    | "--legacy-md5"
                    | "--legacy-no-qop"
            ) || values.insert(key.to_owned(), pair[1].clone()).is_some()
            {
                return Err(ARGUMENT_ERROR);
            }
        }
        for key in ["--owner-authorized", "--plaintext", "--subscribe"] {
            if text(&values, key)? != "yes" {
                return Err(ARGUMENT_ERROR);
            }
        }
        let root = PathBuf::from(values.get("--root").ok_or(ARGUMENT_ERROR)?);
        if !clean_absolute(&root) {
            return Err(ARGUMENT_ERROR);
        }
        let site = text(&values, "--site")?.to_owned();
        fss_reference::reference_deployment::validate_site_lineage(&site)
            .map_err(|_| ARGUMENT_ERROR)?;
        if site.len() > 256 {
            return Err(ARGUMENT_ERROR);
        }
        let principal = values
            .get("--principal")
            .map_or(Ok("operator:local-onvif-metadata"), |v| {
                v.to_str().ok_or(ARGUMENT_ERROR)
            })?
            .to_owned();
        if principal.is_empty() || principal.len() > 256 || principal.chars().any(char::is_control)
        {
            return Err(ARGUMENT_ERROR);
        }
        let sensor = SensorId::parse(text(&values, "--sensor")?).map_err(|_| ARGUMENT_ERROR)?;
        if sensor.as_str().len() > 256 {
            return Err(ARGUMENT_ERROR);
        }
        let device_generation = digest(text(&values, "--device-generation")?)?;
        let profile_generation = digest(text(&values, "--profile-generation")?)?;
        let profile = text(&values, "--profile")?.to_owned();
        if profile.is_empty()
            || profile.len() > 256
            || profile.trim() != profile
            || profile.chars().any(char::is_control)
        {
            return Err(ARGUMENT_ERROR);
        }
        let receive_origin_ns = text(&values, "--receive-origin-ns")?
            .parse::<i128>()
            .map_err(|_| ARGUMENT_ERROR)?;
        let timeout_ns = unsigned(&values, "--timeout-ms", 30000, 5000, 60000)?
            .checked_mul(1_000_000)
            .ok_or(ARGUMENT_ERROR)?;
        if receive_origin_ns < 0
            || receive_origin_ns
                .checked_add(i128::from(timeout_ns))
                .is_none()
        {
            return Err(ARGUMENT_ERROR);
        }
        let max_pulls = unsigned(&values, "--max-pulls", 4, 1, 32)? as u32;
        let pull_timeout_seconds = unsigned(&values, "--poll-seconds", 5, 1, 30)? as u32;
        let message_limit = unsigned(&values, "--message-limit", 128, 1, 128)? as u16;
        let lifetime_seconds = unsigned(&values, "--lifetime-seconds", 120, 5, 3600)? as u32;
        let max_steps = unsigned(&values, "--max-steps", 100000, 2048, 100000)? as u32;
        let generation = unsigned(&values, "--generation", 1, 1, u64::MAX)?;
        let peer = text(&values, "--peer")?
            .parse::<SocketAddr>()
            .map_err(|_| ARGUMENT_ERROR)?;
        let authority = text(&values, "--authority")?;
        let target = text(&values, "--events-path")?;
        let service_root = text(&values, "--service-root")?.to_owned();
        let auth_values = [
            "--credential-file",
            "--auth-realm",
            "--legacy-md5",
            "--legacy-no-qop",
        ]
        .into_iter()
        .filter_map(|key| values.get(key).map(|v| (key, v)))
        .map(|(key, value)| Ok((key, value.to_str().ok_or(ARGUMENT_ERROR)?)))
        .collect::<Result<BTreeMap<_, _>, &'static str>>()?;
        let auth = AuthPlan::parse(&auth_values, |value| {
            let path = PathBuf::from(value);
            if clean_absolute(&path) {
                Ok(path)
            } else {
                Err(ARGUMENT_ERROR)
            }
        })
        .map_err(|_| ARGUMENT_ERROR)?;

        // Bind defaults as well as exact user arguments, including the finite
        // subscription lifecycle. No credential values enter this identity.
        let mut e = CanonicalEncoder::new();
        e.text("fss.onvif_metadata_capture_request.v1");
        e.text("one-pullpoint:create:bounded-pull:unsubscribe:no-automatic-reconnect");
        for (key, value) in &values {
            e.text(key);
            e.bytes(value.as_encoded_bytes());
        }
        for value in [
            timeout_ns,
            u64::from(max_pulls),
            u64::from(pull_timeout_seconds),
            u64::from(message_limit),
            u64::from(lifetime_seconds),
            u64::from(max_steps),
            generation,
        ] {
            e.u64(value);
        }
        e.text(&principal);
        let approval = ContentDigest::sha256(&e.finish_checked().map_err(|_| ARGUMENT_ERROR)?);
        let events = HttpRoute::event_service(peer, authority, target, generation, approval)
            .map_err(|_| ARGUMENT_ERROR)?;
        if !route_in_service_root(&events, &service_root) {
            return Err(ARGUMENT_ERROR);
        }
        let credentials = auth.as_ref().map(|auth| auth.credential_file.clone());
        let config = PullPointConfig {
            events,
            service_root,
            auth: auth.map(|auth| DigestConfig {
                expected_realm: auth.realm,
                policy: auth.policy,
            }),
            limits: HttpLimits::default(),
            deadline_ns: timeout_ns,
            max_steps,
            max_pulls,
            pull_timeout_seconds,
            message_limit,
            lifetime_seconds,
        };
        fss_reference::onvif::pullpoint::validate_config(&config).map_err(|_| ARGUMENT_ERROR)?;
        Ok(Self {
            root,
            site,
            principal,
            sensor,
            device_generation,
            profile_generation,
            profile,
            receive_origin_ns,
            approval,
            credentials,
            config,
        })
    }
}
