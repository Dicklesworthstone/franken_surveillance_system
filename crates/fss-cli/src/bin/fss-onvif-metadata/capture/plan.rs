#![forbid(unsafe_code)]
//! Pure, explicitly authorized bounded subscription plan. No secrets or I/O.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, SensorId};
use fss_reference::onvif::client::DigestConfig;
use fss_reference::onvif::http::{HttpLimits, HttpRoute};
use fss_reference::onvif::pullpoint::{MAX_RENEWALS, PullPointConfig, route_in_service_root};

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
  [--max-steps 100000] [--max-renewals 0]
  [--credential-file /PRIVATE_FILE --auth-realm EXACT_REALM]
  [--legacy-md5 yes] [--legacy-no-qop yes]

Creates one finite device-event PullPoint subscription, retains complete event responses,
then attempts Unsubscribe within the original deadline. No automatic reconnect.
Renewal is opt-in: --max-renewals 1..4 allows bounded extensions using --lifetime-seconds.
Each renewal preserves the original session deadline, poll limit and cleanup reserve.
Its intent is durably recorded before dispatch; an uncertain response never causes retry.
The peer is a literal IP; authority and service subtree remain independently pinned.
Only explicit plaintext HTTP with optional HTTP Digest is supported in this lane.
Native capture requires Linux entropy, including anonymous capture. Credentials use a
private-file lease: username newline password newline.
--receive-origin-ns is the operator-declared epoch at monotonic request start.
Camera timestamps remain unverified vendor claims. Empty polls establish no coverage.
Profile pins are owner attribution; this subscription does not request a profile filter.
The deadline bounds network and cooperative storage checkpoints. An in-flight filesystem
call can finish after expiry; known durable handles are still reported.
Durable intent, Create and cleanup receipts support restart inspection and separately
approved cleanup. Output lists retained metadata/control handles and the cleanup state.
Inspect an import separately to reveal its private values. Incomplete/indeterminate
capture or cleanup returns a nonzero exit code while preserving known durable handles.
";

pub(crate) struct Plan {
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub sensor: SensorId,
    pub device_generation: ContentDigest,
    pub profile_generation: ContentDigest,
    pub profile: String,
    pub receive_origin_ns: i128,
    pub approval: ContentDigest,
    pub cleanup_expected_control: Option<ContentDigest>,
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
        Self::parse_inner(args, None)
    }

    /// Fresh approval for exactly one retained subscription cleanup. This mode
    /// never authorizes Create or PullMessages, including through capture flags.
    pub fn parse_cleanup(
        args: &[OsString],
        subscription_id: ContentDigest,
        expected_root: ContentDigest,
        expected_control: ContentDigest,
    ) -> Result<Self, &'static str> {
        if [subscription_id, expected_root, expected_control]
            .iter()
            .any(|value| value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32])
        {
            return Err(ARGUMENT_ERROR);
        }
        Self::parse_inner(
            args,
            Some((subscription_id, expected_root, expected_control)),
        )
    }

    fn parse_inner(
        args: &[OsString],
        cleanup: Option<(ContentDigest, ContentDigest, ContentDigest)>,
    ) -> Result<Self, &'static str> {
        if args.len() > 64
            || args.len() % 2 != 0
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err(ARGUMENT_ERROR);
        }
        let mut values = BTreeMap::new();
        for pair in args.chunks_exact(2) {
            let key = pair[0].to_str().ok_or(ARGUMENT_ERROR)?;
            let common = matches!(
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
                    | "--receive-origin-ns"
                    | "--generation"
                    | "--timeout-ms"
                    | "--max-steps"
                    | "--credential-file"
                    | "--auth-realm"
                    | "--legacy-md5"
                    | "--legacy-no-qop"
            );
            let action = if cleanup.is_some() {
                key == "--unsubscribe"
            } else {
                matches!(
                    key,
                    "--subscribe"
                        | "--max-pulls"
                        | "--poll-seconds"
                        | "--message-limit"
                        | "--lifetime-seconds"
                        | "--max-renewals"
                )
            };
            if !(common || action) || values.insert(key.to_owned(), pair[1].clone()).is_some() {
                return Err(ARGUMENT_ERROR);
            }
        }
        let action_approval = if cleanup.is_some() {
            "--unsubscribe"
        } else {
            "--subscribe"
        };
        for key in ["--owner-authorized", "--plaintext", action_approval] {
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
        // Cleanup reuses only the pinned route/auth/network limits from this
        // config. Its finite placeholder poll bounds never authorize polling.
        let (max_pulls, pull_timeout_seconds, message_limit, lifetime_seconds) =
            if cleanup.is_some() {
                (1, 1, 1, 5)
            } else {
                (
                    unsigned(&values, "--max-pulls", 4, 1, 32)? as u32,
                    unsigned(&values, "--poll-seconds", 5, 1, 30)? as u32,
                    unsigned(&values, "--message-limit", 128, 1, 128)? as u16,
                    unsigned(&values, "--lifetime-seconds", 120, 5, 3600)? as u32,
                )
            };
        let max_renewals = if cleanup.is_some() {
            0
        } else {
            unsigned(&values, "--max-renewals", 0, 0, u64::from(MAX_RENEWALS))? as u32
        };
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
        if let Some((subscription_id, expected_root, expected_control)) = cleanup {
            e.text("fss.onvif_metadata_unsubscribe_request.v2");
            e.text("unsubscribe-existing-only:no-create:no-pull");
            e.digest(subscription_id);
            e.digest(expected_root);
            e.digest(expected_control);
        } else {
            // Preserve the existing capture approval domain and encoding.
            e.text("fss.onvif_metadata_capture_request.v1");
            e.text("one-pullpoint:create:bounded-pull:unsubscribe:no-automatic-reconnect");
        }
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
        // Keep pre-renewal approvals byte-for-byte stable when renewal is disabled.
        // Explicit arguments are already bound above; enabled renewal also binds
        // its effective cap and distinct effect scope.
        if max_renewals > 0 {
            e.text("fss.onvif_metadata_capture_bounded_renewal.v1");
            e.u64(u64::from(max_renewals));
        }
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
            max_renewals,
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
            cleanup_expected_control: cleanup.map(|(_, _, witness)| witness),
            credentials,
            config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Test = Result<(), Box<dyn std::error::Error>>;

    fn arguments(action: &str) -> Vec<OsString> {
        let mut args: Vec<_> = [
            ("--root", "/var/lib/fss"),
            ("--site", "site:control-fixture"),
            ("--sensor", "sensor:front"),
            ("--profile", "main"),
            ("--peer", "127.0.0.1:8080"),
            ("--authority", "camera.local:8080"),
            ("--events-path", "/onvif/events"),
            ("--service-root", "/onvif"),
            ("--owner-authorized", "yes"),
            ("--plaintext", "yes"),
            (action, "yes"),
            ("--receive-origin-ns", "100"),
        ]
        .into_iter()
        .flat_map(|(key, value)| [OsString::from(key), OsString::from(value)])
        .collect();
        for (key, value) in [
            ("--device-generation", ContentDigest::sha256(b"device-v1")),
            ("--profile-generation", ContentDigest::sha256(b"profile-v1")),
        ] {
            args.extend([OsString::from(key), OsString::from(value.to_text())]);
        }
        args
    }

    fn cleanup(args: &[OsString]) -> Result<Plan, &'static str> {
        Plan::parse_cleanup(
            args,
            ContentDigest::sha256(b"created-receipt"),
            ContentDigest::sha256(b"created-root"),
            ContentDigest::sha256(b"cleanup-control-state"),
        )
    }

    #[test]
    fn ordinary_capture_preserves_its_existing_approval_and_defaults() -> Test {
        let plan = Plan::parse(&arguments("--subscribe"))?;
        assert_eq!(
            plan.approval.to_text(),
            "sha256:93d9d1a10faf1ef6c4831e3b610e7af769a5903425c5cba4f9e210eebfb03882"
        );
        assert_eq!(plan.config.max_pulls, 4);
        assert_eq!(plan.config.max_renewals, 0);
        assert_eq!(plan.config.pull_timeout_seconds, 5);
        assert_eq!(plan.config.message_limit, 128);
        assert_eq!(plan.config.lifetime_seconds, 120);
        assert_eq!(plan.config.deadline_ns, 30_000_000_000);
        assert_eq!(plan.config.max_steps, 100000);
        Ok(())
    }

    #[test]
    fn renewal_is_explicit_bounded_and_part_of_the_owner_approval() -> Test {
        let args = arguments("--subscribe");
        let baseline = Plan::parse(&args)?;
        for maximum in 0..=MAX_RENEWALS {
            let mut enabled = args.clone();
            enabled.extend([
                OsString::from("--max-renewals"),
                OsString::from(maximum.to_string()),
            ]);
            let plan = Plan::parse(&enabled)?;
            assert_eq!(plan.config.max_renewals, maximum);
            assert_eq!(plan.config.deadline_ns, baseline.config.deadline_ns);
            assert_eq!(plan.config.max_pulls, baseline.config.max_pulls);
            assert_ne!(plan.approval, baseline.approval);
            assert_eq!(plan.config.events.plaintext_approval(), plan.approval);
            let reordered: Vec<_> = enabled.chunks_exact(2).rev().flatten().cloned().collect();
            assert_eq!(Plan::parse(&reordered)?.approval, plan.approval);
        }
        for maximum in ["5", "-1", "18446744073709551616", "unbounded"] {
            let mut invalid = args.clone();
            invalid.extend([OsString::from("--max-renewals"), OsString::from(maximum)]);
            assert!(Plan::parse(&invalid).is_err());
        }
        let mut duplicate = args;
        duplicate.extend([
            OsString::from("--max-renewals"),
            OsString::from("1"),
            OsString::from("--max-renewals"),
            OsString::from("2"),
        ]);
        assert!(Plan::parse(&duplicate).is_err());
        Ok(())
    }

    #[test]
    fn cleanup_requires_owner_plaintext_and_unsubscribe_approval_now() -> Test {
        for key in ["--owner-authorized", "--plaintext", "--unsubscribe"] {
            let mut args = arguments("--unsubscribe");
            let index = args
                .chunks_exact(2)
                .position(|pair| pair[0] == key)
                .ok_or("approval argument absent from fixture")?
                * 2;
            args[index + 1] = OsString::from("no");
            assert!(cleanup(&args).is_err(), "accepted refused approval {key}");
            drop(args.drain(index..index + 2));
            assert!(cleanup(&args).is_err(), "accepted missing approval {key}");
        }
        Ok(())
    }

    #[test]
    fn cleanup_and_capture_reject_each_others_effect_arguments() -> Test {
        for (key, value) in [
            ("--subscribe", "yes"),
            ("--max-pulls", "1"),
            ("--poll-seconds", "1"),
            ("--message-limit", "1"),
            ("--lifetime-seconds", "5"),
            ("--max-renewals", "1"),
        ] {
            let mut args = arguments("--unsubscribe");
            args.extend([OsString::from(key), OsString::from(value)]);
            assert!(
                cleanup(&args).is_err(),
                "cleanup accepted capture flag {key}"
            );
        }
        let mut capture = arguments("--subscribe");
        capture.extend([OsString::from("--unsubscribe"), OsString::from("yes")]);
        assert!(Plan::parse(&capture).is_err());
        assert!(Plan::parse(&arguments("--unsubscribe")).is_err());
        assert!(cleanup(&arguments("--subscribe")).is_err());
        Ok(())
    }

    #[test]
    fn cleanup_approval_binds_both_selected_handles_and_its_distinct_action() -> Test {
        let args = arguments("--unsubscribe");
        let baseline = cleanup(&args)?.approval;
        let changed_identity = Plan::parse_cleanup(
            &args,
            ContentDigest::sha256(b"different-created-receipt"),
            ContentDigest::sha256(b"created-root"),
            ContentDigest::sha256(b"cleanup-control-state"),
        )?;
        let changed_root = Plan::parse_cleanup(
            &args,
            ContentDigest::sha256(b"created-receipt"),
            ContentDigest::sha256(b"different-created-root"),
            ContentDigest::sha256(b"cleanup-control-state"),
        )?;
        assert_ne!(baseline, changed_identity.approval);
        assert_ne!(baseline, changed_root.approval);
        let changed_control = Plan::parse_cleanup(
            &args,
            ContentDigest::sha256(b"created-receipt"),
            ContentDigest::sha256(b"created-root"),
            ContentDigest::sha256(b"different-control-state"),
        )?;
        assert_ne!(baseline, changed_control.approval);
        assert_ne!(baseline, Plan::parse(&arguments("--subscribe"))?.approval);
        Ok(())
    }

    #[test]
    fn cleanup_binds_exact_arguments_and_finite_defaults_canonically() -> Test {
        let args = arguments("--unsubscribe");
        let plan = cleanup(&args)?;
        assert_eq!(plan.config.max_pulls, 1);
        assert_eq!(plan.config.pull_timeout_seconds, 1);
        assert_eq!(plan.config.message_limit, 1);
        assert_eq!(plan.config.lifetime_seconds, 5);
        assert_eq!(plan.config.events.plaintext_approval(), plan.approval);
        let reordered: Vec<_> = args.chunks_exact(2).rev().flatten().cloned().collect();
        assert_eq!(cleanup(&reordered)?.approval, plan.approval);
        let mut explicit_default = args;
        explicit_default.extend([OsString::from("--timeout-ms"), OsString::from("30000")]);
        assert_ne!(cleanup(&explicit_default)?.approval, plan.approval);
        Ok(())
    }

    #[test]
    fn cleanup_reuses_pure_auth_validation_and_rejects_duplicates() -> Test {
        let mut args = arguments("--unsubscribe");
        args.extend([
            OsString::from("--credential-file"),
            OsString::from("/owner/private/cleanup-credentials"),
            OsString::from("--auth-realm"),
            OsString::from("camera-fixture"),
        ]);
        let plan = cleanup(&args)?;
        assert_eq!(
            plan.credentials,
            Some(PathBuf::from("/owner/private/cleanup-credentials"))
        );
        assert_eq!(
            plan.config
                .auth
                .as_ref()
                .map(|auth| auth.expected_realm.as_str()),
            Some("camera-fixture")
        );
        args.extend([OsString::from("--unsubscribe"), OsString::from("yes")]);
        assert!(cleanup(&args).is_err());
        Ok(())
    }

    #[test]
    fn cleanup_target_handles_must_be_nonzero_sha256() -> Test {
        let args = arguments("--unsubscribe");
        let valid = ContentDigest::sha256(b"selected");
        for invalid in [
            ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
            ContentDigest::new(DigestAlgorithm::Blake3, [1; 32]),
        ] {
            assert!(Plan::parse_cleanup(&args, invalid, valid, valid).is_err());
            assert!(Plan::parse_cleanup(&args, valid, invalid, valid).is_err());
            assert!(Plan::parse_cleanup(&args, valid, valid, invalid).is_err());
        }
        Ok(())
    }
}
