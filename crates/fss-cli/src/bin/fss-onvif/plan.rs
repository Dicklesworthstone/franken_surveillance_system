#![forbid(unsafe_code)]
//! Pure operator plan; credentials, clocks, paths and sockets are unopened here.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest, PrincipalId};
use fss_reference::onvif::client::{
    AuthenticationConfig, ClientConfig, DigestConfig, RtspScope, validate_stream_uri,
};
use fss_reference::onvif::http::{HttpLimits, HttpRoute};
use fss_reference::onvif::wire::{MediaVersion, get_stream_uri_request};

use super::authentication::AuthPlan;
use super::handoff::digest;
use super::private_file::absolute_path;

pub(super) const MAX_ARGUMENTS: usize = 48;
const ARGUMENT: &str = "ERR-ONVIF-ARGUMENT-001";
const MEDIA1_POLICY: &str = "read-only-media1:same-pinned-http-origin:explicit-service-subtree:\
one-scoped-digest-retry:no-basic-no-wsse-no-tls:private-create-only-metadata:\
independently-pinned-rtsp:stable-avc-uri:no-capture-authority:v1";
const MEDIA2_POLICY: &str = "read-only-media2:same-pinned-http-origin:explicit-service-subtree:\
one-scoped-digest-retry:no-basic-no-wsse-no-tls:private-create-only-metadata:\
independently-pinned-rtsp:media2-indefinite-avc-hevc-uri:no-capture-authority:v2";
const USERNAME_TOKEN_MEDIA1_POLICY: &str = "read-only-media1:same-pinned-http-origin:\
explicit-service-subtree:username-token-passworddigest-sha1:\
one-unsigned-getsystemdatetime:camera-utc-plus-owned-monotonic:token-freshness-only:\
fresh-128bit-nonce-per-request:no-http-auth-fallback-no-basic-no-tls:\
private-create-only-metadata:independently-pinned-rtsp:stable-avc-uri:\
no-capture-authority-no-capture-time-claim:v3";
const USERNAME_TOKEN_MEDIA2_POLICY: &str = "read-only-media2:same-pinned-http-origin:\
explicit-service-subtree:username-token-passworddigest-sha1:\
one-unsigned-getsystemdatetime:camera-utc-plus-owned-monotonic:token-freshness-only:\
fresh-128bit-nonce-per-request:no-http-auth-fallback-no-basic-no-tls:\
private-create-only-metadata:independently-pinned-rtsp:media2-indefinite-avc-hevc-uri:\
no-capture-authority-no-capture-time-claim:v3";
pub(super) const HELP: &str = "fss-onvif --peer IP:PORT --authority HOST[:PORT]\n\
  --device-path /onvif/device_service --service-root /onvif\n\
  --output NEW_ABSOLUTE_PRIVATE_FILE --owner-authorized yes --plaintext yes\n\
  [--media-version media1|media2]\n\
  [--auth-mode http-digest|username-token]\n\
  [--credential-file /PRIVATE_CREDENTIAL_FILE --auth-realm EXACT_REALM]\n\
  [--legacy-md5 yes] [--legacy-no-qop yes]\n\
  [--profile TOKEN --rtsp-peer IP:PORT --rtsp-authority HOST[:PORT]]\n\
  [--generation 1] [--timeout-ms 30000] [--max-steps 20000]\n\
  [--max-response-bytes 262144] [--connect-timeout-ms 5000]\n\
  [--principal principal:local-operator] [--approve sha256:HEX]\n\
\n\
Without --approve, output is a pure plan: no files, clock, credentials or network are opened.\n\
Repeat the exact options with the returned approval for bounded owner-authorized SOAP requests.\n\
Media1 (default) uses GetCapabilities and GetProfiles. Explicit --media-version media2 uses\n\
GetServices and Media2 GetProfiles with VideoEncoder configurations. Read the private inventory\n\
to choose an exact profile token. An approved --profile request retrieves its RTSP URI and writes\n\
a private handoff for `fss-capture-rtsp from-onvif`. This command never starts video capture.\n\
\n\
The HTTP peer is a literal address. Its exact Host origin and service subtree are approved;\n\
advertised services outside that origin/subtree are refused. No DNS, redirect, account discovery,\n\
device settings, PTZ, audio, transport fallback or Basic authentication is performed.\n\
For selection, independently approve the RTSP peer and exact authority. Returned URI spelling is\n\
preserved and must match that scope. Media1 supports AVC/H.264 with false invalidation flags and\n\
zero timeout. Media2 supports AVC/H.264 and HEVC/H.265 with Media2's indefinite URI contract; its\n\
handoff records that validity basis explicitly. Native capture must verify the selected SDP codec.\n\
\n\
HTTP Digest is the default authentication mode. Configure it with --credential-file and\n\
--auth-realm; SHA-256 with qop=auth is default, and MD5/no-qop each need legacy approval.\n\
Explicit --auth-mode username-token uses WS-Security PasswordDigest, requires --credential-file,\n\
and rejects --auth-realm and either legacy option, including a value of no. It first sends one\n\
unsigned GetSystemDateAndTime to the pinned device endpoint, then signs two inventory requests\n\
or three selection requests with fresh nonces. The camera UTC plus owned monotonic elapsed time\n\
is used only for token freshness; no host wall clock, guessed offset or HTTP-auth fallback is used.\n\
Camera time is unauthenticated and establishes no capture-time truth. This mode requires its own\n\
v3 approval. PasswordDigest neither encrypts the transport nor authenticates the server.\n\
\n\
Both authentication modes use the existing Linux private regular-file credential owner. The file\n\
contains exactly username LF password LF, has one link, owner-read permission and no group/other\n\
permissions. It is never read before approval. Rotation/removal/modification revokes the lease.\n\
Credentials never appear in argv, output, handoff or errors. HTTP is explicitly unencrypted and its server\n\
identity is not authenticated. RTSP capture needs its own independently approved credential scope.\n\
\n\
Output uses Linux create-only mode 0600 under an existing canonical directory that is not writable\n\
by group/others. No file or symlink is overwritten. Stdout contains only safe counts, digests and\n\
outcomes; device names, profile tokens and exact stream URIs remain in the private output.\n\
Retain a partial output after failure for inspection; retry only with a new output path/approval.\n\
Successful onboarding does not establish media continuity, recording custody, Profile T\n\
conformance, device firmware qualification, useful scene coverage or capture-time truth.\n";

pub(super) enum OnvifAuthPlan {
    HttpDigest(AuthPlan),
    UsernameTokenDigest { credential_file: PathBuf },
}

impl OnvifAuthPlan {
    fn parse(values: &BTreeMap<&str, &str>) -> Result<Option<Self>, &'static str> {
        match values.get("--auth-mode").copied().unwrap_or("http-digest") {
            "http-digest" => AuthPlan::parse(values, absolute_path)
                .map(|auth| auth.map(Self::HttpDigest))
                .map_err(|_| ARGUMENT),
            "username-token" => {
                if ["--auth-realm", "--legacy-md5", "--legacy-no-qop"]
                    .iter()
                    .any(|key| values.contains_key(key))
                {
                    return Err(ARGUMENT);
                }
                let path = values.get("--credential-file").copied().ok_or(ARGUMENT)?;
                Ok(Some(Self::UsernameTokenDigest {
                    credential_file: absolute_path(path)?,
                }))
            }
            _ => Err(ARGUMENT),
        }
    }

    pub(super) fn credential_file(&self) -> &Path {
        match self {
            Self::HttpDigest(auth) => &auth.credential_file,
            Self::UsernameTokenDigest { credential_file } => credential_file,
        }
    }

    fn preview(&self) -> String {
        match self {
            Self::HttpDigest(auth) => auth.preview(),
            Self::UsernameTokenDigest { credential_file } => object(&[
                ("mode", string("username-token")),
                ("password_type", string("PasswordDigest")),
                (
                    "credential_file",
                    string(&credential_file.to_string_lossy()),
                ),
                ("credential_backend", string("linux_private_regular_file")),
                ("entropy_backend", string("linux_urandom")),
                ("nonce_bytes_per_request", "16".into()),
                ("clock_bootstrap", string("unsigned-GetSystemDateAndTime")),
                (
                    "created_time_source",
                    string("camera-utc-plus-owned-monotonic"),
                ),
                ("camera_clock_purpose", string("token-freshness-only")),
                ("camera_clock_authenticated", "false".into()),
                ("capture_time_truth", "false".into()),
                ("http_auth_fallback", "false".into()),
                ("credentials_read", "false".into()),
                ("server_identity_verified", "false".into()),
                ("transport_encrypted", "false".into()),
            ]),
        }
    }
}

pub(super) struct Plan {
    pub(super) media_version: MediaVersion,
    pub(super) peer: SocketAddr,
    pub(super) authority: String,
    pub(super) device_path: String,
    pub(super) service_root: String,
    pub(super) generation: u64,
    pub(super) output: PathBuf,
    pub(super) profile: Option<String>,
    pub(super) rtsp: Option<RtspScope>,
    pub(super) auth: Option<OnvifAuthPlan>,
    pub(super) timeout_ns: u64,
    pub(super) max_steps: u32,
    pub(super) limits: HttpLimits,
    pub(super) principal: String,
    pub(super) approval: Option<ContentDigest>,
}

impl Plan {
    pub(super) fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err(ARGUMENT);
        }
        const ALLOWED: &[&str] = &[
            "--peer",
            "--authority",
            "--device-path",
            "--service-root",
            "--output",
            "--owner-authorized",
            "--plaintext",
            "--media-version",
            "--auth-mode",
            "--profile",
            "--rtsp-peer",
            "--rtsp-authority",
            "--credential-file",
            "--auth-realm",
            "--legacy-md5",
            "--legacy-no-qop",
            "--generation",
            "--timeout-ms",
            "--max-steps",
            "--max-response-bytes",
            "--connect-timeout-ms",
            "--principal",
            "--approve",
        ];
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or(ARGUMENT)?;
            let value = pair[1].to_str().ok_or(ARGUMENT)?;
            if !ALLOWED.contains(&key)
                || value.is_empty()
                || value.starts_with("--")
                || values.insert(key, value).is_some()
            {
                return Err(ARGUMENT);
            }
        }
        let required = |key| values.get(key).copied().ok_or(ARGUMENT);
        if required("--owner-authorized")? != "yes" || required("--plaintext")? != "yes" {
            return Err(ARGUMENT);
        }
        let media_version = match values.get("--media-version").copied().unwrap_or("media1") {
            "media1" => MediaVersion::Media1,
            "media2" => MediaVersion::Media2,
            _ => return Err(ARGUMENT),
        };
        let number = |key, default, low, high| {
            let value = values.get(key).map_or(Ok(default), |text| {
                if !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(ARGUMENT);
                }
                text.parse::<u64>().map_err(|_| ARGUMENT)
            })?;
            if !(low..=high).contains(&value) {
                return Err(ARGUMENT);
            }
            Ok(value)
        };
        let peer = required("--peer")?.parse().map_err(|_| ARGUMENT)?;
        let authority = required("--authority")?.to_owned();
        let device_path = required("--device-path")?.to_owned();
        let service_root = required("--service-root")?.to_owned();
        let generation = number("--generation", 1, 1, u64::MAX)?;
        let probe = ContentDigest::sha256(b"fss.onvif.pure-plan-validation.v1");
        HttpRoute::new(peer, &authority, &device_path, generation, probe).map_err(|_| ARGUMENT)?;
        HttpRoute::new(peer, &authority, &service_root, generation, probe).map_err(|_| ARGUMENT)?;
        if service_root.ends_with('/') && service_root != "/" {
            return Err(ARGUMENT);
        }
        if !in_service_root(&device_path, &service_root) {
            return Err(ARGUMENT);
        }
        let profile = values.get("--profile").map(|value| (*value).to_owned());
        if let Some(token) = &profile {
            get_stream_uri_request(token).map_err(|_| ARGUMENT)?;
        }
        let rtsp = match (
            values.get("--rtsp-peer"),
            values.get("--rtsp-authority"),
            profile.is_some(),
        ) {
            (None, None, false) => None,
            (Some(peer), Some(authority), true) => {
                let scope = RtspScope {
                    peer: peer.parse().map_err(|_| ARGUMENT)?,
                    authority: (*authority).to_owned(),
                };
                validate_stream_uri(&format!("rtsp://{authority}/"), &scope)
                    .map_err(|_| ARGUMENT)?;
                Some(scope)
            }
            _ => return Err(ARGUMENT),
        };
        let auth = OnvifAuthPlan::parse(&values)?;
        let output = absolute_path(required("--output")?)?;
        if auth
            .as_ref()
            .is_some_and(|auth| output == auth.credential_file())
        {
            return Err(ARGUMENT);
        }
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| ARGUMENT)?;
        if principal.len() > 256 {
            return Err(ARGUMENT);
        }
        let body_bytes = number("--max-response-bytes", 262144, 1024, 1048576)? as usize;
        let limits = HttpLimits {
            body_bytes,
            wire_bytes: (body_bytes * 2).min(2097152),
            connect_timeout_ns: number("--connect-timeout-ms", 5000, 1, 5000)? * 1_000_000,
            ..HttpLimits::default()
        };
        Ok(Self {
            media_version,
            peer,
            authority,
            device_path,
            service_root,
            generation,
            output,
            profile,
            rtsp,
            auth,
            timeout_ns: number("--timeout-ms", 30000, 1, 60000)? * 1_000_000,
            max_steps: number("--max-steps", 20000, 1, 100000)? as u32,
            limits,
            principal,
            approval: values
                .get("--approve")
                .map(|text| digest(text))
                .transpose()?,
        })
    }

    pub(super) fn digest(&self) -> Result<ContentDigest, &'static str> {
        let mut encoded = CanonicalEncoder::new();
        // Existing unsigned/HTTP Digest v1/v2 plans retain their exact bytes.
        // UsernameToken has a distinct domain, mode, media and clock policy.
        encoded.text(self.schema());
        encoded.text(self.policy());
        if self.uses_username_token() {
            encoded.text(self.media_version_name());
        }
        for text in [
            self.peer.to_string().as_str(),
            &self.authority,
            &self.device_path,
            &self.service_root,
            self.output.to_str().ok_or(ARGUMENT)?,
            &self.principal,
        ] {
            encoded.text(text);
        }
        encoded.u64(self.generation);
        encoded.bool(self.profile.is_some());
        if let Some(profile) = &self.profile {
            encoded.text(profile);
        }
        encoded.bool(self.rtsp.is_some());
        if let Some(scope) = &self.rtsp {
            encoded.text(&scope.peer.to_string());
            encoded.text(&scope.authority);
        }
        encoded.bool(self.auth.is_some());
        if let Some(auth) = &self.auth {
            match auth {
                OnvifAuthPlan::HttpDigest(auth) => {
                    encoded.text(auth.credential_file.to_str().ok_or(ARGUMENT)?);
                    encoded.text(&auth.realm);
                    encoded.bool(auth.policy.allow_legacy_md5);
                    encoded.bool(auth.policy.allow_legacy_no_qop);
                }
                OnvifAuthPlan::UsernameTokenDigest { credential_file } => {
                    encoded.text("username-token");
                    encoded.text(credential_file.to_str().ok_or(ARGUMENT)?);
                }
            }
        }
        for number in [
            self.timeout_ns,
            self.max_steps as u64,
            self.limits.request_bytes as u64,
            self.limits.header_bytes as u64,
            self.limits.body_bytes as u64,
            self.limits.wire_bytes as u64,
            self.limits.io_bytes as u64,
            self.limits.io_calls,
            self.limits.connect_timeout_ns,
        ] {
            encoded.u64(number);
        }
        Ok(ContentDigest::sha256(
            &encoded.finish_checked().map_err(|_| ARGUMENT)?,
        ))
    }

    pub(super) fn config(&self, approval: ContentDigest) -> Result<ClientConfig, &'static str> {
        Ok(ClientConfig {
            media_version: self.media_version,
            device: HttpRoute::new(
                self.peer,
                &self.authority,
                &self.device_path,
                self.generation,
                approval,
            )
            .map_err(|_| ARGUMENT)?,
            service_root: self.service_root.clone(),
            auth: self.auth.as_ref().map(|auth| match auth {
                OnvifAuthPlan::HttpDigest(auth) => AuthenticationConfig::HttpDigest(DigestConfig {
                    expected_realm: auth.realm.clone(),
                    policy: auth.policy,
                }),
                OnvifAuthPlan::UsernameTokenDigest { .. } => {
                    AuthenticationConfig::UsernameTokenDigest
                }
            }),
            rtsp: self.rtsp.clone(),
            limits: self.limits,
            deadline_ns: self.timeout_ns,
            max_steps: self.max_steps,
        })
    }

    pub(super) fn preview(&self) -> Result<String, &'static str> {
        Ok(object(&[
            ("schema", string(self.schema())),
            ("phase", string("planned")),
            ("approval", string(&self.digest()?.to_text())),
            ("policy", string(self.policy())),
            ("media_version", string(self.media_version_name())),
            ("peer", string(&self.peer.to_string())),
            ("authority", string(&self.authority)),
            ("device_path", string(&self.device_path)),
            ("service_root", string(&self.service_root)),
            ("generation", self.generation.to_string()),
            ("output", string(self.output.to_str().ok_or(ARGUMENT)?)),
            (
                "profile_digest",
                self.profile.as_ref().map_or_else(
                    || "null".into(),
                    |token| string(&ContentDigest::sha256(token.as_bytes()).to_text()),
                ),
            ),
            (
                "rtsp_peer",
                self.rtsp
                    .as_ref()
                    .map_or_else(|| "null".into(), |scope| string(&scope.peer.to_string())),
            ),
            (
                "rtsp_authority",
                self.rtsp
                    .as_ref()
                    .map_or_else(|| "null".into(), |scope| string(&scope.authority)),
            ),
            (
                "authentication",
                self.auth
                    .as_ref()
                    .map_or_else(|| string("challenge-refused"), OnvifAuthPlan::preview),
            ),
            ("timeout_ns", self.timeout_ns.to_string()),
            ("max_steps", self.max_steps.to_string()),
            ("max_response_bytes", self.limits.body_bytes.to_string()),
            ("max_http_exchanges", self.max_http_exchanges().to_string()),
            ("credentials_read", "false".into()),
            ("capture_authorized", "false".into()),
            ("effects", string("none-until-exact-approval")),
        ]) + "\n")
    }

    pub(super) fn media_version_name(&self) -> &'static str {
        match self.media_version {
            MediaVersion::Media1 => "media1",
            MediaVersion::Media2 => "media2",
        }
    }

    pub(super) fn uses_username_token(&self) -> bool {
        matches!(&self.auth, Some(OnvifAuthPlan::UsernameTokenDigest { .. }))
    }

    pub(super) fn max_http_exchanges(&self) -> u64 {
        match (self.uses_username_token(), self.profile.is_some()) {
            (true, false) => 3,
            (true, true) => 4,
            (false, false) => 4,
            (false, true) => 6,
        }
    }

    fn schema(&self) -> &'static str {
        if self.uses_username_token() {
            return "fss.onvif_operator_plan.v3";
        }
        match self.media_version {
            MediaVersion::Media1 => "fss.onvif_operator_plan.v1",
            MediaVersion::Media2 => "fss.onvif_operator_plan.v2",
        }
    }

    fn policy(&self) -> &'static str {
        match (self.uses_username_token(), self.media_version) {
            (false, MediaVersion::Media1) => MEDIA1_POLICY,
            (false, MediaVersion::Media2) => MEDIA2_POLICY,
            (true, MediaVersion::Media1) => USERNAME_TOKEN_MEDIA1_POLICY,
            (true, MediaVersion::Media2) => USERNAME_TOKEN_MEDIA2_POLICY,
        }
    }
}

pub(super) fn in_service_root(path: &str, root: &str) -> bool {
    root == "/"
        || path == root
        || path
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(extra: &[&str]) -> Vec<OsString> {
        [
            "--peer",
            "127.0.0.1:8080",
            "--authority",
            "127.0.0.1:8080",
            "--device-path",
            "/onvif/device_service",
            "--service-root",
            "/onvif",
            "--output",
            "/tmp/fss-media-version-handoff.json",
            "--owner-authorized",
            "yes",
            "--plaintext",
            "yes",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn unsigned_and_http_digest_approval_bytes_remain_compatible() {
        // Independently reconstructed using the pre-UsernameToken canonical
        // field order and big-endian encoding; the first also matches 410a257.
        let golden = [
            (
                "media1",
                0,
                "sha256:208bbac9cd0f816ff3bc6c0c1ee922bc846cf09b5cae30ac1ca97615d1824060",
            ),
            (
                "media1",
                1,
                "sha256:ef8a80f11b36522e8a2de0241d0ca2473de6bbe7aee6d5ca6705c9103ef079ca",
            ),
            (
                "media1",
                2,
                "sha256:e7a770ecb39c549a97065213852a9b272220a0413ca83bbdb422626a6cce34b3",
            ),
            (
                "media2",
                0,
                "sha256:5cdbdb008c8afb89868f8ce03763c9ba78edafefeb25154c05d70e03d1c268da",
            ),
            (
                "media2",
                1,
                "sha256:8dea8c906fab858ff59d2a88d97a7d65e8095c5f6128c07f5638f55596367f34",
            ),
            (
                "media2",
                2,
                "sha256:f28d3bf140a5cbc736ebda14a0e47ddf12c6a33e9b345c6964b9c0fb9cb4d25a",
            ),
        ];
        for (media, mode, expected) in golden {
            let mut extra = vec!["--media-version", media];
            if mode != 0 {
                extra.extend([
                    "--credential-file",
                    "/tmp/fss-onvif-credentials",
                    "--auth-realm",
                    "camera",
                ]);
            }
            if mode == 2 {
                extra.extend([
                    "--legacy-md5",
                    "yes",
                    "--legacy-no-qop",
                    "yes",
                    "--profile",
                    "main",
                    "--rtsp-peer",
                    "127.0.0.1:554",
                    "--rtsp-authority",
                    "127.0.0.1:554",
                ]);
            }
            let default = Plan::parse(&arguments(&extra)).unwrap();
            assert_eq!(default.digest().unwrap().to_text(), expected);
            extra.extend(["--auth-mode", "http-digest"]);
            let explicit = Plan::parse(&arguments(&extra)).unwrap();
            assert_eq!(explicit.digest().unwrap(), default.digest().unwrap());
            assert_eq!(explicit.preview().unwrap(), default.preview().unwrap());
        }
    }

    #[test]
    fn username_token_requires_credentials_and_rejects_digest_options_even_when_disabled() {
        assert!(Plan::parse(&arguments(&["--auth-mode", "username-token"])).is_err());
        for (option, value) in [
            ("--auth-realm", "camera"),
            ("--legacy-md5", "yes"),
            ("--legacy-md5", "no"),
            ("--legacy-no-qop", "yes"),
            ("--legacy-no-qop", "no"),
        ] {
            assert!(
                Plan::parse(&arguments(&[
                    "--auth-mode",
                    "username-token",
                    "--credential-file",
                    "/tmp/fss-onvif-credentials",
                    option,
                    value,
                ]))
                .is_err()
            );
        }
        assert!(
            Plan::parse(&arguments(&[
                "--auth-mode",
                "auto",
                "--credential-file",
                "/tmp/fss-onvif-credentials",
            ]))
            .is_err()
        );
        assert!(
            Plan::parse(&arguments(&[
                "--auth-mode",
                "username-token",
                "--credential-file",
                "/tmp/fss-media-version-handoff.json",
            ]))
            .is_err()
        );
        assert!(
            Plan::parse(&arguments(&[
                "--auth-mode",
                "username-token",
                "--credential-file",
                "relative-credentials",
            ]))
            .is_err()
        );
    }

    #[test]
    fn username_token_approval_binds_mode_media_selection_and_clock_policy() {
        let base = [
            "--auth-mode",
            "username-token",
            "--credential-file",
            "/tmp/fss-onvif-credentials",
        ];
        let plan = Plan::parse(&arguments(&base)).unwrap();
        let approval = plan.digest().unwrap();
        assert!(plan.uses_username_token());
        assert_eq!(plan.schema(), "fss.onvif_operator_plan.v3");
        assert_eq!(plan.max_http_exchanges(), 3);
        assert!(matches!(
            plan.config(approval).unwrap().auth,
            Some(AuthenticationConfig::UsernameTokenDigest)
        ));
        let preview = plan.preview().unwrap();
        for field in [
            "\"clock_bootstrap\":\"unsigned-GetSystemDateAndTime\"",
            "\"created_time_source\":\"camera-utc-plus-owned-monotonic\"",
            "\"camera_clock_authenticated\":false",
            "\"capture_time_truth\":false",
            "\"http_auth_fallback\":false",
            "\"credentials_read\":false",
            "\"max_http_exchanges\":3",
        ] {
            assert!(preview.contains(field), "missing {field}");
        }
        assert!(plan.policy().contains(
            "one-unsigned-getsystemdatetime:camera-utc-plus-owned-monotonic:token-freshness-only"
        ));
        assert!(
            plan.policy()
                .contains("fresh-128bit-nonce-per-request:no-http-auth-fallback")
        );

        let digest = Plan::parse(&arguments(&[
            "--credential-file",
            "/tmp/fss-onvif-credentials",
            "--auth-realm",
            "camera",
        ]))
        .unwrap()
        .digest()
        .unwrap();
        assert_ne!(approval, digest);
        let mut options = base.to_vec();
        options.extend(["--media-version", "media2"]);
        let media2 = Plan::parse(&arguments(&options)).unwrap();
        assert_ne!(media2.digest().unwrap(), approval);
        assert_eq!(media2.schema(), "fss.onvif_operator_plan.v3");
        options.extend([
            "--profile",
            "main",
            "--rtsp-peer",
            "127.0.0.1:554",
            "--rtsp-authority",
            "127.0.0.1:554",
        ]);
        let selection = Plan::parse(&arguments(&options)).unwrap();
        assert_ne!(selection.digest().unwrap(), media2.digest().unwrap());
        assert_eq!(selection.max_http_exchanges(), 4);
        let mut alternate = Plan::parse(&arguments(&base)).unwrap();
        alternate.auth = Some(OnvifAuthPlan::UsernameTokenDigest {
            credential_file: PathBuf::from("/tmp/fss-other-credentials"),
        });
        assert_ne!(alternate.digest().unwrap(), approval);
        let mut stale = base.to_vec();
        let digest_text = digest.to_text();
        stale.extend(["--approve", &digest_text]);
        let stale = Plan::parse(&arguments(&stale)).unwrap();
        assert_ne!(stale.approval, Some(stale.digest().unwrap()));
    }

    #[test]
    fn media1_approval_is_compatible_and_media2_requires_a_distinct_approval() {
        let mut args: Vec<_> = [
            "--peer",
            "127.0.0.1:8080",
            "--authority",
            "127.0.0.1:8080",
            "--device-path",
            "/onvif/device_service",
            "--service-root",
            "/onvif",
            "--output",
            "/tmp/fss-media-version-handoff.json",
            "--owner-authorized",
            "yes",
            "--plaintext",
            "yes",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let default = Plan::parse(&args).unwrap();
        // Retained from the original Media1 binary at commit 410a257.
        let original = "sha256:208bbac9cd0f816ff3bc6c0c1ee922bc846cf09b5cae30ac1ca97615d1824060";
        assert_eq!(default.digest().unwrap().to_text(), original);
        args.extend([OsString::from("--media-version"), OsString::from("media1")]);
        assert_eq!(
            Plan::parse(&args).unwrap().digest().unwrap(),
            default.digest().unwrap()
        );
        *args.last_mut().unwrap() = OsString::from("media2");
        let media2 = Plan::parse(&args).unwrap();
        assert_ne!(media2.digest().unwrap(), default.digest().unwrap());
        assert_eq!(
            media2
                .config(media2.digest().unwrap())
                .unwrap()
                .media_version,
            MediaVersion::Media2
        );
        assert!(
            media2
                .preview()
                .unwrap()
                .contains("\"media_version\":\"media2\"")
        );
        *args.last_mut().unwrap() = OsString::from("auto");
        assert!(Plan::parse(&args).is_err());
    }
}
