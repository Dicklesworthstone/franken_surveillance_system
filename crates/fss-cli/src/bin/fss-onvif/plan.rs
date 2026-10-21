#![forbid(unsafe_code)]
//! Pure operator plan; credentials, clocks, paths and sockets are unopened here.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest, PrincipalId};
use fss_reference::onvif::client::{ClientConfig, DigestConfig, RtspScope, validate_stream_uri};
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
pub(super) const HELP: &str = "fss-onvif --peer IP:PORT --authority HOST[:PORT]\n\
  --device-path /onvif/device_service --service-root /onvif\n\
  --output NEW_ABSOLUTE_PRIVATE_FILE --owner-authorized yes --plaintext yes\n\
  [--media-version media1|media2]\n\
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
device settings, PTZ, audio, transport fallback, Basic or WS-Security is performed.\n\
For selection, independently approve the RTSP peer and exact authority. Returned URI spelling is\n\
preserved and must match that scope. Media1 supports AVC/H.264 with false invalidation flags and\n\
zero timeout. Media2 supports AVC/H.264 and HEVC/H.265 with Media2's indefinite URI contract; its\n\
handoff records that validity basis explicitly. Native capture must verify the selected SDP codec.\n\
\n\
Optional HTTP Digest uses the existing Linux private regular-file credential owner. The file\n\
contains exactly username LF password LF, has one link, owner-read permission and no group/other\n\
permissions. It is never read before approval. Rotation/removal/modification revokes the lease.\n\
SHA-256 with qop=auth is default; MD5 and no-qop each require explicit legacy approval. Credentials\n\
never appear in argv, output, handoff or errors. HTTP is explicitly unencrypted and its server\n\
identity is not authenticated. RTSP capture needs its own independently approved credential scope.\n\
\n\
Output uses Linux create-only mode 0600 under an existing canonical directory that is not writable\n\
by group/others. No file or symlink is overwritten. Stdout contains only safe counts, digests and\n\
outcomes; device names, profile tokens and exact stream URIs remain in the private output.\n\
Retain a partial output after failure for inspection; retry only with a new output path/approval.\n\
Successful onboarding does not establish media continuity, recording custody, Profile T\n\
conformance, device firmware qualification, useful scene coverage or capture-time truth.\n";

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
    pub(super) auth: Option<AuthPlan>,
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
        let auth = AuthPlan::parse(&values, absolute_path).map_err(|_| ARGUMENT)?;
        let output = absolute_path(required("--output")?)?;
        if auth
            .as_ref()
            .is_some_and(|auth| output == auth.credential_file)
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
        // Existing Media1 plans retain their exact digest bytes. Selecting Media2
        // changes both the domain and approved protocol policy before any I/O.
        encoded.text(self.schema());
        encoded.text(self.policy());
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
            encoded.text(auth.credential_file.to_str().ok_or(ARGUMENT)?);
            encoded.text(&auth.realm);
            encoded.bool(auth.policy.allow_legacy_md5);
            encoded.bool(auth.policy.allow_legacy_no_qop);
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
            auth: self.auth.as_ref().map(|auth| DigestConfig {
                expected_realm: auth.realm.clone(),
                policy: auth.policy,
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
                    .map_or_else(|| string("challenge-refused"), AuthPlan::preview),
            ),
            ("timeout_ns", self.timeout_ns.to_string()),
            ("max_steps", self.max_steps.to_string()),
            ("max_response_bytes", self.limits.body_bytes.to_string()),
            (
                "max_http_exchanges",
                if self.profile.is_some() { "6" } else { "4" }.into(),
            ),
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

    fn schema(&self) -> &'static str {
        match self.media_version {
            MediaVersion::Media1 => "fss.onvif_operator_plan.v1",
            MediaVersion::Media2 => "fss.onvif_operator_plan.v2",
        }
    }

    fn policy(&self) -> &'static str {
        match self.media_version {
            MediaVersion::Media1 => MEDIA1_POLICY,
            MediaVersion::Media2 => MEDIA2_POLICY,
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
