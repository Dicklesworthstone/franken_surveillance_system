#![forbid(unsafe_code)]
//! Native owner composes the bounded SOAP client, private secret lease and output.

use std::cell::RefCell;

use fss_cli::agent_json::{array, object, string};
use fss_core::{ContentDigest, RuntimeGrant};
use fss_reference::onvif::authentication::{UsernameToken, UtcDateTime};
use fss_reference::onvif::client::{self, ClientError, MediaDiscovery, Onboarding, OnvifContext};
use fss_reference::onvif::http::{HttpAuthority, HttpDenial, HttpOperation, HttpRoute};
use fss_reference::onvif::wire::{self, MediaVersion, SoapRequest, VideoEncoding};
use fss_reference::rtsp::authentication::{DigestAuthorization, DigestChallenge};

use super::authentication::{CredentialLease, Entropy, MAX_CREDENTIAL_BYTES, SecretError};
use super::handoff::Handoff;
use super::plan::{OnvifAuthPlan, Plan, in_service_root};
use super::private_file::{MAX_FILE_BYTES, Output};
use super::runtime::{self, Request, Scope};

struct Owner<'a, 'scope, 'task> {
    scope: &'a Scope<'scope, 'task>,
    plan: &'a Plan,
    approval: ContentDigest,
    credentials: Option<&'a CredentialLease>,
    entropy: RefCell<Option<Entropy>>,
}

fn context_error(code: &'static str) -> ClientError {
    match code {
        "ERR-ONVIF-CANCELLED-001" => ClientError::Cancelled,
        "ERR-ONVIF-DEADLINE-001" => ClientError::Deadline,
        "ERR-ONVIF-BUDGET-001" => ClientError::Budget,
        _ => ClientError::Authority,
    }
}
fn secret_error(error: SecretError) -> ClientError {
    match error {
        SecretError::Credentials => ClientError::Credentials,
        SecretError::Entropy => ClientError::Entropy,
        SecretError::Deadline => ClientError::Deadline,
        SecretError::Revoked | SecretError::Authority => ClientError::Authority,
    }
}
fn secret_check(scope: &Scope<'_, '_>) -> Result<(), SecretError> {
    scope
        .admit(RuntimeGrant::AdapterAuth, true)
        .map(|_| ())
        .map_err(|code| {
            if code == "ERR-ONVIF-DEADLINE-001" {
                SecretError::Deadline
            } else {
                SecretError::Authority
            }
        })
}
fn denial(code: &'static str) -> HttpDenial {
    match code {
        "ERR-ONVIF-CANCELLED-001" => HttpDenial::Cancelled,
        "ERR-ONVIF-DEADLINE-001" => HttpDenial::Deadline,
        "ERR-ONVIF-BUDGET-001" => HttpDenial::Budget,
        _ => HttpDenial::Unauthorized,
    }
}

fn checkpoint_error(error: HttpDenial) -> ClientError {
    match error {
        HttpDenial::Cancelled => ClientError::Cancelled,
        HttpDenial::Deadline => ClientError::Deadline,
        HttpDenial::Budget => ClientError::Budget,
        HttpDenial::Unauthorized | HttpDenial::Revoked => ClientError::Authority,
    }
}

// The secret owner independently checks the exact typed operation, including its
// profile token and media version. A valid origin alone never grants a generic
// SOAP signer. Bootstrap and already-signed requests cannot equal these bodies.
fn username_token_request_matches(plan: &Plan, route: &HttpRoute, request: &SoapRequest) -> bool {
    if !plan.uses_username_token() {
        return false;
    }
    let (discovery, profiles) = match plan.media_version {
        MediaVersion::Media1 => (
            wire::get_capabilities_request(),
            wire::get_profiles_request(),
        ),
        MediaVersion::Media2 => (
            wire::get_services_request(),
            wire::get_media2_profiles_request(),
        ),
    };
    if request == &discovery {
        return route.target() == plan.device_path;
    }
    if request == &profiles {
        return true;
    }
    let Some(profile) = plan.profile.as_deref() else {
        return false;
    };
    let expected = match plan.media_version {
        MediaVersion::Media1 => wire::get_stream_uri_request(profile),
        MediaVersion::Media2 => wire::get_media2_stream_uri_request(profile),
    };
    expected.is_ok_and(|expected| request == &expected)
}

impl HttpAuthority for Owner<'_, '_, '_> {
    fn checkpoint(
        &self,
        route: &HttpRoute,
        _: HttpOperation,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), HttpDenial> {
        let now = self
            .scope
            .admit(RuntimeGrant::AdapterNet, false)
            .map_err(denial)?;
        if route.peer() != self.plan.peer
            || route.authority() != self.plan.authority
            || route.generation() != self.plan.generation
            || route.plaintext_approval() != self.approval
            || !in_service_root(route.target(), &self.plan.service_root)
            || now_ns > now
            || deadline_ns > self.plan.timeout_ns
        {
            return Err(HttpDenial::Unauthorized);
        }
        if now >= deadline_ns {
            return Err(HttpDenial::Deadline);
        }
        if let Some(lease) = self.credentials {
            lease
                .revalidate(&|| secret_check(self.scope))
                .map_err(|error| match error {
                    SecretError::Deadline => HttpDenial::Deadline,
                    SecretError::Revoked | SecretError::Credentials => HttpDenial::Revoked,
                    _ => HttpDenial::Unauthorized,
                })?;
        }
        Ok(())
    }
}

impl OnvifContext for Owner<'_, '_, '_> {
    fn now_ns(&self) -> Result<u64, ClientError> {
        self.scope.now().map_err(context_error)
    }

    fn wait(&self, deadline_ns: u64) -> Result<(), ClientError> {
        if let Some(lease) = self.credentials {
            lease
                .revalidate(&|| secret_check(self.scope))
                .map_err(secret_error)?;
        }
        self.scope.wait(deadline_ns).map_err(context_error)
    }

    fn authorize(
        &self,
        route: &HttpRoute,
        challenge: &DigestChallenge,
    ) -> Result<DigestAuthorization, ClientError> {
        if !matches!(&self.plan.auth, Some(OnvifAuthPlan::HttpDigest(_))) {
            return Err(ClientError::Authority);
        }
        let now = self.now_ns()?;
        self.checkpoint(route, HttpOperation::Write, now, self.plan.timeout_ns)
            .map_err(|_| ClientError::Authority)?;
        let check = || secret_check(self.scope);
        let lease = self.credentials.ok_or(ClientError::Credentials)?;
        lease.revalidate(&check).map_err(secret_error)?;
        let mut entropy = self
            .entropy
            .try_borrow_mut()
            .map_err(|_| ClientError::Entropy)?;
        let nonce = entropy
            .as_mut()
            .ok_or(ClientError::Entropy)?
            .next(&check)
            .map_err(secret_error)?;
        let credentials = lease.credentials().map_err(secret_error)?;
        let authorization = challenge
            .authorize("POST", route.target(), &credentials, nonce, 1)
            .map_err(ClientError::Authentication)?;
        lease.revalidate(&check).map_err(secret_error)?;
        Ok(authorization)
    }

    fn username_token(
        &self,
        route: &HttpRoute,
        request: &SoapRequest,
        created: UtcDateTime,
    ) -> Result<UsernameToken, ClientError> {
        if !username_token_request_matches(self.plan, route, request) {
            return Err(ClientError::Authority);
        }
        let now = self.now_ns()?;
        self.checkpoint(route, HttpOperation::Write, now, self.plan.timeout_ns)
            .map_err(checkpoint_error)?;
        let check = || secret_check(self.scope);
        let lease = self.credentials.ok_or(ClientError::Credentials)?;
        lease.revalidate(&check).map_err(secret_error)?;
        let mut entropy = self
            .entropy
            .try_borrow_mut()
            .map_err(|_| ClientError::Entropy)?;
        let nonce = entropy
            .as_mut()
            .ok_or(ClientError::Entropy)?
            .next(&check)
            .map_err(secret_error)?;
        let credentials = lease.credentials().map_err(secret_error)?;
        let token = UsernameToken::new(&credentials, nonce, created);
        lease.revalidate(&check).map_err(secret_error)?;
        let now = self.now_ns()?;
        self.checkpoint(route, HttpOperation::Write, now, self.plan.timeout_ns)
            .map_err(checkpoint_error)?;
        Ok(token)
    }
}

fn inventory(report: &Onboarding, approval: ContentDigest) -> String {
    let profiles: Vec<_> = report
        .profiles
        .iter()
        .map(|profile| {
            let video = profile.video.as_ref().map_or_else(
                || "null".into(),
                |video| {
                    object(&[
                        (
                            "encoding",
                            string(match video.encoding {
                                VideoEncoding::H264 => "H264",
                                VideoEncoding::H265 => "H265",
                                VideoEncoding::Jpeg => "JPEG",
                                VideoEncoding::Mpeg4 => "MPEG4",
                                VideoEncoding::Unsupported => "unsupported",
                            }),
                        ),
                        ("width", video.width.to_string()),
                        ("height", video.height.to_string()),
                        (
                            "capture_supported",
                            (video.encoding == VideoEncoding::H264
                                || (video.encoding == VideoEncoding::H265
                                    && matches!(&report.discovery, MediaDiscovery::Media2(_))))
                            .to_string(),
                        ),
                    ])
                },
            );
            object(&[
                ("token", string(&profile.token)),
                ("name", string(&profile.name)),
                (
                    "token_digest",
                    string(&ContentDigest::sha256(profile.token.as_bytes()).to_text()),
                ),
                ("video", video),
                ("source", string("untrusted-device-advertisement")),
            ])
        })
        .collect();
    let mut fields = match &report.discovery {
        MediaDiscovery::Media1(capabilities) => vec![
            ("schema", string("fss.onvif_media1_inventory.v1")),
            ("onboarding_plan", string(&approval.to_text())),
            (
                "media_xaddr",
                capabilities
                    .media_xaddr
                    .as_ref()
                    .map_or_else(|| "null".into(), |uri| string(uri)),
            ),
            (
                "rtp_rtsp_tcp",
                capabilities
                    .rtp_rtsp_tcp
                    .map_or_else(|| "null".into(), |flag| flag.to_string()),
            ),
        ],
        MediaDiscovery::Media2(service) => vec![
            ("schema", string("fss.onvif_media2_inventory.v1")),
            ("onboarding_plan", string(&approval.to_text())),
            ("media_version", string("media2")),
            ("media_xaddr", string(&service.xaddr)),
            (
                "service_version",
                object(&[
                    ("major", service.version.major.to_string()),
                    ("minor", service.version.minor.to_string()),
                ]),
            ),
        ],
    };
    fields.extend([
        ("profiles", array(&profiles)),
        ("capture_authorized", "false".into()),
        ("source_evidence", "false".into()),
        ("profile_t_conformance", string("not-established")),
    ]);
    object(&fields) + "\n"
}

pub(super) fn execute(plan: &Plan) -> Result<String, &'static str> {
    let approval = plan.digest()?;
    if plan.approval != Some(approval) {
        return Err("ERR-ONVIF-APPROVAL-001");
    }
    let config = plan.config(approval)?;
    let network = plan
        .max_http_exchanges()
        .checked_mul((plan.limits.request_bytes + plan.limits.wire_bytes) as u64)
        .ok_or("ERR-ONVIF-BUDGET-001")?;
    let request = Request {
        approval,
        principal: plan.principal.clone(),
        timeout_ns: plan.timeout_ns,
        bytes: network + MAX_FILE_BYTES as u64 + MAX_CREDENTIAL_BYTES as u64 + 128,
        network_bytes: network,
        storage_operations: u64::from(plan.max_steps) * 64 + 8192,
        network: true,
        write: true,
        secrets: plan.auth.is_some(),
    };
    runtime::run(request, |scope| {
        let output = Output::prepare(&plan.output, &|| scope.output())?;
        let check = || secret_check(scope);
        let credentials = plan
            .auth
            .as_ref()
            .map(|auth| CredentialLease::load(auth.credential_file(), &check))
            .transpose()
            .map_err(|error| secret_error(error).code())?;
        let entropy = if credentials.is_some() {
            Some(Entropy::open(&check).map_err(|error| secret_error(error).code())?)
        } else {
            None
        };
        let owner = Owner {
            scope,
            plan,
            approval,
            credentials: credentials.as_ref(),
            entropy: RefCell::new(entropy),
        };
        let report =
            client::run(&config, plan.profile.as_deref(), &owner).map_err(|error| error.code())?;
        let bytes = match &report.selection {
            Some(selected) => Handoff::from_selected(selected, approval)?.render()?,
            None => inventory(&report, approval),
        };
        let file_digest = ContentDigest::sha256(bytes.as_bytes());
        if let Some(lease) = &credentials {
            lease
                .revalidate(&check)
                .map_err(|error| secret_error(error).code())?;
        }
        output.write(bytes.as_bytes(), &|| scope.output())?;
        Ok(object(&[
            ("schema", string("fss.onvif_operator_result.v1")),
            ("phase", string("completed")),
            ("media_version", string(plan.media_version_name())),
            ("approval", string(&approval.to_text())),
            ("output_digest", string(&file_digest.to_text())),
            ("output_bytes", bytes.len().to_string()),
            ("profiles", report.profiles.len().to_string()),
            ("http_exchanges", report.exchanges.to_string()),
            ("handoff_ready", report.selection.is_some().to_string()),
            ("native_resources_quiescent", "true".into()),
            ("capture_authorized", "false".into()),
            ("source_evidence", "false".into()),
        ]) + "\n")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_reference::rtsp::authentication::DigestCredentials;
    use std::ffi::OsString;

    fn plan(media: &str, profile: Option<&str>) -> Plan {
        let mut args = vec![
            "--peer",
            "127.0.0.1:8080",
            "--authority",
            "127.0.0.1:8080",
            "--device-path",
            "/onvif/device_service",
            "--service-root",
            "/onvif",
            "--output",
            "/tmp/fss-onvif-owner-plan.json",
            "--owner-authorized",
            "yes",
            "--plaintext",
            "yes",
            "--media-version",
            media,
            "--auth-mode",
            "username-token",
            "--credential-file",
            "/tmp/fss-onvif-owner-credentials",
        ];
        if let Some(profile) = profile {
            args.extend([
                "--profile",
                profile,
                "--rtsp-peer",
                "127.0.0.1:554",
                "--rtsp-authority",
                "127.0.0.1:554",
            ]);
        }
        Plan::parse(&args.into_iter().map(OsString::from).collect::<Vec<_>>()).unwrap()
    }

    fn route(plan: &Plan, path: &str) -> HttpRoute {
        HttpRoute::new(
            plan.peer,
            &plan.authority,
            path,
            plan.generation,
            plan.digest().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn token_owner_admits_only_exact_media_operations_and_selected_profile() {
        for media in ["media1", "media2"] {
            let plan = plan(media, Some("selected-profile"));
            let device = route(&plan, &plan.device_path);
            let service = route(&plan, "/onvif/media_service");
            let (discovery, profiles, selected, other_discovery, other_profiles, other_selected) =
                if media == "media1" {
                    (
                        wire::get_capabilities_request(),
                        wire::get_profiles_request(),
                        wire::get_stream_uri_request("selected-profile").unwrap(),
                        wire::get_services_request(),
                        wire::get_media2_profiles_request(),
                        wire::get_media2_stream_uri_request("selected-profile").unwrap(),
                    )
                } else {
                    (
                        wire::get_services_request(),
                        wire::get_media2_profiles_request(),
                        wire::get_media2_stream_uri_request("selected-profile").unwrap(),
                        wire::get_capabilities_request(),
                        wire::get_profiles_request(),
                        wire::get_stream_uri_request("selected-profile").unwrap(),
                    )
                };
            assert!(username_token_request_matches(&plan, &device, &discovery));
            assert!(!username_token_request_matches(&plan, &service, &discovery));
            assert!(username_token_request_matches(&plan, &service, &profiles));
            assert!(username_token_request_matches(&plan, &service, &selected));
            for refused in [
                other_discovery,
                other_profiles,
                other_selected,
                wire::get_stream_uri_request("different-profile").unwrap(),
                wire::get_media2_stream_uri_request("different-profile").unwrap(),
                wire::get_snapshot_uri_request("selected-profile").unwrap(),
                wire::get_system_date_and_time_request(),
            ] {
                assert!(!username_token_request_matches(&plan, &device, &refused));
                assert!(!username_token_request_matches(&plan, &service, &refused));
            }
            let token = UsernameToken::new(
                &DigestCredentials::new("fixture-user", "fixture-password").unwrap(),
                [7; 16],
                UtcDateTime::new(2026, 10, 21, 12, 0, 0).unwrap(),
            );
            let already_signed = profiles.with_username_token(&token).unwrap();
            assert!(!username_token_request_matches(
                &plan,
                &service,
                &already_signed
            ));
        }
    }

    #[test]
    fn token_owner_refuses_stream_selection_without_a_profile_or_auth_mode() {
        for media in ["media1", "media2"] {
            let mut plan = plan(media, None);
            let service = route(&plan, "/onvif/media_service");
            for request in [
                wire::get_stream_uri_request("main").unwrap(),
                wire::get_media2_stream_uri_request("main").unwrap(),
            ] {
                assert!(!username_token_request_matches(&plan, &service, &request));
            }
            plan.auth = None;
            assert!(!username_token_request_matches(
                &plan,
                &service,
                &wire::get_profiles_request()
            ));
            assert!(!username_token_request_matches(
                &plan,
                &service,
                &wire::get_media2_profiles_request()
            ));
        }
    }

    #[test]
    fn token_owner_preserves_live_checkpoint_refusal_kinds() {
        for (denied, code) in [
            (HttpDenial::Cancelled, "ERR-ONVIF-CANCELLED-001"),
            (HttpDenial::Deadline, "ERR-ONVIF-DEADLINE-001"),
            (HttpDenial::Budget, "ERR-ONVIF-BUDGET-001"),
            (HttpDenial::Revoked, "ERR-ONVIF-AUTHORITY-001"),
            (HttpDenial::Unauthorized, "ERR-ONVIF-AUTHORITY-001"),
        ] {
            assert_eq!(checkpoint_error(denied).code(), code);
        }
    }
}
