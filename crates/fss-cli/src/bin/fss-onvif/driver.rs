#![forbid(unsafe_code)]
//! Native owner composes the bounded SOAP client, private secret lease and output.

use std::cell::RefCell;

use fss_cli::agent_json::{array, object, string};
use fss_core::{ContentDigest, RuntimeGrant};
use fss_reference::onvif::client::{self, ClientError, MediaDiscovery, Onboarding, OnvifContext};
use fss_reference::onvif::http::{HttpAuthority, HttpDenial, HttpOperation, HttpRoute};
use fss_reference::onvif::wire::VideoEncoding;
use fss_reference::rtsp::authentication::{DigestAuthorization, DigestChallenge};

use super::authentication::{CredentialLease, Entropy, MAX_CREDENTIAL_BYTES, SecretError};
use super::handoff::Handoff;
use super::plan::{Plan, in_service_root};
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
    let exchanges = if plan.profile.is_some() { 6_u64 } else { 4 };
    let network = exchanges
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
            .map(|auth| CredentialLease::load(&auth.credential_file, &check))
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
