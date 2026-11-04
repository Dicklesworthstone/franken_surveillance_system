#![forbid(unsafe_code)]
//! Native execution of an already reviewed source probe; no subprocess or recording.

use std::cell::Cell;

use fss_core::RuntimeGrant;
use fss_reference::rtsp::authentication::DigestPolicy;
use fss_reference::rtsp::tcp::{
    SocketReadiness, TcpAuthority, TcpBinding, TcpDenial, TcpOperation,
};
use fss_reference::site::live_probe::{
    LiveSiteProbe, LiveSiteProbeConfig, ProbeDigestConfig, ProbeStep,
};

use super::plan::{
    MAX_IO_CALLS, MAX_RECEIVED_BYTES, MAX_SENT_BYTES, MAX_STEPS, ProbePlan, receipt_json,
};
use crate::error::ExitIdentity;
use crate::json_output::{array, object, string};

// Compile the exact existing credential lease and owned request runtime. This does
// not introduce a second secret resolver, scheduler or cancellation architecture.
#[allow(
    dead_code,
    unused_imports,
    reason = "The shared credential owner also exposes standalone capture planning"
)]
#[path = "../bin/fss-capture-rtsp/authentication.rs"]
mod authentication;
#[allow(
    dead_code,
    reason = "The shared runtime also serves retained reads and durable publications"
)]
#[path = "../bin/fss-onvif/runtime.rs"]
mod runtime;

use authentication::{CredentialLease, Entropy, SecretError};

#[derive(Clone, Copy, Default)]
pub(super) struct Facts {
    connection_attempted: bool,
    credential_access_attempted: bool,
    remote_session_may_exist: bool,
    teardown_acknowledged: bool,
}

pub(super) fn refusal(code: &str, facts: Facts, exit: ExitIdentity) -> (String, ExitIdentity) {
    (
        object(&[
            ("schema", string("fss.site_probe_diagnostic.v1")),
            ("status", string("refused")),
            ("error_id", string(code)),
            ("exit_id", string(exit.identifier)),
            ("exit_code", exit.code.to_string()),
            (
                "connection_attempted",
                facts.connection_attempted.to_string(),
            ),
            (
                "credential_access_attempted",
                facts.credential_access_attempted.to_string(),
            ),
            (
                "remote_session_may_exist",
                facts.remote_session_may_exist.to_string(),
            ),
            (
                "teardown_acknowledged",
                facts.teardown_acknowledged.to_string(),
            ),
            ("source_retained", "false".to_owned()),
            ("receipt_issued", "false".to_owned()),
            ("retry_automatically", "false".to_owned()),
        ]),
        exit,
    )
}

fn runtime_error(code: &'static str) -> &'static str {
    match code {
        "ERR-ONVIF-DEADLINE-001" => "ERR-SITE-PROBE-DEADLINE-001",
        "ERR-ONVIF-CANCELLED-001" => "ERR-SITE-PROBE-CANCELLED-001",
        "ERR-ONVIF-BUDGET-001" => "ERR-SITE-PROBE-BUDGET-001",
        "ERR-ONVIF-AUTHORITY-001" => "ERR-SITE-PROBE-AUTHORITY-001",
        other => other,
    }
}

fn secret_error(error: SecretError) -> &'static str {
    match error {
        SecretError::Credentials => "ERR-SITE-PROBE-CREDENTIAL-001",
        SecretError::Revoked => "ERR-SITE-PROBE-CREDENTIAL-REVOKED-001",
        SecretError::Entropy => "ERR-SITE-PROBE-ENTROPY-001",
        SecretError::Authority => "ERR-SITE-PROBE-AUTHORITY-001",
        SecretError::Deadline => "ERR-SITE-PROBE-DEADLINE-001",
    }
}

fn secret_check(scope: &runtime::Scope<'_, '_>) -> Result<(), SecretError> {
    scope
        .admit(RuntimeGrant::AdapterAuth, true)
        .map(|_| ())
        .map_err(|code| match code {
            "ERR-ONVIF-DEADLINE-001" => SecretError::Deadline,
            _ => SecretError::Authority,
        })
}

struct Owner<'owner, 'scope, 'task> {
    scope: &'owner runtime::Scope<'scope, 'task>,
    binding: &'owner TcpBinding,
    deadline_ns: u64,
    credentials: Option<&'owner CredentialLease>,
}
impl TcpAuthority for Owner<'_, '_, '_> {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), TcpDenial> {
        if binding != self.binding || deadline_ns != self.deadline_ns {
            return Err(TcpDenial::Unauthorized);
        }
        let observed =
            self.scope
                .admit(RuntimeGrant::AdapterNet, false)
                .map_err(|code| match code {
                    "ERR-ONVIF-DEADLINE-001" => TcpDenial::Deadline,
                    "ERR-ONVIF-CANCELLED-001" => TcpDenial::Cancelled,
                    "ERR-ONVIF-BUDGET-001" => TcpDenial::Budget,
                    _ => TcpDenial::Unauthorized,
                })?;
        if now_ns > observed || observed >= deadline_ns {
            return Err(TcpDenial::Deadline);
        }
        if let Some(credentials) = self.credentials {
            credentials
                .revalidate(&|| secret_check(self.scope))
                .map_err(|error| match error {
                    SecretError::Deadline => TcpDenial::Deadline,
                    SecretError::Revoked => TcpDenial::Revoked,
                    _ => TcpDenial::Unauthorized,
                })?;
        }
        Ok(())
    }
}

pub(super) fn execute(plan: &ProbePlan<'_>) -> (String, ExitIdentity) {
    let facts = Cell::new(Facts::default());
    let source = &plan.manifest.sources[plan.source_index];
    let timeout_ns = plan.options.timeout_ms * 1_000_000;
    let result = runtime::run_site_probe(
        runtime::Request {
            approval: plan.approval,
            principal: plan.options.principal.clone(),
            timeout_ns,
            bytes: MAX_RECEIVED_BYTES + MAX_SENT_BYTES + 2 * 1024 * 1024,
            network_bytes: MAX_RECEIVED_BYTES + MAX_SENT_BYTES,
            storage_operations: MAX_IO_CALLS * 8 + 1024,
            network: true,
            write: false,
            secrets: source.authentication.is_some(),
        },
        |scope| {
            let credentials = source
                .authentication
                .as_ref()
                .map(|auth| {
                    let mut current = facts.get();
                    current.credential_access_attempted = true;
                    facts.set(current);
                    CredentialLease::load(&auth.credential_file, &|| secret_check(scope))
                        .map_err(secret_error)
                })
                .transpose()?;
            let mut entropy = if credentials.is_some() {
                Some(Entropy::open(&|| secret_check(scope)).map_err(secret_error)?)
            } else {
                None
            };
            let owner = Owner {
                scope,
                binding: &plan.binding,
                deadline_ns: timeout_ns,
                credentials: credentials.as_ref(),
            };
            let config = LiveSiteProbeConfig {
                source_index: plan.source_index,
                protocol: plan.protocol.clone(),
                binding: plan.binding.clone(),
                transport: plan.transport,
                codec: plan.options.codec,
                payload_type: plan.options.payload_type,
                deadline_ns: timeout_ns,
                max_steps: MAX_STEPS,
                stop_after_pictures: plan.options.observe_frames,
                digest: source
                    .authentication
                    .as_ref()
                    .map(|auth| ProbeDigestConfig {
                        realm: auth.realm.clone(),
                        policy: DigestPolicy {
                            allow_legacy_md5: auth.legacy_md5,
                            allow_legacy_no_qop: auth.legacy_no_qop,
                        },
                    }),
            };
            let now = scope.now().map_err(runtime_error)?;
            let mut probe = match LiveSiteProbe::connect(plan.manifest, config, now, &owner) {
                Ok(probe) => {
                    let mut current = facts.get();
                    current.connection_attempted = true;
                    facts.set(current);
                    probe
                }
                Err(failure) => {
                    let mut current = facts.get();
                    current.connection_attempted = failure.connection_attempted;
                    facts.set(current);
                    return Err(failure.reason.code());
                }
            };
            let result = (|| {
                for _ in 0..MAX_STEPS {
                    let now = scope.now().map_err(runtime_error)?;
                    let borrowed = if probe.needs_credentials() {
                        credentials
                            .as_ref()
                            .map(CredentialLease::credentials)
                            .transpose()
                            .map_err(secret_error)?
                    } else {
                        None
                    };
                    let cnonce = if borrowed.is_some() {
                        entropy
                            .as_mut()
                            .ok_or("ERR-SITE-PROBE-ENTROPY-001")?
                            .next(&|| secret_check(scope))
                            .map_err(secret_error)?
                    } else {
                        [0; 16]
                    };
                    let step = probe
                        .step(
                            SocketReadiness {
                                readable: true,
                                writable: true,
                            },
                            now,
                            borrowed.as_ref(),
                            cnonce,
                            &owner,
                        )
                        .map_err(|failure| {
                            if let Some(retirement) = &failure.retirement {
                                let mut current = facts.get();
                                current.remote_session_may_exist =
                                    retirement.close.remote_session_may_exist;
                                current.teardown_acknowledged = retirement.teardown_acknowledged;
                                facts.set(current);
                            }
                            failure.reason.code()
                        })?;
                    match step {
                        ProbeStep::Progress => {}
                        ProbeStep::Pending { wake_at_ns, .. } => {
                            let now = scope.now().map_err(runtime_error)?;
                            let wake = wake_at_ns.unwrap_or(timeout_ns).min(timeout_ns);
                            if wake > now {
                                scope.wait(wake).map_err(runtime_error)?;
                            }
                        }
                        ProbeStep::Complete { receipt, close, .. } => {
                            let mut current = facts.get();
                            current.remote_session_may_exist = close.remote_session_may_exist;
                            current.teardown_acknowledged =
                                !close.remote_session_may_exist && close.pending_cseq.is_none();
                            facts.set(current);
                            if !current.teardown_acknowledged {
                                return Err("ERR-SITE-PROBE-CLOSE-001");
                            }
                            if let Some(credentials) = &credentials {
                                credentials
                                    .revalidate(&|| secret_check(scope))
                                    .map_err(secret_error)?;
                            }
                            receipt
                                .validate_for(plan.manifest)
                                .map_err(|_| "ERR-SITE-PROBE-RECEIPT-001")?;
                            let output = array(&[receipt_json(&receipt)]);
                            if output.len() > crate::site_cmd::MAX_SITE_OUTPUT_BYTES {
                                return Err("ERR-SITE-PROBE-OUTPUT-001");
                            }
                            return Ok(output);
                        }
                    }
                }
                Err("ERR-SITE-PROBE-BUDGET-001")
            })();
            if let Some(retirement) = probe.cancel() {
                let mut current = facts.get();
                current.remote_session_may_exist = retirement.close.remote_session_may_exist;
                current.teardown_acknowledged = retirement.teardown_acknowledged;
                facts.set(current);
            }
            result
        },
    )
    .map_err(runtime_error);
    match result {
        Ok(output) => (output, ExitIdentity::SUCCESS),
        Err(code) => refusal(code, facts.get(), ExitIdentity::RUNTIME_FAILURE),
    }
}
