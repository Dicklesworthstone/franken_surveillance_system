#![forbid(unsafe_code)]
//! Native execution of an already reviewed source probe; no subprocess or recording.

use std::cell::Cell;

use fss_core::RuntimeGrant;
use fss_reference::rtsp::authentication::DigestPolicy;
use fss_reference::rtsp::tcp::{
    SocketReadiness, TcpAuthority, TcpBinding, TcpDenial, TcpOperation, TcpTotals,
};
use fss_reference::site::SiteProbeReceipt;
use fss_reference::site::live_probe::{
    LiveSiteProbe, LiveSiteProbeConfig, ProbeAccounting, ProbeDigestConfig, ProbeRetirement,
    ProbeStep,
};

use super::plan::{MAX_STEPS, ProbeOutput, ProbePlan, WAIT_QUANTUM_NS, receipt_json};
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

// The approval must name the limits of the actual included credential owner.
const _: () = assert!(authentication::MAX_CREDENTIAL_BYTES == super::plan::MAX_CREDENTIAL_BYTES);
const _: () = assert!(authentication::MAX_SECRET_IO_CALLS == super::plan::MAX_SECRET_IO_CALLS);
const _: () = assert!(runtime::WAIT_QUANTUM_NS == WAIT_QUANTUM_NS);

#[derive(Clone, Copy, Default)]
pub(super) struct Facts {
    pub(super) connection_attempted: bool,
    pub(super) credential_access_attempted: bool,
    pub(super) credentials_loaded: bool,
    pub(super) remote_session_may_exist: bool,
    pub(super) teardown_acknowledged: bool,
    pub(super) pending_cseq: Option<u32>,
    pub(super) totals: Option<TcpTotals>,
    pub(super) accounting: Option<ProbeAccounting>,
    pub(super) request_sent_bytes: usize,
    pub(super) unsent_request_bytes: usize,
    /// Last admitted owner elapsed time, not the later runtime-retirement duration.
    pub(super) last_observed_ns: u64,
}

impl Facts {
    fn retired(&mut self, retirement: &ProbeRetirement) {
        self.remote_session_may_exist = retirement.close.remote_session_may_exist;
        self.teardown_acknowledged = retirement.teardown_acknowledged;
        self.pending_cseq = retirement.close.pending_cseq;
        self.totals = Some(retirement.totals);
        self.accounting = Some(retirement.accounting);
        self.request_sent_bytes = retirement.request_sent_bytes;
        self.unsent_request_bytes = retirement.unsent_request_bytes;
    }
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

fn network_denial(code: &'static str) -> TcpDenial {
    match code {
        "ERR-ONVIF-DEADLINE-001" => TcpDenial::Deadline,
        "ERR-ONVIF-CANCELLED-001" => TcpDenial::Cancelled,
        "ERR-ONVIF-BUDGET-001" => TcpDenial::Budget,
        _ => TcpDenial::Unauthorized,
    }
}

struct Owner<'owner, 'scope, 'task> {
    scope: &'owner runtime::Scope<'scope, 'task>,
    binding: &'owner TcpBinding,
    deadline_ns: u64,
    credentials: Option<&'owner CredentialLease>,
    private_source: Option<&'owner super::unifi::private_file::InputLease>,
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
        let admit = || {
            self.scope
                .admit(RuntimeGrant::AdapterNet, false)
                .map_err(network_denial)
        };
        let observed = admit()?;
        if now_ns > observed || observed >= deadline_ns {
            return Err(TcpDenial::Deadline);
        }
        if let Some(source) = self.private_source {
            source
                .revalidate(&|| self.scope.input())
                .map_err(|code| match code {
                    "ERR-ONVIF-DEADLINE-001" => TcpDenial::Deadline,
                    "ERR-ONVIF-CANCELLED-001" => TcpDenial::Cancelled,
                    _ => TcpDenial::Revoked,
                })?;
        }
        if let Some(credentials) = self.credentials {
            credentials
                .revalidate(&|| secret_check(self.scope))
                .map_err(|error| match error {
                    SecretError::Deadline => TcpDenial::Deadline,
                    SecretError::Revoked | SecretError::Credentials => TcpDenial::Revoked,
                    _ => TcpDenial::Unauthorized,
                })?;
        }
        // Credential metadata operations may block or observe changed authority.
        // Re-admit the exact network grant and actual time after those operations,
        // rather than allowing an earlier network checkpoint to authorize I/O.
        let observed = admit()?;
        if now_ns > observed || observed >= deadline_ns {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}

fn run_native(
    plan: &ProbePlan<'_>,
    scope: &runtime::Scope<'_, '_>,
    facts: &Cell<Facts>,
) -> Result<SiteProbeReceipt, &'static str> {
    let source = &plan.manifest.sources[plan.source_index];
    let timeout_ns = plan.options.timeout_ms * 1_000_000;
    // Refusal before the first live admission must not imply a credential read.
    scope.now().map_err(runtime_error)?;
    let private_source = plan
        .private
        .as_ref()
        .map(|private| {
            let input =
                super::unifi::private_file::InputLease::open(&private.spec.source, &|| {
                    scope.input()
                })?;
            private.verify(&input)?;
            Ok::<_, &'static str>(input)
        })
        .transpose()?;
    let credentials = source
        .authentication
        .as_ref()
        .map(|auth| {
            secret_check(scope).map_err(secret_error)?;
            let mut current = facts.get();
            current.credential_access_attempted = true;
            facts.set(current);
            let credentials = CredentialLease::load(&auth.credential_file, &|| secret_check(scope))
                .map_err(secret_error)?;
            let mut current = facts.get();
            current.credentials_loaded = true;
            facts.set(current);
            Ok::<_, &'static str>(credentials)
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
        private_source: private_source.as_ref(),
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
    let mut probe = match LiveSiteProbe::connect_with_route(
        plan.manifest,
        config,
        plan.route.clone(),
        now,
        &owner,
    ) {
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
            scope.now().map_err(runtime_error)?;
            let borrowed = if probe.needs_credentials() {
                let lease = credentials
                    .as_ref()
                    .ok_or("ERR-SITE-PROBE-CREDENTIAL-001")?;
                lease
                    .revalidate(&|| secret_check(scope))
                    .map_err(secret_error)?;
                Some(lease.credentials().map_err(secret_error)?)
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
            // Secret/entropy boundaries must not leave the protocol using a
            // caller timestamp sampled before those potentially blocking reads.
            let now = scope.now().map_err(runtime_error)?;
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
                        current.retired(retirement);
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
                ProbeStep::Complete {
                    receipt,
                    totals,
                    close,
                    accounting,
                } => {
                    let mut current = facts.get();
                    current.remote_session_may_exist = close.remote_session_may_exist;
                    current.pending_cseq = close.pending_cseq;
                    current.teardown_acknowledged =
                        !close.remote_session_may_exist && close.pending_cseq.is_none();
                    current.totals = Some(totals);
                    current.accounting = Some(accounting);
                    current.request_sent_bytes = 0;
                    current.unsent_request_bytes = 0;
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
                    if let Some(input) = &private_source {
                        input.revalidate(&|| scope.input())?;
                    }
                    current.last_observed_ns = scope.now().map_err(runtime_error)?;
                    facts.set(current);
                    return Ok(receipt);
                }
            }
        }
        Err("ERR-SITE-PROBE-BUDGET-001")
    })();
    // Preserve exact local/remote retirement facts even if an outer clock, secret
    // or wait check refused before the native connection could return an event.
    if let Some(retirement) = probe.cancel() {
        let mut current = facts.get();
        current.retired(&retirement);
        facts.set(current);
    }
    result
}

pub(super) fn execute(plan: &ProbePlan<'_>) -> (String, ExitIdentity) {
    let facts = Cell::new(Facts::default());
    let source = &plan.manifest.sources[plan.source_index];
    let timeout_ns = plan.options.timeout_ms * 1_000_000;
    let request = runtime::Request {
        approval: plan.approval,
        principal: plan.options.principal.clone(),
        timeout_ns,
        bytes: plan.allowance.bytes,
        network_bytes: plan.allowance.network_bytes,
        storage_operations: plan.allowance.storage_operations,
        network: true,
        write: false,
        secrets: source.authentication.is_some(),
    };
    let work = |scope: &runtime::Scope<'_, '_>| {
        let result = run_native(plan, scope, &facts);
        let mut current = facts.get();
        current.last_observed_ns = scope.observed_ns();
        facts.set(current);
        result
    };
    let result = if plan.private.is_some() {
        runtime::run_private_site_probe(request, work)
    } else {
        runtime::run_site_probe(request, work)
    }
    .map_err(runtime_error);
    match result {
        // The shared owner rechecks cancellation, the actual final deadline, task
        // retirement and region closure before it releases either output format.
        Ok(receipt) if plan.private.is_some() => {
            super::unifi::save_receipt(plan, &receipt, facts.get())
        }
        Ok(receipt) => {
            let output = match plan.options.output {
                ProbeOutput::Receipts => Ok(array(&[receipt_json(&receipt)])),
                ProbeOutput::Session => super::report::success(plan, &receipt, facts.get()),
            };
            match output {
                Ok(output) if output.len() <= crate::site_cmd::MAX_SITE_OUTPUT_BYTES => {
                    (output, ExitIdentity::SUCCESS)
                }
                Ok(_) => refusal(
                    "ERR-SITE-PROBE-OUTPUT-001",
                    facts.get(),
                    ExitIdentity::RUNTIME_FAILURE,
                ),
                Err(code) => refusal(code, facts.get(), ExitIdentity::RUNTIME_FAILURE),
            }
        }
        Err(code) if plan.options.output == ProbeOutput::Session => (
            super::report::refusal(plan, code, facts.get(), ExitIdentity::RUNTIME_FAILURE),
            ExitIdentity::RUNTIME_FAILURE,
        ),
        Err(code) => refusal(code, facts.get(), ExitIdentity::RUNTIME_FAILURE),
    }
}
