#![forbid(unsafe_code)]
//! One owner-approved Media1 snapshot through the native scoped HTTP transport,
//! followed by private staging and a verified durable file-import custody record.

#[path = "fss-onvif/runtime.rs"]
mod runtime;
#[path = "fss-capture-onvif/staging.rs"]
mod staging;
#[cfg(test)]
#[path = "fss-capture-onvif/tests.rs"]
mod tests;

use fss_cli::agent_json::{object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, OperationId, RuntimeGrant, SensorId, StreamId,
    TimestampNs,
};
use fss_reference::ingest::{
    FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::onvif::client::{ClientError, OnvifContext};
use fss_reference::onvif::http::{
    HttpAuthority, HttpDenial, HttpLimits, HttpOperation, HttpRoute,
};
use fss_reference::onvif::snapshot::{self, Snapshot, SnapshotPlan};
use fss_reference::rtsp::authentication::{DigestAuthorization, DigestChallenge};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};
use std::collections::BTreeSet;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};

const REPORT_SCHEMA: &str = "fss.onvif_capture_cli.v1";
const SITE: &str = "site:lab-onvif-import";
const DEFAULT_MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARGS: usize = 30;
const STORAGE: &str = "ERR-ONVIF-STORAGE-001";
const CUSTODY: &str = "ERR-ONVIF-CUSTODY-001";
const CANCELLED: &str = "ERR-ONVIF-CANCELLED-001";
const SCOPE: &str = "ERR-ONVIF-SCOPE-001";

const HELP: &str =
    "fss-capture-onvif --xaddr http://IP:PORT/ONVIF_MEDIA1_SERVICE --root ABSOLUTE_DEPLOYMENT
  --sensor-id ID --stream-id ID --receive-time-ns N --owner-authorized
  [--peer IP:PORT] [--profile TOKEN] [--max-source-bytes N] [--timeout-ms N]
  Fetch and retain one owner-authorized JPEG: GetProfiles + GetSnapshotUri + GET.
  --owner-authorized approves this device, its media, and the explicit plaintext HTTP lane.
  The exact peer is pinned. Hostname URLs require --peer; no DNS or redirect is followed.
  A returned snapshot URI must have the same exact HTTP authority as --xaddr.
  Default source limit: 4 MiB (maximum 64 MiB). Total network timeout: 30000 ms (maximum 60000).
  Authentication-required cameras are refused; this lane never acquires credentials.
  URI paths/queries from the camera are redacted. Receive time is never capture time.
  A single JPEG proves neither media continuity nor ONVIF Profile T conformance.
  JSON report: fss.onvif_capture_cli.v1. Durable source bytes are verified before success.
";

#[derive(Clone)]
struct Options {
    xaddr: String,
    peer: Option<SocketAddr>,
    root: PathBuf,
    sensor_id: String,
    stream_id: String,
    receive_time_ns: i128,
    profile: Option<String>,
    max_source_bytes: usize,
    timeout_ms: u64,
}

struct Endpoint<'a> {
    host: &'a str,
    port: u16,
    authority: &'a str,
    target: &'a str,
}

fn endpoint(value: &str) -> Result<Endpoint<'_>, &'static str> {
    let rest = value.strip_prefix("http://").ok_or(SCOPE)?;
    let slash = rest.find('/').ok_or(SCOPE)?;
    let (authority, target) = rest.split_at(slash);
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or(SCOPE)?;
        let port = if tail.is_empty() {
            80
        } else {
            tail.strip_prefix(':')
                .ok_or(SCOPE)?
                .parse()
                .map_err(|_| SCOPE)?
        };
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().map_err(|_| SCOPE)?),
            None => (authority, 80),
        }
    };
    Ok(Endpoint {
        host,
        port,
        authority,
        target,
    })
}

impl Options {
    fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.onvif.snapshot-cli.v1:explicit-owner-plaintext-approval");
        encoder.text(&self.xaddr);
        encoder.text(&self.peer.map(|peer| peer.to_string()).unwrap_or_default());
        encoder.text(self.root.to_str().ok_or(SCOPE)?);
        encoder.text(&self.sensor_id);
        encoder.text(&self.stream_id);
        encoder.i128(self.receive_time_ns);
        encoder.text(self.profile.as_deref().unwrap_or(""));
        encoder.u64(self.max_source_bytes as u64);
        encoder.u64(self.timeout_ms);
        Ok(ContentDigest::sha256(
            &encoder.finish_checked().map_err(|_| SCOPE)?,
        ))
    }

    fn plan(&self) -> Result<SnapshotPlan, &'static str> {
        let endpoint = endpoint(&self.xaddr)?;
        let peer = match self.peer {
            Some(peer) => peer,
            None => SocketAddr::new(
                endpoint.host.parse::<IpAddr>().map_err(|_| SCOPE)?,
                endpoint.port,
            ),
        };
        let media = HttpRoute::new(
            peer,
            endpoint.authority,
            endpoint.target,
            1,
            self.approval()?,
        )
        .map_err(|_| SCOPE)?;
        Ok(SnapshotPlan {
            media,
            profile_token: self.profile.clone(),
            max_source_bytes: self.max_source_bytes,
            deadline_ns: self.timeout_ms * 1_000_000,
            max_steps: 100_000,
        })
    }
}

struct Owner<'a, 'scope, 'task> {
    scope: &'a runtime::Scope<'scope, 'task>,
    plan: &'a SnapshotPlan,
}

fn context_error(code: &'static str) -> ClientError {
    match code {
        "ERR-ONVIF-CANCELLED-001" => ClientError::Cancelled,
        "ERR-ONVIF-DEADLINE-001" => ClientError::Deadline,
        "ERR-ONVIF-BUDGET-001" => ClientError::Budget,
        _ => ClientError::Authority,
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
            .map_err(|code| match code {
                CANCELLED => HttpDenial::Cancelled,
                "ERR-ONVIF-DEADLINE-001" => HttpDenial::Deadline,
                "ERR-ONVIF-BUDGET-001" => HttpDenial::Budget,
                _ => HttpDenial::Unauthorized,
            })?;
        let approved = &self.plan.media;
        if route.peer() != approved.peer()
            || route.authority() != approved.authority()
            || route.generation() != approved.generation()
            || route.plaintext_approval() != approved.plaintext_approval()
        {
            return Err(HttpDenial::Unauthorized);
        }
        if deadline_ns != self.plan.deadline_ns || now_ns > now || now >= deadline_ns {
            return Err(HttpDenial::Deadline);
        }
        Ok(())
    }
}

impl OnvifContext for Owner<'_, '_, '_> {
    fn now_ns(&self) -> Result<u64, ClientError> {
        self.scope.now().map_err(context_error)
    }
    fn wait(&self, deadline_ns: u64) -> Result<(), ClientError> {
        self.scope.wait(deadline_ns).map_err(context_error)
    }
    fn authorize(
        &self,
        _: &HttpRoute,
        _: &DigestChallenge,
    ) -> Result<DigestAuthorization, ClientError> {
        Err(ClientError::Credentials)
    }
}

/// The existing bounded file-import owner is separate from the network lease.
fn context(root: &Path, max_bytes: usize) -> Result<ReplayCx, &'static str> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:lab:onvif-import".to_owned(),
        operation_id: OperationId::parse("op:lab:onvif-import").map_err(|_| STORAGE)?,
        principal: "operator:lab".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(max_bytes as u64)
            .storage_operations(1 << 20)
            .build()
            .map_err(|_| STORAGE)?,
        privacy_scope: "privacy:local-authorized-files".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })
    .map_err(|_| STORAGE)?;
    authority.validate().map_err(|_| STORAGE)?;
    ReplayCx::from_context_authority(&authority, root.to_path_buf()).map_err(|_| STORAGE)
}

fn run(options: &Options) -> Result<String, &'static str> {
    let plan = options.plan()?;
    let reservation = (options.max_source_bytes as u64) * 2 + 2 * 1024 * 1024;
    // Reserve all three bounded requests, both SOAP responses and the snapshot wire ceiling.
    let soap_limits = HttpLimits::default();
    let snapshot_wire = ((options.max_source_bytes as u64) * 2).max(65_536);
    let network_reservation = snapshot_wire
        + 2 * soap_limits.wire_bytes as u64
        + 3 * soap_limits.request_bytes as u64;
    let snapshot = runtime::run(
        runtime::Request {
            approval: options.approval()?,
            principal: "operator:lab".into(),
            timeout_ns: plan.deadline_ns,
            bytes: reservation,
            network_bytes: network_reservation,
            storage_operations: 4096,
            network: true,
            write: false,
            secrets: false,
        },
        |scope| {
            snapshot::capture(&plan, &Owner { scope, plan: &plan }).map_err(|error| error.code())
        },
    )?;
    let cx = context(&options.root, options.max_source_bytes)?;
    let result = (|| {
        let mut staged = staging::Source::new(&snapshot.jpeg, &cx)?;
        let report = retain(options, &plan, &snapshot, staged.path(), &cx);
        let cleanup = staged.close();
        report.and_then(|report| cleanup.map(|()| report))
    })();
    cx.drain_and_finalize();
    result
}

fn retain(
    options: &Options,
    plan: &SnapshotPlan,
    snapshot: &Snapshot,
    path: &Path,
    cx: &ReplayCx,
) -> Result<String, &'static str> {
    cx.checkpoint("onvif-before-retain")
        .map_err(|_| CANCELLED)?;
    let mut deployment = ReferenceDeployment::open(&options.root, SITE, cx).map_err(|_| STORAGE)?;
    let sensor = SensorId::parse(&options.sensor_id).map_err(|_| SCOPE)?;
    let stream = StreamId::parse(&options.stream_id).map_err(|_| SCOPE)?;
    let mut request = FileIngestRequest::new(path.to_path_buf(), sensor, stream)
        .with_receive_time(TimestampNs(options.receive_time_ns));
    request.format_hint = Some(FileFormatHint::JpegStream);
    request.limits.max_file_bytes = options.max_source_bytes as u64;
    request.limits.max_segments = 1;
    request.limits.mjpeg_limits.max_input_bytes = options.max_source_bytes;
    request.limits.mjpeg_limits.max_frame_bytes = options.max_source_bytes;
    request.limits.mjpeg_limits.max_frames = 1;
    let imported = FileIngestAdapter::ingest(request, cx, &mut deployment).map_err(|_| STORAGE)?;
    let limits = RetainedReadLimits {
        max_source_bytes: options.max_source_bytes as u64,
        max_segment_bytes: options.max_source_bytes as u64,
        ..RetainedReadLimits::default()
    };
    let retained = RetainedFileImport::open(&deployment, imported.import_identity, limits, cx)
        .map_err(|_| CUSTODY)?;
    let manifest = retained.manifest();
    if manifest.input_sha256 != snapshot.source_digest
        || manifest.input_bytes != snapshot.jpeg.len() as u64
        || retained
            .verify_source(&deployment, limits, cx)
            .map_err(|_| CUSTODY)?
            != snapshot.source_digest
    {
        return Err(CUSTODY);
    }
    cx.checkpoint("onvif-before-report")
        .map_err(|_| CANCELLED)?;
    let service = endpoint(&options.xaddr)?;
    Ok(object(&[
        ("schema", string(REPORT_SCHEMA)),
        (
            "onvif_service",
            object(&[
                ("host", string(service.host)),
                ("port", service.port.to_string()),
                ("path", string(service.target)),
            ]),
        ),
        (
            "snapshot",
            object(&[
                ("host", string(service.host)),
                ("port", service.port.to_string()),
                ("path", string("[redacted]")),
            ]),
        ),
        ("bytes", manifest.input_bytes.to_string()),
        ("jpeg_sha256", string(&snapshot.source_digest.to_text())),
        (
            "import_identity",
            string(&imported.import_identity.to_text()),
        ),
        ("import_outcome", string(imported.outcome.as_str())),
        ("media_format", string(&manifest.format)),
        ("import_root", string(&retained.import_root().to_text())),
        (
            "valid_until",
            snapshot
                .uri
                .valid_until
                .as_deref()
                .map(string)
                .unwrap_or_else(|| "null".into()),
        ),
        ("owner_authorized", "true".into()),
        ("media_continuity", string("unverified")),
        ("scope_digest", string(&plan.media.digest().to_text())),
        (
            "network",
            object(&[
                ("io_calls", snapshot.network.io_calls.to_string()),
                ("sent_bytes", snapshot.network.sent_bytes.to_string()),
                (
                    "received_bytes",
                    snapshot.network.received_bytes.to_string(),
                ),
            ]),
        ),
        (
            "note",
            string(
                "Single Media1 JPEG snapshot over explicitly approved plaintext HTTP; exact source retained and verified. No continuity, capture-time, decoded-scene, or Profile T conformance claim.",
            ),
        ),
    ]) + "\n")
}

fn parse(args: &[String]) -> Result<Options, &'static str> {
    if args.len() > MAX_ARGS || args.iter().any(|arg| arg.len() > 4096) {
        return Err("argument bounds exceeded");
    }
    let mut options = Options {
        xaddr: String::new(),
        peer: None,
        root: PathBuf::new(),
        sensor_id: String::new(),
        stream_id: String::new(),
        receive_time_ns: 0,
        profile: None,
        max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
        timeout_ms: 30_000,
    };
    let mut seen = BTreeSet::new();
    let mut authorized = false;
    let mut index = 0;
    while index < args.len() {
        let key = args[index].as_str();
        if !seen.insert(key) {
            return Err("duplicate argument");
        }
        if key == "--owner-authorized" {
            authorized = true;
            index += 1;
            continue;
        }
        if !matches!(
            key,
            "--xaddr"
                | "--peer"
                | "--root"
                | "--sensor-id"
                | "--stream-id"
                | "--receive-time-ns"
                | "--profile"
                | "--max-source-bytes"
                | "--timeout-ms"
        ) {
            return Err("unknown argument");
        }
        let value = args.get(index + 1).ok_or("argument requires a value")?;
        match key {
            "--xaddr" => options.xaddr = value.clone(),
            "--peer" => options.peer = Some(value.parse().map_err(|_| SCOPE)?),
            "--root" => options.root = PathBuf::from(value),
            "--sensor-id" => options.sensor_id = value.clone(),
            "--stream-id" => options.stream_id = value.clone(),
            "--receive-time-ns" => {
                options.receive_time_ns = value.parse().map_err(|_| "invalid receive time")?
            }
            "--profile" => options.profile = Some(value.clone()),
            "--max-source-bytes" => {
                options.max_source_bytes = value.parse().map_err(|_| "invalid source ceiling")?
            }
            "--timeout-ms" => options.timeout_ms = value.parse().map_err(|_| "invalid timeout")?,
            _ => return Err("unknown argument"),
        }
        index += 2;
    }
    if !authorized {
        return Err(
            "refused: --owner-authorized is required for this device, media and plaintext HTTP",
        );
    }
    if !options.root.is_absolute()
        || options
            .root
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || options
            .root
            .to_str()
            .is_none_or(|path| path.chars().any(char::is_control))
        || options.receive_time_ns <= 0
        || !(1..=snapshot::MAX_SOURCE_BYTES).contains(&options.max_source_bytes)
        || !(1..=60_000).contains(&options.timeout_ms)
    {
        return Err("invalid root, receive time, source ceiling or timeout");
    }
    SensorId::parse(&options.sensor_id).map_err(|_| SCOPE)?;
    StreamId::parse(&options.stream_id).map_err(|_| SCOPE)?;
    if let Some(token) = &options.profile {
        fss_reference::onvif::wire::get_snapshot_uri_request(token).map_err(|_| SCOPE)?;
    }
    options.plan()?;
    Ok(options)
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).take(MAX_ARGS + 1).collect();
    if args.is_empty()
        || matches!(
            args.first().map(String::as_str),
            Some("help" | "--help" | "-h")
        )
    {
        print!("{HELP}");
        return std::process::ExitCode::SUCCESS;
    }
    let options = match parse(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("fss-capture-onvif: {error}");
            return std::process::ExitCode::from(64);
        }
    };
    match run(&options) {
        Ok(report) => {
            let mut out = std::io::stdout().lock();
            if out.write_all(report.as_bytes()).is_err() || out.flush().is_err() {
                return std::process::ExitCode::from(70);
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fss-capture-onvif: {error}");
            std::process::ExitCode::from(70)
        }
    }
}
