#![forbid(unsafe_code)]
//! Owner-scoped, journaled upload of one independently identified local object.
//!
//! Preparation never contacts a provider. Execution requires the independently
//! retained preparation pin; neither journal bytes nor endpoint discovery grant
//! authority. Provider object completion is not graph closure or retrievability.

#[path = "s3_observation.rs"]
mod observation;
#[path = "s3_retrieval.rs"]
mod retrieval;
#[path = "s3_resume.rs"]
mod resumption;
#[path = "s3_io.rs"]
mod s3_io;
#[path = "s3_verify.rs"]
mod verification;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use fss_cli::agent_json::{budget, object, string};
use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION, ExitIdentity,
};
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, ObligationState, OperationId, RegionId,
    RegionKind, RegionTree, RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_object::multipart::{
    MultipartPhase, MultipartRecovery, MultipartSession, TransportCx, TransportOperation,
    UploadIntent, UploadJournalPin,
};
use fss_object::planner::{ChunkPolicy, MIN_PART_SIZE, plan_chunks};
use fss_object::upload_journal::{FileUploadJournal, UploadJournalLimits};
use fss_object::uploader::{StagedUpload, minimum_upload_budget};
use fss_reference::s3_upload::{
    NativeS3Transport, S3Clock, S3Credentials, S3Endpoint, S3Error, S3Limits,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::grant::GrantSet;

use s3_io::ScopedS3Io;

const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REPORT_BYTES: usize = 16 * 1024;
const LOCAL_RUNTIME_NS: i128 = 600_000_000_000;
const PRINCIPAL: &str = "principal:archive-s3-operator";

pub(super) const HELP: &str = "fss-archive upload-s3-prepare | upload-s3-resume | upload-s3-abort | upload-s3-reconcile | upload-s3-verify\n\
  Required: --source ABSOLUTE_FILE --source-sha256 sha256:HEX --source-bytes U64\n\
            --journal ABSOLUTE_DIR --peer IP:PORT --host HOST:PORT --region NAME\n\
            --bucket NAME --key OBJECT_KEY --credentials ABSOLUTE_FILE\n\
            --plaintext-approval sha256:HEX --operation OPERATION_ID\n\
            --deadline-ns I128 --max-memory-bytes U64 --max-wire-bytes U64\n\
            --max-requests U64 --max-local-bytes U64 --max-local-operations U64\n\
  Optional: --part-bytes U64 (default 5 MiB, maximum 64 MiB)\n\
  Resume/abort/reconcile/verify additionally require: --minimum-sequence U64 --minimum-root sha256:HEX\n\
  Reconcile/verify additionally require: --observation-operation OPERATION_ID\n\
                                  --observation-receipt NEW_ABSOLUTE_FILE\n\
  Verify after indeterminate completion additionally accepts the paired options:\n\
            --completion-observation ABSOLUTE_FILE\n\
            --completion-observation-sha256 sha256:INDEPENDENT_RECEIPT_DIGEST\n\
  Prepare verifies the complete source and creates a durable pending journal without\n\
  provider contact. Independently retain its journal pin before resume or abort.\n\
  Resume skips acknowledged parts and completes the exact object without overwriting.\n\
  A lost part reply permits one bounded inventory check, then a durable cold reopen.\n\
  Only positive exact evidence permits forward work within the original allowance.\n\
  Abort addresses only known owned staging; an uncertain dispatch is never blindly retried.\n\
  Reconcile observes a locally closed indeterminate completion using a new read-only owner.\n\
  Its deadline and transfer bounds authorize only the new observation; the original upload\n\
  stays closed. The source file is not read. A separate immutable receipt records the result.\n\
  Verify reads a completed object's bounded ranges under fresh read-media authority, checks\n\
  each original part and the independent source digest, and retains a separate immutable\n\
  retrieval receipt. It needs neither the source file nor the original transfer allowance.\n\
  Credentials file: access key, secret key, optional session token, one per LF-terminated\n\
  line. The file must be private to its owner. Credential values never enter argv/reports.\n\
  Only explicitly approved loopback/private S3-compatible HTTP endpoints are admitted.\n\
  This transfers one object of at most 64 MiB. It does not encrypt source bytes, publish\n\
  an archive graph, verify replicas, or connect directly using TLS. Only verify proves the\n\
  exact object's independent retrieval for this observation.\n\n\
fss-archive verify-s3-object\n\
  Required: --object-sha256 sha256:HEX --object-bytes U64\n\
            --peer IP:PORT --host HOST:PORT --region NAME --bucket NAME --key OBJECT_KEY\n\
            --credentials ABSOLUTE_FILE --plaintext-approval sha256:HEX\n\
            --operation OPERATION_ID --deadline-ns I128 --receipt NEW_ABSOLUTE_FILE\n\
            --max-memory-bytes U64 --max-wire-bytes U64 --max-requests U64\n\
            --max-local-bytes U64 --max-local-operations U64\n\
  Reads every byte in bounded signed ranges and verifies the independently retained\n\
  full-object SHA-256 and length. A fresh read owner stores an immutable verification\n\
  receipt; no upload journal is opened or changed. Object reads require media authority.\n\
  This proves that one object was readable at that time, not future availability,\n\
  replica count, encryption or archive graph closure. The local HTTP profile still applies.\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Prepare,
    Resume,
    Abort,
    Reconcile,
    Verify,
}
impl Command {
    fn name(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Resume => "resume",
            Self::Abort => "abort",
            Self::Reconcile => "reconcile",
            Self::Verify => "verify",
        }
    }
}
pub(super) fn handles(args: &[OsString]) -> bool {
    verification::handles(args)
        || args.first().is_some_and(|value| {
            [
                "upload-s3-prepare",
                "upload-s3-resume",
                "upload-s3-abort",
                "upload-s3-reconcile",
                "upload-s3-verify",
            ]
            .iter()
            .any(|name| value == OsStr::new(name))
        })
}

enum Error {
    Argument(&'static str, &'static str),
    Runtime(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument(_, message) | Self::Runtime(message) => f.write_str(message),
        }
    }
}
type Result<T> = std::result::Result<T, Error>;
fn malformed(message: &'static str) -> Error {
    Error::Argument(ERR_CLI_MALFORMED_VALUE, message)
}

struct Options {
    command: Command,
    source: PathBuf,
    source_digest: ContentDigest,
    source_bytes: u64,
    journal: PathBuf,
    credentials: PathBuf,
    endpoint: S3Endpoint,
    operation: OperationId,
    deadline: TimestampNs,
    policy: ChunkPolicy,
    transfer: BudgetVector,
    local: BudgetVector,
    minimum: Option<UploadJournalPin>,
    observation: Option<ObservationOptions>,
    completion_observation: Option<CompletionInput>,
}

struct CompletionInput {
    path: PathBuf,
    digest: ContentDigest,
}

struct ObservationOptions {
    operation: OperationId,
    receipt: PathBuf,
}

fn parse(args: &[OsString]) -> Result<Options> {
    const ALLOWED: [&str; 25] = [
        "--source",
        "--source-sha256",
        "--source-bytes",
        "--journal",
        "--peer",
        "--host",
        "--region",
        "--bucket",
        "--key",
        "--credentials",
        "--plaintext-approval",
        "--operation",
        "--deadline-ns",
        "--max-memory-bytes",
        "--max-wire-bytes",
        "--max-requests",
        "--max-local-bytes",
        "--max-local-operations",
        "--part-bytes",
        "--minimum-sequence",
        "--minimum-root",
        "--observation-operation",
        "--observation-receipt",
        "--completion-observation",
        "--completion-observation-sha256",
    ];
    if !handles(args)
        || args.len() > 1 + ALLOWED.len() * 2
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(malformed(
            "command, argument count or argument size refused",
        ));
    }
    let command = match args[0].to_str() {
        Some("upload-s3-prepare") => Command::Prepare,
        Some("upload-s3-resume") => Command::Resume,
        Some("upload-s3-abort") => Command::Abort,
        Some("upload-s3-reconcile") => Command::Reconcile,
        Some("upload-s3-verify") => Command::Verify,
        _ => return Err(malformed("unknown S3 upload command")),
    };
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or(Error::Argument(
            ERR_CLI_INVALID_UNICODE,
            "option name must be UTF-8",
        ))?;
        if !ALLOWED.contains(&key) {
            return Err(Error::Argument(ERR_CLI_UNKNOWN_OPTION, "unknown option"));
        }
        if values.contains_key(key) {
            return Err(Error::Argument(
                ERR_CLI_DUPLICATE_OPTION,
                "duplicate option",
            ));
        }
        let value = pair
            .get(1)
            .filter(|value| {
                !value.is_empty() && !value.to_str().is_some_and(|value| value.starts_with("--"))
            })
            .ok_or(Error::Argument(
                ERR_CLI_MISSING_VALUE,
                "missing option value",
            ))?;
        values.insert(key, value.as_os_str());
    }
    let text = |key: &str| -> Result<&str> {
        values
            .get(key)
            .ok_or(Error::Argument(
                ERR_CLI_MISSING_VALUE,
                "required option missing",
            ))?
            .to_str()
            .ok_or(Error::Argument(
                ERR_CLI_INVALID_UNICODE,
                "option value must be UTF-8",
            ))
    };
    let number = |key: &str, minimum: u64, maximum: u64| -> Result<u64> {
        let raw = text(key)?;
        if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(malformed("bounded unsigned decimal integer required"));
        }
        let value = raw
            .parse::<u64>()
            .map_err(|_| malformed("integer overflow"))?;
        if value < minimum || value > maximum {
            return Err(malformed("numeric bound refused"));
        }
        Ok(value)
    };
    let digest = |key: &str| -> Result<ContentDigest> {
        let value = ContentDigest::parse(text(key)?)
            .map_err(|_| malformed("nonzero SHA-256 digest required"))?;
        if value.algorithm() != DigestAlgorithm::Sha256
            || value.is_laboratory()
            || value.bytes() == [0; 32]
        {
            return Err(malformed("nonzero canonical SHA-256 digest required"));
        }
        Ok(value)
    };
    let path = |key: &str| -> Result<PathBuf> {
        let value = text(key)?;
        let path = PathBuf::from(value);
        if !path.is_absolute()
            || value.chars().any(char::is_control)
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(malformed("absolute normalized path required"));
        }
        Ok(path)
    };
    let raw_deadline = text("--deadline-ns")?;
    if raw_deadline.is_empty() || !raw_deadline.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed("positive decimal deadline required"));
    }
    let deadline = TimestampNs(
        raw_deadline
            .parse::<i128>()
            .map_err(|_| malformed("deadline overflow"))?,
    );
    if deadline.0 == 0 {
        return Err(malformed("positive deadline required"));
    }
    let minimum = match (
        values.contains_key("--minimum-sequence"),
        values.contains_key("--minimum-root"),
    ) {
        (false, false) if command == Command::Prepare => None,
        (true, true) if command != Command::Prepare => Some(UploadJournalPin {
            sequence: number("--minimum-sequence", 1, 65_536)?,
            root: digest("--minimum-root")?,
        }),
        _ => {
            return Err(malformed(
                "resume, abort, reconcile and verify require an independently retained minimum pin",
            ));
        }
    };
    let endpoint = S3Endpoint::new(
        text("--peer")?
            .parse::<SocketAddr>()
            .map_err(|_| malformed("pinned IP address and port required"))?,
        text("--host")?,
        text("--region")?,
        text("--bucket")?,
        text("--key")?,
        digest("--plaintext-approval")?,
    )
    .map_err(|_| malformed("local S3 endpoint or explicit plaintext approval refused"))?;
    let source = path("--source")?;
    let credentials = path("--credentials")?;
    let journal = path("--journal")?;
    if source == credentials
        || source.starts_with(&journal)
        || credentials.starts_with(&journal)
        || journal.starts_with(&source)
        || journal.starts_with(&credentials)
    {
        return Err(malformed(
            "source, credentials and journal must have separate paths",
        ));
    }
    let operation = OperationId::parse(text("--operation")?)
        .map_err(|_| malformed("invalid stable operation identity"))?;
    let observation = if matches!(command, Command::Reconcile | Command::Verify) {
        let observation_operation = OperationId::parse(text("--observation-operation")?)
            .map_err(|_| malformed("invalid observation operation identity"))?;
        if observation_operation == operation {
            return Err(malformed(
                "observation requires a distinct operation identity",
            ));
        }
        let receipt = path("--observation-receipt")?;
        if [&source, &credentials, &journal]
            .iter()
            .any(|other| receipt.starts_with(other) || other.starts_with(&receipt))
        {
            return Err(malformed("observation receipt must have a separate path"));
        }
        Some(ObservationOptions {
            operation: observation_operation,
            receipt,
        })
    } else {
        if values.contains_key("--observation-operation")
            || values.contains_key("--observation-receipt")
        {
            return Err(malformed(
                "observation options require upload-s3-reconcile or upload-s3-verify",
            ));
        }
        None
    };
    let completion_observation = match (
        values.contains_key("--completion-observation"),
        values.contains_key("--completion-observation-sha256"),
    ) {
        (false, false) => None,
        (true, true) if command == Command::Verify => {
            let input = path("--completion-observation")?;
            let output = &observation
                .as_ref()
                .ok_or(malformed("retrieval options absent"))?
                .receipt;
            if [&source, &credentials, &journal, output]
                .iter()
                .any(|other| input.starts_with(other) || other.starts_with(&input))
            {
                return Err(malformed(
                    "completion observation input must have a separate path",
                ));
            }
            Some(CompletionInput {
                path: input,
                digest: digest("--completion-observation-sha256")?,
            })
        }
        _ => {
            return Err(malformed(
                "paired completion observation input and independent digest require upload-s3-verify",
            ));
        }
    };
    let part_size = if values.contains_key("--part-bytes") {
        number("--part-bytes", MIN_PART_SIZE, MAX_SOURCE_BYTES)?
    } else {
        MIN_PART_SIZE
    };
    let mut transfer = BudgetVector::ZERO;
    transfer.bytes = number("--max-memory-bytes", 1, 1024 * 1024 * 1024)?;
    transfer.network_bytes = number("--max-wire-bytes", 1, 1024 * 1024 * 1024)?;
    transfer.storage_operations = number(
        "--max-requests",
        if matches!(command, Command::Reconcile | Command::Verify) {
            1
        } else {
            4
        },
        65_536,
    )?;
    let mut local = BudgetVector::ZERO;
    local.latency_ms = (LOCAL_RUNTIME_NS / 1_000_000) as u64;
    local.bytes = number("--max-local-bytes", 1, 1024 * 1024 * 1024)?;
    local.storage_operations = number("--max-local-operations", 1, 4_000_000)?;
    Ok(Options {
        command,
        source,
        credentials,
        journal,
        endpoint,
        deadline,
        transfer,
        local,
        minimum,
        observation,
        completion_observation,
        source_digest: digest("--source-sha256")?,
        source_bytes: number("--source-bytes", 0, MAX_SOURCE_BYTES)?,
        operation,
        policy: ChunkPolicy { part_size },
    })
}

fn wall_now() -> Result<TimestampNs> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Runtime("host clock precedes the Unix epoch"))?;
    Ok(TimestampNs(
        i128::from(elapsed.as_secs()) * 1_000_000_000 + i128::from(elapsed.subsec_nanos()),
    ))
}
struct HostClock;
impl S3Clock for HostClock {
    fn now(&mut self, _cx: &TransportCx<'_>) -> std::result::Result<TimestampNs, S3Error> {
        wall_now().map_err(|_| S3Error::Clock)
    }
}

fn spec(
    options: &Options,
    allowance: BudgetVector,
    deadline: Option<TimestampNs>,
    capabilities: &[RuntimeGrant],
) -> RootAuthoritySpec {
    RootAuthoritySpec {
        trace_id: "trace:archive-s3-object".into(),
        operation_id: options.operation.clone(),
        principal: PRINCIPAL.into(),
        capabilities: capabilities
            .iter()
            .map(|grant| grant.as_str().to_owned())
            .collect(),
        deadline,
        priority: 10,
        budgets: allowance,
        privacy_scope: "privacy:owner-approved-local-object-store".into(),
        retention_scope: "retention:durable-upload-journal".into(),
        anchor_universe: options.source_digest,
        generation: 1,
    }
}

fn local_io(options: &Options, origin: TimestampNs, started: Instant) -> Result<Arc<ScopedS3Io>> {
    let mut grants = vec![
        RuntimeGrant::ReadMedia,
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::ObjectStage,
    ];
    if options.completion_observation.is_some() {
        grants.push(RuntimeGrant::ObserveStatus);
    }
    let deadline = TimestampNs(
        origin
            .0
            .checked_add(LOCAL_RUNTIME_NS)
            .ok_or(Error::Runtime("local deadline overflow"))?,
    );
    let (mut authority, tree) = AuthorityCx::root(
        spec(options, options.local, Some(deadline), &grants),
        RegionId::new("region:archive-s3-local")
            .map_err(|_| Error::Runtime("local region identity refused"))?,
        RegionKind::Process,
        options.local,
        origin,
    )
    .map_err(|_| Error::Runtime("local file authority refused"))?;
    let mut scopes = GrantSet::empty();
    for (grant, path) in [
        (RuntimeGrant::ReadMedia, &options.source),
        (RuntimeGrant::AdapterAuth, &options.credentials),
    ] {
        let resource = path
            .to_str()
            .ok_or(Error::Runtime("path scope is not UTF-8"))?;
        scopes = scopes.with_scope(grant, [resource.to_owned()].into_iter().collect());
    }
    let mut output_scopes = std::collections::BTreeSet::from([options
        .journal
        .to_str()
        .ok_or(Error::Runtime("journal scope is not UTF-8"))?
        .to_owned()]);
    if let Some(observation) = &options.observation {
        output_scopes.insert(
            observation
                .receipt
                .to_str()
                .ok_or(Error::Runtime("observation scope is not UTF-8"))?
                .to_owned(),
        );
    }
    scopes = scopes.with_scope(RuntimeGrant::ObjectStage, output_scopes);
    if let Some(input) = &options.completion_observation {
        scopes = scopes.with_scope(
            RuntimeGrant::ObserveStatus,
            std::collections::BTreeSet::from([input
                .path
                .to_str()
                .ok_or(Error::Runtime("completion observation scope is not UTF-8"))?
                .to_owned()]),
        );
    }
    authority
        .narrow_grants(scopes)
        .map_err(|_| Error::Runtime("local path scope refused"))?;
    Ok(Arc::new(
        ScopedS3Io::new(
            options.journal.clone(),
            options.source.clone(),
            options.credentials.clone(),
            options
                .observation
                .as_ref()
                .map(|value| value.receipt.clone()),
            options
                .completion_observation
                .as_ref()
                .map(|value| value.path.clone()),
            authority,
            tree,
            started,
            origin,
        )
        .map_err(|_| Error::Runtime("scoped local file admission refused"))?,
    ))
}

fn upload_authority(
    options: &Options,
    allowance: BudgetVector,
    now: TimestampNs,
) -> Result<(AuthorityCx, AuthorityCx, RegionTree, RootAuthoritySpec)> {
    let grants = [
        RuntimeGrant::ObjectStage,
        RuntimeGrant::ObjectPublish,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
    ];
    // The process/property owners may perform bounded cleanup after the original
    // transfer deadline. The upload child retains that original deadline.
    let owner_spec = spec(options, allowance, None, &grants);
    let (mut root, mut tree) = AuthorityCx::root(
        owner_spec.clone(),
        RegionId::new("region:archive-s3-process")
            .map_err(|_| Error::Runtime("upload process identity refused"))?,
        RegionKind::Process,
        allowance,
        now,
    )
    .map_err(|_| Error::Runtime("upload process authority refused"))?;
    let mut scopes = GrantSet::empty();
    for grant in grants {
        scopes = scopes.with_scope(
            grant,
            [options.endpoint.resource().to_owned()]
                .into_iter()
                .collect(),
        );
    }
    root.narrow_grants(scopes)
        .map_err(|_| Error::Runtime("upload resource scope refused"))?;
    let property = root
        .scope_down(
            &mut tree,
            RegionId::new("region:archive-s3-property")
                .map_err(|_| Error::Runtime("upload property identity refused"))?,
            RegionKind::Property,
            allowance,
            owner_spec,
            now,
        )
        .map_err(|_| Error::Runtime("upload property authority refused"))?;
    Ok((
        root,
        property,
        tree,
        spec(options, allowance, Some(options.deadline), &grants),
    ))
}

fn phase(phase: MultipartPhase) -> (&'static str, Option<&'static str>) {
    match phase {
        MultipartPhase::Prepared => ("prepared", None),
        MultipartPhase::Uploading => ("uploading", None),
        MultipartPhase::Completed => ("completed", None),
        MultipartPhase::Aborted => ("aborted", None),
        MultipartPhase::Uncertain(operation) => (
            "uncertain",
            Some(match operation {
                TransportOperation::Initiate => "initiate",
                TransportOperation::UploadPart => "upload_part",
                TransportOperation::Complete => "complete",
                TransportOperation::Abort => "abort",
                TransportOperation::Reconcile => "reconcile",
            }),
        ),
    }
}

struct Report {
    intent: UploadIntent,
    phase: MultipartPhase,
    confirmed: usize,
    total: usize,
    minimum: UploadJournalPin,
    head: UploadJournalPin,
    consumed: BudgetVector,
    remaining: BudgetVector,
    local_work: BudgetVector,
    receipt: Option<ContentDigest>,
    settled: bool,
    source_verified: bool,
    dispatch_requested: bool,
    failure: Option<&'static str>,
    durability_failed: bool,
    // Internal continuation only; never a provider success or public receipt.
    resume_after_reconciliation: bool,
}
impl Report {
    fn render(&self, options: &Options) -> Result<String> {
        let (state, uncertain) = phase(self.phase);
        let next = if self.durability_failed {
            "cold_reopen_from_retained_pin"
        } else if !self.settled
            && matches!(
                self.phase,
                MultipartPhase::Completed | MultipartPhase::Aborted
            )
        {
            "resume_local_settlement"
        } else {
            match self.phase {
                MultipartPhase::Prepared => "retain_minimum_pin_then_resume_or_abort",
                MultipartPhase::Uploading => "resume_or_abort_from_retained_pin",
                MultipartPhase::Uncertain(_) => "independent_provider_reconciliation_required",
                MultipartPhase::Completed => "independent_retrieval_verification_required",
                MultipartPhase::Aborted => "terminal",
            }
        };
        let mut report = object(&[
            ("schema", string("fss.s3_upload_cli.v1")),
            ("kind", string("s3_object_upload")),
            ("command", string(options.command.name())),
            ("resource", string(self.intent.resource())),
            ("intent_digest", string(&self.intent.digest().to_text())),
            ("operation", string(self.intent.operation().as_str())),
            ("source_digest", string(&options.source_digest.to_text())),
            ("source_bytes", options.source_bytes.to_string()),
            (
                "source_verified_this_invocation",
                self.source_verified.to_string(),
            ),
            ("plan_digest", string(&self.intent.plan_digest().to_text())),
            ("phase", string(state)),
            (
                "uncertain_operation",
                uncertain.map_or_else(|| "null".into(), string),
            ),
            ("confirmed_parts", self.confirmed.to_string()),
            ("total_parts", self.total.to_string()),
            ("minimum_sequence", self.minimum.sequence.to_string()),
            ("minimum_root", string(&self.minimum.root.to_text())),
            ("journal_sequence", self.head.sequence.to_string()),
            ("journal_head", string(&self.head.root.to_text())),
            ("upload_consumed", budget(&self.consumed)),
            ("upload_remaining", budget(&self.remaining)),
            ("local_work", budget(&self.local_work)),
            (
                "receipt_digest",
                self.receipt
                    .map_or_else(|| "null".into(), |value| string(&value.to_text())),
            ),
            ("locally_settled", self.settled.to_string()),
            (
                "journal_requires_cold_reopen",
                self.durability_failed.to_string(),
            ),
            (
                "provider_work_requested_this_invocation",
                self.dispatch_requested.to_string(),
            ),
            (
                "error_kind",
                self.failure.map_or_else(|| "null".into(), string),
            ),
            ("next_action", string(next)),
            (
                "transport_profile",
                string("approved_local_plaintext_sigv4"),
            ),
            ("independent_retrievability_verified", "false".into()),
            ("graph_closure_verified", "false".into()),
            ("client_side_encryption_performed", "false".into()),
        ]);
        report.push('\n');
        if report.len() > MAX_REPORT_BYTES {
            return Err(Error::Runtime("upload report exceeds its bound"));
        }
        Ok(report)
    }
}

// Pure preparation and terminal local settlement cannot accidentally acquire a
// socket or require a readable credential file.
struct NoNetwork;
impl fss_object::multipart::MultipartTransport for NoNetwork {
    fn initiate(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &UploadIntent,
    ) -> std::result::Result<fss_object::multipart::UploadId, String> {
        Err("provider operation unavailable in local preparation".into())
    }
    fn upload_part(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &fss_object::multipart::UploadId,
        _: &fss_object::planner::PlannedChunk,
        _: &[u8],
        _: ContentDigest,
    ) -> std::result::Result<fss_object::multipart::PartReceipt, String> {
        Err("provider operation unavailable in local preparation".into())
    }
    fn complete(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &fss_object::multipart::UploadId,
        _: &UploadIntent,
        _: &[fss_object::multipart::PartReceipt],
    ) -> std::result::Result<(), String> {
        Err("provider operation unavailable in local preparation".into())
    }
    fn abort(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &fss_object::multipart::UploadId,
        _: &UploadIntent,
    ) -> std::result::Result<(), String> {
        Err("provider operation unavailable in local preparation".into())
    }
    fn reconcile(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &UploadIntent,
    ) -> std::result::Result<fss_object::multipart::Reconciliation, String> {
        Err("provider operation unavailable in local preparation".into())
    }
}

fn expected_intent(options: &Options, now: TimestampNs) -> Result<UploadIntent> {
    let plan = plan_chunks(options.source_bytes, options.policy)
        .map_err(|_| Error::Runtime("object chunk plan refused"))?;
    let mut transport = NoNetwork;
    let session = MultipartSession::prepare(
        &mut transport,
        &plan,
        options.source_digest,
        options.operation.clone(),
        options.endpoint.resource(),
        now,
    )
    .map_err(|_| Error::Runtime("object upload intent refused"))?;
    Ok(session.intent().clone())
}

fn verify_source(options: &Options, local: &ScopedS3Io) -> Result<Vec<u8>> {
    let bytes = local
        .read_source(options.source_bytes)
        .map_err(|_| Error::Runtime("bounded immutable source read refused"))?;
    if ContentDigest::sha256(&bytes) != options.source_digest {
        return Err(Error::Runtime(
            "source checksum differs from the independently supplied digest",
        ));
    }
    local
        .check()
        .map_err(|_| Error::Runtime("source verification outlived local authority"))?;
    Ok(bytes)
}

fn journal_limits() -> UploadJournalLimits {
    UploadJournalLimits {
        max_total_bytes: 64 * 1024 * 1024,
        max_records: 65_536,
        max_checkpoint_bytes: 128 * 1024,
        max_read_bytes: 256 * 1024 * 1024,
    }
}

fn validate_transfer_allowance(options: &Options, limits: &S3Limits) -> Result<()> {
    let plan = plan_chunks(options.source_bytes, options.policy)
        .map_err(|_| Error::Runtime("object chunk plan refused"))?;
    let mut required = minimum_upload_budget(options.source_bytes, options.policy)
        .map_err(|_| Error::Runtime("minimum upload allowance refused"))?;
    let overhead = limits
        .overhead_budget(plan.chunks.len())
        .map_err(|_| Error::Runtime("native transport allowance overflow"))?;
    required.bytes = required
        .bytes
        .saturating_add(options.source_bytes)
        .saturating_add(overhead.bytes);
    required.network_bytes = required
        .network_bytes
        .saturating_add(overhead.network_bytes);
    required.storage_operations = required
        .storage_operations
        .saturating_add(plan.chunks.len() as u64)
        .saturating_add(overhead.storage_operations);
    if !required.fits_within(options.transfer) {
        return Err(Error::Runtime(
            "explicit allowance cannot cover source, wire framing and cleanup",
        ));
    }
    Ok(())
}

fn report_recovery(
    options: &Options,
    recovery: &MultipartRecovery,
    expected: UploadIntent,
) -> Result<Report> {
    let receipt = match recovery.phase() {
        MultipartPhase::Completed => recovery
            .completion_receipt()
            .ok()
            .map(|value| value.digest()),
        MultipartPhase::Aborted => recovery.abort_receipt().ok().map(|value| value.digest()),
        _ => None,
    };
    let state = recovery
        .owner_state()
        .map_err(|_| Error::Runtime("upload owner checkpoint refused"))?;
    Ok(Report {
        intent: expected,
        phase: recovery.phase(),
        confirmed: recovery.confirmed_parts(),
        total: recovery.plan().chunks.len(),
        minimum: options
            .minimum
            .ok_or(Error::Runtime("recovery minimum absent"))?,
        head: recovery.head(),
        consumed: recovery.consumed(),
        remaining: recovery.remaining_budget(),
        local_work: BudgetVector::ZERO,
        receipt,
        settled: state.is_some_and(|state| state != ObligationState::Pending),
        source_verified: false,
        dispatch_requested: false,
        durability_failed: false,
        resume_after_reconciliation: false,
        failure: Some("indeterminate_ownership_requires_independent_reconciliation"),
    })
}

fn close_parents(
    root: &mut AuthorityCx,
    property: &mut AuthorityCx,
    tree: &mut RegionTree,
    now: TimestampNs,
) -> Result<()> {
    property
        .request_cancellation(tree, now)
        .and_then(|()| property.begin_drain(tree, now))
        .and_then(|()| property.finalize(tree, now).map(|_| ()))
        .map_err(|_| Error::Runtime("upload property finalization refused"))?;
    root.release_scope_reservation(tree, property)
        .map_err(|_| Error::Runtime("upload property reservation remained owned"))?;
    root.request_cancellation(tree, now)
        .and_then(|()| root.begin_drain(tree, now))
        .and_then(|()| root.finalize(tree, now).map(|_| ()))
        .map_err(|_| Error::Runtime("upload process finalization refused"))
}

fn drive<T: fss_object::multipart::MultipartTransport>(
    options: &Options,
    journal: &mut FileUploadJournal,
    transport: &mut T,
    recovery: Option<MultipartRecovery>,
    expected: UploadIntent,
    source: Option<&[u8]>,
) -> Result<Report> {
    let now = wall_now()?;
    let allowance = recovery
        .as_ref()
        .map_or(options.transfer, |value| value.remaining_budget());
    let total_parts = plan_chunks(options.source_bytes, options.policy)
        .map_err(|_| Error::Runtime("object plan refused"))?
        .chunks
        .len();
    let (mut root, mut property, mut tree, child_spec) = upload_authority(options, allowance, now)?;
    let mut upload = if let Some(recovery) = recovery {
        StagedUpload::recover(
            &mut property,
            &mut tree,
            transport,
            journal,
            recovery,
            &expected,
            child_spec,
            now,
        )
        .map_err(|_| Error::Runtime("pinned upload recovery or fresh authority refused"))?
    } else {
        let mut owner = StagedUpload::stage(
            &mut property,
            &mut tree,
            transport,
            options.operation.clone(),
            options.source_bytes,
            options.policy,
            options.source_digest,
            child_spec,
            options.endpoint.resource(),
            now,
        )
        .map_err(|_| Error::Runtime("bounded upload preparation refused"))?;
        owner.attach_journal(&tree, now, journal).map_err(|_| {
            Error::Runtime("initial upload checkpoint could not be durably confirmed")
        })?;
        owner
    };
    let minimum = options
        .minimum
        .or_else(|| upload.journal_pin())
        .ok_or(Error::Runtime("durable minimum pin absent"))?;
    let mut failure = None;
    let mut receipt = None;
    let mut settled = false;
    let mut dispatch_requested = false;
    let mut resume_after_reconciliation = false;
    if options.command != Command::Prepare {
        let was_part_uncertain =
            upload.phase() == MultipartPhase::Uncertain(TransportOperation::UploadPart);
        let confirmed_before = upload.confirmed_parts();
        let result: std::result::Result<(), ()> = match upload.phase() {
            MultipartPhase::Completed => upload
                .finish(&mut tree, wall_now()?)
                .map(|value| {
                    receipt = Some(value.digest());
                    settled = true;
                })
                .map_err(|_| ()),
            MultipartPhase::Aborted => upload
                .cancel(&mut tree, wall_now()?)
                .map(|value| {
                    receipt = Some(value.digest());
                    settled = true;
                })
                .map_err(|_| ()),
            MultipartPhase::Uncertain(_) => {
                dispatch_requested = true;
                match upload.reconcile(&mut tree, wall_now()?) {
                    Ok(MultipartPhase::Completed) => upload
                        .finish(&mut tree, wall_now()?)
                        .map(|value| {
                            receipt = Some(value.digest());
                            settled = true;
                        })
                        .map_err(|_| ()),
                    Ok(MultipartPhase::Aborted) => upload
                        .cancel(&mut tree, wall_now()?)
                        .map(|value| {
                            receipt = Some(value.digest());
                            settled = true;
                        })
                        .map_err(|_| ()),
                    Ok(MultipartPhase::Uploading)
                        if options.command == Command::Resume && was_part_uncertain =>
                    {
                        if upload.durability_failed()
                            || upload.confirmed_parts() <= confirmed_before
                        {
                            Err(())
                        } else {
                            // The native adapter stays uncertain until this durable
                            // proof is independently recovered by a fresh owner.
                            resume_after_reconciliation = true;
                            Ok(())
                        }
                    }
                    Ok(_) => Ok(()),
                    Err(_) => Err(()),
                }
            }
            MultipartPhase::Prepared | MultipartPhase::Uploading
                if options.command == Command::Abort =>
            {
                dispatch_requested = upload.phase() == MultipartPhase::Uploading;
                match upload.request_cancellation(&mut tree, wall_now()?) {
                    Ok(()) => upload
                        .cancel(&mut tree, wall_now()?)
                        .map(|value| {
                            receipt = Some(value.digest());
                            settled = true;
                        })
                        .map_err(|_| ()),
                    Err(_) => Err(()),
                }
            }
            MultipartPhase::Prepared | MultipartPhase::Uploading => {
                dispatch_requested = true;
                let progress = if upload.phase() == MultipartPhase::Uploading
                    && upload.confirmed_parts() == total_parts
                {
                    // Every original source range already has durable provider proof.
                    // Finishing does not need to reopen or reread the local source.
                    upload
                        .finish(&mut tree, wall_now()?)
                        .map(resumption::Progress::Completed)
                        .map_err(|_| ())
                } else {
                    let bytes = source.ok_or(Error::Runtime("verified source is absent"))?;
                    resumption::upload_pass(&mut upload, &mut tree, bytes)
                };
                match progress {
                    Ok(resumption::Progress::Completed(value)) => {
                        receipt = Some(value.digest());
                        settled = true;
                        Ok(())
                    }
                    Ok(resumption::Progress::Reopen) => {
                        resume_after_reconciliation = true;
                        Ok(())
                    }
                    Err(()) => Err(()),
                }
            }
        };
        if result.is_err() {
            failure = Some("upload_operation_refused");
        }
        if matches!(upload.phase(), MultipartPhase::Uncertain(_)) && !upload.durability_failed() {
            // Close local ownership without claiming rollback or publication.
            // The pre-settlement journal head is the retained follow-up record.
            let follow_up = upload.journal_pin().ok_or(Error::Runtime(
                "uncertain upload has no retained follow-up pin",
            ))?;
            match upload.settle_indeterminate(
                &mut tree, wall_now()?,
                "Independently reconcile this journal-bound provider outcome before any new upload.",
                follow_up.root,
            ) {
                Ok(value) => { receipt = Some(value.digest()); settled = true; }
                Err(_) => failure = Some("indeterminate_local_settlement_refused"),
            }
            failure.get_or_insert("provider_outcome_indeterminate");
        }
        if upload.durability_failed() {
            failure = Some("journal_requires_cold_reopen");
        }
        if options.command == Command::Abort && upload.phase() == MultipartPhase::Completed {
            failure = Some("completed_object_cannot_be_aborted");
        }
        if options.command == Command::Resume && upload.phase() == MultipartPhase::Aborted {
            failure = Some("upload_already_aborted");
        }
    }
    let head = upload
        .journal_pin()
        .ok_or(Error::Runtime("confirmed journal head absent"))?;
    let report = Report {
        intent: upload.intent().clone(),
        phase: upload.phase(),
        confirmed: upload.confirmed_parts(),
        total: total_parts,
        minimum,
        head,
        consumed: upload
            .cumulative_consumed()
            .map_err(|_| Error::Runtime("cumulative upload accounting refused"))?,
        remaining: upload.budget().remaining(),
        local_work: BudgetVector::ZERO,
        receipt,
        settled,
        source_verified: source.is_some(),
        dispatch_requested,
        failure,
        durability_failed: upload.durability_failed(),
        resume_after_reconciliation,
    };
    drop(upload);
    if settled {
        close_parents(&mut root, &mut property, &mut tree, wall_now()?)?;
    }
    // Prepared or locally refused work remains explicitly pending in the
    // durable journal. No transport task, thread, or socket outlives this call.
    Ok(report)
}

fn execute_in(options: &Options, local: &Arc<ScopedS3Io>) -> Result<Report> {
    let now = wall_now()?;
    let expected = expected_intent(options, now)?;
    if options.command == Command::Prepare {
        if now >= options.deadline {
            return Err(Error::Runtime("preparation deadline has already expired"));
        }
        validate_transfer_allowance(options, &S3Limits::default())?;
        let source = verify_source(options, local)?;
        let mut journal =
            FileUploadJournal::create(&options.journal, journal_limits(), local.clone())
                .map_err(|_| Error::Runtime("new exclusive upload journal refused"))?;
        return drive(
            options,
            &mut journal,
            &mut NoNetwork,
            None,
            expected,
            Some(&source),
        );
    }
    resumption::execute(options, local, expected)
}

fn execute(options: &Options) -> Result<(String, bool)> {
    if options.command == Command::Reconcile {
        return observation::execute(options);
    }
    if options.command == Command::Verify {
        return retrieval::execute(options);
    }
    let started = Instant::now();
    let local = local_io(options, wall_now()?, started)?;
    let result = execute_in(options, &local);
    // Every journal and advisory lock has been dropped before local finalization.
    let work = local
        .consumed()
        .map_err(|_| Error::Runtime("local work accounting refused"))?;
    let finalized = local
        .finalize()
        .map_err(|_| Error::Runtime("local file authority could not finalize"));
    let mut report = result?;
    finalized?;
    report.local_work = work;
    let success = report.failure.is_none()
        && match options.command {
            Command::Prepare => report.phase == MultipartPhase::Prepared,
            Command::Resume => report.phase == MultipartPhase::Completed && report.settled,
            Command::Abort => report.phase == MultipartPhase::Aborted && report.settled,
            Command::Reconcile | Command::Verify => false,
        };
    Ok((report.render(options)?, success))
}

pub(super) fn dispatch(args: &[OsString]) -> ExitCode {
    if verification::handles(args) {
        return verification::dispatch(args);
    }
    match parse(args).and_then(|options| execute(&options)) {
        Ok((report, success)) => {
            if super::emit(&mut io::stdout().lock(), report.as_bytes()).is_err() {
                eprintln!(
                    "{ERR_CLI_RUNTIME_FAILURE}: report output failed; retain the minimum pin and inspect the journal before retrying"
                );
                return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
            }
            ExitCode::from(if success {
                ExitIdentity::SUCCESS.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            })
        }
        Err(error) => {
            let (code, status) = match &error {
                Error::Argument(code, _) => (*code, ExitIdentity::MALFORMED_VALUE),
                Error::Runtime(_) => (ERR_CLI_RUNTIME_FAILURE, ExitIdentity::RUNTIME_FAILURE),
            };
            eprintln!("{code}: {error}");
            eprintln!(
                "Retain the original journal and minimum pin. Do not start a replacement upload after an uncertain outcome."
            );
            ExitCode::from(status.code)
        }
    }
}
