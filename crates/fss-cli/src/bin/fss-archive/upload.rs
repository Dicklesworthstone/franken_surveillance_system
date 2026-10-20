#![forbid(unsafe_code)]
//! Bounded read-only inspection of the actual durable multipart owner.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{budget, object, string};
use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION, ExitIdentity,
};
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_object::multipart::{MultipartError, MultipartPhase, TransportOperation, UploadJournalPin};
use fss_object::upload_journal::{
    UploadJournalInspection, UploadJournalLimits, inspect_upload_journal,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::grant::GrantSet;

const MAX_REPORT_BYTES: usize = 16 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JOURNAL_RECORDS: u64 = 65_536;

pub(super) const HELP: &str = "fss-archive upload-inspect [options]\n\
  Required: --journal EXISTING_DIR --journal-resource EXACT_ARCHIVE_RESOURCE\n\
            --minimum-sequence U64 --minimum-root sha256:HEX\n\
            --attested-now-ns I128 --max-journal-bytes U64 --max-records U64\n\
            --max-checkpoint-bytes U64 --max-read-bytes U64\n\
  Optional: --expected-head sha256:HEX\n\
  Verifies the complete committed history through a separately retained minimum\n\
  pin. Reports the exact intent, namespace binding, durable head, acknowledged\n\
  parts, remaining transfer allowance and required recovery action. The status\n\
  grant is scoped to the exact archive resource recorded by the uploader.\n\
  Inspection work is charged separately; it cannot refill the upload allowance.\n\
  Maximum 64 MiB retained, 65536 records, 16 MiB per checkpoint, 256 MiB read work.\n\
  The caller attests current time. An optional expected head must match exactly.\n\
  Legacy unbound journals are readable but need explicit adoption before writes.\n\
  No journal creation, provider contact, upload recovery, adoption or repair occurs.\n\
  Provider acknowledgements do not establish independent retrievability.\n";

pub(super) fn handles(args: &[OsString]) -> bool {
    args.first()
        .is_some_and(|value| value == OsStr::new("upload-inspect"))
}

enum Error {
    Argument(&'static str, &'static str),
    Authority,
    Journal(MultipartError),
    HeadMismatch,
    Report,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument(_, message) => f.write_str(message),
            Self::Authority => f.write_str("inspection authority or resource accounting refused"),
            Self::Journal(error) => fmt::Display::fmt(error, f),
            Self::HeadMismatch => f.write_str("upload journal head differs from the expected head"),
            Self::Report => f.write_str("upload inspection report exceeds its bound"),
        }
    }
}
type Result<T> = std::result::Result<T, Error>;
fn malformed(message: &'static str) -> Error {
    Error::Argument(ERR_CLI_MALFORMED_VALUE, message)
}

struct Options {
    root: PathBuf,
    resource: String,
    limits: UploadJournalLimits,
    minimum: UploadJournalPin,
    now: TimestampNs,
    expected_head: Option<ContentDigest>,
}

fn parse(args: &[OsString]) -> Result<Options> {
    const ALLOWED: [&str; 10] = [
        "--journal",
        "--journal-resource",
        "--attested-now-ns",
        "--max-journal-bytes",
        "--max-records",
        "--expected-head",
        "--minimum-sequence",
        "--minimum-root",
        "--max-checkpoint-bytes",
        "--max-read-bytes",
    ];
    if !handles(args)
        || args.len() > 1 + 2 * ALLOWED.len()
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(malformed("command, argument count or length refused"));
    }
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
                !value.is_empty() && !value.to_str().is_some_and(|text| text.starts_with("--"))
            })
            .ok_or(Error::Argument(
                ERR_CLI_MISSING_VALUE,
                "missing option value",
            ))?;
        values.insert(key, value.as_os_str());
    }
    let required = |key: &str| -> Result<&OsStr> {
        values.get(key).copied().ok_or(Error::Argument(
            ERR_CLI_MISSING_VALUE,
            "required option missing",
        ))
    };
    let text = |key: &str| -> Result<&str> {
        required(key)?.to_str().ok_or(Error::Argument(
            ERR_CLI_INVALID_UNICODE,
            "option value must be UTF-8",
        ))
    };
    let number = |key: &str, maximum: u64| -> Result<u64> {
        let raw = text(key)?;
        if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(malformed("positive decimal integer required"));
        }
        let value = raw
            .parse::<u64>()
            .map_err(|_| malformed("integer overflow"))?;
        if !(1..=maximum).contains(&value) {
            return Err(malformed("numeric bound refused"));
        }
        Ok(value)
    };
    let resource = text("--journal-resource")?;
    if resource.is_empty() || resource.len() > 1024 || resource.chars().any(char::is_control) {
        return Err(malformed("bounded journal resource required"));
    }
    let raw_time = text("--attested-now-ns")?;
    let digits = raw_time.strip_prefix('-').unwrap_or(raw_time);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed("signed decimal attested time required"));
    }
    let now = TimestampNs(
        raw_time
            .parse::<i128>()
            .map_err(|_| malformed("attested time overflow"))?,
    );
    let digest = |key: &str| -> Result<ContentDigest> {
        let digest =
            ContentDigest::parse(text(key)?).map_err(|_| malformed("invalid journal digest"))?;
        if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
            return Err(malformed("nonzero SHA-256 journal digest required"));
        }
        Ok(digest)
    };
    let expected_head = if values.contains_key("--expected-head") {
        Some(digest("--expected-head")?)
    } else {
        None
    };
    Ok(Options {
        root: PathBuf::from(required("--journal")?),
        resource: resource.to_owned(),
        limits: UploadJournalLimits {
            max_total_bytes: number("--max-journal-bytes", MAX_JOURNAL_BYTES)?,
            max_records: number("--max-records", MAX_JOURNAL_RECORDS)? as usize,
            max_checkpoint_bytes: number("--max-checkpoint-bytes", 16 * 1024 * 1024)? as usize,
            max_read_bytes: number("--max-read-bytes", 256 * 1024 * 1024)?,
        },
        minimum: UploadJournalPin {
            sequence: number("--minimum-sequence", MAX_JOURNAL_RECORDS)?,
            root: digest("--minimum-root")?,
        },
        now,
        expected_head,
    })
}

fn phase(value: MultipartPhase) -> (&'static str, Option<&'static str>) {
    match value {
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

fn report(
    inspection: &UploadJournalInspection,
    options: &Options,
    work: &BudgetVector,
) -> Result<String> {
    let intent = inspection.intent();
    let (state, uncertain) = phase(inspection.phase());
    let mut result = object(&[
        ("schema", string("fss.upload_journal_inspection.v1")),
        ("kind", string("multipart_upload_journal_inspected")),
        ("intent_digest", string(&intent.digest().to_text())),
        ("operation", string(intent.operation().as_str())),
        ("resource", string(intent.resource())),
        ("plan_digest", string(&intent.plan_digest().to_text())),
        ("manifest_root", string(&intent.manifest_root().to_text())),
        ("phase", string(state)),
        (
            "uncertain_operation",
            uncertain.map_or_else(|| "null".into(), string),
        ),
        ("confirmed_parts", inspection.confirmed_parts().to_string()),
        ("total_parts", inspection.total_parts().to_string()),
        ("upload_consumed", budget(&inspection.consumed())),
        ("upload_remaining", budget(&inspection.remaining())),
        ("journal_head", string(&inspection.head().root.to_text())),
        ("journal_sequence", inspection.head().sequence.to_string()),
        ("journal_records", inspection.records().to_string()),
        ("minimum_sequence", options.minimum.sequence.to_string()),
        ("minimum_root", string(&options.minimum.root.to_text())),
        ("minimum_pin_verified", "true".into()),
        (
            "last_observed_at_ns",
            string(&inspection.observed_at().0.to_string()),
        ),
        ("attested_now_ns", string(&options.now.0.to_string())),
        ("cancelled", inspection.cancelled().to_string()),
        (
            "deadline_ns",
            inspection
                .deadline()
                .map_or_else(|| "null".into(), |value| string(&value.0.to_string())),
        ),
        (
            "deadline_expired",
            inspection
                .deadline()
                .is_some_and(|deadline| options.now >= deadline)
                .to_string(),
        ),
        (
            "orphaned_staging_count",
            inspection.orphaned_staging_count().to_string(),
        ),
        (
            "namespace_binding",
            string(&inspection.namespace_binding().to_text()),
        ),
        (
            "namespace_binding_verified",
            inspection.namespace_binding_verified().to_string(),
        ),
        (
            "legacy_read_only",
            inspection.legacy_read_only().to_string(),
        ),
        (
            "reconciliation_reference",
            inspection
                .reconciliation_reference()
                .map_or_else(|| "null".into(), |value| string(&value.to_text())),
        ),
        ("locally_settled", inspection.locally_settled().to_string()),
        (
            "expected_head_verified",
            options.expected_head.is_some().to_string(),
        ),
        ("next_action", string(inspection.next_action())),
        ("inspection_work", budget(work)),
        ("provider_contacted", "false".into()),
        ("independent_retrievability_verified", "false".into()),
    ]);
    result.push('\n');
    if result.len() > MAX_REPORT_BYTES {
        return Err(Error::Report);
    }
    Ok(result)
}

fn execute(options: &Options) -> Result<String> {
    let mut allowance = BudgetVector::ZERO;
    allowance.bytes = options.limits.max_read_bytes;
    allowance.storage_operations = 4096 + 64 * options.limits.max_records as u64;
    let spec = RootAuthoritySpec {
        trace_id: "trace:archive-upload-inspection".into(),
        operation_id: OperationId::parse("operation:archive-upload-inspection")
            .map_err(|_| Error::Authority)?,
        principal: "principal:archive-upload-inspector".into(),
        capabilities: vec![RuntimeGrant::ObserveStatus.as_str().to_owned()],
        deadline: None,
        priority: 10,
        budgets: allowance,
        privacy_scope: "privacy:archive-status".into(),
        retention_scope: "retention:local-inspection".into(),
        anchor_universe: ContentDigest::sha256(options.resource.as_bytes()),
        generation: 1,
    };
    let (mut authority, mut tree) = AuthorityCx::root(
        spec,
        RegionId::new("region:archive-upload-inspection").map_err(|_| Error::Authority)?,
        RegionKind::Process,
        allowance,
        options.now,
    )
    .map_err(|_| Error::Authority)?;
    authority
        .narrow_grants(GrantSet::empty().with_scope(
            RuntimeGrant::ObserveStatus,
            [options.resource.clone()].into_iter().collect(),
        ))
        .map_err(|_| Error::Authority)?;
    let inspected = inspect_upload_journal(
        &options.root,
        options.limits,
        options.minimum,
        &options.resource,
        &mut authority,
        &tree,
        options.now,
    )
    .map_err(Error::Journal);
    let work = *authority.budget().consumed();
    // Even a refused inspection leaves no live process scope or detached I/O owner.
    authority
        .request_cancellation(&mut tree, options.now)
        .map_err(|_| Error::Authority)?;
    authority
        .begin_drain(&mut tree, options.now)
        .map_err(|_| Error::Authority)?;
    authority
        .finalize(&mut tree, options.now)
        .map_err(|_| Error::Authority)?;
    let inspection = inspected?;
    if options
        .expected_head
        .is_some_and(|expected| expected != inspection.head().root)
    {
        return Err(Error::HeadMismatch);
    }
    report(&inspection, options, &work)
}

pub(super) fn dispatch(args: &[OsString]) -> ExitCode {
    match parse(args).and_then(|options| execute(&options)) {
        Ok(report) => match super::emit(&mut io::stdout().lock(), report.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            let (code, identity) = match error {
                Error::Argument(code, _) => (code, ExitIdentity::MALFORMED_VALUE),
                _ => (ERR_CLI_RUNTIME_FAILURE, ExitIdentity::RUNTIME_FAILURE),
            };
            eprintln!("{code}: {error}");
            ExitCode::from(identity.code)
        }
    }
}
