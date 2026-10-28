#![forbid(unsafe_code)]
//! Bounded live ONVIF acquisition, retained vendor claims, and independent cold verification.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use fss_core::{
    BudgetVector, CanonicalEncoder, CaptureInterval, ContentDigest, ContextAuthority, OperationId,
    RootAuthoritySpec, SensorId, TimestampNs,
};
use fss_reference::onvif::metadata::{
    Interpretation, MAX_SOURCE_BYTES, RetainedMetadata, SourceBinding, retain_with_interpretation,
};
use fss_reference::onvif::wire::{
    AnalyticsClassFormat, AnalyticsFrame, AnalyticsTransformation, AnalyticsVector,
    EventDocumentFormat, EventItems, PropertyOperation,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

#[path = "fss-onvif-metadata/admission.rs"]
mod admission;
#[path = "fss-capture-rtsp/authentication.rs"]
mod authentication;
#[path = "fss-onvif-metadata/capture.rs"]
mod capture;
#[path = "fss-onvif-metadata/control.rs"]
mod control;
#[path = "fss-onvif-metadata/rtp.rs"]
mod rtp;
#[path = "fss-onvif/runtime.rs"]
mod runtime;

const HELP: &str = "fss-onvif-metadata <capture|control|import|inspect|verify|import-rtp|inspect-rtp|verify-rtp> [options]
  RTP metadata: import-rtp/inspect-rtp/verify-rtp --help
  capture: see fss-onvif-metadata capture --help for explicit live subscription options.
  control: see fss-onvif-metadata control --help for cold discovery, operation inspection and explicit cleanup.
  All commands: --root ABSOLUTE_DIR --site SITE [--principal ID]
                [--include-values yes|no]
  import: --input FILE --sensor ID --device-generation sha256:HEX
          --profile-generation sha256:HEX --profile TOKEN
          --received-start-ns N --received-end-ns N
          [--source-sha256 sha256:HEX]
          [--interpretation analytics-v2|events-v1]
  inspect/verify: --import-id sha256:HEX [--expected-root sha256:HEX]

Imports one complete ONVIF PullMessages SOAP response or MetadataStream XML document.
The source file is bounded to 256 KiB and retained exactly with immutable owner pins.
Receive times use the operator's declared clock; camera UtcTime remains an unverified claim.
inspect and verify both reopen, hash and reparse only retained bytes, without the input file.
New imports use analytics-v2; events-v1 supports exact retries of older imports.
Cold reads always use the retained generation and never reinterpret an existing import.
SimpleItem values, object IDs, classes and geometry are withheld by default.
--include-values yes explicitly reveals private
vendor values to this local command's stdout; it enables no sensitive analysis or effects.
Notification order, duplicates, initialization and deletion operations are preserved.
File imports do not authenticate a camera. The capture command requires a separately
approved finite subscription. Neither lane establishes coverage, physical absence or control.
";

const ARGUMENT_ERROR: &str = "ERR-ONVIF-METADATA-ARGUMENT-001";
const INPUT_ERROR: &str = "ERR-ONVIF-METADATA-INPUT-001";
const LIMIT_ERROR: &str = "ERR-ONVIF-METADATA-LIMIT-001";
const CUSTODY_ERROR: &str = "ERR-ONVIF-METADATA-CUSTODY-001";
const REPORT_LIMIT: usize = 2 * 1024 * 1024;
// Each bounded history step admits through both the replay and I/O authority;
// leave a fixed reserve for source reads, root publication and request retirement.
const STORAGE_CHECKPOINT_ALLOWANCE: u64 =
    4 * fss_reference::onvif::metadata::MAX_HISTORY_BATCHES as u64 + 4096;
const COMMITTED_GUIDANCE: &str = "durable_publication=true\nsafe_next=verify_exact_import\n";

enum Action {
    Import {
        input: PathBuf,
        binding: SourceBinding,
        interpretation: Interpretation,
        expected_source: Option<ContentDigest>,
    },
    Inspect {
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
        verify: bool,
    },
}
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    include_values: bool,
    approval: ContentDigest,
    action: Action,
}

fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, &'static str> {
    values
        .get(key)
        .and_then(|value| value.to_str())
        .ok_or(ARGUMENT_ERROR)
}
fn digest(value: &str) -> Result<ContentDigest, &'static str> {
    let digest = ContentDigest::parse(value).map_err(|_| ARGUMENT_ERROR)?;
    if digest.algorithm() != fss_core::DigestAlgorithm::Sha256 {
        return Err(ARGUMENT_ERROR);
    }
    Ok(digest)
}
fn optional_digest(
    values: &BTreeMap<String, OsString>,
    key: &str,
) -> Result<Option<ContentDigest>, &'static str> {
    values
        .get(key)
        .map(|value| value.to_str().ok_or(ARGUMENT_ERROR).and_then(digest))
        .transpose()
}
fn clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}
fn parse(args: &[OsString]) -> Result<Option<Options>, &'static str> {
    if args.is_empty() || args == [OsString::from("--help")] || args == [OsString::from("-h")] {
        return Ok(None);
    }
    if args.len() > 40
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        || args.len() % 2 != 1
    {
        return Err(ARGUMENT_ERROR);
    }
    let command = args[0].to_str().ok_or(ARGUMENT_ERROR)?;
    let importing = command == "import";
    if !matches!(command, "import" | "inspect" | "verify") {
        return Err(ARGUMENT_ERROR);
    }
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or(ARGUMENT_ERROR)?;
        let common = matches!(
            key,
            "--root" | "--site" | "--principal" | "--include-values"
        );
        let specific = if importing {
            matches!(
                key,
                "--input"
                    | "--sensor"
                    | "--device-generation"
                    | "--profile-generation"
                    | "--profile"
                    | "--received-start-ns"
                    | "--received-end-ns"
                    | "--source-sha256"
                    | "--interpretation"
            )
        } else {
            matches!(key, "--import-id" | "--expected-root")
        };
        if (!common && !specific) || values.insert(key.to_owned(), pair[1].clone()).is_some() {
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
        .map_or(Ok("operator:local-onvif-metadata"), |value| {
            value.to_str().ok_or(ARGUMENT_ERROR)
        })?
        .to_owned();
    if principal.is_empty() || principal.len() > 256 || principal.chars().any(char::is_control) {
        return Err(ARGUMENT_ERROR);
    }
    let include_values = match values.get("--include-values").map(OsString::as_os_str) {
        None => false,
        Some(value) if value == OsStr::new("no") => false,
        Some(value) if value == OsStr::new("yes") => true,
        _ => return Err(ARGUMENT_ERROR),
    };
    let action = if importing {
        let binding = SourceBinding {
            sensor_id: SensorId::parse(text(&values, "--sensor")?).map_err(|_| ARGUMENT_ERROR)?,
            device_generation: digest(text(&values, "--device-generation")?)?,
            profile_generation: digest(text(&values, "--profile-generation")?)?,
            profile_token: text(&values, "--profile")?.to_owned(),
            receive_interval: CaptureInterval::new(
                TimestampNs(
                    text(&values, "--received-start-ns")?
                        .parse()
                        .map_err(|_| ARGUMENT_ERROR)?,
                ),
                TimestampNs(
                    text(&values, "--received-end-ns")?
                        .parse()
                        .map_err(|_| ARGUMENT_ERROR)?,
                ),
            )
            .map_err(|_| ARGUMENT_ERROR)?,
        };
        binding.validate().map_err(|_| ARGUMENT_ERROR)?;
        let interpretation = match values.get("--interpretation").map(OsString::as_os_str) {
            None => Interpretation::AnalyticsV2,
            Some(value) if value == OsStr::new("analytics-v2") => Interpretation::AnalyticsV2,
            Some(value) if value == OsStr::new("events-v1") => Interpretation::EventsV1,
            _ => return Err(ARGUMENT_ERROR),
        };
        Action::Import {
            input: PathBuf::from(values.get("--input").ok_or(ARGUMENT_ERROR)?),
            binding,
            interpretation,
            expected_source: optional_digest(&values, "--source-sha256")?,
        }
    } else {
        Action::Inspect {
            identity: digest(text(&values, "--import-id")?)?,
            expected_root: optional_digest(&values, "--expected-root")?,
            verify: command == "verify",
        }
    };
    let mut e = CanonicalEncoder::new();
    e.text("fss.onvif_metadata_local_request.v1");
    for arg in args {
        e.bytes(arg.as_encoded_bytes());
    }
    let approval = ContentDigest::sha256(&e.finish_checked().map_err(|_| ARGUMENT_ERROR)?);
    Ok(Some(Options {
        root,
        site,
        principal,
        include_values,
        approval,
        action,
    }))
}

fn read_input(path: &Path, scope: &runtime::Scope<'_, '_>) -> Result<Vec<u8>, &'static str> {
    scope.input()?;
    let metadata = fs::symlink_metadata(path).map_err(|_| INPUT_ERROR)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_SOURCE_BYTES as u64 {
        return Err(INPUT_ERROR);
    }
    scope.input()?;
    let file = File::open(path).map_err(|_| INPUT_ERROR)?;
    scope.input()?;
    let opened = file.metadata().map_err(|_| INPUT_ERROR)?;
    if !opened.is_file() || opened.len() > MAX_SOURCE_BYTES as u64 {
        return Err(INPUT_ERROR);
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    scope.input()?;
    file.take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| INPUT_ERROR)?;
    scope.now()?;
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
        return Err(LIMIT_ERROR);
    }
    Ok(bytes)
}
fn run(options: Options) -> Result<CommandOutput, &'static str> {
    let request = runtime::Request {
        approval: options.approval,
        principal: options.principal.clone(),
        timeout_ns: 30_000_000_000,
        bytes: 4 * 1024 * 1024,
        network_bytes: 0,
        storage_operations: STORAGE_CHECKPOINT_ALLOWANCE,
        network: false,
        // Existing deployment opens take its owner lock and may finalize its own recovery.
        write: true,
        secrets: false,
    };
    let work = |scope: &runtime::Scope<'_, '_>| {
        let input = if let Action::Import {
            input,
            expected_source,
            interpretation,
            ..
        } = &options.action
        {
            let bytes = read_input(input, scope)?;
            if expected_source.is_some_and(|expected| expected != ContentDigest::sha256(&bytes)) {
                return Err(CUSTODY_ERROR);
            }
            // Fail malformed input before creating or opening any destination.
            interpretation
                .parse(&bytes)
                .map_err(|_| "ERR-ONVIF-METADATA-WIRE-001")?;
            Some(bytes)
        } else {
            None
        };
        scope.input()?;
        match fs::symlink_metadata(&options.root) {
            Ok(metadata) if !metadata.file_type().is_dir() => return Err(INPUT_ERROR),
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && matches!(&options.action, Action::Import { .. }) => {}
            Err(_) => return Err(INPUT_ERROR),
        }
        if matches!(&options.action, Action::Inspect { .. }) {
            scope.input()?;
            if !fs::symlink_metadata(options.root.join("LAYOUT"))
                .map_err(|_| INPUT_ERROR)?
                .file_type()
                .is_file()
            {
                return Err(INPUT_ERROR);
            }
        }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-metadata".into(),
            operation_id: OperationId::parse("operation:onvif-metadata")
                .map_err(|_| ARGUMENT_ERROR)?,
            principal: options.principal.clone(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(4 * 1024 * 1024)
                .storage_operations(STORAGE_CHECKPOINT_ALLOWANCE)
                .build()
                .map_err(|_| LIMIT_ERROR)?,
            privacy_scope: "privacy:owner-private-vendor-metadata".into(),
            retention_scope: "retention:explicit-metadata-import".into(),
            anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| ARGUMENT_ERROR)?;
        // This constructor performs no ambient filesystem work.
        let cx = ReplayCx::from_context_authority_read_only(&authority, options.root.clone())
            .map_err(|_| ARGUMENT_ERROR)?
            .with_admission(|_| admission::check(scope));
        let result = (|| {
            scope.output()?;
            let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)
                .map_err(|_| "ERR-ONVIF-METADATA-PUBLICATION-001")?;
            match &options.action {
                Action::Import {
                    binding,
                    interpretation,
                    ..
                } => {
                    scope.output()?;
                    let source = input.as_deref().ok_or(INPUT_ERROR)?;
                    retain_with_interpretation(
                        &mut deployment,
                        binding.clone(),
                        source,
                        *interpretation,
                        &cx,
                    )
                    .map_err(|error| error.code())
                }
                Action::Inspect {
                    identity,
                    expected_root,
                    ..
                } => {
                    scope.input()?;
                    RetainedMetadata::open(&deployment, *identity, *expected_root, &cx)
                        .map_err(|error| error.code())
                }
            }
        })();
        let owner_error = cx.admission_refusal().map(admission::code);
        cx.drain_and_finalize();
        match result {
            Ok(retained) => Ok((retained, owner_error)),
            Err(error) => Err(owner_error.unwrap_or(error)),
        }
    };
    if matches!(&options.action, Action::Import { .. }) {
        let completed = runtime::run_committing(request, |scope| {
            // Only the durable library receipt can cross this success boundary.
            // Rendering is pure and happens after runtime drain, with a minimal
            // custody receipt fallback if optional detail exceeds its bound.
            work(scope).map(runtime::Committed::new)
        })?;
        let (retained, owner_error) = completed.value;
        let post_commit_error = owner_error.or(completed.post_commit_error);
        let mut custody_receipt = custody_header(&retained);
        custody_receipt.push_str(COMMITTED_GUIDANCE);
        Ok(CommandOutput {
            report: committed_report(
                &retained,
                options.include_values,
                post_commit_error,
                completed.finalization_error,
            ),
            custody_receipt: Some(custody_receipt),
        })
    } else {
        let (retained, owner_error) = runtime::run(request, work)?;
        if let Some(error) = owner_error {
            return Err(error);
        }
        let operation = match options.action {
            Action::Inspect { verify: true, .. } => "verify",
            _ => "inspect",
        };
        report(&retained, operation, options.include_values).map(|report| CommandOutput {
            report,
            custody_receipt: None,
        })
    }
}

fn custody_header(retained: &RetainedMetadata) -> String {
    format!(
        "operation=import\nimport_identity={}\npublication_root={}\nsource_sha256={}\n",
        retained.identity(),
        retained.publication_root(),
        retained.source_digest()
    )
}

fn committed_report(
    retained: &RetainedMetadata,
    include_values: bool,
    post_commit_error: Option<&'static str>,
    finalization_error: Option<&'static str>,
) -> String {
    let minimal = || format!("{}values_disclosed=false\n", custody_header(retained));
    // A durable acknowledgment survives revocation; optional private values do not.
    let mut out = if post_commit_error.is_some() || finalization_error.is_some() {
        minimal()
    } else {
        report(retained, "import", include_values).unwrap_or_else(|error| {
            // A presentation failure must not erase the already committed root.
            format!("{}report_error={error}\n", minimal())
        })
    };
    out.push_str(COMMITTED_GUIDANCE);
    if let Some(error) = post_commit_error {
        out.push_str(&format!("post_commit_error={error}\n"));
    }
    if let Some(error) = finalization_error {
        out.push_str(&format!("finalization_error={error}\n"));
    }
    out
}

fn report(
    retained: &RetainedMetadata,
    operation: &str,
    include_values: bool,
) -> Result<String, &'static str> {
    let mut out = String::new();
    let binding = retained.binding();
    let document = retained.document();
    macro_rules! line {
        ($($arg:tt)*) => { writeln!(&mut out, $($arg)*).map_err(|_| LIMIT_ERROR)? };
    }
    line!("operation={operation}");
    line!("import_identity={}", retained.identity());
    line!("publication_root={}", retained.publication_root());
    line!("source_sha256={}", retained.source_digest());
    line!("source_bytes={}", retained.source_bytes());
    line!("projection_sha256={}", retained.projection_digest());
    line!(
        "authority_sequence={}",
        retained.authority_anchor().commit_sequence
    );
    line!("parser_generation={}", retained.parser_generation());
    line!(
        "projection_schema={}",
        retained.interpretation().projection_domain()
    );
    line!("plane={}", retained.plane().as_str());
    line!("provenance={}", retained.provenance().as_str());
    line!("source_mode={}", retained.source_mode());
    if let Some(acquisition) = retained.pullpoint_acquisition() {
        line!("capture_approval={}", acquisition.approval);
        line!("event_route_sha256={}", acquisition.event_route);
        line!(
            "subscription_route_sha256={}",
            acquisition.subscription_route
        );
        line!(
            "subscription_source_sha256={}",
            acquisition.subscription_source
        );
        line!(
            "subscription_source_bytes={}",
            acquisition.subscription_source_bytes
        );
        line!("pull_index={}", acquisition.pull_index);
        line!(
            "client_digest_authenticated={}",
            acquisition.client_authenticated
        );
        line!("request_message_id={}", acquisition.message_id);
        line!(
            "subscription_message_id={}",
            acquisition.subscription_message_id
        );
        line!(
            "subscription_started_ns={}",
            acquisition.subscription_started_ns
        );
        line!(
            "subscription_completed_ns={}",
            acquisition.subscription_completed_ns
        );
        line!("pull_started_ns={}", acquisition.started_ns);
        line!("pull_completed_ns={}", acquisition.completed_ns);
        line!("subscription_scope=device_events");
        line!("profile_attribution_verified=false");
        line!("server_identity_verified=false");
        line!("transport_encrypted=false");
    }
    line!("camera_authenticated=false");
    line!("vendor_clock_trusted=false");
    line!("coverage_claimed=false");
    line!("absence_claimed=false");
    line!("effects_authorized=false");
    line!("sensitive_features_enabled=false");
    line!("coordinates_calibrated=false");
    line!("classes_calibrated=false");
    line!("identity_claimed=false");
    line!("values_disclosed={include_values}");
    line!("sensor={:?}", binding.sensor_id.as_str());
    line!("device_generation={}", binding.device_generation);
    line!("profile_generation={}", binding.profile_generation);
    line!("profile_token={:?}", binding.profile_token);
    line!("received_start_ns={}", binding.receive_interval.earliest.0);
    line!("received_end_ns={}", binding.receive_interval.latest.0);
    line!(
        "format={}",
        match document.format {
            EventDocumentFormat::PullMessages => "pull_messages",
            EventDocumentFormat::MetadataStream => "metadata_stream",
        }
    );
    line!("notification_count={}", document.notifications.len());
    line!("unsupported_sections={}", document.unsupported_sections);
    line!(
        "has_unsupported_content={}",
        document.has_unsupported_content()
    );
    line!("analytics_frame_count={}", document.analytics_frames.len());
    line!(
        "analytics_object_count={}",
        document
            .analytics_frames
            .iter()
            .map(|frame| frame.objects.len())
            .sum::<usize>()
    );
    if let Some(time) = &document.current_time {
        line!("vendor_current_time={time:?}");
    }
    if let Some(time) = &document.termination_time {
        line!("vendor_termination_time={time:?}");
    }
    for (index, notification) in document.notifications.iter().enumerate() {
        line!(
            "notification.{index}.digest={}",
            retained
                .notification_digest(index)
                .map_err(|error| error.code())?
        );
        line!(
            "notification.{index}.topic_namespace={:?}",
            notification.topic.namespace
        );
        line!(
            "notification.{index}.topic_path={:?}",
            notification.topic.path.join("/")
        );
        line!(
            "notification.{index}.vendor_utc_time={:?}",
            notification.utc_time
        );
        line!(
            "notification.{index}.property_operation={}",
            match notification.property_operation {
                None => "not_supplied",
                Some(PropertyOperation::Initialized) => "Initialized",
                Some(PropertyOperation::Changed) => "Changed",
                Some(PropertyOperation::Deleted) => "Deleted",
            }
        );
        line!(
            "notification.{index}.unsupported_extensions={}",
            notification.unsupported_extensions
        );
        for (kind, items) in [
            ("source", notification.source.as_ref()),
            ("key", notification.key.as_ref()),
            ("data", notification.data.as_ref()),
        ] {
            report_items(&mut out, index, kind, items, include_values)?;
        }
        if out.len() > REPORT_LIMIT {
            return Err(LIMIT_ERROR);
        }
    }
    for (index, frame) in document.analytics_frames.iter().enumerate() {
        line!(
            "analytics.{index}.digest={}",
            retained
                .analytics_frame_digest(index)
                .map_err(|error| error.code())?
        );
        report_analytics(&mut out, index, frame, include_values)?;
        if out.len() > REPORT_LIMIT {
            return Err(LIMIT_ERROR);
        }
    }
    if out.len() > REPORT_LIMIT {
        return Err(LIMIT_ERROR);
    }
    Ok(out)
}
fn report_claim(
    out: &mut String,
    key: &str,
    value: &str,
    include_values: bool,
) -> Result<(), &'static str> {
    if include_values {
        // Preserve lexical numbers and escape all vendor-controlled strings.
        writeln!(out, "{key}={value:?}").map_err(|_| LIMIT_ERROR)
    } else {
        writeln!(out, "{key}=withheld").map_err(|_| LIMIT_ERROR)
    }
}

fn report_vector(
    out: &mut String,
    key: &str,
    value: Option<&AnalyticsVector>,
    include_values: bool,
) -> Result<(), &'static str> {
    writeln!(out, "{key}.present={}", value.is_some()).map_err(|_| LIMIT_ERROR)?;
    if let Some(value) = value {
        report_claim(out, &format!("{key}.x"), value.x.as_str(), include_values)?;
        report_claim(out, &format!("{key}.y"), value.y.as_str(), include_values)?;
        writeln!(
            out,
            "{key}.unsupported_extensions={}",
            value.unsupported_extensions
        )
        .map_err(|_| LIMIT_ERROR)?;
    }
    Ok(())
}

fn report_transformation(
    out: &mut String,
    key: &str,
    value: Option<&AnalyticsTransformation>,
    include_values: bool,
) -> Result<(), &'static str> {
    writeln!(out, "{key}.present={}", value.is_some()).map_err(|_| LIMIT_ERROR)?;
    if let Some(value) = value {
        report_vector(
            out,
            &format!("{key}.translate"),
            value.translate.as_ref(),
            include_values,
        )?;
        report_vector(
            out,
            &format!("{key}.scale"),
            value.scale.as_ref(),
            include_values,
        )?;
        writeln!(
            out,
            "{key}.unsupported_extensions={}",
            value.unsupported_extensions
        )
        .map_err(|_| LIMIT_ERROR)?;
    }
    Ok(())
}

fn report_analytics(
    out: &mut String,
    index: usize,
    frame: &AnalyticsFrame,
    include_values: bool,
) -> Result<(), &'static str> {
    macro_rules! line {
        ($($arg:tt)*) => { writeln!(out, $($arg)*).map_err(|_| LIMIT_ERROR)? };
    }
    let key = format!("analytics.{index}");
    line!("{key}.vendor_utc_time={:?}", frame.utc_time);
    line!("{key}.source.present={}", frame.source.is_some());
    if let Some(source) = &frame.source {
        report_claim(out, &format!("{key}.source.value"), source, include_values)?;
    }
    report_transformation(
        out,
        &format!("{key}.transformation"),
        frame.transformation.as_ref(),
        include_values,
    )?;
    line!("{key}.object_count={}", frame.objects.len());
    line!(
        "{key}.unsupported_extensions={}",
        frame.unsupported_extensions
    );
    for (object_index, object) in frame.objects.iter().enumerate() {
        let key = format!("{key}.object.{object_index}");
        report_claim(
            out,
            &format!("{key}.object_id"),
            &object.object_id,
            include_values,
        )?;
        line!(
            "{key}.unsupported_extensions={}",
            object.unsupported_extensions
        );
        line!("{key}.appearance.present={}", object.appearance.is_some());
        let Some(appearance) = &object.appearance else {
            continue;
        };
        report_transformation(
            out,
            &format!("{key}.appearance.transformation"),
            appearance.transformation.as_ref(),
            include_values,
        )?;
        line!(
            "{key}.appearance.unsupported_extensions={}",
            appearance.unsupported_extensions
        );
        line!("{key}.shape.present={}", appearance.shape.is_some());
        if let Some(shape) = &appearance.shape {
            let bounds = &shape.bounding_box;
            for (name, value) in [
                ("left", &bounds.left),
                ("top", &bounds.top),
                ("right", &bounds.right),
                ("bottom", &bounds.bottom),
            ] {
                report_claim(
                    out,
                    &format!("{key}.shape.bounding_box.{name}"),
                    value.as_str(),
                    include_values,
                )?;
            }
            line!(
                "{key}.shape.bounding_box.unsupported_extensions={}",
                bounds.unsupported_extensions
            );
            report_vector(
                out,
                &format!("{key}.shape.center_of_gravity"),
                Some(&shape.center_of_gravity),
                include_values,
            )?;
            line!(
                "{key}.shape.unsupported_extensions={}",
                shape.unsupported_extensions
            );
        }
        line!("{key}.class.present={}", appearance.class.is_some());
        if let Some(class) = &appearance.class {
            line!("{key}.class.candidate_count={}", class.candidates.len());
            line!(
                "{key}.class.unsupported_extensions={}",
                class.unsupported_extensions
            );
            for (candidate_index, candidate) in class.candidates.iter().enumerate() {
                let key = format!("{key}.class.{candidate_index}");
                line!(
                    "{key}.format={}",
                    match candidate.format {
                        AnalyticsClassFormat::LegacyCandidate => "legacy_candidate",
                        AnalyticsClassFormat::Type => "type",
                    }
                );
                report_claim(
                    out,
                    &format!("{key}.label"),
                    &candidate.label,
                    include_values,
                )?;
                line!(
                    "{key}.likelihood.present={}",
                    candidate.likelihood.is_some()
                );
                if let Some(likelihood) = &candidate.likelihood {
                    report_claim(
                        out,
                        &format!("{key}.likelihood.value"),
                        likelihood.as_str(),
                        include_values,
                    )?;
                }
                line!(
                    "{key}.unsupported_extensions={}",
                    candidate.unsupported_extensions
                );
            }
        }
        if out.len() > REPORT_LIMIT {
            return Err(LIMIT_ERROR);
        }
    }
    Ok(())
}

fn report_items(
    out: &mut String,
    index: usize,
    kind: &str,
    items: Option<&EventItems>,
    include_values: bool,
) -> Result<(), &'static str> {
    macro_rules! line {
        ($($arg:tt)*) => { writeln!(out, $($arg)*).map_err(|_| LIMIT_ERROR)? };
    }
    line!("notification.{index}.{kind}.present={}", items.is_some());
    if let Some(items) = items {
        line!(
            "notification.{index}.{kind}.simple_count={}",
            items.simple_items.len()
        );
        line!(
            "notification.{index}.{kind}.element_count={}",
            items.element_items.len()
        );
        line!(
            "notification.{index}.{kind}.unsupported_extensions={}",
            items.unsupported_extensions
        );
        for (item_index, item) in items.simple_items.iter().enumerate() {
            line!(
                "notification.{index}.{kind}.{item_index}.name={:?}",
                item.name
            );
            if include_values {
                // Rust string escaping prevents vendor-controlled terminal control sequences.
                line!(
                    "notification.{index}.{kind}.{item_index}.value={:?}",
                    item.value
                );
            } else {
                line!("notification.{index}.{kind}.{item_index}.value=withheld");
            }
        }
        for (item_index, name) in items.element_items.iter().enumerate() {
            line!("notification.{index}.{kind}.opaque.{item_index}.name={name:?}");
        }
    }
    Ok(())
}
// Keep durable acknowledgments separate from optional rendered vendor values.
// Live capture also carries a bounded progress receipt, including incomplete states;
// only its explicitly listed batch roots claim durable publication.
struct CommandOutput {
    report: String,
    custody_receipt: Option<String>,
}

fn write_output(
    output: &CommandOutput,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
) -> ExitCode {
    if stdout
        .write_all(output.report.as_bytes())
        .and_then(|()| stdout.flush())
        .is_ok()
    {
        return ExitCode::SUCCESS;
    }
    let _ = stderr.write_all(b"ERR-ONVIF-METADATA-OUTPUT-001\n");
    if let Some(receipt) = &output.custody_receipt {
        // This independent, bounded receipt contains hashes and progress/retry
        // guidance, never optional vendor values, even after a partial write.
        let _ = stderr.write_all(receipt.as_bytes());
    }
    let _ = stderr.flush();
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(81).collect();
    let result = if args.first().is_some_and(|arg| arg == "capture") {
        capture::run_args(&args[1..]).map(|(report, complete)| {
            let output = CommandOutput {
                custody_receipt: Some(report.clone()),
                report,
            };
            (output, complete)
        })
    } else if args.first().is_some_and(|arg| arg == "control") {
        control::run_args(&args[1..]).map(|(report, complete)| {
            let output = CommandOutput {
                custody_receipt: args
                    .get(1)
                    .filter(|arg| *arg == "unsubscribe")
                    .map(|_| report.clone()),
                report,
            };
            (output, complete)
        })
    } else if args.first().is_some_and(|arg| {
        matches!(
            arg.to_str(),
            Some("import-rtp" | "inspect-rtp" | "verify-rtp")
        )
    }) {
        rtp::run_args(&args)
    } else {
        match parse(&args) {
            Ok(None) => Ok((
                CommandOutput {
                    report: HELP.to_owned(),
                    custody_receipt: None,
                },
                true,
            )),
            Ok(Some(options)) => run(options).map(|output| (output, true)),
            Err(error) => Err(error),
        }
    };
    match result {
        Ok((output, complete)) => {
            let status = write_output(
                &output,
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            if complete { status } else { ExitCode::from(1) }
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(if error == ARGUMENT_ERROR { 2 } else { 1 })
        }
    }
}

#[cfg(test)]
mod output_tests {
    use super::{CommandOutput, write_output};
    use std::io::{self, Write};
    use std::process::ExitCode;

    struct FailingWriter {
        accepted: Vec<u8>,
        remaining: usize,
        fail_flush: bool,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"));
            }
            let count = bytes.len().min(self.remaining);
            self.accepted.extend_from_slice(&bytes[..count]);
            self.remaining -= count;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("flush failed"))
            } else {
                Ok(())
            }
        }
    }

    fn imported_output() -> CommandOutput {
        CommandOutput {
            report: "operation=import\nprivate-vendor-canary=secret\n".into(),
            custody_receipt: Some(format!(
                "operation=import\nimport_identity=sha256:{}\npublication_root=sha256:{}\nsource_sha256=sha256:{}\ndurable_publication=true\nsafe_next=verify_exact_import\n",
                "11".repeat(32),
                "22".repeat(32),
                "33".repeat(32),
            )),
        }
    }

    #[test]
    fn failed_import_output_recovers_only_custody_receipt_on_stderr() {
        let output = imported_output();
        for remaining in [0, 5] {
            let mut stdout = FailingWriter {
                accepted: Vec::new(),
                remaining,
                fail_flush: false,
            };
            let mut stderr = Vec::new();
            assert_eq!(
                write_output(&output, &mut stdout, &mut stderr),
                ExitCode::from(1)
            );
            let receipt = output.custody_receipt.as_deref().unwrap_or("");
            assert_eq!(
                stderr,
                format!("ERR-ONVIF-METADATA-OUTPUT-001\n{receipt}").as_bytes()
            );
            assert!(!String::from_utf8_lossy(&stderr).contains("private-vendor-canary"));
            assert_eq!(stdout.accepted, output.report.as_bytes()[..remaining]);
        }
    }

    #[test]
    fn failed_flush_also_preserves_import_receipt_and_failure_exit() {
        let output = imported_output();
        let mut stdout = FailingWriter {
            accepted: Vec::new(),
            remaining: usize::MAX,
            fail_flush: true,
        };
        let mut stderr = Vec::new();
        assert_eq!(
            write_output(&output, &mut stdout, &mut stderr),
            ExitCode::from(1)
        );
        assert_eq!(stdout.accepted, output.report.as_bytes());
        let receipt = output.custody_receipt.as_deref().unwrap_or("");
        assert_eq!(
            stderr,
            format!("ERR-ONVIF-METADATA-OUTPUT-001\n{receipt}").as_bytes()
        );
    }

    #[test]
    fn ordinary_output_failure_does_not_infer_a_receipt_from_report_text() {
        let output = CommandOutput {
            report: "operation=inspect\nimport_identity=sha256:not-a-receipt\n".into(),
            custody_receipt: None,
        };
        let mut stdout = FailingWriter {
            accepted: Vec::new(),
            remaining: 0,
            fail_flush: false,
        };
        let mut stderr = Vec::new();
        assert_eq!(
            write_output(&output, &mut stdout, &mut stderr),
            ExitCode::from(1)
        );
        assert_eq!(stderr, b"ERR-ONVIF-METADATA-OUTPUT-001\n");
    }

    #[test]
    fn successful_output_does_not_duplicate_receipt_on_stderr() {
        let output = imported_output();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_output(&output, &mut stdout, &mut stderr),
            ExitCode::SUCCESS
        );
        assert_eq!(stdout, output.report.as_bytes());
        assert!(stderr.is_empty());
    }

    #[test]
    fn unavailable_stderr_still_returns_failure_without_panicking() {
        let output = imported_output();
        let mut stdout = FailingWriter {
            accepted: Vec::new(),
            remaining: 0,
            fail_flush: false,
        };
        let mut stderr = FailingWriter {
            accepted: Vec::new(),
            remaining: 0,
            fail_flush: false,
        };
        assert_eq!(
            write_output(&output, &mut stdout, &mut stderr),
            ExitCode::from(1)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_reference::onvif::metadata::retain;

    type Test = Result<(), Box<dyn std::error::Error>>;

    struct Directory(PathBuf);
    impl Directory {
        fn new(label: &str) -> Result<Self, std::io::Error> {
            for attempt in 0..64 {
                let path = std::env::temp_dir().join(format!(
                    "fss-onvif-metadata-cli-{label}-{}-{attempt}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
            Err(std::io::Error::other(
                "fixture directory attempts exhausted",
            ))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn args(root: &Path, input: &Path) -> Vec<OsString> {
        vec![
            "import".into(),
            "--root".into(),
            root.into(),
            "--site".into(),
            "site:metadata-cli-test".into(),
            "--input".into(),
            input.into(),
            "--sensor".into(),
            "sensor:front".into(),
            "--device-generation".into(),
            ContentDigest::sha256(b"device").to_text().into(),
            "--profile-generation".into(),
            ContentDigest::sha256(b"profile").to_text().into(),
            "--profile".into(),
            "main".into(),
            "--received-start-ns".into(),
            "100".into(),
            "--received-end-ns".into(),
            "110".into(),
        ]
    }

    fn field<'a>(report: &'a str, name: &str) -> Result<&'a str, &'static str> {
        report
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or("missing report field")
    }

    fn analytics_source() -> &'static str {
        r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics><t:Frame UtcTime="2026-10-27T12:34:56Z" Source="private-module-canary"><t:Transformation><t:Translate x="-0.37591" y="0.75"/><t:Scale x="0.25" y="-0.5"/></t:Transformation><t:Object ObjectId="732103"><t:Appearance><t:Shape><t:BoundingBox left="-0.12591" top="0.87391" right="0.5" bottom="-0.2"/><t:CenterOfGravity x="0.1" y="0.2"/></t:Shape><t:Class><t:Type Likelihood="0.75">private&quot;class\canary</t:Type><t:Type>Unknown</t:Type></t:Class><t:Face><t:Identity>opaque-biometric-canary</t:Identity></t:Face></t:Appearance></t:Object></t:Frame></t:VideoAnalytics></t:MetadataStream>"#
    }

    #[test]
    fn analytics_disclosure_is_explicit_escaped_and_retains_uncertainty() -> Test {
        let directory = Directory::new("analytics")?;
        let input = directory.0.join("source.xml");
        let root = directory.0.join("deployment");
        fs::write(&input, analytics_source())?;
        let mut import_args = args(&root, &input);
        let hidden = run(parse(&import_args)?.ok_or("options")?)?.report;
        assert_eq!(
            field(&hidden, "parser_generation=")?,
            Interpretation::AnalyticsV2.parser_generation()
        );
        assert_eq!(field(&hidden, "analytics_frame_count=")?, "1");
        assert_eq!(field(&hidden, "analytics_object_count=")?, "1");
        assert_eq!(
            field(&hidden, "analytics.0.object.0.object_id=")?,
            "withheld"
        );
        assert_eq!(
            field(&hidden, "analytics.0.object.0.class.1.likelihood.present=")?,
            "false"
        );
        assert!(!hidden.contains("private-module-canary"));
        assert!(!hidden.contains("-0.37591"));
        assert!(!hidden.contains("-0.12591"));
        assert!(!hidden.contains("private\\\"class"));
        assert_eq!(field(&hidden, "has_unsupported_content=")?, "true");
        import_args.extend(["--include-values".into(), "yes".into()]);
        let disclosed = run(parse(&import_args)?.ok_or("disclosure options")?)?.report;
        assert_eq!(
            field(&disclosed, "import_identity=")?,
            field(&hidden, "import_identity=")?
        );
        assert_eq!(
            field(&disclosed, "authority_sequence=")?,
            field(&hidden, "authority_sequence=")?
        );
        assert_eq!(
            field(&disclosed, "analytics.0.object.0.object_id=")?,
            "\"732103\""
        );
        assert!(disclosed.contains(&format!("label={:?}", "private\"class\\canary")));
        assert!(disclosed.contains("source.value=\"private-module-canary\""));
        assert!(!disclosed.contains("opaque-biometric-canary"));
        for flag in [
            "coordinates_calibrated",
            "classes_calibrated",
            "identity_claimed",
            "camera_authenticated",
            "coverage_claimed",
            "absence_claimed",
            "effects_authorized",
            "sensitive_features_enabled",
        ] {
            assert_eq!(field(&disclosed, &format!("{flag}="))?, "false");
        }
        Ok(())
    }

    #[test]
    fn legacy_import_and_cold_verify_use_the_retained_parser_generation() -> Test {
        let directory = Directory::new("legacy")?;
        let input = directory.0.join("source.xml");
        let root = directory.0.join("deployment");
        fs::write(
            &input,
            analytics_source().replace("2026-10-27T12:34:56Z", "opaque-old-time"),
        )?;
        let mut import_args = args(&root, &input);
        assert_eq!(
            run(parse(&import_args)?.ok_or("options")?).err(),
            Some("ERR-ONVIF-METADATA-WIRE-001")
        );
        assert!(!root.exists());
        import_args.extend(["--interpretation".into(), "events-v1".into()]);
        let imported = run(parse(&import_args)?.ok_or("legacy options")?)?.report;
        assert_eq!(field(&imported, "analytics_frame_count=")?, "0");
        assert_eq!(field(&imported, "unsupported_sections=")?, "1");
        assert_eq!(
            field(&imported, "parser_generation=")?,
            Interpretation::EventsV1.parser_generation()
        );
        fs::remove_file(&input)?;
        let verify = vec![
            "verify".into(),
            "--root".into(),
            root.into(),
            "--site".into(),
            "site:metadata-cli-test".into(),
            "--import-id".into(),
            field(&imported, "import_identity=")?.into(),
        ];
        let verified = run(parse(&verify)?.ok_or("verify options")?)?.report;
        assert_eq!(
            field(&verified, "parser_generation=")?,
            Interpretation::EventsV1.parser_generation()
        );
        assert_eq!(
            field(&verified, "projection_sha256=")?,
            field(&imported, "projection_sha256=")?
        );
        Ok(())
    }

    #[test]
    fn interpretation_selection_is_strict_and_disallowed_for_cold_reads() -> Test {
        let directory = Directory::new("args")?;
        let mut import_args = args(
            &directory.0.join("deployment"),
            &directory.0.join("source.xml"),
        );
        import_args.extend(["--interpretation".into(), "auto".into()]);
        assert!(parse(&import_args).is_err());
        let inspect_args = vec![
            "inspect".into(),
            "--root".into(),
            directory.0.clone().into(),
            "--site".into(),
            "site:metadata-cli-test".into(),
            "--import-id".into(),
            ContentDigest::sha256(b"fake").to_text().into(),
            "--interpretation".into(),
            "events-v1".into(),
        ];
        assert!(parse(&inspect_args).is_err());
        Ok(())
    }

    #[test]
    fn native_command_round_trip_reopens_without_input() -> Test {
        let directory = Directory::new("roundtrip")?;
        let input = directory.0.join("source.xml");
        let root = directory.0.join("deployment");
        fs::write(&input, br#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:Event/></t:MetadataStream>"#)?;
        let imported = run(parse(&args(&root, &input))?.ok_or("options")?)?.report;
        assert!(imported.contains("durable_publication=true\n"));
        assert!(imported.contains("coverage_claimed=false\n"));
        let identity = field(&imported, "import_identity=")?.to_owned();
        let publication_root = field(&imported, "publication_root=")?.to_owned();
        fs::remove_file(&input)?;
        let verify = vec![
            "verify".into(),
            "--root".into(),
            root.into(),
            "--site".into(),
            "site:metadata-cli-test".into(),
            "--import-id".into(),
            identity.clone().into(),
            "--expected-root".into(),
            publication_root.clone().into(),
        ];
        let verified = run(parse(&verify)?.ok_or("verify options")?)?.report;
        assert_eq!(field(&verified, "import_identity=")?, identity);
        assert_eq!(field(&verified, "publication_root=")?, publication_root);
        assert_eq!(field(&verified, "operation=")?, "verify");
        Ok(())
    }

    #[test]
    fn malformed_source_refuses_before_creating_destination() -> Test {
        let directory = Directory::new("malformed")?;
        let input = directory.0.join("source.xml");
        let root = directory.0.join("deployment");
        fs::write(&input, b"<!DOCTYPE x><x/>")?;
        assert_eq!(
            run(parse(&args(&root, &input))?.ok_or("options")?).err(),
            Some("ERR-ONVIF-METADATA-WIRE-001")
        );
        assert!(!root.exists());
        Ok(())
    }

    #[test]
    fn committed_acknowledgment_keeps_handles_but_withholds_private_values_after_revocation() -> Test
    {
        let directory = Directory::new("receipt")?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:metadata-cli-test".into(),
            operation_id: OperationId::parse("operation:metadata-cli-test")?,
            principal: "operator:metadata-cli-test".into(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(4 * 1024 * 1024)
                .storage_operations(256)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"test"),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, directory.0.clone())?;
        let mut deployment =
            ReferenceDeployment::open(&directory.0, "site:metadata-cli-test", &cx)?;
        let binding = SourceBinding {
            sensor_id: SensorId::parse("sensor:front")?,
            device_generation: ContentDigest::sha256(b"device"),
            profile_generation: ContentDigest::sha256(b"profile"),
            profile_token: "private-profile-canary".into(),
            receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
        };
        let retained = retain(&mut deployment, binding,
            br#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:Event/></t:MetadataStream>"#, &cx)?;
        cx.drain_and_finalize();
        let output = committed_report(
            &retained,
            true,
            Some("ERR-CANCELLED-TEST"),
            Some("ERR-DRAIN-TEST"),
        );
        assert!(output.contains(&format!("import_identity={}\n", retained.identity())));
        assert!(output.contains(&format!(
            "publication_root={}\n",
            retained.publication_root()
        )));
        assert!(output.contains("durable_publication=true\n"));
        assert!(output.contains("values_disclosed=false\n"));
        assert!(output.contains("post_commit_error=ERR-CANCELLED-TEST\n"));
        assert!(output.contains("finalization_error=ERR-DRAIN-TEST\n"));
        assert!(!output.contains("private-profile-canary"));
        assert!(!output.contains("notification_count="));
        Ok(())
    }
}
