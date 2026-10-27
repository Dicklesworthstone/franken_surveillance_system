#![forbid(unsafe_code)]
//! Local, source-retained ONVIF vendor-event imports and independent cold verification.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{Read, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use fss_core::{
    BudgetVector, CanonicalEncoder, CaptureInterval, ContentDigest, ContextAuthority, OperationId,
    RootAuthoritySpec, SensorId, TimestampNs,
};
use fss_reference::onvif::metadata::{
    MAX_SOURCE_BYTES, PARSER_GENERATION, RetainedMetadata, SourceBinding, retain,
};
use fss_reference::onvif::wire::{
    EventDocumentFormat, EventItems, PropertyOperation, parse_event_document,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

#[path = "fss-onvif/runtime.rs"]
mod runtime;

const HELP: &str = "fss-onvif-metadata <import|inspect|verify> [options]
  All commands: --root ABSOLUTE_DIR --site SITE [--principal ID]
                [--include-values yes|no]
  import: --input FILE --sensor ID --device-generation sha256:HEX
          --profile-generation sha256:HEX --profile TOKEN
          --received-start-ns N --received-end-ns N
          [--source-sha256 sha256:HEX]
  inspect/verify: --import-id sha256:HEX [--expected-root sha256:HEX]

Imports one complete ONVIF PullMessages SOAP response or MetadataStream XML document.
The source file is bounded to 256 KiB and retained exactly with immutable owner pins.
Receive times use the operator's declared clock; camera UtcTime remains an unverified claim.
inspect and verify both reopen, hash and reparse only retained bytes, without the input file.
SimpleItem values are withheld by default. --include-values yes explicitly reveals private
vendor values to this local command's stdout; it enables no sensitive analysis or effects.
Notification order, duplicates, initialization and deletion operations are preserved.
No live subscription, camera authentication, coverage, physical absence or control is claimed.
";

const ARGUMENT_ERROR: &str = "ERR-ONVIF-METADATA-ARGUMENT-001";
const INPUT_ERROR: &str = "ERR-ONVIF-METADATA-INPUT-001";
const LIMIT_ERROR: &str = "ERR-ONVIF-METADATA-LIMIT-001";
const CUSTODY_ERROR: &str = "ERR-ONVIF-METADATA-CUSTODY-001";
const REPORT_LIMIT: usize = 2 * 1024 * 1024;

enum Action {
    Import {
        input: PathBuf,
        binding: SourceBinding,
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
        Action::Import {
            input: PathBuf::from(values.get("--input").ok_or(ARGUMENT_ERROR)?),
            binding,
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
fn run(options: Options) -> Result<String, &'static str> {
    let request = runtime::Request {
        approval: options.approval,
        principal: options.principal.clone(),
        timeout_ns: 30_000_000_000,
        bytes: 4 * 1024 * 1024,
        network_bytes: 0,
        storage_operations: 256,
        network: false,
        // Existing deployment opens take its owner lock and may finalize its own recovery.
        write: true,
        secrets: false,
    };
    let work = |scope: &runtime::Scope<'_, '_>| {
        let input = if let Action::Import {
            input,
            expected_source,
            ..
        } = &options.action
        {
            let bytes = read_input(input, scope)?;
            if expected_source.is_some_and(|expected| expected != ContentDigest::sha256(&bytes)) {
                return Err(CUSTODY_ERROR);
            }
            // Fail malformed input before creating or opening any destination.
            parse_event_document(&bytes).map_err(|_| "ERR-ONVIF-METADATA-WIRE-001")?;
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
                .storage_operations(256)
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
            .map_err(|_| ARGUMENT_ERROR)?;
        let result = (|| {
            scope.output()?;
            let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)
                .map_err(|_| "ERR-ONVIF-METADATA-PUBLICATION-001")?;
            match &options.action {
                Action::Import { binding, .. } => {
                    scope.output()?;
                    let source = input.as_deref().ok_or(INPUT_ERROR)?;
                    retain(&mut deployment, binding.clone(), source, &cx)
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
        cx.drain_and_finalize();
        result
    };
    if matches!(&options.action, Action::Import { .. }) {
        let completed = runtime::run_committing(request, |scope| {
            // Only the durable library receipt can cross this success boundary.
            // Rendering is pure and happens after runtime drain, with a minimal
            // custody receipt fallback if optional detail exceeds its bound.
            work(scope).map(runtime::Committed::new)
        })?;
        Ok(committed_report(
            &completed.value,
            options.include_values,
            completed.post_commit_error,
            completed.finalization_error,
        ))
    } else {
        let retained = runtime::run(request, work)?;
        let operation = match options.action {
            Action::Inspect { verify: true, .. } => "verify",
            _ => "inspect",
        };
        report(&retained, operation, options.include_values)
    }
}

fn committed_report(
    retained: &RetainedMetadata,
    include_values: bool,
    post_commit_error: Option<&'static str>,
    finalization_error: Option<&'static str>,
) -> String {
    let minimal = || {
        format!(
            "operation=import\nimport_identity={}\npublication_root={}\nsource_sha256={}\nvalues_disclosed=false\n",
            retained.identity(),
            retained.publication_root(),
            retained.source_digest()
        )
    };
    // A durable acknowledgment survives revocation; optional private values do not.
    let mut out = if post_commit_error.is_some() || finalization_error.is_some() {
        minimal()
    } else {
        report(retained, "import", include_values).unwrap_or_else(|error| {
            // A presentation failure must not erase the already committed root.
            format!("{}report_error={error}\n", minimal())
        })
    };
    out.push_str("durable_publication=true\nsafe_next=verify_exact_import\n");
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
    line!("parser_generation={PARSER_GENERATION}");
    line!("plane={}", retained.plane().as_str());
    line!("provenance={}", retained.provenance().as_str());
    line!("source_mode=owner_supplied_file");
    line!("camera_authenticated=false");
    line!("vendor_clock_trusted=false");
    line!("coverage_claimed=false");
    line!("absence_claimed=false");
    line!("effects_authorized=false");
    line!("sensitive_features_enabled=false");
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
    if out.len() > REPORT_LIMIT {
        return Err(LIMIT_ERROR);
    }
    Ok(out)
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
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(41).collect();
    let result = match parse(&args) {
        Ok(None) => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Ok(Some(options)) => run(options),
        Err(error) => Err(error),
    };
    match result {
        Ok(report) => match std::io::stdout().lock().write_all(report.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => {
                eprintln!("ERR-ONVIF-METADATA-OUTPUT-001");
                ExitCode::from(1)
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(if error == ARGUMENT_ERROR { 2 } else { 1 })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn native_command_round_trip_reopens_without_input() -> Test {
        let directory = Directory::new("roundtrip")?;
        let input = directory.0.join("source.xml");
        let root = directory.0.join("deployment");
        fs::write(&input, br#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:Event/></t:MetadataStream>"#)?;
        let imported = run(parse(&args(&root, &input))?.ok_or("options")?)?;
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
        let verified = run(parse(&verify)?.ok_or("verify options")?)?;
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
