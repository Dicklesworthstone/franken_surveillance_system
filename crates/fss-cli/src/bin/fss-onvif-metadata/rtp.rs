#![forbid(unsafe_code)]
//! Owner-scoped packet-file import and cold verification of ONVIF RTP metadata.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, CanonicalEncoder, CaptureInterval, ContentDigest, ContextAuthority, OperationId,
    RootAuthoritySpec, SensorId, TimestampNs,
};
use fss_packet::{OnvifMetadataLimits, ReorderLimits, StreamKey};
use fss_reference::onvif::metadata::SourceBinding;
use fss_reference::onvif::metadata::rtp::{
    self, RetainedRtpMetadata, RtpMetadataConfig, RtpMetadataImportLimits,
};
use fss_reference::onvif::wire::{EventDocumentFormat, PropertyOperation};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{
    ARGUMENT_ERROR, CUSTODY_ERROR, CommandOutput, INPUT_ERROR, LIMIT_ERROR, REPORT_LIMIT,
    STORAGE_CHECKPOINT_ALLOWANCE, admission, clean_absolute, digest, optional_digest, runtime,
    text,
};

const STORAGE_BYTES: u64 = 512 * 1024 * 1024;
const STORAGE_OPERATIONS: u64 = STORAGE_CHECKPOINT_ALLOWANCE + 16 * 16_384 + 32 * 64;
const HELP: &str = "fss-onvif-metadata <import-rtp|inspect-rtp|verify-rtp> [options]
  All commands: --root ABSOLUTE_DIR --site SITE [--principal ID]
                [--timeout-ms 30000] [--include-values yes|no]
                [--document-index N]
  import-rtp: --input FILE --sensor ID --device-generation sha256:HEX
              --profile-generation sha256:HEX --profile TOKEN
              --received-start-ns N --received-end-ns N
              --ingress N --stream-generation N --ssrc N --payload-type N
              [--source-sha256 sha256:HEX]
              [--encoding vnd.onvif.metadata] [--clock-rate 90000]
              [--max-input-bytes 8388608] [--max-records 16384]
              [--max-documents 64] [--max-document-bytes 262144]
              [--max-fragments 4096] [--document-timeout-ms 2000]
              [--reorder-delay-ms 100]
  inspect-rtp/verify-rtp: --import-id sha256:HEX [--expected-root sha256:HEX]

Imports one bounded original #!rtpplay1.0 packet file. No network or credentials.
Only uncompressed ONVIF metadata with dynamic payload type 96..127 is supported.
The owner pins ingress, stream generation, SSRC and payload type independently.
Reconstruction begins after an observed RTP marker boundary. Reordering is bounded;
loss, truncated packets and expired/incomplete documents are reported explicitly.
RTP timestamps never split documents or establish camera time. Recorder offsets drive
deterministic replay only; receive times are the independent owner declaration.
One durable root retains the complete original file, replay report and completed XML,
including malformed/rejected documents. Damaged or empty reconstruction exits nonzero
after publication and still reports its retained identity for cold verification.
Cold commands verify the retained generation and packet provenance without the input
file. Their success means custody verified, even for an originally incomplete import.
Values are withheld by default. --include-values yes reveals parsed vendor values;
--document-index selects one document and its full packet span map without weakening
whole-root verification. Record outcomes and issues are summarized by reason; their
complete canonical report and every packet mapping remain in the verified root.
No coverage, physical absence, identity, calibrated geometry or effects are claimed.
";

enum Action {
    Import {
        input: PathBuf,
        source: SourceBinding,
        config: RtpMetadataConfig,
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
    approval: ContentDigest,
    timeout_ns: u64,
    include_values: bool,
    document_index: Option<usize>,
    action: Action,
}

fn number(
    values: &BTreeMap<String, OsString>,
    key: &str,
    default: Option<u128>,
    min: u128,
    max: u128,
) -> Result<u128, &'static str> {
    let value = match values.get(key) {
        Some(value) => value
            .to_str()
            .ok_or(ARGUMENT_ERROR)?
            .parse::<u128>()
            .map_err(|_| ARGUMENT_ERROR)?,
        None => default.ok_or(ARGUMENT_ERROR)?,
    };
    if !(min..=max).contains(&value) {
        return Err(ARGUMENT_ERROR);
    }
    Ok(value)
}

fn parse(args: &[OsString]) -> Result<Options, &'static str> {
    if args.is_empty()
        || args.len() > 71
        || args.len() % 2 != 1
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(ARGUMENT_ERROR);
    }
    let command = args[0].to_str().ok_or(ARGUMENT_ERROR)?;
    if !matches!(command, "import-rtp" | "inspect-rtp" | "verify-rtp") {
        return Err(ARGUMENT_ERROR);
    }
    let importing = command == "import-rtp";
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or(ARGUMENT_ERROR)?;
        let common = matches!(
            key,
            "--root"
                | "--site"
                | "--principal"
                | "--timeout-ms"
                | "--include-values"
                | "--document-index"
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
                    | "--ingress"
                    | "--stream-generation"
                    | "--ssrc"
                    | "--payload-type"
                    | "--source-sha256"
                    | "--encoding"
                    | "--clock-rate"
                    | "--max-input-bytes"
                    | "--max-records"
                    | "--max-documents"
                    | "--max-document-bytes"
                    | "--max-fragments"
                    | "--document-timeout-ms"
                    | "--reorder-delay-ms"
            )
        } else {
            matches!(key, "--import-id" | "--expected-root")
        };
        if !(common || specific) || values.insert(key.to_owned(), pair[1].clone()).is_some() {
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
    if principal.is_empty()
        || principal.len() > 256
        || principal.trim() != principal
        || principal.chars().any(char::is_control)
    {
        return Err(ARGUMENT_ERROR);
    }
    let include_values = match values
        .get("--include-values")
        .and_then(|value| value.to_str())
    {
        None | Some("no") => false,
        Some("yes") => true,
        _ => return Err(ARGUMENT_ERROR),
    };
    if values
        .get("--include-values")
        .is_some_and(|value| value.to_str().is_none())
    {
        return Err(ARGUMENT_ERROR);
    }
    let document_index = values
        .contains_key("--document-index")
        .then(|| number(&values, "--document-index", None, 0, 63).map(|value| value as usize))
        .transpose()?;
    let timeout_ns = number(&values, "--timeout-ms", Some(30000), 1000, 60000)? as u64 * 1_000_000;
    let action = if importing {
        if values
            .get("--encoding")
            .is_some_and(|value| value != "vnd.onvif.metadata")
            || number(&values, "--clock-rate", Some(90000), 90000, 90000)? != 90000
        {
            return Err(ARGUMENT_ERROR);
        }
        let source = SourceBinding {
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
        source.validate().map_err(|_| ARGUMENT_ERROR)?;
        let config = RtpMetadataConfig {
            stream: StreamKey {
                ingress: number(&values, "--ingress", None, 1, u128::MAX)?,
                generation: number(&values, "--stream-generation", None, 1, u64::MAX as u128)?
                    as u64,
                ssrc: number(&values, "--ssrc", None, 0, u32::MAX as u128)? as u32,
            },
            payload_type: number(&values, "--payload-type", None, 96, 127)? as u8,
            limits: RtpMetadataImportLimits {
                max_input_bytes: number(
                    &values,
                    "--max-input-bytes",
                    Some(8 * 1024 * 1024),
                    1,
                    8 * 1024 * 1024,
                )? as usize,
                max_records: number(&values, "--max-records", Some(16384), 1, 16384)? as usize,
                max_documents: number(&values, "--max-documents", Some(64), 1, 64)? as usize,
            },
            reorder: ReorderLimits {
                max_delay_ns: number(&values, "--reorder-delay-ms", Some(100), 1, 60000)? as u64
                    * 1_000_000,
                ..ReorderLimits::default()
            },
            metadata: OnvifMetadataLimits {
                max_document_bytes: number(
                    &values,
                    "--max-document-bytes",
                    Some(262144),
                    1,
                    262144,
                )? as usize,
                max_fragment_packets: number(&values, "--max-fragments", Some(4096), 1, 4096)?
                    as usize,
                max_pending_age_ns: number(&values, "--document-timeout-ms", Some(2000), 1, 60000)?
                    as u64
                    * 1_000_000,
            },
        };
        config.validate().map_err(|_| ARGUMENT_ERROR)?;
        Action::Import {
            input: PathBuf::from(values.get("--input").ok_or(ARGUMENT_ERROR)?),
            source,
            config,
            expected_source: optional_digest(&values, "--source-sha256")?,
        }
    } else {
        Action::Inspect {
            identity: digest(text(&values, "--import-id")?)?,
            expected_root: optional_digest(&values, "--expected-root")?,
            verify: command == "verify-rtp",
        }
    };
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.onvif_rtp_metadata_operator_request.v1");
    encoder.text(command);
    for (key, value) in &values {
        encoder.text(key);
        encoder.bytes(value.as_encoded_bytes());
    }
    encoder.text(&principal);
    encoder.u64(timeout_ns);
    let approval = ContentDigest::sha256(&encoder.finish_checked().map_err(|_| ARGUMENT_ERROR)?);
    Ok(Options {
        root,
        site,
        principal,
        approval,
        timeout_ns,
        include_values,
        document_index,
        action,
    })
}

fn read_input(
    path: &Path,
    maximum: usize,
    scope: &runtime::Scope<'_, '_>,
) -> Result<Vec<u8>, &'static str> {
    scope.input()?;
    let before = fs::symlink_metadata(path).map_err(|_| INPUT_ERROR)?;
    if !before.file_type().is_file() || before.len() > maximum as u64 {
        return Err(INPUT_ERROR);
    }
    scope.input()?;
    let input = File::open(path).map_err(|_| INPUT_ERROR)?;
    scope.input()?;
    let opened = input.metadata().map_err(|_| INPUT_ERROR)?;
    if !opened.is_file() || opened.len() > maximum as u64 {
        return Err(INPUT_ERROR);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve(opened.len() as usize)
        .map_err(|_| LIMIT_ERROR)?;
    scope.input()?;
    input
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| INPUT_ERROR)?;
    scope.now()?;
    if bytes.len() > maximum {
        return Err(LIMIT_ERROR);
    }
    Ok(bytes)
}

fn run(options: Options) -> Result<(CommandOutput, bool), &'static str> {
    let importing = matches!(&options.action, Action::Import { .. });
    let request = runtime::Request {
        approval: options.approval,
        principal: options.principal.clone(),
        timeout_ns: options.timeout_ns,
        bytes: STORAGE_BYTES,
        network_bytes: 0,
        storage_operations: STORAGE_OPERATIONS,
        network: false,
        write: true,
        secrets: false,
    };
    let work = |scope: &runtime::Scope<'_, '_>| {
        let input = match &options.action {
            Action::Import {
                input,
                config,
                expected_source,
                ..
            } => {
                let bytes = read_input(input, config.limits.max_input_bytes, scope)?;
                if expected_source.is_some_and(|expected| expected != ContentDigest::sha256(&bytes))
                {
                    return Err(CUSTODY_ERROR);
                }
                Some(bytes)
            }
            Action::Inspect { .. } => None,
        };
        scope.input()?;
        match fs::symlink_metadata(&options.root) {
            Ok(metadata) if !metadata.file_type().is_dir() => return Err(INPUT_ERROR),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && importing => {}
            Err(_) => return Err(INPUT_ERROR),
        }
        if !importing {
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
            trace_id: "trace:onvif-rtp-metadata".into(),
            operation_id: OperationId::parse("operation:onvif-rtp-metadata")
                .map_err(|_| ARGUMENT_ERROR)?,
            principal: options.principal.clone(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(STORAGE_BYTES)
                .storage_operations(STORAGE_OPERATIONS)
                .build()
                .map_err(|_| LIMIT_ERROR)?,
            privacy_scope: "privacy:owner-private-vendor-metadata".into(),
            retention_scope: "retention:explicit-rtp-metadata-import".into(),
            anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| ARGUMENT_ERROR)?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, options.root.clone())
            .map_err(|_| ARGUMENT_ERROR)?
            .with_admission(|_| admission::check(scope));
        let result = (|| {
            scope.output()?;
            let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)
                .map_err(|_| "ERR-ONVIF-METADATA-PUBLICATION-001")?;
            match &options.action {
                Action::Import { source, config, .. } => rtp::retain(
                    &mut deployment,
                    input.as_deref().ok_or(INPUT_ERROR)?,
                    source.clone(),
                    config.clone(),
                    &cx,
                )
                .map_err(|error| error.code()),
                Action::Inspect {
                    identity,
                    expected_root,
                    ..
                } => RetainedRtpMetadata::open(&deployment, *identity, *expected_root, &cx)
                    .map_err(|error| error.code()),
            }
        })();
        let owner_error = cx.admission_refusal().map(admission::code);
        cx.drain_and_finalize();
        match result {
            Ok(retained) => Ok((retained, owner_error)),
            Err(error) => Err(owner_error.unwrap_or(error)),
        }
    };
    if importing {
        let completed =
            runtime::run_committing(request, |scope| work(scope).map(runtime::Committed::new))?;
        let (retained, owner_error) = completed.value;
        let error = owner_error
            .or(completed.post_commit_error)
            .or(completed.finalization_error);
        let custody = custody_header(&retained);
        let result = if error.is_some() {
            Err(error.unwrap_or(LIMIT_ERROR))
        } else {
            report(
                &retained,
                "import-rtp",
                options.include_values,
                options.document_index,
            )
        };
        let (report, detail_ok) = match result {
            Ok(report) => (report, true),
            Err(error) => (
                format!(
                    "{custody}phase=retained_with_error\nerror={error}\nowner_error={}\npost_commit_error={}\nfinalization_error={}\nvalues_disclosed=false\n",
                    owner_error.unwrap_or("none"),
                    completed.post_commit_error.unwrap_or("none"),
                    completed.finalization_error.unwrap_or("none"),
                ),
                false,
            ),
        };
        let complete = detail_ok && retained.report().processing_complete();
        Ok((
            CommandOutput {
                report,
                custody_receipt: Some(custody),
            },
            complete,
        ))
    } else {
        let (retained, owner_error) = runtime::run(request, work)?;
        if let Some(error) = owner_error {
            return Err(error);
        }
        let operation = match options.action {
            Action::Inspect { verify: true, .. } => "verify-rtp",
            _ => "inspect-rtp",
        };
        Ok((
            CommandOutput {
                report: report(
                    &retained,
                    operation,
                    options.include_values,
                    options.document_index,
                )?,
                custody_receipt: None,
            },
            true,
        ))
    }
}

fn custody_header(retained: &RetainedRtpMetadata) -> String {
    format!(
        "operation=import-rtp\nimport_identity={}\npublication_root={}\nsource_sha256={}\nsource_bytes={}\ndurable_publication=true\nsafe_next=verify_rtp_exact_import\n",
        retained.identity(),
        retained.publication_root(),
        retained.source_digest(),
        retained.source_bytes(),
    )
}

fn report(
    retained: &RetainedRtpMetadata,
    operation: &str,
    include_values: bool,
    selected: Option<usize>,
) -> Result<String, &'static str> {
    if selected.is_some_and(|index| index >= retained.documents().len()) {
        return Err(ARGUMENT_ERROR);
    }
    let mut out = String::new();
    let binding = retained.binding();
    let config = retained.config();
    let replay = retained.report();
    macro_rules! line {
        ($($arg:tt)*) => {{
            writeln!(&mut out, $($arg)*).map_err(|_| LIMIT_ERROR)?;
            if out.len() > REPORT_LIMIT { return Err(LIMIT_ERROR); }
        }};
    }
    line!("operation={operation}");
    line!("import_identity={}", retained.identity());
    line!("publication_root={}", retained.publication_root());
    line!("source_sha256={}", retained.source_digest());
    line!("source_bytes={}", retained.source_bytes());
    line!("replay_report_sha256={}", retained.report_digest());
    line!("durable_publication=true");
    line!(
        "authority_sequence={}",
        retained.authority_anchor().commit_sequence
    );
    line!("source_mode={}", retained.source_mode());
    line!("replay_generation={}", rtp::REPLAY_GENERATION);
    line!("parser_generation={}", retained.parser_generation());
    line!("plane={}", retained.plane().as_str());
    line!("provenance={}", retained.provenance().as_str());
    line!("encoding=vnd.onvif.metadata");
    line!("clock_rate=90000");
    line!("ingress={}", config.stream.ingress);
    line!("stream_generation={}", config.stream.generation);
    line!("ssrc={}", config.stream.ssrc);
    line!("payload_type={}", config.payload_type);
    line!(
        "sensor_sha256={}",
        ContentDigest::sha256(binding.sensor_id.as_str().as_bytes())
    );
    line!("device_generation={}", binding.device_generation);
    line!("profile_generation={}", binding.profile_generation);
    line!(
        "profile_token_sha256={}",
        ContentDigest::sha256(binding.profile_token.as_bytes())
    );
    line!("received_start_ns={}", binding.receive_interval.earliest.0);
    line!("received_end_ns={}", binding.receive_interval.latest.0);
    line!("receive_interval_source=owner_declaration");
    line!("reconstruction_scope=after_first_observed_marker");
    line!("recorded_offsets_trusted=false");
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
    if include_values {
        line!("sensor={:?}", binding.sensor_id.as_str());
        line!("profile_token={:?}", binding.profile_token);
    }
    line!("processing_complete={}", replay.processing_complete());
    line!("end_reason={}", replay.end_reason);
    line!("record_count={}", replay.records.len());
    line!("issue_count={}", replay.issues.len());
    line!("complete_documents={}", replay.complete_documents);
    line!("usable_documents={}", replay.usable_documents);
    line!("rejected_documents={}", replay.rejected_documents);
    line!("unprocessed_source={}", replay.unprocessed_span.is_some());
    if let Some(span) = &replay.unprocessed_span {
        line!("unprocessed_source_start={}", span.start);
        line!("unprocessed_source_end={}", span.end);
    }
    line!("record_reporting=disposition_counts");
    let mut dispositions = BTreeMap::<&str, usize>::new();
    let mut sequences = BTreeMap::<&str, usize>::new();
    let mut reconstruction = BTreeMap::<&str, usize>::new();
    for record in &replay.records {
        *dispositions.entry(record.result).or_default() += 1;
        if let Some(class) = record.sequence_class {
            *sequences.entry(class).or_default() += 1;
        }
        if let Some(result) = record.reconstruction {
            *reconstruction.entry(result).or_default() += 1;
        }
    }
    for (reason, count) in dispositions {
        line!("records.{reason}={count}");
    }
    for (reason, count) in sequences {
        line!("sequence_classes.{reason}={count}");
    }
    for (reason, count) in reconstruction {
        line!("reconstruction.{reason}={count}");
    }
    line!("issue_reporting=reason_counts");
    let mut issues = BTreeMap::<&str, usize>::new();
    for issue in &replay.issues {
        *issues.entry(issue.reason).or_default() += 1;
    }
    for (reason, count) in issues {
        line!("issues.{reason}={count}");
    }
    if let Some(index) = selected {
        line!("document_selection={index}");
        line!("provenance_reporting=selected_document_fragments");
    } else {
        line!("document_selection=all");
        line!("provenance_reporting=document_summaries");
    }
    for document in retained.documents() {
        let index = document.index();
        if selected.is_some_and(|selected| selected != index) {
            continue;
        }
        let key = format!("document.{index}");
        let provenance = document.provenance();
        line!("{key}.xml_sha256={}", document.source_digest());
        line!("{key}.xml_bytes={}", document.source_bytes());
        line!("{key}.xml_accepted={}", document.document().is_some());
        line!(
            "{key}.parse_error={}",
            document.parse_error().unwrap_or("none")
        );
        if let Some(digest) = document.projection_digest() {
            line!("{key}.projection_sha256={digest}");
        }
        line!("{key}.fragment_count={}", provenance.fragments.len());
        line!("{key}.boundary_record={}", provenance.boundary.record);
        line!("{key}.boundary_sequence={}", provenance.boundary.sequence);
        line!(
            "{key}.boundary_source={}..{}",
            provenance.boundary.source.start,
            provenance.boundary.source.end
        );
        line!("{key}.boundary_timestamp={}", provenance.boundary.timestamp);
        line!(
            "{key}.boundary_replay_received_ns={}",
            provenance.boundary.replay_received_ns
        );
        line!("{key}.replay_started_ns={}", provenance.replay_started_ns);
        line!(
            "{key}.replay_completed_ns={}",
            provenance.replay_completed_ns
        );
        if let (Some(first), Some(last)) =
            (provenance.fragments.first(), provenance.fragments.last())
        {
            line!("{key}.first_sequence={}", first.sequence);
            line!("{key}.last_sequence={}", last.sequence);
        }
        if selected.is_some() {
            for (ordinal, fragment) in provenance.fragments.iter().enumerate() {
                line!(
                    "{key}.fragment.{ordinal}=record:{},sequence:{},source:{}..{},payload:{}..{},xml:{}..{},timestamp:{},replay_received_ns:{}",
                    fragment.record,
                    fragment.sequence,
                    fragment.source.start,
                    fragment.source.end,
                    fragment.payload.start,
                    fragment.payload.end,
                    fragment.document.start,
                    fragment.document.end,
                    fragment.timestamp,
                    fragment.replay_received_ns,
                );
            }
        }
        if let Some(parsed) = document.document() {
            line!(
                "{key}.format={}",
                match parsed.format {
                    EventDocumentFormat::MetadataStream => "metadata_stream",
                    EventDocumentFormat::PullMessages => "pull_messages",
                }
            );
            line!("{key}.notification_count={}", parsed.notifications.len());
            line!(
                "{key}.analytics_frame_count={}",
                parsed.analytics_frames.len()
            );
            line!(
                "{key}.analytics_object_count={}",
                parsed
                    .analytics_frames
                    .iter()
                    .map(|frame| frame.objects.len())
                    .sum::<usize>()
            );
            line!("{key}.unsupported_sections={}", parsed.unsupported_sections);
            line!(
                "{key}.has_unsupported_content={}",
                parsed.has_unsupported_content()
            );
            if include_values {
                let mut details = String::new();
                for (ordinal, notification) in parsed.notifications.iter().enumerate() {
                    writeln!(&mut details, "notification.{ordinal}.topic_namespace={:?}\nnotification.{ordinal}.topic_path={:?}\nnotification.{ordinal}.vendor_utc_time={:?}\nnotification.{ordinal}.property_operation={}",
                        notification.topic.namespace, notification.topic.path.join("/"), notification.utc_time,
                        match notification.property_operation {
                            None => "not_supplied",
                            Some(PropertyOperation::Initialized) => "Initialized",
                            Some(PropertyOperation::Changed) => "Changed",
                            Some(PropertyOperation::Deleted) => "Deleted",
                        },
                    ).map_err(|_| LIMIT_ERROR)?;
                    for (kind, items) in [
                        ("source", notification.source.as_ref()),
                        ("key", notification.key.as_ref()),
                        ("data", notification.data.as_ref()),
                    ] {
                        super::report_items(&mut details, ordinal, kind, items, true)?;
                    }
                    if details.len() > REPORT_LIMIT {
                        return Err(LIMIT_ERROR);
                    }
                }
                for (ordinal, frame) in parsed.analytics_frames.iter().enumerate() {
                    super::report_analytics(&mut details, ordinal, frame, true)?;
                    if details.len() > REPORT_LIMIT {
                        return Err(LIMIT_ERROR);
                    }
                }
                for detail in details.lines() {
                    line!("{key}.{detail}");
                }
            }
        }
    }
    Ok(out)
}

pub(super) fn run_args(args: &[OsString]) -> Result<(CommandOutput, bool), &'static str> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok((
            CommandOutput {
                report: HELP.to_owned(),
                custody_receipt: None,
            },
            true,
        ));
    }
    run(parse(args)?)
}
