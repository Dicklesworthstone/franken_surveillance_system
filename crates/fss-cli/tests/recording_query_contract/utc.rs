#![forbid(unsafe_code)]
//! Actual CLI/MCP UTC selection with unavailable clocks, protected context and metadata custody.

#[path = "utc_set.rs"]
mod utc_set;

use super::*;
use std::io::Write;
use std::process::Stdio;

use fss_reference::agent_recording_context::utc::{
    RecordingUtcContextError, RecordingUtcContextLimits, RecordingUtcContextRequest,
    query_recordings_utc_in_deployment,
};
use fss_reference::agent_recordings::utc::RecordingUtcQueryRequest;
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording_clock::{
    ClockWindow, RecordingClockCodec, RecordingClockIndex, UtcInterval, clock_slot,
};

struct UtcFixture {
    base: Fixture,
    request: RecordingUtcContextRequest,
    clock_metadata: ContentDigest,
    known: UtcInterval,
    unknown_root: ContentDigest,
    unknown_bytes: u64,
}

fn hevc_window(decode_time: u64, admission: u64) -> TestResult<PreparedHevcRecording> {
    let mut packets = hevc_recording_support::packets()?;
    for packet in &mut packets {
        packet.received_ns = admission;
    }
    let mut timings = hevc_recording_support::timings(4);
    for timing in &mut timings {
        timing.decode_time += decode_time;
    }
    hevc_recording_support::prepare(&packets, &timings)
}

impl UtcFixture {
    fn new(tag: &str, codec: RecordingQueryCodec) -> TestResult<Self> {
        let mut base = Fixture::new(tag, codec)?;
        let a = SlotName::parse("first-window")?;
        let b = SlotName::parse("second-window")?;
        let (scope, catalog, metadata, clock, leaves, unknown_root, unknown_bytes) = match codec {
            RecordingQueryCodec::Avc => {
                let first = clock_support::window(1, 0, &[30_000_000])?;
                let second = clock_support::window(2, 7200, &[60_000_000])?;
                let scope = clock_support::catalog_scope()?;
                let catalog = prepare_catalog(
                    scope.clone(),
                    &[
                        CatalogWindow {
                            slot: &a,
                            recording: &first,
                        },
                        CatalogWindow {
                            slot: &b,
                            recording: &second,
                        },
                    ],
                )?;
                let clock = clock_support::prepare(
                    &[clock_support::descriptor(a.as_str(), &first)?],
                    &[clock_support::bracket(30_000_000)],
                )?;
                publish(&base.archive, &a, first.manifest())?;
                publish(&base.archive, &b, second.manifest())?;
                let leaves = first
                    .children()
                    .chain(second.children())
                    .map(|(_, digest, _)| digest)
                    .collect();
                (
                    scope,
                    catalog.manifest().clone(),
                    catalog.index_bytes().to_vec(),
                    clock,
                    leaves,
                    second.manifest().root(),
                    second.byte_len() as u64,
                )
            }
            RecordingQueryCodec::Hevc => {
                let first = hevc_window(0, 30_000_000)?;
                let second = hevc_window(200_000, 60_000_000)?;
                let scope = hevc_catalog_support::scope()?;
                let catalog = prepare_hevc_catalog(
                    scope.clone(),
                    &[
                        HevcCatalogWindow {
                            slot: &a,
                            recording: &first,
                        },
                        HevcCatalogWindow {
                            slot: &b,
                            recording: &second,
                        },
                    ],
                )?;
                let clock = RecordingClockIndex::prepare(
                    scope.clone(),
                    RecordingClockCodec::Hevc,
                    clock_support::approval(),
                    clock_support::exchange()?,
                    clock_support::host(100_000_000),
                    &[clock_support::bracket(30_000_000)],
                    &[ClockWindow::from_hevc(a.clone(), &first)?],
                )?;
                publish(&base.archive, &a, first.manifest())?;
                publish(&base.archive, &b, second.manifest())?;
                let leaves = first
                    .publication_plan()
                    .children()
                    .chain(second.publication_plan().children())
                    .map(|(_, digest, _)| digest)
                    .collect();
                (
                    scope,
                    catalog.manifest().clone(),
                    catalog.index_bytes().to_vec(),
                    clock,
                    leaves,
                    second.manifest().root(),
                    second.byte_len() as u64,
                )
            }
        };
        let slot = SlotName::parse("catalog")?;
        publish(&base.archive, &slot, &catalog)?;
        put(&base.archive, &metadata)?;
        let clock_slot = clock_slot(clock.codec(), &scope)?;
        publish(&base.archive, &clock_slot, clock.manifest())?;
        put(&base.archive, clock.index_bytes())?;
        let known = clock.windows()[0].utc_interval();
        let recording = RecordingUtcQueryRequest {
            codec,
            scope: scope.clone(),
            catalog_slot: slot.clone(),
            catalog_root: catalog.root(),
            clock_slot,
            clock_root: clock.root(),
            interval: known.earliest_ns..known.latest_ns + 1,
            max_windows: 32,
            max_hydration_bytes: 256 * 1024 * 1024,
        };
        base.metadata = ContentDigest::sha256(&metadata);
        base.source_leaves = leaves;
        // Retain an actual independent decode-clock query for compatibility comparisons.
        base.request.recording = RecordingQueryRequest {
            codec,
            scope,
            catalog_slot: slot,
            catalog_root: catalog.root(),
            interval: 0..u64::MAX,
            max_windows: 32,
            max_hydration_bytes: 256 * 1024 * 1024,
        };
        Ok(Self {
            request: RecordingUtcContextRequest {
                recording,
                principal: base.request.principal.clone(),
                expected_anchor: None,
            },
            base,
            clock_metadata: ContentDigest::sha256(clock.index_bytes()),
            known,
            unknown_root,
            unknown_bytes,
        })
    }

    fn fields(&self) -> Vec<(&'static str, String)> {
        let r = &self.request.recording;
        let scope = &r.scope;
        let mut fields = vec![
            ("target", "recordings".to_owned()),
            ("codec", r.codec.as_str().to_owned()),
            ("catalog_slot", r.catalog_slot.as_str().to_owned()),
            ("catalog_root", r.catalog_root.to_text()),
            ("sensor", scope.recording.sensor.as_str().to_owned()),
            ("stream", scope.recording.stream.as_str().to_owned()),
            ("generation", scope.recording.generation.to_string()),
            ("source_anchor", scope.recording.anchor.to_text()),
            ("receive_clock", scope.recording.receive_clock.to_text()),
            ("decode_clock", scope.decode_clock.to_text()),
            ("time_scale", scope.time_scale.to_string()),
            ("clock_slot", r.clock_slot.as_str().to_owned()),
            ("clock_root", r.clock_root.to_text()),
            ("start_utc_ns", r.interval.start.to_string()),
            ("end_utc_ns", r.interval.end.to_string()),
            ("max_windows", r.max_windows.to_string()),
            ("max_hydration_bytes", r.max_hydration_bytes.to_string()),
        ];
        if let Some(anchor) = &self.request.expected_anchor {
            fields.push(("anchor", anchor.as_str().to_owned()));
        }
        fields
    }

    fn run(&self) -> TestResult<(String, ExitIdentity)> {
        self.run_fields(self.fields(), false)
    }

    fn run_fields(
        &self,
        fields: Vec<(&str, String)>,
        catalog_set: bool,
    ) -> TestResult<(String, ExitIdentity)> {
        let mut args: Vec<OsString> = vec![
            "query".into(),
            "--json".into(),
            "--root".into(),
            self.base.deployment.as_os_str().to_owned(),
            "--archive-root".into(),
            self.base.archive.as_os_str().to_owned(),
            format!("--principal={}", self.request.principal.as_str()).into(),
        ];
        args.extend(
            fields
                .into_iter()
                .map(|(key, value)| OsString::from(format!("--{}={value}", key.replace('_', "-")))),
        );
        let command = parse_fss_args(args.clone())?;
        if catalog_set {
            assert!(matches!(
                command,
                fss_cli::FssCommand::RecordingUtcSetQuery(_)
            ));
        } else {
            assert!(matches!(command, fss_cli::FssCommand::RecordingUtcQuery(_)));
        }
        let answer = execute_fss_with_exit(command);
        let process = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(args)
            .output()?;
        assert_eq!(process.status.code(), Some(i32::from(answer.1.code)));
        assert_eq!(
            String::from_utf8(process.stdout)?,
            format!("{}\n", answer.0)
        );
        assert!(process.stderr.is_empty());
        parse_json(&answer.0)?;
        Ok(answer)
    }

    fn mcp(&self) -> TestResult<(String, bool)> {
        let fields = self
            .fields()
            .iter()
            .map(|(key, value)| {
                let value = if matches!(*key, "time_scale" | "max_windows") {
                    value.clone()
                } else {
                    format!("\"{}\"", fss_cli::escape_json_str(value))
                };
                format!("\"{key}\":{value}")
            })
            .collect::<Vec<_>>()
            .join(",");
        self.mcp_fields(&fields)
    }

    fn mcp_fields(&self, fields: &str) -> TestResult<(String, bool)> {
        let request = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"query\",\"arguments\":{{{fields}}}}}}}"
        );
        let mut process = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
            .arg("--root")
            .arg(&self.base.deployment)
            .arg("--archive-root")
            .arg(&self.base.archive)
            .arg("--principal")
            .arg(self.request.principal.as_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = process.stdin.take().ok_or("MCP stdin")?;
        writeln!(
            input,
            "{}",
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"UTC-contract","version":"1"}}}"#
        )?;
        writeln!(
            input,
            "{}",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        )?;
        writeln!(input, "{request}")?;
        drop(input);
        let output = process.wait_with_output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout)?;
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        let response = parse_json(lines[1])?;
        let content = at(&response, &["result", "content"])?
            .array()
            .ok_or("MCP content")?;
        assert_eq!(content.len(), 1);
        let is_error = at(&response, &["result", "isError"])?
            .boolean()
            .ok_or("MCP outcome")?;
        Ok((text_at(&content[0], &["text"])?.to_owned(), is_error))
    }
}

#[test]
fn utc_cli_and_mcp_preserve_unknown_clocks_protected_context_and_exact_semantic_bytes() -> TestResult
{
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture = UtcFixture::new(&format!("utc-{}", codec.as_str()), codec)?;
        fixture
            .base
            .publish_hypothesis("event:protected-utc-query")?;
        let before = tree(&fixture.base.directory)?;
        let (output, exit) = fixture.run()?;
        assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
        assert_eq!(fixture.mcp()?, (output.clone(), false));
        assert_eq!(fixture.run()?, (output.clone(), exit));
        let envelope = parse_json(&output)?;
        assert_eq!(
            text_at(&envelope, &["schema"])?,
            "fss.agent_response_envelope.v1"
        );
        assert_eq!(
            text_at(&envelope, &["payload", "coverage", "stopReason"])?,
            "pinned_clock_catalog_exhausted"
        );
        assert_eq!(
            text_at(
                proposition(&envelope, "claim:recordings-utc:window:0")?,
                &["state"]
            )?,
            "known"
        );
        assert_eq!(
            text_at(
                proposition(&envelope, "claim:recordings-utc:window:1")?,
                &["state"]
            )?,
            "not_observable"
        );
        assert_eq!(
            text_at(
                proposition(&envelope, "claim:recordings-utc:physical-observability")?,
                &["state"]
            )?,
            "unknown"
        );
        assert!(output.contains("clock_unavailable"));
        assert!(output.contains("packet-admission coordinates were not replayed"));
        assert!(output.contains("native-recording-clock-metadata"));
        let handles = at(&envelope, &["payload", "evidenceHandles"])?
            .array()
            .ok_or("handles")?;
        assert_eq!(handles.len(), 4);
        for handle in handles {
            assert_eq!(text_at(handle, &["hydration"])?, "H0");
            assert_eq!(
                at(handle, &["allowedHydration"])?
                    .array()
                    .ok_or("allowed hydration")?,
                &[Value::Text("H0".to_owned())]
            );
        }
        let query = query_recordings_utc_in_deployment(
            &HostSpoolIo,
            &fixture.base.deployment,
            &fixture.base.archive,
            &fixture.request,
            &RecordingUtcContextLimits::default(),
            &|| false,
        )?;
        let orientation = orient_deployment(
            &query.snapshot,
            &OrientRequest {
                view: AgentView::Brief,
                principal: fixture.request.principal.clone(),
                budget_tokens: None,
            },
            &RecordingUtcContextLimits::default().snapshot,
        )?;
        for cell in &orientation.capsule().frame.knowledge_cells {
            let actual = proposition(&envelope, cell.claim_id())?;
            assert_eq!(
                text_at(actual, &["state"])?,
                cell.knowledge_state().as_str()
            );
            assert_eq!(
                text_at(actual, &["statement"])?,
                cell.disclosable_statement()
            );
        }
        assert!(output.contains("event:protected-utc-query"));
        assert!(output.contains(&query.anchor_token));
        for leaf in &fixture.base.source_leaves {
            assert!(!object_path(&fixture.base.archive, *leaf).exists());
        }
        assert_eq!(tree(&fixture.base.directory)?, before);
    }
    Ok(())
}

#[test]
fn unannotated_windows_survive_outside_utc_and_consume_atomic_output_limits() -> TestResult {
    let mut fixture = UtcFixture::new("utc-unknown-budget", RecordingQueryCodec::Avc)?;
    fixture.request.recording.max_windows = 1;
    assert_eq!(fixture.run()?.1, ExitIdentity::AGENT_REFUSED);
    fixture.request.recording.interval = fixture.known.latest_ns + 1..fixture.known.latest_ns + 10;
    fixture.request.recording.max_hydration_bytes = fixture.unknown_bytes;
    let (output, exit) = fixture.run()?;
    assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
    assert_eq!(fixture.mcp()?, (output.clone(), false));
    assert!(output.contains(&fixture.unknown_root.to_text()));
    let envelope = parse_json(&output)?;
    assert!(proposition(&envelope, "claim:recordings-utc:window:0").is_err());
    assert!(proposition(&envelope, "claim:recordings-utc:window:1").is_ok());
    let gap = proposition(&envelope, "claim:recordings-utc:indexed-gap:0")?;
    assert_eq!(text_at(gap, &["state"])?, "not_observable");
    assert!(text_at(gap, &["statement"])?.contains("Windows with unavailable clocks may overlap"));
    fixture.request.recording.max_hydration_bytes -= 1;
    let before = tree(&fixture.base.directory)?;
    let (refused, exit) = fixture.run()?;
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert_eq!(fixture.mcp()?, (refused, true));
    assert_eq!(tree(&fixture.base.directory)?, before);
    Ok(())
}

#[test]
fn utc_context_revalidates_anchor_and_never_opens_source_or_writer_handles() -> TestResult {
    let mut fixture = UtcFixture::new("utc-context", RecordingQueryCodec::Avc)?;
    let limits = RecordingUtcContextLimits::default();
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let initial = query_recordings_utc_in_deployment(
        &io,
        &fixture.base.deployment,
        &fixture.base.archive,
        &fixture.request,
        &limits,
        &|| false,
    )?;
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    fixture.request.expected_anchor =
        Some(AnchorToken::parse(&initial.anchor_token).ok_or("anchor")?);
    fixture.base.publish_hypothesis("event:utc-new-head")?;
    let before = tree(&fixture.base.directory)?;
    assert_eq!(fixture.run()?.1, ExitIdentity::AGENT_REFUSED);
    assert_eq!(tree(&fixture.base.directory)?, before);
    fixture.request.expected_anchor = None;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let changed = AtomicBool::new(false);
    let cancel = || {
        if io.call_count(SpoolIoCall::OpenRead) >= 5 && !changed.swap(true, Ordering::SeqCst) {
            return fixture
                .base
                .publish_hypothesis("event:utc-racing-head")
                .is_err();
        }
        false
    };
    let raced = query_recordings_utc_in_deployment(
        &io,
        &fixture.base.deployment,
        &fixture.base.archive,
        &fixture.request,
        &limits,
        &cancel,
    );
    assert!(changed.load(Ordering::SeqCst));
    assert!(
        matches!(raced, Err(RecordingUtcContextError::AnchorChanged)),
        "{raced:?}"
    );
    for leaf in &fixture.base.source_leaves {
        fs::write(
            object_path(&fixture.base.archive, *leaf),
            b"corrupt source bytes must stay unread",
        )?;
    }
    let cx = fixture.base.cx()?;
    let writer = ReferenceDeployment::open(&fixture.base.deployment, SITE, &cx)?;
    let lock = fs::File::create(fixture.base.archive.join("LOCK"))?;
    lock.try_lock()?;
    let before = tree(&fixture.base.directory)?;
    assert_eq!(fixture.run()?.1, ExitIdentity::SUCCESS);
    assert_eq!(tree(&fixture.base.directory)?, before);
    lock.unlock()?;
    drop(writer);
    Ok(())
}

#[test]
fn utc_context_shared_budgets_and_cancellation_refuse_without_mutation() -> TestResult {
    let fixture = UtcFixture::new("utc-budgets", RecordingQueryCodec::Avc)?;
    let limits = RecordingUtcContextLimits::default();
    let baseline = query_recordings_utc_in_deployment(
        &HostSpoolIo,
        &fixture.base.deployment,
        &fixture.base.archive,
        &fixture.request,
        &limits,
        &|| false,
    )?;
    let exact = RecordingUtcContextLimits {
        deployment_bytes: baseline.deployment_bytes_read as usize + 1,
        deployment_reads: baseline.deployment_metadata_reads as usize,
        ..limits
    };
    let admitted = query_recordings_utc_in_deployment(
        &HostSpoolIo,
        &fixture.base.deployment,
        &fixture.base.archive,
        &fixture.request,
        &exact,
        &|| false,
    )?;
    assert_eq!(admitted.native.rows, baseline.native.rows);
    assert_eq!(
        admitted.deployment_metadata_reads,
        baseline.deployment_metadata_reads
    );
    let before = tree(&fixture.base.directory)?;
    for (dimension, mut lowered) in [exact; 3].into_iter().enumerate() {
        match dimension {
            0 => lowered.deployment_bytes = baseline.deployment_bytes_read as usize - 1,
            1 => lowered.deployment_reads -= 1,
            _ => lowered.recording.metadata.max_io_calls = baseline.native.read_usage.io_calls - 1,
        }
        assert!(
            query_recordings_utc_in_deployment(
                &HostSpoolIo,
                &fixture.base.deployment,
                &fixture.base.archive,
                &fixture.request,
                &lowered,
                &|| false,
            )
            .is_err()
        );
    }
    assert!(matches!(
        query_recordings_utc_in_deployment(
            &HostSpoolIo,
            &fixture.base.deployment,
            &fixture.base.archive,
            &fixture.request,
            &limits,
            &|| true,
        ),
        Err(RecordingUtcContextError::Cancelled)
    ));
    assert_eq!(tree(&fixture.base.directory)?, before);
    Ok(())
}

#[test]
fn utc_missing_corrupt_or_revoked_clock_evidence_never_becomes_an_empty_success() -> TestResult {
    for fault in [
        "clock-metadata",
        "clock-root",
        "clock-binding",
        "source-tombstone",
    ] {
        let mut fixture = UtcFixture::new(fault, RecordingQueryCodec::Avc)?;
        match fault {
            "clock-metadata" => fs::write(
                object_path(&fixture.base.archive, fixture.clock_metadata),
                b"corrupt clock metadata",
            )?,
            "clock-root" => {
                fixture.request.recording.clock_root = ContentDigest::sha256(b"foreign clock root")
            }
            "clock-binding" => fs::remove_file(fixture.base.archive.join("roots").join(format!(
                "{}.root",
                fixture.request.recording.clock_slot.as_str(),
            )))?,
            _ => {
                let leaf = fixture.base.source_leaves.first().ok_or("source leaf")?;
                fs::write(
                    fixture
                        .base
                        .archive
                        .join("tombstones")
                        .join(format!("{}.tomb", leaf.to_text().replacen(':', "-", 1),)),
                    b"deletion present",
                )?;
            }
        }
        let before = tree(&fixture.base.directory)?;
        let (output, exit) = fixture.run()?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{fault}: {output}");
        assert!(!output.contains("claim:recordings-utc:catalog-selection"));
        assert_eq!(fixture.mcp()?, (output, true));
        assert_eq!(tree(&fixture.base.directory)?, before);
    }
    Ok(())
}
