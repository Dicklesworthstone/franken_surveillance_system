#![forbid(unsafe_code)]
//! Source-verified recorder UTC through the actual native, CLI and MCP query surfaces.

#[path = "../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod hevc_recording_support;
#[path = "../../fss-reference/tests/recording_support/mod.rs"]
mod recording_support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::client::replay::{ReplayAcceptance, ReplayWindow};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::ReplayRequest;
use recording_support::{Error, fixture, scope};

type TestResult = Result<(), Error>;
static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

fn path(name: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("recording_replay_query_contract")
        .join(format!(
            "{}-{}-{name}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16,
        512,
        16,
        128,
        SpoolLimits::new(128, 32 * 1024 * 1024, 8 * 1024 * 1024, 256),
    )
}

fn request() -> Result<ReplayRequest, Error> {
    Ok(ReplayRequest::new(
        scope()?,
        ContentDigest::sha256(b"approved credential-free route"),
        ReplayWindow::from_timestamps("20261105T010000Z", "20261105T010500Z")?,
        ContentDigest::sha256(b"original decode clock"),
    )?)
}

fn catalog_scope(request: &ReplayRequest) -> CatalogScope {
    CatalogScope {
        recording: request.scope().clone(),
        decode_clock: request.decode_clock(),
        time_scale: 90_000,
    }
}

fn accepted(request: &ReplayRequest) -> Result<ReplayAcceptance, Error> {
    Ok(ReplayAcceptance::new(
        7,
        request.window(),
        ReplayWindow::from_timestamps("20261105T010100Z", "20261105T010400Z")?,
    )?)
}

fn publish_window(
    publisher: &mut LocalRootPublisher,
    slot: &SlotName,
    recording: &PreparedRecording,
) -> TestResult {
    let mut job = RecordingPublication::new(
        recording,
        publisher,
        slot.clone(),
        recording.byte_len(),
        100,
    )?;
    for now in 0..4 {
        assert!(matches!(
            job.step(now, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    assert!(matches!(
        job.step(4, &NeverCancel)?,
        RecordingProgress::Published(_)
    ));
    Ok(())
}

#[path = "../../fss-reference/tests/recording_replay_contract/utc"]
mod native {
    #[allow(dead_code)]
    #[path = "fixtures.rs"]
    mod fixtures;

    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::path::Path;
    use std::process::{Command, Output, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use fixtures::*;
    use fss_cli::{ExitIdentity, execute_fss_with_exit, parse_fss_args};
    use fss_core::{
        BudgetVector, ContextAuthority, EffectIntent, EffectState, IdempotencyKey, ObligationId,
        OperationId, RootAuthoritySpec, TimestampNs,
        json_input::{Value, parse},
    };
    use fss_object::HostSpoolIo;
    use fss_reference::agent_follow::{AnchorToken, snapshot_anchor_token};
    use fss_reference::agent_orient::{DeploymentHistory, OrientLimits};
    use fss_reference::rtsp::recording_replay::time::pinned::{
        ReplayTimeReadLimits, query_replay_time_read_only,
    };
    use fss_reference::{ReferenceDeployment, ReplayCx};

    type Test<T = ()> = Result<T, Error>;
    const SITE: &str = "site:recorder-agent-query";
    const PRINCIPAL: &str = "principal:recorder-agent-query";
    const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"recorder-query-contract","version":"1"}}}"#;
    const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

    // Native publication locks must not be inherited by another concurrently spawned test.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    struct Fixture {
        source: Sealed,
        deployment: PathBuf,
    }

    impl Fixture {
        fn new(label: &str, codec: &str, unknown: bool) -> Test<Self> {
            let source = if codec == "avc" {
                let source = if unknown {
                    fixture(951, true)?
                } else {
                    rebuild_avc(fixture(951, true)?, |index, wire| {
                        if index == 0 {
                            stamp(wire, NTP_SECONDS, 0x8000_0000, 0x80, 7)?;
                        }
                        Ok(())
                    })?
                };
                seal_avc(label, &source, 2, 7)?
            } else {
                let mut packets = stamped_hevc()?;
                // Preserve a real, unknown source-only tail as well as two timed samples.
                packets[5].bytes[24] |= 1;
                seal_hevc(label, &packets[..8], &hevc_recording_support::timings(2), 7)?
            };
            let deployment = path("deployment");
            let authority = ContextAuthority::new_root(RootAuthoritySpec {
                trace_id: "trace:recorder-agent-query".to_owned(),
                operation_id: OperationId::parse("operation:recorder-agent-query")?,
                principal: PRINCIPAL.to_owned(),
                capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
                deadline: None,
                priority: 10,
                budgets: BudgetVector::default(),
                privacy_scope: "privacy:fixture".to_owned(),
                retention_scope: "retention:fixture".to_owned(),
                anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
                generation: 1,
            })?;
            let cx = ReplayCx::from_context_authority_read_only(&authority, &deployment)?;
            let mut owner = ReferenceDeployment::open(&deployment, SITE, &cx)?;
            for (name, committed) in [("prepared", false), ("committed", true)] {
                let intent = EffectIntent::new(
                    OperationId::parse(format!("operation:recorder-query:{name}"))?,
                    IdempotencyKey::parse(format!("idempotency:recorder-query:{name}"))?,
                    "fixture:notification",
                    ContentDigest::sha256(name.as_bytes()),
                    ContentDigest::sha256(b"fixture-effect-authority"),
                )?;
                owner.effects_mut().prepare(
                    intent.clone(),
                    ObligationId::parse(format!("obligation:recorder-query:{name}"))?,
                    "fixture notification observed",
                    TimestampNs(1),
                )?;
                if committed {
                    owner.effects_mut().transition(
                        &intent.operation_id,
                        EffectState::Committed,
                        TimestampNs(2),
                        None,
                        None,
                    )?;
                }
            }
            drop(owner);
            Ok(Self { source, deployment })
        }

        fn values(&self) -> Vec<(&'static str, String)> {
            let query = self.source.query();
            let scope = &query.scope;
            vec![
                ("target", "recordings".to_owned()),
                ("codec", query.codec.as_str().to_owned()),
                ("sensor", scope.recording.sensor.as_str().to_owned()),
                ("stream", scope.recording.stream.as_str().to_owned()),
                ("generation", scope.recording.generation.to_string()),
                ("source_anchor", scope.recording.anchor.to_text()),
                ("receive_clock", scope.recording.receive_clock.to_text()),
                ("decode_clock", scope.decode_clock.to_text()),
                ("time_scale", scope.time_scale.to_string()),
                ("replay_root", query.receipt_root.to_text()),
                ("replay_request", query.request.to_text()),
                ("ntp_era", query.ntp_era.to_string()),
                ("utc_start_ns", query.start_ns.to_string()),
                ("utc_end_ns", query.end_ns.to_string()),
            ]
        }

        fn cli_args(&self, extras: &[(&str, &str)]) -> Vec<OsString> {
            let mut args = vec![
                "query".into(),
                "--json".into(),
                "--root".into(),
                self.deployment.clone().into(),
                "--archive-root".into(),
                self.source.root.clone().into(),
                format!("--principal={PRINCIPAL}").into(),
                "--verify-replay-source=yes".into(),
            ];
            args.extend(
                self.values()
                    .into_iter()
                    .map(|(key, value)| format!("--{}={value}", key.replace('_', "-")).into()),
            );
            args.extend(
                extras
                    .iter()
                    .map(|(key, value)| format!("{key}={value}").into()),
            );
            args
        }

        fn mcp_arguments(&self, extra: &str) -> String {
            let fields = self
                .values()
                .into_iter()
                .map(|(key, value)| {
                    let value = if matches!(key, "time_scale" | "ntp_era") {
                        value
                    } else {
                        fss_cli::json_output::string(&value)
                    };
                    format!("\"{key}\":{value}")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{fields}{extra}}}")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.source.root);
            let _ = fs::remove_dir_all(&self.deployment);
        }
    }

    fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
        value
            .object()
            .and_then(|fields| fields.get(name))
            .ok_or_else(|| format!("missing {name}").into())
    }

    fn binary(name: &str) -> Test<PathBuf> {
        let (override_name, compiled) = match name {
            "fss" => ("FSS_BIN", option_env!("CARGO_BIN_EXE_fss")),
            "fss-mcp" => ("FSS_MCP_BIN", option_env!("CARGO_BIN_EXE_fss-mcp")),
            _ => return Err("unknown test binary".into()),
        };
        std::env::var_os(override_name)
            .or_else(|| compiled.map(OsString::from))
            .map(PathBuf::from)
            .ok_or_else(|| format!("missing {name}; set {override_name}").into())
    }

    fn captured(reader: impl Read) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        reader.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(io::Error::other("test output exceeded bound"));
        }
        Ok(bytes)
    }

    fn process(name: &str, args: &[OsString], input: Option<&str>) -> Test<Output> {
        let mut child = Command::new(binary(name)?)
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(input) = input {
            let mut stdin = child.stdin.take().ok_or("stdin pipe")?;
            stdin.write_all(input.as_bytes())?;
        }
        let stdout = child.stdout.take().ok_or("stdout pipe")?;
        let stderr = child.stderr.take().ok_or("stderr pipe")?;
        thread::scope(|scope| {
            let stdout = scope.spawn(move || captured(stdout));
            let stderr = scope.spawn(move || captured(stderr));
            let deadline = Instant::now() + Duration::from_secs(30);
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    result => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return match result {
                            Err(error) => Err(error.into()),
                            _ => Err("recorder query process timed out".into()),
                        };
                    }
                }
            };
            Ok(Output {
                status,
                stdout: stdout.join().map_err(|_| "stdout reader panicked")??,
                stderr: stderr.join().map_err(|_| "stderr reader panicked")??,
            })
        })
    }

    fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
        let mut pending = vec![root.to_owned()];
        let mut result = BTreeMap::new();
        while let Some(path) = pending.pop() {
            let kind = fs::symlink_metadata(&path)?;
            let relative = path.strip_prefix(root)?.to_owned();
            if kind.is_dir() {
                result.insert(relative, None);
                for entry in fs::read_dir(path)? {
                    pending.push(entry?.path());
                }
            } else if kind.is_file() {
                result.insert(relative, Some(fs::read(path)?));
            } else {
                return Err("unexpected fixture filesystem kind".into());
            }
        }
        Ok(result)
    }

    fn cli(fixture: &Fixture, extras: &[(&str, &str)]) -> Test<(String, ExitIdentity)> {
        let args = fixture.cli_args(extras);
        let expected = execute_fss_with_exit(parse_fss_args(args.clone())?);
        let actual = process("fss", &args, None)?;
        assert_eq!(
            actual.status.code(),
            Some(i32::from(expected.1.code)),
            "{}",
            String::from_utf8_lossy(&actual.stderr)
        );
        assert!(
            actual.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&actual.stderr)
        );
        assert_eq!(
            String::from_utf8(actual.stdout)?,
            format!("{}\n", expected.0)
        );
        Ok(expected)
    }

    fn mcp(fixture: &Fixture, allow: bool, extra: &str) -> Test<Value> {
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"query","arguments":{}}}}}"#,
            fixture.mcp_arguments(extra)
        );
        let input = format!("{INIT}\n{READY}\n{request}\n");
        let mut args = vec![
            "--root".into(),
            fixture.deployment.clone().into(),
            "--principal".into(),
            PRINCIPAL.into(),
            "--archive-root".into(),
            fixture.source.root.clone().into(),
        ];
        if allow {
            args.push("--allow-replay-source-verification".into());
        }
        let output = process("fss-mcp", &args, Some(&input))?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = String::from_utf8(output.stdout)?;
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 2, "{output}");
        Ok(parse(lines[1])?)
    }

    fn same_mcp(fixture: &Fixture, extra: &str, expected: &(String, ExitIdentity)) -> Test {
        let output = mcp(fixture, true, extra)?;
        let result = field(&output, "result")?;
        assert_eq!(
            field(result, "isError")?.boolean(),
            Some(expected.1.code != 0)
        );
        let content = field(result, "content")?
            .array()
            .and_then(|items| items.first())
            .ok_or("tool content")?;
        assert_eq!(field(content, "text")?.text(), Some(expected.0.as_str()));
        Ok(())
    }

    #[test]
    fn native_cli_and_mcp_agree_under_writer_lock_and_preserve_pending_context() -> Test {
        let _serial = serial();
        for codec in ["avc", "hevc"] {
            let fixture = Fixture::new("surface-parity", codec, false)?;
            let _writer = fixture.source.open()?;
            let mut native_request = fixture.source.query();
            native_request.limits.max_results = 32;
            let native = query_replay_time_read_only(
                &HostSpoolIo,
                &fixture.source.root,
                &native_request,
                ReplayTimeReadLimits::default(),
                &|| false,
            )?;
            if codec == "hevc" {
                assert!(!native.report.source_only.is_empty(), "HEVC tail fixture");
            }
            let archive_before = tree(&fixture.source.root)?;
            let deployment_before = tree(&fixture.deployment)?;
            let result = cli(&fixture, &[])?;
            assert_eq!(result.1, ExitIdentity::SUCCESS, "{}", result.0);
            let envelope = parse(&result.0)?;
            assert_eq!(
                field(&envelope, "schema")?.text(),
                Some("fss.agent_response_envelope.v1")
            );
            assert_eq!(
                field(&envelope, "effectiveCapabilities")?.array(),
                Some(
                    [
                        Value::Text("CAP-AGENT-QUERY-001".to_owned()),
                        Value::Text("CAP-READ-MEDIA-001".to_owned()),
                    ]
                    .as_slice()
                )
            );
            for expected in [
                "AOP-005".to_owned(),
                "fss.agent_cognitive_envelope.v1".to_owned(),
                native.report.digest.to_text(),
                native.report.index_digest.to_text(),
                "obligation:recorder-query:prepared".to_owned(),
                "obligation:recorder-query:committed".to_owned(),
            ] {
                assert!(
                    result.0.contains(&expected),
                    "missing {expected}: {}",
                    result.0
                );
            }
            for row in native
                .report
                .matches
                .iter()
                .chain(native.report.unknown.iter())
            {
                assert!(result.0.contains(&row.evidence.proof_digest.to_text()));
            }
            for row in &native.report.source_only {
                assert!(result.0.contains(&row.evidence.proof_digest.to_text()));
            }
            assert!(
                !result
                    .0
                    .contains(fixture.source.root.to_str().ok_or("UTF-8 fixture")?)
            );
            same_mcp(&fixture, "", &result)?;
            assert_eq!(cli(&fixture, &[])?, result);
            assert_eq!(tree(&fixture.source.root)?, archive_before);
            assert_eq!(tree(&fixture.deployment)?, deployment_before);
        }
        Ok(())
    }

    #[test]
    fn missing_time_evidence_remains_visible_in_all_surfaces() -> Test {
        let _serial = serial();
        let fixture = Fixture::new("unknown-time", "avc", true)?;
        let result = cli(&fixture, &[])?;
        assert_eq!(result.1, ExitIdentity::SUCCESS, "{}", result.0);
        assert!(result.0.contains("unknown"));
        assert!(result.0.contains("absence"));
        let mut request = fixture.source.query();
        request.limits.max_results = 32;
        let native = query_replay_time_read_only(
            &HostSpoolIo,
            &fixture.source.root,
            &request,
            ReplayTimeReadLimits::default(),
            &|| false,
        )?;
        assert_eq!(native.report.unknown.len(), 2);
        assert!(native.report.matches.is_empty());
        for row in &native.report.unknown {
            assert!(result.0.contains(&row.evidence.proof_digest.to_text()));
        }
        same_mcp(&fixture, "", &result)?;
        Ok(())
    }

    #[test]
    fn budgets_and_stale_pins_refuse_without_partial_source_rows_or_mutation() -> Test {
        let _serial = serial();
        let fixture = Fixture::new("bounded-refusal", "hevc", false)?;
        let archive_before = tree(&fixture.source.root)?;
        let deployment_before = tree(&fixture.deployment)?;
        for (option, value, extra) in [
            ("--max-query-results", "1", ",\"max_query_results\":1"),
            (
                "--max-query-read-bytes",
                "1",
                ",\"max_query_read_bytes\":\"1\"",
            ),
            ("--max-query-io-calls", "1", ",\"max_query_io_calls\":\"1\""),
        ] {
            let result = cli(&fixture, &[(option, value)])?;
            assert_eq!(result.1, ExitIdentity::AGENT_REFUSED, "{}", result.0);
            assert!(!result.0.contains("packet_set_digest"));
            assert!(!result.0.contains("packet_set="));
            assert!(!result.0.contains("claim:recordings-replay:match:"));
            assert!(!result.0.contains("claim:recordings-replay:unknown:"));
            assert!(!result.0.contains("claim:recordings-replay:source-only:"));
            same_mcp(&fixture, extra, &result)?;
        }
        let history = DeploymentHistory::read(&fixture.deployment, &OrientLimits::default())?;
        let snapshot = history.snapshot_at(history.head())?;
        let mut stale = snapshot_anchor_token(&snapshot);
        let tail = stale.pop().ok_or("anchor tail")?;
        stale.push(if tail == 'a' { 'b' } else { 'a' });
        assert!(AnchorToken::parse(&stale).is_some());
        let result = cli(&fixture, &[("--anchor", &stale)])?;
        assert_eq!(result.1, ExitIdentity::AGENT_REFUSED);
        same_mcp(
            &fixture,
            &format!(",\"anchor\":{}", fss_cli::json_output::string(&stale)),
            &result,
        )?;
        assert_eq!(tree(&fixture.source.root)?, archive_before);
        assert_eq!(tree(&fixture.deployment)?, deployment_before);
        Ok(())
    }

    #[test]
    fn mcp_clients_cannot_enable_source_verification_or_override_owner_scope() -> Test {
        let _serial = serial();
        let fixture = Fixture::new("owner-only", "avc", false)?;
        let archive_before = tree(&fixture.source.root)?;
        let deployment_before = tree(&fixture.deployment)?;
        for (allow, extra) in [
            (false, ""),
            (false, ",\"verify_replay_source\":true"),
            (true, ",\"verify_replay_source\":true"),
            (true, ",\"allow_replay_source_verification\":true"),
            (true, ",\"archive_root\":\"/private-override-sentinel\""),
            (true, ",\"principal\":\"principal:other\""),
            (true, ",\"clock_slot\":\"unrelated-clock\""),
            (true, ",\"start_utc_ns\":\"0\""),
        ] {
            let output = mcp(&fixture, allow, extra)?;
            let error = field(&output, "error")?;
            assert_eq!(field(error, "code")?.integer(), Some(-32602));
        }
        assert_eq!(tree(&fixture.source.root)?, archive_before);
        assert_eq!(tree(&fixture.deployment)?, deployment_before);
        Ok(())
    }
}
