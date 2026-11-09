#![forbid(unsafe_code)]
//! Genuine retained XML -> canonical Rust/CLI/MCP transcript parity and no-write contract.
//! Synthetic vendor declarations establish wiring, not camera or physical-world qualification.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::{ExitIdentity, execute_fss_with_exit, parse_fss_args};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, EffectIntent, EffectState,
    IdempotencyKey, ObligationId, OperationId, PrincipalId, RootAuthoritySpec, SensorId,
    TimestampNs,
    json_input::{Value, parse},
};
use fss_object::HostSpoolIo;
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_onvif::{
    OnvifAnalysis, OnvifQueryLimits, OnvifQueryRequest, query_onvif_in_deployment,
};
use fss_reference::onvif::metadata::tracks::TrackSourcePin;
use fss_reference::onvif::metadata::{SourceBinding, retain};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const SITE: &str = "site:onvif-agent-query-process";
const PRINCIPAL: &str = "principal:onvif-agent-query-process";
const PRIVATE_MODULE: &str = "private-query-module-8675309-canary";
const PRIVATE_ID: &str = "8675309";
const PRIVATE_RENAMED_ID: &str = "8675310";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"onvif-query-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

struct Fixture {
    root: PathBuf,
    pin: TrackSourcePin,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let mut selected = None;
        for attempt in 0..64 {
            let root = std::env::temp_dir().join(format!(
                "fss-onvif-agent-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    selected = Some(root);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let root = selected.ok_or("owned fixture directory capacity")?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-agent-query-process".to_owned(),
            operation_id: OperationId::parse("operation:onvif-agent-query-process")?,
            principal: PRINCIPAL.to_owned(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(128 * 1024 * 1024)
                .storage_operations(16_384)
                .build()?,
            privacy_scope: "privacy:fixture".to_owned(),
            retention_scope: "retention:fixture".to_owned(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, &root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let source = retain(
            &mut deployment,
            SourceBinding {
                sensor_id: SensorId::parse("sensor:front")?,
                device_generation: ContentDigest::sha256(b"device"),
                profile_generation: ContentDigest::sha256(b"profile"),
                profile_token: "private-query-profile-canary".to_owned(),
                receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
            },
            &xml(),
            &cx,
        )?;
        let pin = TrackSourcePin::Xml {
            identity: source.identity(),
            root: source.publication_root(),
        };
        // Readers must leave both obligations in their exact pending states. Opening a
        // recovery writer here would rewrite the journal and fail the byte-tree check.
        for (name, commit) in [("prepared", false), ("committed", true)] {
            let intent = EffectIntent::new(
                OperationId::parse(format!("operation:onvif-query:{name}"))?,
                IdempotencyKey::parse(format!("idempotency:onvif-query:{name}"))?,
                "fixture:notification",
                ContentDigest::sha256(name.as_bytes()),
                ContentDigest::sha256(b"query-effect-authority"),
            )?;
            deployment.effects_mut().prepare(
                intent.clone(),
                ObligationId::parse(format!("obligation:onvif-query:{name}"))?,
                "fixture notification observed",
                TimestampNs(1),
            )?;
            if commit {
                deployment.effects_mut().transition(
                    &intent.operation_id,
                    EffectState::Committed,
                    TimestampNs(2),
                    None,
                    None,
                )?;
            }
        }
        drop(deployment);
        Ok(Self { root, pin })
    }
    fn selector(&self) -> String {
        format!(
            r#"[{{"kind":"xml","identity":"{}","root":"{}"}}]"#,
            self.pin.identity(),
            self.pin.root()
        )
    }
    fn native(&self) -> Test<fss_reference::agent_onvif::DeploymentOnvifQuery> {
        Ok(query_onvif_in_deployment(
            &HostSpoolIo,
            &self.root,
            &OnvifQueryRequest {
                sources: vec![self.pin],
                analysis: OnvifAnalysis::Tracks,
                max_entries: 32,
                principal: PrincipalId::parse(PRINCIPAL)?,
                expected_anchor: None,
            },
            OnvifQueryLimits::default(),
            &|| false,
        )?)
    }
    fn policy(&self) -> Test<String> {
        let query = self.native()?;
        let frame = query.native.tracks.frames.first().ok_or("original frame")?;
        let object = query
            .native
            .tracks
            .occurrences
            .first()
            .ok_or("original occurrence")?;
        let module = frame.module_digest.ok_or("named module")?;
        Ok(format!(
            r#"{{"schema":"fss.onvif_vendor_zone_policy.v1","coordinates":"raw_vendor_object_millionths","zones":[{{"id":"entry","scope":"{}","module_digest":"{module}","frame_transform_digest":"{}","object_transform_digest":"{}","min":[0,0],"max":[1000000,1000000],"margin":0}}]}}"#,
            frame.reference.scope, frame.transformation_digest, object.transformation_digest
        ))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn xml() -> Vec<u8> {
    let object = |id: &str, behaviour: &str| {
        format!(
            r#"<t:Object ObjectId="{id}"><t:Appearance><t:Shape><t:BoundingBox left="0.1" right="0.2" top="0.2" bottom="0.1"/><t:CenterOfGravity x="0.15" y="0.15"/></t:Shape></t:Appearance>{behaviour}</t:Object>"#
        )
    };
    format!(r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics><t:Frame UtcTime="2026-10-28T00:00:01Z" Source="{PRIVATE_MODULE}">{}</t:Frame><t:Frame UtcTime="2026-10-28T00:00:02Z" Source="{PRIVATE_MODULE}">{}<t:ObjectTree><t:Rename><t:from ObjectId="{PRIVATE_ID}"/><t:to ObjectId="{PRIVATE_RENAMED_ID}"/></t:Rename></t:ObjectTree></t:Frame><t:Frame UtcTime="2026-10-28T00:00:03Z" Source="{PRIVATE_MODULE}">{}</t:Frame></t:VideoAnalytics></t:MetadataStream>"#,
        object(PRIVATE_ID, ""), object(PRIVATE_RENAMED_ID, ""), object(PRIVATE_RENAMED_ID, "<t:Behaviour><t:Idle/><t:Removed/></t:Behaviour>")).into_bytes()
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
        .ok_or_else(|| format!("missing {name} binary; set {override_name}").into())
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
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("ONVIF process fixture timed out".into());
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error.into());
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
fn tree(root: &Path) -> Test<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_owned()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_owned();
        if metadata.is_dir() {
            result.insert(relative, (true, Vec::new()));
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(relative, (false, fs::read(path)?));
        } else {
            return Err("unexpected fixture filesystem kind".into());
        }
    }
    Ok(result)
}
fn quote(text: &str) -> String {
    fss_cli::json_output::string(text)
}
fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(name))
        .ok_or_else(|| format!("missing {name}").into())
}
fn cli(
    fixture: &Fixture,
    analysis: &str,
    policy: Option<&str>,
    extras: &[(&str, &str)],
) -> Test<(String, ExitIdentity)> {
    let mut args: Vec<OsString> = vec![
        "query".into(),
        "--json".into(),
        "--root".into(),
        fixture.root.clone().into(),
        format!("--principal={PRINCIPAL}").into(),
        "--target=onvif".into(),
        format!("--analysis={analysis}").into(),
        format!("--sources={}", fixture.selector()).into(),
    ];
    if let Some(policy) = policy {
        args.push(format!("--zone-policy={policy}").into());
    }
    args.extend(
        extras
            .iter()
            .map(|(name, value)| format!("{name}={value}").into()),
    );
    let expected = execute_fss_with_exit(parse_fss_args(args.clone())?);
    let output = process("fss", &args, None)?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(expected.1.code)),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout)?,
        format!("{}\n", expected.0)
    );
    Ok(expected)
}
fn mcp(fixture: &Fixture, arguments: &str) -> Test<Value> {
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"query","arguments":{arguments}}}}}"#
    );
    let input = format!("{INIT}\n{READY}\n{request}\n");
    let output = process(
        "fss-mcp",
        &[
            "--root".into(),
            fixture.root.clone().into(),
            "--principal".into(),
            PRINCIPAL.into(),
        ],
        Some(&input),
    )?;
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
    assert_eq!(lines.len(), 2);
    Ok(parse(lines[1])?)
}
fn same_mcp(
    fixture: &Fixture,
    analysis: &str,
    policy: Option<&str>,
    extra: &str,
    expected: &(String, ExitIdentity),
) -> Test {
    let policy = policy.map_or_else(String::new, |policy| format!(",\"zone_policy\":{policy}"));
    let args = format!(
        r#"{{"target":"onvif","analysis":"{analysis}","sources":{}{policy}{extra}}}"#,
        fixture.selector()
    );
    let output = mcp(fixture, &args)?;
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
fn tracks_lifecycle_and_zones_match_across_real_processes_and_leave_pending_state_untouched() -> Test
{
    let fixture = Fixture::new("parity")?;
    let policy = fixture.policy()?;
    let anchor = fixture.native()?.anchor_token;
    let before = tree(&fixture.root)?;
    for analysis in ["tracks", "lifecycle", "zones"] {
        let selected_policy = (analysis == "zones").then_some(policy.as_str());
        let expected = cli(
            &fixture,
            analysis,
            selected_policy,
            &[("--anchor", &anchor)],
        )?;
        assert_eq!(expected.1, ExitIdentity::SUCCESS, "{}", expected.0);
        let value = parse(&expected.0)?;
        assert_eq!(
            field(&value, "schema")?.text(),
            Some("fss.agent_response_envelope.v1")
        );
        assert!(expected.0.contains("fss.agent_cognitive_envelope.v1"));
        assert!(expected.0.contains("AOP-005"));
        assert!(expected.0.contains(&fixture.pin.root().to_text()));
        assert!(expected.0.contains("obligation:onvif-query:prepared"));
        assert!(expected.0.contains("obligation:onvif-query:committed"));
        for private in [
            PRIVATE_MODULE,
            PRIVATE_ID,
            PRIVATE_RENAMED_ID,
            "private-query-profile-canary",
            "2026-10-28T",
            "<t:",
        ] {
            assert!(
                !expected.0.contains(private),
                "raw vendor value escaped: {private}"
            );
        }
        if analysis == "lifecycle" {
            assert!(expected.0.contains("kind=rename"));
            assert!(expected.0.contains("idle=true, removed=true"));
        }
        if analysis == "zones" {
            assert!(expected.0.contains("unavailable") && expected.0.contains("zone-cell:"));
        }
        same_mcp(
            &fixture,
            analysis,
            selected_policy,
            &format!(",\"anchor\":{}", quote(&anchor)),
            &expected,
        )?;
        // The semantic native policy digest, not JSON whitespace or object-key order,
        // determines the same request and complete response across processes.
        if let Some(policy) = selected_policy {
            let pretty = policy.replace(',', ",\n  ").replace('{', "{\n  ");
            assert_eq!(
                cli(&fixture, analysis, Some(&pretty), &[("--anchor", &anchor)])?,
                expected
            );
        }
    }
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn row_and_stale_anchor_refusals_are_lossless_across_processes() -> Test {
    let fixture = Fixture::new("refusals")?;
    let before = tree(&fixture.root)?;
    let limited = cli(&fixture, "lifecycle", None, &[("--max-entries", "1")])?;
    assert_eq!(limited.1, ExitIdentity::AGENT_REFUSED);
    assert!(!limited.0.contains("lifecycle-operation:"));
    same_mcp(&fixture, "lifecycle", None, ",\"max_entries\":1", &limited)?;
    let current = fixture.native()?.anchor_token;
    let mut stale = current.clone();
    let tail = stale.pop().ok_or("anchor tail")?;
    stale.push(if tail == 'a' { 'b' } else { 'a' });
    assert!(AnchorToken::parse(&stale).is_some());
    let refused = cli(&fixture, "tracks", None, &[("--anchor", &stale)])?;
    assert_eq!(refused.1, ExitIdentity::AGENT_REFUSED);
    assert!(!refused.0.contains("occurrence:"));
    same_mcp(
        &fixture,
        "tracks",
        None,
        &format!(",\"anchor\":{}", quote(&stale)),
        &refused,
    )?;
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn mcp_denies_root_principal_disclosure_and_file_indirection_before_execution() -> Test {
    let fixture = Fixture::new("denials")?;
    let before = tree(&fixture.root)?;
    for extra in [
        r#", "root":"/outside-private-canary""#,
        r#", "principal":"principal:other""#,
        r#", "archive_root":"/outside-private-canary""#,
        r#", "include_values":true"#,
        r#", "hydrate":"H3""#,
        r#", "continuation":"any""#,
        r#", "zone_policy":"/outside-private-canary""#,
    ] {
        let args = format!(
            r#"{{"target":"onvif","analysis":"tracks","sources":{}{extra}}}"#,
            fixture.selector()
        );
        let response = mcp(&fixture, &args)?;
        assert_eq!(
            field(field(&response, "error")?, "code")?.integer(),
            Some(-32602)
        );
        assert!(!format!("{response:?}").contains("outside-private-canary"));
    }
    for value in ["\"/outside-private-canary\"", "\"-\"", "{}"] {
        let args = format!(r#"{{"target":"onvif","analysis":"tracks","sources":{value}}}"#);
        let response = mcp(&fixture, &args)?;
        assert_eq!(
            field(field(&response, "error")?, "code")?.integer(),
            Some(-32602)
        );
    }
    let bad_root = ContentDigest::sha256(b"unpublished-root");
    let args = format!(
        r#"{{"target":"onvif","analysis":"tracks","sources":[{{"kind":"xml","identity":"{}","root":"{bad_root}"}}]}}"#,
        fixture.pin.identity()
    );
    let response = mcp(&fixture, &args)?;
    assert_eq!(
        field(field(&response, "result")?, "isError")?.boolean(),
        Some(true)
    );
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}
