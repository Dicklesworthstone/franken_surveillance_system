#![forbid(unsafe_code)]
//! Operator site onboarding through the actual CLI binaries. Synthetic control documents
//! exercise planning only: no camera, credentials, rights service, or retained media is needed.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::agent_json::string;
use fss_core::ContentDigest;
use fss_core::json_input::{self, Value};
use fss_reference::site::parse_manifest;

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Directory(PathBuf);

impl Directory {
    fn new(name: &str) -> Test<Self> {
        let path = std::env::temp_dir().join(format!("fss-site-cli-{name}-{}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> Test<PathBuf> {
        let path = self.0.join(name);
        fs::write(&path, bytes)?;
        Ok(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary(native: bool) -> Test<PathBuf> {
    let (override_name, built) = if native {
        (
            "FSS_CAPTURE_RTSP_BIN",
            option_env!("CARGO_BIN_EXE_fss-capture-rtsp"),
        )
    } else {
        ("FSS_BIN", option_env!("CARGO_BIN_EXE_fss"))
    };
    std::env::var_os(override_name)
        .map(PathBuf::from)
        .or_else(|| built.map(PathBuf::from))
        .ok_or_else(|| format!("required CLI binary unavailable: {override_name}").into())
}

fn run(native: bool, args: &[OsString]) -> Test<Output> {
    Ok(Command::new(binary(native)?).args(args).output()?)
}

fn good(output: Output) -> Test<Value> {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(json_input::parse(&String::from_utf8(output.stdout)?)?)
}

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("missing output field: {name}").into())
}

fn text<'a>(value: &'a Value, name: &str) -> Test<&'a str> {
    field(value, name)?
        .text()
        .ok_or_else(|| format!("not text: {name}").into())
}

fn boolean(value: &Value, name: &str) -> Test<bool> {
    field(value, name)?
        .boolean()
        .ok_or_else(|| format!("not boolean: {name}").into())
}

fn items<'a>(value: &'a Value, name: &str) -> Test<&'a [Value]> {
    field(value, name)?
        .array()
        .ok_or_else(|| format!("not array: {name}").into())
}

fn object_mut(value: &mut Value) -> Test<&mut BTreeMap<String, Value>> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err("expected fixture object".into()),
    }
}

fn array_mut(value: &mut Value) -> Test<&mut Vec<Value>> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err("expected fixture array".into()),
    }
}

fn render(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => string(value),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(render).collect::<Vec<_>>().join(",")
        ),
        Value::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(key, value)| format!("{}:{}", string(key), render(value)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn set(value: &mut Value, key: &str, replacement: Value) -> Test {
    let _ = object_mut(value)?.insert(key.to_owned(), replacement);
    Ok(())
}

fn source_mut(manifest: &mut Value, index: usize) -> Test<&mut Value> {
    let sources = object_mut(manifest)?
        .get_mut("sources")
        .ok_or("missing fixture sources")?;
    array_mut(sources)?
        .get_mut(index)
        .ok_or_else(|| "missing fixture source".into())
}

/// Plain synthetic control inputs, not simulated hardware qualification or signed rights.
struct Fixture {
    directory: Directory,
    manifest: Value,
    probes: Value,
}

impl Fixture {
    fn new(name: &str, peer: &str) -> Test<Self> {
        let directory = Directory::new(name)?;
        let peer_address: std::net::SocketAddr = peer.parse()?;
        let authority = string(&format!("camera.test:{}", peer_address.port()));
        let credential = string(
            directory
                .0
                .join("credentials-not-created")
                .to_str()
                .ok_or("UTF-8 fixture path")?,
        );
        let mut sources = Vec::new();
        for (index, source_id) in ["source:front", "source:back"].into_iter().enumerate() {
            let authentication = if index == 0 {
                "null".to_owned()
            } else {
                format!(
                    r#"{{"credential_file":{credential},"realm":"owner-realm","legacy_md5":false,"legacy_no_qop":false}}"#
                )
            };
            sources.push(format!(r#"{{"source_id":{},"generation":1,"kind":"rtsp","peer":{},"authority":{authority},"presentation":"/camera/{index}/main","control_root":"/camera/{index}","stream_role":"main","authentication":{authentication},"retention_class":"ordinary","rights_verdict_ref":"fldt:rights:test-lease","zones":[],"payment_masks":[],"max_connections":1,"owner_authorized":true,"plaintext":true,"retain_originals":true}}"#,
                string(source_id), string(peer)));
        }
        let manifest = json_input::parse(&format!(
            r#"{{"schema":"fss.site_camera_manifest.v1","site_id":"site:test-camera","generation":1,"network_route":"lan","sources":[{}]}}"#,
            sources.join(",")
        ))?;
        let parsed = parse_manifest(render(&manifest).as_bytes())?;
        let digest = parsed.digest()?.to_text();
        let mut probes = Vec::new();
        for (index, (source_id, codec, parameters)) in
            [("source:front", "avc", 2), ("source:back", "hevc", 3)]
                .into_iter()
                .enumerate()
        {
            let parameters = (0..parameters)
                .map(|number| {
                    string(
                        &ContentDigest::sha256(
                            format!("synthetic-{codec}-parameter-{number}").as_bytes(),
                        )
                        .to_text(),
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            probes.push(json_input::parse(&format!(r#"{{"schema":"fss.site_probe_receipt.v1","site_id":"site:test-camera","source_id":{},"manifest_digest":{},"source_generation":1,"peer":{},"authority":{authority},"presentation":"/camera/{index}/main","control_root":"/camera/{index}","media_index":0,"rtp_channel":0,"rtcp_channel":1,"sdp_digest":{},"codec":"{codec}","payload_type":96,"ssrc":{},"frame_duration_ticks":3600,"clock_rate_hz":90000,"observed_frames":4,"first_rtp_timestamp":1000,"last_rtp_timestamp":11800,"parameter_set_digests":[{parameters}],"server_identity":"fixture-server"}}"#,
                string(source_id), string(&digest), string(peer),
                string(&ContentDigest::sha256(format!("synthetic-{codec}-sdp").as_bytes()).to_text()), index + 7))?);
        }
        Ok(Self {
            directory,
            manifest,
            probes: Value::Array(probes),
        })
    }

    fn write(&self) -> Test {
        self.directory
            .write("manifest.json", render(&self.manifest))?;
        self.directory.write("probes.json", render(&self.probes))?;
        Ok(())
    }

    fn rebind_manifest(&mut self) -> Test {
        let manifest = parse_manifest(render(&self.manifest).as_bytes())?;
        let digest = manifest.digest()?.to_text();
        for receipt in array_mut(&mut self.probes)? {
            set(receipt, "manifest_digest", Value::Text(digest.clone()))?;
        }
        Ok(())
    }

    fn probe_mut(&mut self, index: usize) -> Test<&mut Value> {
        array_mut(&mut self.probes)?
            .get_mut(index)
            .ok_or_else(|| "missing fixture receipt".into())
    }

    fn args(&self) -> Vec<OsString> {
        let mut args = vec!["site".into(), "plan".into()];
        for (key, value) in [
            ("--manifest", self.directory.0.join("manifest.json")),
            ("--probes", self.directory.0.join("probes.json")),
            (
                "--archive-root",
                self.directory.0.join("archive-not-created"),
            ),
            ("--pins-root", self.directory.0.join("pins-not-created")),
        ] {
            args.extend([key.into(), value.into_os_string()]);
        }
        args.extend([
            "--epoch".into(),
            "9".into(),
            "--stop-after-pictures".into(),
            "2".into(),
            "--json".into(),
        ]);
        args
    }

    fn untouched(&self) {
        for name in [
            "archive-not-created",
            "pins-not-created",
            "credentials-not-created",
        ] {
            assert!(
                !self.directory.0.join(name).exists(),
                "planning created or consumed an output/secret path"
            );
        }
    }
}

fn replace_arg(args: &mut [OsString], key: &str, value: impl Into<OsString>) -> Test {
    let position = args
        .iter()
        .position(|argument| argument == key)
        .ok_or("missing fixture argument")?;
    let slot = args
        .get_mut(position + 1)
        .ok_or("missing fixture argument value")?;
    *slot = value.into();
    Ok(())
}

fn argv(value: &Value) -> Test<Vec<OsString>> {
    items(value, "argv")?
        .iter()
        .map(|argument| {
            argument
                .text()
                .map(OsString::from)
                .ok_or_else(|| "non-string planned argument".into())
        })
        .collect()
}

fn native_value<'a>(args: &'a [OsString], name: &str) -> Test<&'a str> {
    args.chunks_exact(2)
        .find(|pair| pair[0] == name)
        .and_then(|pair| pair[1].to_str())
        .ok_or_else(|| format!("missing native option {name}").into())
}

fn validate_args(path: &Path) -> Vec<OsString> {
    vec![
        "site".into(),
        "validate".into(),
        "--manifest".into(),
        path.as_os_str().to_owned(),
        "--json".into(),
    ]
}

fn refused(output: Output, expected: Option<&str>, canaries: &[&str]) -> Test<Value> {
    assert_eq!(output.status.code(), Some(2));
    for bytes in [&output.stdout, &output.stderr] {
        let rendered = String::from_utf8_lossy(bytes);
        for canary in canaries {
            assert!(!rendered.contains(canary), "refusal exposed input canary");
        }
    }
    let diagnostic = json_input::parse(&String::from_utf8(output.stdout)?)?;
    assert_eq!(text(&diagnostic, "schema")?, "fss.site_diagnostic.v1");
    if let Some(expected) = expected {
        assert_eq!(text(&diagnostic, "error_id")?, expected);
    }
    for key in [
        "device_contacted",
        "credentials_read",
        "effect_started",
        "partial_plan",
    ] {
        assert!(!boolean(&diagnostic, key)?);
    }
    assert!(
        !diagnostic
            .object()
            .is_some_and(|fields| fields.contains_key("sources"))
    );
    Ok(diagnostic)
}

fn no_connection(listener: &TcpListener) -> Test {
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("planning contacted a camera".into()),
    }
}

#[test]
fn multi_source_avc_and_hevc_plans_match_native_cli_without_contact_or_secret_reads() -> Test {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let fixture = Fixture::new("native-equivalence", &listener.local_addr()?.to_string())?;
    fixture.write()?;

    let validation = good(run(
        false,
        &validate_args(&fixture.directory.0.join("manifest.json")),
    )?)?;
    assert_eq!(text(&validation, "schema")?, "fss.site_validation.v1");
    assert_eq!(field(&validation, "source_count")?.integer(), Some(2));
    for key in [
        "device_contacted",
        "credentials_read",
        "rights_verdict_verified",
        "capture_authorized",
    ] {
        assert!(!boolean(&validation, key)?);
    }

    let output = run(false, &fixture.args())?;
    let bytes = output.stdout.clone();
    let site = good(output)?;
    assert_eq!(text(&site, "schema")?, "fss.site_capture_plan.v1");
    assert!(
        !site
            .object()
            .is_some_and(|fields| fields.contains_key("reserved_pins_root"))
    );
    for key in [
        "effects_started",
        "executor_available",
        "rights_leases_verified",
    ] {
        assert!(!boolean(&site, key)?);
    }
    assert_eq!(
        run(false, &fixture.args())?.stdout,
        bytes,
        "identical request changed plan bytes"
    );
    let site_text = String::from_utf8(bytes)?;
    let sources = items(&site, "sources")?;
    assert_eq!(sources.len(), 2);
    let mut identities: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (index, source) in sources.iter().enumerate() {
        assert_eq!(
            text(source, "source_id")?,
            ["source:front", "source:back"][index]
        );
        assert_eq!(
            field(source, "source_index")?.integer(),
            Some(index as i128)
        );
        assert_eq!(text(source, "command")?, "fss-capture-rtsp");
        let args = argv(source)?;
        assert!(!args.chunks_exact(2).any(|pair| pair[0] == "--approve"));
        assert_eq!(native_value(&args, "--codec")?, ["avc", "hevc"][index]);
        assert_eq!(native_value(&args, "--ssrc")?, (index + 7).to_string());
        assert_eq!(native_value(&args, "--frame-duration-ticks")?, "3600");
        assert_eq!(native_value(&args, "--stop-after-pictures")?, "2");
        if index == 1 {
            assert!(args.iter().any(|arg| arg == "--credential-file"));
        }
        let native_output = run(true, &args)?;
        let native_text = String::from_utf8(native_output.stdout.clone())?;
        let native = good(native_output)?;
        assert_eq!(field(source, "native_plan")?, &native);
        assert_eq!(text(source, "native_approval")?, text(&native, "approval")?);
        assert!(
            site_text.contains(&format!("\"native_plan\":{}", native_text.trim_end())),
            "site plan changed the native JSON preview bytes"
        );
        for name in [
            "--root",
            "--pins",
            "--sensor-id",
            "--stream-id",
            "--ingress",
            "--journal-id",
            "--receive-clock",
        ] {
            identities
                .entry(name)
                .or_default()
                .push(native_value(&args, name)?.to_owned());
        }
    }
    for (name, values) in identities {
        assert_ne!(values[0], values[1], "two sources shared {name}");
    }
    no_connection(&listener)?;
    fixture.untouched();
    Ok(())
}

#[test]
fn receipt_order_does_not_change_source_order_or_approval_and_changed_epoch_does() -> Test {
    let mut fixture = Fixture::new("ordering", "127.0.0.1:8554")?;
    fixture.write()?;
    let original = good(run(false, &fixture.args())?)?;
    array_mut(&mut fixture.probes)?.reverse();
    fixture.write()?;
    let reordered = good(run(false, &fixture.args())?)?;
    assert_eq!(reordered, original);

    let mut next_args = fixture.args();
    replace_arg(&mut next_args, "--epoch", "10")?;
    let next = good(run(false, &next_args)?)?;
    assert_ne!(text(&next, "approval")?, text(&original, "approval")?);
    for (old, new) in items(&original, "sources")?
        .iter()
        .zip(items(&next, "sources")?)
    {
        assert_ne!(text(old, "native_approval")?, text(new, "native_approval")?);
        let old_args = argv(old)?;
        let new_args = argv(new)?;
        assert_ne!(
            native_value(&old_args, "--root")?,
            native_value(&new_args, "--root")?
        );
        assert_ne!(
            native_value(&old_args, "--journal-id")?,
            native_value(&new_args, "--journal-id")?
        );
    }
    fixture.untouched();
    Ok(())
}

#[test]
fn timestamp_wrap_and_zero_ssrc_are_exact_observations_not_default_substitutions() -> Test {
    let mut fixture = Fixture::new("rtp-wrap", "127.0.0.1:8554")?;
    let first = u32::MAX - 5000;
    for (key, value) in [
        ("first_rtp_timestamp", first),
        ("last_rtp_timestamp", first.wrapping_add(10_800)),
        ("ssrc", 0),
    ] {
        set(fixture.probe_mut(0)?, key, Value::Number(value.to_string()))?;
    }
    fixture.write()?;
    let plan = good(run(false, &fixture.args())?)?;
    let args = argv(&items(&plan, "sources")?[0])?;
    assert_eq!(native_value(&args, "--ssrc")?, "0");
    assert_eq!(native_value(&args, "--frame-duration-ticks")?, "3600");
    fixture.untouched();
    Ok(())
}

#[test]
fn one_bad_receipt_refuses_the_entire_multi_source_plan() -> Test {
    let mut fixture = Fixture::new("receipt-refusals", "127.0.0.1:8554")?;
    let baseline = fixture.probes.clone();
    let digest = ContentDigest::sha256(b"different manifest").to_text();
    for (field_name, replacement) in [
        ("manifest_digest", Value::Text(digest)),
        ("site_id", Value::Text("site:foreign".to_owned())),
        ("source_id", Value::Text("source:foreign".to_owned())),
        ("source_generation", Value::Number("2".to_owned())),
        ("peer", Value::Text("127.0.0.1:8555".to_owned())),
        ("authority", Value::Text("foreign.test:8554".to_owned())),
        ("presentation", Value::Text("/foreign/main".to_owned())),
        ("control_root", Value::Text("/foreign".to_owned())),
        ("frame_duration_ticks", Value::Number("3601".to_owned())),
        ("last_rtp_timestamp", Value::Number("11801".to_owned())),
        ("observed_frames", Value::Number("1".to_owned())),
        ("clock_rate_hz", Value::Number("8000".to_owned())),
        ("payload_type", Value::Number("128".to_owned())),
        ("rtcp_channel", Value::Number("0".to_owned())),
    ] {
        fixture.probes = baseline.clone();
        set(fixture.probe_mut(1)?, field_name, replacement)?;
        fixture.write()?;
        refused(run(false, &fixture.args())?, None, &[])?;
        fixture.untouched();
    }
    for variant in 0..3 {
        fixture.probes = baseline.clone();
        let receipts = array_mut(&mut fixture.probes)?;
        match variant {
            0 => {
                let _ = receipts.pop();
            }
            1 => {
                receipts[1] = receipts[0].clone();
            }
            _ => {
                receipts.push(receipts[0].clone());
            }
        }
        fixture.write()?;
        refused(run(false, &fixture.args())?, None, &[])?;
        fixture.untouched();
    }
    Ok(())
}

#[test]
fn source_permissions_and_payment_masks_cannot_fall_through_to_capture() -> Test {
    let mut fixture = Fixture::new("source-refusals", "127.0.0.1:8554")?;
    let baseline = fixture.manifest.clone();
    for permission in ["owner_authorized", "plaintext", "retain_originals"] {
        fixture.manifest = baseline.clone();
        set(
            source_mut(&mut fixture.manifest, 1)?,
            permission,
            Value::Bool(false),
        )?;
        fixture.rebind_manifest()?;
        fixture.write()?;
        // A denied intent is valid configuration, but cannot compile affirmative native flags.
        good(run(
            false,
            &validate_args(&fixture.directory.0.join("manifest.json")),
        )?)?;
        refused(run(false, &fixture.args())?, Some("ERR-SITE-PLAN-001"), &[])?;
    }
    fixture.manifest = baseline.clone();
    set(
        source_mut(&mut fixture.manifest, 1)?,
        "payment_masks",
        json_input::parse(r#"[{"x":100000,"y":100000,"width":250000,"height":200000}]"#)?,
    )?;
    fixture.rebind_manifest()?;
    fixture.write()?;
    refused(run(false, &fixture.args())?, Some("ERR-SITE-PLAN-001"), &[])?;

    for kind in ["payment", "payment_terminal", "lane_pay"] {
        fixture.manifest = baseline.clone();
        set(
            source_mut(&mut fixture.manifest, 1)?,
            "zones",
            json_input::parse(&format!(
                r#"[{{"zone_id":"zone:private-payment","kind":"{kind}","vertices":[[0,0],[100000,0],[100000,100000],[0,100000]]}}]"#,
            ))?,
        )?;
        fixture.rebind_manifest()?;
        fixture.write()?;
        // A missing mask cannot turn a declared payment zone into permission to retain it.
        refused(run(false, &fixture.args())?, Some("ERR-SITE-PLAN-001"), &[])?;
    }

    fixture.untouched();
    Ok(())
}

#[test]
fn destinations_are_separate_and_credentials_cannot_collide_with_any_source_output() -> Test {
    let mut fixture = Fixture::new("destinations", "127.0.0.1:8554")?;
    fixture.write()?;
    for root in [
        fixture.directory.0.join("archive-not-created"),
        fixture.directory.0.join("archive-not-created/child"),
    ] {
        let mut args = fixture.args();
        replace_arg(&mut args, "--pins-root", root.into_os_string())?;
        refused(run(false, &args)?, Some("ERR-SITE-PLAN-001"), &[])?;
    }
    let plan = good(run(false, &fixture.args())?)?;
    let first = argv(&items(&plan, "sources")?[0])?;
    let foreign_credential = PathBuf::from(native_value(&first, "--root")?).join("credentials");
    let authentication = object_mut(source_mut(&mut fixture.manifest, 1)?)?
        .get_mut("authentication")
        .ok_or("fixture authentication")?;
    set(
        authentication,
        "credential_file",
        Value::Text(
            foreign_credential
                .to_str()
                .ok_or("UTF-8 credential path")?
                .to_owned(),
        ),
    )?;
    fixture.rebind_manifest()?;
    fixture.write()?;
    refused(run(false, &fixture.args())?, Some("ERR-SITE-PLAN-001"), &[])?;
    fixture.untouched();
    Ok(())
}

#[test]
fn direct_nvr_channels_compile_but_discovery_source_kinds_require_their_own_planners() -> Test {
    let mut fixture = Fixture::new("source-kinds", "127.0.0.1:8554")?;
    let baseline = fixture.manifest.clone();
    set(
        source_mut(&mut fixture.manifest, 1)?,
        "kind",
        Value::Text("nvr_channel".to_owned()),
    )?;
    fixture.rebind_manifest()?;
    fixture.write()?;
    let plan = good(run(false, &fixture.args())?)?;
    assert_eq!(text(&items(&plan, "sources")?[1], "kind")?, "nvr_channel");

    for (kind, field_name, value) in [
        ("onvif", "onvif_service_path", "/onvif/device_service"),
        ("unifi_protect", "unifi_camera_id", "camera:protected"),
    ] {
        fixture.manifest = baseline.clone();
        let source = source_mut(&mut fixture.manifest, 1)?;
        set(source, "kind", Value::Text(kind.to_owned()))?;
        set(source, "presentation", Value::Null)?;
        set(source, "control_root", Value::Null)?;
        set(source, field_name, Value::Text(value.to_owned()))?;
        fixture.rebind_manifest()?;
        fixture.write()?;
        good(run(
            false,
            &validate_args(&fixture.directory.0.join("manifest.json")),
        )?)?;
        refused(run(false, &fixture.args())?, Some("ERR-SITE-PLAN-001"), &[])?;
    }
    fixture.untouched();
    Ok(())
}

#[test]
fn unknown_fields_and_embedded_credentials_are_payload_free_refusals() -> Test {
    let mut fixture = Fixture::new("secret-refusals", "127.0.0.1:8554")?;
    let baseline = fixture.manifest.clone();
    const CANARY: &str = "PRIVATE_PASSWORD_VALUE_CANARY";
    for (key, value) in [
        ("password", CANARY.to_owned()),
        ("authority", format!("user:{CANARY}@camera.test:8554")),
    ] {
        fixture.manifest = baseline.clone();
        set(
            source_mut(&mut fixture.manifest, 1)?,
            key,
            Value::Text(value),
        )?;
        fixture.write()?;
        refused(run(false, &fixture.args())?, None, &[CANARY])?;
    }
    fixture.untouched();
    Ok(())
}

#[test]
fn malformed_and_non_regular_inputs_fail_without_disclosing_document_bytes_or_paths() -> Test {
    let directory = Directory::new("input-refusals")?;
    let private_name = "PRIVATE_CAMERA_PATH_CANARY";
    let canary = "PASSWORD_AND_TOKEN_CANARY";
    let missing = directory.0.join(private_name);
    refused(
        run(false, &validate_args(&missing))?,
        Some("ERR-SITE-INPUT-001"),
        &[private_name],
    )?;
    refused(
        run(false, &validate_args(&directory.0))?,
        Some("ERR-SITE-INPUT-001"),
        &[],
    )?;
    for (index, bytes) in [
        format!("{{\"private\":\"{canary}\",\"private\":false}}").into_bytes(),
        format!("{{\"password\":\"{canary}\"}} trailing").into_bytes(),
        vec![0xff, 0xfe],
        vec![b' '; json_input::MAX_INPUT_BYTES + 1],
    ]
    .into_iter()
    .enumerate()
    {
        let path = directory.write(&format!("{private_name}-{index}"), bytes)?;
        refused(
            run(false, &validate_args(&path))?,
            None,
            &[private_name, canary],
        )?;
    }
    #[cfg(unix)]
    {
        let target = directory.write("target.json", "{}")?;
        let link = directory.0.join("link.json");
        std::os::unix::fs::symlink(target, &link)?;
        refused(
            run(false, &validate_args(&link))?,
            Some("ERR-SITE-INPUT-001"),
            &[],
        )?;
    }
    Ok(())
}

#[test]
fn site_grammar_refuses_execution_unknown_actions_and_ambiguous_options() -> Test {
    for args in [
        vec!["site", "capture", "--json"],
        vec![
            "site",
            "validate",
            "--manifest",
            "unused",
            "--approve",
            "unused",
            "--json",
        ],
        vec![
            "site",
            "validate",
            "--manifest",
            "unused",
            "--manifest",
            "unused",
            "--json",
        ],
        vec!["site", "plan", "--manifest", "unused", "--json"],
    ] {
        let args: Vec<_> = args.into_iter().map(OsString::from).collect();
        let output = run(false, &args)?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty(), "grammar refusal returned a plan");
        assert!(!output.stderr.is_empty());
    }
    Ok(())
}

fn select_jpeg(fixture: &mut Fixture, index: usize) -> Test {
    let receipt = fixture.probe_mut(index)?;
    set(receipt, "codec", Value::Text("jpeg".to_owned()))?;
    set(receipt, "payload_type", Value::Number("26".to_owned()))?;
    set(receipt, "parameter_set_digests", Value::Array(Vec::new()))?;
    set(
        receipt,
        "sdp_digest",
        Value::Text(ContentDigest::sha256(b"synthetic-jpeg-sdp").to_text()),
    )?;
    Ok(())
}

#[test]
fn mixed_avc_jpeg_fixture_matches_native_capture_with_and_without_unread_credentials() -> Test {
    let mut fixture = Fixture {
        directory: Directory::new("jpeg-native-equivalence")?,
        manifest: json_input::parse(include_str!("../../../fixtures/site/manifest.v1.json"))?,
        probes: json_input::parse(include_str!(
            "../../../fixtures/site/probes-avc-jpeg.v1.json"
        ))?,
    };
    for authenticated in [false, true] {
        if authenticated {
            let credential = fixture.directory.0.join("credentials-not-created");
            set(
                source_mut(&mut fixture.manifest, 1)?,
                "authentication",
                json_input::parse(&format!(
                    r#"{{"credential_file":{},"realm":"jpeg-owner-realm","legacy_md5":true,"legacy_no_qop":false}}"#,
                    string(credential.to_str().ok_or("UTF-8 credential path")?),
                ))?,
            )?;
            fixture.rebind_manifest()?;
        }
        fixture.write()?;
        let output = run(false, &fixture.args())?;
        let report_text = String::from_utf8(output.stdout.clone())?;
        let plan = good(output)?;
        assert!(text(&plan, "policy")?.contains("receipt-bound-jpeg-retention"));
        assert_eq!(
            text(&plan, "reserved_pins_root")?,
            fixture
                .directory
                .0
                .join("pins-not-created")
                .to_str()
                .ok_or("UTF-8 pin parent")?,
        );
        for flag in [
            "effects_started",
            "device_contacted",
            "credentials_read",
            "executor_available",
            "rights_leases_verified",
            "capture_authorized",
        ] {
            assert!(!boolean(&plan, flag)?);
        }
        let sources = items(&plan, "sources")?;
        assert_eq!(sources.len(), 2);
        for (index, source) in sources.iter().enumerate() {
            let args = argv(source)?;
            assert!(!args.iter().any(|arg| arg == "--approve"));
            if index == 1 {
                assert_eq!(args.first(), Some(&OsString::from("jpeg")));
                assert_eq!(native_value(&args[1..], "--payload-type")?, "26");
                assert_eq!(native_value(&args[1..], "--ssrc")?, "43");
                let _ = ContentDigest::parse(native_value(&args[1..], "--retention-evidence")?)?;
                for excluded in [
                    "--pins",
                    "--journal-id",
                    "--timing-evidence",
                    "--frame-duration-ticks",
                    "--codec",
                ] {
                    assert!(!args.iter().any(|arg| arg == excluded));
                }
                assert_eq!(text(source, "kind")?, "nvr_channel");
            } else {
                assert_eq!(native_value(&args, "--codec")?, "avc");
                assert_eq!(native_value(&args, "--frame-duration-ticks")?, "3600");
            }
            let native_output = run(true, &args)?;
            let native_text = String::from_utf8(native_output.stdout.clone())?;
            let native = good(native_output)?;
            assert_eq!(field(source, "native_plan")?, &native);
            assert_eq!(text(source, "native_approval")?, text(&native, "approval")?);
            assert!(report_text.contains(&format!("\"native_plan\":{}", native_text.trim_end())));
            if index == 1 {
                assert_eq!(text(&native, "schema")?, "fss.rtsp_jpeg_capture_cli.v1");
                assert_eq!(text(&native, "mode")?, "capture");
                assert!(!native_text.contains("jpeg-owner-realm"));
            }
        }
        fixture.untouched();
    }
    Ok(())
}

#[test]
fn jpeg_native_limits_refuse_the_complete_site_without_substituting_probe_observations() -> Test {
    let mut fixture = Fixture::new("jpeg-native-limits", "127.0.0.1:8554")?;
    select_jpeg(&mut fixture, 1)?;
    let baseline = fixture.probes.clone();
    for (key, replacement) in [("ssrc", "0"), ("media_index", "16")] {
        fixture.probes = baseline.clone();
        set(
            fixture.probe_mut(1)?,
            key,
            Value::Number(replacement.to_owned()),
        )?;
        fixture.write()?;
        let diagnostic = refused(run(false, &fixture.args())?, Some("ERR-SITE-PLAN-001"), &[])?;
        assert_eq!(field(&diagnostic, "source_index")?.integer(), Some(1));
        assert!(
            !diagnostic
                .object()
                .is_some_and(|fields| fields.contains_key("approval"))
        );
        fixture.untouched();
    }
    fixture.probes = baseline;
    for (key, replacement) in [
        ("ssrc", "1"),
        ("media_index", "15"),
        ("payload_type", "127"),
        ("rtp_channel", "254"),
        ("rtcp_channel", "255"),
    ] {
        set(
            fixture.probe_mut(1)?,
            key,
            Value::Number(replacement.to_owned()),
        )?;
    }
    fixture.write()?;
    let mut args = fixture.args();
    replace_arg(&mut args, "--stop-after-pictures", "256")?;
    let plan = good(run(false, &args)?)?;
    let jpeg_args = argv(&items(&plan, "sources")?[1])?;
    assert_eq!(
        native_value(&jpeg_args[1..], "--stop-after-pictures")?,
        "256"
    );
    assert_eq!(native_value(&jpeg_args[1..], "--media-index")?, "15");
    assert_eq!(native_value(&jpeg_args[1..], "--ssrc")?, "1");
    assert_eq!(native_value(&jpeg_args[1..], "--rtp-channel")?, "254");
    assert_eq!(native_value(&jpeg_args[1..], "--payload-type")?, "127");
    replace_arg(&mut args, "--stop-after-pictures", "257")?;
    let diagnostic = refused(run(false, &args)?, Some("ERR-SITE-PLAN-001"), &[])?;
    assert_eq!(field(&diagnostic, "source_index")?.integer(), Some(1));

    // Adding JPEG support cannot bypass the common original-retention gates.
    set(
        source_mut(&mut fixture.manifest, 1)?,
        "retain_originals",
        Value::Bool(false),
    )?;
    fixture.rebind_manifest()?;
    fixture.write()?;
    refused(run(false, &fixture.args())?, Some("ERR-SITE-PLAN-001"), &[])?;
    fixture.untouched();
    Ok(())
}

#[test]
fn all_jpeg_site_binds_reserved_pin_parent_and_exact_retention_receipts() -> Test {
    let mut fixture = Fixture::new("jpeg-retention-binding", "127.0.0.1:8554")?;
    select_jpeg(&mut fixture, 0)?;
    select_jpeg(&mut fixture, 1)?;
    fixture.write()?;
    let original = good(run(false, &fixture.args())?)?;
    assert_eq!(
        text(&original, "reserved_pins_root")?,
        fixture
            .directory
            .0
            .join("pins-not-created")
            .to_str()
            .ok_or("UTF-8 pin parent")?,
    );

    array_mut(&mut fixture.probes)?.reverse();
    fixture.write()?;
    assert_eq!(good(run(false, &fixture.args())?)?, original);
    array_mut(&mut fixture.probes)?.reverse();
    fixture.write()?;

    let unused_pin_parent = fixture.directory.0.join("different-reserved-pins");
    let mut moved_args = fixture.args();
    replace_arg(
        &mut moved_args,
        "--pins-root",
        unused_pin_parent.as_os_str(),
    )?;
    let moved = good(run(false, &moved_args)?)?;
    assert_ne!(text(&original, "approval")?, text(&moved, "approval")?);
    assert_eq!(
        text(&moved, "reserved_pins_root")?,
        unused_pin_parent.to_str().ok_or("UTF-8 pin parent")?,
    );
    // JPEG has no independent AVC/HEVC journal. This declaration is bound only
    // by the enclosing JPEG site policy, not invented as a native JPEG argument.
    assert_eq!(items(&original, "sources")?, items(&moved, "sources")?);
    assert!(!unused_pin_parent.exists());

    set(
        fixture.probe_mut(1)?,
        "server_identity",
        Value::Text("different-synthetic-jpeg-server".to_owned()),
    )?;
    fixture.write()?;
    let changed = good(run(false, &fixture.args())?)?;
    assert_ne!(text(&original, "approval")?, text(&changed, "approval")?);
    assert_eq!(
        items(&original, "sources")?[0],
        items(&changed, "sources")?[0]
    );
    let old = &items(&original, "sources")?[1];
    let new = &items(&changed, "sources")?[1];
    assert_ne!(text(old, "native_approval")?, text(new, "native_approval")?);
    let old_args = argv(old)?;
    let new_args = argv(new)?;
    assert_ne!(
        native_value(&old_args[1..], "--retention-evidence")?,
        native_value(&new_args[1..], "--retention-evidence")?,
    );
    assert_eq!(
        native_value(&old_args[1..], "--root")?,
        native_value(&new_args[1..], "--root")?,
    );
    fixture.untouched();
    Ok(())
}
