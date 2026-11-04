#![forbid(unsafe_code)]
//! Real command contracts for site planning from a protected historical ONVIF handoff.

use super::*;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const PRIVATE_PATH: &str = "PRIVATE_ONVIF_PATH_CANARY";
const PRIVATE_QUERY: &str = "PRIVATE_ONVIF_QUERY_CANARY";
const PRIVATE_PROFILE: &str = "PRIVATE_ONVIF_PROFILE_CANARY";

struct OnvifFixture {
    site: Fixture,
    handoff: PathBuf,
    bytes: Vec<u8>,
    bindings: Value,
}

fn private_file(path: &Path, bytes: &[u8]) -> Test {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn private_output(output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let rendered = String::from_utf8_lossy(bytes);
        for canary in [PRIVATE_PATH, PRIVATE_QUERY, PRIVATE_PROFILE] {
            assert!(
                !rendered.contains(canary),
                "command exposed private ONVIF metadata"
            );
        }
    }
}

impl OnvifFixture {
    fn new(name: &str, http_peer: &str, rtsp_peer: &str) -> Test<Self> {
        let mut site = Fixture::new(name, rtsp_peer)?;
        let http_address: std::net::SocketAddr = http_peer.parse()?;
        let authority = text(source_mut(&mut site.manifest, 0)?, "authority")?.to_owned();
        let source = source_mut(&mut site.manifest, 0)?;
        set(source, "kind", Value::Text("onvif".into()))?;
        set(source, "peer", Value::Text(http_peer.to_owned()))?;
        set(
            source,
            "authority",
            Value::Text(format!("camera.test:{}", http_address.port())),
        )?;
        set(source, "presentation", Value::Null)?;
        set(source, "control_root", Value::Null)?;
        set(
            source,
            "onvif_service_path",
            Value::Text("/onvif/device_service".into()),
        )?;
        let root = format!("/{PRIVATE_PATH}");
        let presentation = format!("{root}/%4a/main?opaque={PRIVATE_QUERY}");
        set(
            site.probe_mut(0)?,
            "presentation",
            Value::Text(presentation.clone()),
        )?;
        set(
            site.probe_mut(0)?,
            "control_root",
            Value::Text(root.clone()),
        )?;
        // Synthetic receipts declare an RTSP endpoint distinct from the ONVIF HTTP
        // endpoint. They are not observations produced by either local listener.
        site.rebind_manifest()?;
        let onboarding = ContentDigest::sha256(b"synthetic-historical-onboarding-plan").to_text();
        let profile = ContentDigest::sha256(PRIVATE_PROFILE.as_bytes()).to_text();
        let bytes = format!(
            r#"{{"schema":"fss.onvif_rtsp_handoff.v1","onboarding_plan":{},"profile_digest":{},"peer":{},"authority":{},"uri":{},"codec":"avc","invalid_after_connect":false,"invalid_after_reboot":false,"timeout":"PT0S","capture_authorized":false,"source_evidence":false}}"#,
            string(&onboarding), string(&profile), string(rtsp_peer), string(&authority),
            string(&format!("rtsp://{authority}{presentation}"))
        ).into_bytes();
        let handoff = site.directory.0.join("private-onvif.json");
        private_file(&handoff, &bytes)?;
        for parent in ["archive-not-created", "pins-not-created"] {
            fs::create_dir(site.directory.0.join(parent))?;
        }
        let manifest = parse_manifest(render(&site.manifest).as_bytes())?;
        let bindings = json_input::parse(&format!(
            r#"{{"schema":"fss.site_onvif_bindings.v1","manifest_digest":{},"sources":[{{"source_id":"source:front","source_file":{},"source_digest":{},"onboarding_plan":{},"profile_digest":{},"rtsp_peer":{},"rtsp_authority":{},"control_root":{}}}]}}"#,
            string(&manifest.digest()?.to_text()),
            string(handoff.to_str().ok_or("UTF-8 handoff path")?),
            string(&ContentDigest::sha256(&bytes).to_text()),
            string(&onboarding),
            string(&profile),
            string(rtsp_peer),
            string(&authority),
            string(&root)
        ))?;
        let fixture = Self {
            site,
            handoff,
            bytes,
            bindings,
        };
        fixture.write()?;
        Ok(fixture)
    }

    fn write(&self) -> Test {
        self.site.write()?;
        self.site
            .directory
            .write("onvif-bindings.json", render(&self.bindings))?;
        Ok(())
    }

    fn args(&self) -> Vec<OsString> {
        let mut args = self.site.args();
        args.extend([
            "--onvif-bindings".into(),
            self.site
                .directory
                .0
                .join("onvif-bindings.json")
                .into_os_string(),
        ]);
        args
    }

    fn no_capture(&self) -> Test {
        for parent in ["archive-not-created", "pins-not-created"] {
            assert!(
                fs::read_dir(self.site.directory.0.join(parent))?
                    .next()
                    .is_none()
            );
        }
        assert!(
            !self
                .site
                .directory
                .0
                .join("credentials-not-created")
                .exists()
        );
        assert_eq!(fs::read(&self.handoff)?, self.bytes);
        Ok(())
    }
}

#[test]
fn protected_onvif_site_plan_matches_native_wrapper_without_http_or_rtsp_contact() -> Test {
    let http = TcpListener::bind("127.0.0.1:0")?;
    let rtsp = TcpListener::bind("127.0.0.1:0")?;
    http.set_nonblocking(true)?;
    rtsp.set_nonblocking(true)?;
    let fixture = OnvifFixture::new(
        "onvif-native-equivalence",
        &http.local_addr()?.to_string(),
        &rtsp.local_addr()?.to_string(),
    )?;
    let original_manifest = render(&fixture.site.manifest);
    let output = run(false, &fixture.args())?;
    private_output(&output);
    let site = good(output)?;
    assert_eq!(
        text(&site, "manifest_digest")?,
        parse_manifest(original_manifest.as_bytes())?
            .digest()?
            .to_text()
    );
    assert_eq!(
        text(&site, "onvif_selection_provenance")?,
        "operator-bound-historical-consistency"
    );
    assert!(!boolean(&site, "onvif_http_origin_verified")?);
    let sources = items(&site, "sources")?;
    assert_eq!(sources.len(), 2);
    assert_eq!(text(&sources[0], "kind")?, "onvif");
    let arguments = argv(&sources[0])?;
    assert_eq!(arguments.first(), Some(&OsString::from("from-onvif")));
    for forbidden in [
        "--approve",
        "--peer",
        "--authority",
        "--presentation",
        "--control-root",
        "--codec",
    ] {
        assert!(!arguments.iter().any(|value| value == forbidden));
    }
    assert_eq!(native_value(&arguments[1..], "--capture-mode")?, "single");
    assert_eq!(
        native_value(&arguments[1..], "--onvif-control-root-digest")?,
        ContentDigest::sha256(format!("/{PRIVATE_PATH}").as_bytes()).to_text()
    );
    let native_output = run(true, &arguments)?;
    private_output(&native_output);
    let native = good(native_output)?;
    assert_eq!(field(&sources[0], "native_plan")?, &native);
    assert_eq!(
        text(&sources[0], "native_approval")?,
        text(&native, "approval")?
    );
    assert_eq!(
        text(field(&native, "native_capture")?, "peer")?,
        rtsp.local_addr()?.to_string()
    );
    let direct = good(run(true, &argv(&sources[1])?)?)?;
    assert_eq!(field(&sources[1], "native_plan")?, &direct);
    assert_eq!(site, good(run(false, &fixture.args())?)?);
    assert_eq!(
        fs::read_to_string(fixture.site.directory.0.join("manifest.json"))?,
        original_manifest
    );
    fixture.no_capture()?;
    no_connection(&http)?;
    no_connection(&rtsp)?;
    Ok(())
}

#[test]
fn onvif_replacement_invalidates_approval_and_binding_drift_refuses_whole_site() -> Test {
    let http = TcpListener::bind("127.0.0.1:0")?;
    let rtsp = TcpListener::bind("127.0.0.1:0")?;
    http.set_nonblocking(true)?;
    rtsp.set_nonblocking(true)?;
    let mut fixture = OnvifFixture::new(
        "onvif-binding-drift",
        &http.local_addr()?.to_string(),
        &rtsp.local_addr()?.to_string(),
    )?;
    let original = good(run(false, &fixture.args())?)?;
    let replacement = fixture.site.directory.0.join("replacement.json");
    private_file(&replacement, &fixture.bytes)?;
    fs::rename(replacement, &fixture.handoff)?;
    let changed = good(run(false, &fixture.args())?)?;
    assert_ne!(text(&original, "approval")?, text(&changed, "approval")?);
    let old_source = &items(&original, "sources")?[0];
    assert_ne!(
        text(old_source, "native_approval")?,
        text(&items(&changed, "sources")?[0], "native_approval")?
    );
    assert_eq!(
        items(&original, "sources")?[1],
        items(&changed, "sources")?[1]
    );

    // A site-generated approval from the old inode cannot authorize native work.
    let mut stale = argv(old_source)?;
    stale.extend([
        "--approve".into(),
        text(old_source, "native_approval")?.into(),
    ]);
    let refused_native = run(true, &stale)?;
    private_output(&refused_native);
    assert!(!refused_native.status.success());
    assert!(String::from_utf8(refused_native.stderr)?.contains("ERR-CAPTURE-ONVIF-APPROVAL-001"));

    let original_bindings = fixture.bindings.clone();
    for (key, replacement, expected) in [
        (
            "profile_digest",
            ContentDigest::sha256(b"other-profile").to_text(),
            "ERR-SITE-PLAN-001",
        ),
        (
            "onboarding_plan",
            ContentDigest::sha256(b"other-onboarding").to_text(),
            "ERR-SITE-PLAN-001",
        ),
        (
            "rtsp_peer",
            http.local_addr()?.to_string(),
            "ERR-SITE-PLAN-001",
        ),
        (
            "source_digest",
            ContentDigest::sha256(b"other-handoff").to_text(),
            "ERR-SITE-ONVIF-INPUT-001",
        ),
    ] {
        fixture.bindings = original_bindings.clone();
        set(
            source_mut(&mut fixture.bindings, 0)?,
            key,
            Value::Text(replacement),
        )?;
        fixture.write()?;
        refused(
            run(false, &fixture.args())?,
            Some(expected),
            &[PRIVATE_PATH, PRIVATE_QUERY, PRIVATE_PROFILE],
        )?;
    }
    fixture.bindings = original_bindings;
    set(
        fixture.site.probe_mut(0)?,
        "presentation",
        Value::Text(format!("/{PRIVATE_PATH}/foreign")),
    )?;
    fixture.write()?;
    refused(
        run(false, &fixture.args())?,
        Some("ERR-SITE-PLAN-001"),
        &[PRIVATE_PATH, PRIVATE_QUERY, PRIVATE_PROFILE],
    )?;
    fs::set_permissions(&fixture.handoff, fs::Permissions::from_mode(0o644))?;
    refused(
        run(false, &fixture.args())?,
        Some("ERR-SITE-ONVIF-INPUT-001"),
        &[PRIVATE_PATH, PRIVATE_QUERY, PRIVATE_PROFILE],
    )?;
    fixture.no_capture()?;
    no_connection(&http)?;
    no_connection(&rtsp)?;
    Ok(())
}

#[test]
fn selected_onvif_preserves_native_plan_and_excluded_handoffs_are_not_opened() -> Test {
    let http = TcpListener::bind("127.0.0.1:0")?;
    let rtsp = TcpListener::bind("127.0.0.1:0")?;
    http.set_nonblocking(true)?;
    rtsp.set_nonblocking(true)?;
    let mut fixture = OnvifFixture::new(
        "onvif-selected",
        &http.local_addr()?.to_string(),
        &rtsp.local_addr()?.to_string(),
    )?;
    let all_output = run(false, &fixture.args())?;
    private_output(&all_output);
    let all = good(all_output)?;
    let receipts = fixture
        .site
        .probes
        .array()
        .ok_or("fixture receipt array")?
        .to_vec();
    fixture.site.probes = Value::Array(vec![receipts[0].clone()]);
    fixture.write()?;
    let mut selected = fixture.args();
    selected.extend(["--source".into(), "source:front".into()]);
    let output = run(false, &selected)?;
    private_output(&output);
    let plan = good(output)?;
    assert_eq!(text(&plan, "schema")?, "fss.site_capture_plan.v2");
    assert_eq!(items(&plan, "sources")?, &items(&all, "sources")?[..1]);
    assert_eq!(
        text(&plan, "manifest_digest")?,
        text(&all, "manifest_digest")?
    );
    assert_eq!(
        items(&plan, "unselected_source_ids")?,
        &[Value::Text("source:back".into())]
    );
    assert!(!boolean(&plan, "onvif_http_origin_verified")?);

    // An excluded source needs neither its protected file nor a binding input.
    // An owner-readable handoff is mandatory if the protected path is actually entered.
    fs::set_permissions(&fixture.handoff, fs::Permissions::from_mode(0o000))?;
    fixture.site.probes = Value::Array(vec![receipts[1].clone()]);
    fixture.write()?;
    let mut direct_only = fixture.site.args();
    direct_only.extend(["--source".into(), "source:back".into()]);
    let output = run(false, &direct_only)?;
    private_output(&output);
    let direct = good(output)?;
    assert_eq!(items(&direct, "sources")?, &items(&all, "sources")?[1..]);
    fs::set_permissions(&fixture.handoff, fs::Permissions::from_mode(0o600))?;
    fixture.no_capture()?;
    no_connection(&http)?;
    no_connection(&rtsp)
}
