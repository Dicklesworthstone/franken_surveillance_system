#![forbid(unsafe_code)]
//! Real command contracts for protected site-to-native UniFi handoff.

use super::*;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const CAMERA: &str = "camera:private-identity-canary";
const TOKEN: &str = "PRIVATE_UNIFI_STREAM_CAPABILITY_CANARY";
const NAME: &str = "PRIVATE_UNIFI_CAMERA_NAME_CANARY";

struct UnifiFixture {
    site: Fixture,
    export: PathBuf,
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

impl UnifiFixture {
    fn new(name: &str, peer: &str) -> Test<Self> {
        let mut site = Fixture::new(name, peer)?;
        let authority = text(source_mut(&mut site.manifest, 0)?, "authority")?.to_owned();
        let source = source_mut(&mut site.manifest, 0)?;
        set(source, "kind", Value::Text("unifi_protect".into()))?;
        set(source, "presentation", Value::Null)?;
        set(source, "control_root", Value::Null)?;
        set(source, "unifi_camera_id", Value::Text(CAMERA.into()))?;
        for key in ["presentation", "control_root"] {
            set(site.probe_mut(0)?, key, Value::Text(format!("/{TOKEN}")))?;
        }
        // These are explicitly declared synthetic receipts, not measurements or
        // rebinding of acquired evidence. No fixture endpoint serves media.
        site.rebind_manifest()?;
        let bytes = format!(
            r#"{{"camera":{{"id":{},"name":{},"hasPackageCamera":true}},"streams":{{"high":"rtsps://{authority}/{TOKEN}"}},"rtsp":{{"high":"rtsp://{authority}/{TOKEN}"}}}}"#,
            string(CAMERA), string(NAME)
        ).into_bytes();
        let export = site.directory.0.join("private-protect.json");
        private_file(&export, &bytes)?;
        for parent in ["archive-not-created", "pins-not-created"] {
            fs::create_dir(site.directory.0.join(parent))?;
        }
        let manifest = parse_manifest(render(&site.manifest).as_bytes())?;
        let bindings = json_input::parse(&format!(
            r#"{{"schema":"fss.site_unifi_bindings.v1","manifest_digest":{},"sources":[{{"source_id":"source:front","source_file":{},"source_digest":{},"quality":"high","stream_transport":"operator-rtsp"}}]}}"#,
            string(&manifest.digest()?.to_text()),
            string(export.to_str().ok_or("UTF-8 export path")?),
            string(&ContentDigest::sha256(&bytes).to_text())
        ))?;
        let fixture = Self {
            site,
            export,
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
            .write("bindings.json", render(&self.bindings))?;
        Ok(())
    }

    fn args(&self) -> Vec<OsString> {
        let mut args = self.site.args();
        args.extend([
            "--unifi-bindings".into(),
            self.site.directory.0.join("bindings.json").into_os_string(),
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
        Ok(())
    }
}

#[test]
fn protected_site_plan_matches_native_wrapper_and_never_connects() -> Test {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let fixture = UnifiFixture::new(
        "unifi-native-equivalence",
        &listener.local_addr()?.to_string(),
    )?;
    let output = run(false, &fixture.args())?;
    let encoded = String::from_utf8(output.stdout.clone())?;
    for canary in [TOKEN, CAMERA, NAME] {
        assert!(
            !encoded.contains(canary),
            "site report exposed private metadata"
        );
    }
    let site = good(output)?;
    let sources = items(&site, "sources")?;
    assert_eq!(sources.len(), 2);
    assert_eq!(text(&sources[0], "kind")?, "unifi_protect");
    let arguments = argv(&sources[0])?;
    assert_eq!(arguments.first(), Some(&OsString::from("from-unifi")));
    for forbidden in [
        "--approve",
        "--authority",
        "--presentation",
        "--control-root",
    ] {
        assert!(!arguments.iter().any(|value| value == forbidden));
    }
    assert_eq!(native_value(&arguments[1..], "--capture-mode")?, "single");
    let native = good(run(true, &arguments)?)?;
    assert_eq!(field(&sources[0], "native_plan")?, &native);
    assert_eq!(
        text(&sources[0], "native_approval")?,
        text(&native, "approval")?
    );
    let direct = good(run(true, &argv(&sources[1])?)?)?;
    assert_eq!(field(&sources[1], "native_plan")?, &direct);
    let again = good(run(false, &fixture.args())?)?;
    assert_eq!(site, again);
    fixture.no_capture()?;
    no_connection(&listener)?;
    Ok(())
}

#[test]
fn protected_file_replacement_changes_approval_and_bad_inputs_refuse_whole_site() -> Test {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let mut fixture = UnifiFixture::new("unifi-drift", &listener.local_addr()?.to_string())?;
    let original = good(run(false, &fixture.args())?)?;
    let replacement = fixture.site.directory.0.join("replacement.json");
    private_file(&replacement, &fixture.bytes)?;
    fs::rename(replacement, &fixture.export)?;
    let replaced = good(run(false, &fixture.args())?)?;
    assert_ne!(text(&original, "approval")?, text(&replaced, "approval")?);
    assert_ne!(
        text(&items(&original, "sources")?[0], "native_approval")?,
        text(&items(&replaced, "sources")?[0], "native_approval")?
    );
    assert_eq!(
        field(&items(&original, "sources")?[1], "native_plan")?,
        field(&items(&replaced, "sources")?[1], "native_plan")?
    );
    refused(
        run(false, &fixture.site.args())?,
        Some("ERR-SITE-PLAN-001"),
        &[TOKEN, CAMERA, NAME],
    )?;
    fs::set_permissions(&fixture.export, fs::Permissions::from_mode(0o644))?;
    refused(
        run(false, &fixture.args())?,
        Some("ERR-SITE-UNIFI-INPUT-001"),
        &[TOKEN, CAMERA, NAME],
    )?;
    fs::set_permissions(&fixture.export, fs::Permissions::from_mode(0o600))?;
    let original_bindings = fixture.bindings.clone();
    set(&mut fixture.bindings, "sources", Value::Array(Vec::new()))?;
    fixture.write()?;
    refused(
        run(false, &fixture.args())?,
        Some("ERR-SITE-UNIFI-INPUT-001"),
        &[TOKEN, CAMERA, NAME],
    )?;
    fixture.bindings = original_bindings;
    set(
        fixture.site.probe_mut(0)?,
        "presentation",
        Value::Text(format!("/{TOKEN}/wrong")),
    )?;
    fixture.write()?;
    refused(
        run(false, &fixture.args())?,
        Some("ERR-SITE-PLAN-001"),
        &[TOKEN, CAMERA, NAME],
    )?;
    fixture.no_capture()?;
    no_connection(&listener)?;
    Ok(())
}
