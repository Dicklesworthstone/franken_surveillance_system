#![forbid(unsafe_code)]
//! Private UniFi export -> native observation -> protected receipt -> site plan.
//! Synthetic loopback cameras exercise the real CLI without contacting a console.

use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

const CAMERA: &str = "PRIVATE_UNIFI_CAMERA_ID_CANARY";
const CAMERA_NAME: &str = "PRIVATE_UNIFI_CAMERA_NAME_CANARY";
const CAPABILITY: &str = "PRIVATE_UNIFI_STREAM_CAPABILITY_CANARY";
const PRESENTATION: &str =
    "/PRIVATE_UNIFI_STREAM_CAPABILITY_CANARY?quality=high&variant=%41%2b&order=2";
const ROOT: &str = "/PRIVATE_UNIFI_STREAM_CAPABILITY_CANARY";

struct PrivateFixture {
    fixture: Fixture,
    export: PathBuf,
    bindings: PathBuf,
    receipt: PathBuf,
    transport: &'static str,
    uri: String,
}

fn write_private(path: &Path, bytes: &[u8]) -> Test {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

impl PrivateFixture {
    fn new(label: &str, peer: SocketAddr, transport: &'static str) -> Test<Self> {
        let mut fixture = Fixture::new(label, peer)?;
        fixture.directory.0 = fixture.directory.0.canonicalize()?;
        set(
            fixture.source()?,
            "kind",
            Value::Text("unifi_protect".into()),
        )?;
        set(fixture.source()?, "presentation", Value::Null)?;
        set(fixture.source()?, "control_root", Value::Null)?;
        set(
            fixture.source()?,
            "unifi_camera_id",
            Value::Text(CAMERA.into()),
        )?;
        let uri = format!(
            "rtsp://{}{PRESENTATION}",
            text(fixture.source()?, "authority")?
        );
        fixture.write()?;
        let export = fixture.directory.0.join("protect-export.json");
        let published = if transport == "published" {
            uri.clone()
        } else {
            // A secure published URL must never be converted implicitly. The owner
            // separately supplies the exact plaintext endpoint for this fixture.
            uri.replacen("rtsp://", "rtsps://", 1)
        };
        write_private(
            &export,
            format!(
                r#"{{"camera":{{"id":{},"name":{}}},"streams":{{"high":{}}},"rtsp":{{"high":{}}}}}"#,
                string(CAMERA),
                string(CAMERA_NAME),
                string(&published),
                string(&uri)
            )
            .as_bytes(),
        )?;
        let receipt_parent = fixture.directory.0.join("private-receipts");
        fs::DirBuilder::new().mode(0o700).create(&receipt_parent)?;
        for name in ["plan-archive", "plan-pins"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(fixture.directory.0.join(name))?;
        }
        let result = Self {
            bindings: fixture.directory.0.join("bindings.json"),
            receipt: receipt_parent.join("probe.json"),
            fixture,
            export,
            transport,
            uri,
        };
        result.bind()?;
        Ok(result)
    }

    fn bind(&self) -> Test {
        let manifest = parse_manifest(render(&self.fixture.manifest).as_bytes())?;
        let bytes = fs::read(&self.export)?;
        fs::write(
            &self.bindings,
            format!(
                r#"{{"schema":"fss.site_unifi_bindings.v1","manifest_digest":{},"sources":[{{"source_id":"source:front","source_file":{},"source_digest":{},"quality":"high","stream_transport":{}}}]}}"#,
                string(&manifest.digest()?.to_text()),
                string(self.export.to_str().ok_or("UTF-8 export path")?),
                string(&ContentDigest::sha256(&bytes).to_text()),
                string(self.transport)
            ),
        )?;
        Ok(())
    }

    fn args(&self, codec: Codec) -> Vec<OsString> {
        let mut args = self.fixture.args(codec);
        args.extend([
            "--unifi-bindings".into(),
            self.bindings.as_os_str().to_owned(),
            "--receipt-file".into(),
            self.receipt.as_os_str().to_owned(),
        ]);
        args
    }

    fn approved(&self, codec: Codec) -> Test<Vec<OsString>> {
        let mut args = self.args(codec);
        let output = run(&args)?;
        private_output(&output);
        let preview = good(output)?;
        args.extend(["--approve".into(), text(&preview, "approval")?.into()]);
        Ok(args)
    }

    fn plan_args(&self) -> Test<Vec<OsString>> {
        let mut args = self.fixture.plan_args(&self.receipt);
        replace(
            &mut args,
            "--archive-root",
            self.fixture.directory.0.join("plan-archive"),
        )?;
        replace(
            &mut args,
            "--pins-root",
            self.fixture.directory.0.join("plan-pins"),
        )?;
        args.extend([
            "--unifi-bindings".into(),
            self.bindings.as_os_str().to_owned(),
        ]);
        Ok(args)
    }

    fn mutate_export(&self, change: impl FnOnce(String) -> String) -> Test {
        fs::write(&self.export, change(fs::read_to_string(&self.export)?))?;
        self.bind()
    }
}

fn private_output(output: &Output) {
    no_secrets(output);
    for bytes in [&output.stdout, &output.stderr] {
        let output = String::from_utf8_lossy(bytes);
        for private in [
            CAMERA,
            CAMERA_NAME,
            CAPABILITY,
            "%41%2b",
            "rtsp://",
            "rtsps://",
            "OTHER_PRIVATE_CAMERA",
            "PRIVATE_QUERY",
            "ANOTHER_PRIVATE_NAME",
            "CHANGED_PRIVATE_NAME",
        ] {
            assert!(
                !output.contains(private),
                "private capability escaped to CLI output"
            );
        }
    }
}

fn refusal(output: Output, connection: bool) -> Test<Value> {
    assert!(
        !output.status.success(),
        "private probe unexpectedly succeeded"
    );
    private_output(&output);
    let value = json_input::parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(&value, "schema")?, "fss.site_probe_diagnostic.v1");
    assert_eq!(boolean(&value, "connection_attempted")?, connection);
    for name in [
        "credential_access_attempted",
        "receipt_issued",
        "source_retained",
        "retry_automatically",
    ] {
        assert!(!boolean(&value, name)?);
    }
    Ok(value)
}

#[test]
fn avc_and_hevc_private_receipts_feed_the_same_bound_site_plan() -> Test {
    for (codec, transport) in [(Codec::Avc, "operator-rtsp"), (Codec::Hevc, "published")] {
        let listener = listener()?;
        let fixture = PrivateFixture::new(codec.name(), listener.local_addr()?, transport)?;
        let original_manifest = fs::read(fixture.fixture.directory.0.join("manifest.json"))?;
        let args = fixture.args(codec);
        let output = run(&args)?;
        private_output(&output);
        let original_preview = output.stdout.clone();
        let preview = good(output)?;
        assert_eq!(text(&preview, "schema")?, "fss.site_probe_plan.v1");
        assert_eq!(text(&preview, "status")?, "requires_approval");
        assert_eq!(
            text(&preview, "presentation")?,
            ContentDigest::sha256(PRESENTATION.as_bytes()).to_text()
        );
        assert_eq!(
            text(&preview, "control_root")?,
            ContentDigest::sha256(ROOT.as_bytes()).to_text()
        );
        let private = field(&preview, "unifi")?;
        assert_eq!(text(private, "route_projection")?, "sha256_digests");
        assert_eq!(text(private, "stream_transport")?, transport);
        assert_eq!(text(private, "receipt_file_mode")?, "0600");
        assert!(boolean(private, "receipt_file_create_only")?);
        assert!(boolean(private, "private_export_read")?);
        assert!(!boolean(private, "console_contacted")?);
        assert!(!boolean(&preview, "device_contacted")?);
        assert!(!fixture.receipt.exists());
        assert_eq!(run(&args)?.stdout, original_preview);
        no_connection(&listener)?;

        let mut approved = args;
        approved.extend(["--approve".into(), text(&preview, "approval")?.into()]);
        let (output, transcript) = probed(
            listener,
            &approved,
            codec,
            Behavior::PrivateRoute {
                acknowledge_teardown: true,
                replace_parent: None,
            },
        )?;
        private_output(&output);
        let result = good(output)?;
        assert_eq!(text(&result, "schema")?, "fss.site_unifi_probe_result.v1");
        assert_eq!(text(&result, "status")?, "ok");
        assert!(boolean(&result, "receipt_saved")?);
        assert!(boolean(&result, "teardown_acknowledged")?);
        assert!(!boolean(&result, "remote_session_may_exist")?);
        assert!(!boolean(&result, "source_retained")?);
        assert!(!boolean(&result, "console_contacted")?);
        assert_eq!(
            text(&result, "receipt_file")?,
            fixture.receipt.to_str().ok_or("UTF-8 receipt path")?
        );
        assert_eq!(
            fs::metadata(&fixture.receipt)?.permissions().mode() & 0o777,
            0o600
        );
        let bytes = fs::read(&fixture.receipt)?;
        let receipts = parse_probe_receipts(&bytes)?;
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        let manifest = parse_manifest(&original_manifest)?;
        receipt.validate_for(&manifest)?;
        assert_eq!(receipt.manifest_digest, manifest.digest()?);
        assert_eq!(receipt.presentation, PRESENTATION);
        assert_eq!(receipt.control_root, ROOT);
        assert_eq!(receipt.codec.as_str(), codec.name());
        assert_eq!(receipt.parameter_set_digests, codec.parameter_digests()?);
        assert_eq!(receipt.observed_frames, 3);
        assert_eq!(receipt.frame_duration_ticks, FRAME_TICKS);
        assert_eq!(
            text(&result, "receipt_digest")?,
            receipt.digest()?.to_text()
        );
        assert_eq!(
            text(&result, "receipt_file_digest")?,
            ContentDigest::sha256(&bytes).to_text()
        );
        assert_eq!(
            transcript.methods,
            ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]
        );
        let base = format!("{}/", fixture.uri.split('?').next().ok_or("fixture URI")?);
        let track = format!("{base}trackID=0");
        assert_eq!(
            transcript.target_digests,
            [&fixture.uri, &fixture.uri, &track, &base, &base]
                .map(|uri| ContentDigest::sha256(uri.as_bytes()))
        );
        assert!(transcript.client_closed);

        let output = run(&fixture.plan_args()?)?;
        private_output(&output);
        let plan = good(output)?;
        assert_eq!(text(&plan, "schema")?, "fss.site_capture_plan.v1");
        assert!(!boolean(&plan, "effects_started")?);
        let sources = field(&plan, "sources")?.array().ok_or("planned sources")?;
        assert_eq!(sources.len(), 1);
        assert_eq!(text(&sources[0], "kind")?, "unifi_protect");
        let argv = field(&sources[0], "argv")?
            .array()
            .ok_or("native arguments")?;
        assert_eq!(argv.first().and_then(Value::text), Some("from-unifi"));
        for forbidden in ["--presentation", "--control-root", "--authority"] {
            assert!(!argv.iter().any(|value| value.text() == Some(forbidden)));
        }
        for name in ["plan-archive", "plan-pins"] {
            assert!(
                fs::read_dir(fixture.fixture.directory.0.join(name))?
                    .next()
                    .is_none()
            );
        }
        assert_eq!(
            fs::read(fixture.fixture.directory.0.join("manifest.json"))?,
            original_manifest
        );
    }
    Ok(())
}

#[test]
fn private_probe_requires_both_files_and_rejects_unimplemented_output_before_network() -> Test {
    let listener = listener()?;
    let fixture = PrivateFixture::new("private-options", listener.local_addr()?, "operator-rtsp")?;
    for missing in ["--unifi-bindings", "--receipt-file"] {
        let mut args = fixture.args(Codec::Avc);
        let index = args
            .iter()
            .position(|value| value == missing)
            .ok_or("fixture flag")?;
        args.drain(index..index + 2);
        refusal(run(&args)?, false)?;
    }
    let mut session_args = fixture.args(Codec::Avc);
    session_args.extend(["--output".into(), "session".into()]);
    refusal(run(&session_args)?, false)?;
    refusal(run(&fixture.args(Codec::Jpeg))?, false)?;
    refusal(run(&fixture.fixture.args(Codec::Avc))?, false)?;
    assert!(!fixture.receipt.exists());
    no_connection(&listener)
}

#[test]
fn wrong_camera_secure_published_stream_and_route_drift_refuse_without_contact() -> Test {
    for change in 0..4 {
        let listener = listener()?;
        let mut fixture =
            PrivateFixture::new("private-selection", listener.local_addr()?, "operator-rtsp")?;
        match change {
            0 => fixture.mutate_export(|bytes| bytes.replace(CAMERA, "OTHER_PRIVATE_CAMERA"))?,
            1 => {
                fixture.transport = "published";
                fixture.bind()?;
            }
            2 => fixture
                .mutate_export(|bytes| bytes.replace(PRIVATE_ROUTE, "different-authority"))?,
            _ => fixture
                .mutate_export(|bytes| bytes.replace("quality=high", "token=PRIVATE_QUERY"))?,
        }
        refusal(run(&fixture.args(Codec::Avc))?, false)?;
        assert!(!fixture.receipt.exists());
        no_connection(&listener)?;
    }
    Ok(())
}

#[test]
fn export_content_identity_and_receipt_destination_invalidate_prior_approval() -> Test {
    for change in 0..4 {
        let listener = listener()?;
        let fixture =
            PrivateFixture::new("private-approval", listener.local_addr()?, "operator-rtsp")?;
        let mut args = fixture.approved(Codec::Avc)?;
        match change {
            0 => {
                // A new private export is not approved merely because its selected URL agrees.
                fixture
                    .mutate_export(|bytes| bytes.replace(CAMERA_NAME, "ANOTHER_PRIVATE_NAME"))?;
            }
            1 => {
                let bytes = fs::read(&fixture.export)?;
                fs::rename(&fixture.export, fixture.export.with_extension("original"))?;
                write_private(&fixture.export, &bytes)?;
            }
            2 => replace(
                &mut args,
                "--receipt-file",
                fixture.receipt.with_file_name("other.json"),
            )?,
            _ => replace(
                &mut args,
                "--approve",
                ContentDigest::sha256(b"unrelated approval").to_text(),
            )?,
        }
        let refused = refusal(run(&args)?, false)?;
        assert_eq!(text(&refused, "error_id")?, "ERR-SITE-PROBE-APPROVAL-001");
        assert!(!fixture.receipt.exists());
        no_connection(&listener)?;
    }
    Ok(())
}

#[test]
fn changed_export_digest_or_existing_receipt_refuses_before_the_first_connection() -> Test {
    for existing in [false, true] {
        let listener = listener()?;
        let fixture =
            PrivateFixture::new("private-preflight", listener.local_addr()?, "operator-rtsp")?;
        let approved = fixture.approved(Codec::Avc)?;
        let original = b"UNRELATED_EXISTING_PRIVATE_RECEIPT";
        if existing {
            write_private(&fixture.receipt, original)?;
        } else {
            // Leave the binding unchanged so content mismatch is a preflight refusal.
            fs::write(
                &fixture.export,
                fs::read_to_string(&fixture.export)?.replace(CAMERA_NAME, "CHANGED_PRIVATE_NAME"),
            )?;
        }
        refusal(run(&approved)?, false)?;
        if existing {
            assert_eq!(fs::read(&fixture.receipt)?, original);
        } else {
            assert!(!fixture.receipt.exists());
        }
        no_connection(&listener)?;
    }
    Ok(())
}

#[test]
fn unconfirmed_teardown_never_creates_a_private_receipt() -> Test {
    let listener = listener()?;
    let fixture = PrivateFixture::new("private-close", listener.local_addr()?, "operator-rtsp")?;
    let (output, transcript) = probed(
        listener,
        &fixture.approved(Codec::Avc)?,
        Codec::Avc,
        Behavior::PrivateRoute {
            acknowledge_teardown: false,
            replace_parent: None,
        },
    )?;
    let refused = refusal(output, true)?;
    assert!(boolean(&refused, "remote_session_may_exist")?);
    assert!(!fixture.receipt.exists());
    assert!(transcript.client_closed);
    Ok(())
}

#[test]
fn replacing_the_receipt_parent_during_probe_never_redirects_a_private_receipt() -> Test {
    let listener = listener()?;
    let fixture = PrivateFixture::new(
        "private-output-parent",
        listener.local_addr()?,
        "operator-rtsp",
    )?;
    let parent = fixture
        .receipt
        .parent()
        .ok_or("fixture receipt parent")?
        .to_owned();
    let (output, transcript) = probed(
        listener,
        &fixture.approved(Codec::Avc)?,
        Codec::Avc,
        Behavior::PrivateRoute {
            acknowledge_teardown: true,
            replace_parent: Some(parent.clone()),
        },
    )?;
    assert!(!output.status.success());
    private_output(&output);
    let result = json_input::parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(&result, "schema")?, "fss.site_unifi_probe_result.v1");
    assert_eq!(text(&result, "status")?, "refused");
    assert!(!boolean(&result, "receipt_saved")?);
    assert!(!boolean(&result, "receipt_file_may_exist")?);
    assert!(boolean(&result, "teardown_acknowledged")?);
    assert!(!boolean(&result, "remote_session_may_exist")?);
    assert!(!fixture.receipt.exists());
    assert!(
        !parent
            .with_extension("original")
            .join("probe.json")
            .exists()
    );
    assert!(transcript.client_closed);
    Ok(())
}
