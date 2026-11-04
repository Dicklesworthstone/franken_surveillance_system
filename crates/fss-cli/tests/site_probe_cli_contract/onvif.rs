#![forbid(unsafe_code)]
//! Protected historical handoff → real native RTSP observation → private site receipt.
//! The independent ONVIF HTTP listener must remain untouched throughout this workflow.

use super::*;
use fss_cli::json_output::{array, object};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

const CAPABILITY: &str = "PRIVATE_ONVIF_PROBE_CAPABILITY_CANARY";
const PROFILE: &str = "PRIVATE_ONVIF_PROBE_PROFILE_CANARY";
const ROOT: &str = "/PRIVATE_ONVIF_PROBE_CAPABILITY_CANARY";
const PRESENTATION: &str =
    "/PRIVATE_ONVIF_PROBE_CAPABILITY_CANARY/%4a/main?opaque=PRIVATE_ONVIF_PROBE_QUERY_CANARY";

struct PrivateFixture {
    fixture: Fixture,
    handoff: PathBuf,
    bindings: PathBuf,
    binding: Value,
    receipt: PathBuf,
    uri: String,
    rtsp_peer: SocketAddr,
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
    fn new(label: &str, http: SocketAddr, rtsp: SocketAddr, codec: Codec) -> Test<Self> {
        let mut fixture = Fixture::new(label, http)?;
        fixture.directory.0 = fixture.directory.0.canonicalize()?;
        set(fixture.source()?, "kind", Value::Text("onvif".into()))?;
        set(fixture.source()?, "presentation", Value::Null)?;
        set(fixture.source()?, "control_root", Value::Null)?;
        set(
            fixture.source()?,
            "onvif_service_path",
            Value::Text("/onvif/device_service".into()),
        )?;
        let authority = format!("{PRIVATE_ROUTE}.test:{}", rtsp.port());
        let uri = format!("rtsp://{authority}{PRESENTATION}");
        let onboarding = ContentDigest::sha256(b"synthetic-historical-onvif-probe-plan");
        let profile = ContentDigest::sha256(PROFILE.as_bytes());
        let media2 = matches!(codec, Codec::Hevc);
        let mut fields = vec![
            (
                "schema",
                string(if media2 {
                    "fss.onvif_rtsp_handoff.v2"
                } else {
                    "fss.onvif_rtsp_handoff.v1"
                }),
            ),
            ("onboarding_plan", string(&onboarding.to_text())),
            ("profile_digest", string(&profile.to_text())),
            ("peer", string(&rtsp.to_string())),
            ("authority", string(&authority)),
            ("uri", string(&uri)),
            ("codec", string(codec.name())),
        ];
        if media2 {
            fields.extend([
                ("media_version", string("media2")),
                (
                    "uri_validity",
                    object(&[("basis", string("media2_indefinite_contract"))]),
                ),
            ]);
        } else {
            fields.extend([
                ("invalid_after_connect", "false".into()),
                ("invalid_after_reboot", "false".into()),
                ("timeout", string("PT0S")),
            ]);
        }
        fields.extend([
            ("capture_authorized", "false".into()),
            ("source_evidence", "false".into()),
        ]);
        let bytes = object(&fields).into_bytes();
        let handoff = fixture.directory.0.join("private-handoff.json");
        write_private(&handoff, &bytes)?;
        let parent = fixture.directory.0.join("private-receipts");
        fs::DirBuilder::new().mode(0o700).create(&parent)?;
        for name in ["plan-archive", "plan-pins"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(fixture.directory.0.join(name))?;
        }
        let binding = json_input::parse(&object(&[
            ("source_id", string("source:front")),
            (
                "source_file",
                string(handoff.to_str().ok_or("UTF-8 handoff path")?),
            ),
            (
                "source_digest",
                string(&ContentDigest::sha256(&bytes).to_text()),
            ),
            ("onboarding_plan", string(&onboarding.to_text())),
            ("profile_digest", string(&profile.to_text())),
            ("rtsp_peer", string(&rtsp.to_string())),
            ("rtsp_authority", string(&authority)),
            ("control_root", string(ROOT)),
        ]))?;
        let result = Self {
            bindings: fixture.directory.0.join("onvif-bindings.json"),
            receipt: parent.join("probe.json"),
            fixture,
            handoff,
            binding,
            uri,
            rtsp_peer: rtsp,
        };
        result.write()?;
        Ok(result)
    }

    fn write(&self) -> Test {
        self.fixture.write()?;
        let manifest = parse_manifest(render(&self.fixture.manifest).as_bytes())?;
        fs::write(
            &self.bindings,
            object(&[
                ("schema", string("fss.site_onvif_bindings.v1")),
                ("manifest_digest", string(&manifest.digest()?.to_text())),
                ("sources", array(&[render(&self.binding)])),
            ]),
        )?;
        Ok(())
    }

    fn args(&self, codec: Codec) -> Vec<OsString> {
        let mut args = self.fixture.args(codec);
        args.extend([
            "--onvif-bindings".into(),
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
            "--onvif-bindings".into(),
            self.bindings.as_os_str().to_owned(),
        ]);
        Ok(args)
    }
}

fn private_output(output: &Output) {
    no_secrets(output);
    for bytes in [&output.stdout, &output.stderr] {
        let rendered = String::from_utf8_lossy(bytes);
        for canary in [
            CAPABILITY,
            PROFILE,
            "PRIVATE_ONVIF_PROBE_QUERY_CANARY",
            "%4a",
            "rtsp://",
            "rtsps://",
        ] {
            assert!(
                !rendered.contains(canary),
                "protected ONVIF route escaped to CLI output"
            );
        }
    }
}

fn refusal(output: Output, connected: bool) -> Test<Value> {
    assert!(
        !output.status.success(),
        "private ONVIF probe unexpectedly succeeded"
    );
    private_output(&output);
    let value = json_input::parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(&value, "schema")?, "fss.site_probe_diagnostic.v1");
    assert_eq!(boolean(&value, "connection_attempted")?, connected);
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
fn media1_avc_and_media2_hevc_measure_private_rtsp_and_feed_original_manifest_plans() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let http = listener()?;
        let rtsp = listener()?;
        let fixture =
            PrivateFixture::new(codec.name(), http.local_addr()?, rtsp.local_addr()?, codec)?;
        let original = fs::read(fixture.fixture.directory.0.join("manifest.json"))?;
        let args = fixture.args(codec);
        let output = run(&args)?;
        private_output(&output);
        let preview_bytes = output.stdout.clone();
        let preview = good(output)?;
        assert_eq!(text(&preview, "schema")?, "fss.site_probe_plan.v1");
        assert_eq!(
            text(&preview, "presentation")?,
            ContentDigest::sha256(PRESENTATION.as_bytes()).to_text()
        );
        assert_eq!(
            text(&preview, "control_root")?,
            ContentDigest::sha256(ROOT.as_bytes()).to_text()
        );
        assert_eq!(text(&preview, "peer")?, fixture.rtsp_peer.to_string());
        let private = field(&preview, "onvif")?;
        assert_eq!(text(private, "route_projection")?, "sha256_digests");
        assert_eq!(text(private, "receipt_file_mode")?, "0600");
        assert!(boolean(private, "receipt_file_create_only")?);
        assert!(boolean(private, "private_handoff_read")?);
        assert_eq!(
            text(private, "binding_basis")?,
            "operator-bound-historical-consistency"
        );
        assert!(!boolean(private, "onvif_http_contacted")?);
        assert!(!boolean(private, "onvif_http_origin_verified")?);
        assert!(!boolean(&preview, "device_contacted")?);
        assert!(!fixture.receipt.exists());
        assert_eq!(run(&args)?.stdout, preview_bytes);
        no_connection(&http)?;
        no_connection(&rtsp)?;

        let mut approved = args;
        approved.extend(["--approve".into(), text(&preview, "approval")?.into()]);
        let (output, transcript) = probed(
            rtsp,
            &approved,
            codec,
            Behavior::PrivateRoute {
                acknowledge_teardown: true,
                replace_parent: None,
            },
        )?;
        private_output(&output);
        let result = good(output)?;
        assert_eq!(text(&result, "schema")?, "fss.site_onvif_probe_result.v1");
        assert_eq!(
            text(&result, "binding_basis")?,
            "operator-bound-historical-consistency"
        );
        assert!(boolean(&result, "receipt_saved")?);
        assert!(boolean(&result, "teardown_acknowledged")?);
        for name in [
            "remote_session_may_exist",
            "source_retained",
            "onvif_http_contacted",
            "onvif_http_origin_verified",
        ] {
            assert!(!boolean(&result, name)?);
        }
        assert_eq!(
            fs::metadata(&fixture.receipt)?.permissions().mode() & 0o777,
            0o600
        );
        let bytes = fs::read(&fixture.receipt)?;
        let receipts = parse_probe_receipts(&bytes)?;
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        let manifest = parse_manifest(&original)?;
        assert_eq!(receipt.manifest_digest, manifest.digest()?);
        assert_eq!(receipt.peer, fixture.rtsp_peer);
        assert_ne!(receipt.peer, manifest.sources[0].peer);
        assert!(
            receipt.validate_for(&manifest).is_err(),
            "generic manifest-only validation was weakened"
        );
        assert_eq!(receipt.presentation, PRESENTATION);
        assert_eq!(receipt.control_root, ROOT);
        assert_eq!(receipt.codec.as_str(), codec.name());
        assert_eq!(receipt.parameter_set_digests, codec.parameter_digests()?);
        assert_eq!(receipt.observed_frames, 3);
        assert_eq!(receipt.frame_duration_ticks, FRAME_TICKS);
        assert!(receipt.clock_evidence.is_none());
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
        assert!(!boolean(&plan, "onvif_http_origin_verified")?);
        let sources = field(&plan, "sources")?.array().ok_or("planned sources")?;
        assert_eq!(sources.len(), 1);
        assert_eq!(text(&sources[0], "kind")?, "onvif");
        let argv = field(&sources[0], "argv")?
            .array()
            .ok_or("native arguments")?;
        assert_eq!(argv.first().and_then(Value::text), Some("from-onvif"));
        for forbidden in [
            "--presentation",
            "--control-root",
            "--authority",
            "--approve",
        ] {
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
            original
        );
        no_connection(&http)?;
    }
    Ok(())
}

#[test]
fn private_onvif_grammar_and_codec_refuse_before_network_or_public_receipt_output() -> Test {
    let http = listener()?;
    let rtsp = listener()?;
    let fixture = PrivateFixture::new(
        "onvif-options",
        http.local_addr()?,
        rtsp.local_addr()?,
        Codec::Avc,
    )?;
    for missing in ["--onvif-bindings", "--receipt-file"] {
        let mut args = fixture.args(Codec::Avc);
        let at = args
            .iter()
            .position(|value| value == missing)
            .ok_or("fixture flag")?;
        args.drain(at..at + 2);
        refusal(run(&args)?, false)?;
    }
    let mut session_args = fixture.args(Codec::Avc);
    session_args.extend(["--output".into(), "session".into()]);
    refusal(run(&session_args)?, false)?;
    refusal(run(&fixture.args(Codec::Jpeg))?, false)?;
    refusal(run(&fixture.args(Codec::Hevc))?, false)?;
    refusal(run(&fixture.fixture.args(Codec::Avc))?, false)?;
    assert!(!fixture.receipt.exists());
    no_connection(&http)?;
    no_connection(&rtsp)
}

#[test]
fn independent_handoff_pins_route_and_owner_refuse_before_connect() -> Test {
    for change in 0..6 {
        let http = listener()?;
        let rtsp = listener()?;
        let mut fixture = PrivateFixture::new(
            "onvif-pins",
            http.local_addr()?,
            rtsp.local_addr()?,
            Codec::Avc,
        )?;
        match change {
            0 => set(
                &mut fixture.binding,
                "source_digest",
                Value::Text(ContentDigest::sha256(b"other handoff").to_text()),
            )?,
            1 => set(
                &mut fixture.binding,
                "onboarding_plan",
                Value::Text(ContentDigest::sha256(b"other onboarding").to_text()),
            )?,
            2 => set(
                &mut fixture.binding,
                "profile_digest",
                Value::Text(ContentDigest::sha256(b"other profile").to_text()),
            )?,
            3 => set(
                &mut fixture.binding,
                "rtsp_authority",
                Value::Text(format!("other.test:{}", rtsp.local_addr()?.port())),
            )?,
            4 => set(
                &mut fixture.binding,
                "control_root",
                Value::Text("/different-root".into()),
            )?,
            _ => set(
                fixture.fixture.source()?,
                "owner_authorized",
                Value::Bool(false),
            )?,
        }
        fixture.write()?;
        refusal(run(&fixture.args(Codec::Avc))?, false)?;
        assert!(!fixture.receipt.exists());
        no_connection(&http)?;
        no_connection(&rtsp)?;
    }
    Ok(())
}

#[test]
fn replaced_handoff_identity_and_changed_destination_invalidate_approval() -> Test {
    for change in 0..3 {
        let http = listener()?;
        let rtsp = listener()?;
        let fixture = PrivateFixture::new(
            "onvif-approval",
            http.local_addr()?,
            rtsp.local_addr()?,
            Codec::Avc,
        )?;
        let mut args = fixture.approved(Codec::Avc)?;
        match change {
            0 => {
                let bytes = fs::read(&fixture.handoff)?;
                fs::rename(&fixture.handoff, fixture.handoff.with_extension("original"))?;
                write_private(&fixture.handoff, &bytes)?;
            }
            1 => replace(
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
        let result = refusal(run(&args)?, false)?;
        assert_eq!(text(&result, "error_id")?, "ERR-SITE-PROBE-APPROVAL-001");
        assert!(!fixture.receipt.exists());
        no_connection(&http)?;
        no_connection(&rtsp)?;
    }
    Ok(())
}

#[test]
fn unsafe_handoff_permissions_and_existing_receipt_refuse_before_connect() -> Test {
    for existing in [false, true] {
        let http = listener()?;
        let rtsp = listener()?;
        let fixture = PrivateFixture::new(
            "onvif-files",
            http.local_addr()?,
            rtsp.local_addr()?,
            Codec::Avc,
        )?;
        let args = fixture.approved(Codec::Avc)?;
        let sentinel = b"EXISTING_UNRELATED_PRIVATE_RECEIPT";
        if existing {
            write_private(&fixture.receipt, sentinel)?;
        } else {
            fs::set_permissions(&fixture.handoff, fs::Permissions::from_mode(0o644))?;
        }
        refusal(run(&args)?, false)?;
        if existing {
            assert_eq!(fs::read(&fixture.receipt)?, sentinel);
        } else {
            assert!(!fixture.receipt.exists());
        }
        no_connection(&http)?;
        no_connection(&rtsp)?;
    }
    Ok(())
}

#[test]
fn onvif_media_faults_and_unsettled_teardown_never_publish_receipts() -> Test {
    for behavior in [
        Behavior::WrongSender,
        Behavior::WrongCadence,
        Behavior::LostTeardownAck,
        Behavior::WrongTeardownCseq,
    ] {
        let http = listener()?;
        let rtsp = listener()?;
        let fixture = PrivateFixture::new(
            "onvif-live-fault",
            http.local_addr()?,
            rtsp.local_addr()?,
            Codec::Avc,
        )?;
        let (output, transcript) =
            probed(rtsp, &fixture.approved(Codec::Avc)?, Codec::Avc, behavior)?;
        refusal(output, true)?;
        assert!(!fixture.receipt.exists());
        assert!(transcript.client_closed);
        no_connection(&http)?;
    }
    Ok(())
}

#[test]
fn onvif_digest_probe_uses_existing_private_credentials_and_leaves_http_untouched() -> Test {
    let http = listener()?;
    let rtsp = listener()?;
    let mut fixture = PrivateFixture::new(
        "onvif-digest",
        http.local_addr()?,
        rtsp.local_addr()?,
        Codec::Avc,
    )?;
    credentials(&mut fixture.fixture)?;
    fixture.write()?;
    let (output, transcript) = probed(
        rtsp,
        &fixture.approved(Codec::Avc)?,
        Codec::Avc,
        Behavior::Digest,
    )?;
    private_output(&output);
    let result = good(output)?;
    assert_eq!(text(&result, "schema")?, "fss.site_onvif_probe_result.v1");
    assert!(boolean(&result, "receipt_saved")?);
    assert!(boolean(&result, "credential_access_attempted")?);
    assert_eq!(transcript.signed, 5);
    assert_eq!(
        transcript.methods,
        [
            "OPTIONS", "OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"
        ]
    );
    assert!(transcript.client_closed);
    assert_eq!(parse_probe_receipts(&fs::read(&fixture.receipt)?)?.len(), 1);
    no_connection(&http)
}

#[test]
fn receipt_parent_replacement_after_play_cannot_redirect_onvif_publication() -> Test {
    let http = listener()?;
    let rtsp = listener()?;
    let fixture = PrivateFixture::new(
        "onvif-parent",
        http.local_addr()?,
        rtsp.local_addr()?,
        Codec::Avc,
    )?;
    let parent = fixture.receipt.parent().ok_or("fixture parent")?.to_owned();
    let (output, transcript) = probed(
        rtsp,
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
    assert_eq!(text(&result, "schema")?, "fss.site_onvif_probe_result.v1");
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
    no_connection(&http)
}
