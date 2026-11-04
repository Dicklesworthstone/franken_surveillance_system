#![forbid(unsafe_code)]
//! Native planner contracts over synthetic handoffs and actual private-file observations.

use super::*;
use crate::capture_plan::prepare_onvif;
use fss_reference::site::parse_probe_receipts;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

#[allow(dead_code, unused_imports)]
#[path = "../bin/fss-onvif/private_file.rs"]
mod private_file;

pub(crate) type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(crate) const ROOT: &str = "/PRIVATE_CAPABILITY_CANARY";
pub(crate) const PRESENTATION: &str =
    "/PRIVATE_CAPABILITY_CANARY/%4a/main?opaque=PRIVATE_QUERY_CANARY";

pub(crate) struct Fixture {
    pub(crate) directory: PathBuf,
    lease: private_file::InputLease,
    fingerprint: [u8; 88],
    pub(crate) spec: OnvifSourceSpec,
    profile_digest: ContentDigest,
    pub(crate) manifest: SiteManifest,
    pub(crate) receipts: Vec<SiteProbeReceipt>,
    pub(crate) options: SitePlanOptions,
}

impl Fixture {
    pub(crate) fn new(codec: ProbeCodec, media2: bool) -> Test<Self> {
        Self::with_profile(codec, media2, b"PRIVATE_PROFILE_TOKEN_CANARY")
    }

    fn with_profile(codec: ProbeCodec, media2: bool, profile: &[u8]) -> Test<Self> {
        let profile_digest = ContentDigest::sha256(profile);
        let directory = std::env::temp_dir().canonicalize()?.join(format!(
            "fss-site-onvif-compiler-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        DirBuilder::new().mode(0o700).create(&directory)?;
        let mut manifest = SiteManifest::parse(include_str!(
            "../../../../fixtures/site_probe/manifest.v1.json"
        ))?;
        let source = &mut manifest.sources[0];
        source.kind = SourceKind::Onvif;
        source.peer = "192.0.2.10:80".parse()?;
        source.authority = "camera-10.example:80".to_owned();
        source.presentation = None;
        source.control_root = None;
        source.onvif_service_path = Some("/onvif/device_service".to_owned());
        let mut receipt =
            parse_probe_receipts(include_bytes!("../../../../fixtures/site/probes.v1.json"))?
                .remove(if codec == ProbeCodec::Hevc { 1 } else { 0 });
        receipt.site_id = manifest.site_id.clone();
        receipt.source_id = source.source_id.clone();
        receipt.source_generation = source.generation;
        receipt.peer = "192.0.2.10:554".parse()?;
        receipt.authority = "camera-10.example:554".to_owned();
        receipt.presentation = PRESENTATION.to_owned();
        receipt.control_root = ROOT.to_owned();
        receipt.manifest_digest = manifest.digest()?;
        receipt.validate()?;
        let mut fields = vec![
            (
                "schema",
                string(if media2 {
                    "fss.onvif_rtsp_handoff.v2"
                } else {
                    "fss.onvif_rtsp_handoff.v1"
                }),
            ),
            (
                "onboarding_plan",
                string(&ContentDigest::sha256(b"historical-onboarding-plan").to_text()),
            ),
            ("profile_digest", string(&profile_digest.to_text())),
            ("peer", string(&receipt.peer.to_string())),
            ("authority", string(&receipt.authority)),
            (
                "uri",
                string(&format!("rtsp://{}{}", receipt.authority, PRESENTATION)),
            ),
            ("codec", string(codec.as_str())),
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
                ("invalid_after_connect", "false".to_owned()),
                ("invalid_after_reboot", "false".to_owned()),
                ("timeout", string("PT0S")),
            ]);
        }
        fields.extend([
            ("capture_authorized", "false".to_owned()),
            ("source_evidence", "false".to_owned()),
        ]);
        let bytes = object(&fields).into_bytes();
        let source_file = directory.join("handoff.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source_file)?;
        file.write_all(&bytes)?;
        drop(file);
        let lease = private_file::InputLease::open(&source_file, &|| Ok(()))?;
        let fingerprint = lease.fingerprint();
        Ok(Self {
            options: SitePlanOptions {
                epoch: 29,
                archive_root: directory.join("archives-not-created"),
                pins_root: directory.join("pins-not-created"),
                principal: "principal:local-operator".to_owned(),
                stop_after_pictures: 3,
            },
            spec: OnvifSourceSpec {
                source: source_file,
                expected: ContentDigest::sha256(&bytes),
            },
            directory,
            lease,
            fingerprint,
            profile_digest,
            manifest,
            receipts: vec![receipt],
        })
    }

    pub(crate) fn input(&self) -> SiteOnvifInput<'_> {
        SiteOnvifInput {
            source_id: &self.manifest.sources[0].source_id,
            spec: &self.spec,
            onboarding_plan: ContentDigest::sha256(b"historical-onboarding-plan"),
            profile_digest: self.profile_digest,
            peer: "192.0.2.10:554".parse().expect("fixture peer"),
            authority: "camera-10.example:554",
            control_root: ROOT,
            input: ProtectedOnvifInput {
                bytes: self.lease.bytes(),
                fingerprint: &self.fingerprint,
            },
        }
    }

    pub(crate) fn compile(&self) -> Result<SitePlan, SitePlanError> {
        compile_with_protected(
            &self.manifest,
            &self.receipts,
            &self.options,
            &[],
            &[self.input()],
        )
    }

    pub(crate) fn rebind(&mut self) -> Test {
        let digest = self.manifest.digest()?;
        for receipt in &mut self.receipts {
            receipt.manifest_digest = digest;
        }
        Ok(())
    }

    pub(crate) fn binding_document(&self) -> Test<Vec<u8>> {
        let input = self.input();
        Ok(object(&[
            (
                "schema",
                string(crate::site_onvif::SITE_ONVIF_BINDINGS_SCHEMA),
            ),
            (
                "manifest_digest",
                string(&self.manifest.digest()?.to_text()),
            ),
            (
                "sources",
                array(&[object(&[
                    ("source_id", string(input.source_id)),
                    (
                        "source_file",
                        string(input.spec.source.to_str().ok_or("fixture path")?),
                    ),
                    ("source_digest", string(&input.spec.expected.to_text())),
                    ("onboarding_plan", string(&input.onboarding_plan.to_text())),
                    ("profile_digest", string(&input.profile_digest.to_text())),
                    ("rtsp_peer", string(&input.peer.to_string())),
                    ("rtsp_authority", string(input.authority)),
                    ("control_root", string(input.control_root)),
                ])]),
            ),
        ])
        .into_bytes())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn option<'a>(source: &'a SiteSourcePlan, key: &str) -> Test<&'a str> {
    source
        .argv()
        .windows(2)
        .find(|pair| pair[0] == key)
        .map(|pair| pair[1].as_str())
        .ok_or_else(|| format!("missing option {key}").into())
}

#[test]
fn media1_and_media2_sites_use_the_actual_native_handoff_planner_without_private_routes() -> Test {
    for (codec, media2) in [
        (ProbeCodec::Avc, false),
        (ProbeCodec::Avc, true),
        (ProbeCodec::Hevc, true),
    ] {
        let fixture = Fixture::new(codec, media2)?;
        // The historical RTSP scope is independent from the unchanged ONVIF HTTP endpoint.
        assert!(fixture.receipts[0].validate_for(&fixture.manifest).is_err());
        let original = fixture.manifest.digest()?;
        let plan = fixture.compile()?;
        assert_eq!(fixture.manifest.digest()?, original);
        let source = &plan.sources()[0];
        assert_eq!(source.argv()[0], "from-onvif");
        let start = source
            .argv()
            .iter()
            .position(|arg| arg == "--root")
            .ok_or("native arguments")?;
        let args: Vec<_> = source.argv()[start..].iter().map(OsString::from).collect();
        let native = prepare_onvif(&fixture.spec, fixture.input().input, &args)?;
        assert_eq!(source.native_approval(), native.approval);
        assert_eq!(source.native_preview(), native.preview);
        assert_eq!(fixture.compile()?.approval(), plan.approval());
        assert_eq!(
            option(source, "--onvif-control-root-digest")?,
            ContentDigest::sha256(ROOT.as_bytes()).to_text()
        );
        let report = format!("{} {plan:?} {source:?}", plan.render_json());
        for canary in [
            "PRIVATE_CAPABILITY_CANARY",
            "PRIVATE_QUERY_CANARY",
            "PRIVATE_PROFILE_TOKEN_CANARY",
            "rtsp://camera-10",
        ] {
            assert!(!report.contains(canary), "private source leaked");
        }
        for key in [
            "--peer",
            "--authority",
            "--presentation",
            "--control-root",
            "--codec",
            "--approve",
        ] {
            assert!(!source.argv().iter().any(|arg| arg == key));
        }
        assert!(report.contains("operator-bound-historical-consistency"));
        assert!(!fixture.options.archive_root.exists());
        assert!(!fixture.options.pins_root.exists());
        fixture.lease.revalidate(&|| Ok(()))?;
    }
    Ok(())
}

#[test]
fn hash_reference_and_explicit_private_root_have_identical_native_approvals() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, false)?;
    let plan = fixture.compile()?;
    let source = &plan.sources()[0];
    let start = source
        .argv()
        .iter()
        .position(|arg| arg == "--root")
        .ok_or("native arguments")?;
    let mut args: Vec<_> = source.argv()[start..].iter().map(OsString::from).collect();
    let at = args
        .iter()
        .position(|arg| arg == "--onvif-control-root-digest")
        .ok_or("root reference")?;
    args[at] = OsString::from("--control-root");
    args[at + 1] = OsString::from(ROOT);
    let original = prepare_onvif(&fixture.spec, fixture.input().input, &args)?;
    assert_eq!(original.approval, source.native_approval());
    assert_eq!(original.preview, source.native_preview());
    let mut escaped = args.clone();
    escaped[at] = OsString::from("--onvif-control-root-digest");
    escaped[at + 1] =
        OsString::from(ContentDigest::sha256(format!("{ROOT}/%4a").as_bytes()).to_text());
    // Hash reconstruction never widens the native control subtree syntax contract.
    assert!(prepare_onvif(&fixture.spec, fixture.input().input, &escaped).is_err());
    args.extend([
        OsString::from("--onvif-control-root-digest"),
        OsString::from(ContentDigest::sha256(ROOT.as_bytes()).to_text()),
    ]);
    assert!(prepare_onvif(&fixture.spec, fixture.input().input, &args).is_err());
    Ok(())
}

#[test]
fn changing_selected_profile_specializes_stream_without_inventing_a_new_physical_sensor() -> Test {
    let mut original = Fixture::new(ProbeCodec::Avc, false)?;
    let selected = Fixture::with_profile(ProbeCodec::Avc, false, b"different-historical-profile")?;
    let first = original.compile()?;
    let other = selected.compile()?;
    assert_eq!(
        option(&first.sources()[0], "--sensor-id")?,
        option(&other.sources()[0], "--sensor-id")?
    );
    assert_ne!(
        option(&first.sources()[0], "--stream-id")?,
        option(&other.sources()[0], "--stream-id")?
    );
    original.options.epoch += 1;
    let next = original.compile()?;
    assert_eq!(
        option(&first.sources()[0], "--sensor-id")?,
        option(&next.sources()[0], "--sensor-id")?
    );
    assert_eq!(
        option(&first.sources()[0], "--stream-id")?,
        option(&next.sources()[0], "--stream-id")?
    );
    assert_ne!(
        option(&first.sources()[0], "--root")?,
        option(&next.sources()[0], "--root")?
    );
    assert_ne!(first.approval(), next.approval());
    Ok(())
}

#[test]
fn exact_historical_profile_onboarding_peer_and_receipt_binding_are_all_required() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, false)?;
    for kind in 0..6 {
        let mut input = fixture.input();
        match kind {
            0 => input.profile_digest = ContentDigest::sha256(b"foreign-profile"),
            1 => input.onboarding_plan = ContentDigest::sha256(b"foreign-onboarding"),
            2 => input.peer = "192.0.2.11:554".parse()?,
            3 => input.authority = "other.example:554",
            4 => input.control_root = "/",
            _ => input.source_id = "source:foreign",
        }
        assert!(
            compile_with_protected(
                &fixture.manifest,
                &fixture.receipts,
                &fixture.options,
                &[],
                &[input]
            )
            .is_err()
        );
    }
    assert!(compile(&fixture.manifest, &fixture.receipts, &fixture.options).is_err());
    assert!(
        compile_with_protected(
            &fixture.manifest,
            &fixture.receipts,
            &fixture.options,
            &[],
            &[fixture.input(), fixture.input()]
        )
        .is_err()
    );
    for kind in 0..5 {
        let mut receipts = fixture.receipts.clone();
        match kind {
            0 => receipts[0].source_generation += 1,
            1 => receipts[0].manifest_digest = ContentDigest::sha256(b"stale-manifest"),
            2 => receipts[0].presentation = format!("{ROOT}/other"),
            3 => receipts[0].authority = "other.example:554".to_owned(),
            _ => receipts[0].peer = "192.0.2.11:554".parse()?,
        }
        assert!(
            compile_with_protected(
                &fixture.manifest,
                &receipts,
                &fixture.options,
                &[],
                &[fixture.input()]
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn historical_handoff_codec_and_stability_are_not_guessed_or_downgraded() -> Test {
    let mut fixture = Fixture::new(ProbeCodec::Avc, false)?;
    let other = Fixture::new(ProbeCodec::Hevc, true)?;
    fixture.receipts[0].codec = ProbeCodec::Hevc;
    fixture.receipts[0].parameter_set_digests = other.receipts[0].parameter_set_digests.clone();
    assert!(fixture.compile().is_err());
    let fixture = Fixture::new(ProbeCodec::Hevc, false)?;
    assert!(fixture.compile().is_err());
    let fixture = Fixture::new(ProbeCodec::Avc, false)?;
    let original = std::str::from_utf8(fixture.input().input.bytes)?;
    for bytes in [
        original.replace("PT0S", "PT30S"),
        original.replace(
            "\"invalid_after_connect\":false",
            "\"invalid_after_connect\":true",
        ),
        original.replace(
            "\"capture_authorized\":false",
            "\"capture_authorized\":true",
        ),
    ] {
        let mut spec = fixture.spec.clone();
        spec.expected = ContentDigest::sha256(bytes.as_bytes());
        let mut input = fixture.input();
        input.spec = &spec;
        input.input.bytes = bytes.as_bytes();
        assert!(
            compile_with_protected(
                &fixture.manifest,
                &fixture.receipts,
                &fixture.options,
                &[],
                &[input]
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn duplicate_selected_route_refuses_the_complete_site_without_rewriting_http_sources() -> Test {
    let mut fixture = Fixture::new(ProbeCodec::Avc, false)?;
    let mut second = fixture.manifest.sources[0].clone();
    second.source_id = "source:second".to_owned();
    second.peer = "192.0.2.20:80".parse()?;
    second.authority = "camera-20.example:80".to_owned();
    fixture.manifest.sources.push(second);
    let mut receipt = fixture.receipts[0].clone();
    receipt.source_id = "source:second".to_owned();
    fixture.receipts.push(receipt);
    fixture.rebind()?;
    let mut second = fixture.input();
    second.source_id = "source:second";
    let error = compile_with_protected(
        &fixture.manifest,
        &fixture.receipts,
        &fixture.options,
        &[],
        &[fixture.input(), second],
    )
    .err()
    .ok_or("duplicate selected route must refuse")?;
    assert!(error.reason.contains("resolved source routes"));
    assert_eq!(fixture.manifest.sources[1].peer.port(), 80);
    Ok(())
}

#[test]
fn mixed_direct_jpeg_and_onvif_plans_are_atomic_and_keep_independent_native_owners() -> Test {
    let mut fixture = Fixture::new(ProbeCodec::Avc, false)?;
    let mut source = fixture.manifest.sources[0].clone();
    source.source_id = "source:jpeg".to_owned();
    source.kind = SourceKind::Rtsp;
    source.peer = "192.0.2.12:554".parse()?;
    source.authority = source.peer.to_string();
    source.onvif_service_path = None;
    source.presentation = Some("/jpeg".to_owned());
    source.control_root = Some("/jpeg".to_owned());
    let mut receipt = fixture.receipts[0].clone();
    receipt.source_id = source.source_id.clone();
    receipt.peer = source.peer;
    receipt.authority = source.authority.clone();
    receipt.presentation = "/jpeg".to_owned();
    receipt.control_root = "/jpeg".to_owned();
    receipt.codec = ProbeCodec::Jpeg;
    receipt.payload_type = 26;
    receipt.parameter_set_digests.clear();
    fixture.manifest.sources.push(source);
    fixture.receipts.push(receipt);
    fixture.rebind()?;
    let plan = fixture.compile()?;
    assert_eq!(plan.sources().len(), 2);
    assert_eq!(plan.sources()[0].argv()[0], "from-onvif");
    assert_eq!(plan.sources()[1].argv()[0], "jpeg");
    fixture.receipts[1].source_generation += 1;
    assert!(fixture.compile().is_err());
    Ok(())
}
