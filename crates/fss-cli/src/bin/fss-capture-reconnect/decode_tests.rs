#![forbid(unsafe_code)]
use super::*;
use std::cell::Cell;
use std::fs;
use std::path::PathBuf;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, SensorId};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> Result<Self, std::io::Error> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-reconnect-decode-{name}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("test directory bound"))
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn context(root: &Path) -> Result<ReplayCx, Box<dyn std::error::Error>> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:reconnect-decode-tests".into(),
        operation_id: OperationId::parse("operation:reconnect-decode-tests")?,
        principal: "principal:reconnect-decode-tests".into(),
        capabilities: vec!["ADP-REPLAY-001".into(), "CAP-MEDIA-DECODE-001".into()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).storage_operations(8192).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:reconnect-decode"), generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
fn native(work: &mut DecodeBudget<'_>) -> Result<fss_codec_mjpeg::DecodedLuma, DecodeError> {
    fss_codec_mjpeg::decode_luma(JPEG, ContentDigest::sha256(JPEG).bytes(), ComponentInterpretation::Grayscale, DecodeLimits::default(), work)
}
fn options(root: &Path) -> Result<Options, &'static str> {
    let root = root.to_str().ok_or("path")?;
    Options::parse(&BTreeMap::from([
        ("--decode", "grayscale"), ("--privacy-root", root),
        ("--site", "site:reconnect-decode"), ("--sensor", "sensor:reconnect-decode"),
    ]), Path::new("/another/recording/archive"), 16 * 1024 * 1024)?.ok_or("decode options")
}

#[test]
fn current_masks_change_only_later_decodes_and_never_emit_the_unmasked_hash() -> TestResult {
    let directory = Directory::new("mask")?; let root = directory.0.join("deployment");
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:reconnect-decode", &cx)?;
    let sensor = SensorId::parse("sensor:reconnect-decode")?;
    let mut decoder = Decoder::new(&options(&root)?)?;
    let first = decoder.masked(SensorMask::new(&deployment, &sensor), || Ok(()), native)?;
    assert_eq!(first.mask_policy(), None);
    let dimensions = first.dimensions();
    let original = first.receipt().luma_sha256;
    let policy = PrivacyMaskPolicy::new(sensor.clone(), dimensions, &[[0, 0, dimensions[0], dimensions[1]]])?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    let second = decoder.masked(SensorMask::new(&deployment, &sensor), || Ok(()), native)?;
    assert_eq!(second.mask_policy(), Some(policy.digest()));
    assert_eq!(second.mask_generation(), Some(1));
    assert!(second.pixels().iter().all(|pixel| *pixel == 16));
    assert_ne!(original, second.receipt().luma_sha256);
    let rendered = privacy::frame_json(Some(&second));
    assert!(!rendered.contains(&super::super::byte_digest(original)));
    assert!(rendered.contains("\"pixels_emitted\":false"));
    assert_eq!(first.mask_policy(), None); // immutable earlier result, not retroactively reinterpreted
    assert_eq!(decoder.frames(), 2);
    assert_eq!(decoder.pixels(), 2 * u64::from(dimensions[0]) * u64::from(dimensions[1]));
    cx.drain_and_finalize();
    Ok(())
}
#[test]
fn exact_shared_native_budget_cannot_refill_between_frames_or_connections() -> TestResult {
    let directory = Directory::new("budget")?; let root = directory.0.join("deployment");
    let cx = context(&root)?; let deployment = ReferenceDeployment::open(&root, "site:reconnect-decode", &cx)?;
    let sensor = SensorId::parse("sensor:reconnect-decode")?;
    let mut measured = DecodeBudget::new(1_000_000_000); native(&mut measured)?;
    let cost = measured.used(); assert!(cost > 0);
    let mut opts = options(&root)?; opts.work = cost;
    let mut decoder = Decoder::new(&opts)?;
    decoder.masked(SensorMask::new(&deployment, &sensor), || Ok(()), native)?;
    assert_eq!(decoder.remaining(), 0);
    assert!(matches!(decoder.masked(SensorMask::new(&deployment, &sensor), || Ok(()), native), Err(Failure::Native(DecodeError::BudgetExhausted))));
    assert_eq!(decoder.used(), cost); assert_eq!(decoder.frames(), 1);
    cx.drain_and_finalize();
    Ok(())
}
#[test]
fn late_authority_denial_hides_all_results_but_preserves_consumed_decode_work() -> TestResult {
    let directory = Directory::new("revoke")?; let root = directory.0.join("deployment");
    let cx = context(&root)?; let deployment = ReferenceDeployment::open(&root, "site:reconnect-decode", &cx)?;
    let sensor = SensorId::parse("sensor:reconnect-decode")?;
    let mut decoder = Decoder::new(&options(&root)?)?;
    let calls = Cell::new(0);
    let result = decoder.masked(SensorMask::new(&deployment, &sensor), || {
        calls.set(calls.get() + 1);
        if calls.get() == 3 { Err(HttpCameraDenial::Revoked) } else { Ok(()) }
    }, native);
    assert!(matches!(result, Err(Failure::Authority(HttpCameraDenial::Revoked))));
    assert_eq!(decoder.frames(), 0); assert!(decoder.used() > 0); assert!(decoder.pixels() > 0);
    cx.drain_and_finalize(); Ok(())
}
#[test]
fn resolution_mismatch_refuses_without_falling_back_to_an_unmasked_plane() -> TestResult {
    let directory = Directory::new("resolution")?; let root = directory.0.join("deployment");
    let cx = context(&root)?; let mut deployment = ReferenceDeployment::open(&root, "site:reconnect-decode", &cx)?;
    let sensor = SensorId::parse("sensor:reconnect-decode")?;
    let policy = PrivacyMaskPolicy::new(sensor.clone(), [1, 1], &[[0, 0, 1, 1]])?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    let mut decoder = Decoder::new(&options(&root)?)?;
    assert!(matches!(decoder.masked(SensorMask::new(&deployment, &sensor), || Ok(()), native), Err(Failure::Privacy(MaskRefusal::Resolution { .. }))));
    assert_eq!(decoder.frames(), 0); assert!(decoder.used() > 0);
    cx.drain_and_finalize(); Ok(())
}
#[test]
fn decode_options_require_complete_current_privacy_context_and_bounded_work() -> TestResult {
    let directory = Directory::new("options")?;
    let opts = options(&directory.0)?;
    assert_eq!(opts.mode, HttpCheckDecode::Grayscale);
    let archive = Path::new("/archive");
    assert!(Options::parse(&BTreeMap::from([("--decode", "grayscale")]), archive, 4096).is_err());
    assert!(Options::parse(&BTreeMap::from([("--max-decode-work", "1")]), archive, 4096).is_err());
    assert!(Options::parse(&BTreeMap::from([("--sensor", "sensor:x")]), archive, 4096).is_err());
    for (key, value) in [("--max-decode-work", "-1"), ("--max-decode-work", "18446744073709551616"),
        ("--max-dimension", "4097"), ("--max-pixels", "0"), ("--decode", "auto")] {
        let mut values = BTreeMap::from([("--decode", "grayscale"), ("--privacy-root", "/privacy"), ("--site", "site:test"), ("--sensor", "sensor:x")]);
        values.insert(key, value);
        assert!(Options::parse(&values, archive, 4096).is_err());
    }
    let absent = directory.0.join("absent");
    assert!(options(&absent)?.privacy.open("principal:test").is_err());
    assert!(!absent.exists());
    Ok(())
}
