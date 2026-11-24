#![forbid(unsafe_code)]
//! Unit and pixel-level privacy-mask redaction audit tests for H2 and H3 hydration.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma_v1};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, HydrationLevel, OperationId, PrincipalId,
    RootAuthoritySpec, SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::file_adapter::{FileIngestAdapter, FileIngestRequest};
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

use super::budget::{HydrationCostInputs, PricingProfile, compute_budget, estimate_payload_tokens};
use super::h2::{H2HydrationRequest, hydrate_h2};
use super::h3::{H3HydrationRequest, hydrate_h3};
use super::{
    CAP_AGENT_HYDRATE_H2, CAP_AGENT_HYDRATE_H3, CapabilityGrantContext, CropBox,
    DEFAULT_H3_JPEG_QUALITY, ERR_CAPABILITY_DENIED, ERR_HYDRATION_BOUNDS, ExtendedHydrationRequest,
    H3Limits, HydrationError, HydrationTarget, decode_base64, encode_base64, execute_extended,
};
use crate::error::ExitIdentity;

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-hydration-unit-{tag}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create unit temp dir");
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn test_cx(root: &Path) -> ReplayCx {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:hydration-unit".into(),
        operation_id: OperationId::parse("operation:hydration-unit").expect("op id"),
        principal: "principal:hydration-unit".into(),
        capabilities: vec![ADP_REPLAY_ROW_ID.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(100_000)
            .build()
            .expect("budget"),
        privacy_scope: "private:property".into(),
        retention_scope: "retention:current-deletion-restrictions".into(),
        anchor_universe: ContentDigest::sha256(b"hydration-unit-test"),
        generation: 1,
    })
    .expect("context authority");
    ReplayCx::new(
        ReplayIoAuthority::from_context_authority(&authority, root.to_path_buf())
            .expect("replay io authority"),
    )
}

/// Encodes a 128x96 RGB frame with bright white [255,255,255] inside (0,0,64,48)
/// and a distinct medium-bright scene outside for pixel-level redaction audits.
fn encode_audit_jpeg(width: u32, height: u32, variant: u32) -> Vec<u8> {
    let mut rgb = vec![0_u8; (width as usize) * (height as usize) * 3];
    for y in 0..height {
        for x in 0..width {
            let idx = ((y as usize) * (width as usize) + (x as usize)) * 3;
            if x < 64 && y < 48 {
                rgb[idx..idx + 3].copy_from_slice(&[255, 255, 255]);
            } else if x >= 80 + variant * 2 && x < 104 + variant * 2 && (56..80).contains(&y) {
                rgb[idx..idx + 3].copy_from_slice(&[235, 220, 200]);
            } else {
                rgb[idx..idx + 3].copy_from_slice(&[135, 165, 110]);
            }
        }
    }
    let limits = EncodeLimits::default();
    let mut budget = EncodeBudget::new(limits.work_bound(PixelFormat::Rgb));
    let digest = ContentDigest::sha256(&rgb).bytes();
    encode_jpeg(
        width,
        height,
        &rgb,
        digest,
        EncodeConfig {
            quality: 90,
            format: PixelFormat::Rgb,
        },
        &limits,
        &mut budget,
    )
    .expect("encode audit jpeg")
    .into_bytes()
}

struct MaskedFixture {
    _tmp: TempDir,
    root: PathBuf,
    import_id: ContentDigest,
    policy_digest: ContentDigest,
}

impl MaskedFixture {
    fn create(tag: &str, frame_count: u32) -> Self {
        let tmp = TempDir::new(tag);
        let root = tmp.0.join("deployment");
        let cx = test_cx(&tmp.0.join("cx"));
        let mut deployment =
            ReferenceDeployment::open(&root, "site:hydration-unit", &cx).expect("open");
        let mut mjpeg = Vec::new();
        for i in 0..frame_count {
            mjpeg.extend_from_slice(&encode_audit_jpeg(128, 96, i));
        }
        let mjpeg_path = tmp.0.join("recording.mjpeg");
        fs::write(&mjpeg_path, &mjpeg).expect("write mjpeg");
        let sensor = SensorId::parse("sensor:front-door").expect("sensor");
        let stream = StreamId::parse("stream:main").expect("stream");
        let req = FileIngestRequest::new(&mjpeg_path, sensor.clone(), stream)
            .with_receive_time(TimestampNs(1_700_000_000_000_000_000));
        let receipt = FileIngestAdapter::ingest(req, &cx, &mut deployment).expect("ingest");
        let policy = PrivacyMaskPolicy::new(sensor, [128, 96], &[[0, 0, 64, 48]]).expect("policy");
        let preview = preview_mask(&deployment, &policy).expect("preview");
        let declared = declare_mask(&mut deployment, &policy, preview.approval, &cx).expect("mask");
        Self {
            _tmp: tmp,
            root,
            import_id: receipt.import_identity,
            policy_digest: declared.policy_digest,
        }
    }

    fn h3_req(
        &self,
        segs: Vec<usize>,
        caps: BTreeSet<String>,
        allow_visual: bool,
    ) -> H3HydrationRequest {
        H3HydrationRequest {
            root: self.root.clone(),
            principal: PrincipalId::parse("principal:auditor").expect("principal"),
            target: HydrationTarget::Import {
                import_id: self.import_id,
            },
            segment_indices: segs,
            limits: H3Limits::default(),
            crop_box: None,
            jpeg_quality: DEFAULT_H3_JPEG_QUALITY,
            expected_anchor: None,
            expected_descriptor: None,
            session_id: None,
            session_generation: None,
            capabilities: CapabilityGrantContext {
                granted_capabilities: caps,
                allow_visual_hydration: allow_visual,
            },
            budget_tokens: None,
        }
    }
}

fn decode_luma(jpeg: &[u8]) -> (Vec<u8>, [u32; 2]) {
    let digest = ContentDigest::sha256(jpeg).bytes();
    let limits = DecodeLimits::default();
    let mut budget = DecodeBudget::new(limits.luma_work_bound());
    let decoded = decode_luma_v1(
        jpeg,
        digest,
        ComponentInterpretation::YCbCr,
        limits,
        &mut budget,
    )
    .expect("decode JPEG luma");
    (decoded.pixels().to_vec(), decoded.dimensions())
}

fn assert_masked_rect_dark(luma: &[u8], width: usize, mask_w: usize, mask_h: usize, ctx: &str) {
    for y in 0..mask_h {
        for x in 0..mask_w {
            let val = luma[y * width + x];
            assert!(
                val <= 28,
                "{ctx}: masked pixel ({x},{y}) leaked luma={val} (MASK_FILL_LUMA={MASK_FILL_LUMA})"
            );
        }
    }
}

#[test]
fn pixel_level_privacy_mask_audit_full_frame_crop_and_downscale() {
    let fixture = MaskedFixture::create("pixel-audit", 2);
    let caps = BTreeSet::from([CAP_AGENT_HYDRATE_H3.to_owned()]);

    // 1) Full-frame H3 hydration.
    let full = hydrate_h3(&fixture.h3_req(vec![0], caps.clone(), true), &|| false)
        .expect("full-frame H3 succeeds");
    assert_eq!(full.frames.len(), 1);
    let frame = &full.frames[0];
    assert_eq!(frame.receipt.privacy_mask_binding, "sensor_policy");
    assert_eq!(
        frame.receipt.privacy_mask_policy_digest,
        Some(fixture.policy_digest)
    );
    assert_eq!(frame.receipt.privacy_mask_generation, Some(1));
    assert_eq!(
        frame.receipt.applied_redaction_transform,
        "transform:bounding_box_redact"
    );
    assert_eq!(frame.receipt.unmasked_access, "refused");
    assert_eq!([frame.receipt.width, frame.receipt.height], [128, 96]);

    let jpeg_bytes = decode_base64(&frame.jpeg_base64).expect("decode base64");
    assert_eq!(
        ContentDigest::sha256(&jpeg_bytes),
        frame.receipt.output_jpeg_sha256
    );
    let (luma, dims) = decode_luma(&jpeg_bytes);
    assert_eq!(dims, [128, 96]);
    assert_masked_rect_dark(&luma, 128, 64, 48, "full-frame");
    assert!(
        luma[72 * 128 + 100] > 100,
        "unmasked scene must remain visible"
    );

    // 2) Overlapping crop (16, 8, 96, 72): masked rect (0..64, 0..48) maps to (0..48, 0..40).
    let mut crop_req = fixture.h3_req(vec![1], caps.clone(), true);
    crop_req.crop_box = Some(CropBox {
        x: 16,
        y: 8,
        width: 96,
        height: 72,
    });
    let cropped = hydrate_h3(&crop_req, &|| false).expect("cropped H3 succeeds");
    let c_bytes = decode_base64(&cropped.frames[0].jpeg_base64).expect("decode crop base64");
    assert_eq!(
        ContentDigest::sha256(&c_bytes),
        cropped.frames[0].receipt.output_jpeg_sha256
    );
    let (c_luma, c_dims) = decode_luma(&c_bytes);
    assert_eq!(c_dims, [96, 72]);
    assert_masked_rect_dark(&c_luma, 96, 48, 40, "overlapping-crop");
    assert!(c_luma[60 * 96 + 75] > 100);

    // 3) Downscaled masked frame (max_dimension = 64 -> 64x48; mask maps to 0..32, 0..24).
    let mut scale_req = fixture.h3_req(vec![0], caps, true);
    scale_req.limits.max_dimension = 64;
    let scaled = hydrate_h3(&scale_req, &|| false).expect("downscaled H3 succeeds");
    let s_bytes = decode_base64(&scaled.frames[0].jpeg_base64).expect("decode scaled base64");
    let (s_luma, s_dims) = decode_luma(&s_bytes);
    assert_eq!(s_dims, [64, 48]);
    assert_masked_rect_dark(&s_luma, 64, 32, 24, "downscaled");
}

#[test]
fn fail_closed_capability_and_launcher_gates() {
    let fixture = MaskedFixture::create("gates", 1);
    let principal = PrincipalId::parse("principal:auditor").expect("principal");
    let h3_caps = BTreeSet::from([CAP_AGENT_HYDRATE_H3.to_owned()]);

    // H3 without --allow-visual-hydration -> ERR-CAPABILITY-DENIED-001.
    let no_flag_req = fixture.h3_req(vec![0], h3_caps, false);
    let err = hydrate_h3(&no_flag_req, &|| false).expect_err("refuse without launcher flag");
    assert!(matches!(err, HydrationError::CapabilityDenied(_)));
    assert_eq!(err.error_id(), ERR_CAPABILITY_DENIED);
    let (json, exit) = execute_extended(
        &ExtendedHydrationRequest::H3(no_flag_req),
        &crate::RequestControl::uncancelled(),
    );
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert!(json.contains(ERR_CAPABILITY_DENIED) && json.contains("\"payload\":null"));

    // H3 WITH --allow-visual-hydration WITHOUT CAP-AGENT-HYDRATE-H3-001 -> ERR-CAPABILITY-DENIED-001.
    let no_cap = hydrate_h3(&fixture.h3_req(vec![0], BTreeSet::new(), true), &|| false)
        .expect_err("refuse without H3 capability");
    assert_eq!(no_cap.error_id(), ERR_CAPABILITY_DENIED);

    // H2 WITHOUT CAP-AGENT-HYDRATE-H2-001 -> ERR-CAPABILITY-DENIED-001.
    let h2_base = |caps: BTreeSet<String>| H2HydrationRequest {
        root: fixture.root.clone(),
        principal: principal.clone(),
        target: HydrationTarget::Import {
            import_id: fixture.import_id,
        },
        expected_anchor: None,
        expected_descriptor: None,
        session_id: None,
        session_generation: None,
        capabilities: CapabilityGrantContext {
            granted_capabilities: caps,
            allow_visual_hydration: false,
        },
        budget_tokens: None,
    };
    let h2_err = hydrate_h2(&h2_base(BTreeSet::new()), &|| false).expect_err("refuse H2");
    assert_eq!(h2_err.error_id(), ERR_CAPABILITY_DENIED);

    let h2_ok = hydrate_h2(
        &h2_base(BTreeSet::from([CAP_AGENT_HYDRATE_H2.to_owned()])),
        &|| false,
    )
    .expect("H2 import projection succeeds");
    assert_eq!(
        h2_ok.import_privacy_binding.as_deref(),
        Some("sensor_policy")
    );
    assert!(!h2_ok.receipt.calibrated);
}

#[test]
fn h3_visual_bounds_are_enforced_fail_closed() {
    let fixture = MaskedFixture::create("bounds", 1);
    let caps = BTreeSet::from([CAP_AGENT_HYDRATE_H3.to_owned()]);

    for bad_frames in [0_usize, 5] {
        let mut req = fixture.h3_req(vec![0], caps.clone(), true);
        req.limits.max_h3_frames = bad_frames;
        assert_eq!(
            hydrate_h3(&req, &|| false)
                .expect_err("bad frame count")
                .error_id(),
            ERR_HYDRATION_BOUNDS
        );
    }
    let mut tiny_bytes = fixture.h3_req(vec![0], caps.clone(), true);
    tiny_bytes.limits.max_h3_bytes = 64;
    assert_eq!(
        hydrate_h3(&tiny_bytes, &|| false)
            .expect_err("tiny byte cap")
            .error_id(),
        ERR_HYDRATION_BOUNDS
    );
    for bad_dim in [32_u32, 2048] {
        let mut req = fixture.h3_req(vec![0], caps.clone(), true);
        req.limits.max_dimension = bad_dim;
        assert_eq!(
            hydrate_h3(&req, &|| false)
                .expect_err("bad max_dimension")
                .error_id(),
            ERR_HYDRATION_BOUNDS
        );
    }
    let mut bad_crop = fixture.h3_req(vec![0], caps, true);
    bad_crop.crop_box = Some(CropBox {
        x: 100,
        y: 0,
        width: 40,
        height: 32,
    });
    assert_eq!(
        hydrate_h3(&bad_crop, &|| false)
            .expect_err("out-of-bounds crop")
            .error_id(),
        ERR_HYDRATION_BOUNDS
    );
}

#[test]
fn payload_proportional_budget_and_base64_roundtrip() {
    assert_eq!(estimate_payload_tokens(0), 0);
    assert_eq!(estimate_payload_tokens(1), 1);
    assert_eq!(estimate_payload_tokens(4), 1);
    assert_eq!(estimate_payload_tokens(5), 2);
    assert_eq!(estimate_payload_tokens(4001), 1001);

    let legacy_h0 = compute_budget(
        PricingProfile::LegacyV1,
        &HydrationCostInputs {
            level: HydrationLevel::H0,
            serialized_bytes: 120,
            storage_reads: 2,
            media_bytes_read: 0,
            decode_work_units: 0,
            encode_work_units: 0,
            frame_count: 0,
        },
    )
    .expect("legacy h0");
    assert_eq!(legacy_h0.vector.tokens, 5_000);

    let v2_h3 = compute_budget(
        PricingProfile::PayloadProportionalV2,
        &HydrationCostInputs {
            level: HydrationLevel::H3,
            serialized_bytes: 12_001,
            storage_reads: 7,
            media_bytes_read: 9_000,
            decode_work_units: 500,
            encode_work_units: 400,
            frame_count: 2,
        },
    )
    .expect("v2 h3");
    assert_eq!(v2_h3.vector.tokens, 3_001);
    assert_eq!(v2_h3.vector.bytes, 12_001 + 9_000);
    assert_eq!(v2_h3.vector.storage_operations, 7);

    for len in [0_usize, 1, 2, 3, 4, 17, 257] {
        let data: Vec<u8> = (0..len).map(|i| ((i * 37) % 256) as u8).collect();
        assert_eq!(decode_base64(&encode_base64(&data)).expect("b64"), data);
    }
    assert!(decode_base64("AB=").is_err());
    assert!(decode_base64("AB==").is_err());
}
