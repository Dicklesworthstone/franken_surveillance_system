#![forbid(unsafe_code)]

use super::enforce::ZoneMasking;
use super::*;
use crate::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeError,
    RecordedDecodeRequest, RecordedFrame,
};
use crate::ingest::{FileIngestAdapter, FileIngestRequest, RetainedReadLimits};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, StreamId};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

const JPEG: &[u8] = include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
const SITE: &str = "site:privacy-mask";
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-privacy-mask-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sensor() -> TestResult<SensorId> {
    Ok(SensorId::parse("sensor:privacy-mask")?)
}

fn context(root: &std::path::Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:privacy-mask".to_owned(),
        operation_id: OperationId::parse("operation:privacy-mask")?,
        principal: "principal:privacy-mask".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn deployment(
    name: &str,
) -> TestResult<(
    OwnedDirectory,
    ReplayCx,
    ReferenceDeployment,
    RecordedDecodeRequest,
)> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("source.mjpeg");
    fs::write(&path, [JPEG, JPEG].concat())?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let request = FileIngestRequest::new(path, sensor()?, StreamId::parse("stream:privacy-mask")?)
        .with_receive_time(TimestampNs(1_000_000_000));
    let imported = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
    let request = RecordedDecodeRequest {
        import_identity: imported.import_identity,
        segment_index: 1,
        interpretation: ComponentInterpretation::Grayscale,
        read_limits: RetainedReadLimits::default(),
        decode_limits: DecodeLimits::default(),
    };
    Ok((directory, cx, deployment, request))
}

fn policy(resolution: [u32; 2], rectangles: &[[u32; 4]]) -> TestResult<PrivacyMaskPolicy> {
    Ok(PrivacyMaskPolicy::new(sensor()?, resolution, rectangles)?)
}

#[test]
fn policy_bytes_are_canonical_order_independent_and_strictly_decoded() -> TestResult {
    let a = policy([64, 48], &[[8, 8, 16, 16], [0, 0, 4, 4]])?;
    let b = policy([64, 48], &[[0, 0, 4, 4], [8, 8, 16, 16]])?;
    assert_eq!(a, b);
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.regions()[0].method(), "transform:bounding_box_redact");
    let bytes = a.to_bytes();
    assert_eq!(PrivacyMaskPolicy::from_bytes(&bytes, a.digest())?, a);
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        PrivacyMaskPolicy::from_bytes(&tampered, ContentDigest::sha256(&tampered)),
        Err(PrivacyMaskError::InvalidRecord)
    ));
    assert!(PrivacyMaskPolicy::from_bytes(&bytes, ContentDigest::sha256(b"other")).is_err());
    let mut suffixed = bytes;
    suffixed.push(0);
    assert!(PrivacyMaskPolicy::from_bytes(&suffixed, ContentDigest::sha256(&suffixed)).is_err());
    Ok(())
}

#[test]
fn invalid_policies_are_typed_refusals() -> TestResult {
    let too_many: Vec<[u32; 4]> = (0..33).map(|i| [i, 0, 1, 1]).collect();
    for (resolution, rectangles) in [
        ([64, 48], vec![]),
        ([64, 48], vec![[0, 0, 0, 4]]),
        ([64, 48], vec![[60, 0, 8, 4]]),
        ([64, 48], vec![[0, 40, 4, 9]]),
        ([64, 48], vec![[1, 1, 2, 2], [1, 1, 2, 2]]),
        ([0, 48], vec![[0, 0, 1, 1]]),
        ([4097, 48], vec![[0, 0, 1, 1]]),
        ([64, 48], too_many),
    ] {
        let refused = PrivacyMaskPolicy::new(sensor()?, resolution, &rectangles);
        assert!(
            matches!(&refused, Err(error) if error.stable_id() == "ERR-PRIVACY-MASK-POLICY-001"),
            "{resolution:?} {rectangles:?}: {refused:?}"
        );
    }
    Ok(())
}

#[test]
fn binding_digests_mark_absence_explicitly_and_differ_per_policy() -> TestResult {
    let first = policy([64, 48], &[[0, 0, 8, 8]])?;
    let second = policy([64, 48], &[[0, 0, 8, 9]])?;
    let none = binding_digest(None);
    assert_eq!(MaskBinding::NoPolicy.digest(), none);
    assert_ne!(binding_digest(Some(first.digest())), none);
    assert_ne!(
        binding_digest(Some(first.digest())),
        binding_digest(Some(second.digest()))
    );
    for marker in [None, Some(first.digest())] {
        let mut e = CanonicalEncoder::new();
        encode_marker(&mut e, marker);
        let bytes = e.finish();
        let mut d = CanonicalDecoder::new(&bytes);
        assert_eq!(decode_marker(&mut d)?, marker);
        d.ensure_finished()?;
    }
    let mut d = CanonicalDecoder::new(&[2]);
    assert!(decode_marker(&mut d).is_err());
    Ok(())
}

fn bound(policy: PrivacyMaskPolicy) -> MaskBinding {
    MaskBinding::Policy(Box::new(RetainedMaskPolicy {
        digest: policy.digest(),
        policy,
        generation: 1,
    }))
}

#[test]
fn planes_are_filled_exactly_and_chroma_conservatively() -> TestResult {
    let dims = [6, 5];
    let mask = bound(policy(dims, &[[1, 1, 2, 3]])?);
    let mut luma = vec![200_u8; 30];
    mask.apply_luma(&mut luma, dims)?;
    for y in 0..5 {
        for x in 0..6 {
            let expected = if (1..3).contains(&x) && (1..4).contains(&y) {
                MASK_FILL_LUMA
            } else {
                200
            };
            assert_eq!(luma[y * 6 + x], expected, "({x},{y})");
        }
    }
    // Chroma 3x3: luma columns 1..=2 touch chroma columns 0..=1, rows 1..=3 touch rows 0..=1.
    let mut cb = vec![90_u8; 9];
    let mut cr = vec![170_u8; 9];
    mask.apply_chroma420(&mut cb, &mut cr, dims)?;
    for row in 0..3 {
        for column in 0..3 {
            let masked = column <= 1 && row <= 1;
            assert_eq!(
                cb[row * 3 + column],
                if masked { MASK_FILL_CHROMA } else { 90 }
            );
            assert_eq!(
                cr[row * 3 + column],
                if masked { MASK_FILL_CHROMA } else { 170 }
            );
        }
    }
    let mut rgb = vec![7_u8; 90];
    mask.apply_rgb(&mut rgb, dims)?;
    assert_eq!(&rgb[(6 + 1) * 3..(6 + 1) * 3 + 3], &MASK_FILL_RGB);
    assert_eq!(&rgb[0..3], &[7, 7, 7]);
    let allowed = mask.allowed(dims)?;
    assert_eq!(allowed.iter().filter(|v| **v == 0).count(), 6);
    assert_eq!(allowed[7], 0);
    assert_eq!(allowed[0], 1);

    // No policy changes nothing; a resolution mismatch never passes pixels through.
    let mut untouched = vec![200_u8; 30];
    MaskBinding::NoPolicy.apply_luma(&mut untouched, dims)?;
    assert!(untouched.iter().all(|v| *v == 200));
    let refused = mask.apply_luma(&mut [0_u8; 42], [7, 6]);
    assert!(matches!(
        refused,
        Err(PrivacyMaskError::ResolutionMismatch {
            declared: [6, 5],
            decoded: [7, 6]
        })
    ));
    assert!(mask.apply_luma(&mut [0_u8; 29], dims).is_err());
    Ok(())
}

#[test]
fn zone_masking_distinguishes_unmasked_partial_and_full_cover() -> TestResult {
    let p = policy([96, 48], &[[0, 0, 48, 32], [48, 0, 48, 16]])?;
    assert_eq!(p.zone_masking([0, 36, 96, 12]), ZoneMasking::Unmasked);
    assert_eq!(p.zone_masking([40, 8, 16, 16]), ZoneMasking::Partial);
    assert_eq!(p.zone_masking([8, 8, 60, 8]), ZoneMasking::Full);
    assert_eq!(p.zone_masking([200, 200, 4, 4]), ZoneMasking::Unmasked);
    Ok(())
}

#[test]
fn declaration_is_approval_gated_idempotent_and_stale_approvals_are_refused() -> TestResult {
    let (_directory, cx, mut deployment, _) = deployment("declare")?;
    let first = policy([64, 48], &[[0, 0, 8, 8]])?;
    let anchor = deployment.current_anchor().clone();
    let preview = preview_mask(&deployment, &first)?;
    assert_eq!(preview.status, MaskDeclarationStatus::Proposed);
    assert_eq!(preview.generation, None);
    assert_eq!(
        *deployment.current_anchor(),
        anchor,
        "a preview writes nothing"
    );
    assert_eq!(
        current_mask(&deployment, &sensor()?)?,
        MaskBinding::NoPolicy
    );

    let wrong = ContentDigest::sha256(b"not an approval");
    assert!(matches!(
        declare_mask(&mut deployment, &first, wrong, &cx),
        Err(PrivacyMaskError::StaleApproval(_))
    ));
    assert_eq!(*deployment.current_anchor(), anchor);

    let retained = declare_mask(&mut deployment, &first, preview.approval, &cx)?;
    assert_eq!(retained.status, MaskDeclarationStatus::Retained);
    assert_eq!(retained.generation, Some(1));
    let after = deployment.current_anchor().clone();
    let again = declare_mask(&mut deployment, &first, preview.approval, &cx)?;
    assert_eq!(again.status, MaskDeclarationStatus::AlreadyCurrent);
    assert_eq!(
        *deployment.current_anchor(),
        after,
        "an exact rerun writes nothing"
    );
    let current = current_mask(&deployment, &sensor()?)?;
    assert_eq!(current.policy_digest(), Some(first.digest()));
    assert_eq!(current.generation(), Some(1));

    // A preview computed against generation 1 goes stale once generation 2 is retained.
    let second = policy([64, 48], &[[8, 8, 8, 8]])?;
    let third = policy([64, 48], &[[16, 16, 8, 8]])?;
    let stale = preview_mask(&deployment, &second)?;
    let replacing = preview_mask(&deployment, &third)?;
    assert_eq!(replacing.replaces, Some(first.digest()));
    declare_mask(&mut deployment, &third, replacing.approval, &cx)?;
    let refused = declare_mask(&mut deployment, &second, stale.approval, &cx);
    assert!(matches!(&refused, Err(PrivacyMaskError::StaleApproval(_))));
    assert_eq!(
        refused.err().map(|e| e.stable_id()),
        Some("ERR-PRIVACY-MASK-APPROVAL-STALE-001")
    );
    let current = current_mask(&deployment, &sensor()?)?;
    assert_eq!(current.policy_digest(), Some(third.digest()));
    assert_eq!(current.generation(), Some(2));
    assert_eq!(superseded_bindings(&deployment, &sensor()?)?, {
        let mut expected = vec![binding_digest(None), binding_digest(Some(first.digest()))];
        expected.sort_unstable();
        expected
    });
    assert!(matches!(
        refuse_unmasked_source(&deployment, &sensor()?),
        Err(PrivacyMaskError::UnmaskedAccessRefused)
    ));
    Ok(())
}

#[test]
fn retained_decode_is_masked_bound_and_never_serves_another_lineage() -> TestResult {
    let (_directory, cx, mut deployment, request) = deployment("decode")?;
    let unmasked = RecordedFrame::decode_and_publish(
        &mut deployment,
        &request,
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?;
    assert_eq!(unmasked.receipt().mask_policy(), None);
    let dims = unmasked.receipt().dimensions();
    let rect = [0, 0, dims[0].min(4), dims[1].min(4)];
    let mask = policy(dims, &[rect])?;
    let preview = preview_mask(&deployment, &mask)?;
    declare_mask(&mut deployment, &mask, preview.approval, &cx)?;

    // The unmasked lineage is refused, never served, once a policy is retained.
    let refused = RecordedFrame::open(&deployment, &request, &cx);
    assert!(
        matches!(
            &refused,
            Err(RecordedDecodeError::PrivacyMask(
                PrivacyMaskError::UnmaskedAccessRefused
            ))
        ),
        "{refused:?}"
    );
    let masked = RecordedFrame::decode_and_publish(
        &mut deployment,
        &request,
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?;
    assert_eq!(masked.receipt().mask_policy(), Some(mask.digest()));
    assert_ne!(masked.receipt().identity(), unmasked.receipt().identity());
    assert_ne!(masked.receipt().digest()?, unmasked.receipt().digest()?);
    let width = dims[0] as usize;
    for y in 0..dims[1] as usize {
        for x in 0..width {
            let inside = x < rect[2] as usize && y < rect[3] as usize;
            let value = masked.pixels()[y * width + x];
            if inside {
                assert_eq!(value, MASK_FILL_LUMA);
            } else {
                assert_eq!(value, unmasked.pixels()[y * width + x]);
            }
        }
    }
    assert_eq!(
        masked.receipt().codec().luma_sha256,
        ContentDigest::sha256(masked.pixels()).bytes()
    );
    let reopened = RecordedFrame::open(&deployment, &request, &cx)?;
    assert_eq!(reopened, masked);
    reopened.verify_by_replay(
        &deployment,
        &request,
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?;
    Ok(())
}
