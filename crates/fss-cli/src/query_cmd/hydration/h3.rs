#![forbid(unsafe_code)]
//! H3 privacy-masked visual keyframe and crop hydration (`CAP-AGENT-HYDRATE-H3-001`).
//!
//! Security invariants enforced strictly fail-closed:
//! 1. **Dual gate:** Requires BOTH `--allow-visual-hydration` launcher grant AND
//!    `CAP-AGENT-HYDRATE-H3-001`. Missing either refuses with `ERR-CAPABILITY-DENIED-001` and
//!    decodes ZERO pixels.
//! 2. **Hard visual bounds:** `max_h3_frames` in `1..=4`, `max_h3_bytes` up to `512 KiB`,
//!    `max_dimension` in `64..=1280`, and optional `crop_box` strictly inside frame bounds.
//! 3. **Mandatory pre-crop / pre-encode privacy masking:** Resolves `current_mask(...)` at the
//!    pinned anchor and applies `transform:bounding_box_redact` (`MASK_FILL_RGB`) directly onto
//!    the decoded pixel buffer BEFORE cropping, downscaling, or pure-Rust JPEG encoding, with
//!    conservative mask-cell propagation during downscaling so zero masked pixels ever leak.
//! 4. **TOCTOU defense:** Revalidates both `current_mask` and `ImmutableRetainedSource::revalidate`
//!    before releasing any encoded frame bytes.

use std::collections::BTreeSet;
use std::path::PathBuf;

use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, HydrationLevel, LedgerAnchor, PrincipalId,
    SessionId,
};
use fss_reference::agent_follow::{AnchorToken, snapshot_anchor_token};
use fss_reference::ingest::privacy_mask::{MaskBinding, current_mask};
use fss_reference::ingest::recorded_decode::retained_source_capsule;
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits, VerifiedChunkCache};

use super::budget::{HydrationBudgetReport, HydrationCostInputs, PricingProfile, compute_budget};
use super::h3_media::{
    crop_rgb_and_mask, decode_segment_rgb, downscale_rgb_masked, resolve_h3_target,
    seal_h3_frame_receipt,
};
use super::render_json::{render_h3_answer_json, render_h3_frame_receipt_json};
use super::{
    CapabilityGrantContext, CropBox, DEFAULT_H3_JPEG_QUALITY, H3_RECEIPT_DOMAIN, H3Limits,
    HydrationError, HydrationTarget, build_readonly_cx, encode_base64, open_readonly_source,
    resolve_effective_capabilities,
};

/// Explicit request for H3 privacy-masked visual keyframe/crop hydration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H3HydrationRequest {
    /// Existing deployment root; opened strictly read-only.
    pub root: PathBuf,
    /// Audit principal label.
    pub principal: PrincipalId,
    /// Exact committed event revision or retained import target.
    pub target: HydrationTarget,
    /// Optional explicit zero-based source segment indices (`1..=max_h3_frames`).
    pub segment_indices: Vec<usize>,
    /// Hard frame-count, total-byte, and output-dimension ceilings.
    pub limits: H3Limits,
    /// Optional crop rectangle validated strictly inside original decoded bounds.
    pub crop_box: Option<CropBox>,
    /// JPEG quantizer scale in `1..=100` (default 80).
    pub jpeg_quality: u8,
    /// Optional exact current deployment anchor precondition.
    pub expected_anchor: Option<AnchorToken>,
    /// Optional H0 descriptor digest pin.
    pub expected_descriptor: Option<ContentDigest>,
    /// Optional retained session identity inspected read-only for stored capabilities.
    pub session_id: Option<SessionId>,
    /// Optional expected session symbol-table generation.
    pub session_generation: Option<u64>,
    /// Dual-gate grants (`allow_visual_hydration` AND `CAP-AGENT-HYDRATE-H3-001`).
    pub capabilities: CapabilityGrantContext,
    /// Optional per-request token ceiling verified against payload-proportional pricing.
    pub budget_tokens: Option<u64>,
}

/// Canonical per-frame privacy-redaction and encoding receipt (`fss.hydration.h3_receipt.v1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H3FrameReceipt {
    /// Canonical receipt digest under `fss.hydration.h3_receipt.v1`.
    pub receipt_digest: ContentDigest,
    /// Zero-based retained source segment index.
    pub segment_index: usize,
    /// Retained import identity containing this frame.
    pub source_import_id: ContentDigest,
    /// Verified retained source capsule digest.
    pub source_capsule_digest: ContentDigest,
    /// Authenticated sensor identity from the retained capsule.
    pub sensor_id: String,
    /// Privacy binding label (`"sensor_policy"` or `"no_policy_declared"`).
    pub privacy_mask_binding: &'static str,
    /// Canonical privacy-mask binding digest.
    pub privacy_mask_binding_digest: ContentDigest,
    /// Active privacy-mask policy digest (`None` only when no policy is declared at anchor).
    pub privacy_mask_policy_digest: Option<ContentDigest>,
    /// Active privacy-mask ledger generation (`None` only when no policy is declared at anchor).
    pub privacy_mask_generation: Option<u64>,
    /// Applied redaction transform (`"transform:bounding_box_redact"` or `"none:no_policy_at_anchor"`).
    pub applied_redaction_transform: &'static str,
    /// Permanent policy marker: unmasked access is always `"refused"`.
    pub unmasked_access: &'static str,
    /// Original decoded frame dimensions `[width, height]`.
    pub source_dimensions: [u32; 2],
    /// Applied crop rectangle in original decoded coordinates, if any.
    pub crop_box: Option<CropBox>,
    /// Final encoded JPEG width in pixels.
    pub width: u32,
    /// Final encoded JPEG height in pixels.
    pub height: u32,
    /// Complete encoded JPEG byte length.
    pub output_bytes: usize,
    /// SHA-256 of the exact returned JPEG bytes.
    pub output_jpeg_sha256: ContentDigest,
    /// Pure-Rust JPEG encoder receipt digest.
    pub encoder_receipt_digest: ContentDigest,
}

impl H3FrameReceipt {
    /// Renders this per-frame receipt as deterministic JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        render_h3_frame_receipt_json(self)
    }
}

/// One privacy-masked visual frame derivative and its canonical receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H3HydratedFrame {
    /// Zero-based retained source segment index.
    pub segment_index: usize,
    /// RFC 4648 base64 encoding of the privacy-masked baseline JPEG.
    pub jpeg_base64: String,
    /// Canonical receipt binding source custody, active mask generation, and output digest.
    pub receipt: H3FrameReceipt,
}

/// Complete anchor-pinned H3 visual hydration answer.
#[derive(Clone, Debug, PartialEq)]
pub struct H3HydrationAnswer {
    /// Exact authority anchor verified through final revalidation.
    pub anchor: LedgerAnchor,
    /// Canonical anchor token string.
    pub anchor_token: String,
    /// Evidence clock observation timestamp.
    pub observed_at_ns: i128,
    /// Target identifier label.
    pub target_label: String,
    /// Applied hard visual bounds.
    pub limits: H3Limits,
    /// Total encoded JPEG bytes across all returned frames.
    pub total_output_bytes: usize,
    /// Aggregate visual hydration receipt digest (`fss.hydration.h3_receipt.v1`).
    pub receipt_digest: ContentDigest,
    /// Ordered privacy-masked visual frames.
    pub frames: Vec<H3HydratedFrame>,
    /// Deterministic payload-proportional budget report.
    pub budget: HydrationBudgetReport,
    /// Proof pointers covering source capsules and frame receipts.
    pub proof_pointers: Vec<String>,
    /// Explicit privacy and derivation warnings.
    pub warnings: Vec<String>,
}

impl H3HydrationAnswer {
    /// Renders the complete H3 visual hydration payload as deterministic JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        render_h3_answer_json(self)
    }
}

/// Executes dual-gated, privacy-masked H3 visual keyframe/crop hydration.
pub fn hydrate_h3(
    request: &H3HydrationRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<H3HydrationAnswer, HydrationError> {
    if cancelled() {
        return Err(HydrationError::Cancelled);
    }
    // DUAL FAIL-CLOSED GATE FIRST: zero storage media read, zero pixels decoded if denied.
    if !request.capabilities.allow_visual_hydration {
        return Err(HydrationError::CapabilityDenied(
            "H3 visual hydration requires explicit --allow-visual-hydration launcher grant"
                .to_owned(),
        ));
    }
    let effective_caps = resolve_effective_capabilities(
        &request.root,
        &request.principal,
        request.session_id.as_ref(),
        request.session_generation,
        &request.capabilities.granted_capabilities,
    )?;
    request.capabilities.require_h3(&effective_caps)?;

    request.limits.validate()?;
    let quality = if request.jpeg_quality == 0 {
        DEFAULT_H3_JPEG_QUALITY
    } else {
        request.jpeg_quality
    };
    if !(1..=100).contains(&quality) {
        return Err(HydrationError::InvalidRequest(
            "jpeg_quality must be in 1..=100".into(),
        ));
    }
    if request.segment_indices.len() > request.limits.max_h3_frames {
        return Err(HydrationError::BoundsExceeded(format!(
            "requested {} segments exceeds max_h3_frames {}",
            request.segment_indices.len(),
            request.limits.max_h3_frames
        )));
    }
    let mut seen_segments = BTreeSet::new();
    for &seg in &request.segment_indices {
        if !seen_segments.insert(seg) {
            return Err(HydrationError::InvalidRequest(
                "duplicate segment index in segment_indices".into(),
            ));
        }
    }

    let cx = build_readonly_cx(&request.root, &request.principal, &effective_caps)?;
    let owner = open_readonly_source(&request.root, &cx, cancelled)?;
    let snapshot = owner.snapshot();
    let anchor_token = snapshot_anchor_token(snapshot);
    if let Some(expected) = &request.expected_anchor
        && expected.as_str() != anchor_token
    {
        return Err(HydrationError::AnchorMismatch(
            "deployment anchor changed; refresh anchor before H3 hydration".into(),
        ));
    }

    let (import_id, selected_segments, target_label) = resolve_h3_target(&owner, request)?;
    if selected_segments.is_empty() || selected_segments.len() > request.limits.max_h3_frames {
        return Err(HydrationError::BoundsExceeded(format!(
            "selected {} frames violates 1..={} bound",
            selected_segments.len(),
            request.limits.max_h3_frames
        )));
    }

    let read_limits = RetainedReadLimits::default();
    let retained =
        RetainedFileImport::open(&owner, import_id, read_limits, &cx).map_err(|err| {
            if err.stable_id() == Some("ERR-EVIDENCE-DELETED-001") {
                HydrationError::EvidenceDeleted("retained import is deleted".into())
            } else {
                HydrationError::NotFound(format!("retained import unavailable: {err}"))
            }
        })?;

    let mut frames = Vec::with_capacity(selected_segments.len());
    let mut total_output_bytes = 0_usize;
    let mut media_bytes_read = 0_u64;
    let mut decode_work_units = 0_u64;
    let mut encode_work_units = 0_u64;
    let mut verified_masks: Vec<(fss_core::SensorId, MaskBinding)> = Vec::new();
    let mut chunk_cache = VerifiedChunkCache::default();

    for &seg_index in &selected_segments {
        if cancelled() {
            return Err(HydrationError::Cancelled);
        }
        if seg_index >= retained.manifest().segment_spans.len() {
            return Err(HydrationError::NotFound(format!(
                "segment index {seg_index} out of range (total {})",
                retained.manifest().segment_spans.len()
            )));
        }
        let capsule = retained_source_capsule(&owner, &retained, seg_index).map_err(|err| {
            HydrationError::CustodyFailure(format!("capsule read refused: {err}"))
        })?;
        let capsule_digest = ContentDigest::sha256(
            &capsule
                .try_canonical_bytes()
                .map_err(|_| HydrationError::CustodyFailure("capsule encoding failed".into()))?,
        );
        // MANDATORY: resolve active privacy-mask policy at pinned anchor BEFORE decoding.
        let mask_binding = current_mask(&owner, &capsule.sensor_id).map_err(|err| {
            HydrationError::PrivacyRefused {
                error_id: err.stable_id(),
                detail: err.to_string(),
            }
        })?;
        verified_masks.push((capsule.sensor_id.clone(), mask_binding.clone()));

        let (mut rgb, source_dims, seg_media_bytes, seg_decode_work) = decode_segment_rgb(
            &owner,
            &retained,
            seg_index,
            &capsule,
            &mask_binding,
            read_limits,
            &mut chunk_cache,
            &cx,
            cancelled,
        )?;
        media_bytes_read = media_bytes_read.saturating_add(seg_media_bytes);
        decode_work_units = decode_work_units.saturating_add(seg_decode_work);

        // MANDATORY SECURITY INVARIANT: apply active privacy mask directly to decoded buffer
        // BEFORE cropping, downscaling, or JPEG encoding.
        mask_binding
            .apply_rgb(&mut rgb, source_dims)
            .map_err(|err| HydrationError::PrivacyRefused {
                error_id: err.stable_id(),
                detail: err.to_string(),
            })?;
        let allowed =
            mask_binding
                .allowed(source_dims)
                .map_err(|err| HydrationError::PrivacyRefused {
                    error_id: err.stable_id(),
                    detail: err.to_string(),
                })?;

        let (cropped_rgb, cropped_allowed, cropped_dims) = match request.crop_box {
            Some(crop) => {
                crop.validate_within(source_dims)?;
                let (c_rgb, c_allow) = crop_rgb_and_mask(&rgb, &allowed, source_dims, crop);
                (c_rgb, c_allow, [crop.width, crop.height])
            }
            None => (rgb, allowed, source_dims),
        };
        let (final_rgb, final_dims) = downscale_rgb_masked(
            &cropped_rgb,
            &cropped_allowed,
            cropped_dims,
            request.limits.max_dimension,
        );

        let remaining_bytes = request
            .limits
            .max_h3_bytes
            .checked_sub(total_output_bytes)
            .filter(|&rem| rem > 0)
            .ok_or_else(|| {
                HydrationError::BoundsExceeded(
                    "total encoded H3 JPEG bytes exceed max_h3_bytes".into(),
                )
            })?;
        let encode_limits = EncodeLimits {
            maximum_dimension: request.limits.max_dimension,
            maximum_pixels: (final_dims[0] as usize) * (final_dims[1] as usize),
            maximum_output_bytes: remaining_bytes,
        };
        let mut encode_budget = EncodeBudget::with_cancellation_probe(
            encode_limits.work_bound(PixelFormat::Rgb),
            cancelled,
        );
        let pixel_sha256 = ContentDigest::sha256(&final_rgb).bytes();
        let encoded = encode_jpeg(
            final_dims[0],
            final_dims[1],
            &final_rgb,
            pixel_sha256,
            EncodeConfig {
                quality,
                format: PixelFormat::Rgb,
            },
            &encode_limits,
            &mut encode_budget,
        )
        .map_err(|err| match err {
            fss_codec_jpeg_encode::EncodeError::Limit => HydrationError::BoundsExceeded(
                "encoded H3 JPEG exceeded max_h3_bytes ceiling".into(),
            ),
            fss_codec_jpeg_encode::EncodeError::Cancelled => HydrationError::Cancelled,
            other => HydrationError::CodecFailure(format!("H3 JPEG encode failed: {other}")),
        })?;
        encode_work_units = encode_work_units.saturating_add(encoded.receipt().work_units);
        let output_bytes = encoded.bytes().len();
        total_output_bytes = total_output_bytes
            .checked_add(output_bytes)
            .filter(|&total| total <= request.limits.max_h3_bytes)
            .ok_or_else(|| {
                HydrationError::BoundsExceeded(
                    "total encoded H3 JPEG bytes exceed max_h3_bytes".into(),
                )
            })?;

        let output_jpeg_sha256 = ContentDigest::sha256(encoded.bytes());
        let applied_transform = if mask_binding.policy().is_some() {
            "transform:bounding_box_redact"
        } else {
            "none:no_policy_at_anchor"
        };
        let frame_receipt = seal_h3_frame_receipt(
            &snapshot.anchor,
            seg_index,
            import_id,
            capsule_digest,
            capsule.sensor_id.as_str(),
            &mask_binding,
            applied_transform,
            source_dims,
            request.crop_box,
            final_dims,
            output_bytes,
            output_jpeg_sha256,
            encoded.receipt().digest(),
        );
        frames.push(H3HydratedFrame {
            segment_index: seg_index,
            jpeg_base64: encode_base64(encoded.bytes()),
            receipt: frame_receipt,
        });
    }

    // TOCTOU defense: revalidate active privacy masks and immutable custody before release.
    for (sensor, expected_mask) in &verified_masks {
        let current =
            current_mask(&owner, sensor).map_err(|err| HydrationError::PrivacyRefused {
                error_id: err.stable_id(),
                detail: err.to_string(),
            })?;
        if current != *expected_mask {
            return Err(HydrationError::AnchorMismatch(
                "sensor privacy mask generation changed during H3 hydration".into(),
            ));
        }
    }
    owner.revalidate().map_err(|err| {
        HydrationError::CustodyFailure(format!("final H3 custody revalidation failed: {err}"))
    })?;

    let mut agg = CanonicalEncoder::new();
    agg.text(H3_RECEIPT_DOMAIN);
    snapshot.anchor.encode_canonical(&mut agg);
    agg.text(&target_label);
    agg.u64(frames.len() as u64);
    for frame in &frames {
        agg.digest(frame.receipt.receipt_digest);
    }
    let receipt_digest = ContentDigest::sha256(&agg.finish());

    let mut proof_pointers: Vec<String> = frames
        .iter()
        .flat_map(|f| {
            [
                f.receipt.source_capsule_digest.to_text(),
                f.receipt.output_jpeg_sha256.to_text(),
                f.receipt.receipt_digest.to_text(),
            ]
        })
        .collect();
    proof_pointers.push(receipt_digest.to_text());
    proof_pointers.sort();
    proof_pointers.dedup();

    let placeholder_budget = compute_budget(
        PricingProfile::PayloadProportionalV2,
        &HydrationCostInputs {
            level: HydrationLevel::H3,
            serialized_bytes: 0,
            storage_reads: 0,
            media_bytes_read,
            decode_work_units,
            encode_work_units,
            frame_count: frames.len(),
        },
    )?;
    let mut answer = H3HydrationAnswer {
        anchor: snapshot.anchor.clone(),
        anchor_token,
        observed_at_ns: snapshot.latest_evidence_time.0,
        target_label,
        limits: request.limits,
        total_output_bytes,
        receipt_digest,
        frames,
        budget: placeholder_budget,
        proof_pointers,
        warnings: vec![
            "H3 visual derivatives are privacy-masked BEFORE cropping, downscaling, and lossy baseline JPEG encoding."
                .to_owned(),
            "Unmasked pixel access is permanently refused; visual derivatives grant no identity or effect authority."
                .to_owned(),
        ],
    };

    let usage = owner.usage();
    let serialized_bytes = answer.to_json().len();
    let budget = compute_budget(
        PricingProfile::PayloadProportionalV2,
        &HydrationCostInputs {
            level: HydrationLevel::H3,
            serialized_bytes,
            storage_reads: usage.read_objects,
            media_bytes_read,
            decode_work_units,
            encode_work_units,
            frame_count: answer.frames.len(),
        },
    )?;
    if let Some(limit) = request.budget_tokens
        && budget.vector.tokens > limit
    {
        return Err(HydrationError::BoundsExceeded(format!(
            "H3 visual response requires {} tokens, exceeding requested ceiling {limit}",
            budget.vector.tokens
        )));
    }
    answer.budget = budget;
    Ok(answer)
}
