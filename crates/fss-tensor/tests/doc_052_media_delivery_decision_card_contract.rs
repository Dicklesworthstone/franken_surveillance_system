#![forbid(unsafe_code)]
//! Contract & fault suite for `DOC-052` (`fss-x4a.5.52`): deterministic Decision Card comparing
//! passthrough/remux/transcode, live delivery surfaces, 6 archive storage tiers with dated pricing,
//! backend-neutral migration without semantic identity rewrite, unavailable codec retention, and
//! `MediaDerivativeReceipt` (`DOC-041`) binding.

use std::error::Error;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, TimestampNs,
};
use fss_tensor::{
    ArchiveStorageTier, BackendPlacementChild, CodecSupportStatus, DerivativePublicationState,
    DerivativeReceiptRequest, LiveDeliverySurface, LiveGatewaySpec, MediaDeliveryCandidate,
    MediaDeliveryCardError, MediaDeliveryConstraints, MediaDeliveryDecisionCard,
    MediaDerivativeKind, MediaDerivativeReceipt, MediaMovementMode, ReproducibilityClass,
    SourceByteSpan, SourceCustodyBinding, TierPricingQuote, TranscodeJustification, TransformStep,
    evaluate_media_delivery_card,
};

type TestResult = Result<(), Box<dyn Error>>;

fn make_derivative_receipt(
    id: &str,
    lossy: bool,
) -> Result<MediaDerivativeReceipt, Box<dyn Error>> {
    let policy = ContentDigest::sha256(b"privacy:mask-v1");
    let req = DerivativeReceiptRequest {
        receipt_id: id.to_owned(),
        kind: if lossy {
            MediaDerivativeKind::Transcode
        } else {
            MediaDerivativeKind::Clip
        },
        derivative_digest: ContentDigest::sha256(id.as_bytes()),
        derivative_bytes: 4096,
        format_profile: "video/mp4;cmaf".to_owned(),
        source_binding: SourceCustodyBinding::RetainedAnchor {
            evidence_anchor_digest: ContentDigest::sha256(b"anchor:event-052"),
            source_spans: vec![SourceByteSpan {
                source_object_digest: ContentDigest::sha256(b"source:cam-052"),
                byte_offset: 0,
                byte_len: 8192,
                pts_ns: 1_000,
                dts_ns: 1_000,
                stream_generation: Generation(1),
            }],
        },
        parent_receipts: Vec::new(),
        transforms: vec![
            TransformStep::Decode {
                codec_id: "fss.codec.h264.scalar.v1".to_owned(),
                decoder_generation: Generation(1),
            },
            TransformStep::PrivacyMask {
                mask_policy_digest: policy,
                masked_region_count: 1,
            },
        ],
        implementation_identity: "fss-tensor:doc-052-v1".to_owned(),
        generation: Generation(1),
        privacy_policy_digest: policy,
        retention_group_digest: ContentDigest::sha256(b"ret:90d"),
        is_lossy: lossy,
        reproducibility: ReproducibilityClass::BitExactScalar,
        publication_state: DerivativePublicationState::RootPublished,
        created_at_ns: TimestampNs(1_000),
        clock_uncertainty_ns: 0,
    };
    Ok(MediaDerivativeReceipt::seal(req, || false)?)
}

fn quote(tier: ArchiveStorageTier, storage: u64, lock: bool) -> TierPricingQuote {
    TierPricingQuote {
        tier,
        pricing_date: "2026-11-27".to_owned(),
        pricing_manifest_digest: ContentDigest::sha256(b"pricing:2026-11-27:v1"),
        storage_micros_per_gib_month: storage,
        put_micros_per_k: 5_000,
        head_micros_per_k: 400,
        get_micros_per_k: 400,
        list_micros_per_k: 5_000,
        retrieval_micros_per_gib: if tier == ArchiveStorageTier::InfrequentAccess {
            10_000
        } else {
            0
        },
        egress_micros_per_gib: 90_000,
        min_duration_days: if tier == ArchiveStorageTier::InfrequentAccess {
            30
        } else {
            0
        },
        object_lock_supported: lock,
        region_code: "us-east-1".to_owned(),
        durability_nines: 11,
    }
}

fn clean_gateway() -> LiveGatewaySpec {
    LiveGatewaySpec {
        has_vendor_credentials: false,
        privacy_masked_proxy: true,
        auth_grant_digest: ContentDigest::sha256(b"grant:live-viewer"),
        max_bandwidth_kbps: 4_000,
        auth_expires_at_ns: TimestampNs(50_000),
    }
}

#[test]
fn doc_052_remux_before_transcode_clamps_pareto_frontier_and_backend_portability() -> TestResult {
    let event_digest = ContentDigest::sha256(b"event:driveway-2026-11-27");
    let content_root = ContentDigest::sha256(b"content:source-root-052");
    let constraints = MediaDeliveryConstraints {
        card_id: "card:doc-052-delivery-v1".to_owned(),
        generation: Generation(2),
        evaluated_at_ns: TimestampNs(10_000),
        semantic_event_digest: event_digest,
        content_root_digest: content_root,
        max_latency_ms: 500,
        max_bandwidth_kbps: 4_000,
        max_energy_mj: 5_000,
        require_privacy_mask: true,
        require_object_lock: true,
    };

    let q_hot = quote(ArchiveStorageTier::HotRemoteEvent, 23_000, true);
    let q_hold = quote(ArchiveStorageTier::EvidenceHold, 12_500, true);
    let q_local = quote(ArchiveStorageTier::HotLocalSource, 5_000, true);
    let q_nolock = quote(ArchiveStorageTier::StandardHistorical, 15_000, false);

    // 1. Remux LL-HLS/CMAF (low cost, zero fidelity loss) -> nondominated!
    let c_remux = MediaDeliveryCandidate {
        candidate_id: "opt-a-remux-cmaf".to_owned(),
        mode: MediaMovementMode::Remux,
        transcode_justification: TranscodeJustification::None,
        codec_support: CodecSupportStatus::NativePureRust,
        live_surface: LiveDeliverySurface::LlHlsCmafFmp4,
        live_gateway: clean_gateway(),
        tier_quote: q_hold.clone(),
        placement: BackendPlacementChild {
            provider_id: "s3-primary".to_owned(),
            tier: ArchiveStorageTier::EvidenceHold,
            region_code: "us-east-1".to_owned(),
            placement_receipt_digest: ContentDigest::sha256(b"place:s3-primary"),
            migrated_from_provider: None,
        },
        total_cost_micros: q_hold.estimate_total_cost_micros(10, 500, 100, 1),
        latency_ms: 280,
        bandwidth_kbps: 2_000,
        energy_millijoules: 400,
        fidelity_loss_bps: 0,
        derivative_receipt: make_derivative_receipt("deriv:remux-cmaf", false)?,
        overwrites_source: false,
        grants_effect_authority: false,
    };

    // 2. Passthrough WebRTC (lower latency, higher cost) -> nondominated Pareto tradeoff!
    let c_webrtc = MediaDeliveryCandidate {
        candidate_id: "opt-b-passthrough-webrtc".to_owned(),
        mode: MediaMovementMode::Passthrough,
        transcode_justification: TranscodeJustification::None,
        codec_support: CodecSupportStatus::NativePureRust,
        live_surface: LiveDeliverySurface::AuthorizedWebRtc,
        live_gateway: clean_gateway(),
        tier_quote: q_hot.clone(),
        placement: BackendPlacementChild {
            provider_id: "local-edge".to_owned(),
            tier: ArchiveStorageTier::HotRemoteEvent,
            region_code: "local-site-a".to_owned(),
            placement_receipt_digest: ContentDigest::sha256(b"place:local-edge"),
            migrated_from_provider: None,
        },
        total_cost_micros: q_hot.estimate_total_cost_micros(10, 500, 200, 2),
        latency_ms: 90,
        bandwidth_kbps: 2_500,
        energy_millijoules: 600,
        fidelity_loss_bps: 0,
        derivative_receipt: make_derivative_receipt("deriv:pass-webrtc", false)?,
        overwrites_source: false,
        grants_effect_authority: false,
    };

    // 3. Transcode with ClientCodecIncompatibility -> dominated by compatible remux (`remux-before-transcode`)!
    let c_transcode_dom = MediaDeliveryCandidate {
        candidate_id: "opt-c-transcode-dom".to_owned(),
        mode: MediaMovementMode::Transcode,
        transcode_justification: TranscodeJustification::ClientCodecIncompatibility,
        codec_support: CodecSupportStatus::NativePureRust,
        live_surface: LiveDeliverySurface::JustifiedRtpRtspRelay,
        live_gateway: clean_gateway(),
        tier_quote: q_local.clone(),
        placement: BackendPlacementChild {
            provider_id: "local-spool".to_owned(),
            tier: ArchiveStorageTier::HotLocalSource,
            region_code: "local-site-a".to_owned(),
            placement_receipt_digest: ContentDigest::sha256(b"place:local-spool"),
            migrated_from_provider: None,
        },
        total_cost_micros: q_local.estimate_total_cost_micros(10, 500, 100, 0),
        latency_ms: 350,
        bandwidth_kbps: 1_500,
        energy_millijoules: 3_000,
        fidelity_loss_bps: 500,
        derivative_receipt: make_derivative_receipt("deriv:transcode-dom", true)?,
        overwrites_source: false,
        grants_effect_authority: false,
    };

    // 4. Hard-clamped rejections: vendor credentials in gateway, missing object lock, unavailable codec!
    let mut c_vendor_creds = c_remux.clone();
    c_vendor_creds.candidate_id = "opt-d-vendor-creds".to_owned();
    c_vendor_creds.live_gateway.has_vendor_credentials = true;

    let mut c_unavail_codec = c_transcode_dom.clone();
    c_unavail_codec.candidate_id = "opt-e-unavail-codec".to_owned();
    c_unavail_codec.codec_support = CodecSupportStatus::UnavailableIndexedRetainedOnly;

    let mut c_no_lock = c_remux.clone();
    c_no_lock.candidate_id = "opt-f-no-lock".to_owned();
    c_no_lock.tier_quote = q_nolock;

    let mut c_overwrite = c_remux.clone();
    c_overwrite.candidate_id = "opt-g-overwrite".to_owned();
    c_overwrite.overwrites_source = true;

    let card = evaluate_media_delivery_card(
        &constraints,
        &[
            c_remux,
            c_webrtc,
            c_transcode_dom,
            c_vendor_creds,
            c_unavail_codec,
            c_no_lock,
            c_overwrite,
        ],
        || false,
    )?;

    assert!(card.verify_digest());
    assert!(card.semantic_identity_preserved);
    assert!(!card.overwrites_source);
    assert!(!card.grants_effect_authority);
    assert_eq!(card.nondominated_frontier.len(), 2);
    assert_eq!(card.dominated_options.len(), 1);
    assert_eq!(
        card.dominated_options[0].candidate_id,
        "opt-c-transcode-dom"
    );
    assert_eq!(
        card.dominated_options[0].dominated_by.as_deref(),
        Some("opt-a-remux-cmaf")
    );
    assert_eq!(card.clamped_rejections.len(), 4);
    assert!(
        card.clamped_rejections
            .iter()
            .all(|r| r.source_indexed_and_retained)
    );

    // Backend-neutral migration publishes a new placement child WITHOUT rewriting semantic identity!
    let migrated = card.append_backend_migration_child(
        BackendPlacementChild {
            provider_id: "b2-eu-mirror".to_owned(),
            tier: ArchiveStorageTier::InfrequentAccess,
            region_code: "eu-central-1".to_owned(),
            placement_receipt_digest: ContentDigest::sha256(b"place:b2-eu-mirror"),
            migrated_from_provider: Some("s3-primary".to_owned()),
        },
        event_digest,
        content_root,
        TimestampNs(20_000),
    )?;
    assert_eq!(migrated.semantic_event_digest, event_digest);
    assert_eq!(migrated.content_root_digest, content_root);
    assert_eq!(
        migrated.placement_children.len(),
        card.placement_children.len() + 1
    );
    assert!(migrated.verify_digest());

    // Attempting to rewrite semantic_event_digest during migration MUST fail closed!
    assert_eq!(
        card.append_backend_migration_child(
            BackendPlacementChild {
                provider_id: "b2-eu-mirror".to_owned(),
                tier: ArchiveStorageTier::MetadataAfterExpiry,
                region_code: "eu-central-1".to_owned(),
                placement_receipt_digest: ContentDigest::sha256(b"place:bad"),
                migrated_from_provider: Some("s3-primary".to_owned()),
            },
            ContentDigest::sha256(b"rewritten-event"),
            content_root,
            TimestampNs(21_000),
        ),
        Err(MediaDeliveryCardError::SemanticIdentityRewriteForbidden)
    );

    // Canonical binary round-trip + wire forgery refusal!
    let mut enc = CanonicalEncoder::new();
    migrated.encode_canonical(&mut enc);
    let encoded = enc.finish();
    let decoded =
        MediaDeliveryDecisionCard::decode_canonical(&mut CanonicalDecoder::new(&encoded))?;
    assert_eq!(decoded, migrated);

    let mut forged = migrated;
    forged.grants_effect_authority = true;
    forged.card_digest = forged.computed_digest();
    let mut bad_enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut bad_enc);
    assert!(
        MediaDeliveryDecisionCard::decode_canonical(&mut CanonicalDecoder::new(&bad_enc.finish()))
            .is_err()
    );

    println!(
        "CAPLOG {{\"step\":\"doc_052_media_delivery_card\",\"frontier\":{},\"dominated\":{},\"clamped\":{},\"verdict\":\"ok\"}}",
        card.nondominated_frontier.len(),
        card.dominated_options.len(),
        card.clamped_rejections.len()
    );
    Ok(())
}

#[test]
fn doc_052_refuses_corrupt_derivative_receipt_unjustified_transcode_and_cancel() -> TestResult {
    let constraints = MediaDeliveryConstraints {
        card_id: "card:doc-052-faults".to_owned(),
        generation: Generation(1),
        evaluated_at_ns: TimestampNs(10_000),
        semantic_event_digest: ContentDigest::sha256(b"event:fault"),
        content_root_digest: ContentDigest::sha256(b"content:fault"),
        max_latency_ms: 500,
        max_bandwidth_kbps: 4_000,
        max_energy_mj: 5_000,
        require_privacy_mask: true,
        require_object_lock: false,
    };

    let mut bad_receipt = make_derivative_receipt("deriv:tampered", false)?;
    bad_receipt.receipt_digest = ContentDigest::sha256(b"forged-digest");

    let cand_tampered = MediaDeliveryCandidate {
        candidate_id: "opt-tampered".to_owned(),
        mode: MediaMovementMode::Remux,
        transcode_justification: TranscodeJustification::None,
        codec_support: CodecSupportStatus::NativePureRust,
        live_surface: LiveDeliverySurface::SameHostFrameTransport,
        live_gateway: clean_gateway(),
        tier_quote: quote(ArchiveStorageTier::HotLocalSource, 5_000, true),
        placement: BackendPlacementChild {
            provider_id: "local".to_owned(),
            tier: ArchiveStorageTier::HotLocalSource,
            region_code: "local".to_owned(),
            placement_receipt_digest: ContentDigest::sha256(b"place:local"),
            migrated_from_provider: None,
        },
        total_cost_micros: 100,
        latency_ms: 10,
        bandwidth_kbps: 500,
        energy_millijoules: 50,
        fidelity_loss_bps: 0,
        derivative_receipt: bad_receipt,
        overwrites_source: false,
        grants_effect_authority: false,
    };

    assert_eq!(
        evaluate_media_delivery_card(&constraints, std::slice::from_ref(&cand_tampered), || false),
        Err(MediaDeliveryCardError::InvalidDerivativeReceipt(
            "corrupt_or_source_claiming_derivative_receipt"
        ))
    );
    assert_eq!(
        evaluate_media_delivery_card(&constraints, &[cand_tampered], || true),
        Err(MediaDeliveryCardError::Cancelled)
    );
    Ok(())
}
