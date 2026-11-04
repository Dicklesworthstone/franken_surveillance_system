#![forbid(unsafe_code)]

use super::*;

fn manifest() -> Result<SiteManifest, Box<dyn std::error::Error>> {
    Ok(SiteManifest::parse(include_str!(
        "../../../../fixtures/site/manifest.v1.json"
    ))?)
}

fn options(manifest: &SiteManifest) -> SiteProbeOptions {
    SiteProbeOptions {
        unifi_bindings: None,
        receipt_file: None,
        source: manifest.sources[0].source_id.clone(),
        codec: ProbeCodec::Avc,
        media_index: 0,
        payload_type: None,
        rtp_channel: 0,
        observe_frames: 6,
        timeout_ms: 10_000,
        principal: "principal:probe-test".into(),
        output: ProbeOutput::Receipts,
        approve: None,
    }
}

#[test]
fn approval_binds_every_selection_and_the_complete_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let options = options(&manifest);
    let baseline = ProbePlan::new(&manifest, &options)?.approval;
    let mut variants = Vec::new();
    let mut changed = options.clone();
    changed.codec = ProbeCodec::Hevc;
    variants.push(changed);
    let mut changed = options.clone();
    changed.media_index = 1;
    variants.push(changed);
    let mut changed = options.clone();
    changed.payload_type = Some(96);
    variants.push(changed);
    let mut changed = options.clone();
    changed.rtp_channel = 2;
    variants.push(changed);
    let mut changed = options.clone();
    changed.observe_frames += 1;
    variants.push(changed);
    let mut changed = options.clone();
    changed.timeout_ms += 1;
    variants.push(changed);
    let mut changed = options.clone();
    changed.principal = "principal:other".into();
    variants.push(changed);
    for changed in variants {
        assert_ne!(ProbePlan::new(&manifest, &changed)?.approval, baseline);
    }
    let mut changed = manifest.clone();
    changed.generation += 1;
    assert_ne!(ProbePlan::new(&changed, &options)?.approval, baseline);
    changed = manifest.clone();
    changed.sources[1].retention_class = "retention:changed-unselected-source".into();
    assert_ne!(ProbePlan::new(&changed, &options)?.approval, baseline);
    let mut approved = options.clone();
    approved.approve = Some(baseline);
    assert_eq!(ProbePlan::new(&manifest, &approved)?.approval, baseline);
    Ok(())
}

#[test]
fn stale_approval_refuses_at_the_pure_native_admission_gate()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let mut options = options(&manifest);
    let approval = ProbePlan::new(&manifest, &options)?.approval;
    assert_eq!(
        ProbePlan::new(&manifest, &options)?.check_approval(),
        Ok(false)
    );
    options.approve = Some(ContentDigest::sha256(b"stale-approval"));
    let refusal = ProbePlan::new(&manifest, &options)?.check_approval();
    assert_eq!(refusal, Err(APPROVAL_ERROR));
    assert!(!format!("{refusal:?}").contains(&manifest.sources[0].authority));
    options.approve = Some(approval);
    assert_eq!(
        ProbePlan::new(&manifest, &options)?.check_approval(),
        Ok(true)
    );
    Ok(())
}

#[test]
fn pure_preview_keeps_exact_approval_and_redacts_the_unread_realm()
-> Result<(), Box<dyn std::error::Error>> {
    let mut manifest = manifest()?;
    let mut options = options(&manifest);
    let realm = "PRIVATE_REALM_CANARY_NEVER_PRINTED";
    manifest.sources[0].authentication = Some(fss_reference::site::SiteAuthentication {
        credential_file: "/fss-site-probe-never-created/private-credential".into(),
        realm: realm.into(),
        legacy_md5: false,
        legacy_no_qop: false,
    });
    let plan = ProbePlan::new(&manifest, &options)?;
    let preview = plan.preview()?;
    assert!(!preview.contains(realm));
    assert!(preview.contains(&ContentDigest::sha256(realm.as_bytes()).to_text()));
    let value = fss_core::json_input::parse(&preview)?;
    let fields = value.object().ok_or("preview object")?;
    for field in [
        "device_contacted",
        "credentials_read",
        "source_retained",
        "capture_authorized",
        "rights_verdict_verified",
    ] {
        assert_eq!(
            fields.get(field),
            Some(&fss_core::json_input::Value::Bool(false))
        );
    }
    options.approve = Some(plan.approval);
    let approved = ProbePlan::new(&manifest, &options)?;
    assert_eq!(approved.check_approval(), Ok(true));
    assert_eq!(approved.preview()?, preview);
    Ok(())
}

#[test]
fn protocol_scope_and_budget_refusals_do_not_disclose_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let mut manifest = manifest()?;
    let options = options(&manifest);
    manifest.sources[0].owner_authorized = false;
    let refusal = ProbePlan::new(&manifest, &options)
        .err()
        .ok_or("denied owner accepted")?;
    assert_eq!(refusal, PLAN_ERROR);
    assert!(!refusal.contains(&manifest.sources[0].authority));
    for frames in [0, 2, 65, u32::MAX] {
        let mut bad = options.clone();
        bad.observe_frames = frames;
        assert_eq!(bad.validate(), Err(PLAN_ERROR));
    }
    for timeout in [0, 99, 60_001, u64::MAX] {
        let mut bad = options.clone();
        bad.timeout_ms = timeout;
        assert_eq!(bad.validate(), Err(PLAN_ERROR));
    }
    let mut bad = options.clone();
    bad.rtp_channel = 255;
    assert_eq!(bad.validate(), Err(PLAN_ERROR));
    let mut bad = options;
    bad.payload_type = Some(26);
    assert_eq!(bad.validate(), Err(PLAN_ERROR));
    Ok(())
}

#[test]
fn jpeg_static_and_dynamic_selections_are_explicit_and_approval_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let mut options = options(&manifest);
    let avc_approval = ProbePlan::new(&manifest, &options)?.approval;
    options.codec = ProbeCodec::Jpeg;
    let automatic = ProbePlan::new(&manifest, &options)?;
    let automatic_approval = automatic.approval;
    assert_ne!(automatic_approval, avc_approval);
    assert!(automatic.preview()?.contains(JPEG_POLICY));
    options.payload_type = Some(26);
    let static_plan = ProbePlan::new(&manifest, &options)?;
    let static_approval = static_plan.approval;
    assert_ne!(static_approval, automatic_approval);
    options.payload_type = Some(97);
    assert_ne!(
        ProbePlan::new(&manifest, &options)?.approval,
        static_approval
    );
    options.approve = Some(static_approval);
    assert_eq!(
        ProbePlan::new(&manifest, &options)?.check_approval(),
        Err(APPROVAL_ERROR)
    );
    options.payload_type = Some(26);
    assert_eq!(
        ProbePlan::new(&manifest, &options)?.check_approval(),
        Ok(true)
    );
    Ok(())
}

#[test]
fn static_jpeg_payload_never_enters_an_avc_or_hevc_plan() -> Result<(), Box<dyn std::error::Error>>
{
    let manifest = manifest()?;
    let mut options = options(&manifest);
    for codec in [ProbeCodec::Avc, ProbeCodec::Hevc] {
        options.codec = codec;
        options.payload_type = Some(26);
        assert_eq!(options.validate(), Err(PLAN_ERROR));
    }
    options.codec = ProbeCodec::Jpeg;
    for payload in [0, 25, 27, 95, 128, 255] {
        options.payload_type = Some(payload);
        assert_eq!(options.validate(), Err(PLAN_ERROR));
    }
    for payload in [26, 96, 127] {
        options.payload_type = Some(payload);
        assert!(ProbePlan::new(&manifest, &options).is_ok());
    }
    Ok(())
}

#[test]
fn receipt_output_round_trips_the_existing_site_input_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let receipts = fss_reference::site::parse_probe_receipts(include_bytes!(
        "../../../../fixtures/site/probes.v1.json"
    ))?;
    for receipt in receipts {
        let text = array(&[receipt_json(&receipt)]);
        let decoded = fss_reference::site::parse_probe_receipts(text.as_bytes())?;
        assert_eq!(decoded, vec![receipt]);
    }
    Ok(())
}

#[test]
fn distinct_sources_have_distinct_stable_ingress_even_in_one_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let first_options = options(&manifest);
    let first = ProbePlan::new(&manifest, &first_options)?;
    let first_key = first.binding.key();
    let mut second_options = first_options.clone();
    second_options.source = manifest.sources[1].source_id.clone();
    let second = ProbePlan::new(&manifest, &second_options)?;
    assert_eq!(first_key.generation, second.binding.key().generation);
    assert_ne!(first_key.ingress, second.binding.key().ingress);
    assert_ne!(first_key, second.binding.key());
    assert_ne!(first.approval, second.approval);
    assert_ne!(first_key.ingress, 0);

    // Unrelated site-policy changes invalidate approval without renaming the selected stream.
    let mut changed = manifest.clone();
    changed.sources[1].retention_class = "retention:unrelated-policy-change".into();
    let replanned = ProbePlan::new(&changed, &first_options)?;
    assert_eq!(replanned.binding.key().ingress, first_key.ingress);
    assert_ne!(replanned.approval, first.approval);

    // Generation is a separate native coordinate, not a replacement logical stream identity.
    changed.sources[0].generation += 1;
    let next_generation = ProbePlan::new(&changed, &first_options)?;
    assert_eq!(next_generation.binding.key().ingress, first_key.ingress);
    assert_eq!(
        next_generation.binding.key().generation,
        first_key.generation + 1
    );
    assert_ne!(next_generation.approval, first.approval);
    Ok(())
}

#[test]
fn changing_output_projection_requires_its_own_exact_approval()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let mut options = options(&manifest);
    let receipts = ProbePlan::new(&manifest, &options)?;
    let receipt_approval = receipts.approval;
    let allowance = receipts.allowance;
    let ingress = receipts.binding.key().ingress;
    options.output = ProbeOutput::Session;
    options.approve = Some(receipt_approval);
    let session = ProbePlan::new(&manifest, &options)?;
    assert_ne!(session.approval, receipt_approval);
    assert_eq!(session.check_approval(), Err(APPROVAL_ERROR));
    assert_eq!(session.allowance, allowance);
    assert_eq!(session.binding.key().ingress, ingress);
    let session_approval = session.approval;
    let preview = session.preview()?;
    let value = fss_core::json_input::parse(&preview)?;
    let fields = value.object().ok_or("preview object")?;
    assert_eq!(
        fields.get("output"),
        Some(&fss_core::json_input::Value::Text("session".into()))
    );
    options.approve = Some(session_approval);
    assert_eq!(
        ProbePlan::new(&manifest, &options)?.check_approval(),
        Ok(true)
    );
    assert_eq!(ProbeOutput::Receipts.as_str(), "receipts");
    Ok(())
}

#[test]
fn runtime_reservation_covers_native_buffers_and_preserves_tight_transport_caps()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let mut options = options(&manifest);
    for codec in [ProbeCodec::Avc, ProbeCodec::Hevc] {
        options.codec = codec;
        let plan = ProbePlan::new(&manifest, &options)?;
        assert_eq!(plan.allowance.bytes, 64 * 1024 * 1024);
        assert_eq!(
            plan.allowance.network_bytes,
            plan.transport.max_received_bytes + plan.transport.max_sent_bytes
        );
        assert_eq!(plan.allowance.storage_operations, MAX_STEPS * 64);
        assert_eq!(plan.allowance.latency_ms, options.timeout_ms);
        assert_eq!(plan.allowance.model_calls, 0);
        assert_eq!(plan.allowance.tokens, 0);
        assert_eq!(
            plan.transport.max_received_bytes,
            8 * 1024 * 1024 + 256 * 1024
        );
        assert_eq!(plan.transport.max_sent_bytes, 64 * 1024);
        assert_eq!(plan.transport.max_request_bytes, 16 * 1024);
        assert_eq!(plan.transport.chunk_bytes, MAX_WIRE_CHUNK);
        assert_eq!(plan.transport.max_io_calls, MAX_STEPS);
        let assembly_bytes = match codec {
            ProbeCodec::Avc => AvcAssemblyLimits::default().max_bytes,
            ProbeCodec::Hevc => HevcAssemblyLimits::default().max_bytes,
            ProbeCodec::Jpeg => return Err("unexpected codec".into()),
        };
        let nal_bytes = match codec {
            ProbeCodec::Avc => H264Limits::default().max_nal_bytes,
            ProbeCodec::Hevc => H265Limits::default().max_nal_bytes,
            ProbeCodec::Jpeg => return Err("unexpected codec".into()),
        };
        assert!(
            plan.allowance.bytes
                >= (assembly_bytes
                    + nal_bytes
                    + MAX_WIRE_BUFFER
                    + crate::site_cmd::MAX_SITE_OUTPUT_BYTES) as u64
        );
        assert_eq!(
            plan.binding.ssrc_policy(),
            fss_reference::rtsp::tcp::SsrcPolicy::LearnOnce
        );
    }
    options.timeout_ms = 100;
    let short = ProbePlan::new(&manifest, &options)?;
    assert_eq!(short.protocol.response_timeout_ns, 100_000_000);
    assert_eq!(short.transport.connect_timeout_ns, 100_000_000);
    assert_eq!(short.allowance.latency_ms, 100);
    assert_eq!(WAIT_QUANTUM_NS, 1_000_000);
    assert_eq!(MAX_CREDENTIAL_BYTES, 1282);
    assert_eq!(MAX_SECRET_IO_CALLS, 16);
    Ok(())
}

#[test]
fn preview_describes_minimum_native_prefix_and_independently_bound_observer_limits()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let mut options = options(&manifest);
    let avc = ProbePlan::new(&manifest, &options)?;
    let preview = avc.preview()?;
    let value = fss_core::json_input::parse(&preview)?;
    let fields = value.object().ok_or("preview object")?;
    for (name, expected) in [
        ("output", "receipts"),
        ("observe_frames_meaning", "minimum_native_picture_groups"),
        (
            "unverified_tail_policy",
            "count_and_omit_after_confirmed_prefix",
        ),
        (
            "reservation_basis",
            "declared_logical_working_bound_not_measured_rss",
        ),
        ("ssrc_policy", "learn_once"),
    ] {
        assert_eq!(
            fields.get(name),
            Some(&fss_core::json_input::Value::Text(expected.into()))
        );
    }
    let avc_limits = avc.observer_limits_digest;
    assert_eq!(avc_limits, observer_limits_digest(ProbeCodec::Avc)?);
    let avc_approval = avc.approval;
    options.codec = ProbeCodec::Hevc;
    let hevc = ProbePlan::new(&manifest, &options)?;
    assert_ne!(hevc.observer_limits_digest, avc_limits);
    assert_ne!(hevc.approval, avc_approval);
    let jpeg_limits = observer_limits_digest(ProbeCodec::Jpeg)?;
    assert_ne!(jpeg_limits, avc_limits);
    assert_ne!(jpeg_limits, hevc.observer_limits_digest);
    Ok(())
}

#[test]
fn nonretaining_probe_does_not_promote_payment_or_rights_declarations()
-> Result<(), Box<dyn std::error::Error>> {
    let mut manifest = manifest()?;
    let options = options(&manifest);
    manifest.sources[0].retain_originals = false;
    manifest.sources[0]
        .zones
        .push(fss_reference::site::SiteZone {
            zone_id: "zone:payment".into(),
            kind: "payment".into(),
            vertices: vec![[0, 0], [100_000, 0], [100_000, 100_000], [0, 100_000]],
        });
    manifest.sources[0]
        .payment_masks
        .push(fss_reference::site::PaymentMask {
            x: 0,
            y: 0,
            width: 100_000,
            height: 100_000,
        });
    let plan = ProbePlan::new(&manifest, &options)?;
    let previous = plan.approval;
    let preview = plan.preview()?;
    let value = fss_core::json_input::parse(&preview)?;
    let fields = value.object().ok_or("preview object")?;
    for field in [
        "source_retained",
        "capture_authorized",
        "rights_verdict_verified",
    ] {
        assert_eq!(
            fields.get(field),
            Some(&fss_core::json_input::Value::Bool(false))
        );
    }
    manifest.sources[0].rights_verdict_ref = "fldt:rights:still-unverified".into();
    assert_ne!(ProbePlan::new(&manifest, &options)?.approval, previous);
    manifest.sources[0].owner_authorized = false;
    assert!(ProbePlan::new(&manifest, &options).is_err());
    Ok(())
}
