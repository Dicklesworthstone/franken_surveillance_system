#![forbid(unsafe_code)]

use super::*;

fn manifest() -> Result<SiteManifest, Box<dyn std::error::Error>> {
    Ok(SiteManifest::parse(include_str!(
        "../../../../fixtures/site/manifest.v1.json"
    ))?)
}

fn options(manifest: &SiteManifest) -> SiteProbeOptions {
    SiteProbeOptions {
        source: manifest.sources[0].source_id.clone(),
        codec: ProbeCodec::Avc,
        media_index: 0,
        payload_type: None,
        rtp_channel: 0,
        observe_frames: 6,
        timeout_ms: 10_000,
        principal: "principal:probe-test".into(),
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
