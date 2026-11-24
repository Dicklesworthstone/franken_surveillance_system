#![forbid(unsafe_code)]
//! Scenario 2 — Adversarial Security, Pixel-Level H3 Privacy-Mask Verification,
//! Uncorroborated Alert Refusal, Cursor Replay Refusal, Escape-Hatch Rejection & Canary Audit.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_cli::query_cmd::hydration::{
    CAP_AGENT_HYDRATE_H2, CAP_AGENT_HYDRATE_H3, ERR_CAPABILITY_DENIED, H3_RECEIPT_DOMAIN,
    decode_base64,
};
use fss_cli::query_cmd::ops_targets::{
    CAP_AGENT_PLAN_COMMIT, CAP_AGENT_PLAN_PREPARE, CAP_AGENT_QUERY,
};
use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb_v1};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma_v1};
use fss_core::json_input::Value;
use fss_core::{ContentDigest, EventId};
use fss_daemon::{ERR_DAEMON_SECRET_IN_MANIFEST_001, SiteManifest};
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::ingest::privacy_mask::MASK_FILL_LUMA;
use fss_vault::SecretScope;

use super::TestResult;
use super::fixtures::{
    CANARY_CAM_RTSP_PASS, PRINCIPAL, TempWorkspace, VaultCanaryRig,
    import_sentinel_and_watch_event, init_empty_deployment,
};
use super::harness::{McpClient, array, bool_field, field, json_stringify, quote, text};
use super::report::{RedactedPixelProof, Scenario2Report};

fn authority_snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let meta = fs::symlink_metadata(&path)?;
        let rel = path.strip_prefix(root)?.to_path_buf();
        if meta.is_dir() {
            for entry in fs::read_dir(&path)? {
                stack.push(entry?.path());
            }
        } else if meta.is_file()
            && ["ledger", "effects", "objects", "LAYOUT"]
                .iter()
                .any(|p| rel.starts_with(p))
        {
            out.insert(rel, fs::read(&path)?);
        }
    }
    Ok(out)
}

pub fn run() -> TestResult<Scenario2Report> {
    let ws = TempWorkspace::new("s2")?;
    let deploy_root = init_empty_deployment(&ws)?;

    // Seed an RGB 128x96 sentinel MJPEG recording (magenta (255,0,255) in [16,16,48,32],
    // bright green (60,210,70) + moving white box outside) and publish its single-camera watch event.
    let (import_id, single_cam_event_id) =
        import_sentinel_and_watch_event(&ws, "sensor:sentinel-cam", 8)?;
    let import_hex = import_id.to_text();

    // Open vault with high-entropy canary secrets for final leak sweep.
    let rig = VaultCanaryRig::open(
        &ws.vault_dir,
        SecretScope::new(
            fss_vault::AdapterFamily::AlertWebhook,
            "webhook-adversarial",
            "https://hooks.fss.test/adversarial",
        )?,
    )?;

    let mut checks = BTreeMap::new();
    let mut all_tx = Vec::new();

    // Step A: Open session on wall-clock anchor, verify consumed H1 cursor replay refusal,
    // then commit PrivacyMaskPolicy covering exact sentinel rectangle [16, 16, 48, 32] via MCP!
    let mut admin_mcp = McpClient::spawn(
        "scenario_2",
        "s2-admin",
        &deploy_root,
        PRINCIPAL,
        false,
        &[
            CAP_AGENT_PLAN_PREPARE,
            CAP_AGENT_PLAN_COMMIT,
            CAP_AGENT_QUERY,
        ],
    )?;
    let open_sess = admin_mcp.call(
        "session_open",
        r#"{"mission":"Adversarial privacy and capability audit.","objective":"Verify H3 mask redaction, capability gates, cursor replay, and zero canary leaks.","view":"brief","budget_tokens":100000}"#,
    )?;
    assert!(
        !open_sess.is_error,
        "s2 session_open: {}",
        open_sess.body_text
    );
    let session_id = text(&open_sess.envelope, &["sessionId"])?.to_owned();

    // 1. Consumed H1 continuation cursor replay refusal!
    let snap = read_deployment(&deploy_root, &OrientLimits::default())?;
    let single_retained = snap
        .event(&EventId::parse(&single_cam_event_id)?)
        .ok_or("watch event missing")?;
    let rev_digest = single_retained.revision_digest.to_text();
    let anchor = fss_reference::agent_follow::snapshot_anchor_token(&snap);
    let h0 = admin_mcp.call(
        "query",
        &object(&[
            ("target", string("evidence-hydration")),
            ("level", string("H0")),
            ("session", string(&session_id)),
            ("generation", string("0")),
            ("event_id", string(&single_cam_event_id)),
            ("revision_digest", string(&rev_digest)),
            ("anchor", string(&anchor)),
        ]),
    )?;
    assert!(!h0.is_error, "s2 H0: {}", h0.body_text);
    let desc_digest =
        text(&h0.envelope, &["payload", "descriptor", "descriptorDigest"])?.to_owned();
    let cursor_json = json_stringify(field(
        &h0.envelope,
        &["payload", "receipt", "continuation"],
    )?);
    let h1_args = object(&[
        ("target", string("evidence-hydration")),
        ("level", string("H1")),
        ("session", string(&session_id)),
        ("generation", string("0")),
        ("event_id", string(&single_cam_event_id)),
        ("revision_digest", string(&rev_digest)),
        ("descriptor_digest", string(&desc_digest)),
        ("anchor", string(&anchor)),
        ("continuation", string(&cursor_json)),
    ]);
    let h1_first = admin_mcp.call("query", &h1_args)?;
    assert!(!h1_first.is_error, "s2 H1 first: {}", h1_first.body_text);
    let h1_replay = admin_mcp.call("query", &h1_args)?;
    assert!(
        h1_replay.is_error,
        "consumed H1 continuation cursor replay MUST be refused"
    );
    assert_eq!(text(&h1_replay.envelope, &["outcome"])?, "refused");
    assert_eq!(field(&h1_replay.envelope, &["payload"])?, &Value::Null);
    checks.insert("consumed_h1_cursor_replay_refused".to_owned(), true);

    let pm_plan = admin_mcp.call(
        "plan",
        r#"{"intent":"privacy-mask","sensor":"sensor:sentinel-cam","resolution":[128,96],"rectangles":[[16,16,48,32]]}"#,
    )?;
    assert!(
        !pm_plan.is_error,
        "s2 plan(privacy-mask): {}",
        pm_plan.body_text
    );
    let pm_app = text(&pm_plan.envelope, &["payload", "approvalDigest"])?.to_owned();
    let pm_commit = admin_mcp.call(
        "commit",
        &format!(
            r#"{{"intent":"privacy-mask","sensor":"sensor:sentinel-cam","resolution":[128,96],"rectangles":[[16,16,48,32]],"approval_digest":{}}}"#,
            quote(&pm_app)
        ),
    )?;
    assert!(
        !pm_commit.is_error,
        "s2 commit(privacy-mask): {}",
        pm_commit.body_text
    );
    assert!(bool_field(
        &pm_commit.envelope,
        &["payload", "authorityChanged"]
    )?);
    let policy_digest = text(&pm_commit.envelope, &["payload", "policyDigest"])?.to_owned();

    let authority_before = authority_snapshot(&deploy_root)?;

    // 1. H3 capability & launcher dual-gate denials -> MUST refuse with ZERO image bytes!
    let h3_import_args = format!(
        r#"{{"target":"evidence-hydration","level":"H3","import_id":{},"segment_indices":[4],"max_h3_frames":1}}"#,
        quote(&import_hex)
    );
    // 1a. Missing --allow-visual-hydration (even WITH CAP-AGENT-HYDRATE-H3-001)
    let mut cap_only_mcp = McpClient::spawn(
        "scenario_2",
        "s2-cap-only",
        &deploy_root,
        PRINCIPAL,
        false,
        &[CAP_AGENT_HYDRATE_H3],
    )?;
    let r_no_flag = cap_only_mcp.call("query", &h3_import_args)?;
    assert!(r_no_flag.is_error);
    assert_eq!(
        text(&r_no_flag.envelope, &["errorId"])?,
        ERR_CAPABILITY_DENIED
    );
    assert_eq!(r_no_flag.content_blocks()?.len(), 1);
    assert!(!r_no_flag.raw_wire.contains("\"type\":\"image\""));
    checks.insert("h3_denied_without_visual_flag".to_owned(), true);
    all_tx.extend(cap_only_mcp.finish()?.0);

    // 1b. Missing CAP-AGENT-HYDRATE-H3-001 (even WITH --allow-visual-hydration)
    let mut flag_only_mcp = McpClient::spawn(
        "scenario_2",
        "s2-flag-only",
        &deploy_root,
        PRINCIPAL,
        true,
        &[],
    )?;
    let r_no_cap = flag_only_mcp.call("query", &h3_import_args)?;
    assert!(r_no_cap.is_error);
    assert_eq!(
        text(&r_no_cap.envelope, &["errorId"])?,
        ERR_CAPABILITY_DENIED
    );
    assert_eq!(r_no_cap.content_blocks()?.len(), 1);
    assert!(!r_no_cap.raw_wire.contains("\"type\":\"image\""));
    checks.insert("h3_denied_without_capability".to_owned(), true);

    // 1c. H2 denied without CAP-AGENT-HYDRATE-H2-001
    let r_no_h2 = flag_only_mcp.call(
        "query",
        &format!(
            r#"{{"target":"evidence-hydration","level":"H2","import_id":{}}}"#,
            quote(&import_hex)
        ),
    )?;
    assert!(r_no_h2.is_error);
    assert_eq!(
        text(&r_no_h2.envelope, &["errorId"])?,
        ERR_CAPABILITY_DENIED
    );
    checks.insert("h2_denied_without_capability".to_owned(), true);
    all_tx.extend(flag_only_mcp.finish()?.0);

    // 2. Real H3 pixel-level privacy-mask verification (RGB + Luma + overlapping crop)!
    let mut h3_mcp = McpClient::spawn(
        "scenario_2",
        "s2-h3-authorized",
        &deploy_root,
        PRINCIPAL,
        true,
        &[CAP_AGENT_HYDRATE_H2, CAP_AGENT_HYDRATE_H3],
    )?;
    let h3_reply = h3_mcp.call("query", &h3_import_args)?;
    assert!(
        !h3_reply.is_error,
        "H3 authorized failed: {}",
        h3_reply.body_text
    );
    let blocks = h3_reply.content_blocks()?;
    assert_eq!(blocks.len(), 2);
    assert_eq!(text(&blocks[1], &["type"])?, "image");
    assert_eq!(text(&blocks[1], &["mimeType"])?, "image/jpeg");
    let frames = array(&h3_reply.envelope, &["payload", "frames"])?;
    let receipt = field(&frames[0], &["receipt"])?;
    assert_eq!(text(receipt, &["schema"])?, H3_RECEIPT_DOMAIN);
    assert_eq!(text(receipt, &["privacyMaskBinding"])?, "sensor_policy");
    assert_eq!(text(receipt, &["privacyMaskPolicyDigest"])?, policy_digest);
    assert_eq!(text(receipt, &["unmaskedAccess"])?, "refused");

    let jpeg_bytes = decode_base64(text(&blocks[1], &["data"])?)?;
    assert_eq!(
        ContentDigest::sha256(&jpeg_bytes).to_text(),
        text(receipt, &["outputJpegSha256"])?
    );

    // Pure-Rust RGB decode + Luma decode verification!
    let rgb_limits = RgbDecodeLimits::default();
    let mut rgb_budget = DecodeBudget::new(rgb_limits.rgb_work_bound());
    let rgb_img = decode_rgb_v1(
        &jpeg_bytes,
        ContentDigest::sha256(&jpeg_bytes).bytes(),
        ComponentInterpretation::YCbCr,
        rgb_limits,
        &mut rgb_budget,
    )?;
    assert_eq!(rgb_img.dimensions(), [128, 96]);
    let luma_limits = DecodeLimits::default();
    let mut luma_budget = DecodeBudget::new(luma_limits.luma_work_bound());
    let luma_img = decode_luma_v1(
        &jpeg_bytes,
        ContentDigest::sha256(&jpeg_bytes).bytes(),
        ComponentInterpretation::YCbCr,
        luma_limits,
        &mut luma_budget,
    )?;
    let w = 128_usize;
    let rgb_px = rgb_img.pixels();
    let luma_px = luma_img.pixels();

    // Every pixel inside MCU-aligned mask [16..64, 16..48] MUST be dark redacted, ZERO magenta sentinel!
    let mut masked_pixels_checked = 0_usize;
    let mut masked_max_r = 0_u8;
    let mut masked_max_g = 0_u8;
    let mut masked_max_b = 0_u8;
    let mut masked_max_luma = 0_u8;
    let mut masked_sentinel_leaks = 0_usize;
    for y in 16..48_usize {
        for x in 16..64_usize {
            let p = (y * w + x) * 3;
            let (r, g, b) = (rgb_px[p], rgb_px[p + 1], rgb_px[p + 2]);
            let l = luma_px[y * w + x];
            masked_pixels_checked += 1;
            masked_max_r = masked_max_r.max(r);
            masked_max_g = masked_max_g.max(g);
            masked_max_b = masked_max_b.max(b);
            masked_max_luma = masked_max_luma.max(l);
            // Sentinel was (255, 0, 255); masked fill is [16, 16, 16].
            if r > 32 || g > 32 || b > 32 || l > 32 {
                masked_sentinel_leaks += 1;
            }
        }
    }
    assert_eq!(
        masked_sentinel_leaks, 0,
        "privacy mask leaked pixels! max_rgb=({masked_max_r},{masked_max_g},{masked_max_b}) max_luma={masked_max_luma} (fill={MASK_FILL_LUMA})"
    );

    // Pixels outside mask (72..120, 8..40) MUST retain green background signal (60, 210, 70)!
    let mut unmasked_pixels_checked = 0_usize;
    let mut unmasked_green_sum = 0_u64;
    for y in 8..40_usize {
        for x in 72..120_usize {
            let p = (y * w + x) * 3;
            let (r, g, b) = (rgb_px[p], rgb_px[p + 1], rgb_px[p + 2]);
            unmasked_pixels_checked += 1;
            unmasked_green_sum += u64::from(g);
            assert!(
                g > 160 && g > r.saturating_add(80) && g > b.saturating_add(80),
                "scene signal corrupted outside privacy mask at ({x},{y}): rgb=({r},{g},{b})"
            );
        }
    }
    let unmasked_mean_green = (unmasked_green_sum / (unmasked_pixels_checked as u64)) as u32;

    // Also verify overlapping crop_box (32, 24, 64, 48): masked sub-region [0..32, 0..24] has 0 leaks!
    let crop_args = format!(
        r#"{{"target":"evidence-hydration","level":"H3","import_id":{},"segment_indices":[4],"crop_box":"32,24,64,48","max_h3_frames":1}}"#,
        quote(&import_hex)
    );
    let crop_reply = h3_mcp.call("query", &crop_args)?;
    assert!(
        !crop_reply.is_error,
        "H3 crop failed: {}",
        crop_reply.body_text
    );
    let crop_jpeg = decode_base64(text(&crop_reply.content_blocks()?[1], &["data"])?)?;
    let mut crop_budget = DecodeBudget::new(luma_limits.luma_work_bound());
    let crop_luma = decode_luma_v1(
        &crop_jpeg,
        ContentDigest::sha256(&crop_jpeg).bytes(),
        ComponentInterpretation::YCbCr,
        luma_limits,
        &mut crop_budget,
    )?;
    assert_eq!(crop_luma.dimensions(), [64, 48]);
    let mut crop_checked = 0_usize;
    let mut crop_max_luma = 0_u8;
    for y in 0..24_usize {
        for x in 0..32_usize {
            let l = crop_luma.pixels()[y * 64 + x];
            crop_checked += 1;
            crop_max_luma = crop_max_luma.max(l);
            assert!(l <= 32, "H3 cropped mask leaked at ({x},{y}): luma={l}");
        }
    }
    checks.insert("h3_pixel_level_privacy_mask_zero_leak".to_owned(), true);
    checks.insert("h3_overlapping_crop_mask_zero_leak".to_owned(), true);
    all_tx.extend(h3_mcp.finish()?.0);

    // 3. Uncorroborated single-camera alert refusal -> ERR-ALERT-NOT-ELIGIBLE-001!
    let plaintext_app = ContentDigest::sha256(b"s2-adversarial-alert-test").to_text();
    let uncorr_plan = admin_mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(&session_id)),
            ("event_id", string(&single_cam_event_id)),
            ("relay", string("127.0.0.1:9")),
            ("path", string("/fss/uncorr")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
        ]),
    )?;
    assert!(uncorr_plan.is_error, "single-cam alert MUST be refused");
    assert_eq!(
        text(&uncorr_plan.envelope, &["errorId"])?,
        "ERR-ALERT-NOT-ELIGIBLE-001"
    );
    checks.insert("uncorroborated_single_cam_alert_refused".to_owned(), true);

    // 5. Input / escape-hatch / path-traversal / notification adversarial rejections!
    let escape_cases = [
        ("doctor", r#"{"root":"/etc"}"#),
        ("session_orient", r#"{"root":"../../etc/passwd"}"#),
        ("session_orient", r#"{"principal":"principal:attacker"}"#),
        (
            "query",
            r#"{"target":"cameras","capability":"CAP-OBSERVE-STATUS-001"}"#,
        ),
        (
            "query",
            &format!(
                r#"{{"target":"evidence-hydration","level":"H3","import_id":{},"allow_visual_hydration":true}}"#,
                quote(&import_hex)
            ),
        ),
        (
            "plan",
            r#"{"intent":"camera-supervision","op":"start_camera","shell":"cat /etc/passwd"}"#,
        ),
        (
            "investigate",
            r#"{"session":"session:x","transition":"inspect","case":"../../etc/passwd"}"#,
        ),
        (
            "query",
            r#"{"target":"footage","sensor":"../../etc/passwd"}"#,
        ),
        ("session_resume", r#"{"handoff":"../../etc/passwd"}"#),
        (
            "commit",
            r#"{"intent":"dispatch","plan":"plan:x","approve":"bad","root":"/etc"}"#,
        ),
    ];
    for (tool, bad_args) in escape_cases {
        let (wire, _, raw) = admin_mcp.call_raw(tool, bad_args)?;
        let code = wire
            .object()
            .and_then(|o| o.get("error"))
            .and_then(Value::object)
            .and_then(|e| e.get("code"))
            .and_then(Value::integer);
        let is_tool_refusal = wire
            .object()
            .and_then(|o| o.get("result"))
            .and_then(Value::object)
            .and_then(|r| r.get("isError"))
            .and_then(Value::boolean)
            == Some(true);
        assert!(
            code == Some(-32602) || is_tool_refusal,
            "adversarial input ({tool} {bad_args}) was NOT refused fail-closed: {raw}"
        );
    }
    // Notifications must never execute mutations or return replies.
    admin_mcp.send_notification(
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"plan","arguments":{"intent":"privacy-mask","sensor":"sensor:sentinel-cam","resolution":[128,96],"rectangles":[[0,0,8,8]]}}}"#,
    )?;
    // Verify client stays responsive, zero corruption occurred, and authority bytes are unchanged!
    let doc_after = admin_mcp.call("doctor", "{}")?;
    assert_eq!(text(&doc_after.envelope, &["schema"])?, "fss.doctor.v1");
    assert!(!bool_field(&doc_after.envelope, &["possibly_stale"])?);
    assert!(
        matches!(
            text(&doc_after.envelope, &["verdict"])?,
            "healthy" | "attention_required"
        ),
        "unexpected post-gauntlet doctor verdict: {}",
        doc_after.body_text
    );
    assert_eq!(authority_snapshot(&deploy_root)?, authority_before);
    checks.insert("escape_hatch_and_path_traversal_refused".to_owned(), true);
    checks.insert(
        "authority_bytes_unchanged_under_adversarial_gauntlet".to_owned(),
        true,
    );

    // Plaintext secret in SiteManifest MUST be refused fail-closed without echoing canary!
    let secret_str = std::str::from_utf8(CANARY_CAM_RTSP_PASS)?;
    let bad_manifest = format!(
        r#"{{"schema":"fss.site_manifest.v1","site_id":"site-adv","cameras":[{{"sensor_id":"sensor:s1","adapter":"rtsp","endpoint":"rtsp://admin:{secret_str}@10.0.0.1/stream1"}}]}}"#
    );
    let manifest_err = SiteManifest::parse_json(&bad_manifest)
        .err()
        .ok_or("plaintext secret manifest must fail")?;
    assert_eq!(manifest_err.error_id(), ERR_DAEMON_SECRET_IN_MANIFEST_001);
    assert!(!manifest_err.to_string().contains(secret_str));
    checks.insert(
        "plaintext_secret_manifest_refused_without_echo".to_owned(),
        true,
    );

    all_tx.extend(admin_mcp.finish()?.0);

    // 6. Canary Leak Audit across EVERY response, error envelope, and durable journal!
    let mut surfaces = 0_usize;
    let mut bytes_scanned = 0_usize;
    let mut scan = |label: &str, data: &[u8]| -> TestResult {
        surfaces += 1;
        bytes_scanned += data.len();
        rig.scanner.assert_clean(label, data)?;
        Ok(())
    };
    scan("s2_manifest_error", manifest_err.to_string().as_bytes())?;
    for (idx, entry) in all_tx.iter().enumerate() {
        scan(&format!("s2_req_{idx}"), entry.request_json.as_bytes())?;
        scan(&format!("s2_resp_{idx}"), entry.response_json.as_bytes())?;
    }
    for path in [
        deploy_root.join("effects/journal.fssj"),
        deploy_root.join("ledger/journal.fssj"),
        deploy_root.join("agent/sessions/journal.fssj"),
    ] {
        if path.is_file() {
            let bytes = fs::read(&path)?;
            scan(&path.display().to_string(), &bytes)?;
        }
    }
    checks.insert("canary_leak_scanner_zero_leaks".to_owned(), true);

    Ok(Scenario2Report {
        checks,
        pixel_proof: RedactedPixelProof {
            dimensions: [128, 96],
            mask_rect: [16, 16, 48, 32],
            masked_pixels_checked,
            masked_max_r,
            masked_max_g,
            masked_max_b,
            masked_max_luma,
            masked_sentinel_leaks,
            unmasked_pixels_checked,
            unmasked_mean_green,
            crop_masked_pixels_checked: crop_checked,
            crop_max_luma,
        },
        canary_surfaces_scanned: surfaces,
        canary_bytes_scanned: bytes_scanned,
        canary_leaks: 0,
        transcript: all_tx,
    })
}
