#![forbid(unsafe_code)]
//! E2E contract & adversarial privacy tests for H2 (structured analytic) and H3 (redacted visual)
//! hydration over both `fss` CLI and `fss-mcp` JSON-RPC 2.0 stdio transport.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_cli::escape_json_str;
use fss_cli::query_cmd::hydration::{
    CAP_AGENT_HYDRATE_H2, CAP_AGENT_HYDRATE_H3, ERR_CAPABILITY_DENIED, ERR_HYDRATION_BOUNDS,
    H2_PAYLOAD_SCHEMA, H2_RECEIPT_DOMAIN, H3_PAYLOAD_SCHEMA, H3_RECEIPT_DOMAIN, decode_base64,
};
use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma_v1};
use fss_core::json_input::{Value, parse_mcp_reply};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
    StreamId, TimestampNs,
};
use fss_reference::agent_follow::snapshot_anchor_token;
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::ingest::file_adapter::{FileIngestAdapter, FileIngestRequest};
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type Test<T = ()> = Result<T, Box<dyn Error>>;
static SEQ: AtomicU64 = AtomicU64::new(0);

const PRINCIPAL: &str = "principal:hydration-e2e-owner";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"hydration-e2e","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn quote(s: &str) -> String {
    format!("\"{}\"", escape_json_str(s))
}

fn field<'a>(v: &'a Value, name: &str) -> Test<&'a Value> {
    v.object()
        .and_then(|o| o.get(name))
        .ok_or_else(|| format!("missing field {name}").into())
}

fn text<'a>(v: &'a Value, name: &str) -> Test<&'a str> {
    field(v, name)?
        .text()
        .ok_or_else(|| format!("field {name} is not text").into())
}

fn array<'a>(v: &'a Value, name: &str) -> Test<&'a [Value]> {
    field(v, name)?
        .array()
        .ok_or_else(|| format!("field {name} is not an array").into())
}

fn authority_snapshot(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
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

fn encode_scene_frame(frame_idx: u32) -> Test<Vec<u8>> {
    let (w, h) = (128_u32, 96_u32);
    let mut rgb = vec![0_u8; (w as usize) * (h as usize) * 3];
    for y in 0..h {
        for x in 0..w {
            let idx = ((y as usize) * (w as usize) + (x as usize)) * 3;
            if x < 64 && y < 48 {
                // Bright 255 sensitive zone covered by PrivacyMaskPolicy (0,0,64,48).
                rgb[idx..idx + 3].copy_from_slice(&[255, 255, 255]);
            } else if frame_idx >= 3 {
                // Moving foreground box inside unmasked WatchZone (70, 50, 52, 42).
                let bx = 76 + (frame_idx - 3);
                if x >= bx && x < bx + 24 && (56..80).contains(&y) {
                    rgb[idx..idx + 3].copy_from_slice(&[245, 240, 235]);
                } else {
                    rgb[idx..idx + 3].copy_from_slice(&[100, 120, 85]);
                }
            } else {
                // Clean background frames 0..3 for foreground background model.
                rgb[idx..idx + 3].copy_from_slice(&[100, 120, 85]);
            }
        }
    }
    let limits = EncodeLimits::default();
    let mut budget = EncodeBudget::new(limits.work_bound(PixelFormat::Rgb));
    let digest = ContentDigest::sha256(&rgb).bytes();
    Ok(encode_jpeg(
        w,
        h,
        &rgb,
        digest,
        EncodeConfig {
            quality: 90,
            format: PixelFormat::Rgb,
        },
        &limits,
        &mut budget,
    )?
    .into_bytes())
}

struct E2eFixture {
    dir: PathBuf,
    root: PathBuf,
    import_id: ContentDigest,
    event_id: String,
    revision_digest: ContentDigest,
    policy_digest: ContentDigest,
    anchor: String,
    session_id: String,
    descriptor_digest: String,
}

impl Drop for E2eFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl E2eFixture {
    fn build(tag: &str) -> Test<Self> {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "fss-hydration-e2e-{tag}-{}-{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let root = dir.join("deployment");

        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:hydration-e2e".into(),
            operation_id: OperationId::parse("operation:hydration-e2e")?,
            principal: PRINCIPAL.into(),
            capabilities: vec![ADP_REPLAY_ROW_ID.into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(100_000)
                .build()?,
            privacy_scope: "private:property".into(),
            retention_scope: "retention:current-deletion-restrictions".into(),
            anchor_universe: ContentDigest::sha256(b"hydration-e2e"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            root.clone(),
        )?);
        let mut deployment = ReferenceDeployment::open(&root, "site:hydration-e2e", &cx)?;

        // 1. Write and ingest a real 8-frame MJPEG recording.
        let mut mjpeg = Vec::new();
        for i in 0..8_u32 {
            mjpeg.extend_from_slice(&encode_scene_frame(i)?);
        }
        let mjpeg_path = dir.join("watch_scene.mjpeg");
        fs::write(&mjpeg_path, &mjpeg)?;
        let sensor = SensorId::parse("sensor:porch-cam")?;
        let stream = StreamId::parse("stream:main")?;
        let ingest_req = FileIngestRequest::new(&mjpeg_path, sensor.clone(), stream)
            .with_receive_time(TimestampNs(1_700_000_000_000_000_000));
        let receipt = FileIngestAdapter::ingest(ingest_req, &cx, &mut deployment)?;

        // 2. Declare active PrivacyMaskPolicy on (0, 0, 64, 48).
        let policy = PrivacyMaskPolicy::new(sensor, [128, 96], &[[0, 0, 64, 48]])?;
        let preview = preview_mask(&deployment, &policy)?;
        let declared = declare_mask(&mut deployment, &policy, preview.approval, &cx)?;

        // 3. Run native recorded watch and publish a real watch event with track provenance.
        let plan = WatchPlan {
            import_identity: receipt.import_identity,
            interpretation: ComponentInterpretation::YCbCr,
            first_segment: 0,
            segment_count: 8,
            zones: vec![WatchZone {
                zone_id: "entry_zone".to_owned(),
                x: 70,
                y: 50,
                width: 52,
                height: 42,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig {
                confirmation_hits: 2,
                maximum_missed_frames: 2,
                minimum_iou_ppm: 100_000,
            },
        };
        let mut report = WatchReport::analyze(&deployment, &plan, &WatchLimits::default(), &cx)?;
        assert!(
            !report.candidates().is_empty(),
            "watch fixture must produce at least one real track candidate"
        );
        let approvals: BTreeSet<ContentDigest> = report
            .candidates()
            .iter()
            .map(|c| c.proposal_digest())
            .collect();
        let published = report.publish(&mut deployment, &approvals, &cx)?;
        assert!(published >= 1);

        let snapshot = read_deployment(&root, &OrientLimits::default())?;
        let retained_event = snapshot
            .events
            .first()
            .ok_or("expected published watch event")?;
        let event_id = retained_event.event.event_id.as_str().to_owned();
        let revision_digest = retained_event.revision_digest;
        let anchor = snapshot_anchor_token(&snapshot);

        // 4. Open a durable session and run H0 to discover the exact descriptor_digest.
        let open_out = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args([
                "session",
                "open",
                "--json",
                "--root",
                root.to_str().ok_or("utf8 root")?,
                "--principal",
                PRINCIPAL,
                "--mission-text",
                "Investigate entry_zone motion with H2/H3 hydration",
                "--objective",
                "Verify track trajectory and privacy-masked keyframe",
                "--budget-tokens",
                "100000",
            ])
            .output()?;
        assert_eq!(open_out.status.code(), Some(0));
        let open_json = parse_mcp_reply(&String::from_utf8(open_out.stdout)?)?;
        let session_id = text(&open_json, "sessionId")?.to_owned();

        // Compute the exact H0 descriptor digest at this anchor (using latest_evidence_time + 1h
        // because privacy mask policies span [0, i64::MAX] in authority history).
        let orientation = fss_reference::agent_orient::orient_deployment(
            &snapshot,
            &fss_reference::agent_orient::OrientRequest {
                view: fss_core::AgentView::Brief,
                principal: fss_core::PrincipalId::parse(PRINCIPAL)?,
                budget_tokens: None,
            },
            &OrientLimits::default(),
        )?;
        let catalog = fss_reference::agent_event_hydration::build_event_hydration_catalog(
            &snapshot,
            &orientation,
            &retained_event.event.event_id,
            revision_digest,
            TimestampNs(snapshot.latest_evidence_time.0 + 3_600_000_000_000),
        )?;
        let descriptor_digest = catalog.descriptor.descriptor_digest.to_text();

        Ok(Self {
            dir,
            root,
            import_id: receipt.import_identity,
            event_id,
            revision_digest,
            policy_digest: declared.policy_digest,
            anchor,
            session_id,
            descriptor_digest,
        })
    }

    fn call_mcp(&self, launcher_flags: &[&str], tool_args_json: &str) -> Test<Value> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fss-mcp"));
        cmd.arg("--root")
            .arg(&self.root)
            .arg("--principal")
            .arg(PRINCIPAL);
        for flag in launcher_flags {
            cmd.arg(flag);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let call = format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"query","arguments":{tool_args_json}}}}}"#
        );
        {
            let mut stdin = child.stdin.take().ok_or("mcp stdin")?;
            writeln!(stdin, "{INIT}")?;
            writeln!(stdin, "{READY}")?;
            writeln!(stdin, "{call}")?;
        }
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "fss-mcp exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)?;
        let last_line = stdout.lines().last().ok_or("missing mcp reply line")?;
        Ok(parse_mcp_reply(last_line)?)
    }
}

fn assert_masked_luma(jpeg_bytes: &[u8], expected_dims: [u32; 2], mask_w: usize, mask_h: usize) {
    let digest = ContentDigest::sha256(jpeg_bytes).bytes();
    let limits = DecodeLimits::default();
    let mut budget = DecodeBudget::new(limits.luma_work_bound());
    let decoded = decode_luma_v1(
        jpeg_bytes,
        digest,
        ComponentInterpretation::YCbCr,
        limits,
        &mut budget,
    );
    assert!(
        decoded.is_ok(),
        "pure-Rust JPEG luma decode failed: {:?}",
        decoded.as_ref().err()
    );
    let Ok(decoded) = decoded else {
        return;
    };
    assert_eq!(decoded.dimensions(), expected_dims);
    let w = expected_dims[0] as usize;
    let pixels = decoded.pixels();
    for y in 0..mask_h {
        for x in 0..mask_w {
            let luma = pixels[y * w + x];
            assert!(
                luma <= 28,
                "unmasked pixel leak at ({x},{y}): luma={luma}, expected near MASK_FILL_LUMA={MASK_FILL_LUMA}"
            );
        }
    }
}

#[test]
fn h2_and_h3_end_to_end_cli_mcp_and_adversarial_privacy_audit() -> Test {
    let f = E2eFixture::build("contract")?;
    let before_authority = authority_snapshot(&f.root)?;

    // 1. H2 structured analytic hydration over CLI on the real published watch event.
    let h2_cli = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args([
            "query",
            "--json",
            "--target",
            "evidence-hydration",
            "--root",
            f.root.to_str().ok_or("utf8")?,
            "--principal",
            PRINCIPAL,
            "--session",
            &f.session_id,
            "--event-id",
            &f.event_id,
            "--revision-digest",
            &f.revision_digest.to_text(),
            "--descriptor-digest",
            &f.descriptor_digest,
            "--anchor",
            &f.anchor,
            "--level",
            "H2",
            "--capability",
            CAP_AGENT_HYDRATE_H2,
        ])
        .output()?;
    assert_eq!(
        h2_cli.status.code(),
        Some(0),
        "H2 CLI failed: {}",
        String::from_utf8_lossy(&h2_cli.stdout)
    );
    let h2_env = parse_mcp_reply(&String::from_utf8(h2_cli.stdout)?)?;
    assert_eq!(text(&h2_env, "outcome")?, "ok");
    assert_eq!(text(&h2_env, "payloadSchema")?, H2_PAYLOAD_SCHEMA);
    let h2_payload = field(&h2_env, "payload")?;
    assert!(!array(h2_payload, "trackTrajectories")?.is_empty());
    assert!(!array(h2_payload, "failureDomains")?.is_empty());
    assert_eq!(
        field(h2_payload, "calibrated")?.boolean(),
        Some(false),
        "uncalibrated event must declare calibrated=false"
    );
    assert!(field(h2_payload, "graphNeighborhood")?.object().is_some());
    assert_eq!(
        text(field(h2_payload, "receipt")?, "schema")?,
        H2_RECEIPT_DOMAIN
    );
    assert_eq!(
        field(h2_payload, "rawMediaDisclosed")?.boolean(),
        Some(false)
    );

    // 2. H3 visual keyframe hydration via fss-mcp JSON-RPC 2.0 WITH dual gate:
    //    launcher --allow-visual-hydration AND --grant-capability CAP-AGENT-HYDRATE-H3-001.
    let h3_args = format!(
        r#"{{"target":"evidence-hydration","level":"H3","session":{},"event_id":{},"revision_digest":{},"descriptor_digest":{},"anchor":{},"max_h3_frames":2,"max_dimension":640}}"#,
        quote(&f.session_id),
        quote(&f.event_id),
        quote(&f.revision_digest.to_text()),
        quote(&f.descriptor_digest),
        quote(&f.anchor),
    );
    let mcp_h3 = f.call_mcp(
        &[
            "--allow-visual-hydration",
            "--grant-capability",
            CAP_AGENT_HYDRATE_H3,
        ],
        &h3_args,
    )?;
    let result = field(&mcp_h3, "result")?;
    assert_eq!(field(result, "isError")?.boolean(), Some(false));

    // Verify BOTH structuredContent AND content[] with text + image blocks.
    let structured = field(result, "structuredContent")?;
    assert_eq!(text(structured, "payloadSchema")?, H3_PAYLOAD_SCHEMA);
    let h3_payload = field(structured, "payload")?;
    let frames = array(h3_payload, "frames")?;
    assert!(!frames.is_empty() && frames.len() <= 2);

    let content = array(result, "content")?;
    assert_eq!(content.len(), 1 + frames.len());
    assert_eq!(text(&content[0], "type")?, "text");

    for (idx, frame_val) in frames.iter().enumerate() {
        let img_block = &content[idx + 1];
        assert_eq!(text(img_block, "type")?, "image");
        assert_eq!(text(img_block, "mimeType")?, "image/jpeg");
        let b64 = text(img_block, "data")?;
        assert_eq!(b64, text(frame_val, "jpegBase64")?);

        let receipt = field(frame_val, "receipt")?;
        assert_eq!(text(receipt, "schema")?, H3_RECEIPT_DOMAIN);
        assert_eq!(text(receipt, "privacyMaskBinding")?, "sensor_policy");
        assert_eq!(
            text(receipt, "privacyMaskPolicyDigest")?,
            f.policy_digest.to_text()
        );
        assert_eq!(
            text(receipt, "appliedRedactionTransform")?,
            "transform:bounding_box_redact"
        );
        assert_eq!(text(receipt, "unmaskedAccess")?, "refused");

        let jpeg_bytes = decode_base64(b64)?;
        assert_eq!(
            ContentDigest::sha256(&jpeg_bytes).to_text(),
            text(receipt, "outputJpegSha256")?
        );
        assert_masked_luma(&jpeg_bytes, [128, 96], 64, 48);
    }

    // 3. Overlapping crop via fss-mcp on import_id: crop (16, 8, 96, 72) -> masked region (0..48, 0..40).
    let crop_args = format!(
        r#"{{"target":"evidence-hydration","level":"H3","import_id":{},"segment_indices":[0],"crop_box":"16,8,96,72","max_h3_frames":1}}"#,
        quote(&f.import_id.to_text()),
    );
    let mcp_crop = f.call_mcp(
        &[
            "--allow-visual-hydration",
            "--grant-capability",
            CAP_AGENT_HYDRATE_H3,
        ],
        &crop_args,
    )?;
    let crop_result = field(&mcp_crop, "result")?;
    assert_eq!(field(crop_result, "isError")?.boolean(), Some(false));
    let crop_content = array(crop_result, "content")?;
    assert_eq!(crop_content.len(), 2);
    let crop_jpeg = decode_base64(text(&crop_content[1], "data")?)?;
    assert_masked_luma(&crop_jpeg, [96, 72], 48, 40);

    // 4. Adversarial gate checks on fss-mcp:
    // 4a. Missing --allow-visual-hydration (even WITH capability) -> ERR-CAPABILITY-DENIED-001.
    let no_launcher = f.call_mcp(&["--grant-capability", CAP_AGENT_HYDRATE_H3], &h3_args)?;
    let no_launcher_res = field(&no_launcher, "result")?;
    assert_eq!(field(no_launcher_res, "isError")?.boolean(), Some(true));
    assert!(
        no_launcher_res
            .object()
            .is_some_and(|o| !o.contains_key("structuredContent"))
    );
    let no_launcher_text = text(&array(no_launcher_res, "content")?[0], "text")?;
    assert!(no_launcher_text.contains(ERR_CAPABILITY_DENIED));

    // 4b. Missing CAP-AGENT-HYDRATE-H3-001 (even WITH --allow-visual-hydration) -> ERR-CAPABILITY-DENIED-001.
    let no_cap = f.call_mcp(&["--allow-visual-hydration"], &h3_args)?;
    let no_cap_res = field(&no_cap, "result")?;
    assert_eq!(field(no_cap_res, "isError")?.boolean(), Some(true));
    let no_cap_text = text(&array(no_cap_res, "content")?[0], "text")?;
    assert!(no_cap_text.contains(ERR_CAPABILITY_DENIED));

    // 4c. Client attempting authority escalation via arguments -> JSON-RPC -32602.
    for hijack in [
        format!(
            r#"{{"target":"evidence-hydration","level":"H3","import_id":{},"allow_visual_hydration":true}}"#,
            quote(&f.import_id.to_text())
        ),
        format!(
            r#"{{"target":"evidence-hydration","level":"H3","import_id":{},"capability":"CAP-AGENT-HYDRATE-H3-001"}}"#,
            quote(&f.import_id.to_text())
        ),
    ] {
        let reply = f.call_mcp(&[], &hijack)?;
        assert_eq!(
            field(field(&reply, "error")?, "code")?.integer(),
            Some(-32602)
        );
    }

    // 4d. Bounds overflow via MCP -> ERR-HYDRATION-BOUNDS-001.
    let over_frames = format!(
        r#"{{"target":"evidence-hydration","level":"H3","import_id":{},"max_h3_frames":5}}"#,
        quote(&f.import_id.to_text()),
    );
    let bounds_reply = f.call_mcp(
        &[
            "--allow-visual-hydration",
            "--grant-capability",
            CAP_AGENT_HYDRATE_H3,
        ],
        &over_frames,
    )?;
    let bounds_res = field(&bounds_reply, "result")?;
    assert_eq!(field(bounds_res, "isError")?.boolean(), Some(true));
    assert!(text(&array(bounds_res, "content")?[0], "text")?.contains(ERR_HYDRATION_BOUNDS));

    // 5. Authority tree must remain strictly unchanged (read-only invariant).
    assert_eq!(authority_snapshot(&f.root)?, before_authority);
    Ok(())
}
