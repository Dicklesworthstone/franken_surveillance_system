#![forbid(unsafe_code)]
//! Native frame inspection while capture retains the exclusive publication owner.

use fss_reference::retained_source::ImmutableRetainedSource;

use super::*;

pub(super) fn run(plan: &Plan, out: &mut impl Write) -> Result<()> {
    if !matches!(plan.command, Command::Read | Command::Verify) {
        return Err(fail("immutable video operations cannot publish"));
    }
    let approval = plan.digest()?;
    if plan.approval != Some(approval) {
        return Err(fail("exact video operation approval required"));
    }
    let start = Instant::now();
    let root = existing_root(&plan.root)?;
    let export = plan
        .output
        .as_ref()
        .map(|path| Export::prepare(path, &root))
        .transpose()?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:video-cli".into(),
        operation_id: OperationId::parse("operation:video-cli")?,
        principal: plan.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(plan.read.max_read_bytes as u64)
            .storage_operations(plan.read.max_read_objects as u64)
            .build()?,
        privacy_scope: "privacy:exact-owner-video-policy".into(),
        retention_scope: "retention:explicit-native-derived-frames".into(),
        anchor_universe: ContentDigest::sha256(plan.site.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())?;
    let gate = Gate {
        cx: &cx,
        start,
        timeout: Duration::from_millis(plan.timeout_ms),
    };
    let cancelled = || start.elapsed() >= gate.timeout;
    let result = (|| -> Result<()> {
        gate.check()?;
        let source = ImmutableRetainedSource::open_cancellable(&root, plan.read, &cx, &cancelled)?;
        if source.site_lineage() != plan.site {
            return Err(fail("deployment site differs from approved site"));
        }
        let saved = PublishedVideoFrame::open(
            &source,
            plan.frame.ok_or_else(|| fail("frame root required"))?,
            publication_limits(plan),
            &cx,
        )?;
        scope(plan, &saved)?;
        let mut budget = RecordedVideoDecodeBudget::new(plan.work);
        let mut decoded = 0_usize;
        let skipped = if plan.command == Command::Verify {
            let mut range = Range::open(
                plan,
                usize::try_from(saved.range_start())?,
                saved.range_segment_count(),
                &source,
                &mut budget,
                &cx,
            )?;
            let mut matched = false;
            loop {
                gate.check()?;
                let Some(frame) = range.next(&source, &mut budget, &cx)? else {
                    break;
                };
                decoded += 1;
                if frame.output() == saved.output_index() {
                    if matched || !frame.equals(&saved) {
                        return Err(RecordedDecodeError::InvalidReceipt.into());
                    }
                    matched = true;
                }
                // A matching early frame cannot hide a corrupt or refused suffix.
            }
            if !matched {
                return Err(RecordedDecodeError::InvalidReceipt.into());
            }
            range.skipped().to_vec()
        } else {
            Vec::new()
        };
        gate.check()?;
        let export_bytes = if export.is_some() {
            Some(match plan.pixel_format.as_deref() {
                Some("pgm") => {
                    let [width, height] = saved.dimensions();
                    let mut bytes = format!("P5\n{width} {height}\n255\n").into_bytes();
                    bytes.try_reserve_exact(saved.pixels().len())?;
                    bytes.extend_from_slice(saved.pixels());
                    bytes
                }
                Some("i420") => saved.i420().to_vec(),
                Some("rgb") => saved.to_rgb()?,
                _ => return Err(fail("pixel format required")),
            })
        } else {
            None
        };
        // Keep every success row private until the complete snapshot has been revalidated.
        let mut output = Vec::new();
        let mut reports = Reports {
            out: &mut output,
            sequence: 0,
            bytes: 0,
        };
        reports.row(
            "started",
            object(&[
                ("approval", string(&approval.to_text())),
                ("command", string(plan.command.text())),
                ("network_requested", "false".into()),
            ]),
        )?;
        if let Some(bytes) = &export_bytes {
            reports.row(
                "export",
                object(&[
                    ("bytes", bytes.len().to_string()),
                    ("digest", string(&ContentDigest::sha256(bytes).to_text())),
                    (
                        "pixel_format",
                        string(
                            plan.pixel_format
                                .as_deref()
                                .ok_or_else(|| fail("pixel format"))?,
                        ),
                    ),
                ]),
            )?;
        }
        reports.row("frame", frame_json(&saved))?;
        reports.row(
            "terminal",
            object(&[
                ("command", string(plan.command.text())),
                ("complete", "true".into()),
                ("frames_decoded", decoded.to_string()),
                ("decode_work_units", budget.used().to_string()),
                ("charged_derived_bytes", "0".into()),
                (
                    "skipped_rasl_segments",
                    format!(
                        "[{}]",
                        skipped
                            .iter()
                            .map(usize::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                ),
                (
                    "replay_verified",
                    (plan.command == Command::Verify).to_string(),
                ),
                ("new_frame_publication_requested", "false".into()),
                ("network_requested", "false".into()),
                ("absence_certifiable", "false".into()),
            ]),
        )?;
        gate.check()?;
        // The one read allowance covers metadata replay and every selected payload reread.
        // Revalidate finishes by checking the current authority, with no subsequent reads.
        source.revalidate_snapshot_metadata()?;
        source.revalidate()?;
        if let (Some(export), Some(bytes)) = (&export, &export_bytes) {
            export.write(bytes, &gate)?;
        }
        write_bounded(out, &output)?;
        Ok(())
    })();
    cx.drain_and_finalize();
    result
}
