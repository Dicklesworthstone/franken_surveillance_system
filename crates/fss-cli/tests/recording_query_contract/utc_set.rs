#![forbid(unsafe_code)]
//! Explicit catalog-page UTC queries through real CLI/MCP and current deployment context.

use super::*;
use fss_reference::agent_recording_context::utc_set::{
    DeploymentRecordingUtcSetQuery, RecordingUtcSetContextLimits, RecordingUtcSetContextRequest,
    query_recordings_utc_set_in_deployment,
};
use fss_reference::agent_recordings::set::RecordingCatalogPin;
use fss_reference::agent_recordings::utc_set::RecordingUtcSetQueryRequest;

struct UtcSetFixture {
    base: UtcFixture,
    catalogs: Vec<RecordingCatalogPin>,
}

impl UtcSetFixture {
    fn new(tag: &str, codec: RecordingQueryCodec) -> TestResult<Self> {
        let base = UtcFixture::new(tag, codec)?;
        let scope = base.request.recording.scope.clone();
        let a = SlotName::parse("first-window")?;
        let b = SlotName::parse("second-window")?;
        let pages = match codec {
            RecordingQueryCodec::Avc => {
                let first = clock_support::window(1, 0, &[30_000_000])?;
                let second = clock_support::window(2, 7200, &[60_000_000])?;
                [&first, &second]
                    .into_iter()
                    .zip([&a, &b])
                    .map(|(recording, slot)| {
                        let page =
                            prepare_catalog(scope.clone(), &[CatalogWindow { slot, recording }])?;
                        Ok((page.manifest().clone(), page.index_bytes().to_vec()))
                    })
                    .collect::<TestResult<Vec<_>>>()?
            }
            RecordingQueryCodec::Hevc => {
                let first = hevc_window(0, 30_000_000)?;
                let second = hevc_window(200_000, 60_000_000)?;
                [&first, &second]
                    .into_iter()
                    .zip([&a, &b])
                    .map(|(recording, slot)| {
                        let page = prepare_hevc_catalog(
                            scope.clone(),
                            &[HevcCatalogWindow { slot, recording }],
                        )?;
                        Ok((page.manifest().clone(), page.index_bytes().to_vec()))
                    })
                    .collect::<TestResult<Vec<_>>>()?
            }
        };
        let mut catalogs = Vec::new();
        for (ordinal, (manifest, bytes)) in pages.into_iter().enumerate() {
            let slot = SlotName::parse(&format!("utc-catalog-page-{ordinal}"))?;
            publish(&base.base.archive, &slot, &manifest)?;
            put(&base.base.archive, &bytes)?;
            catalogs.push(RecordingCatalogPin {
                slot,
                root: manifest.root(),
            });
        }
        Ok(Self { base, catalogs })
    }

    fn request(&self) -> RecordingUtcSetContextRequest {
        let old = &self.base.request;
        let r = &old.recording;
        RecordingUtcSetContextRequest {
            principal: old.principal.clone(),
            expected_anchor: old.expected_anchor.clone(),
            recording: RecordingUtcSetQueryRequest {
                codec: r.codec,
                scope: r.scope.clone(),
                catalogs: self.catalogs.clone(),
                clock_slot: r.clock_slot.clone(),
                clock_root: r.clock_root,
                interval: r.interval.clone(),
                max_windows: r.max_windows,
                max_hydration_bytes: r.max_hydration_bytes,
            },
        }
    }

    fn fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = self.base.fields();
        fields.retain(|(key, _)| !matches!(*key, "catalog_slot" | "catalog_root"));
        fields
    }

    fn run(&self) -> TestResult<(String, ExitIdentity)> {
        let mut fields = self.fields();
        fields.push((
            "catalogs",
            self.catalogs
                .iter()
                .map(|pin| format!("{}={}", pin.slot.as_str(), pin.root))
                .collect::<Vec<_>>()
                .join(","),
        ));
        self.base.run_fields(fields, true)
    }

    fn mcp(&self) -> TestResult<(String, bool)> {
        let mut fields = self
            .fields()
            .iter()
            .map(|(key, value)| {
                let value = if matches!(*key, "time_scale" | "max_windows") {
                    value.clone()
                } else {
                    format!("\"{}\"", fss_cli::escape_json_str(value))
                };
                format!("\"{key}\":{value}")
            })
            .collect::<Vec<_>>();
        fields.push(format!(
            "\"catalogs\":[{}]",
            self.catalogs
                .iter()
                .map(|pin| {
                    format!(
                        "{{\"slot\":\"{}\",\"root\":\"{}\"}}",
                        pin.slot.as_str(),
                        pin.root
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        ));
        self.base.mcp_fields(&fields.join(","))
    }

    fn query_with(
        &self,
        io: &dyn fss_object::SpoolIo,
        limits: &RecordingUtcSetContextLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<DeploymentRecordingUtcSetQuery, RecordingUtcContextError> {
        query_recordings_utc_set_in_deployment(
            io,
            &self.base.base.deployment,
            &self.base.base.archive,
            &self.request(),
            limits,
            cancelled,
        )
    }
}

#[test]
fn utc_set_cli_and_mcp_preserve_all_pages_unknown_clocks_and_protected_context() -> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture = UtcSetFixture::new(&format!("utc-set-{}", codec.as_str()), codec)?;
        fixture
            .base
            .base
            .publish_hypothesis("event:protected-utc-set")?;
        let before = tree(&fixture.base.base.directory)?;
        let (output, exit) = fixture.run()?;
        assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
        assert_eq!(fixture.mcp()?, (output.clone(), false));
        assert_eq!(fixture.run()?, (output.clone(), exit));
        let envelope = parse_json(&output)?;
        assert_eq!(
            text_at(&envelope, &["schema"])?,
            "fss.agent_response_envelope.v1"
        );
        assert_eq!(
            text_at(&envelope, &["payload", "coverage", "stopReason"])?,
            "pinned_clock_catalog_set_exhausted"
        );
        for (claim, state) in [
            ("claim:recordings-utc-set:window:0", "known"),
            ("claim:recordings-utc-set:window:1", "not_observable"),
            ("claim:recordings-utc-set:physical-observability", "unknown"),
        ] {
            assert_eq!(text_at(proposition(&envelope, claim)?, &["state"])?, state);
        }
        assert!(output.contains("clock_unavailable"));
        assert!(output.contains("packet-admission coordinates were not replayed"));
        assert!(output.contains("native-recording-clock-metadata"));
        assert!(output.contains("event:protected-utc-set"));
        for (ordinal, catalog) in fixture.catalogs.iter().enumerate() {
            assert!(
                proposition(
                    &envelope,
                    &format!("claim:recordings-utc-set:catalog:{ordinal}")
                )?
                .object()
                .is_some()
            );
            assert!(output.contains(&catalog.root.to_text()));
        }
        let handles = at(&envelope, &["payload", "evidenceHandles"])?
            .array()
            .ok_or("handles")?;
        assert_eq!(handles.len(), 5);
        for handle in handles {
            assert_eq!(text_at(handle, &["hydration"])?, "H0");
            assert_eq!(
                at(handle, &["allowedHydration"])?
                    .array()
                    .ok_or("hydration allowance")?,
                &[Value::Text("H0".to_owned())]
            );
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let limits = RecordingUtcSetContextLimits::default();
        let query = fixture.query_with(&io, &limits, &|| false)?;
        assert!(io.is_read_only());
        assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
        let orientation = orient_deployment(
            &query.snapshot,
            &OrientRequest {
                view: AgentView::Brief,
                principal: fixture.base.request.principal.clone(),
                budget_tokens: None,
            },
            &limits.snapshot,
        )?;
        for cell in &orientation.capsule().frame.knowledge_cells {
            let actual = proposition(&envelope, cell.claim_id())?;
            assert_eq!(
                text_at(actual, &["state"])?,
                cell.knowledge_state().as_str()
            );
            assert_eq!(
                text_at(actual, &["statement"])?,
                cell.disclosable_statement()
            );
        }
        for leaf in &fixture.base.base.source_leaves {
            assert!(!object_path(&fixture.base.base.archive, *leaf).exists());
        }
        assert_eq!(tree(&fixture.base.base.directory)?, before);
    }
    Ok(())
}

#[test]
fn utc_set_unknown_windows_survive_outside_bounds_and_share_atomic_result_limits() -> TestResult {
    let mut fixture = UtcSetFixture::new("utc-set-output-bounds", RecordingQueryCodec::Avc)?;
    fixture.base.request.recording.max_windows = 1;
    assert_eq!(fixture.run()?.1, ExitIdentity::AGENT_REFUSED);
    fixture.base.request.recording.interval =
        fixture.base.known.latest_ns + 1..fixture.base.known.latest_ns + 10;
    fixture.base.request.recording.max_hydration_bytes = fixture.base.unknown_bytes;
    let (output, exit) = fixture.run()?;
    assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
    assert_eq!(fixture.mcp()?, (output.clone(), false));
    assert!(output.contains(&fixture.base.unknown_root.to_text()));
    let envelope = parse_json(&output)?;
    let gap = proposition(&envelope, "claim:recordings-utc-set:indexed-gap:0")?;
    assert_eq!(text_at(gap, &["state"])?, "not_observable");
    assert!(text_at(gap, &["statement"])?.contains("Windows with unavailable clocks may overlap"));
    fixture.base.request.recording.max_hydration_bytes -= 1;
    let before = tree(&fixture.base.base.directory)?;
    let (refusal, exit) = fixture.run()?;
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert_eq!(fixture.mcp()?, (refusal, true));
    assert_eq!(tree(&fixture.base.base.directory)?, before);
    Ok(())
}

#[test]
fn utc_set_context_revalidates_current_head_and_refuses_stale_anchor_before_archive_io()
-> TestResult {
    let mut fixture = UtcSetFixture::new("utc-set-context", RecordingQueryCodec::Avc)?;
    let limits = RecordingUtcSetContextLimits::default();
    let initial = fixture.query_with(&HostSpoolIo, &limits, &|| false)?;
    fixture.base.request.expected_anchor =
        Some(AnchorToken::parse(&initial.anchor_token).ok_or("anchor")?);
    fixture
        .base
        .base
        .publish_hypothesis("event:utc-set-new-head")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    assert!(matches!(
        fixture.query_with(&io, &limits, &|| false),
        Err(RecordingUtcContextError::AnchorChanged)
    ));
    assert_eq!(io.call_count(SpoolIoCall::OpenRead), 0);
    fixture.base.request.expected_anchor = None;
    let changed = AtomicBool::new(false);
    let cancel = || {
        if io.call_count(SpoolIoCall::OpenRead) >= 5 && !changed.swap(true, Ordering::SeqCst) {
            return fixture
                .base
                .base
                .publish_hypothesis("event:utc-set-racing-head")
                .is_err();
        }
        false
    };
    assert!(matches!(
        fixture.query_with(&io, &limits, &cancel),
        Err(RecordingUtcContextError::AnchorChanged)
    ));
    assert!(changed.load(Ordering::SeqCst));
    for leaf in &fixture.base.base.source_leaves {
        fs::write(
            object_path(&fixture.base.base.archive, *leaf),
            b"unread corrupt source bytes",
        )?;
    }
    let cx = fixture.base.base.cx()?;
    let writer = ReferenceDeployment::open(&fixture.base.base.deployment, SITE, &cx)?;
    let lock = fs::File::create(fixture.base.base.archive.join("LOCK"))?;
    lock.try_lock()?;
    let before = tree(&fixture.base.base.directory)?;
    assert_eq!(fixture.run()?.1, ExitIdentity::SUCCESS);
    assert_eq!(tree(&fixture.base.base.directory)?, before);
    lock.unlock()?;
    drop(writer);
    Ok(())
}

#[test]
fn utc_set_context_shares_nonrefillable_budgets_and_cancels_without_mutation() -> TestResult {
    let fixture = UtcSetFixture::new("utc-set-budgets", RecordingQueryCodec::Avc)?;
    let limits = RecordingUtcSetContextLimits::default();
    let baseline = fixture.query_with(&HostSpoolIo, &limits, &|| false)?;
    let exact = RecordingUtcSetContextLimits {
        deployment_bytes: baseline.deployment_bytes_read as usize + 1,
        deployment_reads: baseline.deployment_metadata_reads as usize,
        ..limits
    };
    let admitted = fixture.query_with(&HostSpoolIo, &exact, &|| false)?;
    assert_eq!(admitted.native.rows, baseline.native.rows);
    assert_eq!(
        admitted.deployment_metadata_reads,
        baseline.deployment_metadata_reads
    );
    assert_ne!(admitted.request_digest, baseline.request_digest);
    let before = tree(&fixture.base.base.directory)?;
    for (dimension, mut lowered) in [exact; 3].into_iter().enumerate() {
        match dimension {
            0 => lowered.deployment_bytes = baseline.deployment_bytes_read as usize - 1,
            1 => lowered.deployment_reads -= 1,
            _ => lowered.recording.metadata.max_io_calls = baseline.native.read_usage.io_calls - 1,
        }
        assert!(
            fixture
                .query_with(&HostSpoolIo, &lowered, &|| false)
                .is_err()
        );
    }
    assert!(matches!(
        fixture.query_with(&HostSpoolIo, &limits, &|| true),
        Err(RecordingUtcContextError::Cancelled)
    ));
    assert_eq!(tree(&fixture.base.base.directory)?, before);
    Ok(())
}

#[test]
fn utc_set_incomplete_pages_or_revoked_clock_never_return_empty_success() -> TestResult {
    for defect in [
        "missing-page",
        "clock-metadata",
        "clock-root",
        "source-tombstone",
    ] {
        let mut fixture = UtcSetFixture::new(defect, RecordingQueryCodec::Avc)?;
        match defect {
            "missing-page" => {
                fixture.catalogs.remove(0);
            }
            "clock-metadata" => fs::write(
                object_path(&fixture.base.base.archive, fixture.base.clock_metadata),
                b"corrupt clock metadata",
            )?,
            "clock-root" => {
                fixture.base.request.recording.clock_root =
                    ContentDigest::sha256(b"foreign clock root");
            }
            _ => {
                let leaf = fixture
                    .base
                    .base
                    .source_leaves
                    .first()
                    .ok_or("source leaf")?;
                fs::write(
                    fixture
                        .base
                        .base
                        .archive
                        .join("tombstones")
                        .join(format!("{}.tomb", leaf.to_text().replacen(':', "-", 1))),
                    b"deletion present",
                )?;
            }
        }
        let before = tree(&fixture.base.base.directory)?;
        let (output, exit) = fixture.run()?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{defect}: {output}");
        assert!(!output.contains("claim:recordings-utc-set:catalog-selection"));
        assert_eq!(fixture.mcp()?, (output, true));
        assert_eq!(tree(&fixture.base.base.directory)?, before);
    }
    Ok(())
}
