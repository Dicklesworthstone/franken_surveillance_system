#![forbid(unsafe_code)]
//! Namespace-wide UTC metadata through real CLI/MCP and protected deployment authority.

use super::*;
use fss_reference::agent_recording_context::utc_discover::{
    DeploymentRecordingUtcDiscoveryQuery, RecordingUtcDiscoveryContextError,
    RecordingUtcDiscoveryContextLimits, RecordingUtcDiscoveryContextRequest,
    discover_recordings_utc_in_deployment,
};
use fss_reference::agent_recordings::utc_discover::{
    RecordingUtcDiscoveryRequest, discover_recordings_utc,
};
use fss_reference::rtsp::recording_archive::{ArchiveNamespace, hevc::HevcArchiveNamespace};

struct UtcDiscoveryFixture {
    base: UtcFixture,
    pages: Vec<(SlotName, ContentDigest)>,
    windows: Vec<SlotName>,
    last_clocked: UtcInterval,
}

fn slots(
    scope: &CatalogScope,
    codec: RecordingQueryCodec,
    ordinal: usize,
) -> TestResult<(SlotName, SlotName)> {
    Ok(match codec {
        RecordingQueryCodec::Avc => {
            let namespace = ArchiveNamespace::new(scope.clone())?;
            (
                namespace.window_slot(ordinal)?,
                namespace.page_slot(ordinal)?,
            )
        }
        RecordingQueryCodec::Hevc => {
            let namespace = HevcArchiveNamespace::new(scope.clone())?;
            (
                namespace.window_slot(ordinal)?,
                namespace.page_slot(ordinal)?,
            )
        }
    })
}

impl UtcDiscoveryFixture {
    fn new(tag: &str, codec: RecordingQueryCodec) -> TestResult<Self> {
        let mut base = UtcFixture::new(tag, codec)?;
        let scope = base.request.recording.scope.clone();
        let mut pages = Vec::new();
        let mut windows = Vec::new();
        let mut descriptors = Vec::new();
        let mut brackets = Vec::new();
        let mut leaves = BTreeSet::new();
        // Nine independently sealed pages exceed the explicit catalog-set ceiling. The
        // final window lacks a clock annotation and must survive every UTC selection.
        for ordinal in 0..9 {
            let (slot, page_slot) = slots(&scope, codec, ordinal)?;
            let admission = 30_000_000 + 5_000_000 * ordinal as u64;
            let (manifest, bytes, descriptor, root, quote) = match codec {
                RecordingQueryCodec::Avc => {
                    let window = clock_support::window(
                        1 + 2 * ordinal as u64,
                        7200 * ordinal as u64,
                        &[admission],
                    )?;
                    publish(&base.base.archive, &slot, window.manifest())?;
                    leaves.extend(window.children().into_iter().map(|(_, digest, _)| digest));
                    let page = prepare_catalog(
                        scope.clone(),
                        &[CatalogWindow {
                            slot: &slot,
                            recording: &window,
                        }],
                    )?;
                    (
                        page.manifest().clone(),
                        page.index_bytes().to_vec(),
                        ClockWindow::from_avc(slot.clone(), &window)?,
                        window.manifest().root(),
                        window.byte_len() as u64,
                    )
                }
                RecordingQueryCodec::Hevc => {
                    let window = hevc_window(200_000 * ordinal as u64, admission)?;
                    publish(&base.base.archive, &slot, window.manifest())?;
                    leaves.extend(
                        window
                            .publication_plan()
                            .children()
                            .into_iter()
                            .map(|(_, digest, _)| digest),
                    );
                    let page = prepare_hevc_catalog(
                        scope.clone(),
                        &[HevcCatalogWindow {
                            slot: &slot,
                            recording: &window,
                        }],
                    )?;
                    (
                        page.manifest().clone(),
                        page.index_bytes().to_vec(),
                        ClockWindow::from_hevc(slot.clone(), &window)?,
                        window.manifest().root(),
                        window.byte_len() as u64,
                    )
                }
            };
            publish(&base.base.archive, &page_slot, &manifest)?;
            put(&base.base.archive, &bytes)?;
            pages.push((page_slot, manifest.root()));
            windows.push(slot);
            if ordinal < 8 {
                descriptors.push(descriptor);
                brackets.push(clock_support::bracket(admission));
            } else {
                base.unknown_root = root;
                base.unknown_bytes = quote;
            }
        }
        let clock_codec = match codec {
            RecordingQueryCodec::Avc => RecordingClockCodec::Avc,
            RecordingQueryCodec::Hevc => RecordingClockCodec::Hevc,
        };
        let clock = RecordingClockIndex::prepare(
            scope.clone(),
            clock_codec,
            clock_support::approval(),
            clock_support::exchange()?,
            clock_support::host(100_000_000),
            &brackets,
            &descriptors,
        )?;
        base.known = clock
            .windows()
            .first()
            .ok_or("first clock row")?
            .utc_interval();
        let last_clocked = clock
            .windows()
            .last()
            .ok_or("last clock row")?
            .utc_interval();
        base.request.recording.interval = base.known.earliest_ns..last_clocked.latest_ns + 1;
        base.request.recording.clock_slot = clock_slot(clock_codec, &scope)?;
        base.request.recording.clock_root = clock.root();
        base.clock_metadata = ContentDigest::sha256(clock.index_bytes());
        base.base.source_leaves = leaves;
        publish(
            &base.base.archive,
            &base.request.recording.clock_slot,
            clock.manifest(),
        )?;
        put(&base.base.archive, clock.index_bytes())?;
        Ok(Self {
            base,
            pages,
            windows,
            last_clocked,
        })
    }

    fn request(&self) -> RecordingUtcDiscoveryContextRequest {
        let old = &self.base.request;
        let r = &old.recording;
        RecordingUtcDiscoveryContextRequest {
            principal: old.principal.clone(),
            expected_anchor: old.expected_anchor.clone(),
            recording: RecordingUtcDiscoveryRequest {
                codec: r.codec,
                scope: r.scope.clone(),
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
        fields.push(("discover_catalogs", "yes".to_owned()));
        self.base.run_fields(fields, UtcFixtureMode::Discovery)
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
        fields.push("\"discover_catalogs\":true".to_owned());
        self.base.mcp_fields(&fields.join(","))
    }

    fn query_with(
        &self,
        io: &dyn fss_object::SpoolIo,
        limits: &RecordingUtcDiscoveryContextLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<DeploymentRecordingUtcDiscoveryQuery, RecordingUtcDiscoveryContextError> {
        discover_recordings_utc_in_deployment(
            io,
            &self.base.base.deployment,
            &self.base.base.archive,
            &self.request(),
            limits,
            cancelled,
        )
    }

    fn select_unknown_only(&mut self) {
        self.base.request.recording.interval =
            self.last_clocked.latest_ns + 1..self.last_clocked.latest_ns + 10;
    }
}

#[test]
fn utc_discovery_cli_and_mcp_find_nine_pages_with_exact_protected_context() -> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture =
            UtcDiscoveryFixture::new(&format!("utc-discovery-{}", codec.as_str()), codec)?;
        fixture
            .base
            .base
            .publish_hypothesis("event:protected-utc-discovery")?;
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
            "archive_namespace_and_clock_exhausted"
        );
        let inventory = text_at(
            proposition(&envelope, "claim:recordings-utc-discovery:inventory")?,
            &["statement"],
        )?;
        assert!(inventory.contains("catalogs=9"), "{inventory}");
        assert!(inventory.contains("indexed_memberships=9"), "{inventory}");
        assert!(inventory.contains("returned_windows=9"), "{inventory}");
        for (claim, state) in [
            ("claim:recordings-utc-discovery:window:0", "known"),
            ("claim:recordings-utc-discovery:window:8", "not_observable"),
            (
                "claim:recordings-utc-discovery:physical-observability",
                "unknown",
            ),
        ] {
            assert_eq!(text_at(proposition(&envelope, claim)?, &["state"])?, state);
        }
        assert!(output.contains("clock_unavailable"));
        assert!(output.contains("event:protected-utc-discovery"));
        let handles = at(&envelope, &["payload", "evidenceHandles"])?
            .array()
            .ok_or("handles")?;
        assert_eq!(handles.len(), 19);
        for handle in handles {
            assert_eq!(text_at(handle, &["hydration"])?, "H0");
            assert_eq!(
                at(handle, &["allowedHydration"])?
                    .array()
                    .ok_or("hydration allowance")?,
                &[Value::Text("H0".to_owned())]
            );
        }
        let limits = RecordingUtcDiscoveryContextLimits::default();
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let query = fixture.query_with(&io, &limits, &|| false)?;
        assert_eq!(query.native.catalogs.len(), 9);
        assert_eq!(query.native.clock_windows, 8);
        assert_eq!(query.native.rows.len(), 9);
        assert!(io.is_read_only());
        assert_eq!(io.call_count(SpoolIoCall::ReadDir), 2);
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
fn utc_discovery_projects_selected_pages_but_preserves_full_inventory_and_unknown_window_cost()
-> TestResult {
    let mut fixture = UtcDiscoveryFixture::new("utc-discovery-narrow", RecordingQueryCodec::Avc)?;
    fixture.base.request.recording.max_windows = 1;
    assert_eq!(fixture.run()?.1, ExitIdentity::AGENT_REFUSED);
    fixture.select_unknown_only();
    fixture.base.request.recording.max_hydration_bytes = fixture.base.unknown_bytes;
    let (output, exit) = fixture.run()?;
    assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
    assert_eq!(fixture.mcp()?, (output.clone(), false));
    let envelope = parse_json(&output)?;
    let inventory = text_at(
        proposition(&envelope, "claim:recordings-utc-discovery:inventory")?,
        &["statement"],
    )?;
    assert!(inventory.contains("catalogs=9"));
    assert!(inventory.contains("returned_windows=1"));
    assert!(proposition(&envelope, "claim:recordings-utc-discovery:catalog:0").is_err());
    assert!(proposition(&envelope, "claim:recordings-utc-discovery:catalog:8").is_ok());
    assert_eq!(
        at(&envelope, &["payload", "evidenceHandles"])?
            .array()
            .ok_or("handles")?
            .len(),
        3
    );
    let gap = proposition(&envelope, "claim:recordings-utc-discovery:indexed-gap:0")?;
    assert_eq!(text_at(gap, &["state"])?, "not_observable");
    assert!(text_at(gap, &["statement"])?.contains("unavailable clocks"));
    let query = fixture.query_with(
        &HostSpoolIo,
        &RecordingUtcDiscoveryContextLimits::default(),
        &|| false,
    )?;
    assert!(output.contains(&query.native.inventory_digest.to_text()));
    assert_eq!(query.native.rows.len(), 1);
    assert_eq!(query.native.rows[0].utc_interval, None);
    assert_eq!(query.native.rows[0].entry.root(), fixture.base.unknown_root);
    fixture.base.request.recording.max_hydration_bytes -= 1;
    let before = tree(&fixture.base.base.directory)?;
    let (refusal, exit) = fixture.run()?;
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert_eq!(fixture.mcp()?, (refusal, true));
    assert_eq!(tree(&fixture.base.base.directory)?, before);
    Ok(())
}

#[test]
fn utc_discovery_revalidates_deployment_head_and_keeps_source_payloads_unread() -> TestResult {
    let mut fixture = UtcDiscoveryFixture::new("utc-discovery-context", RecordingQueryCodec::Avc)?;
    let limits = RecordingUtcDiscoveryContextLimits::default();
    let initial = fixture.query_with(&HostSpoolIo, &limits, &|| false)?;
    fixture.base.request.expected_anchor =
        Some(AnchorToken::parse(&initial.anchor_token).ok_or("anchor")?);
    fixture
        .base
        .base
        .publish_hypothesis("event:utc-discovery-new-head")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    assert!(matches!(
        fixture.query_with(&io, &limits, &|| false),
        Err(RecordingUtcDiscoveryContextError::AnchorChanged)
    ));
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert_eq!(io.call_count(SpoolIoCall::OpenRead), 0);
    fixture.base.request.expected_anchor = None;
    let changed = AtomicBool::new(false);
    let mutate = || {
        if io.call_count(SpoolIoCall::OpenRead) >= 5 && !changed.swap(true, Ordering::SeqCst) {
            return fixture
                .base
                .base
                .publish_hypothesis("event:utc-discovery-racing-head")
                .is_err();
        }
        false
    };
    assert!(matches!(
        fixture.query_with(&io, &limits, &mutate),
        Err(RecordingUtcDiscoveryContextError::AnchorChanged)
    ));
    assert!(changed.load(Ordering::SeqCst));
    for leaf in &fixture.base.base.source_leaves {
        fs::write(
            object_path(&fixture.base.base.archive, *leaf),
            b"corrupt original bytes remain unread",
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
fn utc_discovery_context_and_namespace_share_nonrefillable_budgets_and_cancel_cleanly() -> TestResult
{
    let fixture = UtcDiscoveryFixture::new("utc-discovery-budgets", RecordingQueryCodec::Avc)?;
    let limits = RecordingUtcDiscoveryContextLimits::default();
    let baseline = fixture.query_with(&HostSpoolIo, &limits, &|| false)?;
    let exact = RecordingUtcDiscoveryContextLimits {
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
    for (dimension, mut lowered) in [exact; 4].into_iter().enumerate() {
        match dimension {
            0 => lowered.deployment_bytes = baseline.deployment_bytes_read as usize - 1,
            1 => lowered.deployment_reads -= 1,
            2 => lowered.recording.metadata.max_io_calls = baseline.native.read_usage.io_calls - 1,
            _ => lowered.recording.max_scan_roots = 1,
        }
        assert!(
            fixture
                .query_with(&HostSpoolIo, &lowered, &|| false)
                .is_err()
        );
    }
    assert!(matches!(
        fixture.query_with(&HostSpoolIo, &limits, &|| true),
        Err(RecordingUtcDiscoveryContextError::Cancelled)
    ));
    assert_eq!(tree(&fixture.base.base.directory)?, before);
    Ok(())
}

#[test]
fn utc_discovery_incomplete_namespace_missing_clock_and_deletion_never_become_empty_success()
-> TestResult {
    for defect in [
        "missing-page",
        "unindexed-tail",
        "empty-namespace",
        "clock-metadata",
        "source-tombstone",
    ] {
        let mut fixture = UtcDiscoveryFixture::new(defect, RecordingQueryCodec::Avc)?;
        fixture.select_unknown_only();
        match defect {
            "missing-page" => fs::remove_file(
                fixture
                    .base
                    .base
                    .archive
                    .join("roots")
                    .join(format!("{}.root", fixture.pages[0].0.as_str())),
            )?,
            "unindexed-tail" => {
                let (slot, _) = slots(
                    &fixture.base.request.recording.scope,
                    RecordingQueryCodec::Avc,
                    9,
                )?;
                let window = clock_support::window(19, 64800, &[75_000_000])?;
                publish(&fixture.base.base.archive, &slot, window.manifest())?;
            }
            "empty-namespace" => {
                for slot in fixture
                    .windows
                    .iter()
                    .chain(fixture.pages.iter().map(|(slot, _)| slot))
                {
                    fs::remove_file(
                        fixture
                            .base
                            .base
                            .archive
                            .join("roots")
                            .join(format!("{}.root", slot.as_str())),
                    )?;
                }
            }
            "clock-metadata" => fs::write(
                object_path(&fixture.base.base.archive, fixture.base.clock_metadata),
                b"corrupt clock metadata",
            )?,
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
        assert!(!output.contains("claim:recordings-utc-discovery:inventory"));
        assert_eq!(fixture.mcp()?, (output, true));
        assert_eq!(tree(&fixture.base.base.directory)?, before);
    }
    Ok(())
}

#[test]
fn utc_discovery_current_deletion_denies_an_unselected_source_with_intact_archive() -> TestResult {
    use fss_geometry::WorkBudget;
    use fss_object::SpoolLimits;
    use fss_publication::{LocalPublicationLimits, LocalRootPublisher};
    use fss_reference::deletion::{CommitOutcome, commit_deletion, plan_deletion};
    use fss_reference::ingest::rtsp_import::{
        RtspImportAuthority, RtspImportCodec, RtspImportRequest, import_rtsp,
    };

    let mut fixture =
        UtcDiscoveryFixture::new("utc-discovery-current-deletion", RecordingQueryCodec::Avc)?;
    fixture.select_unknown_only();
    let recording = clock_support::window(1, 0, &[30_000_000])?;
    let slot = fixture.windows[0].clone();
    let source_digest = recording.children().first().ok_or("source child")?.1;
    let mut source = LocalRootPublisher::open(
        fixture.base.base.directory.join("deletion-source"),
        LocalPublicationLimits::new(
            16,
            64,
            16,
            256,
            SpoolLimits::new(256, 128 * 1024 * 1024, 32 * 1024 * 1024, 256),
        ),
    )?;
    for (_, digest, bytes) in recording.children() {
        assert_eq!(source.stage_object(bytes)?, digest);
    }
    source.publish(&slot, recording.manifest())?;
    // Setup authority belongs only to this synthetic import/deletion, never the query.
    let principal = "principal:utc-discovery-delete";
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:utc-discovery-delete".to_owned(),
        operation_id: OperationId::parse("operation:utc-discovery-delete")?,
        principal: principal.to_owned(),
        capabilities: [
            ADP_REPLAY_ROW_ID,
            "CAP-READ-MEDIA-001",
            "CAP-OBJECT-STAGE-001",
            "CAP-OBJECT-PUBLISH-001",
            "CAP-RETENTION-COMMIT-001",
            "CAP-DELETE-PREPARE-001",
            "CAP-DELETE-COMMIT-001",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(512 * 1024 * 1024).build()?,
        privacy_scope: "privacy:fixture".to_owned(),
        retention_scope: "retention:fixture".to_owned(),
        anchor_universe: ContentDigest::sha256(b"independent-deployment-universe"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, fixture.base.base.deployment.clone())?;
    let mut deployment = ReferenceDeployment::open(&fixture.base.base.deployment, SITE, &cx)?;
    struct Owner(ContentDigest);
    impl RtspImportAuthority for Owner {
        fn permit(&self, request: &RtspImportRequest, destination: &ReferenceDeployment) -> bool {
            request.root == self.0 && destination.site_lineage() == SITE
        }
    }
    let imported = import_rtsp(
        &source,
        &mut deployment,
        &RtspImportRequest {
            codec: RtspImportCodec::Avc,
            slot,
            root: recording.manifest().root(),
            source: recording.summary().scope.clone(),
            receive_time: TimestampNs(10_000_000_000),
            capture_origin: None,
            max_frames: 256,
            max_original_bytes: 32 * 1024 * 1024,
            max_media_bytes: 32 * 1024 * 1024,
        },
        &Owner(recording.manifest().root()),
        &cx,
        &mut WorkBudget::new(512 * 1024 * 1024),
    )?;
    let limits = RecordingUtcDiscoveryContextLimits::default();
    let initial = fixture.query_with(&HostSpoolIo, &limits, &|| false)?;
    assert_eq!(initial.native.rows.len(), 1);
    assert_eq!(
        initial.native.rows[0].entry.root(),
        fixture.base.unknown_root
    );
    assert!(initial.native.reference_digests.contains(&source_digest));
    let plan = plan_deletion(&deployment, imported.import_identity, &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(
        plan.deletable
            .iter()
            .any(|entry| entry.digest == source_digest)
    );
    let receipt = commit_deletion(
        &mut deployment,
        plan.digest()?,
        plan.approval_digest(principal)?,
        principal,
        &cx,
    )?;
    assert_eq!(receipt.outcome, CommitOutcome::Completed);
    drop(deployment);
    drop(source);

    let native = discover_recordings_utc(
        &HostSpoolIo,
        &fixture.base.base.archive,
        &fixture.request().recording,
        limits.recording,
        &|| false,
    )?;
    assert_eq!(native.rows, initial.native.rows);
    assert_eq!(native.reference_digests, initial.native.reference_digests);
    let before = tree(&fixture.base.base.directory)?;
    assert!(matches!(
        fixture.query_with(&HostSpoolIo, &limits, &|| false),
        Err(RecordingUtcDiscoveryContextError::AnchorChanged)
    ));
    let (output, exit) = fixture.run()?;
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert_eq!(fixture.mcp()?, (output, true));
    assert_eq!(tree(&fixture.base.base.directory)?, before);
    Ok(())
}
