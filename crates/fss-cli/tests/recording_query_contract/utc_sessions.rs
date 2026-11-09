#![forbid(unsafe_code)]
//! Complete UTC candidate unions retain each capture epoch's independent source and clock.

use super::*;
use fss_reference::agent_recording_context::utc_sessions::{
    DeploymentRecordingUtcSessionsQuery, RecordingUtcSessionsContextError,
    RecordingUtcSessionsContextLimits, RecordingUtcSessionsContextRequest,
    query_recordings_utc_sessions_in_deployment,
};
use fss_reference::agent_recordings::set::RecordingCatalogPin;
use fss_reference::agent_recordings::utc_sessions::{
    RecordingUtcSessionPin, RecordingUtcSessionsRequest, query_recordings_utc_sessions,
};

struct SessionFixture {
    pin: RecordingUtcSessionPin,
    known: UtcInterval,
    known_admission: u64,
    known_source: ContentDigest,
    known_slot: SlotName,
    unknown_root: ContentDigest,
    unknown_bytes: u64,
    clock_metadata: ContentDigest,
    clock_approval: ContentDigest,
}

struct UtcSessionsFixture {
    base: UtcFixture,
    request: RecordingUtcSessionsContextRequest,
    sessions: Vec<SessionFixture>,
}

// Reconstruct actual AVC pictures under this recording epoch's receiver key. A copied
// manifest with a new generation would not satisfy the native catalog/clock contracts.
fn session_avc_window(
    scope: &CatalogScope,
    ordinal: usize,
    admission: u64,
) -> TestResult<PreparedRecording> {
    use fss_packet::H264Mode;
    use fss_packet::avc::{AvcReceiveLimits, AvcReceiver, parse_pps, parse_sps};
    use fss_reference::rtsp::recording::RecordingPacket;
    use fss_reference::rtsp::recording_collector::{CollectedPicture, RecordingCollector};
    let raw = collector_support::nals();
    let limits = AvcReceiveLimits::default();
    let sps = parse_sps(raw[0], limits.syntax)?;
    let pps = parse_pps(raw[1], &sps, limits.syntax)?;
    let mut key = collector_support::key();
    key.generation = scope.recording.generation;
    let mut receiver = AvcReceiver::new(key, 96, H264Mode::NonInterleaved, limits, (sps, pps))?;
    let sequence = 1 + 2 * ordinal as u64;
    let timestamp = 90_000 + sequence as u32 * 3600;
    receiver.ingest(
        key,
        &collector_support::packet(sequence - 1, timestamp, false, raw[0]),
        0,
    )?;
    let nal = raw
        .iter()
        .find(|nal| nal[0] & 31 == 5)
        .ok_or("IDR fixture")?;
    let bytes = collector_support::packet(sequence, timestamp, true, nal);
    receiver.ingest(key, &bytes, 1)?;
    let mut pictures = collector_support::drain(&mut receiver, 1)?;
    assert_eq!(pictures.len(), 1);
    let mut collector = RecordingCollector::new(
        scope.recording.clone(),
        key,
        96,
        scope.time_scale,
        CollectorLimits::default(),
    )?;
    collector.push_source(
        key,
        RecordingPacket {
            sequence,
            received_ns: admission,
            bytes: &bytes,
        },
        100_000_000,
    )?;
    collector_support::accepted(collector.push_picture(
        CollectedPicture {
            picture: pictures.remove(0),
            timing: collector_support::timing(7200 * ordinal as u64),
        },
        100_000_000,
    ))?;
    collector.seal(100_000_001)?;
    collector
        .take_ready()
        .ok_or_else(|| "missing session AVC recording".into())
}

fn session_hevc_window(
    scope: &CatalogScope,
    ordinal: usize,
    admission: u64,
) -> TestResult<PreparedHevcRecording> {
    use fss_reference::rtsp::recording::hevc::prepare_hevc_recording;
    let mut packets = hevc_recording_support::packets()?;
    for packet in &mut packets {
        packet.received_ns = admission;
    }
    let mut timings = hevc_recording_support::timings(4);
    for timing in &mut timings {
        timing.decode_time += ordinal as u64 * 200_000;
    }
    Ok(prepare_hevc_recording(
        scope.recording.clone(),
        &hevc_recording_support::configuration()?,
        scope.time_scale,
        &timings,
        &hevc_recording_support::borrowed(&packets),
    )?)
}

impl UtcSessionsFixture {
    fn new(tag: &str, codecs: [RecordingQueryCodec; 2]) -> TestResult<Self> {
        let mut base = UtcFixture::new(tag, codecs[0])?;
        let mut sessions = Vec::new();
        let mut all_leaves = BTreeSet::new();
        for (index, codec) in codecs.into_iter().enumerate() {
            let mut scope = base.request.recording.scope.clone();
            scope.recording.sensor = fss_core::SensorId::parse("sensor:utc-session-union")?;
            scope.recording.stream = fss_core::StreamId::parse("stream:utc-session-union")?;
            scope.recording.generation = index as u64 + 1;
            scope.recording.anchor =
                ContentDigest::sha256(format!("session-{index}-source-anchor").as_bytes());
            scope.recording.receive_clock =
                ContentDigest::sha256(format!("session-{index}-receive-clock").as_bytes());
            scope.decode_clock =
                ContentDigest::sha256(format!("session-{index}-decode-clock").as_bytes());
            scope.time_scale = if index == 0 { 90_000 } else { 45_000 };
            let known_admission = 30_000_000 + 40_000_000 * index as u64;
            let mut catalogs = Vec::new();
            let mut known_descriptor = None;
            let mut known_source = None;
            let mut known_slot = None;
            let mut unknown = None;
            for ordinal in 0..2 {
                let slot = SlotName::parse(format!("session-{index}-window-{ordinal}"))?;
                let page_slot = SlotName::parse(format!("session-{index}-page-{ordinal}"))?;
                let admission = known_admission + 15_000_000 * ordinal as u64;
                let (page, metadata, descriptor, root, quote, leaves) = match codec {
                    RecordingQueryCodec::Avc => {
                        let window = session_avc_window(&scope, ordinal, admission)?;
                        publish(&base.base.archive, &slot, window.manifest())?;
                        let leaves = window
                            .children()
                            .into_iter()
                            .map(|(_, digest, _)| digest)
                            .collect::<Vec<_>>();
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
                            leaves,
                        )
                    }
                    RecordingQueryCodec::Hevc => {
                        let window = session_hevc_window(&scope, ordinal, admission)?;
                        publish(&base.base.archive, &slot, window.manifest())?;
                        let leaves = window
                            .publication_plan()
                            .children()
                            .into_iter()
                            .map(|(_, digest, _)| digest)
                            .collect::<Vec<_>>();
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
                            leaves,
                        )
                    }
                };
                publish(&base.base.archive, &page_slot, &page)?;
                put(&base.base.archive, &metadata)?;
                catalogs.push(RecordingCatalogPin {
                    slot: page_slot,
                    root: page.root(),
                });
                if ordinal == 0 {
                    known_source = leaves.first().copied();
                    known_slot = Some(slot);
                    known_descriptor = Some(descriptor);
                } else {
                    unknown = Some((root, quote));
                }
                all_leaves.extend(leaves);
            }
            let clock_codec = match codec {
                RecordingQueryCodec::Avc => RecordingClockCodec::Avc,
                RecordingQueryCodec::Hevc => RecordingClockCodec::Hevc,
            };
            let approval =
                ContentDigest::sha256(format!("session-{index}-clock-approval").as_bytes());
            let clock = RecordingClockIndex::prepare(
                scope.clone(),
                clock_codec,
                approval,
                clock_support::exchange()?,
                clock_support::host(100_000_000),
                &[clock_support::bracket(known_admission)],
                &[known_descriptor.ok_or("known descriptor")?],
            )?;
            let clock_slot = clock_slot(clock_codec, &scope)?;
            publish(&base.base.archive, &clock_slot, clock.manifest())?;
            put(&base.base.archive, clock.index_bytes())?;
            let (unknown_root, unknown_bytes) = unknown.ok_or("unknown window")?;
            sessions.push(SessionFixture {
                pin: RecordingUtcSessionPin {
                    codec,
                    scope,
                    catalogs,
                    clock_slot,
                    clock_root: clock.root(),
                },
                known: clock.windows()[0].utc_interval(),
                known_admission,
                known_source: known_source.ok_or("known source")?,
                known_slot: known_slot.ok_or("known slot")?,
                unknown_root,
                unknown_bytes,
                clock_metadata: ContentDigest::sha256(clock.index_bytes()),
                clock_approval: approval,
            });
        }
        let earliest = sessions
            .iter()
            .map(|session| session.known.earliest_ns)
            .min()
            .ok_or("sessions")?;
        let latest = sessions
            .iter()
            .map(|session| session.known.latest_ns)
            .max()
            .ok_or("sessions")?;
        base.base.source_leaves = all_leaves;
        let request = RecordingUtcSessionsContextRequest {
            principal: base.request.principal.clone(),
            expected_anchor: None,
            recording: RecordingUtcSessionsRequest {
                sessions: sessions.iter().map(|session| session.pin.clone()).collect(),
                interval: earliest..latest + 1,
                max_windows: 32,
                max_hydration_bytes: 256 * 1024 * 1024,
            },
        };
        Ok(Self {
            base,
            request,
            sessions,
        })
    }

    fn sessions_json(&self) -> String {
        let quote = |value: &str| format!("\"{}\"", fss_cli::escape_json_str(value));
        format!("[{}]", self.request.recording.sessions.iter().map(|pin| {
            let catalogs = pin.catalogs.iter().map(|catalog| format!("{{\"slot\":{},\"root\":{}}}",
                quote(catalog.slot.as_str()), quote(&catalog.root.to_text()))).collect::<Vec<_>>().join(",");
            format!("{{\"codec\":{},\"sensor\":{},\"stream\":{},\"generation\":{},\"source_anchor\":{},\"receive_clock\":{},\"decode_clock\":{},\"time_scale\":{},\"catalogs\":[{}],\"clock_slot\":{},\"clock_root\":{}}}",
                quote(pin.codec.as_str()), quote(pin.scope.recording.sensor.as_str()), quote(pin.scope.recording.stream.as_str()),
                quote(&pin.scope.recording.generation.to_string()), quote(&pin.scope.recording.anchor.to_text()),
                quote(&pin.scope.recording.receive_clock.to_text()), quote(&pin.scope.decode_clock.to_text()), pin.scope.time_scale,
                catalogs, quote(pin.clock_slot.as_str()), quote(&pin.clock_root.to_text()))
        }).collect::<Vec<_>>().join(","))
    }

    fn fields(&self) -> Vec<(&'static str, String)> {
        let r = &self.request.recording;
        let mut fields = vec![
            ("target", "recordings".to_owned()),
            ("sessions", self.sessions_json()),
            ("start_utc_ns", r.interval.start.to_string()),
            ("end_utc_ns", r.interval.end.to_string()),
            ("max_windows", r.max_windows.to_string()),
            ("max_hydration_bytes", r.max_hydration_bytes.to_string()),
        ];
        if let Some(anchor) = &self.request.expected_anchor {
            fields.push(("anchor", anchor.as_str().to_owned()));
        }
        fields
    }

    fn run(&self) -> TestResult<(String, ExitIdentity)> {
        self.base
            .run_fields(self.fields(), UtcFixtureMode::Sessions)
    }

    fn mcp(&self) -> TestResult<(String, bool)> {
        let fields = self
            .fields()
            .iter()
            .map(|(key, value)| {
                let value = if matches!(*key, "sessions" | "max_windows") {
                    value.clone()
                } else {
                    format!("\"{}\"", fss_cli::escape_json_str(value))
                };
                format!("\"{key}\":{value}")
            })
            .collect::<Vec<_>>()
            .join(",");
        self.base.mcp_fields(&fields)
    }

    fn query_with(
        &self,
        io: &dyn fss_object::SpoolIo,
        limits: &RecordingUtcSessionsContextLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<DeploymentRecordingUtcSessionsQuery, RecordingUtcSessionsContextError> {
        query_recordings_utc_sessions_in_deployment(
            io,
            &self.base.base.deployment,
            &self.base.base.archive,
            &self.request,
            limits,
            cancelled,
        )
    }

    fn select_unknown_only(&mut self) {
        let after = self
            .sessions
            .iter()
            .map(|session| session.known.latest_ns)
            .max()
            .expect("session fixture")
            + 1;
        self.request.recording.interval = after..after + 10;
    }
}

#[test]
fn utc_sessions_cli_and_mcp_preserve_cross_generation_codecs_clocks_and_protected_context()
-> TestResult {
    for codecs in [
        [RecordingQueryCodec::Avc; 2],
        [RecordingQueryCodec::Hevc; 2],
        [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc],
    ] {
        let mut fixture = UtcSessionsFixture::new("utc-sessions-scope", codecs)?;
        fixture
            .base
            .base
            .publish_hypothesis("event:protected-utc-sessions")?;
        let before = tree(&fixture.base.base.directory)?;
        let limits = RecordingUtcSessionsContextLimits::default();
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let context = fixture.query_with(&io, &limits, &|| false)?;
        let native = query_recordings_utc_sessions(
            &HostSpoolIo,
            &fixture.base.base.archive,
            &fixture.request.recording,
            limits.recording,
            &|| false,
        )?;
        assert_eq!(context.native, native);
        assert_eq!(
            native.request_digest,
            fixture.request.recording.request_digest(limits.recording)?
        );
        assert_eq!(native.sessions.len(), 2);
        assert_eq!(native.scanned_windows, 4);
        assert_eq!(native.unique_windows, 4);
        assert_eq!(native.rows.len(), 4);
        assert_eq!(
            native
                .rows
                .iter()
                .filter(|row| row.row.utc_interval.is_none())
                .count(),
            2
        );
        assert!(io.is_read_only());
        assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
        let (output, exit) = fixture.run()?;
        assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
        assert_eq!(fixture.mcp()?, (output.clone(), false));
        let envelope = parse_json(&output)?;
        assert_eq!(
            text_at(&envelope, &["payload", "coverage", "stopReason"])?,
            "pinned_sessions_catalogs_and_clocks_exhausted"
        );
        let selection = text_at(
            proposition(&envelope, "claim:recordings-utc-sessions:selection")?,
            &["statement"],
        )?;
        assert!(selection.contains("sessions=2") && selection.contains("returned_windows=4"));
        assert_eq!(
            text_at(
                proposition(
                    &envelope,
                    "claim:recordings-utc-sessions:physical-observability"
                )?,
                &["state"]
            )?,
            "unknown"
        );
        assert!(output.contains("event:protected-utc-sessions"));
        for (session_index, session) in native.sessions.iter().enumerate() {
            let fixture_session = fixture
                .sessions
                .iter()
                .find(|entry| entry.pin.scope == session.scope)
                .ok_or("session provenance")?;
            assert_eq!(
                session.session_digest,
                fixture_session.pin.session_digest()?
            );
            assert_eq!(
                session.clock_approval_digest,
                fixture_session.clock_approval
            );
            assert_eq!(
                session.clock_metadata_digest,
                fixture_session.clock_metadata
            );
            assert_eq!(session.clock_windows, 1);
            let scope = text_at(
                proposition(
                    &envelope,
                    &format!("claim:recordings-utc-sessions:session:{session_index}"),
                )?,
                &["statement"],
            )?;
            for exact in [
                session.scope.recording.anchor.to_text(),
                session.scope.recording.receive_clock.to_text(),
                session.scope.decode_clock.to_text(),
            ] {
                assert!(scope.contains(&exact));
            }
            let clock = text_at(
                proposition(
                    &envelope,
                    &format!("claim:recordings-utc-sessions:session:{session_index}:clock"),
                )?,
                &["statement"],
            )?;
            assert!(clock.contains(&fixture_session.clock_approval.to_text()));
        }
        for (index, row) in native.rows.iter().enumerate() {
            assert_eq!(
                row.session_digest,
                native.sessions[row.session_index].session_digest
            );
            let state = if row.row.utc_interval.is_some() {
                "known"
            } else {
                "not_observable"
            };
            assert_eq!(
                text_at(
                    proposition(
                        &envelope,
                        &format!("claim:recordings-utc-sessions:window:{index}")
                    )?,
                    &["state"]
                )?,
                state
            );
        }
        let handles = at(&envelope, &["payload", "evidenceHandles"])?
            .array()
            .ok_or("handles")?;
        assert_eq!(handles.len(), 10);
        for handle in handles {
            assert_eq!(text_at(handle, &["hydration"])?, "H0");
            assert_eq!(
                at(handle, &["allowedHydration"])?
                    .array()
                    .ok_or("hydration")?,
                &[Value::Text("H0".to_owned())]
            );
        }
        let orientation = orient_deployment(
            &context.snapshot,
            &OrientRequest {
                view: AgentView::Brief,
                principal: fixture.request.principal.clone(),
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
        fixture.request.recording.sessions.reverse();
        for session in &mut fixture.request.recording.sessions {
            session.catalogs.reverse();
        }
        assert_eq!(fixture.run()?, (output.clone(), exit));
        assert_eq!(fixture.mcp()?, (output, false));
        for leaf in &fixture.base.base.source_leaves {
            assert!(!object_path(&fixture.base.base.archive, *leaf).exists());
        }
        assert_eq!(tree(&fixture.base.base.directory)?, before);
    }
    Ok(())
}

#[test]
fn utc_sessions_keep_each_scope_gap_and_every_unknown_window_under_narrow_selection() -> TestResult
{
    let mut fixture =
        UtcSessionsFixture::new("utc-sessions-unknown", [RecordingQueryCodec::Avc; 2])?;
    let limits = RecordingUtcSessionsContextLimits::default();
    assert!(fixture.sessions[0].known.latest_ns < fixture.sessions[1].known.earliest_ns);
    let point = fixture.sessions[0].known.earliest_ns;
    fixture.request.recording.interval = point..point + 1;
    let native = fixture.query_with(&HostSpoolIo, &limits, &|| false)?.native;
    assert_eq!(native.rows.len(), 3);
    assert!(native.indexed_gaps.is_empty());
    let session_index = native
        .sessions
        .iter()
        .position(|session| session.scope.recording.generation == 2)
        .ok_or("second epoch")?;
    assert_eq!(
        native.sessions[session_index].indexed_gaps,
        vec![point..point + 1]
    );
    let (output, exit) = fixture.run()?;
    assert_eq!(exit, ExitIdentity::SUCCESS);
    assert_eq!(fixture.mcp()?, (output.clone(), false));
    let envelope = parse_json(&output)?;
    let gap = proposition(
        &envelope,
        &format!("claim:recordings-utc-sessions:session:{session_index}:indexed-gap:0"),
    )?;
    assert_eq!(text_at(gap, &["state"])?, "not_observable");
    assert!(proposition(&envelope, "claim:recordings-utc-sessions:indexed-gap:0").is_err());

    fixture.select_unknown_only();
    fixture.request.recording.max_windows = 2;
    fixture.request.recording.max_hydration_bytes = fixture
        .sessions
        .iter()
        .map(|session| session.unknown_bytes)
        .sum();
    let query = fixture.query_with(&HostSpoolIo, &limits, &|| false)?;
    assert_eq!(query.native.rows.len(), 2);
    assert!(
        query
            .native
            .rows
            .iter()
            .all(|row| row.row.utc_interval.is_none())
    );
    assert_eq!(
        query.native.quoted_hydration_bytes,
        fixture.request.recording.max_hydration_bytes
    );
    assert_eq!(query.selected_catalog_indexes().len(), 2);
    for session in &fixture.sessions {
        assert!(
            query
                .native
                .rows
                .iter()
                .any(|row| row.row.entry.root() == session.unknown_root)
        );
        assert!(
            query
                .native
                .reference_digests
                .contains(&session.known_source)
        );
    }
    let (output, exit) = fixture.run()?;
    assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
    assert_eq!(fixture.mcp()?, (output.clone(), false));
    let envelope = parse_json(&output)?;
    assert_eq!(
        at(&envelope, &["payload", "evidenceHandles"])?
            .array()
            .ok_or("handles")?
            .len(),
        6
    );
    for session_index in 0..2 {
        assert!(
            proposition(
                &envelope,
                &format!("claim:recordings-utc-sessions:session:{session_index}:catalog:0")
            )
            .is_err()
        );
        assert!(
            proposition(
                &envelope,
                &format!("claim:recordings-utc-sessions:session:{session_index}:catalog:1")
            )
            .is_ok()
        );
        assert_eq!(
            text_at(
                proposition(
                    &envelope,
                    &format!("claim:recordings-utc-sessions:session:{session_index}:indexed-gap:0")
                )?,
                &["state"]
            )?,
            "not_observable"
        );
    }
    Ok(())
}

#[test]
fn utc_sessions_refuse_aggregate_output_hydration_and_metadata_exhaustion_atomically() -> TestResult
{
    let mut fixture =
        UtcSessionsFixture::new("utc-sessions-budget", [RecordingQueryCodec::Avc; 2])?;
    let limits = RecordingUtcSessionsContextLimits::default();
    let baseline = fixture.query_with(&HostSpoolIo, &limits, &|| false)?;
    let before = tree(&fixture.base.base.directory)?;
    for (windows, bytes) in [
        (3, 256 * 1024 * 1024),
        (32, baseline.native.quoted_hydration_bytes - 1),
    ] {
        fixture.request.recording.max_windows = windows;
        fixture.request.recording.max_hydration_bytes = bytes;
        let (output, exit) = fixture.run()?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{output}");
        assert!(!output.contains("claim:recordings-utc-sessions:selection"));
        assert_eq!(fixture.mcp()?, (output, true));
    }
    fixture.request.recording.max_windows = 32;
    fixture.request.recording.max_hydration_bytes = 256 * 1024 * 1024;
    let mut one = fixture.request.recording.clone();
    one.sessions.truncate(1);
    let single = query_recordings_utc_sessions(
        &HostSpoolIo,
        &fixture.base.base.archive,
        &one,
        limits.recording,
        &|| false,
    )?;
    assert!(single.read_usage.io_calls < baseline.native.read_usage.io_calls);
    for (dimension, mut lowered) in [limits; 3].into_iter().enumerate() {
        match dimension {
            0 => lowered.recording.max_scanned_windows = 3,
            1 => lowered.recording.metadata.max_io_calls = single.read_usage.io_calls,
            _ => {
                lowered.recording.metadata.max_objects =
                    baseline.native.read_usage.metadata_objects - 1
            }
        }
        assert!(
            fixture
                .query_with(&HostSpoolIo, &lowered, &|| false)
                .is_err()
        );
    }
    assert_eq!(tree(&fixture.base.base.directory)?, before);
    Ok(())
}

#[test]
fn utc_sessions_never_skip_an_unavailable_clock_or_damaged_unselected_session() -> TestResult {
    for defect in [
        "clock-object",
        "clock-binding",
        "unselected-catalog",
        "unselected-source-tombstone",
    ] {
        let mut fixture = UtcSessionsFixture::new(defect, [RecordingQueryCodec::Avc; 2])?;
        fixture.select_unknown_only();
        let second = &fixture.sessions[1];
        match defect {
            "clock-object" => fs::write(
                object_path(&fixture.base.base.archive, second.clock_metadata),
                b"damaged retained clock",
            )?,
            "clock-binding" => fs::remove_file(
                fixture
                    .base
                    .base
                    .archive
                    .join("roots")
                    .join(format!("{}.root", second.pin.clock_slot.as_str())),
            )?,
            "unselected-catalog" => fs::remove_file(
                fixture
                    .base
                    .base
                    .archive
                    .join("roots")
                    .join(format!("{}.root", second.pin.catalogs[0].slot.as_str())),
            )?,
            _ => fs::write(
                fixture.base.base.archive.join("tombstones").join(format!(
                    "{}.tomb",
                    second.known_source.to_text().replacen(':', "-", 1)
                )),
                b"deletion present",
            )?,
        }
        let before = tree(&fixture.base.base.directory)?;
        let (output, exit) = fixture.run()?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{defect}: {output}");
        assert!(!output.contains("claim:recordings-utc-sessions:selection"));
        assert_eq!(fixture.mcp()?, (output, true));
        assert_eq!(tree(&fixture.base.base.directory)?, before);
    }
    Ok(())
}

#[test]
fn utc_sessions_current_deletion_denies_an_unselected_source_in_another_capture_epoch() -> TestResult
{
    use fss_geometry::WorkBudget;
    use fss_object::SpoolLimits;
    use fss_publication::{LocalPublicationLimits, LocalRootPublisher};
    use fss_reference::deletion::{CommitOutcome, commit_deletion, plan_deletion};
    use fss_reference::ingest::rtsp_import::{
        RtspImportAuthority, RtspImportCodec, RtspImportRequest, import_rtsp,
    };
    let mut fixture = UtcSessionsFixture::new(
        "utc-sessions-current-deletion",
        [RecordingQueryCodec::Avc; 2],
    )?;
    fixture.select_unknown_only();
    let second = &fixture.sessions[1];
    let recording = session_avc_window(&second.pin.scope, 0, second.known_admission)?;
    let source_digest = second.known_source;
    assert!(
        recording
            .children()
            .into_iter()
            .any(|(_, digest, _)| digest == source_digest)
    );
    let slot = second.known_slot.clone();
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
    let principal = "principal:utc-sessions-delete";
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:utc-sessions-delete".to_owned(),
        operation_id: OperationId::parse("operation:utc-sessions-delete")?,
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
    let limits = RecordingUtcSessionsContextLimits::default();
    let initial = fixture.query_with(&HostSpoolIo, &limits, &|| false)?;
    assert_eq!(initial.native.rows.len(), 2);
    assert!(
        initial
            .native
            .rows
            .iter()
            .all(|row| row.row.utc_interval.is_none())
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
    let native = query_recordings_utc_sessions(
        &HostSpoolIo,
        &fixture.base.base.archive,
        &fixture.request.recording,
        limits.recording,
        &|| false,
    )?;
    assert_eq!(native.rows, initial.native.rows);
    assert_eq!(native.reference_digests, initial.native.reference_digests);
    let before = tree(&fixture.base.base.directory)?;
    assert!(matches!(
        fixture.query_with(&HostSpoolIo, &limits, &|| false),
        Err(RecordingUtcSessionsContextError::AnchorChanged)
    ));
    let (output, exit) = fixture.run()?;
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert_eq!(fixture.mcp()?, (output, true));
    assert_eq!(tree(&fixture.base.base.directory)?, before);
    Ok(())
}
