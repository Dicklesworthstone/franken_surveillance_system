#![forbid(unsafe_code)]
//! Native archive and deployment owners exercise the complete approved operator path.

#[path = "../../../../fss-reference/tests/rtsp_selected_watch_contract/fixture.rs"]
mod fixture;

use std::fs;

use fss_reference::ingest::rtsp_selected_watch::RtspWatchSelection;

use super::*;

fn request_arguments(
    fixture: &fixture::Fixture,
    selection: &RtspWatchSelection,
) -> Test<Vec<String>> {
    let scope = selection.source();
    let origin = selection.capture_origin().ok_or("capture origin")?;
    let (received, original, media) = match selection {
        RtspWatchSelection::Window(r) => (r.receive_time, r.max_original_bytes, r.max_media_bytes),
        RtspWatchSelection::Catalog(r) => (r.receive_time, r.max_original_bytes, r.max_media_bytes),
        RtspWatchSelection::Pages(r) => (r.receive_time, r.max_original_bytes, r.max_media_bytes),
    };
    let mut args = Vec::new();
    for (key, value) in [
        (
            "--archive",
            fixture.directory.0.join("archive").display().to_string(),
        ),
        (
            "--root",
            fixture
                .directory
                .0
                .join("destination")
                .display()
                .to_string(),
        ),
        ("--site", fixture::SITE.into()),
        ("--principal", fixture::PRINCIPAL.into()),
        ("--codec", selection.codec().as_str().into()),
        ("--sensor-id", scope.sensor.as_str().into()),
        ("--stream-id", scope.stream.as_str().into()),
        ("--generation", scope.generation.to_string()),
        ("--anchor", scope.anchor.to_text()),
        ("--receive-clock", scope.receive_clock.to_text()),
        ("--receive-time-ns", received.0.to_string()),
        ("--capture-start-ns", origin.start_ns.0.to_string()),
        (
            "--capture-uncertainty-ns",
            origin.uncertainty_ns.to_string(),
        ),
        ("--max-frames", selection.maximum_frames().to_string()),
        ("--max-original-bytes", original.to_string()),
        ("--max-media-bytes", media.to_string()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
    ] {
        args.extend([key.into(), value]);
    }
    match selection {
        RtspWatchSelection::Window(r) => args.extend([
            "--window-slot".into(),
            r.slot.as_str().into(),
            "--window-root".into(),
            r.root.to_text(),
        ]),
        RtspWatchSelection::Catalog(r) => args.extend([
            "--catalog-slot".into(),
            r.slot.as_str().into(),
            "--catalog-root".into(),
            r.root.to_text(),
            "--decode-clock".into(),
            r.scope.decode_clock.to_text(),
            "--time-scale".into(),
            r.scope.time_scale.to_string(),
            "--max-windows".into(),
            r.max_windows.to_string(),
        ]),
        RtspWatchSelection::Pages(r) => args.extend([
            "--catalog-pages".into(),
            r.pages
                .iter()
                .map(|page| format!("{}@{}", page.slot.as_str(), page.root.to_text()))
                .collect::<Vec<_>>()
                .join(","),
            "--decode-clock".into(),
            r.scope.decode_clock.to_text(),
            "--time-scale".into(),
            r.scope.time_scale.to_string(),
            "--max-windows".into(),
            r.max_windows.to_string(),
            "--max-pages".into(),
            r.max_pages.to_string(),
        ]),
    }
    Ok(args)
}

#[test]
fn approved_window_catalog_pages_and_hevc_execute_native_watch_and_reconcile_without_effects()
-> Test {
    let mut fixture = fixture::Fixture::new("operator-native", 2)?;
    let requests = fixture
        .plan
        .selections
        .iter()
        .map(|selection| request_arguments(&fixture, selection))
        .collect::<Test<Vec<_>>>()?;
    let root = fixture.directory.0.join("destination");
    let initial_ledger = fs::read(root.join("ledger/journal.fssj"))?;
    let initial_effects = fs::read(root.join("effects/journal.fssj"))?;
    drop(fixture.source.take());
    drop(fixture.target.take());
    fixture.cx.drain_and_finalize();
    let mut input = args(&requests);
    input.extend(["--max-work".into(), fixture::WORK.to_string().into()]);
    let mut options = plan::Options::parse(&input)?;
    let approval = options.approval()?;
    assert!(options.preview()?.contains("\"selections\":4"));
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, initial_ledger);
    options.approve = Some(ContentDigest::sha256(b"wrong-outer-approval"));
    assert_eq!(
        driver::execute(&options),
        Err("ERR-RTSP-SELECTED-WATCH-AUTHORITY-001")
    );
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, initial_ledger);
    options.approve = Some(approval);
    let first = parse(&driver::execute(&options)?)?;
    assert_eq!(
        field(&first, "format")?.text(),
        Some("fss.rtsp_selected_watch_report.v1")
    );
    assert_eq!(
        field(field(&first, "reservation")?, "screening_pixel_samples")?.integer(),
        Some(0)
    );
    for name in [
        "campaign_history_verified",
        "complete_campaign",
        "empty_attempt_coverage",
        "tracker_continuity_across_selections",
        "event_publication_authorized",
        "absence_certifiable",
        "alert_authorized",
        "network_resumed",
    ] {
        assert_eq!(field(&first, name)?.boolean(), Some(false), "{name}");
    }
    let rows = field(&first, "selections")?
        .array()
        .ok_or("selection rows")?;
    assert_eq!(rows.len(), 4);
    let mut identities = Vec::new();
    let mut analyses = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(
            field(row, "kind")?.text(),
            Some(["window", "catalog", "pages", "window"][index])
        );
        let import = field(row, "import")?;
        let watch = field(row, "watch")?;
        let frames = field(import, "frames")?.integer().ok_or("frames")?;
        if index < 3 {
            assert_eq!(frames, [2, 4, 6][index]);
        }
        assert!(frames > 0);
        assert_eq!(field(watch, "frames_decoded")?.integer(), Some(frames));
        assert_eq!(field(watch, "segment_count")?.integer(), Some(frames));
        assert_eq!(field(watch, "first_segment")?.integer(), Some(0));
        assert_eq!(
            field(watch, "analysis_basis_sequence")?,
            field(&first, "analysis_basis_sequence")?
        );
        assert_eq!(field(import, "reused")?.boolean(), Some(false));
        identities.push(
            field(import, "identity")?
                .text()
                .ok_or("identity")?
                .to_owned(),
        );
        analyses.push(
            field(watch, "analysis_digest")?
                .text()
                .ok_or("analysis digest")?
                .to_owned(),
        );
    }
    assert_eq!(
        identities
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
    let ledger = fs::read(root.join("ledger/journal.fssj"))?;
    assert_ne!(ledger, initial_ledger);
    assert_eq!(
        fs::read(root.join("effects/journal.fssj"))?,
        initial_effects
    );
    let retried = parse(&driver::execute(&options)?)?;
    let rows = field(&retried, "selections")?.array().ok_or("retry rows")?;
    for (index, row) in rows.iter().enumerate() {
        let import = field(row, "import")?;
        assert_eq!(field(import, "reused")?.boolean(), Some(true));
        assert_eq!(
            field(import, "identity")?.text(),
            Some(identities[index].as_str())
        );
        assert_eq!(
            field(field(row, "watch")?, "analysis_digest")?.text(),
            Some(analyses[index].as_str())
        );
    }
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(
        fs::read(root.join("effects/journal.fssj"))?,
        initial_effects
    );

    // Missing source refusal precedes destination creation, even after exact approval.
    let absent_target = fixture.directory.0.join("must-not-be-created");
    let mut missing = requests;
    for request in &mut missing {
        set(
            request,
            "--archive",
            &fixture
                .directory
                .0
                .join("not-an-archive")
                .display()
                .to_string(),
        );
        set(request, "--root", &absent_target.display().to_string());
    }
    let mut missing = plan::Options::parse(&args(&missing))?;
    missing.approve = Some(missing.approval()?);
    assert_eq!(driver::execute(&missing), Err("ERR-RTSP-IMPORT-SOURCE-001"));
    assert!(!absent_target.exists());
    Ok(())
}
