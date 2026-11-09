#![forbid(unsafe_code)]
//! Actual CLI preview/approval/revalidation and cold native review of a selected window.

use super::*;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_catalog::hevc::local::HevcCatalogPublication;
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::local::CatalogProgress;
use fss_reference::{ReferenceDeployment, ReplayCx};

fn context(root: &std::path::Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:query-import-cli-fixture".into(),
        operation_id: OperationId::parse("operation:query-import-cli-fixture")?,
        principal: "principal:query-import-fixture".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "CAP-READ-MEDIA-001".into(),
            "CAP-OBJECT-STAGE-001".into(),
            "CAP-OBJECT-PUBLISH-001".into(),
            "CAP-RETENTION-COMMIT-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(b"site:rtsp-import-cli"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn source_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16,
        64,
        16,
        256,
        SpoolLimits::new(256, 32 * 1024 * 1024, 1024 * 1024, 256),
    )
}

fn catalog(
    directory: &Directory,
    first: &PreparedHevcRecording,
) -> Test<(ContentDigest, ContentDigest, ContentDigest)> {
    publish(directory, first)?;
    let mut packets = hevc_recording_support::packets()?;
    for packet in &mut packets {
        packet.sequence += 32;
        packet.received_ns += 32;
        packet.bytes[2..4].copy_from_slice(&(packet.sequence as u16).to_be_bytes());
        let time = u32::from_be_bytes(packet.bytes[4..8].try_into()?);
        packet.bytes[4..8].copy_from_slice(&(time + 144000).to_be_bytes());
    }
    let mut timings = hevc_recording_support::timings(4);
    for timing in &mut timings {
        timing.decode_time += 144000;
    }
    let second = hevc_recording_support::prepare(&packets, &timings)?;
    let first_slot = SlotName::parse("hevc-recording-cli")?;
    let second_slot = SlotName::parse("hevc-recording-unselected")?;
    let clock = ContentDigest::sha256(b"query-import-explicit-decode-clock");
    let catalog = prepare_hevc_catalog(
        CatalogScope {
            recording: first.summary().scope.clone(),
            decode_clock: clock,
            time_scale: first.summary().time_scale,
        },
        &[
            HevcCatalogWindow {
                slot: &first_slot,
                recording: first,
            },
            HevcCatalogWindow {
                slot: &second_slot,
                recording: &second,
            },
        ],
    )?;
    let mut source = LocalRootPublisher::open(directory.0.join("source archive"), source_limits())?;
    {
        let mut publication = RecordingPublication::new(
            second.publication_plan(),
            &mut source,
            second_slot,
            second.byte_len(),
            100,
        )?;
        let mut published = false;
        for now in 0..5 {
            if matches!(
                publication.step(now, &NeverCancel)?,
                RecordingProgress::Published(_)
            ) {
                published = true;
                break;
            }
        }
        assert!(published);
    }
    let mut publication = HevcCatalogPublication::new(
        &catalog,
        &mut source,
        SlotName::parse("query-catalog")?,
        catalog.byte_len(),
        100,
    )?;
    let mut published = false;
    for now in 0..8 {
        if matches!(
            publication.step(now, &NeverCancel)?,
            CatalogProgress::Published(_)
        ) {
            published = true;
            break;
        }
    }
    assert!(published);
    Ok((catalog.manifest().root(), clock, second.manifest().root()))
}

#[test]
fn selected_query_import_reapproves_current_state_and_reuses_closed_native_windows() -> Test {
    let directory = Directory::new()?;
    let first = hevc_recording_support::fixture()?;
    let (catalog_root, clock, unselected_root) = catalog(&directory, &first)?;
    let root = directory.0.join("destination");
    let archive = directory.0.join("source archive");
    let cx = context(&root)?;
    drop(ReferenceDeployment::open(
        &root,
        "site:rtsp-import-cli",
        &cx,
    )?);
    cx.drain_and_finalize();
    let snapshot = || -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(root.join("ledger/journal.fssj"))?,
            fs::read(root.join("effects/journal.fssj"))?,
        ))
    };
    let before = snapshot()?;
    let mut args = arguments(&directory, &first)?;
    for (old, new, value) in [
        (
            "--window-slot",
            "--catalog-slot",
            "query-catalog".to_owned(),
        ),
        ("--window-root", "--catalog-root", catalog_root.to_text()),
    ] {
        let index = args
            .iter()
            .position(|arg| arg == old)
            .ok_or("fixture selector")?;
        args[index] = new.into();
        args[index + 1] = value.into();
    }
    args.insert(0, "query".into());
    args.extend([
        "--decode-clock".into(),
        clock.to_text().into(),
        "--time-scale".into(),
        "90000".into(),
        "--decode-start".into(),
        "50000".into(),
        "--decode-end".into(),
        "100000".into(),
    ]);
    // A held writer lock does not prevent bounded read-only metadata preview.
    let source = LocalRootPublisher::open(&archive, source_limits())?;
    let preview = good(run(&args)?)?;
    assert!(preview.contains("\"source_media_reads\":0"));
    assert!(preview.contains("\"scanned_windows\":2"));
    assert!(preview.contains("\"selected_frames\":4"));
    assert!(preview.contains("\"indexed_gaps\":[{\"start\":\"72000\",\"end\":\"100000\"}]"));
    assert_eq!(snapshot()?, before);
    let mut wrong = args.clone();
    wrong.extend([
        "--approve".into(),
        ContentDigest::sha256(b"wrong-query-approval")
            .to_text()
            .into(),
    ]);
    let refusal = run(&wrong)?;
    assert!(!refusal.status.success());
    assert!(String::from_utf8_lossy(&refusal.stderr).contains("ERR-RTSP-IMPORT-APPROVAL-001"));
    assert_eq!(snapshot()?, before);
    drop(source);

    let mut approved = args.clone();
    approved.extend([
        "--approve".into(),
        field(&preview, "approval_digest")?.into(),
    ]);
    let result = good(run(&approved)?)?;
    assert!(result.contains("\"complete\":true"));
    assert!(result.contains("\"completed_imports\":1"));
    assert!(result.contains("\"capture_time_label\":\"unknown\""));
    assert!(result.contains("\"destination_contains_complete_catalog\":false"));
    let identity = field(&result, "import_identity")?.to_owned();
    let stored = root.join("objects/spool/objects");
    assert!(
        !stored
            .join(unselected_root.to_text().trim_start_matches("sha256:"))
            .exists()
    );
    assert!(
        !stored
            .join(catalog_root.to_text().trim_start_matches("sha256:"))
            .exists()
    );
    let committed = snapshot()?;
    let stale = run(&approved)?;
    assert!(
        !stale.status.success(),
        "old deployment approval was replayed after mutation"
    );
    assert!(String::from_utf8_lossy(&stale.stderr).contains("ERR-RTSP-IMPORT-APPROVAL-001"));
    assert_eq!(snapshot()?, committed);

    let fresh = good(run(&args)?)?;
    approved.pop();
    approved.push(field(&fresh, "approval_digest")?.into());
    let reused = good(run(&approved)?)?;
    assert!(reused.contains("\"reused\":true"));
    assert_eq!(field(&reused, "import_identity")?, identity);
    assert_eq!(snapshot()?, committed);
    fs::rename(&archive, directory.0.join("offline archive"))?;
    let verified = good(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .args(["verify", "--root"])
            .arg(&root)
            .args(["--site", "site:rtsp-import-cli", "--import-id", &identity])
            .output()?,
    )?;
    assert!(verified.contains("segment_count=4"));
    assert!(verified.contains("capture_time_class=unknown"));
    assert_eq!(
        snapshot()?.1,
        before.1,
        "query acquisition changed external-effect state"
    );
    Ok(())
}
