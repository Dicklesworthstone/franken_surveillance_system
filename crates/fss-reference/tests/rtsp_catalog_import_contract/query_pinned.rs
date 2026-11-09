#![forbid(unsafe_code)]
//! Pinned source retrieval preserves native identities while excluding unrelated archive bytes.

use super::*;
use fss_publication::custody_audit::pinned_closure::PinnedClosureReader;
use fss_reference::ingest::rtsp_import::query::import_rtsp_query_pinned;

#[test]
fn pinned_source_reuses_legacy_child_with_writer_lock_held_and_unselected_corruption() -> Test {
    let mut f = Fixture::avc("query-pinned-parity", 4, 0, false)?;
    let plan = preview(&f, 14_400..14_401)?;
    let original = acquire(&mut f, &plan)?;
    let fresh = preview(&f, 14_400..14_401)?;
    // Retain the archive's already-open writer, but make an unselected payload unreadable.
    let unselected = f.original_packs[0];
    fs::write(
        f.directory
            .0
            .join("archive/spool/objects")
            .join(unselected.to_text().trim_start_matches("sha256:")),
        b"corrupt unselected source",
    )?;
    let before_source = integrity::snapshot(&f.directory.0.join("archive"))?;
    let before_target = integrity::snapshot(&f.directory.0.join("destination"))?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader =
        PinnedClosureReader::new(&io, fresh.archive_root(), fresh.source_limits(), &|| false)?;
    let receipt = import_rtsp_query_pinned(
        &io,
        &mut reader,
        f.target.as_mut().ok_or("destination")?,
        &fresh,
        &Owner(Cell::new(true)),
        &f.cx,
        &mut work(),
        &|| false,
    )?;
    assert_eq!(receipt.imports.len(), 1);
    assert_eq!(
        receipt.imports[0].import.import_identity,
        original.imports[0].import.import_identity
    );
    assert_eq!(
        receipt.imports[0].import.import_root,
        original.imports[0].import.import_root
    );
    assert_eq!(
        receipt.imports[0].import.proof,
        original.imports[0].import.proof
    );
    assert!(receipt.imports[0].import.reused);
    let usage = reader.finish()?;
    assert_eq!(usage.completed_roots, 1);
    assert_eq!(usage.objects, 5);
    assert_eq!(usage.edges, 4);
    assert!(io.is_read_only());
    assert_eq!(io.call_count(fss_object::SpoolIoCall::ReadDir), 0);
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("archive"))?,
        before_source
    );
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("destination"))?,
        before_target
    );
    Ok(())
}

#[test]
fn one_pinned_reader_accounts_for_every_selected_window_without_refilling() -> Test {
    let mut f = Fixture::hevc("query-pinned-union")?;
    let plan = preview(&f, 0..144_000)?;
    assert_eq!(plan.windows().len(), 2);
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader =
        PinnedClosureReader::new(&io, plan.archive_root(), plan.source_limits(), &|| false)?;
    let receipt = import_rtsp_query_pinned(
        &io,
        &mut reader,
        f.target.as_mut().ok_or("destination")?,
        &plan,
        &Owner(Cell::new(true)),
        &f.cx,
        &mut work(),
        &|| false,
    )?;
    assert_eq!(receipt.imports.len(), 2);
    let usage = reader.finish()?;
    assert_eq!(usage.completed_roots, 2);
    assert_eq!(usage.objects, 10);
    assert_eq!(usage.edges, 8);
    assert!(usage.read_bytes >= plan.original_bytes() * 2);
    assert!(usage.read_bytes <= plan.source_limits().max_read_bytes);
    assert!(usage.io_calls <= plan.source_limits().max_io_calls);
    assert!(receipt.work_used >= 6 * fss_reference::ingest::rtsp_import::MAX_ORIGINAL_BYTES);
    assert!(io.is_read_only());
    Ok(())
}
