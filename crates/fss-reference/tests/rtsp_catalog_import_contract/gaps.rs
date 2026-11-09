#![forbid(unsafe_code)]
//! Explicit interrupted-archive admission keeps gap, custody and decoder boundaries on cold reads.

use super::*;
use fss_reference::ingest::recorded_decode::{RecordedDecodeError, retained_source_capsule};
use fss_reference::ingest::rtsp_import::gaps::{
    ADAPTER as GAP_ADAPTER, RtspGappedCatalogImportAuthority, RtspGappedCatalogImportReceipt,
    RtspGappedCatalogImportRequest, import_rtsp_gapped_catalog,
};

impl RtspGappedCatalogImportAuthority for Owner {
    fn permit(
        &self,
        _: &RtspGappedCatalogImportRequest,
        destination: &ReferenceDeployment,
    ) -> bool {
        self.0.get() && destination.site_lineage() == SITE
    }
}

fn run(
    f: &mut Fixture,
    request: &RtspGappedCatalogImportRequest,
) -> Test<RtspGappedCatalogImportReceipt> {
    Ok(import_rtsp_gapped_catalog(
        f.source.as_ref().ok_or("source")?,
        f.target.as_mut().ok_or("target")?,
        request,
        &Owner(Cell::new(true)),
        &f.cx,
        &mut work(),
    )?)
}

fn fixture(label: &str, pages: bool, gap: u64) -> Test<(Fixture, RtspGappedCatalogImportRequest)> {
    if pages {
        let (f, request) = avc_pages(label, 0, gap, false)?;
        Ok((f, RtspGappedCatalogImportRequest::Pages(request)))
    } else {
        let f = Fixture::avc(label, 4, gap, false)?;
        let request = RtspGappedCatalogImportRequest::Catalog(f.request.clone());
        Ok((f, request))
    }
}

fn assert_gap(report: &RetainedMovieSelection, expected: Range<u64>) {
    assert_eq!(report.selection.gaps.len(), 1);
    assert_eq!(report.selection.gaps[0].kind, MovieGapKind::Unrepresented);
    assert_eq!(
        report.selection.gaps[0].interval,
        interval(expected.start, expected.end)
    );
}

#[test]
fn explicit_gap_profile_preserves_native_time_and_cold_decoder_boundaries() -> Test {
    for pages in [false, true] {
        let (mut f, request) = fixture(&format!("gapped-cold-{pages}"), pages, 7_200)?;
        let before = integrity::snapshot(&f.directory.0.join("destination"))?;
        let strict = match &request {
            RtspGappedCatalogImportRequest::Catalog(_) => f.run(),
            RtspGappedCatalogImportRequest::Pages(request) => run_pages(&mut f, request),
        };
        assert!(
            strict.is_err(),
            "the original continuous profile admitted a gap"
        );
        assert_eq!(
            integrity::snapshot(&f.directory.0.join("destination"))?,
            before
        );
        let receipt = run(&mut f, &request)?;
        assert_eq!(receipt.pages, if pages { 2 } else { 1 });
        assert_eq!(receipt.decode_gaps, [14_400..21_600]);
        assert_eq!(receipt.catalog.decode_interval, 0..36_000);
        assert_eq!(receipt.catalog.import.frames, 8);
        f.verify_fragment_remux(&receipt.catalog)?;
        let retained = f.retained(&receipt.catalog)?;
        for (index, span) in retained.manifest().segment_spans.iter().enumerate() {
            assert_eq!(span.gap_before, index == 4);
            let capsule = retained_source_capsule(f.target()?, &retained, index)?;
            assert_eq!(capsule.gap_before, index == 4);
            let ticks = index as i128 * 3_600 + if index >= 4 { 7_200 } else { 0 };
            assert_eq!(
                capsule.capture.earliest.0,
                1_000_000_000 + ticks * 1_000_000_000 / 90_000 - 10
            );
        }
        assert!(
            retained
                .manifest()
                .validate_retained(RetainedReadLimits::default())
                .is_err()
        );
        assert!(
            FileIngestAdapter::fetch_segment_bytes(retained.manifest(), f.target()?, 0).is_err()
        );
        assert!(matches!(
            RecordedH264Range::open(
                f.target()?,
                RecordedH264Request {
                    import_identity: receipt.catalog.import.import_identity,
                    first_segment: 0,
                    segment_count: 8,
                    interpretation: ComponentInterpretation::YCbCr,
                    read_limits: RetainedReadLimits::default(),
                    decoder_limits: AvcLimits::default(),
                },
                &f.cx,
            ),
            Err(RecordedDecodeError::H264SourceGap { segment: 4 })
        ));

        drop(f.source.take());
        fs::rename(
            f.directory.0.join("archive"),
            f.directory.0.join("offline-archive"),
        )?;
        drop(f.target.take());
        f.cx = context(&f.directory.0.join("destination"))?;
        f.target = Some(ReferenceDeployment::open(
            &f.directory.0.join("destination"),
            SITE,
            &f.cx,
        )?);
        let retained = f.retained(&receipt.catalog)?;
        let before = integrity::snapshot(&f.directory.0.join("destination"))?;
        let report = select(&f, &retained, 12_600..23_400, origin_allowance(&f), &f.cx)?;
        assert_binding(&f, &receipt.catalog, &retained, &report, GAP_ADAPTER)?;
        assert_gap(&report, 14_400..21_600);
        assert_eq!(report.selection.samples.len(), 2);
        assert_eq!(report.selection.samples[0].sample_index, 3);
        assert_eq!(
            report.selection.samples[0].interval,
            interval(12_600, 14_400)
        );
        assert_eq!(report.selection.samples[1].sample_index, 4);
        assert_eq!(
            report.selection.samples[1].interval,
            interval(21_600, 23_400)
        );
        assert_eq!(report.selection.decode_spans.len(), 2);
        drain_spans(&f, &report)?;
        let gap_only = select(&f, &retained, 16_000..18_000, origin_allowance(&f), &f.cx)?;
        assert_gap(&gap_only, 16_000..18_000);
        assert!(gap_only.selection.samples.is_empty());
        assert!(gap_only.selection.decode_spans.is_empty());
        assert_eq!(gap_only.origin_read_bytes_charged, origin_allowance(&f));
        assert_eq!(
            integrity::snapshot(&f.directory.0.join("destination"))?,
            before
        );
    }
    Ok(())
}

#[test]
fn interrupted_archive_reads_replay_unselected_originals_even_for_gap_only_queries() -> Test {
    for pages in [false, true] {
        let (mut f, request) = fixture(&format!("gapped-damaged-original-{pages}"), pages, 7_200)?;
        let receipt = run(&mut f, &request)?;
        let retained = f.retained(&receipt.catalog)?;
        select(&f, &retained, 0..1, origin_allowance(&f), &f.cx)?;
        let digest = f.original_packs[1];
        let path = f.target()?.publisher().spool().object_path(digest);
        let mut bytes = fs::read(&path)?;
        *bytes.last_mut().ok_or("empty source")? ^= 1;
        let mut permissions = fs::metadata(&path)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions)?;
        fs::write(&path, bytes)?;
        let before = integrity::snapshot(&f.directory.0.join("destination"))?;
        for query in [0..1, 16_000..18_000] {
            assert!(select(&f, &retained, query, origin_allowance(&f), &f.cx).is_err());
        }
        assert_eq!(
            integrity::snapshot(&f.directory.0.join("destination"))?,
            before
        );
        assert_eq!(
            f.source.as_ref().ok_or("source")?.spool().read(digest)?,
            *f.originals.get(&digest).ok_or("source bytes")?
        );
    }
    Ok(())
}

#[test]
fn explicit_gap_policy_never_reuses_a_continuous_request_or_import_identity() -> Test {
    for pages in [false, true] {
        let (mut f, request) = fixture(&format!("gapped-identity-{pages}"), pages, 0)?;
        let (strict_digest, strict_receipt) = match &request {
            RtspGappedCatalogImportRequest::Catalog(request) => (request.digest()?, f.run()?),
            RtspGappedCatalogImportRequest::Pages(request) => {
                (request.digest()?, run_pages(&mut f, request)?)
            }
        };
        assert_ne!(request.digest()?, strict_digest);
        let receipt = run(&mut f, &request)?;
        assert!(receipt.decode_gaps.is_empty());
        assert_ne!(
            receipt.catalog.import.import_identity,
            strict_receipt.import.import_identity
        );
        assert_ne!(receipt.catalog.import.proof, strict_receipt.import.proof);
        assert_eq!(
            f.retained(&strict_receipt)?.manifest().input_sha256,
            f.retained(&receipt.catalog)?.manifest().input_sha256
        );
        assert!(
            f.retained(&receipt.catalog)?
                .manifest()
                .segment_spans
                .iter()
                .all(|s| !s.gap_before)
        );
    }
    Ok(())
}

#[test]
fn gap_permission_does_not_widen_complete_source_bounds_or_decoder_configuration() -> Test {
    let (mut f, request) = fixture("gapped-bounds", false, 7_200)?;
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    assert!(matches!(
        import_rtsp_gapped_catalog(
            f.source.as_ref().ok_or("source")?,
            f.target.as_mut().ok_or("target")?,
            &request,
            &Owner(Cell::new(false)),
            &f.cx,
            &mut work(),
        ),
        Err(RtspImportError::Denied)
    ));
    assert!(
        import_rtsp_gapped_catalog(
            f.source.as_ref().ok_or("source")?,
            f.target.as_mut().ok_or("target")?,
            &request,
            &Owner(Cell::new(true)),
            &f.cx,
            &mut WorkBudget::new(0),
        )
        .is_err()
    );
    for case in 0..3 {
        let mut narrowed = f.request.clone();
        match case {
            0 => narrowed.max_frames = 7,
            1 => narrowed.max_original_bytes = f.original_bytes - 1,
            _ => narrowed.max_media_bytes = f.mp4.len() as u64 - 1,
        }
        assert!(run(&mut f, &RtspGappedCatalogImportRequest::Catalog(narrowed)).is_err());
        assert_eq!(
            integrity::snapshot(&f.directory.0.join("destination"))?,
            before
        );
    }
    let receipt = run(&mut f, &request)?;
    assert_eq!(receipt.catalog.import.frames, 8);
    let mut changed = Fixture::avc("gapped-config-change", 4, 7_200, true)?;
    let before = integrity::snapshot(&changed.directory.0.join("destination"))?;
    let request = RtspGappedCatalogImportRequest::Catalog(changed.request.clone());
    assert!(run(&mut changed, &request).is_err());
    assert_eq!(
        integrity::snapshot(&changed.directory.0.join("destination"))?,
        before
    );
    Ok(())
}

#[test]
fn gap_pages_keep_exact_order_unique_pins_and_cumulative_limits() -> Test {
    let (mut f, original) = avc_pages("gapped-pages-order", 0, 7_200, false)?;
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    for case in 0..4 {
        let mut request = original.clone();
        match case {
            0 => request.pages.swap(0, 1),
            1 => request.pages[1] = request.pages[0].clone(),
            2 => request.max_pages = 1,
            _ => request.max_frames = 7,
        }
        assert!(run(&mut f, &RtspGappedCatalogImportRequest::Pages(request)).is_err());
        assert_eq!(
            integrity::snapshot(&f.directory.0.join("destination"))?,
            before
        );
    }
    let receipt = run(&mut f, &RtspGappedCatalogImportRequest::Pages(original))?;
    assert_eq!(receipt.pages, 2);
    assert_eq!(receipt.decode_gaps, [14_400..21_600]);
    Ok(())
}
