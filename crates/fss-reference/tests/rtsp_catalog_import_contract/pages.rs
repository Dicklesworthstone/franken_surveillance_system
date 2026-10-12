#![forbid(unsafe_code)]
//! Complete ordered page selections share one retained sample/capture map and native cold replay.

use super::*;
use fss_reference::ingest::rtsp_import::pages::{
    ADAPTER as PAGES_ADAPTER, MAX_PAGES, RtspCatalogPage, RtspCatalogPagesImportAuthority,
    RtspCatalogPagesImportReceipt, RtspCatalogPagesImportRequest, import_rtsp_catalog_pages,
};

mod failures;

impl RtspCatalogPagesImportAuthority for Owner {
    fn permit(&self, _: &RtspCatalogPagesImportRequest, destination: &ReferenceDeployment) -> bool {
        self.0.get() && destination.site_lineage() == SITE
    }
}

struct PagesFixture {
    inner: Fixture,
    request: RtspCatalogPagesImportRequest,
}
impl PagesFixture {
    fn new(inner: Fixture, pages: Vec<RtspCatalogPage>) -> Self {
        let common = &inner.request;
        let request = RtspCatalogPagesImportRequest {
            codec: common.codec,
            pages,
            scope: common.scope.clone(),
            receive_time: common.receive_time,
            capture_origin: common.capture_origin,
            max_pages: MAX_PAGES,
            max_windows: common.max_windows,
            max_frames: common.max_frames,
            max_original_bytes: common.max_original_bytes,
            max_media_bytes: common.max_media_bytes,
        };
        Self { inner, request }
    }
    fn avc(
        label: &str,
        page_windows: [usize; 2],
        per_window: usize,
        gap: u64,
        changed_config: bool,
    ) -> Test<Self> {
        let total: usize = page_windows.iter().sum();
        let mut plans = Vec::with_capacity(total);
        let mut slots = Vec::with_capacity(total);
        for index in 0..total {
            let second_page = index >= page_windows[0];
            let start = (index * per_window) as u64 * 3600 + if second_page { gap } else { 0 };
            let source = if second_page && changed_config {
                recording_support::repeated_from(
                    401 + index as u128,
                    per_window,
                    1 + index as u16 * 2000,
                    start as u32,
                    include_bytes!("../../../fss-packet/tests/fixtures/avc/high_cropped.264"),
                )?
            } else {
                recording_support::repeated(
                    401 + index as u128,
                    per_window,
                    1 + index as u16 * 2000,
                    start as u32,
                )?
            };
            plans.push(source.prepare_at(start)?);
            slots.push(slot(index)?);
        }
        let mut pages = Vec::new();
        let mut first = 0;
        for windows in page_windows {
            let end = first + windows;
            let selection: Vec<_> = (first..end)
                .map(|index| CatalogWindow {
                    slot: &slots[index],
                    recording: &plans[index],
                })
                .collect();
            pages.push(Page::Avc(prepare_catalog(
                scope(plans[0].summary()),
                &selection,
            )?));
            first = end;
        }
        let refs: Vec<_> = plans.iter().collect();
        let (inner, pins) = Fixture::from_catalogs(label, RtspImportCodec::Avc, &refs, pages)?;
        Ok(Self::new(inner, pins))
    }
    fn hevc(label: &str) -> Test<Self> {
        let first = hevc_recording_support::fixture()?;
        let mut packets = hevc_recording_support::packets()?;
        for packet in &mut packets {
            packet.sequence += 32;
            packet.received_ns += 32;
            packet.bytes[2..4].copy_from_slice(&(packet.sequence as u16).to_be_bytes());
            let timestamp = u32::from_be_bytes(packet.bytes[4..8].try_into()?);
            packet.bytes[4..8].copy_from_slice(&(timestamp + 72_000).to_be_bytes());
        }
        let mut timings = hevc_recording_support::timings(4);
        for timing in &mut timings {
            timing.decode_time += 72_000;
        }
        timings[1].composition_offset = 18_000;
        timings[2].composition_offset = -18_000;
        let second = hevc_recording_support::prepare(&packets, &timings)?;
        let a = slot(0)?;
        let b = slot(1)?;
        let first_page = prepare_hevc_catalog(
            scope(first.summary()),
            &[HevcCatalogWindow {
                slot: &a,
                recording: &first,
            }],
        )?;
        let second_page = prepare_hevc_catalog(
            scope(first.summary()),
            &[HevcCatalogWindow {
                slot: &b,
                recording: &second,
            }],
        )?;
        let (inner, pins) = Fixture::from_catalogs(
            label,
            RtspImportCodec::Hevc,
            &[first.publication_plan(), second.publication_plan()],
            vec![Page::Hevc(first_page), Page::Hevc(second_page)],
        )?;
        Ok(Self::new(inner, pins))
    }
    fn run(&mut self) -> Test<RtspCatalogPagesImportReceipt> {
        Ok(import_rtsp_catalog_pages(
            self.inner.source.as_ref().ok_or("source")?,
            self.inner.target.as_mut().ok_or("target")?,
            &self.request,
            &Owner(Cell::new(true)),
            &self.inner.cx,
            &mut work(),
        )?)
    }
}

#[test]
fn capture_sized_pages_remain_one_three_hundred_twenty_frame_cold_watch() -> Test {
    // The live capture CLI seals eight windows per page: frame256 is an actual page boundary.
    let mut fixture = PagesFixture::avc("pages-long", [8, 2], 32, 0, false)?;
    let receipt = fixture.run()?;
    assert_eq!(receipt.pages, 2);
    assert_eq!(receipt.catalog.windows, 10);
    assert_eq!(receipt.catalog.import.frames, 320);
    assert_eq!(receipt.catalog.decode_interval, 0..320 * 3600);
    assert_long_cold_watch(fixture.inner, receipt.catalog, PAGES_ADAPTER)
}

#[test]
fn hevc_pages_keep_exact_reordered_timing_and_all_original_deletion_dependencies() -> Test {
    let mut fixture = PagesFixture::hevc("pages-hevc")?;
    let receipt = fixture.run()?;
    assert_eq!(receipt.pages, 2);
    assert_eq!(receipt.catalog.import.frames, 8);
    fixture.inner.verify_fragment_remux(&receipt.catalog)?;
    let retained = fixture.inner.retained(&receipt.catalog)?;
    assert_eq!(retained.manifest().adapter_id, PAGES_ADAPTER);
    let mut check = || Ok(());
    let parsed = fss_container::demux::AvcMp4::parse_recovering_tail(
        &fixture.inner.mp4,
        None,
        fss_container::demux::DemuxLimits::default(),
        &mut check,
    )?;
    let times: Vec<_> = parsed
        .samples()
        .iter()
        .map(|s| s.presentation_time())
        .collect();
    assert!(times.windows(2).any(|w| w[1] < w[0]));
    let earliest = *times.iter().min().ok_or("presentation sample")?;
    for (index, time) in times.iter().enumerate() {
        let capsule = fss_reference::ingest::recorded_decode::retained_source_capsule(
            fixture.inner.target()?,
            &retained,
            index,
        )?;
        let offset = ((*time - earliest) * 1_000_000_000 + 45_000) / 90_000;
        assert_eq!(capsule.capture.earliest.0, 1_000_000_000 + offset - 10);
        assert_eq!(capsule.capture.latest.0, 1_000_000_000 + offset + 10);
    }
    drop(fixture.inner.source.take());
    fs::rename(
        fixture.inner.directory.0.join("archive"),
        fixture.inner.directory.0.join("offline-archive"),
    )?;
    drop(fixture.inner.target.take());
    fixture.inner.cx = context(&fixture.inner.directory.0.join("destination"))?;
    fixture.inner.target = Some(ReferenceDeployment::open(
        &fixture.inner.directory.0.join("destination"),
        SITE,
        &fixture.inner.cx,
    )?);
    let mut decoder = RecordedH265Range::open(
        fixture.inner.target()?,
        RecordedH265Request {
            import_identity: receipt.catalog.import.import_identity,
            first_segment: 0,
            segment_count: 8,
            interpretation: ComponentInterpretation::YCbCr,
            read_limits: RetainedReadLimits::default(),
            decoder_limits: HevcLimits::default(),
        },
        &fixture.inner.cx,
    )?;
    let mut decoded = 0;
    while let Some(frame) = decoder.next_frame(fixture.inner.target()?, &fixture.inner.cx)? {
        assert!(!frame.pixels().is_empty());
        decoded += 1;
    }
    assert_eq!(decoded, 8);
    let deletion = fss_reference::deletion::plan_deletion(
        fixture.inner.target()?,
        receipt.catalog.import.import_identity,
        &fixture.inner.cx,
    )?;
    for digest in fixture
        .inner
        .originals
        .keys()
        .copied()
        .chain(std::iter::once(receipt.catalog.import.proof))
    {
        assert!(
            deletion
                .deletable
                .iter()
                .any(|entry| entry.digest == digest)
        );
    }
    Ok(())
}

#[test]
fn page_boundaries_refuse_native_gaps_and_initialization_changes_before_import_staging() -> Test {
    for (label, gap, changed) in [("pages-gap", 3600, false), ("pages-config", 0, true)] {
        let mut fixture = PagesFixture::avc(label, [1, 1], 1, gap, changed)?;
        let before = fixture.inner.snapshot()?;
        assert!(fixture.run().is_err());
        assert_eq!(fixture.inner.snapshot()?, before);
    }
    Ok(())
}
