#![forbid(unsafe_code)]
//! Index or verify ranges in an explicitly supplied EXISTING reference archive.
//! No sockets, inferred clocks, directory discovery, or raw-media stdout.
//! See docs/RECORDING_CATALOG.md for exact command syntax and authorization boundaries.

use std::{path::Path, time::{Duration, Instant}};
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, PublishCancellation, PublishCutPoint, SlotName};
use fss_reference::rtsp::recording::{RecordingScope, MAX_RECORDING_BYTES};
use fss_reference::rtsp::recording::local::load_recording;
use fss_reference::rtsp::recording_catalog::{CatalogBuilder, CatalogScope, CatalogQueryLimits, MAX_CATALOG_WINDOWS};
use fss_reference::rtsp::recording_catalog::local::{CatalogPublication, CatalogProgress,
    RecordingRangeRead, RangeProgress, load_catalog};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEADLINE_NS: u64 = 30_000_000_000;
const USAGE: &str = "recording_catalog index|query ARCHIVE CATALOG_SLOT SENSOR STREAM GENERATION ANCHOR RECEIVE_CLOCK DECODE_CLOCK TIME_SCALE [WINDOW_SLOT=ROOT ... | CATALOG_ROOT START END MAX_OUTPUT_BYTES]";
struct Deadline { start: Instant }
impl Deadline {
    fn now(&self) -> Result<u64> { Ok(u64::try_from(self.start.elapsed().as_nanos())?) }
}
impl PublishCancellation for Deadline {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool { self.start.elapsed() >= Duration::from_nanos(DEADLINE_NS) }
}
fn main() {
    if let Err(error) = run() { eprintln!("catalog command refused: {error}"); std::process::exit(1); }
}
fn run() -> Result<()> {
    let mut args = Vec::new();
    for arg in std::env::args().skip(1) {
        if args.len() >= MAX_CATALOG_WINDOWS + 10 || arg.len() > 4096 { return Err("argument budget exceeded".into()); }
        args.push(arg);
    }
    if args.len() < 11 { return Err(USAGE.into()); }
    let slot = SlotName::parse(&args[2])?;
    let scope = CatalogScope { recording: RecordingScope {
        sensor: SensorId::parse(&args[3])?, stream: StreamId::parse(&args[4])?, generation: args[5].parse()?,
        anchor: ContentDigest::parse(&args[6])?, receive_clock: ContentDigest::parse(&args[7])?,
    }, decode_clock: ContentDigest::parse(&args[8])?, time_scale: args[9].parse()? };
    if scope.recording.generation == 0 || scope.time_scale == 0 { return Err("nonzero epoch and tick rate required".into()); }
    match args[0].as_str() {
        "index" if (11..=MAX_CATALOG_WINDOWS + 10).contains(&args.len()) => {},
        "query" if args.len() == 14 => {},
        _ => return Err(USAGE.into()),
    }
    let root = Path::new(&args[1]);
    if !root.join("roots").is_dir() || !root.join("spool").is_dir() {
        return Err("an existing reference publication archive is required".into());
    }
    let clock = Deadline { start: Instant::now() };
    // Explicit bounded reference owner, not a production provider or a read-only
    // filesystem promise: open takes the owner's lock and performs recovery checks.
    let limits = LocalPublicationLimits::new(4096, 512, 4096, 8192,
        SpoolLimits::new(32768, 8 * 1024 * 1024 * 1024, MAX_RECORDING_BYTES, 65536));
    let mut publisher = LocalRootPublisher::open(root, limits)?;
    if args[0] == "index" {
        let mut builder = CatalogBuilder::new(scope.clone())?;
        for reference in &args[10..] {
            let (name, digest) = reference.split_once('=').ok_or("use WINDOW_SLOT=algorithm:digest")?;
            let child_slot = SlotName::parse(name)?;
            let window = load_recording(&publisher, &child_slot, ContentDigest::parse(digest)?, &scope.recording, &clock)?;
            builder.push(&child_slot, &window)?;
            // The large source and media objects are dropped at each loop boundary.
        }
        let catalog = builder.prepare()?;
        let mut job = CatalogPublication::new(&catalog, &mut publisher, slot, catalog.byte_len(), DEADLINE_NS)?;
        for _ in 0..MAX_CATALOG_WINDOWS + 3 {
            match job.step(clock.now()?, &clock)? {
                CatalogProgress::WindowVerified { ordinal, root, .. } => println!(
                    "{{\"kind\":\"window_verified\",\"ordinal\":{ordinal},\"root\":\"{root}\"}}"),
                CatalogProgress::IndexStaged { .. } => {},
                CatalogProgress::Published(receipt) => {
                    println!("{{\"kind\":\"catalog_published\",\"root\":\"{}\",\"windows\":{},\"state\":\"{:?}\"}}",
                        receipt.root, catalog.entries().len(), receipt.claims.local);
                    return Ok(());
                }
                CatalogProgress::Complete => return Err("missing publication receipt".into()),
            }
        }
    } else {
        let expected = ContentDigest::parse(&args[10])?;
        let start = args[11].parse()?; let end = args[12].parse()?;
        let limits = CatalogQueryLimits { max_windows: MAX_CATALOG_WINDOWS, max_output_bytes: args[13].parse()? };
        let catalog = load_catalog(&publisher, &slot, expected, &scope, &clock)?;
        let mut read = RecordingRangeRead::new(&publisher, &catalog, &slot, start..end, limits, DEADLINE_NS)?;
        for _ in 0..MAX_CATALOG_WINDOWS + 1 {
            match read.step(clock.now()?, &clock)? {
                RangeProgress::Window { ordinal, requested_interval, recording } => println!(
                    "{{\"kind\":\"recording_verified\",\"ordinal\":{ordinal},\"root\":\"{}\",\"requested_start\":{},\"requested_end\":{},\"bytes\":{}}}",
                    recording.manifest().root(), requested_interval.start, requested_interval.end, recording.byte_len()),
                RangeProgress::Complete(receipt) => {
                    for gap in &receipt.unindexed { println!(
                        "{{\"kind\":\"unindexed\",\"start\":{},\"end\":{},\"evidence_of_absence\":false}}", gap.start, gap.end); }
                    println!("{{\"kind\":\"retrieval_complete\",\"catalog\":\"{}\",\"windows\":{},\"verified_payload_bytes\":{},\"unindexed_intervals\":{},\"camera_coverage_certified\":false}}",
                        receipt.catalog_root, receipt.windows, receipt.output_bytes, receipt.unindexed.len());
                    return Ok(());
                }
                RangeProgress::Exhausted => return Err("missing retrieval receipt".into()),
            }
        }
    }
    Err("bounded progress exhausted without a terminal receipt".into())
}
