#![forbid(unsafe_code)]
//! Laboratory bitstream -> RTP/AVC -> root-last recording -> reopen -> verified retrieval.
//! Usage: cargo run --locked -p fss-reference --example recording_archive_replay -- NEW_DIRECTORY

#[path = "../tests/recording_support/mod.rs"]
mod fixture;

use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording::local::{
    RecordingProgress, RecordingPublication, load_recording,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = std::path::PathBuf::from(
        args.next()
            .ok_or("supply an explicit new reference archive directory")?,
    );
    if args.next().is_some() || root.exists() {
        return Err(
            "exactly one new directory is required; existing data is never replaced".into(),
        );
    }
    let plan = fixture::fixture(1, true)?.prepare()?;
    let slot = SlotName::parse("fixture-recording-001")?;
    let limits = LocalPublicationLimits::new(
        8,
        16,
        8,
        64,
        SpoolLimits::new(64, 4 * 1024 * 1024, 1024 * 1024, 64),
    );
    let mut publisher = LocalRootPublisher::open(&root, limits)?;
    {
        let mut job =
            RecordingPublication::new(&plan, &mut publisher, slot.clone(), plan.byte_len(), 100)?;
        for now in 0..5 {
            match job.step(now, &NeverCancel)? {
                RecordingProgress::ChildStaged {
                    role,
                    digest,
                    bytes,
                    remaining,
                } => println!(
                    "{{\"kind\":\"child_staged\",\"role\":\"{role:?}\",\"digest\":\"{}\",\"bytes\":{bytes},\"remaining\":{remaining}}}",
                    digest.to_text()
                ),
                RecordingProgress::Published(receipt) => println!(
                    "{{\"kind\":\"root_publication\",\"root\":\"{}\",\"local\":\"{:?}\",\"outcome\":\"{:?}\"}}",
                    receipt.root.to_text(),
                    receipt.claims.local,
                    receipt.outcome
                ),
                RecordingProgress::Complete => {
                    return Err("unexpected duplicate terminal step".into());
                }
            }
        }
    }
    drop(publisher);
    let reopened = LocalRootPublisher::open(&root, limits)?;
    let recovered = load_recording(
        &reopened,
        &slot,
        plan.manifest().root(),
        &fixture::scope()?,
        &NeverCancel,
    )?;
    if recovered.objects().source != plan.objects().source
        || recovered.objects().media != plan.objects().media
    {
        return Err("reopened source/media differ from the prepared bytes".into());
    }
    println!(
        "{{\"kind\":\"verified_readback\",\"root\":\"{}\",\"samples\":{},\"packets\":{},\"decoded_here\":false,\"qualification\":\"reference_rehearsal_only\"}}",
        recovered.manifest().root().to_text(),
        recovered.summary().samples,
        recovered.summary().packets
    );
    Ok(())
}
