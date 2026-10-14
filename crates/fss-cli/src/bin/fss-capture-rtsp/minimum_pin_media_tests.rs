#![forbid(unsafe_code)]
//! Native saved work, lost acknowledgements, verified descendants and stale backups.

use super::*;
use fss_reference::rtsp::archive_pins::HevcArchivePinJournal;
use fss_reference::rtsp::recording::hevc::{
    PreparedHevcRecording, local::load_hevc_recording, prepare_hevc_recording,
};
use fss_reference::rtsp::recording_archive::CodecArchiveSnapshot;
use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::{
    CheckpointedArchiveProgress, CheckpointedHevcArchiveWriter,
};
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use std::cell::Cell;

#[path = "../../../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod source;

struct SavedWork {
    minimum: ArchivePinAnchor,
    window: ContentDigest,
    journal_bytes: Vec<u8>,
}

fn recording(options: &Options) -> Test<PreparedHevcRecording> {
    let packets = source::packets()?;
    Ok(prepare_hevc_recording(
        options.recording_config().scope,
        &source::configuration()?,
        90_000,
        &source::timings(2),
        &source::borrowed(&packets[..6]),
    )?)
}

fn fixture(options: &Options) -> Test<SavedWork> {
    let namespace = HevcArchiveNamespace::new(options.catalog_scope().clone())?;
    let mut publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    let mut pins = HevcArchivePinJournal::create(
        &options.pins,
        options.pin_scope(),
        options.pin_limits(),
        &NeverCancel,
    )?;
    let mut writer = CheckpointedHevcArchiveWriter::open(
        &mut publisher,
        namespace,
        options.work_limits().archive,
        options.work_limits(),
        256,
        0,
        1000,
        &NeverCancel,
    )?;
    let window = recording(options)?;
    let root = window.manifest().root();
    let bytes = window.byte_len();
    writer.offer(window, bytes, 0)?;
    let CheckpointedArchiveProgress::PinRequired(pin) = writer.step(0, &NeverCancel)? else {
        return Err("missing native work candidate".into());
    };
    let minimum = pins.persist_candidate(&pin, &NeverCancel)?.anchor();
    writer.acknowledge_checkpoint(&pin, 0, &NeverCancel)?;
    assert!(matches!(
        writer.step(0, &NeverCancel)?,
        CheckpointedArchiveProgress::WorkDurable { .. }
    ));
    let _retained = writer.retire();
    // Drop every original writer and in-memory work object before cold recovery.
    Ok(SavedWork {
        minimum,
        window: root,
        journal_bytes: fs::read(options.pins.join("pins.journal"))?,
    })
}

fn current_anchor(options: &Options) -> Test<ArchivePinAnchor> {
    let pins = HevcArchivePinJournal::open_complete(
        &options.pins,
        options.pin_scope(),
        None,
        options.pin_limits(),
        &NeverCancel,
    )?;
    Ok(pins.anchor())
}

fn window_present(options: &Options) -> Test<bool> {
    let publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    let namespace = HevcArchiveNamespace::new(options.catalog_scope().clone())?;
    Ok(publisher.root(&namespace.window_slot(0)?).is_some())
}

fn verify_original(options: &Options, expected: ContentDigest) -> Test {
    let publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    let namespace = HevcArchiveNamespace::new(options.catalog_scope().clone())?;
    let loaded = load_hevc_recording(
        &publisher,
        &namespace.window_slot(0)?,
        expected,
        &options.recording_config().scope,
        &NeverCancel,
    )?;
    let original = recording(options)?;
    assert_eq!(loaded.manifest().root(), expected);
    assert_eq!(loaded.objects().source, original.objects().source);
    assert_eq!(loaded.objects().media, original.objects().media);
    assert_eq!(loaded.samples(), original.samples());
    assert_eq!(loaded.source_only_nals(), 1);
    assert_eq!(loaded.summary().samples, 2);
    assert!(publisher.root(&namespace.window_slot(1)?).is_none());
    Ok(())
}

fn approve_single(input: &mut Vec<OsString>) -> Test<SinglePlan> {
    let plan = SinglePlan::parse(input)?;
    set(input, "--approve", &approval(&plan.preview()?)?.to_text());
    Ok(SinglePlan::parse(input)?)
}

fn run_work(plan: &impl RecoveryPlan) -> Result<()> {
    execute_codec::<HevcArchiveCodec>(plan, TIMEOUT, |_| Ok(()), &NeverCancel)
}

#[test]
fn lost_restoration_reply_accepts_a_verified_descendant_without_duplicate_media() -> Test {
    let directory = Directory::new()?;
    let mut input = args(&directory, "hevc");
    set(&mut input, "--payload-type", "98");
    set(&mut input, "--recover", "yes");
    let original = SinglePlan::parse(&input)?;
    let saved = fixture(&original.attempts()[0])?;
    set(
        &mut input,
        "--minimum-pin-anchors",
        &anchor_text(1, saved.minimum),
    );
    let plan = approve_single(&mut input)?;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(
            &plan,
            TIMEOUT,
            |row| {
                let row = std::str::from_utf8(row).map_err(|_| OUTPUT)?;
                if row.contains("\"kind\":\"attempt_recovery\"") {
                    Err(OUTPUT)
                } else {
                    Ok(())
                }
            },
            &NeverCancel,
        ),
        Err(OUTPUT),
    );
    verify_original(&original.attempts()[0], saved.window)?;
    let confirmed = current_anchor(&original.attempts()[0])?;
    assert!(confirmed.sequence > saved.minimum.sequence);
    // The old minimum remains valid, but the exact old observed-tip approval is stale.
    assert_eq!(run_work(&plan), Err(APPROVAL));
    let retry = approve_single(&mut input)?;
    run_work(&retry)?;
    assert_eq!(current_anchor(&original.attempts()[0])?, confirmed);
    verify_original(&original.attempts()[0], saved.window)?;

    // Index approval includes the minimum even when two minima are both valid ancestors.
    set(&mut input, "--recover", "index");
    let old_floor_index = SinglePlan::parse(&input)?.preview()?;
    set(&mut input, "--minimum-pin-anchors", &anchor_text(1, confirmed));
    let new_floor_index = SinglePlan::parse(&input)?.preview()?;
    assert_ne!(approval(&old_floor_index)?, approval(&new_floor_index)?);
    set(&mut input, "--approve", &approval(&old_floor_index)?.to_text());
    assert!(SinglePlan::parse(&input)?.execute().is_err());
    approve_single(&mut input)?.execute()?;
    verify_original(&original.attempts()[0], saved.window)?;
    let options = &original.attempts()[0];
    let publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    let snapshot = CodecArchiveSnapshot::<HevcArchiveCodec>::load(
        &publisher,
        HevcArchiveNamespace::new(options.catalog_scope().clone())?,
        options.work_limits().archive,
        &NeverCancel,
    )?;
    assert_eq!(snapshot.windows().len(), 1);
    assert_eq!(snapshot.indexed_windows(), 1);
    assert_eq!(snapshot.pages().len(), 1);
    Ok(())
}

#[test]
fn a_checksum_valid_older_journal_cannot_erase_an_independent_confirmation() -> Test {
    let directory = Directory::new()?;
    let mut input = args(&directory, "hevc");
    set(&mut input, "--payload-type", "98");
    set(&mut input, "--recover", "yes");
    let original = SinglePlan::parse(&input)?;
    let saved = fixture(&original.attempts()[0])?;
    set(
        &mut input,
        "--minimum-pin-anchors",
        &anchor_text(1, saved.minimum),
    );
    run_work(&approve_single(&mut input)?)?;
    let confirmed = current_anchor(&original.attempts()[0])?;
    let path = original.attempts()[0].pins.join("pins.journal");
    // All owners have been dropped. Simulate restoring the original, valid old backup.
    fs::write(&path, &saved.journal_bytes)?;
    set(&mut input, "--minimum-pin-anchors", &anchor_text(1, confirmed));
    for mode in ["yes", "index"] {
        set(&mut input, "--recover", mode);
        let mut refused = SinglePlan::parse(&input)?;
        assert!(refused.preview().is_err());
        assert!(refused.execute().is_err());
        assert_eq!(fs::read(&path)?, saved.journal_bytes);
    }
    verify_original(&original.attempts()[0], saved.window)?;
    Ok(())
}

#[test]
fn reconnect_minima_are_bound_to_original_attempts_before_the_first_restoration() -> Test {
    let directory = Directory::new()?;
    let mut input = args(&directory, "hevc");
    set(&mut input, "--payload-type", "98");
    set(&mut input, "--max-attempts", "3");
    let original = ReconnectPlan::parse(&input)?;
    let saved = fixture(&original.attempts()[0])?;
    let second = genesis::<HevcArchiveCodec>(&original.attempts()[1])?;
    // Attempt three is intentionally unobserved and has no independently retained prefix.
    let minima = format!(
        "{},{}",
        anchor_text(1, saved.minimum),
        anchor_text(2, second),
    );
    set(&mut input, "--minimum-pin-anchors", &minima);
    assert!(ReconnectPlan::parse(&input).is_err());
    set(&mut input, "--recover", "yes");
    let plan = ReconnectPlan::parse(&input)?;
    assert_eq!(plan.capture_digest()?, original.capture_digest()?);
    for (actual, expected) in plan.attempts().iter().zip(original.attempts()) {
        assert_eq!(actual.digest()?, expected.digest()?);
        assert_eq!(actual.root, expected.root);
        assert_eq!(actual.pins, expected.pins);
    }
    let preview = plan.preview()?;
    let reversed = format!(
        "{},{}",
        anchor_text(2, second),
        anchor_text(1, saved.minimum),
    );
    set(&mut input, "--minimum-pin-anchors", &reversed);
    assert_eq!(ReconnectPlan::parse(&input)?.preview()?, preview);

    let invalid = format!(
        "{},{}",
        anchor_text(1, saved.minimum),
        anchor_text(
            2,
            ArchivePinAnchor {
                root: ContentDigest::sha256(b"wrong-second"),
                ..second
            },
        ),
    );
    set(&mut input, "--minimum-pin-anchors", &invalid);
    set(&mut input, "--approve", &approval(&preview)?.to_text());
    let refused = ReconnectPlan::parse(&input)?;
    let mut emitted = 0;
    assert!(
        execute_codec::<HevcArchiveCodec>(
            &refused,
            TIMEOUT,
            |_| {
                emitted += 1;
                Ok(())
            },
            &NeverCancel,
        )
        .is_err()
    );
    assert_eq!(emitted, 0);
    assert!(!window_present(&original.attempts()[0])?);
    assert_eq!(
        fs::read(original.attempts()[0].pins.join("pins.journal"))?,
        saved.journal_bytes,
    );

    // Swapping valid prefixes from different original attempts must also refuse.
    set(
        &mut input,
        "--minimum-pin-anchors",
        &format!(
            "{},{}",
            anchor_text(1, second),
            anchor_text(2, saved.minimum),
        ),
    );
    assert!(ReconnectPlan::parse(&input)?.preview().is_err());
    set(&mut input, "--minimum-pin-anchors", &minima);
    let plan = ReconnectPlan::parse(&input)?;
    run_work(&plan)?;
    verify_original(&original.attempts()[0], saved.window)?;
    assert!(!original.attempts()[2].root.exists());
    assert!(!original.attempts()[2].pins.exists());
    Ok(())
}

struct Cancel(Cell<bool>);
impl PublishCancellation for Cancel {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.0.get()
    }
}

#[test]
fn cancelled_or_unacknowledged_minimum_report_never_starts_original_publication() -> Test {
    let directory = Directory::new()?;
    let mut input = args(&directory, "hevc");
    set(&mut input, "--payload-type", "98");
    set(&mut input, "--recover", "yes");
    let original = SinglePlan::parse(&input)?;
    let saved = fixture(&original.attempts()[0])?;
    set(
        &mut input,
        "--minimum-pin-anchors",
        &anchor_text(1, saved.minimum),
    );
    let plan = approve_single(&mut input)?;
    for fail_output in [false, true] {
        let cancel = Cancel(Cell::new(false));
        assert!(
            execute_codec::<HevcArchiveCodec>(
                &plan,
                TIMEOUT,
                |row| {
                    let row = std::str::from_utf8(row).map_err(|_| OUTPUT)?;
                    if row.contains("\"kind\":\"minimum_prefixes_verified\"") {
                        if fail_output {
                            return Err(OUTPUT);
                        }
                        cancel.0.set(true);
                    }
                    Ok(())
                },
                &cancel,
            )
            .is_err()
        );
        assert!(!window_present(&original.attempts()[0])?);
        assert_eq!(
            fs::read(original.attempts()[0].pins.join("pins.journal"))?,
            saved.journal_bytes,
        );
    }
    run_work(&plan)?;
    verify_original(&original.attempts()[0], saved.window)?;
    Ok(())
}
