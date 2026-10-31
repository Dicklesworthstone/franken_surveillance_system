#![forbid(unsafe_code)]

use super::*;
use crate::plan::{Command, Plan};
use fss_core::{CanonicalEncoder, ContentDigest};
use std::cell::Cell;
use std::ffi::OsString;
use std::rc::Rc;

fn args() -> Vec<OsString> {
    [
        "publish",
        "--root",
        "/not-opened/deployment",
        "--site",
        "site:video",
        "--import-id",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "--codec",
        "avc",
        "--privacy-policy",
        "none",
        "--read-originals",
        "yes",
        "--retain-derived",
        "yes",
        "--first-segment",
        "0",
        "--segment-count",
        "3",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

// Independent copy of the pre-selection plan, including the effective native budgets added
// on main. Selection has no presence marker in this encoding: all-frame approvals stay exact.
fn legacy_digest(p: &Plan) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.native_video_cli_plan.v1");
    e.text("explicit-codec-import-and-privacy:sealed-native-frames:bounded-display-order:source-verified-cold-read:whole-range-replay:no-camera:no-effects:incremental-publication:v1");
    let count = if p.command == Command::Publish {
        p.count
    } else {
        p.segments
    };
    let native = match p.codec {
        crate::plan::Codec::Avc => format!("{:?}", p.avc_limits(count)?),
        crate::plan::Codec::Hevc => format!("{:?}", p.hevc_limits(count)),
    };
    e.text(&native);
    e.text(fss_reference::ingest::recorded_decode::video_budget::VIDEO_DECODE_WORK_MODEL);
    e.digest(match p.codec {
        crate::plan::Codec::Avc => {
            fss_reference::ingest::recorded_decode::h264::h264_decoder_identity()
        }
        crate::plan::Codec::Hevc => {
            fss_reference::ingest::recorded_decode::h265::h265_decoder_identity()
        }
    });
    e.u64(crate::plan::MANIFEST_RESERVE as u64);
    e.u64(crate::plan::STORAGE_OPERATIONS);
    for s in [
        p.command.text(),
        p.root.to_str().ok_or_else(|| fail("root"))?,
        &p.site,
        &p.principal,
        p.codec.text(),
    ] {
        e.text(s);
    }
    e.digest(p.identity);
    for pin in [p.privacy, p.frame] {
        e.bool(pin.is_some());
        if let Some(pin) = pin {
            e.digest(pin);
        }
    }
    for n in [
        p.first as u64,
        p.count as u64,
        p.source.max_source_bytes,
        p.source.max_chunk_bytes,
        p.source.max_segment_bytes,
        p.pixels as u64,
        p.dimension as u64,
        p.slices as u64,
        p.segments as u64,
        p.work,
        p.derived as u64,
        p.timeout_ms,
        crate::plan::REPORT_LIMIT as u64,
    ] {
        e.u64(n);
    }
    e.bool(p.output.is_some());
    if let Some(output) = &p.output {
        e.text(output.to_str().ok_or_else(|| fail("output"))?);
        e.text(p.pixel_format.as_deref().ok_or_else(|| fail("format"))?);
        e.text("linux-pinned-parent:create-new:bounded-write:retain-partial-on-failure:v1");
    }
    Ok(ContentDigest::sha256(&e.finish_checked()?))
}

#[test]
fn selected_plan_versions_inband_admission_and_binds_the_display_position() -> Result<()> {
    let legacy = Plan::parse(&args())?;
    assert_eq!(legacy.output_index, None);
    // The selected-output encoding stays additive, but broader avc3/hev1 reconstruction
    // deliberately requires a current-generation approval before any source work.
    assert_ne!(legacy.digest()?, legacy_digest(&legacy)?);
    assert!(!legacy.preview()?.contains("selection_policy"));
    let mut seen = std::collections::BTreeSet::new();
    for index in 0..3 {
        let mut input = args();
        input.extend(["--output-index".into(), index.to_string().into()]);
        let plan = Plan::parse(&input)?;
        assert_eq!(plan.output_index, Some(index));
        assert_eq!(plan.first, 0);
        assert_eq!(plan.count, 3);
        assert_ne!(plan.digest()?, legacy.digest()?);
        assert!(seen.insert(plan.digest()?));
        assert!(
            plan.preview()?
                .contains("\"complete_range_required_before_publication\":true")
        );
        assert!(plan.preview()?.contains("\"maximum_frames_retained\":1"));
        let mut approved = input;
        approved.extend(["--approve".into(), plan.digest()?.to_text().into()]);
        assert_eq!(Plan::parse(&approved)?.digest()?, plan.digest()?);
    }
    Ok(())
}

#[test]
fn tiled_hevc_admission_requires_a_new_operator_plan_identity() -> Result<()> {
    let mut input = args();
    let position = input
        .iter()
        .position(|value| value == "avc")
        .ok_or_else(|| fail("codec fixture"))?;
    input[position] = "hevc".into();
    let mut plan = Plan::parse(&input)?;
    let old = legacy_digest(&plan)?;
    assert_ne!(plan.digest()?, old);
    plan.approval = Some(old);
    let mut output = Vec::new();
    assert!(crate::operation::run(&plan, &mut output).is_err());
    assert!(
        output.is_empty(),
        "old admission approval must fail before storage or publication"
    );
    Ok(())
}

#[test]
fn selection_refuses_signed_overflow_outside_range_and_duplicate_indices() {
    for value in ["-1", "+0", "3", "18446744073709551616"] {
        let mut input = args();
        input.extend(["--output-index".into(), value.into()]);
        assert!(Plan::parse(&input).is_err(), "{value}");
    }
    let mut duplicate = args();
    duplicate.extend([
        "--output-index".into(),
        "0".into(),
        "--output-index".into(),
        "1".into(),
    ]);
    assert!(Plan::parse(&duplicate).is_err());
}

#[test]
fn selection_cannot_be_used_on_reads_or_verified_with_an_all_frame_approval() -> Result<()> {
    let legacy = Plan::parse(&args())?;
    for command in [Command::Read, Command::Verify] {
        let mut plan = Plan::parse(&args())?;
        plan.command = command;
        plan.output_index = Some(0);
        assert!(
            plan.digest().is_err(),
            "invalid in-memory plan must not gain approval"
        );
        let input: Vec<OsString> = [
            command.text(),
            "--root",
            "/not-opened/deployment",
            "--site",
            "site:video",
            "--import-id",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--codec",
            "avc",
            "--privacy-policy",
            "none",
            "--read-originals",
            "yes",
            "--frame-root",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "--output-index",
            "0",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert!(Plan::parse(&input).is_err());
    }
    let mut selected = Plan::parse(&args())?;
    selected.output_index = Some(1);
    selected.approval = Some(legacy.digest()?);
    let mut output = Vec::new();
    assert!(crate::operation::run(&selected, &mut output).is_err());
    assert!(
        output.is_empty(),
        "wrong approval must precede storage and output"
    );
    Ok(())
}

#[test]
fn selection_still_binds_whole_range_work_and_derived_ceilings() -> Result<()> {
    let mut input = args();
    input.extend(["--output-index".into(), "1".into()]);
    let original = Plan::parse(&input)?;
    for (key, value) in [
        ("--work-units", "0"),
        ("--max-derived-bytes", "1"),
        ("--max-pixels", "25344"),
        ("--timeout-ms", "1"),
    ] {
        let mut changed = input.clone();
        changed.extend([key.into(), value.into()]);
        assert_ne!(
            Plan::parse(&changed)?.digest()?,
            original.digest()?,
            "{key}"
        );
    }
    Ok(())
}

#[derive(Debug)]
struct TestFrame {
    output: u64,
    source: usize,
    dimensions: [u32; 2],
}
fn frame(output: u64, source: usize) -> TestFrame {
    TestFrame {
        output,
        source,
        dimensions: [16, 16],
    }
}
fn metadata(frame: &TestFrame) -> (u64, [u32; 2]) {
    (frame.output, frame.dimensions)
}
fn refusal<T>(result: Result<T>) -> Box<RecordedDecodeError> {
    match result {
        Ok(_) => panic!("expected refusal"),
        Err(error) => error.downcast().expect("native error preserved"),
    }
}

#[test]
fn selected_output_is_display_order_and_the_range_is_fully_drained() -> Result<()> {
    let calls = Cell::new(0);
    let mut frames = [frame(0, 0), frame(1, 2), frame(2, 1)].into_iter();
    let selected = drain(
        3,
        1,
        256,
        16,
        || {
            calls.set(calls.get() + 1);
            Ok(frames.next())
        },
        metadata,
    )?;
    assert_eq!(selected.frame.source, 2);
    assert_eq!(selected.outputs, 3);
    assert_eq!(calls.get(), 4);
    Ok(())
}

#[test]
fn late_error_after_chosen_output_never_returns_a_publishable_frame() {
    for error in [
        RecordedDecodeError::Cancelled,
        RecordedDecodeError::Limit,
        RecordedDecodeError::InvalidReceipt,
    ] {
        let mut steps = [Ok(Some(frame(0, 0))), Err(error.into())].into_iter();
        assert!(
            drain(
                3,
                0,
                256,
                16,
                || steps.next().expect("no poll after error"),
                metadata
            )
            .is_err()
        );
        assert!(steps.next().is_none());
    }
}

#[test]
fn rasl_omissions_do_not_substitute_a_missing_display_position() -> Result<()> {
    let mut frames = [frame(0, 0), frame(1, 2)].into_iter();
    let chosen = drain(3, 1, 256, 16, || Ok(frames.next()), metadata)?;
    assert_eq!(chosen.outputs, 2);
    assert_eq!(chosen.frame.source, 2);
    let mut frames = [frame(0, 0), frame(1, 2)].into_iter();
    assert!(matches!(
        *refusal(drain(3, 2, 256, 16, || Ok(frames.next()), metadata)),
        RecordedDecodeError::Unavailable
    ));
    Ok(())
}

#[test]
fn duplicate_unordered_or_extra_display_frames_are_refused() {
    for outputs in [[0, 0], [1, 0]] {
        let mut frames = outputs.into_iter().map(|i| frame(i, i as usize));
        assert!(matches!(
            *refusal(drain(2, 0, 256, 16, || Ok(frames.next()), metadata)),
            RecordedDecodeError::InvalidReceipt
        ));
    }
    let mut frames = [frame(0, 0), frame(1, 1)].into_iter();
    assert!(matches!(
        *refusal(drain(1, 0, 256, 16, || Ok(frames.next()), metadata)),
        RecordedDecodeError::Limit
    ));
}

#[test]
fn unselected_oversize_frame_refuses_without_widening_the_pixel_cap() {
    let mut large = frame(1, 1);
    large.dimensions = [17, 16];
    let mut frames = [frame(0, 0), large].into_iter();
    assert!(matches!(
        *refusal(drain(2, 0, 256, 32, || Ok(frames.next()), metadata)),
        RecordedDecodeError::Limit
    ));
}

#[test]
fn selected_pixel_ownership_is_bounded_independently_of_range_length() -> Result<()> {
    struct Counted {
        index: u64,
        alive: Rc<Cell<usize>>,
    }
    impl Drop for Counted {
        fn drop(&mut self) {
            self.alive.set(self.alive.get() - 1);
        }
    }
    let alive = Rc::new(Cell::new(0));
    let peak = Cell::new(0);
    let mut index = 0;
    let selected = drain(
        MAX_H264_RANGE_SEGMENTS,
        2,
        256,
        16,
        || {
            if index == MAX_H264_RANGE_SEGMENTS {
                return Ok(None);
            }
            alive.set(alive.get() + 1);
            peak.set(peak.get().max(alive.get()));
            let frame = Counted {
                index: index as u64,
                alive: Rc::clone(&alive),
            };
            index += 1;
            Ok(Some(frame))
        },
        |frame| (frame.index, [16, 16]),
    )?;
    assert_eq!(selected.outputs, MAX_H264_RANGE_SEGMENTS);
    assert_eq!(peak.get(), 2);
    assert_eq!(alive.get(), 1);
    drop(selected);
    assert_eq!(alive.get(), 0);
    Ok(())
}
