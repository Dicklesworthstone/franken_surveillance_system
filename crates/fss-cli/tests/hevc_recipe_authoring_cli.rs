#![forbid(unsafe_code)]
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
//! Actual operator processes over cold native HEVC originals, not mocked storage or native requests.
#[path = "../../fss-reference/tests/hevc_datagram_support/mod.rs"]
mod support;
use fss_cli::agent_json::{object, string};
use fss_cli::json_input::{self, Value};
use fss_core::ContentDigest;
use fss_publication::{LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::datagram_archive::DatagramPin;
use fss_reference::rtsp::datagram_archive::prefix::DatagramPrefix;
use fss_reference::rtsp::datagram_reconstruction::hevc::recording::*;
use fss_reference::rtsp::hevc_recording_capture::HevcCapturePoll;
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording_recipe::hevc::storage::*;
use fss_reference::rtsp::recording_recipe::hevc::*;
use std::path::PathBuf;
use std::process::{Command, Output};
use support::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn row(n: u64) -> String {
    object(&[
        ("rtp_timestamp", (9000 + n * 18000).to_string()),
        ("decode_time", (n * 18000).to_string()),
        ("duration", "18000".into()),
        ("composition_offset", "0".into()),
    ])
}
fn data(fragmented: bool, eob: bool) -> Test<Vec<Observation>> {
    let mut out = observations(fragmented)?;
    let nals = media::nals()?;
    let idr = nals
        .iter()
        .find(|n| matches!((n[0] >> 1) & 63, 19 | 20))
        .ok_or("IDR")?;
    let seq = out.len() as u64 + 1;
    out.push((0, 9 + seq, raw(seq, 27000, true, idr)));
    if eob {
        out.push((0, 10 + seq, raw(seq + 1, 27000, false, &[37 << 1, 1, 0x80])));
        out.push((1, 11 + seq, vec![0, 0, 0]));
    }
    Ok(out)
}
fn draft(pin: DatagramPin, rows: &[String]) -> Test<String> {
    let s = scope()?;
    let r = media::scope()?;
    let c = media::configuration()?;
    let source = object(&[
        ("ingress", string(&s.binding.key().ingress.to_string())),
        ("generation", s.binding.key().generation.to_string()),
        ("ssrc", s.binding.key().ssrc.to_string()),
        ("peer", string(&s.binding.peer().to_string())),
        ("authority", string(s.binding.authority())),
        ("rtp_channel", s.channels.0.to_string()),
        ("rtcp_channel", s.channels.1.to_string()),
        ("receive_clock", string(&s.receive_clock.to_text())),
        (
            "retention_evidence",
            string(&s.retention_evidence.to_text()),
        ),
        ("head", string(&pin.head.to_text())),
        ("datagrams", pin.datagrams.to_string()),
        ("payload_bytes", pin.payload_bytes.to_string()),
    ]);
    let recording = object(&[
        ("sensor", string(r.sensor.as_str())),
        ("stream", string(r.stream.as_str())),
        ("anchor", string(&r.anchor.to_text())),
        ("time_scale", "90000".into()),
        (
            "timing_evidence",
            string(&ContentDigest::sha256(b"explicit independent owner timing").to_text()),
        ),
        (
            "configuration_evidence",
            string(&spec().configuration_evidence.to_text()),
        ),
        ("payload_type", media::PT.to_string()),
        ("reduced_rtcp", "false".into()),
        ("sprop_max_don_diff", "0".into()),
        ("vps_hex", string(&hex(c.vps()))),
        ("sps_hex", string(&hex(c.sps()))),
        ("pps_hex", string(&hex(c.pps()))),
    ]);
    Ok(object(&[
        ("schema", string("fss.hevc_recipe_draft.v1")),
        ("source", source),
        ("recording", recording),
        ("timings", format!("[{}]", rows.join(","))),
    ]))
}
struct Fixture {
    root: PathBuf,
    file: PathBuf,
    pin: DatagramPin,
    text: String,
}
impl Fixture {
    fn new(name: &str, data: &[Observation], rows: &[String]) -> Test<Self> {
        let parent = fresh(&format!("cli-{name}"))?;
        std::fs::create_dir_all(&parent)?;
        let root = parent.join("source");
        let pin = save(&root, data)?;
        let file = parent.join("draft.json");
        let text = draft(pin, rows)?;
        std::fs::write(&file, &text)?;
        Ok(Self {
            root,
            file,
            pin,
            text,
        })
    }
    fn args(&self) -> Vec<String> {
        vec![
            "author-hevc-recipe".into(),
            "--root".into(),
            self.root.to_string_lossy().into_owned(),
            "--draft".into(),
            self.file.to_string_lossy().into_owned(),
            "--draft-id".into(),
            ContentDigest::sha256(self.text.as_bytes()).to_text(),
            "--max-object-bytes".into(),
            "2097152".into(),
        ]
    }
    fn call(&self, extra: &[&str]) -> Test<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-archive"))
            .args(self.args())
            .args(extra)
            .output()?)
    }
    fn changed(&mut self, text: String) -> Test {
        self.text = text;
        std::fs::write(&self.file, &self.text)?;
        Ok(())
    }
    fn roots(&self) -> Test<usize> {
        Ok(LocalRootPublisher::open(&self.root, storage())?
            .visible_roots()
            .count())
    }
}
fn parsed(out: &Output) -> Test<Value> {
    if !out.status.success() {
        return Err(format!("process failure: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    Ok(json_input::parse(std::str::from_utf8(&out.stdout)?)?)
}
fn v<'a>(o: &'a Value, k: &str) -> Test<&'a Value> {
    o.object()
        .and_then(|m| m.get(k))
        .ok_or_else(|| "missing report field".into())
}
fn text<'a>(o: &'a Value, k: &str) -> Test<&'a str> {
    v(o, k)?.text().ok_or_else(|| "report text".into())
}
fn number(o: &Value, k: &str) -> Test<u64> {
    Ok(u64::try_from(v(o, k)?.integer().ok_or("report integer")?)?)
}
fn boolean(o: &Value, k: &str) -> Test<bool> {
    v(o, k)?.boolean().ok_or_else(|| "report bool".into())
}
fn refused(out: &Output) {
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}
fn recipe_pin(report: &Value, source: DatagramPin) -> Test<RecordingRecipePin> {
    Ok(RecordingRecipePin {
        slot: fss_publication::SlotName::parse(text(report, "recipe_slot")?)?,
        root: ContentDigest::parse(text(report, "recipe_root")?)?,
        recipe: ContentDigest::parse(text(report, "recipe")?)?,
        source,
    })
}
fn replay(f: &Fixture, report: &Value) -> Test<Vec<PreparedHevcRecording>> {
    let p = LocalRootPublisher::open(&f.root, storage())?;
    let prefix = DatagramPrefix::recover(&p, scope()?, limits(), f.pin, &NeverCancel, &mut work())?;
    let pin = recipe_pin(report, f.pin)?;
    let recipe = load_recording_recipe(
        &p,
        &pin,
        prefix.archive(),
        RecordingRecipeLimits::default(),
        RecipeStorageLimits::default(),
        &NeverCancel,
        &mut work(),
    )?;
    let mut driver = PlannedRecordingReplay::new(
        &recipe,
        prefix.archive(),
        RecordingRecipeLimits::default(),
        bounds(),
        0,
    )?;
    let mut output = Vec::new();
    let mut budget = work();
    for _ in 0..2048 {
        match driver.step(&p, 0, &NeverCancel, &mut budget)? {
            RecipeReplayStep::Replay(HevcRecordingReplayStep::Capture(e)) => {
                if let HevcCapturePoll::Window(w) = *e {
                    output.push(*w);
                }
            }
            RecipeReplayStep::Replay(HevcRecordingReplayStep::FinishedPrefix { .. }) => {
                return Ok(output);
            }
            RecipeReplayStep::Replay(HevcRecordingReplayStep::Stopped { .. })
            | RecipeReplayStep::Ended => return Err("authored recipe stopped".into()),
            _ => {}
        }
    }
    Err("replay allowance".into())
}
#[test]
fn preview_then_approved_publication_and_exact_retry_use_existing_canonical_recipe() -> Test {
    for fragmented in [false, true] {
        let f = Fixture::new(
            &format!("roundtrip-{fragmented}"),
            &data(fragmented, false)?,
            &[row(0)],
        )?;
        let before = f.roots()?;
        let preview = parsed(&f.call(&[])?)?;
        assert_eq!(text(&preview, "recipe_status")?, "not_requested");
        assert!(!boolean(&preview, "publication_requested")?);
        assert!(!boolean(&preview, "capture_complete")?);
        assert!(!boolean(&preview, "recording_published")?);
        assert_eq!(number(&preview, "preview_pictures")?, 1);
        assert_eq!(number(&preview, "timings_applied")?, 1);
        assert_eq!(f.roots()?, before);
        let id = text(&preview, "recipe")?;
        let publication = f.call(&["--commit", "yes", "--approve-recipe", id])?;
        std::fs::write(
            f.root
                .parent()
                .ok_or("parent")?
                .join("published-report.json"),
            &publication.stdout,
        )?;
        let published = parsed(&publication)?;
        assert_eq!(text(&published, "recipe_status")?, "published");
        assert_eq!(
            text(&published, "recipe_root")?,
            text(&preview, "recipe_root")?
        );
        assert_eq!(f.roots()?, before + 1);
        let retry = f.call(&["--commit", "yes", "--approve-recipe", id])?;
        std::fs::write(
            f.root.parent().ok_or("parent")?.join("retry-report.json"),
            &retry.stdout,
        )?;
        let retried = parsed(&retry)?;
        assert_eq!(text(&retried, "recipe_status")?, "already_durable");
        assert_eq!(f.roots()?, before + 1);
        let windows = replay(&f, &published)?;
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].samples().len(), 1);
        assert_eq!(windows[0].source_only_nals(), 1);
        std::fs::write(
            f.root.parent().ok_or("parent")?.join("preview-report.json"),
            f.call(&[])?.stdout,
        )?;
    }
    Ok(())
}
#[test]
fn wrong_approval_or_stale_draft_cannot_publish_and_stale_draft_does_not_open_source() -> Test {
    let f = Fixture::new("stale", &data(false, false)?, &[row(0)])?;
    let before = f.roots()?;
    let wrong = ContentDigest::sha256(b"not an approved recipe").to_text();
    refused(&f.call(&["--commit", "yes", "--approve-recipe", &wrong])?);
    assert_eq!(f.roots()?, before);
    std::fs::write(&f.file, format!("{} ", f.text))?;
    let absent = f.root.with_file_name("must-not-create");
    let mut args = f.args();
    args[2] = absent.to_string_lossy().into_owned();
    let out = Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .args(args)
        .output()?;
    refused(&out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("draft differs"));
    assert!(!absent.exists());
    Ok(())
}
#[test]
fn strict_input_refuses_unknown_duplicate_numeric_and_parameter_substitution() -> Test {
    let mut f = Fixture::new("strict", &data(false, false)?, &[row(0)])?;
    let original = f.text.clone();
    let before = f.roots()?;
    let bad = [
        original.replacen("\"schema\":", "\"unexpected\":true,\"schema\":", 1),
        original.replacen("\"generation\":1", "\"generation\":1,\"generation\":1", 1),
        original.replacen("\"decode_time\":0", "\"decode_time\":\"0\"", 1),
        original.replacen("\"duration\":18000", "\"duration\":1.8e4", 1),
        original.replacen("\"duration\":18000", "\"duration\":0", 1),
        original.replacen("\"sprop_max_don_diff\":0", "\"sprop_max_don_diff\":1", 1),
        original.replacen("\"pps_hex\":\"", "\"pps_hex\":\"xx", 1),
        original.replacen("\"ingress\":\"73\"", "\"ingress\":\"073\"", 1),
        format!("{original} false"),
    ];
    for bytes in bad {
        assert_ne!(bytes, original);
        f.changed(bytes)?;
        let out = f.call(&[])?;
        refused(&out);
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(f.roots()?, before);
    }
    Ok(())
}
#[test]
fn missing_extra_wrong_timestamp_and_native_loss_refuse_without_any_new_root() -> Test {
    let mut f = Fixture::new("bad-timing", &data(false, false)?, &[row(0)])?;
    let before = f.roots()?;
    for rows in [vec![], vec![row(0), row(1)], vec![row(1)]] {
        f.changed(draft(f.pin, &rows)?)?;
        refused(&f.call(&[])?);
        assert_eq!(f.roots()?, before);
    }
    let mut corrupted = data(false, false)?;
    corrupted.push((0, 100, vec![0]));
    let g = Fixture::new("native-refusal", &corrupted, &[row(0)])?;
    let before = g.roots()?;
    refused(&g.call(&[])?);
    assert_eq!(g.roots()?, before);
    Ok(())
}
#[test]
fn operation_and_output_bounds_are_not_replenished_by_authoring() -> Test {
    let f = Fixture::new("bounded", &data(false, true)?, &[row(0), row(1)])?;
    let before = f.roots()?;
    for bound in [
        "--max-steps",
        "--max-work",
        "--max-draft-bytes",
        "--max-source-bytes",
        "--max-output-bytes",
        "--max-windows",
    ] {
        refused(&f.call(&[bound, "1"])?);
        assert_eq!(f.roots()?, before);
    }
    refused(&f.call(&["--max-timings", "0"])?);
    assert_eq!(f.roots()?, before);
    Ok(())
}
#[test]
fn recipe_uses_exact_older_prefix_while_verifying_later_source_chain() -> Test {
    let f = Fixture::new("prefix", &data(false, false)?, &[row(0)])?;
    let preview = parsed(&f.call(&[])?)?;
    {
        let (mut p, mut a) = reopen(&f.root, f.pin)?;
        append(&mut p, &mut a, &[(1, 50, vec![0, 0, 0])])?;
    }
    let later = parsed(&f.call(&[])?)?;
    assert_eq!(text(&preview, "recipe")?, text(&later, "recipe")?);
    assert_eq!(number(&later, "source_datagrams")?, f.pin.datagrams);
    assert_eq!(
        number(&later, "observed_source_datagrams_at_load")?,
        f.pin.datagrams + 1
    );
    let published = parsed(&f.call(&[
        "--commit",
        "yes",
        "--approve-recipe",
        text(&preview, "recipe")?,
    ])?)?;
    assert_eq!(replay(&f, &published)?.len(), 1);
    Ok(())
}
#[test]
fn real_eob_and_incomplete_fragment_have_distinct_reports() -> Test {
    let f = Fixture::new("eob", &data(false, true)?, &[row(0), row(1)])?;
    let report = parsed(&f.call(&[])?)?;
    assert!(boolean(&report, "end_of_bitstream")?);
    assert_eq!(number(&report, "remaining_datagrams")?, 1);
    assert_eq!(number(&report, "preview_pictures")?, 2);
    assert!(!boolean(&report, "capture_complete")?);
    let data = observations(true)?;
    let g = Fixture::new("fragment", &data[..2], &[])?;
    let report = parsed(&g.call(&[])?)?;
    assert!(!boolean(&report, "end_of_bitstream")?);
    assert_eq!(number(&report, "preview_windows")?, 0);
    assert_eq!(number(&report, "timings_applied")?, 0);
    assert!(number(&report, "fragment_bytes")? > 0);
    assert!(!boolean(&report, "capture_complete")?);
    let h = Fixture::new("empty", &[], &[])?;
    let report = parsed(&h.call(&[])?)?;
    assert_eq!(number(&report, "preview_windows")?, 0);
    assert_eq!(number(&report, "source_datagrams")?, 0);
    assert!(!boolean(&report, "end_of_bitstream")?);
    Ok(())
}
#[test]
fn corrupt_required_original_refuses_recipe_authoring() -> Test {
    let f = Fixture::new("corrupt", &data(false, false)?, &[row(0)])?;
    let record = {
        let (_, a) = reopen(&f.root, f.pin)?;
        a.records()[1].clone()
    };
    let digest = record.payload_digest.to_text();
    let path = f
        .root
        .join("spool/objects")
        .join(digest.strip_prefix("sha256:").ok_or("digest")?);
    assert!(path.exists(), "fixture object path");
    std::fs::write(path, b"corrupt original")?;
    refused(&f.call(&[])?);
    Ok(())
}
#[test]
fn publication_is_explicit_and_options_are_not_silently_ignored() -> Test {
    let f = Fixture::new("options", &data(false, false)?, &[row(0)])?;
    for options in [
        vec!["--commit", "yes"],
        vec!["--commit", "no"],
        vec!["--approve-recipe", "sha256:00"],
        vec!["--wat", "1"],
        vec!["--max-steps", "1", "--max-steps", "2"],
        vec!["--max-steps"],
        vec!["--max-steps", "--max-work", "10"],
    ] {
        let out = f.call(&options)?;
        refused(&out);
        assert_eq!(out.status.code(), Some(2));
    }
    Ok(())
}
#[test]
fn draft_and_source_symlinks_are_refused_without_following_them() -> Test {
    use std::os::unix::fs::symlink;
    let f = Fixture::new("symlinks", &data(false, false)?, &[row(0)])?;
    let backup = f.file.with_extension("original");
    std::fs::rename(&f.file, &backup)?;
    symlink(&backup, &f.file)?;
    refused(&f.call(&[])?);
    std::fs::remove_file(&f.file)?;
    std::fs::rename(&backup, &f.file)?;
    let alias = f.root.with_file_name("alias");
    symlink(&f.root, &alias)?;
    let mut args = f.args();
    args[2] = alias.to_string_lossy().into_owned();
    refused(
        &Command::new(env!("CARGO_BIN_EXE_fss-archive"))
            .args(args)
            .output()?,
    );
    Ok(())
}
