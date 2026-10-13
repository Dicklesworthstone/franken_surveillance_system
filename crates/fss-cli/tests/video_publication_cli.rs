#![forbid(unsafe_code)]
//! Real processes, retained native codec fixtures, independent source/pixel and privacy checks.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:native-video-cli";
const SENSOR: &str = "sensor:native-video-cli";
const AVC: &[u8] = include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] = include_bytes!("../../fss-codec-h265/tests/fixtures/decode/f_qcif_default.h265");

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-video-cli-{}-{label}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:video-cli-test".into(), operation_id: OperationId::parse("operation:video-cli-test")?,
        principal: "principal:video-cli-test".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).storage_operations(65_536).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
struct Fixture { directory: Directory, root: PathBuf, identity: ContentDigest, codec: &'static str }
impl Fixture {
    fn new(codec: &'static str) -> Test<Self> {
        let directory = Directory::new(codec)?;
        let root = directory.0.join("deployment");
        let source = directory.0.join("input");
        fs::write(&source, if codec == "avc" { AVC } else { HEVC })?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut request = FileIngestRequest::new(source.clone(), SensorId::parse(SENSOR)?, StreamId::parse("stream:video-cli")?)
            .with_receive_time(TimestampNs(1_000_000_000));
        request.format_hint = Some(if codec == "avc" { FileFormatHint::AnnexB } else { FileFormatHint::Hevc });
        let identity = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
        drop(deployment); cx.drain_and_finalize();
        fs::remove_file(source)?;
        Ok(Self { directory, root, identity, codec })
    }
    fn args(&self, command: &str) -> Vec<OsString> {
        let mut args = vec![command.into()];
        for (key, value) in [
            ("--root", self.root.as_os_str().to_owned()), ("--site", SITE.into()),
            ("--import-id", self.identity.to_text().into()), ("--codec", self.codec.into()),
            ("--privacy-policy", "none".into()), ("--read-originals", "yes".into()),
            ("--max-dimension", "176".into()), ("--max-pixels", "25344".into()),
        ] { args.extend([key.into(), value]); }
        args
    }
    fn publish(&self, count: usize) -> Vec<OsString> {
        let mut args = self.args("publish");
        for (key, value) in [("--retain-derived", "yes".to_owned()), ("--first-segment", "0".into()),
                             ("--segment-count", count.to_string())] { args.extend([key.into(), value.into()]); }
        args
    }
    fn read(&self, command: &str, root: &str) -> Vec<OsString> {
        let mut args = self.args(command); args.extend(["--frame-root".into(), root.into()]); args
    }
    fn journals(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((fs::read(self.root.join("ledger/journal.fssj"))?, fs::read(self.root.join("effects/journal.fssj"))?))
    }
    fn mask(&self, rectangles: &[[u32; 4]]) -> Test<ContentDigest> {
        let cx = context(&self.root)?;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &cx)?;
        let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [176, 144], rectangles)?;
        let preview = preview_mask(&deployment, &policy)?;
        let declared = declare_mask(&mut deployment, &policy, preview.approval, &cx)?;
        drop(deployment); cx.drain_and_finalize();
        Ok(declared.policy_digest)
    }
}

fn read_output(reader: impl Read, exceeded: &AtomicBool) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        exceeded.store(true, Ordering::Release);
        return Err(io::Error::other("test output bound exceeded"));
    }
    Ok(bytes)
}
fn run(args: &[OsString]) -> Test<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-video"))
        .args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let stdout = child.stdout.take().ok_or("stdout")?;
    let stderr = child.stderr.take().ok_or("stderr")?;
    let exceeded = AtomicBool::new(false);
    thread::scope(|scope| {
        let out = scope.spawn(|| read_output(stdout, &exceeded));
        let err = scope.spawn(|| read_output(stderr, &exceeded));
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if exceeded.load(Ordering::Acquire) || Instant::now() >= deadline {
                let _ = child.kill(); let _ = child.wait();
                break Err(io::Error::other("native process exceeded bound"));
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(Duration::from_millis(2)),
                Err(e) => { let _ = child.kill(); let _ = child.wait(); break Err(e); }
            }
        };
        let stdout = out.join().map_err(|_| "stdout thread")??;
        let stderr = err.join().map_err(|_| "stderr thread")??;
        Ok(Output { status: status?, stdout, stderr })
    })
}
fn good(args: &[OsString]) -> Test<Output> {
    let out = run(args)?;
    assert!(out.status.success(), "{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.stderr.is_empty());
    Ok(out)
}
fn field<'a>(v: &'a Value, key: &str) -> Test<&'a Value> {
    v.object().and_then(|m| m.get(key)).ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(v: &'a Value, key: &str) -> Test<&'a str> { field(v, key)?.text().ok_or_else(|| format!("nontext {key}").into()) }
fn number(v: &Value, key: &str) -> Test<i128> { field(v, key)?.integer().ok_or_else(|| format!("noninteger {key}").into()) }
fn flag(v: &Value, key: &str) -> Test<bool> { field(v, key)?.boolean().ok_or_else(|| format!("nonboolean {key}").into()) }
fn approved(args: &[OsString]) -> Test<Vec<OsString>> {
    let preview = parse(std::str::from_utf8(&good(args)?.stdout)?)?;
    assert_eq!(text(&preview, "phase")?, "planned");
    let mut args = args.to_vec(); args.extend(["--approve".into(), text(&preview, "approval")?.into()]); Ok(args)
}
fn rows(out: &Output) -> Test<Vec<Value>> {
    let mut rows = Vec::new();
    for (n, line) in std::str::from_utf8(&out.stdout)?.lines().enumerate() {
        let row = parse(line)?;
        assert_eq!(text(&row, "schema")?, "fss.native_video_cli.v1");
        assert_eq!(number(&row, "sequence")?, n as i128);
        rows.push(row);
    }
    Ok(rows)
}
fn details<'a>(rows: &'a [Value], kind: &str) -> Test<Vec<&'a Value>> {
    let mut selected = Vec::new();
    for row in rows { if text(row, "kind")? == kind { selected.push(field(row, "detail")?); } }
    Ok(selected)
}
fn set(args: &mut Vec<OsString>, key: &str, value: impl Into<OsString>) {
    if let Some(index) = args.iter().position(|arg| arg == key) { args[index + 1] = value.into(); }
    else { args.extend([key.into(), value.into()]); }
}
fn refuse(args: &[OsString]) -> Test<Output> {
    let out = run(args)?;
    assert!(!out.status.success(), "unexpected success: {}", String::from_utf8_lossy(&out.stdout));
    assert!(details(&rows(&out)?, "terminal")?.is_empty(), "refusal claimed completion");
    Ok(out)
}

#[test]
fn pure_preview_and_wrong_approval_never_create_a_deployment() -> Test {
    let fixture = Fixture::new("avc")?;
    let mut args = fixture.publish(3);
    let missing = fixture.directory.0.join("uncreated");
    set(&mut args, "--root", missing.as_os_str());
    let approved = approved(&args)?;
    assert!(!missing.exists());
    let mut wrong = approved.clone(); set(&mut wrong, "--approve", ContentDigest::sha256(b"wrong plan").to_text());
    assert!(refuse(&wrong)?.stdout.is_empty());
    assert!(refuse(&approved)?.stdout.is_empty());
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn native_avc_and_hevc_publications_survive_cold_read_and_full_replay_without_duplicate_authority() -> Test {
    for (codec, count) in [("avc", 3), ("hevc", 8)] {
        let fixture = Fixture::new(codec)?;
        let args = approved(&fixture.publish(count))?;
        let before = fixture.journals()?;
        let published = rows(&good(&args)?)?;
        let frames = details(&published, "frame")?;
        assert_eq!(frames.len(), count);
        let roots = frames.iter().map(|f| text(f, "frame_root").map(str::to_owned)).collect::<Test<Vec<_>>>()?;
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(number(frame, "output_index")?, index as i128);
            assert_eq!(number(frame, "range_segment_count")?, count as i128);
            assert!(!flag(frame, "absence_certifiable")?);
        }
        if codec == "hevc" {
            let segments = frames.iter().map(|f| number(f, "segment")).collect::<Test<Vec<_>>>()?;
            assert!(segments.windows(2).any(|p| p[1] < p[0]), "fixture did not exercise display reordering");
        }
        let saved = fixture.journals()?;
        assert_ne!(saved.0, before.0); assert_eq!(saved.1, before.1);
        let retried = rows(&good(&args)?)?;
        let repeated = details(&retried, "frame")?;
        for (index, frame) in repeated.iter().enumerate() {
            assert_eq!(text(frame, "frame_root")?, roots[index]);
            assert_eq!(number(frame, "completion_sequence")?, number(frames[index], "completion_sequence")?);
        }
        assert_eq!(fixture.journals()?, saved);
        for command in ["read", "verify"] {
            let read = rows(&good(&approved(&fixture.read(command, &roots[0]))?)?)?;
            let terminal = details(&read, "terminal")?;
            assert_eq!(flag(terminal[0], "replay_verified")?, command == "verify");
            assert_eq!(number(terminal[0], "frames_decoded")?, if command == "verify" { count as i128 } else { 0 });
            assert_eq!(text(details(&read, "frame")?[0], "receipt_digest")?, text(frames[0], "receipt_digest")?);
            assert_eq!(fixture.journals()?, saved);
        }
    }
    Ok(())
}

#[test]
fn verify_must_drain_after_matching_the_first_frame_and_preserves_budget_refusal() -> Test {
    let fixture = Fixture::new("avc")?;
    // Independently price exactly the input needed to return the FIRST display output of
    // this same three-segment range. This is not the price of a different one-segment decode.
    use fss_reference::ingest::recorded_decode::h264::{DecoderLimits, RecordedH264Range, RecordedH264Request};
    use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
    use fss_reference::ingest::recorded_decode::ComponentInterpretation;
    let cx = context(&fixture.root)?;
    let deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let mut budget = RecordedVideoDecodeBudget::new(8_000_000_000);
    let mut range = RecordedH264Range::open_with_budget(&deployment, RecordedH264Request {
        import_identity: fixture.identity, first_segment: 0, segment_count: 3,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: fss_reference::ingest::RetainedReadLimits::default(),
        decoder_limits: DecoderLimits {
            max_width: 176, max_height: 176, max_macroblocks: 99, max_pictures: 3,
            max_nal_bytes: 16 * 1024 * 1024, max_slices_per_picture: 4096, ..DecoderLimits::default()
        },
    }, &mut budget, &cx)?;
    assert_eq!(range.next_frame_with_budget(&deployment, &mut budget, &cx)?.ok_or("first native output")?.output_index(), 0);
    let one_frame_work = budget.used();
    drop(range); drop(deployment); cx.drain_and_finalize();
    let all = rows(&good(&approved(&fixture.publish(3))?)?)?;
    assert!((one_frame_work as i128) < number(details(&all, "terminal")?[0], "decode_work_units")?,
            "fixture must discriminate full replay from early success");
    let root = text(details(&all, "frame")?[0], "frame_root")?;
    let saved = fixture.journals()?;
    let mut verify = fixture.read("verify", root);
    set(&mut verify, "--work-units", one_frame_work.to_string());
    let out = refuse(&approved(&verify)?)?;
    assert!(details(&rows(&out)?, "frame")?.is_empty());
    assert_eq!(fixture.journals()?, saved);
    set(&mut verify, "--work-units", "8000000000");
    assert!(flag(details(&rows(&good(&approved(&verify)?)?)?, "terminal")?[0], "replay_verified")?);
    assert_eq!(fixture.journals()?, saved);
    Ok(())
}

#[test]
fn insufficient_derived_budget_preserves_prefix_and_counts_completed_reuse() -> Test {
    let fixture = Fixture::new("avc")?;
    let one = rows(&good(&approved(&fixture.publish(1))?)?)?;
    let quote = number(details(&one, "terminal")?[0], "charged_derived_bytes")?;
    let mut args = fixture.publish(3);
    set(&mut args, "--max-derived-bytes", quote.to_string());
    let out = refuse(&approved(&args)?)?;
    let partial = rows(&out)?;
    assert_eq!(details(&partial, "frame")?.len(), 1);
    let root = text(details(&partial, "frame")?[0], "frame_root")?;
    good(&approved(&fixture.read("read", root))?)?;
    let saved = fixture.journals()?;
    refuse(&approved(&args)?)?;
    assert_eq!(fixture.journals()?, saved, "refused reuse appended authority");
    set(&mut args, "--max-derived-bytes", "67108864");
    let complete = rows(&good(&approved(&args)?)?)?;
    assert_eq!(details(&complete, "frame")?.len(), 3);
    assert_eq!(text(details(&complete, "frame")?[0], "frame_root")?, root);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn read_refuses_cross_import_codec_privacy_and_narrowed_bounds_before_export() -> Test {
    let fixture = Fixture::new("avc")?;
    let published = rows(&good(&approved(&fixture.publish(3))?)?)?;
    let root = text(details(&published, "frame")?[0], "frame_root")?;
    let saved = fixture.journals()?;
    for (key, value) in [("--import-id", ContentDigest::sha256(b"other import").to_text()),
        ("--codec", "hevc".into()), ("--privacy-policy", ContentDigest::sha256(b"other policy").to_text()),
        ("--max-pixels", "1".into()), ("--max-dimension", "16".into()), ("--max-source-bytes", "1".into())] {
        let mut read = fixture.read("read", root); set(&mut read, key, value);
        let output = fixture.directory.0.join("refused-pixels");
        set(&mut read, "--output", output.as_os_str()); set(&mut read, "--pixel-format", "i420");
        let out = refuse(&approved(&read)?)?;
        assert!(details(&rows(&out)?, "frame")?.is_empty());
        assert!(!output.exists()); assert_eq!(fixture.journals()?, saved);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn stale_privacy_refuses_old_roots_and_new_publications_export_masked_luma_chroma_and_rgb() -> Test {
    let fixture = Fixture::new("hevc")?;
    let unmasked = rows(&good(&approved(&fixture.publish(3))?)?)?;
    let old_root = text(details(&unmasked, "frame")?[0], "frame_root")?;
    let policy = fixture.mask(&[[0, 0, 176, 144]])?;
    let saved = fixture.journals()?;
    refuse(&approved(&fixture.read("read", old_root))?)?;
    let mut old = fixture.read("read", old_root); set(&mut old, "--privacy-policy", policy.to_text());
    refuse(&approved(&old)?)?;
    refuse(&approved(&fixture.publish(3))?)?;
    assert_eq!(fixture.journals()?, saved);
    let mut publish = fixture.publish(3); set(&mut publish, "--privacy-policy", policy.to_text());
    let masked = rows(&good(&approved(&publish)?)?)?;
    let root = text(details(&masked, "frame")?[0], "frame_root")?;
    assert_ne!(root, old_root);
    let saved = fixture.journals()?;
    for format in ["pgm", "i420", "rgb"] {
        let output = fixture.directory.0.join(format!("pixels.{format}"));
        let mut read = fixture.read("read", root);
        set(&mut read, "--privacy-policy", policy.to_text());
        set(&mut read, "--output", output.as_os_str()); set(&mut read, "--pixel-format", format);
        let args = approved(&read)?;
        good(&args)?;
        let bytes = fs::read(&output)?;
        match format {
            "pgm" => { let mut expected = b"P5\n176 144\n255\n".to_vec(); expected.extend(vec![16; 176 * 144]); assert_eq!(bytes, expected); }
            "i420" => { assert_eq!(bytes.len(), 176 * 144 * 3 / 2); assert!(bytes[..176 * 144].iter().all(|n| *n == 16)); assert!(bytes[176 * 144..].iter().all(|n| *n == 128)); }
            "rgb" => assert_eq!(bytes, vec![16; 176 * 144 * 3]),
            _ => return Err("invalid test format".into()),
        }
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o600); }
        refuse(&args)?;
        assert_eq!(fs::read(output)?, bytes, "export overwrote an existing file");
        assert_eq!(fixture.journals()?, saved);
    }
    let mut verify = fixture.read("verify", root); set(&mut verify, "--privacy-policy", policy.to_text());
    good(&approved(&verify)?)?;
    assert_eq!(fixture.journals()?, saved);
    Ok(())
}

#[test]
fn corrupt_completed_pixels_are_neither_exported_nor_repaired_on_republication() -> Test {
    let fixture = Fixture::new("avc")?;
    let publish = approved(&fixture.publish(3))?;
    let data = rows(&good(&publish)?)?;
    let frame = details(&data, "frame")?[0];
    let root = text(frame, "frame_root")?;
    let digest = ContentDigest::parse(text(frame, "i420_digest")?)?;
    let hex = digest.bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();
    let path = fixture.root.join("objects/spool/objects").join(hex);
    let mut bytes = fs::read(&path)?;
    let last = bytes.len() - 1; bytes[last] ^= 1; fs::write(&path, &bytes)?;
    let saved = fixture.journals()?;
    for command in ["read", "verify"] { refuse(&approved(&fixture.read(command, root))?)?; }
    refuse(&publish)?;
    assert_eq!(fs::read(path)?, bytes);
    assert_eq!(fixture.journals()?, saved);
    Ok(())
}

#[test]
fn retained_source_damage_invalidates_cold_pixels_and_exact_publication_without_repair() -> Test {
    let fixture = Fixture::new("hevc")?;
    let publish = approved(&fixture.publish(8))?;
    let result = rows(&good(&publish)?)?;
    let root = text(details(&result, "frame")?[0], "frame_root")?;
    let source_digest = ContentDigest::sha256(HEVC);
    let path = fixture.root.join("objects/spool/objects").join(
        source_digest.bytes().iter().map(|b| format!("{b:02x}")).collect::<String>());
    let mut damaged = fs::read(&path)?;
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    fs::write(&path, &damaged)?;
    let saved = fixture.journals()?;
    for command in ["read", "verify"] {
        let refused = refuse(&approved(&fixture.read(command, root))?)?;
        assert!(details(&rows(&refused)?, "frame")?.is_empty());
    }
    refuse(&publish)?;
    assert_eq!(fs::read(path)?, damaged);
    assert_eq!(fixture.journals()?, saved);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn export_cannot_follow_a_deployment_alias_or_replace_a_symlink() -> Test {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new("avc")?;
    let result = rows(&good(&approved(&fixture.publish(1))?)?)?;
    let root = text(details(&result, "frame")?[0], "frame_root")?;
    let alias = fixture.directory.0.join("custody-alias");
    symlink(&fixture.root, &alias)?;
    let mut request = fixture.read("read", root);
    set(&mut request, "--output", alias.join("forbidden-pixels").into_os_string());
    set(&mut request, "--pixel-format", "pgm");
    let saved = fixture.journals()?;
    let refused = refuse(&approved(&request)?)?;
    assert!(refused.stdout.is_empty());
    assert!(!fixture.root.join("forbidden-pixels").exists());
    let target = fixture.directory.0.join("existing-target");
    fs::write(&target, b"preserve original")?;
    let link = fixture.directory.0.join("output-link");
    symlink(&target, &link)?;
    set(&mut request, "--output", link.into_os_string());
    assert!(refuse(&approved(&request)?)?.stdout.is_empty());
    assert_eq!(fs::read(target)?, b"preserve original");
    assert_eq!(fixture.journals()?, saved);
    Ok(())
}
