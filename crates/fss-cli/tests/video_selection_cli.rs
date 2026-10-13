#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Separate native CLI processes, real AVC/HEVC, exact frame identity and fail-closed selection.

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Seek};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:video-selection-cli";
const AVC: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] =
    include_bytes!("../../fss-codec-h265/tests/fixtures/decode/f_qcif_default.h265");

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for index in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-video-selection-{label}-{}-{index}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory allowance exhausted".into())
    }
    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run_command(command: &mut Command) -> Test<Output> {
    let directory = Directory::new("process-output")?;
    let file = |name: &str| {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.0.join(name))
    };
    let mut stdout = file("stdout")?;
    let mut stderr = file("stderr")?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?))
        .spawn()?;
    let result = (|| -> Test<Output> {
        const LIMIT: u64 = 4 * 1024 * 1024;
        let start = Instant::now();
        let status = loop {
            if start.elapsed() >= Duration::from_secs(30)
                || stdout.metadata()?.len() > LIMIT
                || stderr.metadata()?.len() > LIMIT
            {
                return Err("native test process exceeded output or lifetime bound".into());
            }
            if let Some(status) = child.try_wait()? {
                break status;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        let read = |file: &mut fs::File| -> Test<Vec<u8>> {
            file.rewind()?;
            let mut bytes = Vec::new();
            file.take(LIMIT + 1).read_to_end(&mut bytes)?;
            if bytes.len() > LIMIT as usize {
                return Err("native output limit".into());
            }
            Ok(bytes)
        };
        Ok(Output {
            status,
            stdout: read(&mut stdout)?,
            stderr: read(&mut stderr)?,
        })
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let reaped = child.wait();
    reaped?;
    result
}
fn raw(args: &[OsString]) -> Test<Output> {
    run_command(Command::new(env!("CARGO_BIN_EXE_fss-video")).args(args))
}
fn successful(output: Output) -> Test<Vec<u8>> {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    Ok(output.stdout)
}
fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|map| map.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| format!("nontext {key}").into())
}
fn number(value: &Value, key: &str) -> Test<u64> {
    Ok(u64::try_from(
        field(value, key)?.integer().ok_or("integer required")?,
    )?)
}
fn flag(value: &Value, key: &str) -> Test<bool> {
    field(value, key)?
        .boolean()
        .ok_or_else(|| format!("nonboolean {key}").into())
}
fn details<'a>(rows: &'a [Value], kind: &str) -> Test<Vec<&'a Value>> {
    let mut result = Vec::new();
    for row in rows {
        if text(row, "kind")? == kind {
            result.push(field(row, "detail")?);
        }
    }
    Ok(result)
}
fn only<'a>(rows: &'a [Value], kind: &str) -> Test<&'a Value> {
    let values = details(rows, kind)?;
    if values.len() != 1 {
        return Err(format!("expected one {kind}, got {}", values.len()).into());
    }
    Ok(values[0])
}
fn preview(args: &[OsString]) -> Test<Value> {
    let bytes = successful(raw(args)?)?;
    Ok(parse(std::str::from_utf8(&bytes)?)?)
}
fn approved(args: &[OsString]) -> Test<Vec<OsString>> {
    let plan = preview(args)?;
    let mut result = args.to_vec();
    result.extend(["--approve".into(), text(&plan, "approval")?.into()]);
    Ok(result)
}
fn execute(args: &[OsString]) -> Test<Vec<Value>> {
    let bytes = successful(raw(&approved(args)?)?)?;
    let rows: Vec<Value> = std::str::from_utf8(&bytes)?
        .lines()
        .map(parse)
        .collect::<Result<_, _>>()?;
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(text(row, "schema")?, "fss.native_video_cli.v1");
        assert_eq!(number(row, "sequence")?, index as u64);
    }
    assert_eq!(text(rows.last().ok_or("no terminal")?, "kind")?, "terminal");
    assert!(flag(only(&rows, "terminal")?, "complete")?);
    Ok(rows)
}
fn refuse_without_frame(args: &[OsString]) -> Test {
    let output = raw(&approved(args)?)?;
    assert!(!output.status.success());
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let row = parse(line)?;
        assert_ne!(
            text(&row, "kind")?,
            "frame",
            "failure emitted a selected prefix"
        );
        assert_ne!(
            text(&row, "kind")?,
            "terminal",
            "failure reported completion"
        );
    }
    Ok(())
}
fn import(directory: &Directory, bytes: &[u8], format: &str, name: &str) -> Test<String> {
    let input = directory.0.join(format!("input-{name}"));
    fs::write(&input, bytes)?;
    let output = run_command(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .arg("import")
            .arg("--root")
            .arg(directory.root())
            .args(["--site", SITE, "--input"])
            .arg(&input)
            .args([
                "--sensor",
                &format!("sensor:{name}"),
                "--stream",
                &format!("stream:{name}"),
                "--receive-time-ns",
                "1000000000",
                "--media-format",
                format,
            ]),
    )?;
    let report = String::from_utf8(successful(output)?)?;
    let identities: Vec<_> = report
        .lines()
        .filter_map(|s| s.strip_prefix("import_identity="))
        .collect();
    assert_eq!(identities.len(), 1);
    fs::remove_file(input)?;
    Ok(identities[0].to_owned())
}
fn base(directory: &Directory, command: &str, identity: &str, codec: &str) -> Vec<OsString> {
    vec![
        command.into(),
        "--root".into(),
        directory.root().into_os_string(),
        "--site".into(),
        SITE.into(),
        "--import-id".into(),
        identity.into(),
        "--codec".into(),
        codec.into(),
        "--privacy-policy".into(),
        "none".into(),
        "--read-originals".into(),
        "yes".into(),
        "--max-pixels".into(),
        "25344".into(),
        "--max-dimension".into(),
        "176".into(),
    ]
}
fn publication(
    directory: &Directory,
    identity: &str,
    codec: &str,
    count: usize,
    index: Option<usize>,
) -> Vec<OsString> {
    let mut result = base(directory, "publish", identity, codec);
    result.extend([
        "--retain-derived".into(),
        "yes".into(),
        "--first-segment".into(),
        "0".into(),
        "--segment-count".into(),
        count.to_string().into(),
    ]);
    if let Some(index) = index {
        result.extend(["--output-index".into(), index.to_string().into()]);
    }
    result
}
fn stored(
    directory: &Directory,
    command: &str,
    identity: &str,
    codec: &str,
    root: &str,
) -> Vec<OsString> {
    let mut result = base(directory, command, identity, codec);
    result.extend(["--frame-root".into(), root.into()]);
    result
}
fn journals(directory: &Directory) -> Test<(Vec<u8>, Vec<u8>)> {
    Ok((
        fs::read(directory.root().join("ledger/journal.fssj"))?,
        fs::read(directory.root().join("effects/journal.fssj"))?,
    ))
}
fn roots(directory: &Directory) -> Test<BTreeMap<OsString, Vec<u8>>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(directory.root().join("objects/roots"))? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            result.insert(entry.file_name(), fs::read(entry.path())?);
        }
    }
    Ok(result)
}

#[test]
fn one_avc_or_hevc_frame_survives_cold_reads_replay_and_exact_retry() -> Test {
    for (bytes, format, codec, count) in [(AVC, "annexb", "avc", 3), (HEVC, "hevc", "hevc", 8)] {
        let directory = Directory::new(codec)?;
        let identity = import(&directory, bytes, format, "camera")?;
        let before = roots(&directory)?;
        let request = publication(&directory, &identity, codec, count, Some(1));
        let planned = preview(&request)?;
        assert_eq!(number(&planned, "maximum_frames_retained")?, 1);
        assert!(flag(
            &planned,
            "complete_range_required_before_publication"
        )?);
        assert_eq!(roots(&directory)?, before, "preview mutated custody");
        let published = execute(&request)?;
        let frame = only(&published, "frame")?;
        let root = text(frame, "frame_root")?;
        assert_eq!(number(frame, "output_index")?, 1);
        assert_eq!(number(frame, "range_segment_count")?, count as u64);
        assert_eq!(
            number(only(&published, "terminal")?, "frames_decoded")?,
            count as u64
        );
        assert!(!flag(
            only(&published, "selection")?,
            "range_publication_complete"
        )?);
        assert_eq!(
            roots(&directory)?.len(),
            before.len() + 1,
            "unselected frame roots were published"
        );
        let retained_journals = journals(&directory)?;
        let retained_roots = roots(&directory)?;
        let retried = execute(&request)?;
        assert_eq!(text(only(&retried, "frame")?, "frame_root")?, root);
        assert_eq!(journals(&directory)?, retained_journals);
        let output = directory.0.join("cold.i420");
        let mut read = stored(&directory, "read", &identity, codec, root);
        read.extend([
            "--output".into(),
            output.clone().into_os_string(),
            "--pixel-format".into(),
            "i420".into(),
        ]);
        let cold = execute(&read)?;
        assert_eq!(number(only(&cold, "terminal")?, "decode_work_units")?, 0);
        assert_eq!(
            ContentDigest::sha256(&fs::read(output)?).to_text(),
            text(frame, "i420_digest")?
        );
        let verified = execute(&stored(&directory, "verify", &identity, codec, root))?;
        assert!(flag(only(&verified, "terminal")?, "replay_verified")?);
        assert_eq!(
            text(only(&verified, "frame")?, "receipt_digest")?,
            text(frame, "receipt_digest")?
        );
        assert_eq!(journals(&directory)?, retained_journals);
        assert_eq!(roots(&directory)?, retained_roots);
    }
    Ok(())
}

#[test]
fn selected_hevc_position_reuses_the_unmodified_all_frame_identity_and_order() -> Test {
    let directory = Directory::new("hevc-order")?;
    let identity = import(&directory, HEVC, "hevc", "camera")?;
    let selected = execute(&publication(&directory, &identity, "hevc", 8, Some(2)))?;
    let all = execute(&publication(&directory, &identity, "hevc", 8, None))?;
    let frames = details(&all, "frame")?;
    assert_eq!(frames.len(), 8);
    let segments: Vec<_> = frames
        .iter()
        .map(|frame| number(frame, "segment"))
        .collect::<Test<_>>()?;
    assert!(segments.windows(2).any(|pair| pair[1] < pair[0]));
    let wanted = frames
        .iter()
        .find(|frame| number(frame, "output_index").ok() == Some(2))
        .ok_or("display position")?;
    assert_eq!(
        text(only(&selected, "frame")?, "frame_root")?,
        text(wanted, "frame_root")?
    );
    assert_eq!(
        text(only(&selected, "frame")?, "receipt_digest")?,
        text(wanted, "receipt_digest")?
    );
    assert!(
        details(&all, "selection")?.is_empty(),
        "legacy output changed"
    );
    assert!(
        number(only(&all, "terminal")?, "charged_derived_bytes")?
            > number(only(&selected, "terminal")?, "charged_derived_bytes")?
    );
    Ok(())
}

#[test]
fn late_decode_or_derived_refusal_publishes_nothing_and_approvals_are_not_interchangeable() -> Test
{
    let directory = Directory::new("ceilings")?;
    let identity = import(&directory, AVC, "annexb", "camera")?;
    let selected = publication(&directory, &identity, "avc", 3, Some(1));
    let existing = execute(&selected)?;
    let used = number(only(&existing, "terminal")?, "decode_work_units")?;
    let quote = number(only(&existing, "terminal")?, "charged_derived_bytes")?;
    assert!(used > 0 && quote > 0);
    let before_journals = journals(&directory)?;
    let before_roots = roots(&directory)?;
    for budget in [0, used - 1] {
        let mut request = publication(&directory, &identity, "avc", 3, Some(0));
        request.extend(["--work-units".into(), budget.to_string().into()]);
        refuse_without_frame(&request)?;
        assert_eq!(journals(&directory)?, before_journals);
        assert_eq!(roots(&directory)?, before_roots);
    }
    let mut insufficient = selected.clone();
    insufficient.extend(["--max-derived-bytes".into(), (quote - 1).to_string().into()]);
    refuse_without_frame(&insufficient)?;
    let mut exact = selected.clone();
    exact.extend(["--max-derived-bytes".into(), quote.to_string().into()]);
    assert_eq!(
        number(
            only(&execute(&exact)?, "terminal")?,
            "charged_derived_bytes"
        )?,
        quote
    );
    let all = publication(&directory, &identity, "avc", 3, None);
    let other = publication(&directory, &identity, "avc", 3, Some(0));
    for (target, source) in [(&selected, &all), (&all, &selected), (&selected, &other)] {
        let plan = preview(source)?;
        let mut wrong = (*target).clone();
        wrong.extend(["--approve".into(), text(&plan, "approval")?.into()]);
        let result = raw(&wrong)?;
        assert!(!result.status.success());
        assert!(
            result.stdout.is_empty(),
            "mismatched approval performed an operation"
        );
    }
    assert_eq!(journals(&directory)?, before_journals);
    assert_eq!(roots(&directory)?, before_roots);
    Ok(())
}

#[test]
fn damaged_selected_pixels_are_not_repaired_by_read_replay_or_publication_retry() -> Test {
    let directory = Directory::new("corruption")?;
    let identity = import(&directory, AVC, "annexb", "camera")?;
    let request = publication(&directory, &identity, "avc", 3, Some(1));
    let report = execute(&request)?;
    let frame = only(&report, "frame")?;
    let root = text(frame, "frame_root")?;
    let hex = text(frame, "i420_digest")?
        .strip_prefix("sha256:")
        .ok_or("SHA-256 pixels")?;
    let path = directory.root().join("objects/spool/objects").join(hex);
    let mut damaged = fs::read(&path)?;
    *damaged.last_mut().ok_or("empty object")? ^= 1;
    fs::write(&path, &damaged)?;
    let before_journals = journals(&directory)?;
    let before_roots = roots(&directory)?;
    for input in [
        stored(&directory, "read", &identity, "avc", root),
        stored(&directory, "verify", &identity, "avc", root),
        request,
    ] {
        refuse_without_frame(&input)?;
        assert_eq!(fs::read(&path)?, damaged);
        assert_eq!(journals(&directory)?, before_journals);
        assert_eq!(roots(&directory)?, before_roots);
    }
    Ok(())
}

// A synthetic, self-consistent wrong-pixel graph distinguishes retained consistency from
// recomputation by the actual native decoder. This does not alter any production verifier.
fn internally_consistent_wrong_pixels(directory: &Directory, root: &str) -> Test<ContentDigest> {
    use fss_core::region::{ContextAuthority, RootAuthoritySpec};
    use fss_core::{
        BatchId, BudgetVector, CanonicalDecode, EvidenceDelta, ObjectId, OperationId, Plane,
    };
    use fss_object::ObjectManifest;
    use fss_publication::SlotName;
    use fss_reference::ingest::video_publication::{PublishedVideoFrame, VideoPublicationLimits};
    use fss_reference::{ReferenceDeployment, ReplayCx};
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:synthetic-video-verifier-probe".into(),
        operation_id: OperationId::parse("operation:synthetic-video-verifier-probe")?,
        principal: "principal:video-test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:synthetic-fixture".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, directory.root())?;
    let result = (|| -> Test<ContentDigest> {
        let mut deployment = ReferenceDeployment::open(&directory.root(), SITE, &cx)?;
        let original = ContentDigest::parse(root)?;
        let frame = PublishedVideoFrame::open(
            &deployment,
            original,
            VideoPublicationLimits::default(),
            &cx,
        )?;
        let original_manifest = ObjectManifest::from_canonical_bytes(
            &deployment
                .publisher()
                .spool()
                .read_bounded(original, 4096)?,
        )?;
        let old_luma = ContentDigest::sha256(frame.pixels());
        let old_i420 = ContentDigest::sha256(frame.i420());
        let mut pixels = frame.i420().to_vec();
        *pixels.first_mut().ok_or("missing native pixels")? ^= 1;
        let new_luma = ContentDigest::sha256(&pixels[..frame.pixels().len()]);
        let new_i420 = ContentDigest::sha256(&pixels);
        let mut receipt = frame.codec_receipt().to_vec();
        for (old, new) in [(old_luma, new_luma), (old_i420, new_i420)] {
            let occurrences: Vec<_> = receipt
                .windows(32)
                .enumerate()
                .filter_map(|(at, bytes)| (bytes == old.bytes().as_slice()).then_some(at))
                .collect();
            assert_eq!(
                occurrences.len(),
                1,
                "synthetic receipt must have one exact target digest"
            );
            receipt[occurrences[0]..occurrences[0] + 32].copy_from_slice(&new.bytes());
        }
        let metadata = ContentDigest::sha256(&receipt);
        let mut children: std::collections::BTreeSet<_> = original_manifest
            .children()
            .iter()
            .copied()
            .filter(|digest| {
                *digest != old_i420 && Some(*digest) != original_manifest.metadata_digest()
            })
            .collect();
        children.insert(new_i420);
        let manifest = ObjectManifest::new(original_manifest.kind(), children, Some(metadata))?;
        let new_root = manifest.root();
        let name = new_root.to_text();
        let hex = name.strip_prefix("sha256:").ok_or("SHA-256 publication")?;
        let slot = SlotName::parse(&format!("fv-{hex}"))?;
        for bytes in [&receipt[..], &pixels[..]] {
            let digest = deployment.publisher_mut().stage_object(bytes)?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        deployment
            .publisher_mut()
            .stage_manifest(&slot, &manifest)?;
        let _publication =
            deployment.publish_and_commit(&slot, &manifest, frame.capsule().capture, &cx)?;
        let delta = EvidenceDelta {
            delta_id: format!("delta:recorded-video:{hex}"),
            family: "decode_receipt".into(),
            object_id: ObjectId::parse(format!("object:recorded-video:{hex}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: frame.capsule().capture,
            plane: Plane::Cognition,
            payload_digest: metadata,
            witness_digest: Some(new_root),
            operation_id: None,
        };
        let mut closure = manifest.children().to_vec();
        closure.push(new_root);
        closure.sort_unstable();
        closure.dedup();
        let _completion = deployment.append_batch(
            BatchId::parse(format!("batch:recorded-video:{hex}"))?,
            vec![delta],
            closure,
            &cx,
        )?;
        let wrong = PublishedVideoFrame::open(
            &deployment,
            new_root,
            VideoPublicationLimits::default(),
            &cx,
        )?;
        assert_eq!(wrong.i420(), pixels);
        assert_ne!(wrong.i420(), frame.i420());
        Ok(new_root)
    })();
    cx.drain_and_finalize();
    result
}

#[test]
fn selected_frame_replay_rejects_self_consistent_wrong_pixel_custody() -> Test {
    let directory = Directory::new("independent-replay")?;
    let identity = import(&directory, AVC, "annexb", "camera")?;
    let original = execute(&publication(&directory, &identity, "avc", 3, Some(1)))?;
    let wrong = internally_consistent_wrong_pixels(
        &directory,
        text(only(&original, "frame")?, "frame_root")?,
    )?;
    let before_journals = journals(&directory)?;
    let before_roots = roots(&directory)?;
    let read = execute(&stored(
        &directory,
        "read",
        &identity,
        "avc",
        &wrong.to_text(),
    ))?;
    assert!(!flag(only(&read, "terminal")?, "replay_verified")?);
    refuse_without_frame(&stored(
        &directory,
        "verify",
        &identity,
        "avc",
        &wrong.to_text(),
    ))?;
    assert_eq!(journals(&directory)?, before_journals);
    assert_eq!(roots(&directory)?, before_roots);
    Ok(())
}
