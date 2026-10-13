#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real file imports and budgeted AVC/HEVC streaming decode through fresh native processes.

use fss_core::ContentDigest;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Seek};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:file-video-stream-cli";
const AVC: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] =
    include_bytes!("../../fss-codec-h265/tests/fixtures/decode/f_qcif_default.h265");

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for index in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-file-video-stream-{label}-{}-{index}",
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
    run_command(Command::new(env!("CARGO_BIN_EXE_fss-file")).args(args))
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

fn fields(bytes: &[u8]) -> Test<BTreeMap<String, Vec<String>>> {
    let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let (key, value) = line.split_once('=').ok_or("non-field native output")?;
        result.entry(key.to_owned()).or_default().push(value.to_owned());
    }
    Ok(result)
}
fn one<'a>(fields: &'a BTreeMap<String, Vec<String>>, key: &str) -> Test<&'a str> {
    let values = fields.get(key).ok_or_else(|| format!("missing field {key}"))?;
    if values.len() != 1 { return Err(format!("ambiguous field {key}").into()); }
    Ok(&values[0])
}
fn set(args: &mut [OsString], key: &str, value: impl Into<OsString>) -> Test {
    let index = args.iter().position(|s| s == key).ok_or("missing option to replace")?;
    args[index + 1] = value.into();
    Ok(())
}
fn args(directory: &Directory, identity: &str, count: usize) -> Vec<OsString> {
    vec!["decode".into(), "--root".into(), directory.root().into_os_string(), "--site".into(), SITE.into(),
         "--import-id".into(), identity.into(), "--segment".into(), "0".into(),
         "--segment-count".into(), count.to_string().into(), "--interpretation".into(), "ycbcr".into(),
         "--max-dimension".into(), "176".into(), "--max-pixels".into(), "25344".into(),
         "--work-units".into(), "1000000000".into()]
}
fn journals(directory: &Directory) -> Test<(Vec<u8>, Vec<u8>)> {
    Ok((fs::read(directory.root().join("ledger/journal.fssj"))?,
        fs::read(directory.root().join("effects/journal.fssj"))?))
}
fn export_args(args: &[OsString], path: &std::path::Path, maximum: usize) -> Vec<OsString> {
    let mut args = args.to_vec();
    args.extend(["--output".into(), path.as_os_str().to_owned(), "--max-output-bytes".into(), maximum.to_string().into()]);
    args
}
fn incomplete(output: &Output) {
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.lines().any(|s| s == "decode_complete=true"));
    assert!(!stdout.contains("pgm_sha256="));
}
fn setup(codec: &str) -> Test<(Directory, String, usize)> {
    let directory = Directory::new(codec)?;
    let (bytes, format, count) = if codec == "avc" { (AVC, "annexb", 3) } else { (HEVC, "hevc", 8) };
    let identity = import(&directory, bytes, format, "camera")?;
    Ok((directory, identity, count))
}
const HEADER: &[u8] = b"P5\n176 144\n255\n";
const PIXELS: usize = 176 * 144;

#[test]
fn streamed_bytes_match_native_receipts_and_display_order_without_publication() -> Test {
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = setup(codec)?;
        let base = args(&directory, &identity, count);
        let before = journals(&directory)?;
        let no_export = fields(&successful(raw(&base)?)?)?;
        assert_eq!(one(&no_export, "decode_complete")?, "true");
        assert!(!no_export.contains_key("pgm_sha256"));
        let path = directory.0.join("frames.pgm");
        let request = export_args(&base, &path, count * (HEADER.len() + PIXELS));
        let exported = fields(&successful(raw(&request)?)?)?;
        let bytes = fs::read(&path)?;
        assert_eq!(one(&exported, "pgm_sha256")?, ContentDigest::sha256(&bytes).to_text());
        assert_eq!(one(&exported, "pgm_bytes")?.parse::<usize>()?, bytes.len());
        assert_eq!(one(&exported, "pgm_frames")?.parse::<usize>()?, count);
        assert_eq!(one(&exported, "decode_published")?, "false");
        assert_eq!(exported.get("frame_receipt_digest"), no_export.get("frame_receipt_digest"));
        assert_eq!(one(&exported, "decode_work_units")?, one(&no_export, "decode_work_units")?);
        let chunks = bytes.chunks_exact(HEADER.len() + PIXELS);
        assert!(chunks.remainder().is_empty());
        let digests = exported.get("frame_luma_sha256").ok_or("frame digests")?;
        assert_eq!(digests.len(), count);
        for (index, chunk) in chunks.enumerate() {
            assert_eq!(&chunk[..HEADER.len()], HEADER);
            assert_eq!(ContentDigest::sha256(&chunk[HEADER.len()..]).to_text(), digests[index]);
        }
        assert_eq!(exported.get("frame_output_index"), Some(&(0..count).map(|n| n.to_string()).collect()));
        let segments = exported.get("frame_segment").ok_or("segments")?.iter()
            .map(|s| s.parse::<usize>()).collect::<Result<Vec<_>, _>>()?;
        if codec == "hevc" { assert!(segments.windows(2).any(|s| s[0] > s[1])); }
        assert_eq!(journals(&directory)?, before);
        incomplete(&raw(&request)?);
        assert_eq!(fs::read(path)?, bytes);
    }
    Ok(())
}

#[test]
fn one_cumulative_decode_budget_has_exact_success_and_refusal_boundaries() -> Test {
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = setup(codec)?;
        let base = args(&directory, &identity, count);
        let full = fields(&successful(raw(&base)?)?)?;
        let used: u64 = one(&full, "decode_work_units")?.parse()?;
        assert!(used > 0);
        assert_eq!(one(&full, "decode_work_unit_model")?, "encoded_bytes_plus_coded_luma_capacity.v1");
        let before = journals(&directory)?;
        let mut exact = base.clone();
        set(&mut exact, "--work-units", used.to_string())?;
        let report = fields(&successful(raw(&exact)?)?)?;
        assert_eq!(one(&report, "remaining_decode_work_units")?, "0");
        set(&mut exact, "--work-units", (used - 1).to_string())?;
        let refused = raw(&exact)?;
        incomplete(&refused);
        let report = fields(&refused.stdout)?;
        assert_eq!(one(&report, "decode_complete")?, "false");
        assert!(one(&report, "decode_work_units")?.parse::<u64>()? < used);
        set(&mut exact, "--work-units", "0")?;
        let path = directory.0.join("zero-work.pgm");
        let refused = raw(&export_args(&exact, &path, 1024 * 1024))?;
        incomplete(&refused);
        assert_eq!(one(&fields(&refused.stdout)?, "decode_work_units")?, "0");
        assert!(!path.exists());
        assert_eq!(journals(&directory)?, before);
    }
    Ok(())
}

#[test]
fn whole_frame_output_admission_keeps_a_prefix_without_claiming_completion() -> Test {
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = setup(codec)?;
        let base = args(&directory, &identity, count);
        let full_path = directory.0.join("full.pgm");
        successful(raw(&export_args(&base, &full_path, count * (HEADER.len() + PIXELS)))?)?;
        let full = fs::read(&full_path)?;
        let tiny = directory.0.join("tiny.pgm");
        incomplete(&raw(&export_args(&base, &tiny, HEADER.len() + PIXELS - 1))?);
        assert!(!tiny.exists());
        let prefix = directory.0.join("prefix.pgm");
        let refused = raw(&export_args(&base, &prefix, HEADER.len() + PIXELS))?;
        incomplete(&refused);
        assert_eq!(one(&fields(&refused.stdout)?, "decode_complete")?, "false");
        assert_eq!(fs::read(&prefix)?, &full[..HEADER.len() + PIXELS]);
        let saved = fs::read(&prefix)?;
        incomplete(&raw(&export_args(&base, &prefix, full.len()))?);
        assert_eq!(fs::read(prefix)?, saved);
    }
    Ok(())
}

#[test]
fn coded_pixel_and_source_limits_are_never_rounded_up_or_ignored() -> Test {
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = setup(codec)?;
        let before = journals(&directory)?;
        for (key, value) in [("--max-pixels", "25343"), ("--max-dimension", "175")] {
            let mut request = args(&directory, &identity, count);
            set(&mut request, key, value)?;
            let path = directory.0.join(format!("refused-{}.pgm", &key[2..]));
            incomplete(&raw(&export_args(&request, &path, 1024 * 1024))?);
            assert!(!path.exists());
        }
        for key in ["--max-source-bytes", "--max-segment-bytes"] {
            let mut request = args(&directory, &identity, count);
            request.extend([key.into(), "1".into()]);
            let path = directory.0.join(format!("refused-{}.pgm", &key[2..]));
            incomplete(&raw(&export_args(&request, &path, 1024 * 1024))?);
            assert!(!path.exists());
        }
        assert_eq!(journals(&directory)?, before);
    }
    Ok(())
}

fn context(directory: &Directory) -> Test<fss_reference::ReplayCx> {
    use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec};
    use fss_reference::ReplayCx;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:stream-mask".into(), operation_id: OperationId::parse("operation:stream-mask")?,
        principal: "principal:test".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).storage_operations(65_536).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, directory.root())?;
    Ok(cx)
}

fn mask(directory: &Directory) -> Test<ContentDigest> {
    use fss_core::SensorId;
    use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
    use fss_reference::ReferenceDeployment;
    let cx = context(directory)?;
    let mut deployment = ReferenceDeployment::open(&directory.root(), SITE, &cx)?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse("sensor:camera")?, [176, 144], &[[0, 0, 176, 144]])?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    let digest = declare_mask(&mut deployment, &policy, approval, &cx)?.policy_digest;
    drop(deployment);
    cx.drain_and_finalize();
    Ok(digest)
}

#[test]
fn only_current_masked_luma_reaches_the_streaming_export() -> Test {
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = setup(codec)?;
        let policy = mask(&directory)?;
        let before = journals(&directory)?;
        let path = directory.0.join("masked.pgm");
        let report = fields(&successful(raw(&export_args(&args(&directory, &identity, count), &path, 1024 * 1024))?)?)?;
        assert_eq!(one(&report, "privacy_mask_policy")?, policy.to_text());
        let bytes = fs::read(path)?;
        for frame in bytes.chunks_exact(HEADER.len() + PIXELS) {
            assert_eq!(&frame[..HEADER.len()], HEADER);
            assert!(frame[HEADER.len()..].iter().all(|p| *p == 16));
        }
        assert_eq!(journals(&directory)?, before);
    }
    Ok(())
}

#[test]
fn damaged_originals_cannot_be_exported_or_silently_repaired() -> Test {
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = setup(codec)?;
        // Resolve the first actual chunk from committed import metadata. The CLI's chunk
        // policy need not retain the complete fixture as a single object.
        let cx = context(&directory)?;
        let deployment = fss_reference::ReferenceDeployment::open(&directory.root(), SITE, &cx)?;
        let retained = fss_reference::ingest::RetainedFileImport::open(
            &deployment, ContentDigest::parse(&identity)?,
            fss_reference::ingest::RetainedReadLimits::default(), &cx)?;
        let digest = *retained.manifest().ordered_chunks.first().ok_or("missing source chunk")?;
        let original_path = directory.root().join("objects/spool/objects").join(
            digest.bytes().iter().map(|b| format!("{b:02x}")).collect::<String>());
        drop(retained);
        drop(deployment);
        cx.drain_and_finalize();
        let original = &original_path;
        let mut bad = fs::read(original)?;
        assert_eq!(ContentDigest::sha256(&bad), digest);
        *bad.last_mut().ok_or("empty original")? ^= 1;
        fs::write(original, &bad)?;
        let path = directory.0.join("corrupt.pgm");
        incomplete(&raw(&export_args(&args(&directory, &identity, count), &path, 1024 * 1024))?);
        assert!(!path.exists());
        assert_eq!(fs::read(original)?, bad);
    }
    Ok(())
}

#[test]
fn invalid_export_allowances_refuse_before_opening_a_deployment() -> Test {
    let directory = Directory::new("grammar")?;
    let identity = ContentDigest::sha256(b"not an existing import").to_text();
    for (output, maximum) in [(false, "1"), (true, "0"), (true, "268435457")] {
        let mut request = args(&directory, &identity, 1);
        if output { request.extend(["--output".into(), directory.0.join("output.pgm").into_os_string()]); }
        request.extend(["--max-output-bytes".into(), maximum.into()]);
        let output = raw(&request)?;
        assert_eq!(output.status.code(), Some(2));
        assert!(!directory.root().exists());
        assert!(!directory.0.join("output.pgm").exists());
    }
    Ok(())
}

#[test]
fn output_aliases_cannot_overwrite_source_custody() -> Test {
    let (directory, identity, count) = setup("avc")?;
    let base = args(&directory, &identity, count);
    let alias = directory.0.join("alias");
    std::os::unix::fs::symlink(directory.root(), &alias)?;
    for path in [directory.root().join("forbidden"), alias.join("forbidden")] {
        incomplete(&raw(&export_args(&base, &path, 1024 * 1024))?);
        assert!(!path.exists());
    }
    let original = directory.0.join("preserved");
    fs::write(&original, b"operator-owned output")?;
    let destination = directory.0.join("linked.pgm");
    std::os::unix::fs::symlink(&original, &destination)?;
    incomplete(&raw(&export_args(&base, &destination, 1024 * 1024))?);
    assert_eq!(fs::read(original)?, b"operator-owned output");
    Ok(())
}

#[test]
fn video_only_output_option_cannot_publish_a_jpeg_decode() -> Test {
    let directory = Directory::new("jpeg-option")?;
    let jpeg = include_bytes!("fixtures/retained_file_8x8.jpg");
    let identity = import(&directory, jpeg, "mjpeg", "camera")?;
    let before = journals(&directory)?;
    let output = directory.0.join("jpeg.pgm");
    incomplete(&raw(&export_args(&args(&directory, &identity, 1), &output, 1024))?);
    assert!(!output.exists());
    assert_eq!(journals(&directory)?, before);
    Ok(())
}
