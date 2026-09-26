#![forbid(unsafe_code)]
//! Raw source export of a privacy-masked sensor is refused on every export path (fss-nswce,
//! PRIVACY.md 4.1), through the real binaries.
//!
//! Raw export paths (the complete list found by source search; every other command either
//! decodes under the mask or emits digests only):
//!
//! 1. `fss-file extract` (retained import segment bytes);
//! 2. `fss-archive export` (RTSP original packets: source, init, media, index, root and playback
//!    files of whole windows).
//!
//! Each works for an unmasked sensor with exactly the original bytes and is refused
//! (`ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001`) before any output once the export's sensor has a
//! current retained mask. An archive export naming no deployment cannot prove the sensor is
//! unmasked and is refused the same way. A mask on another sensor changes nothing.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::rtsp::recording::MAX_RECORDING_BYTES;
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_catalog::hevc::local::HevcCatalogPublication;
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::local::CatalogProgress;

#[path = "../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod source;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:raw-export-privacy";
const REFUSED: &str = "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001";
/// The RTSP archive's sensor (the recording support fixture's scope).
const ARCHIVE_SENSOR: &str = "sensor-hevc-fixture";

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-raw-export-privacy-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }

    fn deployment(&self) -> PathBuf {
        self.0.join("deployment")
    }

    fn archive(&self) -> PathBuf {
        self.0.join("archive")
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn refusal(output: &Output) -> String {
    assert!(!output.status.success(), "expected a refusal");
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

/// Four grayscale 32x16 JPEG frames of distinct levels.
fn frames() -> TestResult<Vec<Vec<u8>>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    (0..4_u8)
        .map(|index| {
            Ok(encode_jpeg(
                32,
                16,
                &vec![40 + index * 30; 32 * 16],
                &config,
            )?)
        })
        .collect()
}

fn import(directory: &OwnedDirectory, sensor: &str, bytes: &[u8]) -> TestResult<String> {
    let input = directory
        .0
        .join(format!("{}.mjpeg", sensor.replace(':', "-")));
    fs::write(&input, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(directory.deployment())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{sensor}")])
        .args([
            "--media-format",
            "mjpeg",
            "--receive-time-ns",
            "10000000000000",
        ])
        .output()?;
    success(&output);
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?)
}

fn extract(directory: &OwnedDirectory, import_id: &str, output: &Path) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("extract")
        .arg("--root")
        .arg(directory.deployment())
        .args(["--site", SITE, "--import-id", import_id, "--segment", "0"])
        .arg("--output")
        .arg(output)
        .output()?)
}

/// Declares (preview, then exact approval) a one-rectangle mask for `sensor`.
fn declare_mask(directory: &OwnedDirectory, sensor: &str) -> TestResult {
    let run = |approve: Option<&str>| -> TestResult<Output> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
        command
            .args(["privacy-mask", "declare", "--root"])
            .arg(directory.deployment())
            .args(["--site", SITE, "--sensor", sensor])
            .args(["--resolution", "32x16", "--rect", "0,0,8,8"]);
        if let Some(approval) = approve {
            command.args(["--approve", approval]);
        }
        Ok(command.output()?)
    };
    let preview = run(None)?;
    success(&preview);
    let text = String::from_utf8(preview.stdout)?;
    let marker = "\"approval_digest\":\"";
    let start = text.find(marker).ok_or("approval digest missing")? + marker.len();
    let approval = &text[start..start + 71];
    let retained = run(Some(approval))?;
    success(&retained);
    assert!(String::from_utf8(retained.stdout)?.contains("\"status\":\"retained\""));
    Ok(())
}

fn scope() -> TestResult<CatalogScope> {
    Ok(CatalogScope {
        recording: source::scope()?,
        decode_clock: ContentDigest::sha256(b"operator-dts"),
        time_scale: 90_000,
    })
}

/// The limits `fss-archive` opens with by default.
fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16_384,
        512,
        16_384,
        16_384,
        SpoolLimits::new(65_536, 1024 * 1024 * 1024, MAX_RECORDING_BYTES, 65_536),
    )
}

/// Publishes one durable, indexed HEVC window of the fixture sensor into a new archive.
fn archive(directory: &OwnedDirectory) -> TestResult<PreparedHevcRecording> {
    let window = source::fixture()?;
    let mut publisher = LocalRootPublisher::open(directory.archive(), limits())?;
    let namespace = HevcArchiveNamespace::new(scope()?)?;
    let slot = namespace.window_slot(0)?;
    let mut request = RecordingPublication::new(
        window.publication_plan(),
        &mut publisher,
        slot.clone(),
        window.byte_len(),
        100,
    )?;
    for step in 0..4 {
        assert!(matches!(
            request.step(step, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    assert!(matches!(
        request.step(4, &NeverCancel)?,
        RecordingProgress::Published(_)
    ));
    let catalog = prepare_hevc_catalog(
        scope()?,
        &[HevcCatalogWindow {
            slot: &slot,
            recording: &window,
        }],
    )?;
    let mut job = HevcCatalogPublication::new(
        &catalog,
        &mut publisher,
        namespace.page_slot(0)?,
        catalog.byte_len(),
        100,
    )?;
    assert!(matches!(
        job.step(0, &NeverCancel)?,
        CatalogProgress::WindowVerified { .. }
    ));
    assert!(matches!(
        job.step(1, &NeverCancel)?,
        CatalogProgress::IndexStaged { .. }
    ));
    assert!(matches!(
        job.step(2, &NeverCancel)?,
        CatalogProgress::Published(_)
    ));
    drop(publisher);
    Ok(window)
}

/// `fss-archive <command>` over the fixture scope.
fn archive_command(
    directory: &OwnedDirectory,
    command: &str,
    extra: &[&str],
) -> TestResult<Output> {
    let scope = scope()?;
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .arg(command)
        .arg("--root")
        .arg(directory.archive())
        .args(["--codec", "hevc", "--sensor", ARCHIVE_SENSOR])
        .args([
            "--stream",
            scope.recording.stream.as_str(),
            "--generation",
            "1",
        ])
        .args(["--anchor", &scope.recording.anchor.to_text()])
        .args(["--receive-clock", &scope.recording.receive_clock.to_text()])
        .args(["--decode-clock", &scope.decode_clock.to_text()])
        .args(["--time-scale", "90000"])
        .args(extra)
        .output()?)
}

fn snapshot(directory: &OwnedDirectory) -> TestResult<String> {
    let inspect = archive_command(directory, "inspect", &[])?;
    success(&inspect);
    let text = String::from_utf8(inspect.stdout)?;
    let marker = "\"snapshot\":\"";
    let start = text.find(marker).ok_or("snapshot missing")? + marker.len();
    Ok(text[start..start + 71].to_owned())
}

fn export(
    directory: &OwnedDirectory,
    snapshot: &str,
    output: &Path,
    privacy: bool,
) -> TestResult<Output> {
    let output_text = output.to_str().ok_or("UTF-8 test path")?;
    let deployment = directory.deployment();
    let deployment_text = deployment.to_str().ok_or("UTF-8 test path")?;
    let mut extra = vec![
        "--expected-snapshot",
        snapshot,
        "--start",
        "0",
        "--end",
        "72000",
        "--output-dir",
        output_text,
        "--allow-whole-windows",
        "yes",
    ];
    if privacy {
        extra.extend_from_slice(&["--privacy-root", deployment_text, "--site", SITE]);
    }
    archive_command(directory, "export", &extra)
}

fn stable_code(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .split(':')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Every exported window file equals the archived original object, byte for byte.
fn assert_original_bytes(output: &Path, window: &PreparedHevcRecording) -> TestResult {
    let plan = window.publication_plan();
    let stem = format!(
        "window-{:016x}-{}",
        0,
        &plan.manifest().root().to_text()[7..]
    );
    for ((_, _, bytes), suffix) in
        plan.children()
            .into_iter()
            .zip(["source.bin", "init.mp4", "media.m4s", "index.bin"])
    {
        assert_eq!(fs::read(output.join(format!("{stem}.{suffix}")))?, bytes);
    }
    assert_eq!(
        fs::read(output.join(format!("{stem}.root.bin")))?,
        plan.manifest().canonical_bytes()
    );
    assert_eq!(
        fs::read(output.join(format!("{stem}.playback.mp4")))?,
        [plan.objects().initialization, plan.objects().media].concat()
    );
    assert!(output.join("COMPLETE.json").is_file());
    Ok(())
}

/// Every file of an export directory, by name, with its bytes.
fn tree(output: &Path) -> TestResult<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(output)? {
        let entry = entry?;
        out.push((
            entry.file_name().to_string_lossy().into_owned(),
            fs::read(entry.path())?,
        ));
    }
    out.sort();
    Ok(out)
}

#[test]
fn raw_exports_work_unmasked_and_are_refused_once_the_sensor_is_masked() -> TestResult {
    let directory = OwnedDirectory::new("paths")?;
    let window = archive(&directory)?;
    let jpegs = frames()?;
    let import_id = import(&directory, "sensor:cam-a", &jpegs.concat())?;
    let snapshot = snapshot(&directory)?;

    // 1. fss-file extract of an unmasked sensor serves the original segment bytes.
    let extracted = directory.0.join("segment-0.jpg");
    success(&extract(&directory, &import_id, &extracted)?);
    assert_eq!(fs::read(&extracted)?, jpegs[0]);

    // 2. fss-archive export of an unmasked sensor serves exactly the archived originals.
    let first = directory.0.join("export-unmasked");
    success(&export(&directory, &snapshot, &first, true)?);
    assert_original_bytes(&first, &window)?;

    // Naming no deployment cannot prove the sensor is unmasked: refused before any output.
    let unnamed = directory.0.join("export-unnamed");
    let refused = export(&directory, &snapshot, &unnamed, false)?;
    assert!(!refused.status.success());
    assert_eq!(stable_code(&refused), REFUSED);
    assert!(refused.stdout.is_empty());
    assert!(!unnamed.exists());

    // A mask on another sensor changes nothing: both exports stay byte-identical.
    declare_mask(&directory, "sensor-unrelated")?;
    let second = directory.0.join("export-other-masked");
    success(&export(&directory, &snapshot, &second, true)?);
    assert_eq!(tree(&first)?, tree(&second)?, "exports are byte-identical");
    let again = directory.0.join("segment-0-again.jpg");
    success(&extract(&directory, &import_id, &again)?);
    assert_eq!(fs::read(&again)?, jpegs[0]);

    // Once each export's sensor carries a mask, its raw export is refused before any output.
    declare_mask(&directory, "sensor:cam-a")?;
    let masked_segment = directory.0.join("segment-0-masked.jpg");
    assert_eq!(
        refusal(&extract(&directory, &import_id, &masked_segment)?),
        REFUSED
    );
    assert!(!masked_segment.exists());
    // The archive sensor is still unmasked: its export still works.
    let third = directory.0.join("export-still-unmasked");
    success(&export(&directory, &snapshot, &third, true)?);
    assert_eq!(tree(&first)?, tree(&third)?);

    declare_mask(&directory, ARCHIVE_SENSOR)?;
    let masked = directory.0.join("export-masked");
    let refused = export(&directory, &snapshot, &masked, true)?;
    assert!(!refused.status.success());
    assert_eq!(stable_code(&refused), REFUSED);
    assert!(refused.stdout.is_empty());
    assert!(!masked.exists(), "no export directory is created");
    // The refusal is deterministic and leaves the archive exportable to nobody.
    let refused_again = export(&directory, &snapshot, &masked, true)?;
    assert_eq!(refused.stderr, refused_again.stderr);
    assert!(!masked.exists());
    Ok(())
}

#[test]
fn archive_export_privacy_options_are_all_or_nothing() -> TestResult {
    let directory = OwnedDirectory::new("options")?;
    let digest = ContentDigest::sha256(b"pin").to_text();
    let output = directory.0.join("never");
    let output_text = output.to_str().ok_or("UTF-8 test path")?;
    for extra in [vec!["--privacy-root", "/unused"], vec!["--site", SITE]] {
        let mut args = vec![
            "--expected-snapshot",
            &digest,
            "--start",
            "0",
            "--end",
            "1",
            "--output-dir",
            output_text,
            "--allow-whole-windows",
            "yes",
        ];
        args.extend(extra);
        let refused = archive_command(&directory, "export", &args)?;
        assert!(!refused.status.success());
        assert_eq!(stable_code(&refused), "ERR-CLI-MISSING-VALUE-001");
        assert!(!output.exists());
    }
    // Privacy options are inapplicable outside export.
    let refused = archive_command(
        &directory,
        "inspect",
        &["--privacy-root", "/unused", "--site", SITE],
    )?;
    assert_eq!(stable_code(&refused), "ERR-CLI-UNKNOWN-OPTION-001");
    Ok(())
}
