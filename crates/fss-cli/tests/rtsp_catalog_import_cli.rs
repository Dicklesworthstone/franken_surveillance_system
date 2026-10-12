#![forbid(unsafe_code)]
//! Whole RTSP catalog custody through the real import and retained-media binaries.
//! Synthetic HEVC is a custody/replay fixture, not a camera or detector qualification.

#[path = "../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod hevc_recording_support;

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_catalog::hevc::local::HevcCatalogPublication;
use fss_reference::rtsp::recording_catalog::hevc::{
    HevcCatalogWindow, HevcRecordingCatalog, prepare_hevc_catalog,
};
use fss_reference::rtsp::recording_catalog::local::CatalogProgress;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-rtsp-catalog-import-cli-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned test-directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-import-rtsp"))
        .args(args)
        .output()?)
}
fn good(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
// Only synthetic fixture fields without escaped quotes are read by this helper.
fn field<'a>(text: &'a str, key: &str) -> Test<&'a str> {
    let marker = format!("\"{key}\":\"");
    let value = text.split_once(&marker).ok_or("missing fixture field")?.1;
    Ok(value.split_once('"').ok_or("unterminated fixture field")?.0)
}

fn publish(directory: &Directory, separate_pages: bool) -> Test<Vec<HevcRecordingCatalog>> {
    let first = hevc_recording_support::fixture()?;
    let mut packets = hevc_recording_support::packets()?;
    for p in &mut packets {
        p.sequence += 32;
        p.received_ns += 32;
        p.bytes[2..4].copy_from_slice(&(p.sequence as u16).to_be_bytes());
        let timestamp = u32::from_be_bytes(p.bytes[4..8].try_into()?);
        p.bytes[4..8].copy_from_slice(&(timestamp + 72_000).to_be_bytes());
    }
    let mut timings = hevc_recording_support::timings(4);
    for t in &mut timings {
        t.decode_time += 72_000;
    }
    let second = hevc_recording_support::prepare(&packets, &timings)?;
    let a = SlotName::parse("first-window")?;
    let b = SlotName::parse("second-window")?;
    let mut source = LocalRootPublisher::open(
        directory.0.join("source archive"),
        LocalPublicationLimits::new(
            8,
            64,
            8,
            128,
            SpoolLimits::new(128, 8 * 1024 * 1024, 1024 * 1024, 128),
        ),
    )?;
    for (slot, plan) in [(&a, &first), (&b, &second)] {
        let mut job = RecordingPublication::new(
            plan.publication_plan(),
            &mut source,
            slot.clone(),
            plan.byte_len(),
            100,
        )?;
        for now in 0..4 {
            assert!(matches!(
                job.step(now, &NeverCancel)?,
                RecordingProgress::ChildStaged { .. }
            ));
        }
        assert!(matches!(
            job.step(4, &NeverCancel)?,
            RecordingProgress::Published(_)
        ));
    }
    let scope = CatalogScope {
        recording: first.summary().scope.clone(),
        decode_clock: ContentDigest::sha256(b"cli-explicit-decode-epoch"),
        time_scale: 90_000,
    };
    let catalogs = if separate_pages {
        vec![
            prepare_hevc_catalog(
                scope.clone(),
                &[HevcCatalogWindow {
                    slot: &a,
                    recording: &first,
                }],
            )?,
            prepare_hevc_catalog(
                scope,
                &[HevcCatalogWindow {
                    slot: &b,
                    recording: &second,
                }],
            )?,
        ]
    } else {
        vec![prepare_hevc_catalog(
            scope,
            &[
                HevcCatalogWindow {
                    slot: &a,
                    recording: &first,
                },
                HevcCatalogWindow {
                    slot: &b,
                    recording: &second,
                },
            ],
        )?]
    };
    for (index, catalog) in catalogs.iter().enumerate() {
        let slot = if index == 0 {
            SlotName::parse("whole-catalog")?
        } else {
            SlotName::parse(&format!("whole-catalog-{index}"))?
        };
        let mut job =
            HevcCatalogPublication::new(catalog, &mut source, slot, catalog.byte_len(), 100)?;
        for now in 0..catalog.entries().len() as u64 + 1 {
            let _ = job.step(now, &NeverCancel)?;
        }
        assert!(matches!(
            job.step(catalog.entries().len() as u64 + 1, &NeverCancel)?,
            CatalogProgress::Published(_)
        ));
    }
    drop(source);
    Ok(catalogs)
}
fn arguments(directory: &Directory, catalog: &HevcRecordingCatalog) -> Test<Vec<OsString>> {
    let scope = catalog.scope();
    Ok([
        "--archive",
        directory
            .0
            .join("source archive")
            .to_str()
            .ok_or("archive")?,
        "--root",
        directory
            .0
            .join("destination")
            .to_str()
            .ok_or("destination")?,
        "--site",
        "site:rtsp-catalog-cli",
        "--catalog-slot",
        "whole-catalog",
        "--catalog-root",
        &catalog.manifest().root().to_text(),
        "--codec",
        "hevc",
        "--sensor-id",
        scope.recording.sensor.as_str(),
        "--stream-id",
        scope.recording.stream.as_str(),
        "--generation",
        &scope.recording.generation.to_string(),
        "--anchor",
        &scope.recording.anchor.to_text(),
        "--receive-clock",
        &scope.recording.receive_clock.to_text(),
        "--decode-clock",
        &scope.decode_clock.to_text(),
        "--time-scale",
        &scope.time_scale.to_string(),
        "--receive-time-ns",
        "5000000000",
        "--owner-authorized",
        "yes",
        "--read-originals",
        "yes",
        "--retain-originals",
        "yes",
        "--timeout-ms",
        "600000",
    ]
    .into_iter()
    .map(OsString::from)
    .collect())
}

#[test]
fn complete_catalog_import_retries_and_cold_decodes_after_source_archive_goes_offline() -> Test {
    assert_import_workflow(false)
}

#[test]
fn complete_page_list_import_retries_and_cold_decodes_both_catalogs_without_the_archive() -> Test {
    assert_import_workflow(true)
}

#[test]
fn maximum_page_list_preview_emits_every_pin_without_creating_either_store() -> Test {
    let directory = Directory::new()?;
    let recording = hevc_recording_support::fixture()?;
    let catalog = prepare_hevc_catalog(
        CatalogScope {
            recording: recording.summary().scope.clone(),
            decode_clock: ContentDigest::sha256(b"preview-decode-clock"),
            time_scale: 90_000,
        },
        &[HevcCatalogWindow {
            slot: &SlotName::parse("preview-window")?,
            recording: &recording,
        }],
    )?;
    let mut args = arguments(&directory, &catalog)?;
    for key in ["--catalog-slot", "--catalog-root"] {
        let position = args
            .iter()
            .position(|arg| arg == key)
            .ok_or("catalog selector")?;
        args.drain(position..position + 2);
    }
    let entries: Vec<_> = (0..64_u32)
        .map(|index| {
            format!(
                "{index:03}{}@{}",
                "a".repeat(fss_publication::MAX_SLOT_NAME_BYTES - 3),
                ContentDigest::sha256(&index.to_be_bytes()).to_text(),
            )
        })
        .collect();
    let pages = entries.join(",");
    assert_eq!(pages.len(), 12_863);
    args.extend(["--catalog-pages".into(), pages.into()]);
    // Pure preview accepts bounded path strings without requiring those owners to exist.
    let archive = directory.0.join("\"".repeat(1800));
    let position = args
        .iter()
        .position(|arg| arg == "--archive")
        .ok_or("archive option")?;
    args[position + 1] = archive.as_os_str().to_owned();
    let preview = good(run(&args)?)?;
    assert!(preview.len() > 16 * 1024);
    assert!(preview.len() < 64 * 1024);
    assert_eq!(preview.matches("\"slot\":").count(), 64);
    assert!(preview.contains("\"pages\":64"));
    assert!(preview.contains("\"writes\":\"none\""));
    assert!(!archive.exists());
    assert!(!directory.0.join("destination").exists());
    Ok(())
}

fn assert_import_workflow(separate_pages: bool) -> Test {
    let directory = Directory::new()?;
    let catalogs = publish(&directory, separate_pages)?;
    let catalog = catalogs.first().ok_or("catalog")?;
    let root = directory.0.join("destination");
    let archive = directory.0.join("source archive");
    let mut args = arguments(&directory, catalog)?;
    if separate_pages {
        for key in ["--catalog-slot", "--catalog-root"] {
            let position = args
                .iter()
                .position(|arg| arg == key)
                .ok_or("catalog selector")?;
            args.drain(position..position + 2);
        }
        let pages = format!(
            "whole-catalog@{},whole-catalog-1@{}",
            catalogs[0].manifest().root().to_text(),
            catalogs[1].manifest().root().to_text()
        );
        args.extend(["--catalog-pages".into(), pages.into()]);
    }
    let preview = good(run(&args)?)?;
    assert!(!root.exists());
    if separate_pages {
        assert!(preview.contains("\"format\":\"fss.rtsp_catalog_pages_import_operator.v1\""));
        assert!(preview.contains("\"selection\":\"complete_ordered_catalog_pages\""));
        assert!(preview.contains("\"pages\":2"));
        assert_eq!(preview.matches("\"slot\":").count(), 2);
    } else {
        assert!(preview.contains("\"format\":\"fss.rtsp_catalog_import_operator.v1\""));
        assert!(preview.contains("\"selection\":\"complete_catalog_page\""));
    }
    assert!(preview.contains("\"maximum_frames\":16384"));
    assert!(preview.contains("\"maximum_windows\":64"));
    assert!(!preview.contains("\"window_root\""));
    let approval = field(&preview, "approval_digest")?.to_owned();
    let mut wrong = args.clone();
    wrong.extend([
        "--approve".into(),
        ContentDigest::sha256(b"wrong catalog approval")
            .to_text()
            .into(),
    ]);
    assert!(!run(&wrong)?.status.success());
    assert!(!root.exists());
    args.extend(["--approve".into(), approval.into()]);
    let imported = good(run(&args)?)?;
    if separate_pages {
        assert!(imported.contains("\"pages\":2"));
        assert!(imported.contains("\"destination_contains_complete_catalog_pages\":true"));
        assert_eq!(imported.matches("\"slot\":").count(), 2);
    }
    assert!(imported.contains("\"windows\":2"));
    assert!(imported.contains("\"frames\":8"));
    assert!(imported.contains("\"destination_contains_complete_catalog\":true"));
    assert!(imported.contains("\"reused\":false"));
    let identity = field(&imported, "import_identity")?.to_owned();
    let proof = field(&imported, "origin_proof")?.to_owned();
    let snapshot = || -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(root.join("ledger/journal.fssj"))?,
            fs::read(root.join("effects/journal.fssj"))?,
        ))
    };
    let committed = snapshot()?;
    let retry = good(run(&args)?)?;
    assert!(retry.contains("\"reused\":true"));
    assert_eq!(field(&retry, "import_identity")?, identity);
    assert_eq!(field(&retry, "origin_proof")?, proof);
    assert_eq!(snapshot()?, committed);
    fs::rename(&archive, directory.0.join("offline archive"))?;
    let common = [
        "--root",
        root.to_str().ok_or("root")?,
        "--site",
        "site:rtsp-catalog-cli",
        "--import-id",
        &identity,
    ];
    let verified = good(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .arg("verify")
            .args(common)
            .output()?,
    )?;
    assert!(verified.contains("media_format=mp4hevc"));
    assert!(verified.contains("segment_count=8"));
    assert!(verified.contains("absence_certifiable=false"));
    let decoded = good(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .arg("decode")
            .args(common)
            .args([
                "--segment",
                "0",
                "--segment-count",
                "8",
                "--interpretation",
                "ycbcr",
                "--work-units",
                "1000000000",
            ])
            .output()?,
    )?;
    assert!(!decoded.is_empty());
    assert_eq!(snapshot()?.1, committed.1);
    let before = snapshot()?;
    let missing = run(&args)?;
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("ERR-RTSP-IMPORT-SOURCE-001"));
    assert!(!archive.exists());
    assert_eq!(snapshot()?, before);
    Ok(())
}
