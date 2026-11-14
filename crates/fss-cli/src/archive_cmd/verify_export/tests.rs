#![forbid(unsafe_code)]
//! Full adapter regressions use real exported native recordings. These belong to the normal
//! fss-cli suite; standalone bundle tests do not substitute for this composition.

use super::super::tests::{argv, clock, path, setup};
use super::*;
use fss_publication::{NeverCancel, SlotName};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_catalog::CatalogBuilder;
use fss_reference::rtsp::recording_catalog::local::{CatalogProgress, CatalogPublication};

#[path = "../../../../fss-reference/tests/recording_support/mod.rs"]
mod avc_source;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn avc_archive(
    name: &str,
) -> std::result::Result<(ArchiveOptions, LocalRootPublisher), Box<dyn std::error::Error>> {
    let mut options = parse_archive_args(&argv("inspect", &[]))?.ok_or("options")?;
    options.codec = Codec::Avc;
    options.scope.recording = avc_source::scope()?;
    options.root = path(name)?;
    let mut publisher = LocalRootPublisher::open(&options.root, options.storage_limits)?;
    let namespace = CodecArchiveNamespace::<AvcArchiveCodec>::new(options.scope.clone())?;
    let recording = avc_source::fixture(8123, true)?.prepare()?;
    let slot: SlotName = namespace.window_slot(0)?;
    {
        let mut job = RecordingPublication::new(
            &recording,
            &mut publisher,
            slot.clone(),
            recording.byte_len(),
            100,
        )?;
        for step in 0..4 {
            assert!(matches!(
                job.step(step, &NeverCancel)?,
                RecordingProgress::ChildStaged { .. }
            ));
        }
        assert!(matches!(
            job.step(4, &NeverCancel)?,
            RecordingProgress::Published(_)
        ));
    }
    let mut builder = CatalogBuilder::new(options.scope.clone())?;
    builder.push(&slot, &recording)?;
    let catalog = builder.prepare()?;
    {
        let mut job = CatalogPublication::new(
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
    }
    options.query = Some(recording.summary().decode_interval.clone());
    Ok((options, publisher))
}

fn copied_export(
    name: &str,
    codec: Codec,
) -> std::result::Result<ArchiveOptions, Box<dyn std::error::Error>> {
    copied_export_query(name, codec, None)
}

fn copied_export_query(
    name: &str,
    codec: Codec,
    query: Option<Range<u64>>,
) -> std::result::Result<ArchiveOptions, Box<dyn std::error::Error>> {
    let (mut options, publisher) = match codec {
        Codec::Avc => avc_archive(name)?,
        Codec::Hevc => {
            let (mut options, publisher) = setup(name)?;
            options.query = Some(70_000..110_000);
            (options, publisher)
        }
    };
    if let Some(query) = query {
        options.query = Some(query);
    }
    let output = path(&format!("{name}-export"))?;
    options.output = Some(output.clone());
    options.action = Action::Export;
    options.expected = Some(match codec {
        Codec::Avc => CodecArchiveSnapshot::<AvcArchiveCodec>::load(
            &publisher,
            CodecArchiveNamespace::<AvcArchiveCodec>::new(options.scope.clone())?,
            options.archive_limits,
            &NeverCancel,
        )?
        .digest()?,
        Codec::Hevc => CodecArchiveSnapshot::<HevcArchiveCodec>::load(
            &publisher,
            CodecArchiveNamespace::<HevcArchiveCodec>::new(options.scope.clone())?,
            options.archive_limits,
            &NeverCancel,
        )?
        .digest()?,
    });
    // Existing exporter tests separately cover the full-lifetime privacy admission guard.
    let report = match codec {
        Codec::Avc => execute_for::<AvcArchiveCodec>(&options, &publisher, &clock())?,
        Codec::Hevc => execute_for::<HevcArchiveCodec>(&options, &publisher, &clock())?,
    };
    let copied = path(&format!("{name}-copied"))?;
    fs::create_dir(&copied)?;
    for entry in fs::read_dir(&output)? {
        let entry = entry?;
        fs::copy(entry.path(), copied.join(entry.file_name()))?;
    }
    drop(publisher);
    fs::remove_dir_all(&options.root)?;
    fs::remove_dir_all(output)?;
    assert!(!options.root.exists());
    options.root = copied;
    options.action = Action::VerifyExport;
    options.expected_completion = Some(ContentDigest::sha256(report.as_bytes()));
    options.expected = None;
    options.query = None;
    options.output = None;
    options.storage_limits.spool.max_objects = bundle::MAX_FILES;
    Ok(options)
}

#[test]
fn native_zero_window_export_remains_explicitly_unindexed() -> TestResult {
    let options = copied_export_query("empty-native-copy", Codec::Avc, Some(100_000..200_000))?;
    let report = execute_archive_with_clock(&options, &clock())?;
    assert!(report.contains("\"verified_windows\":0"));
    assert!(report.contains("\"verified_recording_bytes\":0"));
    assert!(report.contains("\"coverage_claim\":\"not_claimed\""));
    assert!(report.contains("\"original_query\":[100000,200000]"));
    fs::remove_dir_all(options.root)?;
    Ok(())
}

#[test]
fn native_avc_and_hevc_copies_verify_after_original_archive_loss() -> TestResult {
    for codec in [Codec::Avc, Codec::Hevc] {
        let options = copied_export(&format!("cold-verify-{}", codec.name()), codec)?;
        let files_before: Vec<_> = fs::read_dir(&options.root)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<_>>()?;
        let report = execute_archive_with_clock(&options, &clock())?;
        assert!(report.contains(&format!("\"codec\":\"{}\"", codec.name())));
        assert!(report.contains("\"native_source_provenance_verified\":true"));
        assert!(report.contains("\"playback_bytes_verified\":true"));
        assert!(report.contains("\"decoded_pictures_verified\":false"));
        assert!(report.contains("\"original_catalog_reconstructed\":false"));
        assert!(report.contains("\"current_archive_or_disclosure_authorized\":false"));
        assert_eq!(fs::read_dir(&options.root)?.count(), files_before.len());
        fs::remove_dir_all(options.root)?;
    }
    Ok(())
}

#[test]
fn native_codec_verifier_refuses_retagged_hash_consistent_avc_bundle() -> TestResult {
    let mut options = copied_export("codec-relabel", Codec::Avc)?;
    let old_namespace =
        CodecArchiveNamespace::<AvcArchiveCodec>::new(options.scope.clone())?.digest();
    let new_namespace =
        CodecArchiveNamespace::<HevcArchiveCodec>::new(options.scope.clone())?.digest();
    let complete = fs::read_to_string(options.root.join("COMPLETE.json"))?
        .replace("\"codec\":\"avc\"", "\"codec\":\"hevc\"")
        .replace(&old_namespace.to_text(), &new_namespace.to_text());
    let request = fs::read_to_string(options.root.join("REQUEST.json"))?
        .replace("\"codec\":\"avc\"", "\"codec\":\"hevc\"");
    // The spelling grows by one byte. Preserve the existing v1 request-byte accounting.
    let original_request_bytes = fs::metadata(options.root.join("REQUEST.json"))?.len();
    let request = request.trim_end().to_owned();
    assert_eq!(request.len() as u64, original_request_bytes);
    fs::write(options.root.join("REQUEST.json"), request)?;
    fs::write(options.root.join("COMPLETE.json"), &complete)?;
    fs::write(options.root.join("COMPLETE.json.pending"), &complete)?;
    options.codec = Codec::Hevc;
    options.expected_completion = Some(ContentDigest::sha256(complete.as_bytes()));
    assert!(matches!(
        execute_archive_with_clock(&options, &clock()),
        Err(ArchiveCommandError::ExportVerification(
            ExportVerificationError::Integrity
        ))
    ));
    fs::remove_dir_all(options.root)?;
    Ok(())
}

#[test]
fn parser_keeps_copy_verification_separate_from_source_and_disclosure_options() -> TestResult {
    let pin = ContentDigest::sha256(b"independent report identity").to_text();
    let args = argv("verify-export", &["--expected-completion", &pin]);
    let options = parse_archive_args(&args)?.ok_or("options")?;
    assert_eq!(options.action, Action::VerifyExport);
    assert!(options.expected.is_none());
    assert!(options.output.is_none());
    assert!(options.privacy.is_none());
    for extra in [
        vec!["--expected-snapshot", pin.as_str()],
        vec!["--start", "0"],
        vec!["--output-dir", "/unused"],
        vec!["--privacy-root", "/unused"],
        vec!["--max-pages", "1"],
        vec!["--max-scan-roots", "1"],
    ] {
        let mut invalid = args.clone();
        invalid.extend(extra.into_iter().map(OsString::from));
        assert!(parse_archive_args(&invalid).is_err());
    }
    assert!(parse_archive_args(&argv("verify-export", &[])).is_err());
    let mut duplicate = args.clone();
    duplicate.extend(["--expected-completion".into(), pin.into()]);
    assert!(parse_archive_args(&duplicate).is_err());
    Ok(())
}

#[test]
fn copied_completion_pin_missing_completion_and_payload_corruption_are_typed() -> TestResult {
    let mut options = copied_export("copy-faults", Codec::Hevc)?;
    let pin = options.expected_completion;
    options.expected_completion = Some(ContentDigest::sha256(b"wrong completion"));
    assert!(matches!(
        execute_archive_with_clock(&options, &clock()),
        Err(ArchiveCommandError::ExportVerification(
            ExportVerificationError::CompletionPinMismatch
        ))
    ));
    options.expected_completion = pin;
    let source = fs::read_dir(&options.root)?
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".source.bin"))
        .ok_or("source file")?
        .path();
    let mut bytes = fs::read(&source)?;
    bytes[0] ^= 1;
    fs::write(source, bytes)?;
    assert!(matches!(
        execute_archive_with_clock(&options, &clock()),
        Err(ArchiveCommandError::ExportVerification(
            ExportVerificationError::Integrity
        ))
    ));
    fs::remove_file(options.root.join("COMPLETE.json"))?;
    assert!(matches!(
        execute_archive_with_clock(&options, &clock()),
        Err(ArchiveCommandError::ExportVerification(
            ExportVerificationError::Incomplete
        ))
    ));
    fs::remove_dir_all(options.root)?;
    Ok(())
}
