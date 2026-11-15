#![forbid(unsafe_code)]
//! Exercise the actual argument parser, retained import and cold selection command together.

use super::{MovieInterval, interval_text};
use crate::{Action, parse, run};
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const SOURCE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-container/tests/fixtures/indexed_avc.mp4"
));

type Test<T = ()> = Result<T, Box<dyn Error>>;

struct Directory(PathBuf);

impl Directory {
    fn new() -> io::Result<Self> {
        for ordinal in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-movie-selection-cli-{}-{ordinal}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other("test directory capacity"))
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn arguments(root: &Path, command: &str, extra: &[OsString]) -> Vec<OsString> {
    let mut args = vec![
        OsString::from(command),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--site"),
        OsString::from("site:movie-selection-cli"),
    ];
    args.extend_from_slice(extra);
    args
}

fn execute(root: &Path, command: &str, extra: &[OsString], out: &mut Vec<u8>) -> Test {
    let options = parse(&arguments(root, command, extra))
        .map_err(|(code, reason)| io::Error::other(format!("{code}: {reason}")))?
        .ok_or_else(|| io::Error::other("missing action"))?;
    run(options, out)
}

fn text_args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn field<'a>(output: &'a str, name: &str) -> Test<&'a str> {
    let prefix = format!("{name}=");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| io::Error::other(format!("missing field {name}")).into())
}

fn imported_without_external_source(directory: &Directory) -> Test<(PathBuf, String)> {
    let root = directory.0.join("deployment");
    let source = directory.0.join("camera.mp4");
    fs::write(&source, SOURCE)?;
    let mut extra = text_args(&["--input"]);
    extra.push(source.as_os_str().to_owned());
    extra.extend(text_args(&[
        "--sensor",
        "sensor:movie-test",
        "--stream",
        "stream:movie-test",
        "--receive-time-ns",
        "1000000000",
        "--media-format",
        "mp4avc",
        "--chunk-bytes",
        "256",
    ]));
    let mut output = Vec::new();
    execute(&root, "import", &extra, &mut output)?;
    let text = String::from_utf8(output)?;
    let identity = field(&text, "import_identity")?.to_owned();
    fs::remove_file(source)?;
    Ok((root, identity))
}

#[test]
fn retained_movie_command_selects_presentation_order_and_reports_decode_prerequisites() -> Test {
    let directory = Directory::new()?;
    let (root, identity) = imported_without_external_source(&directory)?;
    let mut output = Vec::new();
    // This fixture has a 4096-media-tick edit. Its B picture in coding segment 3 is
    // presented at 400 ms, before coding segment 1 at 600 ms. The 800 ms sample is excluded.
    execute(
        &root,
        "select-movie",
        &text_args(&[
            "--import-id",
            &identity,
            "--start-movie-tick",
            "400",
            "--end-movie-tick",
            "800",
        ]),
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert_eq!(field(&output, "movie_timescale")?, "1000");
    assert_eq!(field(&output, "media_timescale")?, "10240");
    assert_eq!(field(&output, "selected_presentation_count")?, "2");
    assert_eq!(field(&output, "movie_gap_count")?, "0");
    assert_eq!(field(&output, "decode_span_count")?, "1");
    let samples: Vec<&str> = output
        .lines()
        .filter(|line| line.starts_with("movie_sample="))
        .collect();
    assert_eq!(samples.len(), 2);
    assert!(samples[0].contains("segment=3 "), "{output}");
    assert!(samples[1].contains("segment=1 "), "{output}");
    assert!(
        output.contains("decode_span=0 start_segment=0 segment_count=4 "),
        "{output}"
    );
    assert!(output.contains("requested_segments=1,3\n"), "{output}");
    assert_eq!(
        field(&output, "selection_source_bytes_read")?,
        SOURCE.len().to_string()
    );
    assert_eq!(
        field(&output, "selection_time_basis")?,
        "container_movie_timeline"
    );
    assert_eq!(field(&output, "selection_decoded_frames")?, "0");
    assert_eq!(field(&output, "selection_absence_certifiable")?, "false");
    assert_eq!(field(&output, "selection_complete")?, "true");
    Ok(())
}

#[test]
fn movie_time_beyond_the_source_is_an_explicit_gap_and_not_absence() -> Test {
    let directory = Directory::new()?;
    let (root, identity) = imported_without_external_source(&directory)?;
    let mut output = Vec::new();
    execute(
        &root,
        "select-movie",
        &text_args(&[
            "--import-id",
            &identity,
            "--start-movie-tick",
            "2000",
            "--end-movie-tick",
            "2100",
        ]),
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert_eq!(field(&output, "selected_presentation_count")?, "0");
    assert_eq!(field(&output, "decode_span_count")?, "0");
    assert_eq!(field(&output, "movie_gap_count")?, "1");
    assert!(
        output.contains("movie_gap=0 kind=unrepresented "),
        "{output}"
    );
    assert_eq!(field(&output, "selection_absence_certifiable")?, "false");
    Ok(())
}

#[test]
fn source_or_preroll_budget_failure_never_releases_selection_rows_or_completion() -> Test {
    let directory = Directory::new()?;
    let (root, identity) = imported_without_external_source(&directory)?;
    for (limit, amount) in [
        ("--max-source-bytes", "1"),
        ("--max-decode-samples", "2"),
        ("--selection-work-units", "1"),
        ("--max-decode-bytes", "1"),
    ] {
        let mut output = Vec::new();
        assert!(
            execute(
                &root,
                "select-movie",
                &text_args(&[
                    "--import-id",
                    &identity,
                    "--start-movie-tick",
                    "400",
                    "--end-movie-tick",
                    "800",
                    limit,
                    amount,
                ]),
                &mut output
            )
            .is_err(),
            "{limit}"
        );
        let output = String::from_utf8(output)?;
        assert!(
            output.is_empty(),
            "refusal leaked metadata for {limit}: {output}"
        );
        assert!(!output.contains("movie_sample="), "{limit}: {output}");
        assert!(
            !output.contains("selection_complete=true"),
            "{limit}: {output}"
        );
    }
    Ok(())
}

#[test]
fn cancellation_after_a_presentation_row_stops_report_delivery_without_completion() -> Test {
    struct CancellingWriter<'a> {
        cx: &'a ReplayCx,
        bytes: Vec<u8>,
        cancelled: bool,
    }

    impl Write for CancellingWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            // Formatting can write a row in several fragments. Cancel only after the first
            // complete presentation row has been successfully accepted by this output sink.
            if !self.cancelled
                && self
                    .bytes
                    .split_inclusive(|b| *b == b'\n')
                    .any(|line| line.starts_with(b"movie_sample=0 ") && line.ends_with(b"\n"))
            {
                self.cx.request_cancellation();
                self.cancelled = true;
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let directory = Directory::new()?;
    let (root, identity) = imported_without_external_source(&directory)?;
    let options = parse(&arguments(
        &root,
        "select-movie",
        &text_args(&[
            "--import-id",
            &identity,
            "--start-movie-tick",
            "400",
            "--end-movie-tick",
            "800",
        ]),
    ))
    .map_err(|(code, reason)| io::Error::other(format!("{code}: {reason}")))?
    .ok_or_else(|| io::Error::other("missing selection action"))?;
    let Action::Movie(action) = options.action else {
        return Err(io::Error::other("expected movie selection action").into());
    };
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:movie-report-cancellation".to_owned(),
        operation_id: OperationId::parse("operation:movie-report-cancellation")?,
        principal: "operator:movie-report-test".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:local-authorized-files".to_owned(),
        retention_scope: "retention:existing-deployment-policy".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:movie-selection-cli"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let deployment = ReferenceDeployment::open(&root, "site:movie-selection-cli", &cx)?;
    let limits = RetainedReadLimits::default();
    let retained =
        RetainedFileImport::open(&deployment, ContentDigest::parse(&identity)?, limits, &cx)?;
    let mut writer = CancellingWriter {
        cx: &cx,
        bytes: Vec::new(),
        cancelled: false,
    };
    let result = super::run(&action, &retained, &deployment, limits, &cx, &mut writer);
    cx.drain_and_finalize();
    assert!(
        writer.cancelled,
        "the sink must accept a complete sample row first"
    );
    assert!(
        result.is_err(),
        "report cancellation must propagate to its caller"
    );
    let output = String::from_utf8(writer.bytes)?;
    assert!(output.contains("movie_sample=0 segment=3 "), "{output}");
    assert!(!output.contains("movie_sample=1 "), "{output}");
    assert!(!output.contains("selection_complete=true"), "{output}");
    Ok(())
}

#[test]
fn exact_rational_output_preserves_endpoints_beyond_float_integer_precision() {
    assert_eq!(
        interval_text(&MovieInterval {
            start_numerator: 10_000_000_000_000_000_001,
            end_numerator: 10_000_000_000_000_000_003,
            denominator: 3,
        }),
        "10000000000000000001/3,10000000000000000003/3",
    );
}

fn open_writer(root: &Path) -> Test<(ReplayCx, ReferenceDeployment)> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:movie-cli-writer".into(),
        operation_id: OperationId::parse("operation:movie-cli-writer")?,
        principal: "principal:movie-cli-writer".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:movie-selection-cli"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    let writer = ReferenceDeployment::open(root, "site:movie-selection-cli", &cx)?;
    Ok((cx, writer))
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let name = path.strip_prefix(root)?.to_path_buf();
        if fs::symlink_metadata(&path)?.is_dir() {
            entries.insert(name, None);
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else {
            entries.insert(name, Some(fs::read(path)?));
        }
    }
    Ok(entries)
}

fn selection(identity: &str) -> Vec<OsString> {
    text_args(&[
        "--import-id",
        identity,
        "--start-movie-tick",
        "400",
        "--end-movie-tick",
        "800",
    ])
}

#[test]
fn immutable_movie_selection_coexists_with_writer_and_counts_final_read_allowances() -> Test {
    let directory = Directory::new()?;
    let (root, identity) = imported_without_external_source(&directory)?;
    let (cx, _writer) = open_writer(&root)?;
    fs::write(
        root.join("LAYOUT.tmp.movie-must-not-recover"),
        b"preserve this entry",
    )?;
    let before = tree(&root)?;
    let base = selection(&identity);
    let mut output = Vec::new();
    execute(&root, "select-movie", &base, &mut output)?;
    let rendered = std::str::from_utf8(&output)?;
    assert_eq!(field(rendered, "deployment_mutated")?, "false");
    assert_eq!(field(rendered, "selection_complete")?, "true");
    assert!(rendered.contains("movie_sample=0 segment=3 "));
    assert!(rendered.contains("movie_sample=1 segment=1 "));
    let used_bytes = field(rendered, "payload_read_bytes")?.parse::<usize>()?;
    let used_objects = field(rendered, "payload_read_attempts")?.parse::<usize>()?;
    let mut exact = base.clone();
    exact.extend(text_args(&[
        "--max-read-bytes",
        &used_bytes.to_string(),
        "--max-read-objects",
        &used_objects.to_string(),
    ]));
    let mut repeated = Vec::new();
    execute(&root, "select-movie", &exact, &mut repeated)?;
    assert_eq!(repeated, output);
    for (key, amount) in [
        ("--max-read-bytes", used_bytes - 1),
        ("--max-read-objects", used_objects - 1),
    ] {
        let manifest = directory.0.join(format!("refused-{key}.bin"));
        let mut short = base.clone();
        short.extend(text_args(&[key, &amount.to_string(), "--manifest-out"]));
        short.push(manifest.as_os_str().to_owned());
        let mut refused = Vec::new();
        assert!(execute(&root, "select-movie", &short, &mut refused).is_err());
        assert!(refused.is_empty());
        assert!(!manifest.exists());
    }
    assert_eq!(tree(&root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn movie_selection_refuses_wrong_site_missing_root_source_loss_and_torn_history_atomically() -> Test
{
    let directory = Directory::new()?;
    let (root, identity) = imported_without_external_source(&directory)?;
    let (cx, writer) = open_writer(&root)?;
    let manifest = directory.0.join("must-not-export.bin");
    let mut extra = selection(&identity);
    extra.push("--manifest-out".into());
    extra.push(manifest.as_os_str().to_owned());
    let before = tree(&root)?;
    let mut wrong = parse(&arguments(&root, "select-movie", &extra))
        .map_err(|(code, reason)| io::Error::other(format!("{code}: {reason}")))?
        .ok_or("missing movie request")?;
    wrong.site = "site:foreign-movie".into();
    let mut output = Vec::new();
    assert!(run(wrong, &mut output).is_err());
    assert!(output.is_empty());
    assert!(!manifest.exists());
    let missing = directory.0.join("absent-deployment");
    assert!(execute(&missing, "select-movie", &extra, &mut output).is_err());
    assert!(output.is_empty());
    assert!(!missing.exists());
    assert!(!manifest.exists());
    assert_eq!(tree(&root)?, before);

    let retained = RetainedFileImport::open(
        &writer,
        ContentDigest::parse(&identity)?,
        RetainedReadLimits::default(),
        &cx,
    )?;
    let last = *retained
        .manifest()
        .ordered_chunks
        .last()
        .ok_or("source chunk")?;
    let source_path = writer.publisher().spool().object_path(last);
    for path in [
        source_path,
        root.join("ledger/journal.fssj"),
        root.join("effects/journal.fssj"),
    ] {
        let original = fs::read(&path)?;
        if path
            .extension()
            .is_some_and(|extension| extension == "fssj")
        {
            let mut damaged = original.clone();
            damaged.extend_from_slice(b"torn");
            fs::write(&path, damaged)?;
        } else {
            fs::remove_file(&path)?;
        }
        let damaged = tree(&root)?;
        assert!(execute(&root, "select-movie", &extra, &mut output).is_err());
        assert!(output.is_empty());
        assert!(!manifest.exists());
        assert_eq!(tree(&root)?, damaged);
        fs::write(path, original)?;
    }
    cx.drain_and_finalize();
    Ok(())
}
