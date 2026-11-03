#![forbid(unsafe_code)]
//! Parent authority, actual-pin selection and nonrenewing analysis admission.

use std::ffi::OsString;
use std::io::{self, Write};

use fss_core::ContentDigest;
use fss_reference::http_reconnect_history::ReconnectHistoryPin;

use super::plan::Options;

fn digest(byte: u8) -> String {
    ContentDigest::sha256(&[byte]).to_text()
}

fn args() -> Vec<OsString> {
    [
        (
            "--root",
            "/not-created-fss-http-sentinel/archive".to_owned(),
        ),
        ("--peer", "127.0.0.1:9".into()),
        ("--host", "camera.test".into()),
        ("--target", "/mjpeg".into()),
        ("--source", digest(1)),
        ("--generations", "7,9".into()),
        ("--receive-clock", digest(2)),
        ("--retention-evidence", digest(3)),
        ("--owner-authorized", "yes".into()),
        ("--plaintext", "yes".into()),
        ("--retain-originals", "yes".into()),
        ("--durable-history", "yes".into()),
        (
            "--deployment-root",
            "/not-created-fss-http-sentinel/deployment".into(),
        ),
        ("--site", "site:http-capture-sentinel".into()),
        (
            "--binding",
            "7,sensor:camera,stream:camera,10000000000,0,0,25".into(),
        ),
        (
            "--binding",
            "9,sensor:camera,stream:camera,10000000000,0,0,25".into(),
        ),
        ("--interpretation", "gray".into()),
        (
            "--package",
            "/not-created-fss-http-sentinel/model.fmpk".into(),
        ),
        ("--package-digest", digest(4)),
        ("--read-originals", "yes".into()),
        ("--read-model", "yes".into()),
        ("--execute-perception", "yes".into()),
        ("--retain-analysis", "yes".into()),
        ("--sentinel-every-frames", "2".into()),
        ("--sentinel-burst-frames", "1".into()),
        ("--sentinel-max-inferences", "2".into()),
    ]
    .into_iter()
    .flat_map(|(key, value)| [OsString::from(key), OsString::from(value)])
    .collect()
}

fn replace(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(pair) = args.chunks_exact_mut(2).find(|pair| pair[0] == key) {
        pair[1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

#[test]
fn pure_parent_preview_binds_model_route_capture_and_full_analysis_reservation() {
    let original = args();
    let plan = Options::parse(&original).unwrap();
    let preview = plan.preview().unwrap();
    assert!(preview.contains("\"format\":\"fss.http_capture_sentinel.v1\""));
    assert!(
        preview.contains("\"history_selection\":\"exact_typed_settled_prefix_from_this_capture\"")
    );
    assert!(preview.contains("\"camera.test\""));
    assert!(preview.contains("\"interpretation\":\"gray\""));
    assert!(preview.contains("\"minimum_score_ppm\":null"));
    assert!(preview.contains("\"writes\":\"none\""));
    assert!(plan.approve.is_none());
    assert!(plan.capture.approve.is_none());
    assert!(plan.analysis.approve.is_none());
    assert_ne!(plan.approval().unwrap(), plan.capture.approval());
    assert_ne!(plan.approval().unwrap(), plan.analysis.approval().unwrap());
    let mut reordered: Vec<_> = original.chunks_exact(2).map(<[OsString]>::to_vec).collect();
    reordered.sort_by(|left, right| left[0].cmp(&right[0]));
    assert_eq!(
        Options::parse(&reordered.into_iter().flatten().collect::<Vec<_>>())
            .unwrap()
            .approval()
            .unwrap(),
        plan.approval().unwrap()
    );
    for (key, value) in [
        ("--target", "/other"),
        ("--analysis-work", "2000000000000"),
        ("--analysis-framing-work", "20000000000"),
        ("--analysis-timeout-ms", "500000"),
        ("--analysis-report-bytes", "33554432"),
        ("--max-frame-pixels", "4096"),
        ("--minimum-score-ppm", "1"),
        ("--kernels", "scalar-reference"),
        ("--threads", "2"),
        ("--interpretation", "ycbcr"),
        ("--sentinel-every-frames", "3"),
    ] {
        let mut changed = original.clone();
        replace(&mut changed, key, value);
        assert_ne!(
            Options::parse(&changed).unwrap().approval().unwrap(),
            plan.approval().unwrap(),
            "{key}"
        );
    }
}

#[test]
fn native_capture_approval_cannot_authorize_parent_model_or_source_work() {
    let mut plan = Options::parse(&args()).unwrap();
    plan.approve = Some(plan.capture.approval());
    let mut output = Vec::new();
    assert_eq!(
        super::driver::execute(&mut plan, &mut output),
        Err(super::AUTHORITY)
    );
    assert!(output.is_empty());
    // These deliberately absent resources are never consulted by an unapproved operation.
    plan.approve = Some(plan.analysis.approval().unwrap());
    assert_eq!(
        super::driver::execute(&mut plan, &mut output),
        Err(super::AUTHORITY)
    );
    assert!(output.is_empty());
}

#[test]
fn declared_bindings_and_analysis_capacity_must_cover_every_reserved_generation() {
    for (key, value) in [
        (
            "--binding",
            "8,sensor:camera,stream:camera,10000000000,0,0,25",
        ),
        ("--max-frames-per-generation", "127"),
        ("--max-bytes-per-generation", "67108863"),
        ("--max-history-reads", "1023"),
        ("--max-history-bytes", "134217727"),
        ("--stop-after-frames", "1"),
        ("--durable-history", "no"),
        ("--retain-analysis", "no"),
        ("--read-model", "no"),
        ("--read-originals", "no"),
        ("--execute-perception", "no"),
        ("--archive", "/unselected/archive"),
        ("--history-root", &digest(10)),
    ] {
        let mut changed = args();
        replace(&mut changed, key, value);
        assert!(Options::parse(&changed).is_err(), "{key}");
    }
    let mut missing = args();
    let index = missing
        .iter()
        .position(|value| value == "--binding")
        .unwrap();
    missing.drain(index..index + 2);
    assert!(Options::parse(&missing).is_err());
}

#[test]
fn exact_typed_history_selects_only_started_bindings_without_refilling_any_ceiling() {
    let plan = Options::parse(&args()).unwrap();
    let outer = plan.approval().unwrap();
    let pin = ReconnectHistoryPin {
        session: plan.capture.approval(),
        root: ContentDigest::sha256(b"actual source-closed history"),
        connections: 1,
    };
    let (resolved, argv) = plan.resolve(pin).unwrap();
    assert_eq!(resolved.plan.history, pin);
    assert_eq!(resolved.plan.bindings.len(), 1);
    assert_eq!(resolved.plan.bindings[0].generation, 7);
    assert_eq!(resolved.plan.sampling, plan.analysis.plan.sampling);
    assert_eq!(
        resolved.limits.sentinel.digest(),
        plan.analysis.limits.sentinel.digest()
    );
    assert_eq!(resolved.work, plan.analysis.work);
    assert_eq!(resolved.framing, plan.analysis.framing);
    assert_eq!(
        resolved.archive_read_bytes,
        plan.analysis.archive_read_bytes
    );
    assert_eq!(resolved.timeout_ms, plan.analysis.timeout_ms);
    assert_eq!(
        resolved.limits.history.maximum_reads,
        plan.analysis.limits.history.maximum_reads
    );
    assert_eq!(
        resolved.limits.history.maximum_bytes,
        plan.analysis.limits.history.maximum_bytes
    );
    assert_eq!(
        resolved.limits.history.archive.maximum_reads,
        plan.analysis.limits.history.archive.maximum_reads
    );
    assert_eq!(
        resolved.limits.history.archive.maximum_bytes,
        plan.analysis.limits.history.archive.maximum_bytes
    );
    assert_eq!(argv[0], "fss-sentinel-http-history");
    assert!(!argv.iter().any(|word| word == "--approve-import"));
    let parsed = super::analysis_plan::Options::parse(
        &argv[1..].iter().map(OsString::from).collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(parsed.approval().unwrap(), resolved.approval().unwrap());
    assert_eq!(plan.approval().unwrap(), outer);
    assert!(
        plan.resolve(ReconnectHistoryPin {
            connections: 0,
            ..pin
        })
        .is_err()
    );
    assert!(
        plan.resolve(ReconnectHistoryPin {
            connections: 3,
            ..pin
        })
        .is_err()
    );
    assert!(
        plan.resolve(ReconnectHistoryPin {
            session: ContentDigest::sha256(b"other capture"),
            ..pin
        })
        .is_err()
    );
}

#[test]
fn complete_parent_row_refuses_oversized_or_failed_output() {
    let mut plan = Options::parse(&args()).unwrap();
    plan.analysis.limits.maximum_report_bytes = 1024;
    let mut output = Vec::new();
    assert_eq!(
        super::emit(
            &plan,
            &mut output,
            "completed",
            fss_cli::agent_json::string(&"x".repeat(1024))
        ),
        Err(super::LIMIT)
    );
    assert!(output.is_empty());
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        super::emit(&plan, &mut Broken, "analysis_failed", "{}".into()),
        Err(super::OUTPUT)
    );
}
