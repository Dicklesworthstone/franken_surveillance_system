#![forbid(unsafe_code)]
//! Real CLI acquisition of timed and unknown-time candidates with cold destination replay.

use super::*;
use fss_cli::agent_json::{array, object, string};
use fss_cli::json_input::{Value, parse};
use fss_packet::ntp::SntpRequest;
use fss_reference::ReferenceDeployment;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_clock::{
    ClockWindow, ReceiveClockBracket, RecordingClockCodec, RecordingClockIndex, clock_slot,
    publish_clock_index,
};
use fss_reference::site::clock::HostClockSample;
use fss_reference::site::clock_proof::{LOCAL_NTP_CLOCK_POLICY, LocalNtpExchange};

const EPOCH: u64 = 1_800_000_000_000_000_000;
const ADMISSION: u64 = 40_000_000;

fn host(monotonic_ns: u64) -> HostClockSample {
    HostClockSample {
        monotonic_before_ns: monotonic_ns,
        wall_clock_unix_ns: EPOCH + monotonic_ns,
        monotonic_after_ns: monotonic_ns,
    }
}

fn exchange() -> Test<LocalNtpExchange> {
    let request = SntpRequest::new(EPOCH)?;
    let mut reply = [0_u8; 48];
    reply[0] = 0x24;
    reply[1] = 2;
    reply[2] = 6;
    reply[3] = (-30_i8) as u8;
    reply[12..16].copy_from_slice(b"TEST");
    for (start, unix_ns) in [
        (16, EPOCH - 1_000_000_000),
        (32, EPOCH + 1_009_000_000),
        (40, EPOCH + 1_010_000_000),
    ] {
        let seconds = (unix_ns / 1_000_000_000 + 2_208_988_800) as u32;
        let fraction = ((u128::from(unix_ns % 1_000_000_000) << 32) / 1_000_000_000) as u32;
        reply[start..start + 4].copy_from_slice(&seconds.to_be_bytes());
        reply[start + 4..start + 8].copy_from_slice(&fraction.to_be_bytes());
    }
    reply[24..32].copy_from_slice(&request.wire_bytes()[40..48]);
    Ok(LocalNtpExchange {
        peer: "127.0.0.1:123".parse()?,
        request: *request.wire_bytes(),
        reply,
        sent_before: host(0),
        sent_after: host(1_000),
        received_before: host(20_000_000),
        received_after: host(20_001_000),
        policy: LOCAL_NTP_CLOCK_POLICY,
    })
}

fn session(
    scope: &CatalogScope,
    catalog_root: ContentDigest,
    clock: &RecordingClockIndex,
) -> Test<String> {
    Ok(array(&[object(&[
        ("codec", string("hevc")),
        ("sensor", string(scope.recording.sensor.as_str())),
        ("stream", string(scope.recording.stream.as_str())),
        (
            "generation",
            string(&scope.recording.generation.to_string()),
        ),
        ("source_anchor", string(&scope.recording.anchor.to_text())),
        (
            "receive_clock",
            string(&scope.recording.receive_clock.to_text()),
        ),
        ("decode_clock", string(&scope.decode_clock.to_text())),
        ("time_scale", scope.time_scale.to_string()),
        (
            "catalogs",
            array(&[object(&[
                ("slot", string("query-catalog")),
                ("root", string(&catalog_root.to_text())),
            ])]),
        ),
        (
            "clock_slot",
            string(clock_slot(RecordingClockCodec::Hevc, scope)?.as_str()),
        ),
        ("clock_root", string(&clock.root().to_text())),
    ])]))
}

fn identities(report: &str) -> Test<Vec<String>> {
    let value = parse(report)?;
    let imports = value
        .object()
        .and_then(|fields| fields.get("imports"))
        .and_then(Value::array)
        .ok_or("imports")?;
    imports
        .iter()
        .map(|row| {
            row.object()
                .and_then(|fields| fields.get("import_identity"))
                .and_then(Value::text)
                .map(str::to_owned)
                .ok_or_else(|| "native import identity".into())
        })
        .collect()
}

#[test]
fn utc_cli_retains_every_unknown_time_candidate_and_preserves_conditional_clock_provenance() -> Test
{
    let directory = Directory::new()?;
    let mut packets = hevc_recording_support::packets()?;
    for packet in &mut packets {
        packet.received_ns = ADMISSION;
    }
    let first = hevc_recording_support::prepare(&packets, &hevc_recording_support::timings(4))?;
    let (catalog_root, decode_clock, _) = query::catalog(&directory, &first)?;
    let scope = CatalogScope {
        recording: first.summary().scope.clone(),
        decode_clock,
        time_scale: first.summary().time_scale,
    };
    // Only the first window has a retained clock annotation. The second must remain a
    // complete candidate for every UTC predicate until its own clock evidence exists.
    let clock = RecordingClockIndex::prepare(
        scope.clone(),
        RecordingClockCodec::Hevc,
        ContentDigest::sha256(b"historical-fixture-clock-approval"),
        exchange()?,
        host(100_000_000),
        &[ReceiveClockBracket {
            admission_ns: ADMISSION,
            completed: HostClockSample {
                monotonic_before_ns: ADMISSION + 1_000,
                wall_clock_unix_ns: EPOCH + ADMISSION + 1_500,
                monotonic_after_ns: ADMISSION + 2_000,
            },
        }],
        &[ClockWindow::from_hevc(
            SlotName::parse("hevc-recording-cli")?,
            &first,
        )?],
    )?;
    let archive = directory.0.join("source archive");
    let mut source = LocalRootPublisher::open(&archive, query::source_limits())?;
    publish_clock_index(&clock, &mut source, &NeverCancel)?;
    let interval = clock
        .windows()
        .first()
        .ok_or("clocked fixture")?
        .utc_interval();
    let root = directory.0.join("destination");
    let cx = query::context(&root)?;
    drop(ReferenceDeployment::open(
        &root,
        "site:rtsp-import-cli",
        &cx,
    )?);
    cx.drain_and_finalize();
    let snapshot = || -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(root.join("ledger/journal.fssj"))?,
            fs::read(root.join("effects/journal.fssj"))?,
        ))
    };
    let before = snapshot()?;
    let args: Vec<OsString> = [
        "query-utc".to_owned(),
        "--archive".into(),
        archive.to_str().ok_or("archive path")?.into(),
        "--root".into(),
        root.to_str().ok_or("root path")?.into(),
        "--site".into(),
        "site:rtsp-import-cli".into(),
        "--sessions".into(),
        session(&scope, catalog_root, &clock)?,
        "--start-utc-ns".into(),
        interval.earliest_ns.to_string(),
        "--end-utc-ns".into(),
        (interval.latest_ns + 1).to_string(),
        "--receive-time-ns".into(),
        "1800000000100000000".into(),
        "--owner-authorized".into(),
        "yes".into(),
        "--read-originals".into(),
        "yes".into(),
        "--retain-originals".into(),
        "yes".into(),
        "--timeout-ms".into(),
        "600000".into(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    // Source publisher remains locked throughout preview, approved reads and reconciliation.
    let preview = good(run(&args)?)?;
    assert!(preview.contains("\"unknown_clock_candidates\":1"));
    assert!(preview.contains("\"selected_windows_count\":2"));
    assert!(preview.contains("\"clock_state\":\"clock_unavailable\""));
    assert!(preview.contains("\"clock_state\":\"conditional_node_observation\""));
    assert!(preview.contains("\"source_media_reads\":0"));
    assert!(preview.contains("\"receive_time_ns\":\"1800000000100000000\""));
    assert_eq!(snapshot()?, before);
    let mut short = args.clone();
    short.extend(["--max-windows".into(), "1".into()]);
    assert!(
        !run(&short)?.status.success(),
        "unknown-clock candidate was discarded to fit output"
    );
    let mut wrong = args.clone();
    wrong.extend([
        "--approve".into(),
        ContentDigest::sha256(b"wrong-utc-acquisition")
            .to_text()
            .into(),
    ]);
    assert!(!run(&wrong)?.status.success());
    assert_eq!(snapshot()?, before);
    let mut approved = args.clone();
    approved.extend([
        "--approve".into(),
        field(&preview, "approval_digest")?.into(),
    ]);
    let result = good(run(&approved)?)?;
    assert!(result.contains("\"complete\":true"));
    assert!(result.contains("\"completed_imports\":2"));
    assert!(result.contains("\"frames\":8"));
    assert!(result.contains("\"capture_time_label\":\"unknown\""));
    assert!(result.contains("\"trusted_utc\":false"));
    assert!(result.contains("\"packet_to_clock_correspondence_replayed\":false"));
    assert!(result.contains(&clock.root().to_text()));
    let imported = identities(&result)?;
    assert_eq!(imported.len(), 2);
    assert_ne!(imported[0], imported[1]);
    let stored = root.join("objects/spool/objects");
    for partial_root in [catalog_root, clock.root()] {
        assert!(
            !stored
                .join(partial_root.to_text().trim_start_matches("sha256:"))
                .exists(),
            "partial catalog/clock closure was retained"
        );
    }
    let committed = snapshot()?;
    assert!(
        !run(&approved)?.status.success(),
        "stale deployment approval was accepted"
    );
    let fresh = good(run(&args)?)?;
    approved.pop();
    approved.push(field(&fresh, "approval_digest")?.into());
    let reused = good(run(&approved)?)?;
    assert_eq!(identities(&reused)?, imported);
    assert_eq!(reused.matches("\"reused\":true").count(), 2);
    assert_eq!(snapshot()?, committed);
    drop(source);
    fs::rename(&archive, directory.0.join("offline archive"))?;
    for identity in imported {
        let verified = good(
            Command::new(env!("CARGO_BIN_EXE_fss-file"))
                .args(["verify", "--root"])
                .arg(&root)
                .args(["--site", "site:rtsp-import-cli", "--import-id", &identity])
                .output()?,
        )?;
        assert!(verified.contains("segment_count=4"));
        assert!(verified.contains("capture_time_class=unknown"));
    }
    assert_eq!(
        snapshot()?.1,
        before.1,
        "acquisition mutated unrelated effect state"
    );
    Ok(())
}
