#![forbid(unsafe_code)]
//! Minimal native fixtures and subprocess boundaries for replay import.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::ingest::rtsp_import::RtspImportCodec;
use fss_reference::rtsp::client::replay::{ReplayAcceptance, ReplayWindow};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_archive::ArchiveNamespace;
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::{
    OnvifReplaySource, ReplayReceipt, ReplayRequest, ReplayTermination, ReplayWindowProof,
    publish_replay_receipt,
};

use super::{hevc_recording_support, recording_support};

pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const SITE: &str = "site:replay-import-cli";
// Forked binaries must never inherit a concurrent fixture's native archive lock.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub struct Directory(pub PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-replay-import-cli-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned test directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

enum Original {
    Avc(PreparedRecording),
    Hevc(PreparedHevcRecording),
}
impl Original {
    fn plan(&self) -> &PreparedRecording {
        match self {
            Self::Avc(value) => value,
            Self::Hevc(value) => value.publication_plan(),
        }
    }
    fn proof(&self, slot: SlotName) -> Test<ReplayWindowProof> {
        Ok(match self {
            Self::Avc(value) => ReplayWindowProof::from_avc(slot, value)?,
            Self::Hevc(value) => ReplayWindowProof::from_hevc(slot, value)?,
        })
    }
}

pub struct Fixture {
    pub directory: Directory,
    pub receipt: ReplayReceipt,
    pub frames: usize,
}
impl Fixture {
    pub fn new(codec: RtspImportCodec, count: usize, gap: u64) -> Test<Self> {
        let directory = Directory::new()?;
        let mut originals = Vec::new();
        for ordinal in 0..count {
            originals.push(match codec {
                RtspImportCodec::Avc => Original::Avc(
                    recording_support::fixture(900 + ordinal as u128, true)?
                        .prepare_at(ordinal as u64 * (3600 + gap))?,
                ),
                RtspImportCodec::Hevc => {
                    let mut packets = hevc_recording_support::packets()?;
                    let offset = ordinal as u64 * (72_000 + gap);
                    for packet in &mut packets {
                        packet.sequence += ordinal as u64 * 32;
                        packet.received_ns += ordinal as u64 * 32;
                        packet.bytes[2..4].copy_from_slice(&(packet.sequence as u16).to_be_bytes());
                        let time = u32::from_be_bytes(packet.bytes[4..8].try_into()?);
                        packet.bytes[4..8].copy_from_slice(&(time + offset as u32).to_be_bytes());
                    }
                    let mut timing = hevc_recording_support::timings(4);
                    for sample in &mut timing {
                        sample.decode_time += offset;
                    }
                    Original::Hevc(hevc_recording_support::prepare(&packets, &timing)?)
                }
            });
        }
        let source_scope = originals
            .first()
            .ok_or("fixture needs a window")?
            .plan()
            .summary()
            .scope
            .clone();
        let window = ReplayWindow::from_timestamps("20261101T120000Z", "20261101T120500Z")?;
        let route = ContentDigest::sha256(b"independently approved credential-free route");
        let base_clock = ContentDigest::sha256(b"original receiver decode epoch");
        let mut request = match codec {
            RtspImportCodec::Avc => ReplayRequest::new(source_scope, route, window, base_clock)?,
            RtspImportCodec::Hevc => {
                ReplayRequest::new_hevc(source_scope, route, window, base_clock)?
            }
        };
        if codec == RtspImportCodec::Hevc {
            request = request.with_onvif_source(OnvifReplaySource::new(
                ContentDigest::sha256(b"approved protected ONVIF recording selection"),
                ContentDigest::sha256(b"complete protected replay handoff"),
                ContentDigest::sha256(b"observed private replay input file"),
                ContentDigest::sha256(b"selected ONVIF services"),
                ContentDigest::sha256(b"complete GetServices observation"),
                ContentDigest::sha256(b"exact selected recording token"),
                ContentDigest::sha256(b"complete recording information"),
                ContentDigest::sha256(b"exact credential-free replay URI"),
                ContentDigest::sha256(b"complete GetReplayUri observation"),
            )?)?;
        }
        let scope = CatalogScope {
            recording: request.scope().clone(),
            decode_clock: request.decode_clock(),
            time_scale: 90_000,
        };
        let mut publisher = LocalRootPublisher::open(
            directory.0.join("source archive"),
            LocalPublicationLimits::new(
                16,
                512,
                16,
                128,
                SpoolLimits::new(128, 32 * 1024 * 1024, 8 * 1024 * 1024, 256),
            ),
        )?;
        let mut windows = Vec::new();
        let mut frames = 0;
        for (ordinal, original) in originals.iter().enumerate() {
            let slot = match codec {
                RtspImportCodec::Avc => {
                    ArchiveNamespace::new(scope.clone())?.window_slot(ordinal)?
                }
                RtspImportCodec::Hevc => {
                    HevcArchiveNamespace::new(scope.clone())?.window_slot(ordinal)?
                }
            };
            let plan = original.plan();
            let mut publication = RecordingPublication::new(
                plan,
                &mut publisher,
                slot.clone(),
                plan.byte_len(),
                100,
            )?;
            for now in 0..4 {
                assert!(matches!(
                    publication.step(now, &NeverCancel)?,
                    RecordingProgress::ChildStaged { .. }
                ));
            }
            assert!(matches!(
                publication.step(4, &NeverCancel)?,
                RecordingProgress::Published(_)
            ));
            drop(publication);
            windows.push(original.proof(slot)?);
            frames += plan.summary().samples;
        }
        let accepted = ReplayAcceptance::new(
            7,
            window,
            ReplayWindow::from_timestamps("20261101T120100Z", "20261101T120400Z")?,
        )?;
        let receipt = ReplayReceipt::prepare(
            request,
            scope,
            ContentDigest::sha256(b"exact native recorder capture approval"),
            accepted,
            windows,
            ReplayTermination::Budget,
            false,
        )?;
        publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
        drop(publisher);
        Ok(Self {
            directory,
            receipt,
            frames,
        })
    }
    pub fn archive(&self) -> PathBuf {
        self.directory.0.join("source archive")
    }
    pub fn target(&self) -> PathBuf {
        self.directory.0.join("destination")
    }
    pub fn journals(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.target().join("ledger/journal.fssj"))?,
            fs::read(self.target().join("effects/journal.fssj"))?,
        ))
    }
    pub fn args(&self) -> Test<Vec<OsString>> {
        let scope = self.receipt.scope();
        let mut args = vec![
            "replay".into(),
            "--archive".into(),
            self.archive().into_os_string(),
            "--root".into(),
            self.target().into_os_string(),
        ];
        for (key, value) in [
            ("--site", SITE.to_owned()),
            (
                "--codec",
                self.receipt.request().codec().as_str().to_owned(),
            ),
            ("--expected-replay-root", self.receipt.root().to_text()),
            (
                "--expected-replay-request",
                self.receipt.request().digest().to_text(),
            ),
            ("--sensor-id", scope.recording.sensor.as_str().to_owned()),
            ("--stream-id", scope.recording.stream.as_str().to_owned()),
            ("--generation", scope.recording.generation.to_string()),
            ("--anchor", scope.recording.anchor.to_text()),
            ("--receive-clock", scope.recording.receive_clock.to_text()),
            ("--decode-clock", scope.decode_clock.to_text()),
            ("--time-scale", scope.time_scale.to_string()),
            ("--receive-time-ns", "5000000000".to_owned()),
            ("--owner-authorized", "yes".to_owned()),
            ("--read-originals", "yes".to_owned()),
            ("--retain-originals", "yes".to_owned()),
            ("--timeout-ms", "600000".to_owned()),
        ] {
            args.extend([key.into(), value.into()]);
        }
        Ok(args)
    }
}

pub fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-import-rtsp"))
        .args(args)
        .output()?)
}
pub fn good(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() <= 64 * 1024);
    Ok(String::from_utf8(output.stdout)?)
}
pub fn field<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    Ok(value
        .object()
        .and_then(|o| o.get(key))
        .and_then(Value::text)
        .ok_or("missing text report field")?)
}
pub fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(at) = args.iter().position(|arg| arg == key) {
        args[at + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}
pub fn approve(args: &mut Vec<OsString>) -> Test {
    if let Some(at) = args.iter().position(|arg| arg == "--approve") {
        args.drain(at..at + 2);
    }
    let preview = parse(&good(run(args)?)?)?;
    set(args, "--approve", field(&preview, "approval_digest")?);
    Ok(())
}
