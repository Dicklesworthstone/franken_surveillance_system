#![forbid(unsafe_code)]
//! Real approved native RTSP import -> cold retained movie selection -> private timed output.
//! Synthetic original packets exercise custody and pixel replay; no device is contacted.

#[path = "../../../fss-container/tests/rtsp_movie_support/mod.rs"]
mod source;

use super::{OwnedDirectory, TestResult, command, field, success};
use fss_container::matroska_gray::TimedGrayMatroskaConfig;
use fss_core::{
    BudgetVector, CanonicalEncode, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, StreamId,
};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::rtsp::recording::hevc::{
    HevcRecordingTiming, PreparedHevcRecording, prepare_hevc_recording,
};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording::{
    PreparedRecording, RecordingPacket, RecordingScope, prepare_recording,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SITE: &str = "site:media-cli";
const SENSOR: &str = "sensor:rtsp-movie-cli";
const SLOT: &str = "movie-recording";
const MAX_ORIGIN: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Codec {
    Avc,
    Hevc,
}
impl Codec {
    fn name(self) -> &'static str {
        match self {
            Self::Avc => "avc",
            Self::Hevc => "hevc",
        }
    }
    fn query(self) -> Range<u64> {
        match self {
            Self::Avc => 94_500..99_900,
            Self::Hevc => 112_500..139_500,
        }
    }
    fn half_ns(self) -> u64 {
        match self {
            Self::Avc => 30_000_000,
            Self::Hevc => 150_000_000,
        }
    }
}

enum Native {
    Avc(PreparedRecording),
    Hevc(PreparedHevcRecording),
}
impl Native {
    fn plan(&self) -> &PreparedRecording {
        match self {
            Self::Avc(plan) => plan,
            Self::Hevc(recording) => recording.publication_plan(),
        }
    }
}

fn scope() -> TestResult<RecordingScope> {
    Ok(RecordingScope {
        sensor: SensorId::parse(SENSOR)?,
        stream: StreamId::parse("stream:rtsp-movie-cli")?,
        generation: 1,
        anchor: ContentDigest::sha256(SITE.as_bytes()),
        receive_clock: ContentDigest::sha256(b"explicit RTSP movie test receive clock"),
    })
}

fn borrowed(packets: &[source::Packet]) -> Vec<RecordingPacket<'_>> {
    packets
        .iter()
        .map(|packet| RecordingPacket {
            sequence: packet.sequence,
            received_ns: packet.received_ns,
            bytes: &packet.bytes,
        })
        .collect()
}

fn native(codec: Codec) -> TestResult<Native> {
    match codec {
        Codec::Avc => {
            let input = source::avc()?;
            Ok(Native::Avc(prepare_recording(
                scope()?,
                source::SCALE,
                &source::avc_timing(&input.pictures),
                &borrowed(&input.packets),
            )?))
        }
        Codec::Hevc => {
            let input = source::hevc()?;
            let timing: Vec<_> = source::hevc_timing(&input.pictures)
                .iter()
                .map(|sample| HevcRecordingTiming {
                    decode_time: sample.decode_time,
                    duration: sample.duration,
                    composition_offset: sample.composition_offset,
                })
                .collect();
            Ok(Native::Hevc(prepare_hevc_recording(
                scope()?,
                &input.configuration,
                source::SCALE,
                &timing,
                &borrowed(&input.packets),
            )?))
        }
    }
}

fn publish(path: &Path, plan: &PreparedRecording) -> TestResult {
    let mut archive = LocalRootPublisher::open(
        path,
        LocalPublicationLimits::new(
            8,
            16,
            8,
            64,
            SpoolLimits::new(64, 4 * 1024 * 1024, 1024 * 1024, 64),
        ),
    )?;
    let mut job = RecordingPublication::new(
        plan,
        &mut archive,
        SlotName::parse(SLOT)?,
        plan.byte_len(),
        100,
    )?;
    for now in 0..5 {
        if let RecordingProgress::Published(receipt) = job.step(now, &NeverCancel)? {
            assert_eq!(receipt.root, plan.manifest().root());
            return Ok(());
        }
    }
    Err("native recording did not complete root-last publication".into())
}

fn json_field(output: &Output, key: &str) -> TestResult<String> {
    let text = std::str::from_utf8(&output.stdout)?;
    let marker = format!("\"{key}\":\"");
    // Only controlled synthetic fixture values without quotes are inspected here.
    Ok(text
        .split_once(&marker)
        .ok_or("missing fixture JSON field")?
        .1
        .split_once('"')
        .ok_or("unterminated fixture JSON field")?
        .0
        .to_owned())
}

struct Imported {
    directory: OwnedDirectory,
    root: PathBuf,
    codec: Codec,
    identity: String,
    proof: ContentDigest,
    mp4: Vec<u8>,
    originals: Vec<(ContentDigest, Vec<u8>)>,
}

impl Imported {
    fn new(label: &str, codec: Codec) -> TestResult<Self> {
        let directory = OwnedDirectory::new(&format!("{label}-{}", codec.name()))?;
        let archive = directory.0.join("native archive");
        let root = directory.0.join("deployment");
        let recording = native(codec)?;
        let plan = recording.plan();
        publish(&archive, plan)?;
        let original_scope = &plan.summary().scope;
        let mut args = vec![
            "--archive".into(),
            archive.as_os_str().to_owned(),
            "--root".into(),
            root.as_os_str().to_owned(),
        ];
        args.extend(
            [
                "--site",
                SITE,
                "--window-slot",
                SLOT,
                "--window-root",
                &plan.manifest().root().to_text(),
                "--codec",
                codec.name(),
                "--sensor-id",
                original_scope.sensor.as_str(),
                "--stream-id",
                original_scope.stream.as_str(),
                "--generation",
                &original_scope.generation.to_string(),
                "--anchor",
                &original_scope.anchor.to_text(),
                "--receive-clock",
                &original_scope.receive_clock.to_text(),
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
            .map(std::ffi::OsString::from),
        );
        let preview = Command::new(env!("CARGO_BIN_EXE_fss-import-rtsp"))
            .args(&args)
            .output()?;
        success(&preview);
        assert!(!root.exists(), "preview wrote destination custody");
        args.extend([
            "--approve".into(),
            json_field(&preview, "approval_digest")?.into(),
        ]);
        let imported = Command::new(env!("CARGO_BIN_EXE_fss-import-rtsp"))
            .args(&args)
            .output()?;
        success(&imported);
        assert!(std::str::from_utf8(&imported.stdout)?.contains("\"frames\":4"));
        let identity = json_field(&imported, "import_identity")?;
        let proof = ContentDigest::parse(json_field(&imported, "origin_proof")?)?;
        let objects = plan.objects();
        let mp4 = [objects.initialization, objects.media].concat();
        let mut originals = vec![(plan.manifest().root(), plan.manifest().canonical_bytes())];
        originals.extend(
            plan.children()
                .into_iter()
                .map(|(_, digest, bytes)| (digest, bytes.to_vec())),
        );
        // Export must recover custody in a fresh process, with the source archive unavailable.
        fs::rename(&archive, directory.0.join("offline native archive"))?;
        Ok(Self {
            directory,
            root,
            codec,
            identity,
            proof,
            mp4,
            originals,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.0.join(name)
    }

    fn selection(&self, action: &str) -> Command {
        let query = self.codec.query();
        let mut cmd = command(&self.root, action);
        cmd.args([
            "--import-id",
            &self.identity,
            "--start-movie-tick",
            &query.start.to_string(),
            "--end-movie-tick",
            &query.end.to_string(),
        ]);
        cmd
    }

    fn export(&self, path: &Path) -> Command {
        let mut cmd = self.selection("export-movie");
        cmd.args([
            "--interpretation",
            "ycbcr",
            "--output-format",
            "gray-mkv",
            "--output-timing",
            "movie",
            "--max-dimension",
            "256",
            "--max-pixels",
            "65536",
            "--work-units",
            "1000000000",
        ])
        .arg("--output")
        .arg(path);
        cmd
    }

    fn journals(&self) -> TestResult<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }

    fn retained_objects(&self) -> TestResult<(Vec<PathBuf>, Vec<(PathBuf, Vec<u8>)>)> {
        let cx = context(&self.root)?;
        let deployment = ReferenceDeployment::open(&self.root, SITE, &cx)?;
        let retained = RetainedFileImport::open(
            &deployment,
            ContentDigest::parse(&self.identity)?,
            RetainedReadLimits::default(),
            &cx,
        )?;
        assert_eq!(
            retained.manifest().input_sha256,
            ContentDigest::sha256(&self.mp4)
        );
        let originals = self
            .originals
            .iter()
            .map(|(digest, _)| deployment.publisher().spool().object_path(*digest))
            .collect();
        let chunks = retained
            .manifest()
            .ordered_chunks
            .iter()
            .map(|digest| {
                let path = deployment.publisher().spool().object_path(*digest);
                Ok((path.clone(), fs::read(path)?))
            })
            .collect::<TestResult<Vec<_>>>()?;
        assert_eq!(
            chunks
                .iter()
                .flat_map(|(_, bytes)| bytes.iter().copied())
                .collect::<Vec<_>>(),
            self.mp4
        );
        assert_eq!(
            ContentDigest::sha256(&deployment.publisher().spool().read(self.proof)?),
            self.proof
        );
        drop(deployment);
        cx.drain_and_finalize();
        Ok((originals, chunks))
    }
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-movie-test".into(),
        operation_id: OperationId::parse("operation:rtsp-movie-test")?,
        principal: "principal:test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root)?)
}

fn expected(movie: &Imported, masked: bool) -> TestResult<Vec<u8>> {
    let images = source::native_images(&movie.mp4)?;
    let first = images.get(&2).ok_or("selected image")?;
    let half = movie.codec.half_ns();
    let config = TimedGrayMatroskaConfig::new(first.dimensions, half * 2)?;
    let mut bytes = config.initialization()?.bytes().to_vec();
    for (ordinal, segment) in [2, 1].into_iter().enumerate() {
        let image = images.get(&segment).ok_or("selected image")?;
        assert_eq!(image.dimensions, first.dimensions);
        bytes.extend_from_slice(
            config
                .frame(
                    ordinal as u64,
                    ordinal as u64 * half,
                    (ordinal as u64 + 1) * half,
                )?
                .prefix(),
        );
        if masked {
            bytes.resize(bytes.len() + image.pixels.len(), MASK_FILL_LUMA);
        } else {
            bytes.extend_from_slice(&image.pixels);
        }
    }
    Ok(bytes)
}

fn values(output: &Output, name: &str) -> TestResult<Vec<String>> {
    let prefix = format!("{name}=");
    Ok(std::str::from_utf8(&output.stdout)?
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .collect())
}

fn refused(output: &Output, path: &Path) -> TestResult {
    assert!(!output.status.success());
    assert!(!path.exists(), "refused RTSP movie created an output file");
    let text = std::str::from_utf8(&output.stdout)?;
    for marker in [
        "movie_export_complete=true",
        "selection_media_exported=true",
        "gray_mkv_sha256=",
        "gray_mkv_frame_receipts_sha256=",
        "gray_mkv_export_complete=true",
    ] {
        assert!(!text.contains(marker), "refusal certified {marker}");
    }
    Ok(())
}

#[test]
fn approved_original_rtsp_imports_export_exact_clipped_movie_pixels_and_timing_after_restart()
-> TestResult {
    for codec in [Codec::Avc, Codec::Hevc] {
        let movie = Imported::new("rtsp-movie-clip", codec)?;
        let before = movie.journals()?;
        let selected = movie.selection("select-movie").output()?;
        success(&selected);
        assert_eq!(
            field(&selected, "selection_source_adapter")?,
            "ADP-RTSP-RECORDING-ARCHIVE-001"
        );
        let proof_text = movie.proof.to_text();
        assert_eq!(
            field(&selected, "selection_source_adapter_generation")?,
            format!(
                "gen:rtsp-recording-archive:v1:{}",
                proof_text.strip_prefix("sha256:").ok_or("SHA-256 proof")?
            )
        );
        assert_eq!(
            field(&selected, "selection_verified_source_sha256")?,
            ContentDigest::sha256(&movie.mp4).to_text()
        );
        assert_eq!(
            field(&selected, "selection_time_basis")?,
            "container_movie_timeline"
        );
        assert_eq!(
            field(&selected, "selection_origin_read_model")?,
            "conservative_pre_io_bytes"
        );
        assert_eq!(
            field(&selected, "selection_origin_read_bytes_charged")?.parse::<u64>()?,
            movie
                .originals
                .iter()
                .map(|(_, bytes)| bytes.len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            field(&selected, "selection_maximum_origin_read_bytes")?.parse::<u64>()?,
            MAX_ORIGIN
        );
        let path = movie.path("clip.mkv");
        let output = movie.export(&path).output()?;
        success(&output);
        assert_eq!(fs::read(path)?, expected(&movie, false)?);
        assert_eq!(values(&output, "frame_segment")?, ["2", "1"]);
        assert_eq!(field(&output, "movie_output_frames")?, "2");
        assert_eq!(field(&output, "movie_cached_frames")?, "2");
        assert_eq!(
            field(&output, "gray_mkv_duration_ns")?.parse::<u64>()?,
            codec.half_ns() * 2
        );
        assert_eq!(
            field(&output, "gray_mkv_source_capture_timing_preserved")?,
            "false"
        );
        assert_eq!(field(&output, "movie_export_complete")?, "true");
        assert_eq!(movie.journals()?, before);
        movie.retained_objects()?;
    }
    Ok(())
}

#[test]
fn rtsp_movie_output_uses_current_privacy_mask_without_changing_original_custody() -> TestResult {
    for codec in [Codec::Avc, Codec::Hevc] {
        let movie = Imported::new("rtsp-movie-mask", codec)?;
        let plain = movie.path("plain.mkv");
        let output = movie.export(&plain).output()?;
        success(&output);
        assert_eq!(fs::read(plain)?, expected(&movie, false)?);
        let (_, chunks) = movie.retained_objects()?;
        let images = source::native_images(&movie.mp4)?;
        let dimensions = images.get(&0).ok_or("first source picture")?.dimensions;
        let cx = context(&movie.root)?;
        let mut deployment = ReferenceDeployment::open(&movie.root, SITE, &cx)?;
        let policy = PrivacyMaskPolicy::new(
            SensorId::parse(SENSOR)?,
            dimensions,
            &[[0, 0, dimensions[0], dimensions[1]]],
        )?;
        let approval = preview_mask(&deployment, &policy)?.approval;
        declare_mask(&mut deployment, &policy, approval, &cx)?;
        drop(deployment);
        cx.drain_and_finalize();
        let before = movie.journals()?;
        let masked = movie.path("masked.mkv");
        let output = movie.export(&masked).output()?;
        success(&output);
        assert_eq!(fs::read(masked)?, expected(&movie, true)?);
        assert_eq!(values(&output, "frame_segment")?, ["2", "1"]);
        for (path, bytes) in chunks {
            assert_eq!(fs::read(path)?, bytes);
        }
        assert_eq!(movie.journals()?, before);
    }
    Ok(())
}

#[test]
fn every_missing_or_corrupt_native_rtsp_original_refuses_movie_export_with_mp4_intact() -> TestResult
{
    for codec in [Codec::Avc, Codec::Hevc] {
        let movie = Imported::new("rtsp-movie-originals", codec)?;
        let (originals, chunks) = movie.retained_objects()?;
        let before = movie.journals()?;
        for (index, (path, (_, original))) in originals.iter().zip(&movie.originals).enumerate() {
            assert_eq!(&fs::read(path)?, original);
            let withheld = movie.path(&format!("withheld-{index}"));
            fs::rename(path, &withheld)?;
            let output = movie.path(&format!("missing-{index}.mkv"));
            refused(&movie.export(&output).output()?, &output)?;
            fs::rename(&withheld, path)?;
            let mut damaged = original.clone();
            *damaged.first_mut().ok_or("empty native original")? ^= 1;
            fs::write(path, damaged)?;
            let output = movie.path(&format!("corrupt-{index}.mkv"));
            refused(&movie.export(&output).output()?, &output)?;
            fs::write(path, original)?;
            for (path, bytes) in &chunks {
                assert_eq!(&fs::read(path)?, bytes);
            }
        }
        let restored = movie.path("restored.mkv");
        success(&movie.export(&restored).output()?);
        assert_eq!(fs::read(restored)?, expected(&movie, false)?);
        assert_eq!(movie.journals()?, before);
    }
    Ok(())
}

#[test]
fn rtsp_movie_origin_read_allowance_is_explicit_bounded_and_refuses_before_output() -> TestResult {
    for codec in [Codec::Avc, Codec::Hevc] {
        let movie = Imported::new("rtsp-movie-origin-budget", codec)?;
        let selected = movie.selection("select-movie").output()?;
        success(&selected);
        let charged = field(&selected, "selection_origin_read_bytes_charged")?.parse::<u64>()?;
        assert!(charged > 1 && charged <= MAX_ORIGIN);
        let before = movie.journals()?;
        for (index, limit) in [
            "0".to_owned(),
            "-1".to_owned(),
            "invalid".to_owned(),
            (MAX_ORIGIN + 1).to_string(),
            "1".to_owned(),
            (charged - 1).to_string(),
        ]
        .iter()
        .enumerate()
        {
            let path = movie.path(&format!("refused-origin-budget-{index}.mkv"));
            let output = movie
                .export(&path)
                .args(["--max-origin-read-bytes", limit])
                .output()?;
            refused(&output, &path)?;
        }
        let path = movie.path("exact-origin-budget.mkv");
        let output = movie
            .export(&path)
            .args(["--max-origin-read-bytes", &charged.to_string()])
            .output()?;
        success(&output);
        assert_eq!(fs::read(path)?, expected(&movie, false)?);
        assert_eq!(
            field(&output, "selection_origin_read_bytes_charged")?.parse::<u64>()?,
            charged
        );
        assert_eq!(movie.journals()?, before);
    }
    Ok(())
}
