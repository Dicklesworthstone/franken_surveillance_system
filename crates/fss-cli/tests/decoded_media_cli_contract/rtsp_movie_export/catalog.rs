#![forbid(unsafe_code)]
//! Approved native catalogs/pages through cold command-line movie selection and masked output.
//! Authored process contracts require the real binaries; component runs do not execute them.

use super::*;
use fss_container::demux::{AvcMp4, DemuxLimits};
use fss_object::ObjectManifest;
use fss_reference::rtsp::recording_catalog::hevc::local::HevcCatalogPublication;
use fss_reference::rtsp::recording_catalog::hevc::{
    HevcCatalogWindow, HevcRecordingCatalog, prepare_hevc_catalog,
};
use fss_reference::rtsp::recording_catalog::local::{CatalogProgress, CatalogPublication};
use fss_reference::rtsp::recording_catalog::{
    CatalogScope, CatalogWindow, RecordingCatalog, prepare_catalog,
};
use std::ffi::OsString;

const PROOF_RESERVATION: u64 = 4 * 1024 * 1024;

fn step(codec: Codec) -> u64 {
    u64::from(match codec {
        Codec::Avc => source::AVC_STEP,
        Codec::Hevc => source::HEVC_STEP,
    })
}

fn native_window(codec: Codec, ordinal: usize, gap: u64) -> TestResult<Native> {
    let start = source::BASE + ordinal as u64 * (4 * step(codec) + gap);
    match codec {
        Codec::Avc => {
            let input = source::avc_window(ordinal)?;
            Ok(Native::Avc(prepare_recording(
                scope()?,
                source::SCALE,
                &source::avc_timing_at(&input.pictures, start),
                &borrowed(&input.packets),
            )?))
        }
        Codec::Hevc => {
            let input = source::hevc_window(ordinal)?;
            let timing: Vec<_> = source::hevc_timing_at(&input.pictures, start)
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

enum Catalog {
    Avc(RecordingCatalog),
    Hevc(HevcRecordingCatalog),
}
impl Catalog {
    fn manifest(&self) -> &ObjectManifest {
        match self {
            Self::Avc(c) => c.manifest(),
            Self::Hevc(c) => c.manifest(),
        }
    }

    fn index(&self) -> &[u8] {
        match self {
            Self::Avc(c) => c.index_bytes(),
            Self::Hevc(c) => c.index_bytes(),
        }
    }

    fn publish(&self, archive: &mut LocalRootPublisher, slot: SlotName) -> TestResult {
        match self {
            Self::Avc(c) => {
                let mut job = CatalogPublication::new(c, archive, slot, c.byte_len(), 100)?;
                for now in 0..c.entries().len() as u64 + 2 {
                    if let CatalogProgress::Published(receipt) = job.step(now, &NeverCancel)? {
                        assert_eq!(receipt.root, c.manifest().root());
                        return Ok(());
                    }
                }
            }
            Self::Hevc(c) => {
                let mut job = HevcCatalogPublication::new(c, archive, slot, c.byte_len(), 100)?;
                for now in 0..c.entries().len() as u64 + 2 {
                    if let CatalogProgress::Published(receipt) = job.step(now, &NeverCancel)? {
                        assert_eq!(receipt.root, c.manifest().root());
                        return Ok(());
                    }
                }
            }
        }
        Err("native catalog did not complete root-last publication".into())
    }
}

fn catalogs(
    windows: &[Native; 2],
    slots: &[SlotName; 2],
    scope: &CatalogScope,
    pages: bool,
) -> TestResult<Vec<Catalog>> {
    let per_page = if pages { 1 } else { 2 };
    match (&windows[0], &windows[1]) {
        (Native::Avc(first), Native::Avc(second)) => {
            let entries = [
                CatalogWindow {
                    slot: &slots[0],
                    recording: first,
                },
                CatalogWindow {
                    slot: &slots[1],
                    recording: second,
                },
            ];
            entries
                .chunks(per_page)
                .map(|group| Ok(Catalog::Avc(prepare_catalog(scope.clone(), group)?)))
                .collect()
        }
        (Native::Hevc(first), Native::Hevc(second)) => {
            let entries = [
                HevcCatalogWindow {
                    slot: &slots[0],
                    recording: first,
                },
                HevcCatalogWindow {
                    slot: &slots[1],
                    recording: second,
                },
            ];
            entries
                .chunks(per_page)
                .map(|group| Ok(Catalog::Hevc(prepare_hevc_catalog(scope.clone(), group)?)))
                .collect()
        }
        _ => Err("fixture mixed native codecs".into()),
    }
}

struct CatalogMovie {
    movie: Imported,
    pages: bool,
    gap: u64,
}
impl CatalogMovie {
    fn new(codec: Codec, pages: bool, gap: u64) -> TestResult<Self> {
        let directory =
            OwnedDirectory::new(&format!("movie-catalog-{}-{pages}-{gap}", codec.name()))?;
        let archive_path = directory.0.join("native archive");
        let root = directory.0.join("deployment");
        let windows = [native_window(codec, 0, gap)?, native_window(codec, 1, gap)?];
        let slots = [
            SlotName::parse("first-window")?,
            SlotName::parse("second-window")?,
        ];
        let scope = CatalogScope {
            recording: windows[0].plan().summary().scope.clone(),
            decode_clock: ContentDigest::sha256(b"explicit catalog movie decode epoch"),
            time_scale: source::SCALE,
        };
        let catalogs = catalogs(&windows, &slots, &scope, pages)?;
        let mut archive = LocalRootPublisher::open(
            &archive_path,
            LocalPublicationLimits::new(
                8,
                64,
                8,
                128,
                SpoolLimits::new(128, 8 * 1024 * 1024, 1024 * 1024, 128),
            ),
        )?;
        let mut mp4 = Vec::new();
        let mut originals = Vec::new();
        for (ordinal, (window, slot)) in windows.iter().zip(&slots).enumerate() {
            let plan = window.plan();
            let mut job =
                RecordingPublication::new(plan, &mut archive, slot.clone(), plan.byte_len(), 100)?;
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
            drop(job);
            originals.push((plan.manifest().root(), plan.manifest().canonical_bytes()));
            originals.extend(
                plan.children()
                    .into_iter()
                    .map(|(_, digest, bytes)| (digest, bytes.to_vec())),
            );
            let objects = plan.objects();
            if ordinal == 0 {
                mp4.extend_from_slice(objects.initialization);
            } else {
                assert_eq!(
                    objects.initialization,
                    windows[0].plan().objects().initialization
                );
            }
            let mut fragment = objects.media.to_vec();
            assert_eq!(&fragment[12..16], b"mfhd");
            assert_eq!(&fragment[20..24], &1_u32.to_be_bytes());
            fragment[20..24].copy_from_slice(&u32::try_from(ordinal + 1)?.to_be_bytes());
            mp4.extend_from_slice(&fragment);
        }
        let mut pins = Vec::new();
        for (ordinal, catalog) in catalogs.iter().enumerate() {
            let slot = SlotName::parse(&format!("catalog-{ordinal}"))?;
            catalog.publish(&mut archive, slot.clone())?;
            pins.push((slot, catalog.manifest().root()));
            originals.push((
                catalog.manifest().root(),
                catalog.manifest().canonical_bytes(),
            ));
            originals.push((
                ContentDigest::sha256(catalog.index()),
                catalog.index().to_vec(),
            ));
        }
        drop(archive);
        let mut args: Vec<OsString> = vec![
            "--archive".into(),
            archive_path.as_os_str().to_owned(),
            "--root".into(),
            root.as_os_str().to_owned(),
        ];
        args.extend(
            [
                "--site",
                SITE,
                "--codec",
                codec.name(),
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
            .map(OsString::from),
        );
        if pages {
            args.extend([
                "--catalog-pages".into(),
                pins.iter()
                    .map(|(slot, digest)| format!("{}@{}", slot.as_str(), digest.to_text()))
                    .collect::<Vec<_>>()
                    .join(",")
                    .into(),
            ]);
        } else {
            args.extend([
                "--catalog-slot".into(),
                pins[0].0.as_str().into(),
                "--catalog-root".into(),
                pins[0].1.to_text().into(),
            ]);
        }
        if gap != 0 {
            args.extend(["--decode-gaps".into(), "preserve".into()]);
        }
        let preview = Command::new(env!("CARGO_BIN_EXE_fss-import-rtsp"))
            .args(&args)
            .output()?;
        success(&preview);
        assert!(!root.exists(), "catalog preview wrote destination custody");
        args.extend([
            "--approve".into(),
            json_field(&preview, "approval_digest")?.into(),
        ]);
        let imported = Command::new(env!("CARGO_BIN_EXE_fss-import-rtsp"))
            .args(&args)
            .output()?;
        success(&imported);
        let text = std::str::from_utf8(&imported.stdout)?;
        assert!(text.contains("\"frames\":8"));
        assert!(text.contains("\"windows\":2"));
        if gap != 0 {
            assert_eq!(
                json_field(&imported, "format")?,
                "fss.rtsp_gapped_catalog_import_operator.v1"
            );
            assert!(text.contains("\"decode_gap_count\":1"));
            assert!(text.contains("\"absence_certifiable\":false"));
            assert!(text.contains(&format!(
                "\"decode_gap_intervals\":[{{\"start\":\"{}\",\"end\":\"{}\"}}]",
                source::BASE + 4 * step(codec),
                source::BASE + 4 * step(codec) + gap,
            )));
        }
        if pages {
            assert!(text.contains("\"pages\":2"));
        }
        let identity = json_field(&imported, "import_identity")?;
        let proof = ContentDigest::parse(json_field(&imported, "origin_proof")?)?;
        fs::rename(&archive_path, directory.0.join("offline native archive"))?;
        assert!(!archive_path.exists());
        Ok(Self {
            movie: Imported {
                directory,
                root,
                codec,
                identity,
                proof,
                mp4,
                originals,
            },
            pages,
            gap,
        })
    }

    fn allowance(&self) -> u64 {
        // Initialization is shared on disk but its native read is conservatively charged once
        // per window. Keep the duplicate entries in this sum; no unique-digest discount applies.
        PROOF_RESERVATION
            + self
                .movie
                .originals
                .iter()
                .map(|(_, bytes)| bytes.len() as u64)
                .sum::<u64>()
    }

    fn query(&self) -> Range<u64> {
        let step = step(self.movie.codec);
        source::BASE + 3 * step + step / 2..source::BASE + 6 * step + step / 2 + self.gap
    }

    fn selection(&self) -> Command {
        let query = self.query();
        let mut cmd = command(&self.movie.root, "select-movie");
        cmd.args([
            "--import-id",
            &self.movie.identity,
            "--start-movie-tick",
            &query.start.to_string(),
            "--end-movie-tick",
            &query.end.to_string(),
        ]);
        cmd
    }

    fn export(&self, path: &Path) -> Command {
        let query = self.query();
        let mut cmd = command(&self.movie.root, "export-movie");
        cmd.args([
            "--import-id",
            &self.movie.identity,
            "--start-movie-tick",
            &query.start.to_string(),
            "--end-movie-tick",
            &query.end.to_string(),
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

    fn images(&self) -> TestResult<std::collections::BTreeMap<usize, source::Image>> {
        if self.gap == 0 {
            return source::native_images(&self.movie.mp4);
        }
        // The original elementary pictures are identical across these fixture windows.
        // Decode an independent window without inferring continuity from elementary bytes.
        let window = native_window(self.movie.codec, 0, 0)?;
        let objects = window.plan().objects();
        let mut bytes = objects.initialization.to_vec();
        bytes.extend_from_slice(objects.media);
        let first = source::native_images(&bytes)?;
        let mut images = first.clone();
        images.extend(first.into_iter().map(|(index, image)| (index + 4, image)));
        Ok(images)
    }

    fn expected(&self, masked: bool) -> TestResult<Vec<u8>> {
        let images = self.images()?;
        let dimensions = images.get(&3).ok_or("selected native image")?.dimensions;
        let half_ns = step(self.movie.codec) * 1_000_000_000 / u64::from(source::SCALE) / 2;
        let gap_ns = self.gap * 1_000_000_000 / u64::from(source::SCALE);
        let config = TimedGrayMatroskaConfig::new(dimensions, 6 * half_ns + gap_ns)?;
        let mut bytes = config.initialization()?.bytes().to_vec();
        for (ordinal, (segment, begin, end)) in [(3, 0, 1), (4, 1, 3), (6, 3, 5), (5, 5, 6)]
            .into_iter()
            .enumerate()
        {
            let image = images.get(&segment).ok_or("selected native image")?;
            assert_eq!(image.dimensions, dimensions);
            bytes.extend_from_slice(
                config
                    .frame(
                        ordinal as u64,
                        begin * half_ns + if ordinal == 0 { 0 } else { gap_ns },
                        end * half_ns + if ordinal == 0 { 0 } else { gap_ns },
                    )?
                    .prefix(),
            );
            let mut pixels = image.pixels.clone();
            if masked {
                for row in pixels.chunks_exact_mut(dimensions[0] as usize) {
                    row[..(dimensions[0] / 2) as usize].fill(MASK_FILL_LUMA);
                }
            }
            bytes.extend_from_slice(&pixels);
        }
        Ok(bytes)
    }

    fn assert_selection(&self, output: &Output) -> TestResult {
        let (adapter, generation) = if self.gap != 0 {
            ("ADP-RTSP-GAPPED-CATALOG-001", "gen:rtsp-gapped-catalog:v1:")
        } else if self.pages {
            ("ADP-RTSP-CATALOG-PAGES-001", "gen:rtsp-catalog-pages:v1:")
        } else {
            (
                "ADP-RTSP-CATALOG-ARCHIVE-001",
                "gen:rtsp-catalog-archive:v1:",
            )
        };
        assert_eq!(field(output, "selection_source_adapter")?, adapter);
        let proof = self.movie.proof.to_text();
        assert_eq!(
            field(output, "selection_source_adapter_generation")?,
            format!(
                "{generation}{}",
                proof.strip_prefix("sha256:").ok_or("SHA-256 proof")?
            )
        );
        assert_eq!(
            field(output, "selection_verified_source_sha256")?,
            ContentDigest::sha256(&self.movie.mp4).to_text()
        );
        assert_eq!(
            field(output, "selection_source_bytes_read")?.parse::<usize>()?,
            self.movie.mp4.len()
        );
        assert_eq!(
            field(output, "selection_origin_read_bytes_charged")?.parse::<u64>()?,
            self.allowance()
        );
        assert_eq!(
            field(output, "selection_origin_read_model")?,
            "conservative_pre_io_bytes"
        );
        assert_eq!(
            field(output, "selection_time_basis")?,
            "container_movie_timeline"
        );
        assert_eq!(field(output, "selected_presentation_count")?, "4");
        assert_eq!(
            field(output, "movie_gap_count")?,
            if self.gap == 0 { "0" } else { "1" }
        );
        let parsed = AvcMp4::parse(&self.movie.mp4, None, DemuxLimits::default())?;
        let step = step(self.movie.codec);
        let query = self.query();
        if self.gap != 0 {
            let denominator = u128::from(source::SCALE);
            assert_eq!(
                values(output, "movie_gap")?,
                [format!(
                    "0 kind=unrepresented movie_interval={}/{},{}/{}",
                    u128::from(source::BASE + 4 * step) * denominator,
                    source::SCALE,
                    u128::from(source::BASE + 4 * step + self.gap) * denominator,
                    source::SCALE,
                )]
            );
        }
        let intervals = [
            (3, query.start, source::BASE + 4 * step),
            (
                4,
                source::BASE + 4 * step + self.gap,
                source::BASE + 5 * step + self.gap,
            ),
            (
                6,
                source::BASE + 5 * step + self.gap,
                source::BASE + 6 * step + self.gap,
            ),
            (5, source::BASE + 6 * step + self.gap, query.end),
        ];
        let expected: Vec<_> = intervals
            .into_iter()
            .enumerate()
            .map(|(ordinal, (segment, start, end))| {
                let sample_source = &parsed.samples()[segment].source;
                let denominator = u128::from(source::SCALE);
                format!(
                    "{ordinal} segment={segment} edit_index=implicit movie_interval={}/{},{}/{} source_offset={} source_bytes={}",
                    u128::from(start) * denominator,
                    source::SCALE,
                    u128::from(end) * denominator,
                    source::SCALE,
                    sample_source.start,
                    sample_source.len(),
                )
            })
            .collect();
        assert_eq!(values(output, "movie_sample")?, expected);
        Ok(())
    }
}

#[test]
fn approved_catalog_and_pages_export_continuous_and_gapped_movie_pixels_with_cold_custody_and_masks()
-> TestResult {
    // Both origin shapes and codecs, with the existing continuous profile and an explicit gap.
    for (codec, pages, gap) in [
        (Codec::Avc, false, 0),
        (Codec::Hevc, true, 0),
        (Codec::Avc, true, u64::from(source::SCALE)),
        (Codec::Hevc, false, u64::from(source::SCALE)),
    ] {
        let catalog = CatalogMovie::new(codec, pages, gap)?;
        let movie = &catalog.movie;
        let before = movie.journals()?;
        let selected = catalog.selection().output()?;
        success(&selected);
        catalog.assert_selection(&selected)?;
        assert_eq!(field(&selected, "selection_complete")?, "true");
        assert_eq!(field(&selected, "selection_media_exported")?, "false");
        assert_eq!(field(&selected, "selection_absence_certifiable")?, "false");
        assert_eq!(
            field(&selected, "selection_maximum_origin_read_bytes")?.parse::<u64>()?,
            MAX_ORIGIN
        );
        let too_small = movie.path("catalog-origin-too-small.mkv");
        refused(
            &catalog
                .export(&too_small)
                .args([
                    "--max-origin-read-bytes",
                    &(catalog.allowance() - 1).to_string(),
                ])
                .output()?,
            &too_small,
        )?;
        let path = movie.path("cross-window.mkv");
        let exported = catalog
            .export(&path)
            .args(["--max-origin-read-bytes", &catalog.allowance().to_string()])
            .output()?;
        success(&exported);
        catalog.assert_selection(&exported)?;
        assert_eq!(
            field(&exported, "selection_maximum_origin_read_bytes")?.parse::<u64>()?,
            catalog.allowance()
        );
        let expected = catalog.expected(false)?;
        assert_eq!(fs::read(&path)?, expected);
        assert_eq!(
            field(&exported, "gray_mkv_sha256")?,
            ContentDigest::sha256(&expected).to_text()
        );
        assert_eq!(values(&exported, "frame_segment")?, ["3", "4", "6", "5"]);
        assert_eq!(field(&exported, "movie_output_frames")?, "4");
        assert_eq!(field(&exported, "movie_cached_frames")?, "4");
        assert_eq!(
            field(&exported, "gray_mkv_duration_ns")?.parse::<u64>()?,
            (3 * step(codec) + gap) * 1_000_000_000 / u64::from(source::SCALE)
        );
        assert_eq!(
            field(&exported, "gray_mkv_source_capture_timing_preserved")?,
            "false"
        );
        assert_eq!(field(&exported, "movie_export_complete")?, "true");
        assert_eq!(movie.journals()?, before);

        let (original_paths, chunks) = movie.retained_objects()?;
        let images = catalog.images()?;
        let dimensions = images.get(&0).ok_or("first native image")?.dimensions;
        let cx = context(&movie.root)?;
        let mut deployment = ReferenceDeployment::open(&movie.root, SITE, &cx)?;
        let policy = PrivacyMaskPolicy::new(
            SensorId::parse(SENSOR)?,
            dimensions,
            &[[0, 0, dimensions[0] / 2, dimensions[1]]],
        )?;
        let approval = preview_mask(&deployment, &policy)?.approval;
        declare_mask(&mut deployment, &policy, approval, &cx)?;
        drop(deployment);
        cx.drain_and_finalize();
        let before = movie.journals()?;
        let path = movie.path("cross-window-masked.mkv");
        let masked = catalog.export(&path).output()?;
        success(&masked);
        catalog.assert_selection(&masked)?;
        let expected = catalog.expected(true)?;
        assert_eq!(fs::read(path)?, expected);
        assert_eq!(values(&masked, "frame_segment")?, ["3", "4", "6", "5"]);
        assert_eq!(field(&masked, "movie_export_complete")?, "true");
        for (path, (_, bytes)) in original_paths.iter().zip(&movie.originals) {
            assert_eq!(&fs::read(path)?, bytes);
        }
        for (path, bytes) in chunks {
            assert_eq!(fs::read(path)?, bytes);
        }
        assert_eq!(movie.journals()?, before);
    }
    Ok(())
}
