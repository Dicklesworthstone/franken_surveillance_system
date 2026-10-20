#![forbid(unsafe_code)]
//! Reopen native media work and raw datagram owners after all capture state was dropped.

use super::*;
use fss_geometry::WorkBudget;
use fss_reference::rtsp::datagram_archive::{DatagramArchive, DatagramPin};
use fss_reference::rtsp::framed::RtspWireIntake;
use fss_reference::rtsp::recording_archive::{CodecArchiveNamespace, CodecArchiveSnapshot};

#[path = "../../../../fss-reference/tests/recording_support/mod.rs"]
mod avc;

#[derive(Clone)]
struct Observation {
    channel: u8,
    received_ns: u64,
    bytes: Vec<u8>,
}

fn retained_args(directory: &Directory, codec: &str) -> Test<Vec<OsString>> {
    let mut input = args(directory, codec);
    set(
        &mut input,
        "--source-root",
        directory.0.join("source").to_str().ok_or("path")?,
    );
    set(
        &mut input,
        "--source-retention-evidence",
        &ContentDigest::sha256(b"owner raw source retention").to_text(),
    );
    set(&mut input, "--max-datagrams", "32");
    set(&mut input, "--source-storage-bytes", "1048576");
    Ok(input)
}

fn source_config(plan: &ReconnectPlan, index: usize) -> Test<&SourceConfig> {
    Ok(plan
        .sources
        .as_ref()
        .ok_or("missing source plan")?
        .get(index)?)
}

fn originals(plan: &ReconnectPlan, index: usize) -> Test<Vec<Observation>> {
    let window = recording(&plan.attempts[index])?;
    let channel = source_config(plan, index)?.scope.channels.0;
    Ok(window
        .packets()?
        .into_iter()
        .map(|packet| Observation {
            channel,
            received_ns: packet.received_ns,
            bytes: packet.bytes.to_vec(),
        })
        .collect())
}

fn save_source(config: &SourceConfig, observations: &[Observation]) -> Test<DatagramPin> {
    let mut publisher = LocalRootPublisher::open(&config.root, config.storage)?;
    let mut budget = WorkBudget::new(config.work);
    let mut archive = DatagramArchive::recover(
        &publisher,
        config.scope.clone(),
        config.limits,
        None,
        &NeverCancel,
        &mut budget,
    )?;
    for observation in observations {
        let mut bytes = vec![b'$', observation.channel];
        bytes.extend_from_slice(&u16::try_from(observation.bytes.len())?.to_be_bytes());
        bytes.extend_from_slice(&observation.bytes);
        let mut intake = RtspWireIntake::new();
        intake.ingest(&bytes, observation.received_ns)?;
        let frame = intake
            .poll(observation.received_ns)?
            .ok_or("incomplete frame")?;
        let prepared = archive.prepare_frame(&frame, &mut budget)?;
        archive.publish(&prepared, &mut publisher, &NeverCancel, &mut budget)?;
    }
    Ok(archive.pin())
}

fn prefix(attempt: usize, pin: DatagramPin) -> String {
    format!(
        "{}:{}:{}:{}",
        attempt + 1,
        pin.datagrams,
        pin.payload_bytes,
        pin.head
    )
}

fn source_object(config: &SourceConfig, payload: &[u8]) -> Test<PathBuf> {
    let digest = ContentDigest::sha256(payload).to_text();
    Ok(config
        .root
        .join("spool/objects")
        .join(digest.strip_prefix("sha256:").ok_or("digest")?))
}

fn tree(root: &Path) -> Test<Vec<(PathBuf, Vec<u8>)>> {
    fn visit(base: &Path, path: &Path, result: &mut Vec<(PathBuf, Vec<u8>)>) -> Test {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                visit(base, &entry.path(), result)?;
            } else {
                result.push((
                    entry.path().strip_prefix(base)?.to_owned(),
                    fs::read(entry.path())?,
                ));
            }
        }
        Ok(())
    }
    let mut result = Vec::new();
    visit(root, root, &mut result)?;
    result.sort();
    Ok(result)
}

fn snapshot(options: &Options) -> Test<CodecArchiveSnapshot<HevcArchiveCodec>> {
    let publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    Ok(CodecArchiveSnapshot::load(
        &publisher,
        CodecArchiveNamespace::new(options.catalog_scope().clone())?,
        options.work_limits().archive,
        &NeverCancel,
    )?)
}

fn index_rows(plan: &ReconnectPlan) -> Test<String> {
    let mut output = Vec::new();
    indexing::execute_codec::<HevcArchiveCodec>(
        plan,
        TIMEOUT,
        |row| {
            output.extend_from_slice(row);
            Ok(())
        },
        &NeverCancel,
    )?;
    let output = String::from_utf8(output)?;
    for row in output.lines() {
        fss_cli::json_input::parse(row)?;
    }
    Ok(output)
}

#[test]
fn source_retained_work_restores_and_indexes_original_epochs_with_exact_retries() -> Test {
    let directory = Directory::new()?;
    let mut input = retained_args(&directory, "hevc")?;
    let mut plan = ReconnectPlan::parse(&input)?;
    let mut expected = Vec::new();
    let mut minimum = Vec::new();
    let mut sources_before = Vec::new();
    for (index, attempt) in plan.attempts.iter().enumerate() {
        expected.push(fixture(attempt, true)?);
        let config = source_config(&plan, index)?;
        let pin = save_source(config, &originals(&plan, index)?)?;
        minimum.push(prefix(index, pin));
        // Broader raw custody retains RTCP and malformed RTP, beyond the saved media witness.
        save_source(
            config,
            &[
                originals(&plan, index)?.pop().ok_or("missing original")?,
                Observation {
                    channel: config.scope.channels.1,
                    received_ns: 100_000,
                    bytes: b"original malformed RTCP".to_vec(),
                },
                Observation {
                    channel: config.scope.channels.0,
                    received_ns: 100_001,
                    bytes: b"incomplete RTP".to_vec(),
                },
            ],
        )?;
        sources_before.push(tree(&config.root)?);
    }
    let capture = plan.digest()?;
    set(&mut input, "--minimum-source-pins", &minimum.join(","));
    plan = ReconnectPlan::parse(&input)?;
    assert_eq!(plan.digest()?, capture);
    let preview = plan.preview()?;
    assert!(preview.contains("\"minimum_source_prefixes_verified\":true"));
    assert!(
        preview.contains("datagram-source-and-journal-inspection:no-recording-read-or-publication")
    );
    let prior = approve(&mut plan)?;
    let rows = capture_rows(&plan)?;
    for row in rows.lines() {
        fss_cli::json_input::parse(row)?;
    }
    assert!(rows.contains("\"kind\":\"datagram_source_preflight_complete\""));
    assert!(rows.contains("\"selected_work_restored\":2"));
    assert!(rows.contains("\"network_requested\":false"));
    for (index, root) in expected.iter().enumerate() {
        cold_window(&plan.attempts[index], *root)?;
        assert_eq!(
            tree(&source_config(&plan, index)?.root)?,
            sources_before[index]
        );
    }
    // Native confirmation changes the observed recovery state, so the old approval expires.
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel),
        Err(APPROVAL)
    );
    assert_ne!(approve(&mut plan)?, prior);
    let settled = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    assert_eq!(
        capture_rows(&plan)?
            .matches("\"outcome\":\"already_durable\"")
            .count(),
        2
    );
    assert_eq!(
        settled,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );

    set(&mut input, "--recover", "index");
    let mut index = ReconnectPlan::parse(&input)?;
    assert_eq!(index.digest()?, capture);
    approve(&mut index)?;
    let rows = index_rows(&index)?;
    assert!(rows.contains("\"catalogs_published\":2"));
    assert!(rows.contains("\"capture_complete\":false"));
    assert!(rows.contains("\"continuity_across_attempts\":false"));
    for (ordinal, expected) in expected.iter().enumerate() {
        let snapshot = snapshot(&index.attempts[ordinal])?;
        assert_eq!(snapshot.windows().len(), 1);
        assert_eq!(snapshot.windows()[0].root(), *expected);
        assert_eq!(snapshot.indexed_windows(), 1);
        assert_eq!(
            tree(&source_config(&index, ordinal)?.root)?,
            sources_before[ordinal]
        );
    }
    approve(&mut index)?;
    let settled = [
        tree(&index.attempts[0].root)?,
        tree(&index.attempts[1].root)?,
    ];
    assert!(index_rows(&index)?.contains("\"catalogs_published\":0"));
    assert_eq!(
        settled,
        [
            tree(&index.attempts[0].root)?,
            tree(&index.attempts[1].root)?
        ]
    );
    Ok(())
}

#[test]
fn avc_recordings_restore_from_the_same_raw_source_custody_owner() -> Test {
    use fss_container::TimedAvcPicture;
    use fss_reference::rtsp::recording::{RecordingPacket, prepare_recording};
    use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::CheckpointedArchiveWriter;

    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&retained_args(&directory, "avc")?)?;
    let attempt = &plan.attempts[0];
    let fixture = avc::fixture(1, true)?;
    let timed = fixture
        .pictures
        .iter()
        .enumerate()
        .map(|(index, picture)| TimedAvcPicture {
            picture,
            decode_time: index as u64 * 18_000,
            duration: 18_000,
            composition_offset: 0,
        })
        .collect::<Vec<_>>();
    let packets = fixture
        .packets
        .iter()
        .map(|(sequence, received_ns, bytes)| RecordingPacket {
            sequence: *sequence,
            received_ns: *received_ns,
            bytes,
        })
        .collect::<Vec<_>>();
    let recording = prepare_recording(attempt.recording_config().scope, 90_000, &timed, &packets)?;
    let root = recording.manifest().root();
    let original_source = recording.objects().source.to_vec();
    let original_media = recording.objects().media.to_vec();
    let config = source_config(&plan, 0)?;
    let observations = packets
        .iter()
        .map(|packet| Observation {
            channel: config.scope.channels.0,
            received_ns: packet.received_ns,
            bytes: packet.bytes.to_vec(),
        })
        .collect::<Vec<_>>();
    save_source(config, &observations)?;
    {
        let clock = Clock {
            start: Instant::now(),
            timeout: TIMEOUT,
            cancellation: &NeverCancel,
            authority: None,
        };
        let mut source = SourceEntry::load(config, attempt, locate(&config.root)?, None, &clock)?;
        // The same datagram may belong to adjacent original recording witnesses; local
        // multiplicity checks must never consume the source globally across recordings.
        source.verify_recording(&recording, &clock)?;
        source.verify_recording(&recording, &clock)?;
    }
    {
        let mut publisher = LocalRootPublisher::open(&attempt.root, attempt.publication_limits())?;
        let mut pins = CodecArchivePinJournal::<AvcArchiveCodec>::create(
            &attempt.pins,
            attempt.pin_scope(),
            attempt.pin_limits(),
            &NeverCancel,
        )?;
        let namespace =
            CodecArchiveNamespace::<AvcArchiveCodec>::new(attempt.catalog_scope().clone())?;
        let mut writer = CheckpointedArchiveWriter::open(
            &mut publisher,
            namespace,
            attempt.work_limits().archive,
            attempt.work_limits(),
            256,
            0,
            1000,
            &NeverCancel,
        )?;
        let bytes = recording.byte_len();
        writer.offer(recording, bytes, 0)?;
        let CheckpointedArchiveProgress::PinRequired(pin) = writer.step(0, &NeverCancel)? else {
            return Err("missing AVC work candidate".into());
        };
        pins.persist_candidate(&pin, &NeverCancel)?;
        writer.acknowledge_checkpoint(&pin, 0, &NeverCancel)?;
        assert!(matches!(
            writer.step(0, &NeverCancel)?,
            CheckpointedArchiveProgress::WorkDurable { .. }
        ));
        let _retained = writer.retire();
    }
    approve(&mut plan)?;
    execute_codec::<AvcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel)?;
    let attempt = &plan.attempts[0];
    let publisher = LocalRootPublisher::open(&attempt.root, attempt.publication_limits())?;
    let namespace = CodecArchiveNamespace::<AvcArchiveCodec>::new(attempt.catalog_scope().clone())?;
    let loaded = AvcArchiveCodec::load_recording(
        &publisher,
        &namespace.window_slot(0)?,
        root,
        &attempt.recording_config().scope,
        &NeverCancel,
    )?;
    assert_eq!(loaded.objects().source, original_source);
    assert_eq!(loaded.objects().media, original_media);
    Ok(())
}

#[test]
fn complete_source_locks_survive_multi_attempt_preflight() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&retained_args(&directory, "hevc")?)?;
    for (index, attempt) in plan.attempts.iter().enumerate() {
        fixture(attempt, true)?;
        save_source(source_config(&plan, index)?, &originals(&plan, index)?)?;
    }
    approve(&mut plan)?;
    let mut checked = false;
    execute_codec::<HevcArchiveCodec>(
        &plan,
        TIMEOUT,
        |row| {
            if std::str::from_utf8(row)
                .map_err(|_| OUTPUT)?
                .contains("\"kind\":\"datagram_source_preflight_complete\"")
            {
                for index in 0..plan.attempts.len() {
                    let config = plan.sources.as_ref().ok_or(STATE)?.get(index)?;
                    assert!(LocalRootPublisher::open(&config.root, config.storage).is_err());
                }
                checked = true;
            }
            Ok(())
        },
        &NeverCancel,
    )?;
    assert!(checked);
    Ok(())
}

#[test]
fn missing_later_source_refuses_before_any_earlier_media_is_restored() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&retained_args(&directory, "hevc")?)?;
    for (index, attempt) in plan.attempts.iter().enumerate() {
        fixture(attempt, true)?;
        save_source(source_config(&plan, index)?, &originals(&plan, index)?)?;
    }
    approve(&mut plan)?;
    let old = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    let source = &source_config(&plan, 1)?.root;
    fs::rename(source, directory.0.join("lost-later-source"))?;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel),
        Err(ROOT)
    );
    assert!(!source.exists());
    assert_eq!(
        old,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );
    for attempt in &plan.attempts {
        assert!(!window_present(attempt)?);
    }
    Ok(())
}

#[test]
fn newest_corrupt_datagram_cannot_fall_back_to_an_older_valid_minimum() -> Test {
    let directory = Directory::new()?;
    let mut input = retained_args(&directory, "hevc")?;
    let plan = ReconnectPlan::parse(&input)?;
    for (index, attempt) in plan.attempts.iter().enumerate() {
        fixture(attempt, true)?;
        let pin = save_source(source_config(&plan, index)?, &originals(&plan, index)?)?;
        if index == 1 {
            set(&mut input, "--minimum-source-pins", &prefix(index, pin));
        }
    }
    let later = source_config(&plan, 1)?;
    let tail = Observation {
        channel: later.scope.channels.1,
        received_ns: 200_000,
        bytes: b"newer source must also verify".to_vec(),
    };
    save_source(later, std::slice::from_ref(&tail))?;
    let mut plan = ReconnectPlan::parse(&input)?;
    approve(&mut plan)?;
    let old = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    fs::write(
        source_object(source_config(&plan, 1)?, &tail.bytes)?,
        b"damaged newer bytes",
    )?;
    assert!(plan.preview().is_err());
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel),
        Err(STORAGE)
    );
    assert_eq!(
        old,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );
    assert!(!window_present(&plan.attempts[0])?);
    assert!(!window_present(&plan.attempts[1])?);
    Ok(())
}

#[test]
fn every_original_rtp_witness_including_source_only_nals_and_receive_times_is_required() -> Test {
    for mismatch in [
        "empty",
        "source_only",
        "receive_time",
        "wrong_channel",
        "payload",
    ] {
        let directory = Directory::new()?;
        let mut plan = ReconnectPlan::parse(&retained_args(&directory, "hevc")?)?;
        fixture(&plan.attempts[0], true)?;
        let mut retained = originals(&plan, 0)?;
        match mismatch {
            "empty" => retained.clear(),
            // The sixth packet is the next VPS: original lookahead custody outside the
            // two decoded samples, required by the native recording witness.
            "source_only" => {
                retained.remove(5);
            }
            "receive_time" => retained[5].received_ns += 1,
            "wrong_channel" => retained[5].channel = source_config(&plan, 0)?.scope.channels.1,
            "payload" => retained[5].bytes.push(0),
            _ => return Err("fixture mismatch".into()),
        }
        save_source(source_config(&plan, 0)?, &retained)?;
        // A self-consistent source chain is insufficient: execution also proves membership
        // of every source packet in the native original recording, before any confirmation.
        approve(&mut plan)?;
        let old = journal(&plan.attempts[0])?;
        assert_eq!(
            execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel),
            Err(STORAGE),
            "{mismatch}"
        );
        assert_eq!(journal(&plan.attempts[0])?, old);
        assert!(!window_present(&plan.attempts[0])?);
    }
    Ok(())
}

#[test]
fn growing_source_or_replacing_its_directory_invalidates_old_approval() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&retained_args(&directory, "hevc")?)?;
    fixture(&plan.attempts[0], true)?;
    let original = originals(&plan, 0)?;
    save_source(source_config(&plan, 0)?, &original)?;
    let first = approve(&mut plan)?;
    let config = source_config(&plan, 0)?;
    save_source(
        config,
        &[Observation {
            channel: config.scope.channels.1,
            received_ns: 200_000,
            bytes: b"later RTCP".to_vec(),
        }],
    )?;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel),
        Err(APPROVAL)
    );
    assert_ne!(approve(&mut plan)?, first);
    let config = source_config(&plan, 0)?;
    let contents = tree(&config.root)?;
    fs::rename(&config.root, directory.0.join("original-source-directory"))?;
    // Recreate the same complete bytes under a different directory identity.
    for (relative, bytes) in contents {
        let path = config.root.join(relative);
        fs::create_dir_all(path.parent().ok_or("parent")?)?;
        fs::write(path, bytes)?;
    }
    for empty in ["tombstones", "spool/staging", "spool/verified"] {
        fs::create_dir_all(config.root.join(empty))?;
    }
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel),
        Err(APPROVAL)
    );
    assert!(!window_present(&plan.attempts[0])?);
    Ok(())
}

#[test]
fn corruption_after_source_preflight_stops_restore_before_confirmation() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&retained_args(&directory, "hevc")?)?;
    fixture(&plan.attempts[0], true)?;
    let retained = originals(&plan, 0)?;
    save_source(source_config(&plan, 0)?, &retained)?;
    approve(&mut plan)?;
    let path = source_object(source_config(&plan, 0)?, &retained[3].bytes)?;
    let old = journal(&plan.attempts[0])?;
    let mut changed = false;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(
            &plan,
            TIMEOUT,
            |row| {
                if std::str::from_utf8(row)
                    .map_err(|_| OUTPUT)?
                    .contains("\"kind\":\"datagram_source_preflight_complete\"")
                {
                    fs::write(&path, b"damaged after preflight").map_err(|_| STORAGE)?;
                    changed = true;
                }
                Ok(())
            },
            &NeverCancel
        ),
        Err(STORAGE)
    );
    assert!(changed);
    assert_eq!(journal(&plan.attempts[0])?, old);
    assert!(!window_present(&plan.attempts[0])?);
    Ok(())
}

#[test]
fn index_revalidates_raw_custody_after_work_confirmation_output() -> Test {
    let directory = Directory::new()?;
    let mut input = retained_args(&directory, "hevc")?;
    let mut plan = ReconnectPlan::parse(&input)?;
    fixture(&plan.attempts[0], true)?;
    let retained = originals(&plan, 0)?;
    save_source(source_config(&plan, 0)?, &retained)?;
    approve(&mut plan).map_err(|error| format!("initial restore preview: {error}"))?;
    capture_rows(&plan).map_err(|error| format!("initial restore: {error}"))?;
    set(&mut input, "--recover", "index");
    let mut index = ReconnectPlan::parse(&input)?;
    approve(&mut index).map_err(|error| format!("index preview: {error}"))?;
    let path = source_object(source_config(&index, 0)?, &retained[3].bytes)?;
    // Save the native spool envelope as well as the payload; raw RTP bytes alone are
    // intentionally insufficient to replace a corrupt retained object file.
    let original_file = fs::read(&path)?;
    let mut changed = false;
    assert_eq!(
        indexing::execute_codec::<HevcArchiveCodec>(
            &index,
            TIMEOUT,
            |row| {
                if std::str::from_utf8(row)
                    .map_err(|_| OUTPUT)?
                    .contains("\"kind\":\"index_work_confirmed\"")
                {
                    fs::write(&path, b"damaged before catalog publication").map_err(|_| STORAGE)?;
                    changed = true;
                }
                Ok(())
            },
            &NeverCancel
        ),
        Err(STORAGE)
    );
    assert!(changed);
    let remaining =
        snapshot(&index.attempts[0]).map_err(|error| format!("interrupted inventory: {error}"))?;
    assert_eq!(remaining.windows().len(), 1);
    assert_eq!(remaining.indexed_windows(), 0);
    // Repairing the original source permits the native saved catalog work to be recovered;
    // neither an unjournaled page nor a duplicate ordinal is needed.
    fs::write(path, original_file)?;
    approve(&mut plan).map_err(|error| format!("repaired source preview: {error}"))?;
    capture_rows(&plan).map_err(|error| format!("catalog recovery: {error}"))?;
    assert_eq!(snapshot(&plan.attempts[0])?.indexed_windows(), 1);
    Ok(())
}

#[test]
fn all_three_missing_stores_remain_unknown_but_saved_source_pins_forbid_rollback() -> Test {
    for codec in ["avc", "hevc"] {
        let directory = Directory::new()?;
        let mut input = retained_args(&directory, codec)?;
        set(
            &mut input,
            "--credential-file",
            directory.0.join("absent-secret").to_str().ok_or("path")?,
        );
        set(&mut input, "--auth-realm", "original-realm");
        let mut plan = ReconnectPlan::parse(&input)?;
        let preview = plan.preview()?;
        assert!(preview.contains("all_three_stores_unobserved"));
        assert!(!preview.contains("absent-secret"));
        approve(&mut plan)?;
        match codec {
            "avc" => execute_codec::<AvcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel)?,
            _ => execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel)?,
        }
        assert_eq!(fs::read_dir(&directory.0)?.count(), 0);
        set(
            &mut input,
            "--minimum-source-pins",
            &format!(
                "1:1:1:{}",
                ContentDigest::sha256(b"independently saved source")
            ),
        );
        assert_eq!(ReconnectPlan::parse(&input)?.preview(), Err(STORAGE));
        assert_eq!(fs::read_dir(&directory.0)?.count(), 0);
    }
    Ok(())
}

#[test]
fn minimum_source_coordinates_and_original_bounds_are_enforced() -> Test {
    let directory = Directory::new()?;
    let input = retained_args(&directory, "hevc")?;
    let plan = ReconnectPlan::parse(&input)?;
    fixture(&plan.attempts[0], true)?;
    let pin = save_source(source_config(&plan, 0)?, &originals(&plan, 0)?)?;
    for changed in [
        DatagramPin {
            payload_bytes: pin.payload_bytes + 1,
            ..pin
        },
        DatagramPin {
            head: ContentDigest::sha256(b"other valid-looking head"),
            ..pin
        },
        DatagramPin {
            datagrams: pin.datagrams + 1,
            ..pin
        },
    ] {
        let mut invalid = input.clone();
        set(&mut invalid, "--minimum-source-pins", &prefix(0, changed));
        assert_eq!(ReconnectPlan::parse(&invalid)?.preview(), Err(STORAGE));
    }
    for row in [
        prefix(2, pin),
        format!("1:33:1:{}", pin.head),
        format!(
            "1:1:{}:{}",
            source_config(&plan, 0)?.limits.max_payload_bytes + 1,
            pin.head
        ),
    ] {
        let mut invalid = input.clone();
        set(&mut invalid, "--minimum-source-pins", &row);
        assert!(ReconnectPlan::parse(&invalid).is_err());
    }
    let mut without_source = args(&directory, "hevc");
    set(
        &mut without_source,
        "--minimum-source-pins",
        &prefix(0, pin),
    );
    assert!(ReconnectPlan::parse(&without_source).is_err());
    let mut capture: Vec<_> = input
        .as_chunks::<2>()
        .0
        .iter()
        .filter(|pair| pair[0] != "--recover")
        .flat_map(|pair| pair.iter().cloned())
        .collect();
    set(&mut capture, "--minimum-source-pins", &prefix(0, pin));
    assert!(ReconnectPlan::parse(&capture).is_err());
    Ok(())
}

#[test]
fn source_revalidation_consumes_one_finite_allowance_and_honors_cancellation() -> Test {
    let directory = Directory::new()?;
    let mut input = retained_args(&directory, "hevc")?;
    set(&mut input, "--source-work", "25000000");
    let mut plan = ReconnectPlan::parse(&input)?;
    fixture(&plan.attempts[0], true)?;
    save_source(source_config(&plan, 0)?, &originals(&plan, 0)?)?;
    let clock = Clock {
        start: Instant::now(),
        timeout: TIMEOUT,
        cancellation: &NeverCancel,
        authority: None,
    };
    let mut entries = load::<HevcArchiveCodec>(&plan, &clock)?;
    let mut scans = 0;
    while source_recovery::revalidate(&plan, 0, entries[0].source.as_mut(), &clock).is_ok() {
        scans += 1;
        assert!(scans < 1000, "source work allowance was replenished");
    }
    assert!(scans > 0);
    drop(entries);
    struct Cancel(Cell<bool>);
    impl PublishCancellation for Cancel {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            self.0.get()
        }
    }
    approve(&mut plan)?;
    let old = journal(&plan.attempts[0])?;
    let cancel = Cancel(Cell::new(false));
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(
            &plan,
            TIMEOUT,
            |row| {
                if std::str::from_utf8(row)
                    .map_err(|_| OUTPUT)?
                    .contains("\"kind\":\"datagram_source_preflight_complete\"")
                {
                    cancel.0.set(true);
                }
                Ok(())
            },
            &cancel
        ),
        Err(AUTHORITY)
    );
    assert_eq!(journal(&plan.attempts[0])?, old);
    assert!(!window_present(&plan.attempts[0])?);
    Ok(())
}
