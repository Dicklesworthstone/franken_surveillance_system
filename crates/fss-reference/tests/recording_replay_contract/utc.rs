#![forbid(unsafe_code)]
//! Cold queries over actual native source custody, without treating PLAY Range as sample time.

use super::*;
use fss_packet::onvif_replay::{RecordedUtcInterval, ReplayExtensionError as ExtensionError};
use fss_reference::rtsp::recording_replay::time::{
    ReplayTimeError as TimeError, ReplayTimeUnknown as Unknown, query_replay_time,
};

#[path = "utc/fixtures.rs"]
mod fixtures;
use fixtures::*;

#[path = "utc/bounded_io.rs"]
mod bounded_io;

#[test]
fn fragmented_avc_binds_every_original_packet_to_the_first_access_unit_assertion() -> TestResult {
    let source = rebuild_avc(fixture(901, true)?, |index, wire| {
        if index == 0 {
            stamp(wire, NTP_SECONDS, 0x8000_0000, 0xF0, 7)?;
        }
        Ok(())
    })?;
    let original = source.prepare()?;
    let sealed = seal_avc("utc-avc-fragments", &source, 1, 7)?;
    let publisher = sealed.open()?;
    let before = publisher.spool().read(sealed.receipt.root())?;
    let report = query_replay_time(&publisher, &sealed.query(), &NeverCancel)?;
    assert_eq!(report.receipt.root(), sealed.receipt.root());
    assert_eq!(report.scanned_windows, 1);
    assert_eq!(report.scanned_samples, 1);
    assert_eq!(report.scanned_packets as usize, source.packets.len());
    assert_eq!(report.source_bytes as usize, original.byte_len());
    assert_eq!(report.source_bytes_reserved, 32 * 1024 * 1024);
    assert!(report.unknown.is_empty());
    assert!(report.source_only.is_empty());
    assert_eq!(report.matches.len(), 1);
    let row = &report.matches[0];
    assert_eq!(row.window, 0);
    assert_eq!(row.sample, 0);
    assert_eq!(row.root, sealed.receipt.windows()[0].root());
    assert_eq!(&row.slot, sealed.receipt.windows()[0].slot());
    assert_eq!(
        (row.decode_time, row.presentation_time, row.duration),
        (0, 0, 3600)
    );
    assert_eq!(row.rtp_timestamp, 90_000);
    assert_eq!(
        row.evidence.first_sequence,
        source.packets.first().ok_or("first packet")?.0
    );
    assert_eq!(
        row.evidence.last_sequence,
        source.packets.last().ok_or("last packet")?.0
    );
    assert_eq!(row.evidence.packet_count as usize, source.packets.len());
    assert_eq!(
        row.evidence.utc,
        Some(RecordedUtcInterval {
            earliest_ns: UTC_NS + 500_000_000,
            latest_ns: UTC_NS + 500_000_000,
        })
    );
    assert!(row.evidence.unknown.is_none());
    let header = row.evidence.header.ok_or("first packet assertion")?;
    assert!(
        header.clean_point
            && header.end_of_contiguous_section
            && header.discontinuity
            && header.terminal
    );
    assert_eq!(header.cseq_low, 7);
    assert_eq!(publisher.spool().read(sealed.receipt.root())?, before);
    drop(publisher);
    let reopened = sealed.open()?;
    let again = query_replay_time(&reopened, &sealed.query(), &NeverCancel)?;
    assert_eq!(again.digest, report.digest);
    assert_eq!(again.index_digest, report.index_digest);
    assert_eq!(
        again.matches[0].evidence.packet_set_digest,
        row.evidence.packet_set_digest
    );
    Ok(())
}

#[test]
fn absent_foreign_malformed_and_unknown_first_assertions_remain_explicit_unknowns() -> TestResult {
    let cases = [
        Unknown::MissingFirstExtension,
        Unknown::ForeignFirstExtension,
        Unknown::MalformedExtension(ExtensionError::Length),
        Unknown::MalformedExtension(ExtensionError::ReservedBits),
        Unknown::UnknownTimestamp,
        Unknown::UtcOutOfRange,
    ];
    for (case, expected) in cases.into_iter().enumerate() {
        let source = rebuild_avc(fixture(902, true)?, |index, wire| {
            if index == 0 {
                match case {
                    0 => {}
                    1 => raw_extension(wire, 0xBEDE, &content(NTP_SECONDS, 0, 0, 7))?,
                    2 => raw_extension(wire, 0xABAC, &content(NTP_SECONDS, 0, 0, 7)[..8])?,
                    3 => stamp(wire, NTP_SECONDS, 0, 1, 7)?,
                    4 => stamp(wire, 0, 0, 0, 7)?,
                    _ => stamp(wire, 1, 1, 0, 7)?,
                }
            } else if case <= 1 {
                // A later valid assertion cannot repair the absent/foreign first packet.
                stamp(wire, NTP_SECONDS, 0, 0, 7)?;
            }
            Ok(())
        })?;
        let sealed = seal_avc("utc-unknown-first", &source, 1, 7)?;
        let publisher = sealed.open()?;
        let report = query_replay_time(&publisher, &sealed.query(), &NeverCancel)?;
        assert!(report.matches.is_empty(), "case {case}");
        assert_eq!(report.unknown.len(), 1, "case {case}");
        assert_eq!(
            report.unknown[0].evidence.unknown,
            Some(expected),
            "case {case}"
        );
        assert!(report.unknown[0].evidence.utc.is_none(), "case {case}");
        assert_eq!(
            report.unknown[0].evidence.packet_count as usize,
            source.packets.len()
        );
        assert_eq!(report.scanned_samples, 1);
        assert_eq!(report.outside_samples, 0);
    }
    Ok(())
}

#[test]
fn conflicting_repeated_time_flags_or_play_coordinates_never_choose_a_convenient_fragment()
-> TestResult {
    for field in 0..4 {
        let source = rebuild_avc(fixture(903, true)?, |index, wire| {
            let mut seconds = NTP_SECONDS;
            let mut fraction = 0;
            let mut flags = 0;
            let mut cseq = 7;
            if index == 1 {
                match field {
                    0 => seconds += 1,
                    1 => fraction = 1,
                    2 => flags = 0x20,
                    _ => cseq = 8,
                }
            }
            stamp(wire, seconds, fraction, flags, cseq)
        })?;
        let sealed = seal_avc("utc-conflicting-fragments", &source, 1, 7)?;
        let report = query_replay_time(&sealed.open()?, &sealed.query(), &NeverCancel)?;
        assert!(report.matches.is_empty());
        assert_eq!(report.unknown.len(), 1);
        assert_eq!(
            report.unknown[0].evidence.unknown,
            Some(Unknown::ConflictingExtensions)
        );
        assert!(report.unknown[0].evidence.utc.is_none());
    }
    Ok(())
}

#[test]
fn semantically_equal_padding_still_changes_exact_source_and_query_proofs() -> TestResult {
    let mut reports = Vec::new();
    let mut source_roots = Vec::new();
    for changed in [false, true] {
        let source = rebuild_avc(fixture(904, true)?, |index, wire| {
            let mut extension = content(NTP_SECONDS, 0, 0x80, 7);
            if changed {
                extension[10..12].copy_from_slice(&[0xCA, index as u8]);
            }
            raw_extension(wire, 0xABAC, &extension)
        })?;
        let sealed = seal_avc("utc-padding-custody", &source, 1, 7)?;
        source_roots.push(sealed.receipt.windows()[0].original_leaf_digests()[0]);
        reports.push(query_replay_time(
            &sealed.open()?,
            &sealed.query(),
            &NeverCancel,
        )?);
    }
    let a = &reports[0];
    let b = &reports[1];
    assert_eq!(a.matches.len(), 1);
    assert_eq!(b.matches.len(), 1);
    assert_eq!(a.matches[0].evidence.header, b.matches[0].evidence.header);
    assert_eq!(a.matches[0].evidence.utc, b.matches[0].evidence.utc);
    assert_ne!(source_roots[0], source_roots[1]);
    assert_ne!(
        a.matches[0].evidence.packet_set_digest,
        b.matches[0].evidence.packet_set_digest
    );
    assert_ne!(
        a.matches[0].evidence.proof_digest,
        b.matches[0].evidence.proof_digest
    );
    assert_ne!(a.index_digest, b.index_digest);
    assert_ne!(a.digest, b.digest);
    Ok(())
}

#[test]
fn play_low_byte_mismatch_is_unknown_while_a_256_wrap_keeps_separate_receipt_identity() -> TestResult
{
    let source = rebuild_avc(fixture(905, true)?, |index, wire| {
        if index == 0 {
            stamp(wire, NTP_SECONDS, 0, 0, 7)?;
        }
        Ok(())
    })?;
    let first = seal_avc("utc-cseq-seven", &source, 1, 7)?;
    let wrapped = seal_avc("utc-cseq-wrapped", &source, 1, 263)?;
    let wrong = seal_avc("utc-cseq-mismatch", &source, 1, 8)?;
    let a = query_replay_time(&first.open()?, &first.query(), &NeverCancel)?;
    let b = query_replay_time(&wrapped.open()?, &wrapped.query(), &NeverCancel)?;
    assert_eq!(a.matches.len(), 1);
    assert_eq!(b.matches.len(), 1);
    assert_eq!(a.receipt.acceptance().cseq(), 7);
    assert_eq!(b.receipt.acceptance().cseq(), 263);
    assert_eq!(a.matches[0].evidence.header.ok_or("header")?.cseq_low, 7);
    assert_eq!(a.matches[0].evidence.header, b.matches[0].evidence.header);
    assert_eq!(
        first.receipt.request().digest(),
        wrapped.receipt.request().digest()
    );
    assert_ne!(first.receipt.root(), wrapped.receipt.root());
    assert_ne!(a.index_digest, b.index_digest);
    assert_ne!(a.digest, b.digest);
    let refused = query_replay_time(&wrong.open()?, &wrong.query(), &NeverCancel)?;
    assert!(refused.matches.is_empty());
    assert_eq!(
        refused.unknown[0].evidence.unknown,
        Some(Unknown::PlayCseqMismatch)
    );
    assert_eq!(
        refused.unknown[0]
            .evidence
            .unknown
            .ok_or("unknown")?
            .error_code(),
        Some("ERR-RTP-REPLAY-CSEQ-MISMATCH-001")
    );
    Ok(())
}

#[test]
fn hevc_lookahead_keeps_timestamped_source_out_of_the_sample_results() -> TestResult {
    for malformed_tail in [false, true] {
        let mut packets = stamped_hevc()?;
        if malformed_tail {
            // First trailing VPS has a malformed recorded-time flag; video remains source-valid.
            packets[5].bytes[24] |= 1;
        }
        let sealed = seal_hevc(
            "utc-hevc-source-tail",
            &packets[..8],
            &hevc_recording_support::timings(2),
            7,
        )?;
        let publisher = sealed.open()?;
        let all = query_replay_time(&publisher, &sealed.query(), &NeverCancel)?;
        assert_eq!(all.matches.len(), 2);
        assert!(all.unknown.is_empty());
        assert_eq!(all.scanned_packets, 8);
        assert_eq!(all.scanned_samples, 2);
        assert_eq!(all.source_only.len(), 1);
        let tail = &all.source_only[0];
        assert_eq!(tail.evidence.first_sequence, packets[5].sequence);
        assert_eq!(tail.evidence.last_sequence, packets[7].sequence);
        assert_eq!(tail.evidence.packet_count, 3);
        if malformed_tail {
            assert_eq!(
                tail.evidence.unknown,
                Some(Unknown::MalformedExtension(ExtensionError::ReservedBits))
            );
            assert!(tail.evidence.utc.is_none());
        } else {
            assert_eq!(
                tail.evidence.utc,
                Some(RecordedUtcInterval {
                    earliest_ns: UTC_NS + 2_000_000_000,
                    latest_ns: UTC_NS + 2_000_000_000,
                })
            );
        }
        let mut only_tail_time = sealed.query();
        only_tail_time.start_ns = UTC_NS + 2_000_000_000;
        only_tail_time.end_ns = UTC_NS + 3_000_000_000;
        let filtered = query_replay_time(&publisher, &only_tail_time, &NeverCancel)?;
        assert!(filtered.matches.is_empty());
        assert_eq!(filtered.outside_samples, 2);
        assert_eq!(filtered.source_only.len(), 1);
        assert_eq!(filtered.index_digest, all.index_digest);
        assert_ne!(filtered.digest, all.digest);
    }
    Ok(())
}

#[test]
fn hevc_aggregation_and_fragmentation_count_distinct_source_packets_not_nal_copies() -> TestResult {
    let nals = hevc_recording_support::nals()?;
    let split = 2 + (nals[3].len() - 2) / 2;
    let kind = (nals[3][0] >> 1) & 63;
    let mut start = vec![0x62, 1, 0x80 | kind];
    start.extend_from_slice(&nals[3][2..split]);
    let mut end = vec![0x62, 1, 0x40 | kind];
    end.extend_from_slice(&nals[3][split..]);
    let mut packets = vec![
        hevc_recording_support::packet(
            65_534,
            0,
            false,
            &hevc_recording_support::aggregate(&nals[..3]),
        ),
        hevc_recording_support::packet(65_535, 0, false, &start),
        hevc_recording_support::packet(65_536, 0, true, &end),
        hevc_recording_support::packet(65_537, 0, true, &[0x48, 1, 0x80]),
    ];
    let timings = hevc_recording_support::timings(1);
    let before = hevc_recording_support::prepare(&packets, &timings)?;
    for packet in &mut packets {
        stamp(&mut packet.bytes, NTP_SECONDS, 0, 0, 7)?;
    }
    let stamped = hevc_recording_support::prepare(&packets, &timings)?;
    assert_eq!(before.objects().media, stamped.objects().media);
    assert_ne!(before.objects().source, stamped.objects().source);
    assert_eq!(
        stamped.mappings()[3].sources[0].fragment_header_range,
        Some(28..31)
    );
    let sealed = seal_hevc("utc-hevc-ap-fu", &packets, &timings, 7)?;
    let report = query_replay_time(&sealed.open()?, &sealed.query(), &NeverCancel)?;
    assert_eq!(report.matches.len(), 1);
    assert!(report.unknown.is_empty());
    assert!(report.source_only.is_empty());
    assert_eq!(report.matches[0].evidence.packet_count, 4);
    assert_eq!(report.matches[0].evidence.first_sequence, 65_534);
    assert_eq!(report.matches[0].evidence.last_sequence, 65_537);
    assert_eq!(report.scanned_packets, 4);
    Ok(())
}

#[test]
fn reordered_presentation_and_recorder_times_keep_the_native_decode_sample_ordinals() -> TestResult
{
    let mut packets = hevc_recording_support::packets()?;
    let order = [0_u32, 3, 1, 2];
    for packet in &mut packets {
        let old = timestamp(&packet.bytes)? / 18_000;
        let presentation = order[old as usize];
        packet.bytes[4..8].copy_from_slice(&(presentation * 18_000).to_be_bytes());
        stamp(&mut packet.bytes, NTP_SECONDS + presentation, 0, 0, 7)?;
    }
    let mut timings = hevc_recording_support::timings(4);
    timings[1].composition_offset = 36_000;
    timings[2].composition_offset = -18_000;
    timings[3].composition_offset = -18_000;
    let sealed = seal_hevc("utc-reordered-presentation", &packets, &timings, 7)?;
    let publisher = sealed.open()?;
    let report = query_replay_time(&publisher, &sealed.query(), &NeverCancel)?;
    assert_eq!(report.matches.len(), 4);
    assert!(report.unknown.is_empty());
    for (sample, presentation) in order.into_iter().enumerate() {
        let row = report
            .matches
            .iter()
            .find(|row| row.sample == sample)
            .ok_or("sample")?;
        assert_eq!(row.decode_time, sample as u64 * 18_000);
        assert_eq!(row.presentation_time, u64::from(presentation) * 18_000);
        assert_eq!(row.rtp_timestamp, presentation * 18_000);
        assert_eq!(
            row.evidence.utc,
            Some(RecordedUtcInterval {
                earliest_ns: UTC_NS + i128::from(presentation) * 1_000_000_000,
                latest_ns: UTC_NS + i128::from(presentation) * 1_000_000_000,
            })
        );
    }
    let mut query = sealed.query();
    query.start_ns = UTC_NS + 1_000_000_000;
    query.end_ns = UTC_NS + 2_000_000_000;
    let selected = query_replay_time(&publisher, &query, &NeverCancel)?;
    assert_eq!(selected.matches.len(), 1);
    assert_eq!(selected.matches[0].sample, 2);
    assert_eq!(selected.matches[0].decode_time, 36_000);
    assert_eq!(selected.matches[0].presentation_time, 18_000);
    assert_eq!(selected.outside_samples, 3);
    assert_eq!(selected.index_digest, report.index_digest);
    assert_ne!(selected.digest, report.digest);
    Ok(())
}

#[test]
fn source_backed_fraction_uncertainty_intersects_half_open_queries_conservatively() -> TestResult {
    let source = rebuild_avc(fixture(906, true)?, |index, wire| {
        if index == 0 {
            stamp(wire, NTP_SECONDS, 1, 0, 7)?;
        }
        Ok(())
    })?;
    let sealed = seal_avc("utc-outward-rounding", &source, 1, 7)?;
    let publisher = sealed.open()?;
    for (start, end, count) in [(-1, 0, 0), (0, 1, 1), (1, 2, 1), (2, 3, 0)] {
        let mut query = sealed.query();
        query.start_ns = UTC_NS + start;
        query.end_ns = UTC_NS + end;
        let report = query_replay_time(&publisher, &query, &NeverCancel)?;
        assert_eq!(report.matches.len(), count);
        assert_eq!(report.outside_samples as usize, 1 - count);
        assert!(report.unknown.is_empty());
        if let Some(row) = report.matches.first() {
            assert_eq!(
                row.evidence.utc,
                Some(RecordedUtcInterval {
                    earliest_ns: UTC_NS,
                    latest_ns: UTC_NS + 1
                })
            );
        }
    }
    let era_zero = query_replay_time(&publisher, &sealed.query(), &NeverCancel)?;
    let mut query = sealed.query();
    query.ntp_era = 1;
    query.start_ns += ERA_NS;
    query.end_ns += ERA_NS;
    let era_one = query_replay_time(&publisher, &query, &NeverCancel)?;
    assert_eq!(era_one.matches.len(), 1);
    assert_eq!(
        era_one.matches[0].evidence.utc,
        Some(RecordedUtcInterval {
            earliest_ns: UTC_NS + ERA_NS,
            latest_ns: UTC_NS + ERA_NS + 1,
        })
    );
    // The unchanged 2026 PLAY acknowledgement is not used to silently force era zero.
    assert_eq!(era_one.receipt.acceptance(), era_zero.receipt.acceptance());
    assert_ne!(era_one.index_digest, era_zero.index_digest);
    assert_ne!(era_one.digest, era_zero.digest);
    Ok(())
}

#[test]
fn a_real_original_at_the_2036_rollover_needs_its_explicit_nonzero_fraction_and_era() -> TestResult
{
    let source = rebuild_avc(fixture(907, false)?, |index, wire| {
        if index == 0 {
            stamp(wire, 0, 1, 0, 7)?;
        }
        Ok(())
    })?;
    let sealed = seal_avc("utc-2036-rollover", &source, 1, 7)?;
    let publisher = sealed.open()?;
    let wrong_era = query_replay_time(&publisher, &sealed.query(), &NeverCancel)?;
    assert_eq!(
        wrong_era.unknown[0].evidence.unknown,
        Some(Unknown::UtcOutOfRange)
    );
    let mut query = sealed.query();
    query.ntp_era = 1;
    query.start_ns = 2_085_978_496_000_000_000;
    query.end_ns = query.start_ns + 2;
    let correct = query_replay_time(&publisher, &query, &NeverCancel)?;
    assert_eq!(correct.matches.len(), 1);
    assert_eq!(
        correct.matches[0].evidence.utc,
        Some(RecordedUtcInterval {
            earliest_ns: 2_085_978_496_000_000_000,
            latest_ns: 2_085_978_496_000_000_001,
        })
    );
    assert!(correct.unknown.is_empty());
    Ok(())
}

#[test]
fn exact_cold_receipt_request_codec_and_every_authority_coordinate_are_required() -> TestResult {
    let source = rebuild_avc(fixture(908, true)?, |index, wire| {
        if index == 0 {
            stamp(wire, NTP_SECONDS, 0, 0, 7)?;
        }
        Ok(())
    })?;
    let sealed = seal_avc("utc-cold-pins", &source, 1, 7)?;
    let publisher = sealed.open()?;
    let digest = ContentDigest::sha256(b"independently wrong cold query pin");
    for field in 0..10 {
        let mut query = sealed.query();
        match field {
            0 => query.receipt_root = digest,
            1 => query.request = digest,
            2 => query.codec = ReplayCodec::Hevc,
            3 => query.scope.recording.sensor = SensorId::parse("sensor-other-query")?,
            4 => query.scope.recording.stream = StreamId::parse("stream-other-query")?,
            5 => query.scope.recording.generation += 1,
            6 => query.scope.recording.anchor = digest,
            7 => query.scope.recording.receive_clock = digest,
            8 => query.scope.decode_clock = digest,
            _ => query.scope.time_scale += 1,
        }
        assert!(
            query_replay_time(&publisher, &query, &NeverCancel).is_err(),
            "pin {field}"
        );
    }
    assert_eq!(
        query_replay_time(&publisher, &sealed.query(), &NeverCancel)?
            .matches
            .len(),
        1
    );
    Ok(())
}

#[test]
fn coherent_receipt_rehash_cannot_replace_a_native_original_source_role() -> TestResult {
    let source = rebuild_avc(fixture(909, true)?, |index, wire| {
        if index == 0 {
            stamp(wire, NTP_SECONDS, 0, 0, 7)?;
        }
        Ok(())
    })?;
    let root = path("utc-forged-original-role");
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let request = request()?;
    let namespace = ArchiveNamespace::new(catalog_scope(&request))?;
    let original = source.prepare()?;
    let slot = namespace.window_slot(0)?;
    publish_window(&mut publisher, &slot, &original)?;
    let receipt = fixtures::receipt(
        request,
        vec![ReplayWindowProof::from_avc(slot, &original)?],
        7,
    )?;
    let old_source = receipt.windows()[0].original_leaf_digests()[0];
    let new_source =
        publisher.stage_object(b"different asserted original with a valid content digest")?;
    let old_metadata = receipt.manifest().metadata_digest().ok_or("metadata")?;
    let mut metadata = receipt.metadata_bytes().to_vec();
    replace_digest(&mut metadata, old_source, new_source)?;
    rechecksum(&mut metadata)?;
    let metadata = publisher.stage_object(&metadata)?;
    let children = receipt.manifest().children().iter().map(|digest| {
        if *digest == old_source {
            new_source
        } else if *digest == old_metadata {
            metadata
        } else {
            *digest
        }
    });
    let manifest = ObjectManifest::new(receipt.manifest().kind(), children, Some(metadata))?;
    publisher.publish(&receipt.slot()?, &manifest)?;
    drop(publisher);
    let sealed = Sealed { root, receipt };
    let mut query = sealed.query();
    query.receipt_root = manifest.root();
    let error = query_replay_time(&sealed.open()?, &query, &NeverCancel)
        .expect_err("native source mismatch");
    assert_eq!(error.code(), "ERR-REPLAY-TIME-CUSTODY-001");
    Ok(())
}

#[test]
fn durable_deletion_of_any_required_root_or_source_blocks_the_entire_query() -> TestResult {
    for role in 0..4 {
        let source = rebuild_avc(fixture(910, true)?, |index, wire| {
            if index == 0 {
                stamp(wire, NTP_SECONDS, 0, 0, 7)?;
            }
            Ok(())
        })?;
        let sealed = seal_avc("utc-tombstone", &source, 1, 7)?;
        let deleted = match role {
            0 => sealed.receipt.windows()[0].original_leaf_digests()[0],
            1 => sealed.receipt.windows()[0].root(),
            2 => sealed.receipt.root(),
            _ => sealed
                .receipt
                .manifest()
                .metadata_digest()
                .ok_or("metadata")?,
        };
        let witness_bytes = b"authorized replay-time fixture deletion";
        let mut publisher = sealed.open()?;
        let witness = publisher.stage_object(witness_bytes)?;
        drop(publisher);
        let donor_root = path("utc-tombstone-donor");
        let mut donor = LocalRootPublisher::open(&donor_root, limits())?;
        assert_eq!(donor.stage_object(witness_bytes)?, witness);
        donor.record_tombstone(TombstoneRecord::new(
            ObjectId::parse("object:replay-time-fixture")?,
            Generation(2),
            Generation(1),
            TombstoneReason::Deleted,
            Some(witness),
            deleted,
        )?)?;
        drop(donor);
        for entry in std::fs::read_dir(donor_root.join(LOCAL_TOMBSTONES_DIR))? {
            let entry = entry?;
            std::fs::copy(
                entry.path(),
                sealed
                    .root
                    .join(LOCAL_TOMBSTONES_DIR)
                    .join(entry.file_name()),
            )?;
        }
        let publisher = sealed.open()?;
        assert!(publisher.tombstones().any(|digest| *digest == deleted));
        assert!(
            query_replay_time(&publisher, &sealed.query(), &NeverCancel).is_err(),
            "role {role}"
        );
    }
    Ok(())
}

#[test]
fn cancellation_and_every_query_resource_limit_refuse_without_a_partial_report() -> TestResult {
    let source = rebuild_avc(fixture(911, true)?, |index, wire| {
        if index == 0 {
            stamp(wire, NTP_SECONDS, 0, 0, 7)?;
        }
        Ok(())
    })?;
    let sealed = seal_avc("utc-resource-bounds", &source, 2, 7)?;
    let publisher = sealed.open()?;
    struct CancelAfterChecks {
        after: usize,
        seen: AtomicUsize,
    }
    impl PublishCancellation for CancelAfterChecks {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            self.seen.fetch_add(1, Ordering::Relaxed) >= self.after
        }
    }
    let observed = CancelAfterChecks {
        after: usize::MAX,
        seen: AtomicUsize::new(0),
    };
    let baseline = query_replay_time(&publisher, &sealed.query(), &observed)?;
    let checkpoints = observed.seen.load(Ordering::Relaxed);
    assert!(checkpoints > 4);
    assert_eq!(baseline.matches.len(), 2);
    assert_eq!(baseline.source_bytes_reserved, 64 * 1024 * 1024);
    for field in 0..5 {
        let mut query = sealed.query();
        match field {
            0 => query.limits.max_windows = 1,
            1 => query.limits.max_samples = 1,
            2 => query.limits.max_packets = 1,
            3 => query.limits.max_source_bytes = 32 * 1024 * 1024 - 1,
            _ => query.limits.max_results = 1,
        }
        assert!(
            matches!(
                query_replay_time(&publisher, &query, &NeverCancel),
                Err(TimeError::Limit)
            ),
            "limit {field}"
        );
    }
    let interrupted = CancelAfterChecks {
        after: checkpoints / 2,
        seen: AtomicUsize::new(0),
    };
    let cancelled = query_replay_time(&publisher, &sealed.query(), &interrupted)
        .expect_err("owner cancelled during the verified scan");
    assert_eq!(cancelled.code(), "ERR-REPLAY-TIME-CANCELLED-001");
    let retry = query_replay_time(&publisher, &sealed.query(), &NeverCancel)?;
    assert_eq!(retry.digest, baseline.digest);
    assert_eq!(retry.index_digest, baseline.index_digest);
    Ok(())
}

#[test]
fn an_empty_accepted_replay_has_no_sample_time_even_when_its_acknowledged_range_matches()
-> TestResult {
    let source = fixture(912, false)?;
    let sealed = seal_avc("utc-empty-receipt", &source, 0, 7)?;
    let report = query_replay_time(&sealed.open()?, &sealed.query(), &NeverCancel)?;
    assert!(report.matches.is_empty());
    assert!(report.unknown.is_empty());
    assert!(report.source_only.is_empty());
    assert_eq!(report.scanned_windows, 0);
    assert_eq!(report.scanned_samples, 0);
    assert_eq!(report.scanned_packets, 0);
    assert_eq!(report.source_bytes, 0);
    assert_eq!(report.source_bytes_reserved, 0);
    assert_eq!(report.outside_samples, 0);
    Ok(())
}

#[test]
fn aggregate_result_budget_includes_unknown_samples_and_source_only_groups() -> TestResult {
    let mut packets = stamped_hevc()?;
    packets[0].bytes.drain(12..28);
    packets[0].bytes[0] &= !0x10;
    let sealed = seal_hevc(
        "utc-aggregate-result-limit",
        &packets[..8],
        &hevc_recording_support::timings(2),
        7,
    )?;
    let publisher = sealed.open()?;
    let mut query = sealed.query();
    query.start_ns = UTC_NS + 2_000_000_000;
    query.end_ns = UTC_NS + 3_000_000_000;
    query.limits.max_results = 2;
    let report = query_replay_time(&publisher, &query, &NeverCancel)?;
    assert!(report.matches.is_empty());
    assert_eq!(report.unknown.len(), 1);
    assert_eq!(
        report.unknown[0].evidence.unknown,
        Some(Unknown::MissingFirstExtension)
    );
    assert_eq!(report.source_only.len(), 1);
    assert_eq!(report.outside_samples, 1);
    query.limits.max_results = 1;
    assert!(matches!(
        query_replay_time(&publisher, &query, &NeverCancel),
        Err(TimeError::Limit)
    ));
    query = sealed.query();
    query.limits.max_results = 2;
    assert!(matches!(
        query_replay_time(&publisher, &query, &NeverCancel),
        Err(TimeError::Limit)
    ));
    Ok(())
}

#[test]
fn invalid_intervals_and_work_bounds_refuse_before_missing_receipt_lookup() -> TestResult {
    let receipt = fixtures::receipt(request()?, Vec::new(), 7)?;
    let sealed = Sealed {
        root: path("utc-pure-admission"),
        receipt,
    };
    let publisher = sealed.open()?;
    for (start, end) in [
        (-1, UTC_NS),
        (UTC_NS, UTC_NS),
        (UTC_NS + 1, UTC_NS),
        (UTC_NS, 253_402_300_800_000_000_001),
    ] {
        let mut query = sealed.query();
        query.start_ns = start;
        query.end_ns = end;
        assert!(matches!(
            query_replay_time(&publisher, &query, &NeverCancel),
            Err(TimeError::Interval)
        ));
    }
    let mut query = sealed.query();
    query.limits.max_packets = 0;
    assert!(matches!(
        query_replay_time(&publisher, &query, &NeverCancel),
        Err(TimeError::Limit)
    ));
    assert_eq!(
        query_replay_time(&publisher, &sealed.query(), &NeverCancel)
            .expect_err("unpublished receipt")
            .code(),
        "ERR-REPLAY-TIME-CUSTODY-001"
    );
    Ok(())
}
