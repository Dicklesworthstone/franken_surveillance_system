#![forbid(unsafe_code)]
//! Real publication first; copied original objects must stand alone afterward.

use super::super::tests::{Cancel, Directory, Test, add, limits, scope, work};
use super::*;
use fss_core::CanonicalEncode;
use fss_publication::NeverCancel;
use std::cell::Cell;
use std::collections::BTreeMap;

/// Explicit bounded in-memory custody for these synthetic tests, not a runtime substitute.
#[derive(Clone, Default)]
struct Objects {
    bytes: BTreeMap<ContentDigest, Vec<u8>>,
    calls: Vec<(ContentDigest, usize)>,
}
impl DatagramObjectReader for Objects {
    fn read_object(
        &mut self,
        digest: ContentDigest,
        maximum: usize,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<Vec<u8>> {
        probe(cancel)?;
        work.charge(1)?;
        self.calls.push((digest, maximum));
        let bytes = self
            .bytes
            .get(&digest)
            .ok_or(DatagramArchiveError::Source)?;
        if bytes.len() > maximum {
            return Err(DatagramArchiveError::Limit);
        }
        Ok(bytes.clone())
    }
}
impl Objects {
    fn copy(archive: &DatagramArchive, publisher: &LocalRootPublisher) -> Test<Self> {
        let mut out = Self::default();
        for record in archive.records() {
            let root = publisher.spool().read(record.pin.head)?;
            let manifest = ObjectManifest::from_canonical_bytes(&root)?;
            for digest in manifest.children() {
                out.bytes.insert(*digest, publisher.spool().read(*digest)?);
            }
            out.bytes.insert(record.pin.head, root);
        }
        Ok(out)
    }

    fn install(&mut self, mut record: DatagramRecord) -> Test<DatagramRecord> {
        let metadata = record.metadata()?;
        let manifest = record.manifest()?;
        record.pin.head = manifest.root();
        self.bytes
            .insert(ContentDigest::sha256(&metadata), metadata);
        self.bytes
            .insert(manifest.root(), manifest.canonical_bytes());
        Ok(record)
    }
}

fn published(
    originals: &[(u8, u64, Vec<u8>)],
) -> Test<(Directory, LocalRootPublisher, DatagramArchive)> {
    let directory = Directory::new()?;
    let mut publisher = directory.open()?;
    let mut archive = DatagramArchive::new(scope()?, limits())?;
    for (channel, received, bytes) in originals {
        add(&mut archive, &mut publisher, *channel, *received, bytes)?;
    }
    Ok((directory, publisher, archive))
}

fn fixture() -> Test<(Objects, DatagramPin, Vec<DatagramRecord>)> {
    let (_directory, publisher, archive) = published(&[
        (0, 10, b"original malformed RTP".to_vec()),
        (1, 10, Vec::new()),
        (0, 12, b"original malformed RTP".to_vec()),
    ])?;
    let objects = Objects::copy(&archive, &publisher)?;
    Ok((objects, archive.pin(), archive.records().to_vec()))
    // Publisher and directory are gone before any detached verification begins.
}

fn recover(objects: &mut Objects, selected: DatagramPin) -> Result<DetachedDatagramPrefix> {
    DetachedDatagramPrefix::recover(
        scope().map_err(|_| DatagramArchiveError::Configuration)?,
        limits(),
        selected,
        objects,
        &NeverCancel,
        &mut work(),
    )
}

#[test]
fn canonical_original_closure_survives_archive_removal_without_losing_duplicates_or_empty_input()
-> Test {
    let (mut objects, pin, records) = fixture()?;
    let selected = recover(&mut objects, pin)?;
    assert_eq!(selected.pin(), pin);
    assert_eq!(selected.scope(), &scope()?);
    assert_eq!(selected.records(), records);
    assert_eq!(objects.calls.len(), 9);
    assert_eq!(objects.calls[0].0, records[2].pin.head);
    assert_eq!(objects.calls[3].0, records[1].pin.head);
    assert_eq!(objects.calls[6].0, records[0].pin.head);
    assert_eq!(objects.calls[5].1, 0);
    for record in &records {
        let original = selected.read(
            record.pin.datagrams,
            &mut objects,
            &NeverCancel,
            &mut work(),
        )?;
        assert_eq!(original.record(), *record);
        assert_eq!(
            ContentDigest::sha256(original.payload()),
            record.payload_digest
        );
    }
    assert_eq!(records[0].payload_digest, records[2].payload_digest);
    assert_ne!(records[0].pin.head, records[2].pin.head);
    selected.revalidate(&mut objects, &NeverCancel, &mut work())?;
    assert_eq!(objects.calls.len(), 27);
    Ok(())
}

#[test]
fn empty_prefix_is_exact_and_current_cancellation_still_applies() -> Test {
    let archive = DatagramArchive::new(scope()?, limits())?;
    let mut objects = Objects::default();
    let prefix = recover(&mut objects, archive.pin())?;
    assert!(prefix.records().is_empty());
    assert!(objects.calls.is_empty());
    assert!(matches!(
        prefix.read(1, &mut objects, &NeverCancel, &mut work()),
        Err(DatagramArchiveError::Sequence)
    ));
    assert!(matches!(
        prefix.revalidate(&mut objects, &Cancel, &mut work()),
        Err(DatagramArchiveError::Cancelled)
    ));
    for pin in [
        DatagramPin {
            head: ContentDigest::sha256(b"invented empty head"),
            ..archive.pin()
        },
        DatagramPin {
            payload_bytes: 1,
            ..archive.pin()
        },
    ] {
        assert!(recover(&mut objects, pin).is_err());
    }
    Ok(())
}

#[test]
fn every_pin_and_scope_field_is_enforced_before_a_chain_can_be_sealed() -> Test {
    let (objects, pin, _) = fixture()?;
    for wrong in [
        DatagramPin {
            scope: ContentDigest::sha256(b"other scope"),
            ..pin
        },
        DatagramPin {
            head: ContentDigest::sha256(b"other root"),
            ..pin
        },
        DatagramPin {
            datagrams: pin.datagrams - 1,
            ..pin
        },
        DatagramPin {
            datagrams: pin.datagrams + 1,
            ..pin
        },
        DatagramPin {
            payload_bytes: pin.payload_bytes - 1,
            ..pin
        },
        DatagramPin {
            datagrams: u64::MAX,
            ..pin
        },
    ] {
        assert!(recover(&mut objects.clone(), wrong).is_err());
    }
    let mut altered = scope()?;
    altered.receive_clock = ContentDigest::sha256(b"new receive clock");
    let mut changed = objects.clone();
    assert!(matches!(
        DetachedDatagramPrefix::recover(
            altered,
            limits(),
            pin,
            &mut changed,
            &NeverCancel,
            &mut work()
        ),
        Err(DatagramArchiveError::Sequence)
    ));
    assert!(changed.calls.is_empty());
    Ok(())
}

#[test]
fn absent_or_corrupt_predecessors_metadata_and_payloads_refuse_complete_recovery() -> Test {
    let (objects, pin, records) = fixture()?;
    let oldest = records[0];
    for digest in [
        oldest.pin.head,
        ContentDigest::sha256(&oldest.metadata()?),
        oldest.payload_digest,
    ] {
        let mut missing = objects.clone();
        missing.bytes.remove(&digest);
        assert!(recover(&mut missing, pin).is_err());
        let mut changed = objects.clone();
        changed
            .bytes
            .insert(digest, b"changed retained original".to_vec());
        assert!(recover(&mut changed, pin).is_err());
    }
    Ok(())
}

#[test]
fn validly_hashed_wrong_manifest_families_and_child_sets_are_not_accepted() -> Test {
    let (objects, pin, records) = fixture()?;
    let record = records[2];
    let metadata = ContentDigest::sha256(&record.metadata()?);
    for manifest in [
        ObjectManifest::new(
            "other_source_family",
            [record.payload_digest],
            Some(metadata),
        )?,
        ObjectManifest::new(
            RTSP_DATAGRAM_KIND,
            [record.payload_digest, ContentDigest::sha256(b"extra child")],
            Some(metadata),
        )?,
        ObjectManifest::new(RTSP_DATAGRAM_KIND, [record.payload_digest], None)?,
    ] {
        let mut changed = objects.clone();
        changed
            .bytes
            .insert(manifest.root(), manifest.canonical_bytes());
        assert!(matches!(
            recover(
                &mut changed,
                DatagramPin {
                    head: manifest.root(),
                    ..pin
                }
            ),
            Err(DatagramArchiveError::Metadata)
        ));
    }
    Ok(())
}

#[test]
fn noncanonical_root_and_metadata_bytes_refuse_even_with_matching_content_hashes() -> Test {
    let (objects, pin, records) = fixture()?;
    let record = records[2];
    let mut changed = objects.clone();
    let mut root = changed.bytes[&pin.head].clone();
    root.push(0);
    let head = ContentDigest::sha256(&root);
    changed.bytes.insert(head, root);
    assert!(matches!(
        recover(&mut changed, DatagramPin { head, ..pin }),
        Err(DatagramArchiveError::Metadata)
    ));
    let mut changed = objects.clone();
    let mut metadata = record.metadata()?;
    metadata.push(0);
    let metadata_digest = ContentDigest::sha256(&metadata);
    let manifest = ObjectManifest::new(
        RTSP_DATAGRAM_KIND,
        [record.payload_digest],
        Some(metadata_digest),
    )?;
    changed.bytes.insert(metadata_digest, metadata);
    changed
        .bytes
        .insert(manifest.root(), manifest.canonical_bytes());
    assert!(matches!(
        recover(
            &mut changed,
            DatagramPin {
                head: manifest.root(),
                ..pin
            }
        ),
        Err(DatagramArchiveError::Metadata)
    ));
    Ok(())
}

#[test]
fn self_consistent_hashed_chain_still_checks_channels_receive_order_lengths_and_prefix_origin()
-> Test {
    let (objects, _, records) = fixture()?;
    for mutation in 0..5 {
        let mut changed = objects.clone();
        let mut record = records[2];
        match mutation {
            0 => record.channel = 9,
            1 => record.received_ns = 9,
            2 => {
                record.payload_bytes += 1;
                record.pin.payload_bytes += 1;
            }
            3 => {
                record.payload_bytes -= 1;
                record.pin.payload_bytes -= 1;
            }
            4 => {
                record.prior.payload_bytes += 1;
                record.pin.payload_bytes += 1;
            }
            _ => unreachable!(),
        }
        let record = changed.install(record)?;
        assert!(recover(&mut changed, record.pin).is_err());
    }
    let mut changed = objects.clone();
    let mut record = records[0];
    record.prior.head = ContentDigest::sha256(b"invented prefix ancestry");
    let record = changed.install(record)?;
    assert!(matches!(
        recover(&mut changed, record.pin),
        Err(DatagramArchiveError::Sequence)
    ));
    Ok(())
}

#[test]
fn later_reads_recheck_every_object_and_revalidate_never_uses_a_payload_cache() -> Test {
    let (objects, pin, records) = fixture()?;
    let record = records[0];
    for digest in [
        record.pin.head,
        ContentDigest::sha256(&record.metadata()?),
        record.payload_digest,
    ] {
        let mut corrupt = objects.clone();
        let prefix = recover(&mut corrupt, pin)?;
        corrupt
            .bytes
            .get_mut(&digest)
            .ok_or("missing fixture object")?[0] ^= 1;
        assert!(matches!(
            prefix.read(
                record.pin.datagrams,
                &mut corrupt,
                &NeverCancel,
                &mut work()
            ),
            Err(DatagramArchiveError::Metadata)
        ));
        assert!(
            prefix
                .revalidate(&mut corrupt, &NeverCancel, &mut work())
                .is_err()
        );
        let mut changed = objects.clone();
        let prefix = recover(&mut changed, pin)?;
        changed.bytes.remove(&digest);
        assert!(
            prefix
                .read(
                    record.pin.datagrams,
                    &mut changed,
                    &NeverCancel,
                    &mut work()
                )
                .is_err()
        );
        assert!(
            prefix
                .revalidate(&mut changed, &NeverCancel, &mut work())
                .is_err()
        );
    }
    let mut objects = objects;
    let prefix = recover(&mut objects, pin)?;
    for ordinal in [0, pin.datagrams + 1, u64::MAX] {
        let before = objects.calls.len();
        assert!(matches!(
            prefix.read(ordinal, &mut objects, &NeverCancel, &mut work()),
            Err(DatagramArchiveError::Sequence)
        ));
        assert_eq!(objects.calls.len(), before);
    }
    Ok(())
}

#[test]
fn count_payload_scan_and_object_limits_are_independent_of_stored_claims() -> Test {
    let (objects, pin, _) = fixture()?;
    for bounded in [
        DatagramArchiveLimits {
            max_datagrams: 2,
            ..limits()
        },
        DatagramArchiveLimits {
            max_payload_bytes: pin.payload_bytes - 1,
            ..limits()
        },
        DatagramArchiveLimits {
            max_scan_roots: 2,
            ..limits()
        },
    ] {
        let mut reader = objects.clone();
        assert!(matches!(
            DetachedDatagramPrefix::recover(
                scope()?,
                bounded,
                pin,
                &mut reader,
                &NeverCancel,
                &mut work()
            ),
            Err(DatagramArchiveError::Limit)
        ));
        assert!(reader.calls.is_empty());
    }
    let (_directory, publisher, archive) = published(&[(0, 10, vec![5; 1025])])?;
    let mut objects = Objects::copy(&archive, &publisher)?;
    assert!(matches!(
        DetachedDatagramPrefix::recover(
            scope()?,
            DatagramArchiveLimits {
                max_spool_object_bytes: 1024,
                ..limits()
            },
            archive.pin(),
            &mut objects,
            &NeverCancel,
            &mut work()
        ),
        Err(DatagramArchiveError::Limit)
    ));
    assert_eq!(objects.calls.last().map(|call| call.1), Some(1024));
    Ok(())
}

#[test]
fn allocation_and_all_reads_including_failures_and_repeats_consume_one_budget() -> Test {
    let (objects, pin, _) = fixture()?;
    let mut reader = objects.clone();
    let mut measured = work();
    let prefix = DetachedDatagramPrefix::recover(
        scope()?,
        limits(),
        pin,
        &mut reader,
        &NeverCancel,
        &mut measured,
    )?;
    let used = measured.used();
    assert!(used > pin.payload_bytes + pin.datagrams * (1024 + 512));
    let mut exact = WorkBudget::new(used);
    DetachedDatagramPrefix::recover(
        scope()?,
        limits(),
        pin,
        &mut objects.clone(),
        &NeverCancel,
        &mut exact,
    )?;
    assert_eq!(exact.used(), used);
    assert!(matches!(
        DetachedDatagramPrefix::recover(
            scope()?,
            limits(),
            pin,
            &mut objects.clone(),
            &NeverCancel,
            &mut WorkBudget::new(used - 1)
        ),
        Err(DatagramArchiveError::Work(_))
    ));
    let mut reader = objects.clone();
    assert!(matches!(
        DetachedDatagramPrefix::recover(
            scope()?,
            limits(),
            pin,
            &mut reader,
            &NeverCancel,
            &mut WorkBudget::new(1)
        ),
        Err(DatagramArchiveError::Work(_))
    ));
    assert!(reader.calls.is_empty());
    let mut reader = objects;
    reader.bytes.remove(&pin.head);
    let mut budget = work();
    for attempt in 1..=2 {
        assert!(
            prefix
                .read(pin.datagrams, &mut reader, &NeverCancel, &mut budget)
                .is_err()
        );
        assert_eq!(budget.used(), attempt * (1 + 1024 + 1024 * 8 + 1));
    }
    Ok(())
}

#[test]
fn cancellation_before_and_after_last_reader_boundary_never_returns_a_sealed_prefix() -> Test {
    struct Flag<'a>(&'a Cell<bool>);
    impl PublishCancellation for Flag<'_> {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            self.0.get()
        }
    }
    struct LastRead<'a> {
        objects: Objects,
        flag: &'a Cell<bool>,
        at: usize,
    }
    impl DatagramObjectReader for LastRead<'_> {
        fn read_object(
            &mut self,
            digest: ContentDigest,
            maximum: usize,
            cancel: &dyn PublishCancellation,
            work: &mut WorkBudget<'_>,
        ) -> Result<Vec<u8>> {
            let bytes = self.objects.read_object(digest, maximum, cancel, work)?;
            if self.objects.calls.len() == self.at {
                self.flag.set(true);
            }
            Ok(bytes)
        }
    }
    let (objects, pin, _) = fixture()?;
    let mut reader = objects.clone();
    assert!(matches!(
        DetachedDatagramPrefix::recover(scope()?, limits(), pin, &mut reader, &Cancel, &mut work()),
        Err(DatagramArchiveError::Cancelled)
    ));
    assert!(reader.calls.is_empty());
    let flag = Cell::new(false);
    let mut reader = LastRead {
        objects,
        flag: &flag,
        at: 9,
    };
    assert!(matches!(
        DetachedDatagramPrefix::recover(
            scope()?,
            limits(),
            pin,
            &mut reader,
            &Flag(&flag),
            &mut work()
        ),
        Err(DatagramArchiveError::Cancelled)
    ));
    assert_eq!(reader.objects.calls.len(), 9);
    Ok(())
}

#[test]
fn incorrect_reader_length_and_hash_cannot_bypass_canonical_object_verification() -> Test {
    struct Incorrect(bool);
    impl DatagramObjectReader for Incorrect {
        fn read_object(
            &mut self,
            _: ContentDigest,
            maximum: usize,
            _: &dyn PublishCancellation,
            _: &mut WorkBudget<'_>,
        ) -> Result<Vec<u8>> {
            Ok(if self.0 {
                vec![0; maximum + 1]
            } else {
                b"wrong bytes under a requested pin".to_vec()
            })
        }
    }
    let (_, pin, _) = fixture()?;
    for oversized in [false, true] {
        let mut budget = work();
        let result = DetachedDatagramPrefix::recover(
            scope()?,
            limits(),
            pin,
            &mut Incorrect(oversized),
            &NeverCancel,
            &mut budget,
        );
        assert!(matches!(
            result,
            Err(DatagramArchiveError::Metadata | DatagramArchiveError::Limit)
        ));
        assert!(budget.used() > 1024);
    }
    Ok(())
}

#[path = "jpeg_tests.rs"]
mod jpeg;
