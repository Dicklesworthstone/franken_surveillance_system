#![forbid(unsafe_code)]
//! Real published ONVIF source closures through the immutable source capability.

use std::cell::Cell;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use fss_core::{
    BudgetVector, CaptureInterval, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
    TimestampNs,
};
use fss_object::{HostSpoolIo, RecordingSpoolIo, SpoolIoCall};
use fss_packet::{OnvifMetadataLimits, ReorderLimits, StreamKey};
use fss_publication::custody_audit::CustodyAuditLimits;

use super::*;
use crate::deletion::{commit_deletion, plan_deletion};
use crate::onvif::metadata::{
    Interpretation, RetainedMetadata, retain, retain_with_interpretation,
};
use crate::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-immutable-source-test";
const PRINCIPAL: &str = "operator:onvif-immutable-source-test";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let root = std::env::temp_dir().join(format!(
                "fss-onvif-immutable-source-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory capacity".into())
    }

    fn cx(&self) -> Test<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-immutable-source-test".into(),
            operation_id: OperationId::parse("operation:onvif-immutable-source-test")?,
            principal: PRINCIPAL.into(),
            capabilities: vec![crate::ADP_REPLAY_ROW_ID.into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(128 * 1024 * 1024)
                .storage_operations(16_384)
                .build()?,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority_read_only(
            &authority, &self.0,
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binding() -> Test<SourceBinding> {
    Ok(SourceBinding {
        sensor_id: SensorId::parse("sensor:front")?,
        device_generation: ContentDigest::sha256(b"immutable-source-device"),
        profile_generation: ContentDigest::sha256(b"immutable-source-profile"),
        profile_token: "private-immutable-profile".into(),
        receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
    })
}

fn xml(second: u8) -> Vec<u8> {
    format!(
        r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics><t:Frame UtcTime="2026-11-09T00:00:{second:02}Z" Source="private-immutable-module"><t:Object ObjectId="910000011"/></t:Frame></t:VideoAnalytics></t:MetadataStream>"#
    )
    .into_bytes()
}

fn limits() -> CustodyAuditLimits {
    CustodyAuditLimits {
        max_catalogue_entries: 8,
        max_objects: 1024,
        max_edges: 1024,
        max_object_bytes: rtp::MAX_INPUT_BYTES,
        max_read_bytes: 64 * 1024 * 1024,
        max_io_calls: 16_384,
    }
}

fn pin(source: &RetainedMetadata) -> TrackSourcePin {
    TrackSourcePin::Xml {
        identity: source.identity(),
        root: source.publication_root(),
    }
}

fn rtp_config() -> rtp::RtpMetadataConfig {
    rtp::RtpMetadataConfig {
        stream: StreamKey {
            ingress: 17,
            generation: 3,
            ssrc: 42,
        },
        payload_type: 107,
        limits: rtp::RtpMetadataImportLimits::default(),
        reorder: ReorderLimits::default(),
        metadata: OnvifMetadataLimits::default(),
    }
}

fn packet(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 107 | if marker { 0x80 } else { 0 }];
    bytes.extend(sequence.to_be_bytes());
    bytes.extend((u32::from(sequence) * 1000).to_be_bytes());
    bytes.extend(42_u32.to_be_bytes());
    bytes.extend(payload);
    bytes
}

fn dump(documents: &[Vec<u8>]) -> Vec<u8> {
    let mut result = b"#!rtpplay1.0 192.0.2.1/5004\n".to_vec();
    result.extend([0; 16]);
    let mut packets = vec![
        packet(100, false, b"unknown-start"),
        packet(101, true, b"observed-boundary"),
    ];
    for (index, xml) in documents.iter().enumerate() {
        packets.push(packet(102 + index as u16, true, xml));
    }
    for (index, packet) in packets.iter().enumerate() {
        result.extend(((packet.len() + 8) as u16).to_be_bytes());
        result.extend((packet.len() as u16).to_be_bytes());
        result.extend((index as u32).to_be_bytes());
        result.extend(packet);
    }
    result
}

#[test]
fn xml_v1_v2_reconstruction_is_identical_with_writer_lock_and_unrelated_corruption() -> Test {
    let directory = Directory::new("xml-parity")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let bytes = xml(0);
    let modern = retain(&mut deployment, binding()?, &bytes, &cx)?;
    let legacy = retain_with_interpretation(
        &mut deployment,
        binding()?,
        &bytes,
        Interpretation::EventsV1,
        &cx,
    )?;
    let unrelated = retain(&mut deployment, binding()?, &xml(5), &cx)?;
    let modern = RetainedMetadata::open(
        &deployment,
        modern.identity(),
        Some(modern.publication_root()),
        &cx,
    )?;
    let legacy = RetainedMetadata::open(
        &deployment,
        legacy.identity(),
        Some(legacy.publication_root()),
        &cx,
    )?;
    fs::write(
        deployment
            .publisher()
            .spool()
            .object_path(unrelated.source_digest()),
        b"corrupt unrelated retained source",
    )?;
    let root = deployment.publisher().root_dir().to_path_buf();
    let before = (
        fs::read(directory.0.join("ledger/journal.fssj"))?,
        fs::read(directory.0.join("effects/journal.fssj"))?,
    );
    let deletions = DeletionIndex::read(&deployment)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &root, limits(), &|| false)?;
    for original in [&modern, &legacy] {
        let loaded = read_source(
            &mut reader,
            SITE,
            deployment.ledger().batches(),
            &deletions,
            pin(original),
            &|| Ok(()),
        )?;
        assert_eq!(loaded.raw_xml.as_deref(), Some(bytes.as_slice()));
        assert!(!format!("{loaded:?}").contains("private"));
        for digest in [
            original.identity(),
            original.publication_root(),
            original.source_digest(),
            original.projection_digest(),
        ] {
            assert!(loaded.reference_digests.contains(&digest));
        }
        let Source::Xml(actual) = loaded.source else {
            return Err("wrong source variant".into());
        };
        assert_eq!(actual.identity(), original.identity());
        assert_eq!(actual.publication_root(), original.publication_root());
        assert_eq!(actual.document(), original.document());
        assert_eq!(actual.parser_generation(), original.parser_generation());
        assert_eq!(actual.authority_anchor(), original.authority_anchor());
    }
    assert_eq!(modern.document().analytics_frames.len(), 1);
    assert!(legacy.document().analytics_frames.is_empty());
    let usage = reader.finish()?;
    assert_eq!(usage.completed_roots, 2);
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert_eq!(io.call_count(SpoolIoCall::TryLock), 0);
    assert_eq!(fs::read(directory.0.join("ledger/journal.fssj"))?, before.0);
    assert_eq!(
        fs::read(directory.0.join("effects/journal.fssj"))?,
        before.1
    );
    Ok(())
}

#[test]
fn rtp_replay_preserves_rejected_empty_and_original_document_custody() -> Test {
    let directory = Directory::new("rtp-parity")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let documents = [
        xml(0),
        b"<invalid/>".to_vec(),
        br#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"/>"#.to_vec(),
    ];
    let retained = rtp::retain(
        &mut deployment,
        &dump(&documents),
        binding()?,
        rtp_config(),
        &cx,
    )?;
    let original = rtp::RetainedRtpMetadata::open(
        &deployment,
        retained.identity(),
        Some(retained.publication_root()),
        &cx,
    )?;
    let root = deployment.publisher().root_dir().to_path_buf();
    let deletions = DeletionIndex::read(&deployment)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &root, limits(), &|| false)?;
    let loaded = read_source(
        &mut reader,
        SITE,
        deployment.ledger().batches(),
        &deletions,
        TrackSourcePin::Rtp {
            identity: original.identity(),
            root: original.publication_root(),
        },
        &|| Ok(()),
    )?;
    assert!(loaded.raw_xml.is_none());
    for document in &documents {
        assert!(
            loaded
                .reference_digests
                .contains(&ContentDigest::sha256(document))
        );
    }
    let Source::Rtp(actual) = loaded.source else {
        return Err("wrong source variant".into());
    };
    assert_eq!(actual.identity(), original.identity());
    assert_eq!(actual.report(), original.report());
    assert_eq!(actual.authority_anchor(), original.authority_anchor());
    assert_eq!(actual.documents().len(), 3);
    for (actual, original) in actual.documents().iter().zip(original.documents()) {
        assert_eq!(actual.source_xml(), original.source_xml());
        assert_eq!(actual.source_digest(), original.source_digest());
        assert_eq!(actual.projection_digest(), original.projection_digest());
        assert_eq!(actual.document(), original.document());
        assert_eq!(actual.provenance(), original.provenance());
    }
    assert!(actual.documents()[1].document().is_none());
    assert!(
        actual.documents()[2]
            .document()
            .ok_or("empty metadata")?
            .analytics_frames
            .is_empty()
    );
    assert_eq!(reader.finish()?.completed_roots, 1);
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    Ok(())
}

#[test]
fn exact_root_site_and_committed_publication_witness_are_required() -> Test {
    let directory = Directory::new("authority-pins")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let original = retain(&mut deployment, binding()?, &xml(0), &cx)?;
    let root = deployment.publisher().root_dir().to_path_buf();
    let deletions = DeletionIndex::read(&deployment)?;
    for (site, batches, pin) in [
        ("site:wrong", deployment.ledger().batches(), pin(&original)),
        (SITE, &[][..], pin(&original)),
        (
            SITE,
            deployment.ledger().batches(),
            TrackSourcePin::Xml {
                identity: original.identity(),
                root: ContentDigest::sha256(b"wrong root"),
            },
        ),
    ] {
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let mut reader = PinnedClosureReader::new(&io, &root, limits(), &|| false)?;
        assert!(read_source(&mut reader, site, batches, &deletions, pin, &|| Ok(())).is_err());
        assert_eq!(reader.usage().completed_roots, 0);
        assert!(io.is_read_only());
    }
    let mut changed = deployment.ledger().batches().to_vec();
    let batch = changed
        .iter_mut()
        .find(|batch| {
            batch
                .deltas
                .iter()
                .any(|delta| delta.payload_digest == original.publication_root())
        })
        .ok_or("publication batch")?;
    batch.deltas[0].validity = CaptureInterval::new(TimestampNs(200), TimestampNs(210))?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &root, limits(), &|| false)?;
    assert!(matches!(
        read_source(
            &mut reader,
            SITE,
            &changed,
            &deletions,
            pin(&original),
            &|| Ok(())
        ),
        Err(MetadataError::Custody)
    ));
    Ok(())
}

#[test]
fn one_reader_keeps_byte_and_io_balances_across_complete_source_passes() -> Test {
    let directory = Directory::new("shared-budget")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let original = retain(&mut deployment, binding()?, &xml(0), &cx)?;
    let root = deployment.publisher().root_dir().to_path_buf();
    let deletions = DeletionIndex::read(&deployment)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &root, limits(), &|| false)?;
    read_source(
        &mut reader,
        SITE,
        deployment.ledger().batches(),
        &deletions,
        pin(&original),
        &|| Ok(()),
    )?;
    let first = reader.usage();
    read_source(
        &mut reader,
        SITE,
        deployment.ledger().batches(),
        &deletions,
        pin(&original),
        &|| Ok(()),
    )?;
    let total = reader.finish()?;
    assert_eq!(total.completed_roots, 2);
    assert_eq!(total.objects, 2 * first.objects);
    assert_eq!(total.edges, 2 * first.edges);
    assert!(total.read_bytes > first.read_bytes);
    assert!(total.io_calls > first.io_calls);
    assert!(total.peak_reserved_read_bytes > first.peak_reserved_read_bytes);
    for narrowed in [
        CustodyAuditLimits {
            max_read_bytes: first.peak_reserved_read_bytes,
            ..limits()
        },
        CustodyAuditLimits {
            max_io_calls: first.io_calls,
            ..limits()
        },
    ] {
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let mut reader = PinnedClosureReader::new(&io, &root, narrowed, &|| false)?;
        read_source(
            &mut reader,
            SITE,
            deployment.ledger().batches(),
            &deletions,
            pin(&original),
            &|| Ok(()),
        )?;
        assert_eq!(reader.usage().completed_roots, 1);
        assert!(matches!(
            read_source(
                &mut reader,
                SITE,
                deployment.ledger().batches(),
                &deletions,
                pin(&original),
                &|| Ok(())
            ),
            Err(MetadataError::Limit)
        ));
        assert!(reader.finalize().is_err());
    }
    Ok(())
}

#[test]
fn committed_deletion_denies_source_before_any_payload_read() -> Test {
    let directory = Directory::new("deleted")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let original = retain(&mut deployment, binding()?, &xml(0), &cx)?;
    let plan = plan_deletion(&deployment, original.identity(), &cx)?;
    assert!(plan.blockers.is_empty());
    let plan_digest = plan.digest()?;
    commit_deletion(
        &mut deployment,
        plan_digest,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &cx,
    )?;
    let deletions = DeletionIndex::read(&deployment)?;
    let root = deployment.publisher().root_dir().to_path_buf();
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &root, limits(), &|| false)?;
    assert!(
        matches!(read_source(&mut reader, SITE, deployment.ledger().batches(), &deletions, pin(&original), &|| Ok(())), Err(MetadataError::EvidenceDeleted { identity, plan }) if identity == original.identity() && plan == plan_digest)
    );
    assert_eq!(reader.usage().read_bytes, 0);
    assert_eq!(reader.usage().completed_roots, 0);
    assert!(io.is_read_only());
    Ok(())
}

#[test]
fn every_guard_cut_preserves_authority_refusal_including_root_revalidation() -> Test {
    let directory = Directory::new("guard-cuts")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let original = retain(&mut deployment, binding()?, &xml(0), &cx)?;
    let root = deployment.publisher().root_dir().to_path_buf();
    let deletions = DeletionIndex::read(&deployment)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &root, limits(), &|| false)?;
    let count = Cell::new(0);
    read_source(
        &mut reader,
        SITE,
        deployment.ledger().batches(),
        &deletions,
        pin(&original),
        &|| {
            count.set(count.get() + 1);
            Ok(())
        },
    )?;
    let total = count.get();
    assert!(total > 10);
    reader.finish()?;
    for stop in [1, total / 2, total] {
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let mut reader = PinnedClosureReader::new(&io, &root, limits(), &|| false)?;
        let calls = Cell::new(0);
        let result = read_source(
            &mut reader,
            SITE,
            deployment.ledger().batches(),
            &deletions,
            pin(&original),
            &|| {
                calls.set(calls.get() + 1);
                if calls.get() == stop {
                    Err(MetadataError::Authority)
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(result, Err(MetadataError::Authority)));
        assert_eq!(reader.usage().completed_roots, 0);
        assert_eq!(calls.get(), stop);
    }
    Ok(())
}

#[test]
fn selected_source_corruption_refuses_without_recovery_or_repair() -> Test {
    let directory = Directory::new("selected-tamper")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let original = retain(&mut deployment, binding()?, &xml(0), &cx)?;
    let path = deployment
        .publisher()
        .spool()
        .object_path(original.source_digest());
    let corrupted = b"corrupt selected source";
    fs::write(&path, corrupted)?;
    let deletions = DeletionIndex::read(&deployment)?;
    let root = deployment.publisher().root_dir().to_path_buf();
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &root, limits(), &|| false)?;
    assert!(
        read_source(
            &mut reader,
            SITE,
            deployment.ledger().batches(),
            &deletions,
            pin(&original),
            &|| Ok(())
        )
        .is_err()
    );
    assert_eq!(reader.usage().completed_roots, 0);
    assert_eq!(fs::read(path)?, corrupted);
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    Ok(())
}
