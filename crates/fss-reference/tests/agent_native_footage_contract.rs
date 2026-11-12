#![forbid(unsafe_code)]
//! Offline native recorder imports remain discoverable through the canonical metadata owner.
//! Synthetic native packets qualify metadata/custody boundaries, not camera interoperability.

#[allow(dead_code)]
mod hevc_recording_support;
#[allow(dead_code)]
mod recording_support;
#[allow(dead_code)]
#[path = "rtsp_replay_import_contract/support.rs"]
mod support;
#[path = "agent_native_footage_contract/assertions.rs"]
mod assertions;

use std::fs;

use fss_reference::agent_footage::{FootageQueryError, FootageQueryLimits, query_footage};
use fss_reference::deletion::{approval_digest, commit_deletion, plan_deletion};
use fss_reference::ingest::rtsp_import::RtspImportCodec;

use assertions::{assert_metadata, mark_tombstone, object_path, query, request, snapshot};
use support::{Fixture, SITE, Test};

#[test]
fn whole_avc_and_hevc_replays_are_discoverable_after_archive_removal_without_source_reads() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = Fixture::new("footage-offline", codec, 0, true)?;
        let receipt = f.run()?;
        let retained = f.retained(receipt.import.import_identity)?;
        let root = f.target()?.root().to_path_buf();
        let baseline = assert_metadata(&root, &retained, receipt.import.proof)?;
        drop(f.target.take());
        drop(f.source.take());
        fs::rename(
            f.directory.0.join("archive"),
            f.directory.0.join("offline-archive"),
        )?;

        // Originals, reconstructed media and origin proof are outside metadata hydration.
        // Their unavailability cannot be misreported as verified payload/source availability.
        for digest in retained
            .manifest()
            .ordered_chunks
            .iter()
            .copied()
            .chain(f.packet_packs.iter().copied())
            .chain(std::iter::once(receipt.import.proof))
        {
            fs::write(
                object_path(&root, digest)?,
                b"unavailable original or origin proof",
            )?;
        }
        let changed = assert_metadata(&root, &retained, receipt.import.proof)?;
        assert_eq!(changed.rows, baseline.rows);
        assert_eq!(changed.selection_witness, baseline.selection_witness);
        fs::remove_file(object_path(&root, receipt.import.proof)?)?;
        assert_eq!(query(&root)?.rows, baseline.rows);

        mark_tombstone(&root, receipt.import.proof)?;
        let before = snapshot(&root)?;
        assert!(matches!(
            query_footage(
                &root,
                &request()?,
                &FootageQueryLimits::default(),
                &mut |_| true,
            ),
            Err(FootageQueryError::InvalidRecord | FootageQueryError::Read(_))
        ));
        assert_eq!(snapshot(&root)?, before);
    }
    Ok(())
}

#[test]
fn native_capsule_corruption_refuses_even_when_source_filter_matches_nothing() -> Test {
    let mut f = Fixture::new("footage-capsule", RtspImportCodec::Avc, 0, false)?;
    let receipt = f.run()?;
    let retained = f.retained(receipt.import.import_identity)?;
    let root = f.target()?.root().to_path_buf();
    let baseline = assert_metadata(&root, &retained, receipt.import.proof)?;
    drop(f.target.take());
    fs::write(
        object_path(&root, baseline.rows[0].capsule_digest)?,
        b"corrupt selected native capsule metadata",
    )?;
    let mut request = request()?;
    request.filter.sensor = Some(fss_core::SensorId::parse("sensor:no-such-camera")?);
    assert!(matches!(
        query_footage(
            &root,
            &request,
            &FootageQueryLimits::default(),
            &mut |_| true,
        ),
        Err(FootageQueryError::InvalidRecord)
    ));
    Ok(())
}

#[test]
fn committed_native_replay_deletion_removes_its_metadata_without_recovery() -> Test {
    let mut f = Fixture::new("footage-deleted", RtspImportCodec::Hevc, 0, false)?;
    let receipt = f.run()?;
    let root = f.target()?.root().to_path_buf();
    assert!(!query(&root)?.rows.is_empty());
    let plan = plan_deletion(f.target()?, receipt.import.import_identity, &f.cx)?;
    assert!(plan.blockers.is_empty());
    let digest = plan.digest()?;
    let approval = approval_digest(digest, SITE, "principal:replay-import")?;
    commit_deletion(
        f.target.as_mut().ok_or("target closed")?,
        digest,
        approval,
        "principal:replay-import",
        &f.cx,
    )?;
    drop(f.target.take());
    let before = snapshot(&root)?;
    let result = query(&root)?;
    assert!(result.rows.is_empty());
    assert_eq!(result.matched_capsules, 0);
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}
