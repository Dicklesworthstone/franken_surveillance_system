#![forbid(unsafe_code)]
//! Real native replay custody through the immutable retained owner, including late refusal.

use super::*;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use fss_reference::ReplayCx;
use fss_reference::agent_orient::OrientLimits;
use fss_reference::ingest::FileIngestError;
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedSource,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 256 * 1024 * 1024,
        max_read_objects: 16_384,
    }
}

fn read_context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:immutable-retained-replay".into(),
        operation_id: OperationId::parse("operation:immutable-retained-replay")?,
        principal: "principal:immutable-retained-replay".into(),
        capabilities: vec!["ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).build()?,
        privacy_scope: "privacy:retained-source-verification".into(),
        retention_scope: "retention:no-new-retention".into(),
        anchor_universe: ContentDigest::sha256(import_support::SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority_read_only(
        &authority,
        root.to_path_buf(),
    )?)
}

/// Compare all directory entries and bytes, including journals, pending files and writer locks.
fn filesystem(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    fn visit(base: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) -> Test {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_dir() {
            out.insert(path.strip_prefix(base)?.to_path_buf(), None);
            for entry in fs::read_dir(path)? {
                visit(base, &entry?.path(), out)?;
            }
        } else {
            assert!(
                meta.file_type().is_file(),
                "fixture has an unexpected file type"
            );
            out.insert(
                path.strip_prefix(base)?.to_path_buf(),
                Some(fs::read(path)?),
            );
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

fn run(
    owner: &ImmutableRetainedSource<'_>,
    identity: ContentDigest,
    query: &ReplayTimeQuery,
    cx: &ReplayCx,
) -> Test<ReplayTimeReport> {
    Ok(query_retained_replay_time(
        owner,
        identity,
        query,
        RetainedReadLimits::default(),
        cx,
        &NeverCancel,
    )?)
}

#[test]
fn immutable_cold_and_writer_held_avc_hevc_have_exact_native_parity_without_writes() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut fixture = timestamp_fixture("immutable-retained-parity", codec)?;
        let query = query(&fixture);
        let archive = query_replay_time(
            fixture.source.as_ref().ok_or("source")?,
            &query,
            &NeverCancel,
        )?;
        let imported = fixture.run()?.import;
        let root = fixture.target()?.root().to_path_buf();
        let cx = read_context(&root)?;
        // The operational publisher still holds its exclusive writer lock. An immutable
        // reader must nevertheless work; constructing a publisher here would fail.
        let before = filesystem(&root)?;
        {
            let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
            let result = run(&owner, imported.import_identity, &query, &cx)?;
            owner.revalidate()?;
            identical(&archive, &result);
            assert_eq!(owner.history().head(), owner.snapshot().position);
            let usage = owner.usage();
            assert!(usage.read_bytes > 0);
            assert!(usage.read_objects > 3);
        }
        assert_eq!(filesystem(&root)?, before);

        drop(fixture.target.take());
        drop(fixture.source.take());
        fs::rename(
            fixture.directory.0.join("archive"),
            fixture.directory.0.join("unavailable-archive"),
        )?;
        let before = filesystem(&root)?;
        let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
        let result = run(&owner, imported.import_identity, &query, &cx)?;
        owner.revalidate()?;
        identical(&archive, &result);
        assert_eq!(filesystem(&root)?, before);
    }
    Ok(())
}

#[test]
fn one_aggregate_read_allowance_covers_open_query_and_final_revalidation() -> Test {
    let mut fixture = timestamp_fixture("immutable-retained-budget", RtspImportCodec::Avc)?;
    let query = query(&fixture);
    let imported = fixture.run()?.import;
    let root = fixture.target()?.root().to_path_buf();
    let cx = read_context(&root)?;
    let before = filesystem(&root)?;
    let measured = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    let _ = run(&measured, imported.import_identity, &query, &cx)?;
    let query_usage = measured.usage();
    measured.revalidate()?;
    let complete_usage = measured.usage();
    assert!(complete_usage.read_bytes > query_usage.read_bytes);
    assert!(complete_usage.read_objects > query_usage.read_objects);

    let mut bounded = limits();
    bounded.max_read_objects = usize::try_from(query_usage.read_objects)?;
    let owner = ImmutableRetainedSource::open(&root, bounded, &cx)?;
    let _ = run(&owner, imported.import_identity, &query, &cx)?;
    assert_eq!(owner.usage(), query_usage);
    // No fresh budget is minted to make the final custody observation succeed.
    assert!(owner.revalidate().is_err());
    let exhausted = owner.usage();
    assert!(owner.revalidate().is_err());
    assert!(run(&owner, imported.import_identity, &query, &cx).is_err());
    assert_eq!(owner.usage(), exhausted);

    bounded = limits();
    bounded.max_read_bytes = 1;
    assert!(ImmutableRetainedSource::open(&root, bounded, &cx).is_err());
    assert_eq!(filesystem(&root)?, before);
    Ok(())
}

#[test]
fn late_packet_damage_tombstone_and_pending_publication_refuse_final_result() -> Test {
    let mut fixture = timestamp_fixture("immutable-retained-late", RtspImportCodec::Hevc)?;
    let query = query(&fixture);
    let imported = fixture.run()?.import;
    let root = fixture.target()?.root().to_path_buf();
    let cx = read_context(&root)?;
    let packet = *fixture.packet_packs.last().ok_or("packet")?;
    let packet_path = fixture.target()?.publisher().spool().object_path(packet);
    let bytes = fs::read(&packet_path)?;
    let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    let _ = run(&owner, imported.import_identity, &query, &cx)?;
    fs::write(&packet_path, b"changed after native projection")?;
    let damaged = filesystem(&root)?;
    assert!(owner.revalidate().is_err());
    assert_eq!(filesystem(&root)?, damaged);
    fs::write(&packet_path, bytes)?;

    let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    let _ = run(&owner, imported.import_identity, &query, &cx)?;
    let marker = owner
        .history()
        .replay_objects_root()
        .join(fss_publication::LOCAL_TOMBSTONES_DIR)
        .join(format!(
            "{}{}",
            packet.to_text().replacen(':', "-", 1),
            fss_publication::TOMBSTONE_RECORD_SUFFIX,
        ));
    // Any marker, including malformed or interrupted deletion bytes, denies this source.
    fs::write(&marker, b"unverifiable deletion marker")?;
    let marked = filesystem(&root)?;
    assert!(owner.revalidate().is_err());
    assert_eq!(filesystem(&root)?, marked);
    fs::remove_file(marker)?;

    let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    let _ = run(&owner, imported.import_identity, &query, &cx)?;
    let identity = imported.import_identity.to_text();
    let slot = format!("fi-{}", identity.strip_prefix("sha256:").ok_or("identity")?);
    let pending = owner
        .history()
        .replay_objects_root()
        .join(fss_publication::LOCAL_ROOTS_DIR)
        .join(format!(
            "{slot}{}{}",
            fss_publication::ROOT_RECORD_SUFFIX,
            fss_publication::ROOT_TEMP_SUFFIX,
        ));
    fs::write(pending, b"publication replacement in progress")?;
    let replacing = filesystem(&root)?;
    assert!(owner.revalidate().is_err());
    assert_eq!(filesystem(&root)?, replacing);
    Ok(())
}

#[test]
fn external_cancellation_precedes_metadata_and_revokes_existing_source_reads() -> Test {
    let mut fixture = timestamp_fixture("immutable-retained-cancel", RtspImportCodec::Avc)?;
    let imported = fixture.run()?.import;
    let query = query(&fixture);
    let root = fixture.target()?.root().to_path_buf();
    let cx = read_context(&root)?;
    let before = filesystem(&root)?;
    let stopped = AtomicBool::new(true);
    let cancelled = || stopped.load(Ordering::SeqCst);
    assert!(matches!(
        ImmutableRetainedSource::open_cancellable(&root, limits(), &cx, &cancelled),
        Err(FileIngestError::CancellationRequested { .. })
    ));
    stopped.store(false, Ordering::SeqCst);
    let owner = ImmutableRetainedSource::open_cancellable(&root, limits(), &cx, &cancelled)?;
    let _ = run(&owner, imported.import_identity, &query, &cx)?;
    stopped.store(true, Ordering::SeqCst);
    let usage = owner.usage();
    assert!(matches!(
        owner.revalidate(),
        Err(FileIngestError::CancellationRequested { .. })
    ));
    assert_eq!(owner.usage(), usage);
    assert!(owner.read_object(imported.proof).is_err());
    assert_eq!(owner.usage(), usage);
    assert_eq!(filesystem(&root)?, before);

    // Cancellation is also observed while the opening metadata reader is in progress.
    let calls = AtomicUsize::new(0);
    let during_metadata = || calls.fetch_add(1, Ordering::SeqCst) >= 2;
    assert!(matches!(
        ImmutableRetainedSource::open_cancellable(&root, limits(), &cx, &during_metadata),
        Err(FileIngestError::CancellationRequested { .. })
    ));
    assert_eq!(filesystem(&root)?, before);
    Ok(())
}

#[test]
fn partial_journal_tails_are_refused_without_recovery_and_deleted_imports_stay_deleted() -> Test {
    use fss_reference::deletion::{commit_deletion, plan_deletion};

    let mut fixture = timestamp_fixture("immutable-retained-tail", RtspImportCodec::Avc)?;
    let imported = fixture.run()?.import;
    let query = query(&fixture);
    let root = fixture.target()?.root().to_path_buf();
    let cx = read_context(&root)?;
    let paths = [
        root.join(&fixture.target()?.layout_report().ledger_relpath),
        root.join(&fixture.target()?.layout_report().effects_relpath),
    ];
    for path in paths {
        let original = fs::read(&path)?;
        fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(b"x")?;
        let partial = filesystem(&root)?;
        assert!(ImmutableRetainedSource::open(&root, limits(), &cx).is_err());
        assert_eq!(filesystem(&root)?, partial);
        fs::write(path, original)?;
    }

    let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    let _ = run(&owner, imported.import_identity, &query, &cx)?;
    let plan = plan_deletion(fixture.target()?, imported.import_identity, &fixture.cx)?;
    let approval = plan.approval_digest("principal:replay-import")?;
    commit_deletion(
        fixture.target.as_mut().ok_or("target")?,
        plan.digest()?,
        approval,
        "principal:replay-import",
        &fixture.cx,
    )?;
    let deleted = filesystem(&root)?;
    assert!(owner.revalidate().is_err());
    let current = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    let refusal = query_retained_replay_time(
        &current,
        imported.import_identity,
        &query,
        RetainedReadLimits::default(),
        &cx,
        &NeverCancel,
    )
    .expect_err("deleted import acquired fresh immutable authority");
    assert!(matches!(
        refusal,
        fss_reference::ingest::rtsp_import::replay::RetainedReplayTimeError::Custody(
            FileIngestError::EvidenceDeleted { .. }
        )
    ));
    assert_eq!(filesystem(&root)?, deleted);
    Ok(())
}
