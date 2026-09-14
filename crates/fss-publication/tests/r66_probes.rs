#![forbid(unsafe_code)]
//! Contract probes for fss-2h5zq.66 non-mutating inspection.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::ContentDigest;
use fss_object::{
    HostSpoolIo, ObjectManifest, RecordingSpoolIo, SPOOL_HOLDS_DIR, SPOOL_STAGING_DIR, SpoolIo,
    SpoolIoCall, SpoolLimits, SpoolObjectState,
};
use fss_publication::{
    LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LocalPublicationLimits, LocalRootPublisher, LockTableSource,
    MAX_LOCK_TABLE_BYTES, ROOT_INDETERMINATE_SUFFIX, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX,
    SlotName, StringLockTableSource, UnknownLockReason, WriterDetectionOptions, WriterState,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_root(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("r66_probes")
        .join(name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64))
}

fn slot(name: &str) -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(name)?)
}

fn root_file(root: &Path, s: &str) -> PathBuf {
    root.join(LOCAL_ROOTS_DIR)
        .join(format!("{s}{ROOT_RECORD_SUFFIX}"))
}

fn root_temp(root: &Path, s: &str) -> PathBuf {
    root.join(LOCAL_ROOTS_DIR)
        .join(format!("{s}{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}"))
}

fn hex_of(d: ContentDigest) -> String {
    let s = d.to_string();
    s.rsplit(':').next().unwrap_or_default().to_string()
}

fn flip_last_byte(path: &Path) -> TestResult {
    let mut bytes = fs::read(path)?;
    let last = bytes.last_mut().ok_or("empty")?;
    *last ^= 0x01;
    fs::write(path, bytes)?;
    Ok(())
}

/// Digest over relative path, kind, mode, size, mtime, ctime, ino, nlink, content, listing.
fn tree_digest(root: &Path) -> Result<BTreeMap<PathBuf, String>, Box<dyn Error>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        let rel = path.strip_prefix(root)?.to_path_buf();
        let ft = meta.file_type();
        let common = format!(
            "mode={:o} size={} mtime={}.{} ctime={}.{} ino={} nlink={}",
            meta.mode(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
            meta.ino(),
            meta.nlink()
        );
        let detail = if ft.is_symlink() {
            format!("link -> {}", fs::read_link(&path)?.display())
        } else if ft.is_dir() {
            let mut names = Vec::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                names.push(entry.file_name().to_string_lossy().into_owned());
                pending.push(entry.path());
            }
            names.sort();
            format!("dir [{}]", names.join(","))
        } else {
            format!("file {}", ContentDigest::sha256(&fs::read(&path)?))
        };
        out.insert(rel, format!("{common} {detail}"));
    }
    Ok(out)
}

fn assert_same_tree(label: &str, before: &BTreeMap<PathBuf, String>, root: &Path) -> TestResult {
    let after = tree_digest(root)?;
    if &after != before {
        for (k, v) in before {
            if after.get(k) != Some(v) {
                eprintln!(
                    "R66 DIFF {label} {}: {v} => {:?}",
                    k.display(),
                    after.get(k)
                );
            }
        }
        for k in after.keys() {
            if !before.contains_key(k) {
                eprintln!("R66 DIFF {label} NEW {}", k.display());
            }
        }
        return Err(format!("tree changed by {label}").into());
    }
    eprintln!("R66 TREE-IDENTICAL {label} entries={}", after.len());
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> TestResult {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let dest = to.join(entry.file_name());
        if ft.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(entry.path())?, &dest)?;
        } else if ft.is_dir() {
            copy_tree(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

struct Fixture {
    a: ContentDigest,
    victim_child: ContentDigest,
    victim_root: ContentDigest,
    limbo_root: ContentDigest,
}

fn build_fixture(root: &Path) -> Result<Fixture, Box<dyn Error>> {
    let mut p = LocalRootPublisher::open(root, limits())?;
    let a = p.stage_object(b"clip-a")?;
    let b = p.stage_object(b"clip-b")?;
    p.verify_object(a)?;
    p.verify_object(b)?;
    let m = ObjectManifest::new("event_archive", [a, b], None)?;
    p.publish(&slot("good")?, &m)?;
    let c = p.stage_object(b"clip-victim")?;
    p.verify_object(c)?;
    let mv = ObjectManifest::new("event_archive", [c], None)?;
    p.publish(&slot("victim")?, &mv)?;
    let d = p.stage_object(b"clip-limbo")?;
    p.verify_object(d)?;
    let ml = ObjectManifest::new("event_archive", [d], None)?;
    p.publish(&slot("limbo")?, &ml)?;
    let u = p.stage_object(b"unreferenced")?;
    let victim_path = p.spool().object_path(c);
    drop(p);

    flip_last_byte(&victim_path)?;
    fs::copy(root_file(root, "good"), root_temp(root, "good"))?; // redundant temp
    fs::write(root_temp(root, "ghost"), b"partial")?; // orphan temp
    fs::write(
        root.join(LOCAL_ROOTS_DIR).join(format!(
            "limbo{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"
        )),
        b"",
    )?;
    fs::write(root_file(root, "bad"), b"not a root record")?; // broken root
    std::os::unix::fs::symlink("/etc/hostname", root_file(root, "sym"))?; // symlink record
    fs::write(root.join("junk.txt"), b"x")?; // foreign top-level
    let spool = root.join(LOCAL_SPOOL_DIR);
    fs::write(
        spool
            .join(SPOOL_STAGING_DIR)
            .join(format!("{}.0.tmp", hex_of(u))),
        b"orphan",
    )?; // orphaned staging
    std::os::unix::fs::symlink(
        "/etc/hostname",
        spool
            .join("objects")
            .join(hex_of(ContentDigest::sha256(b"symlinked"))),
    )?; // symlink object
    fs::remove_dir_all(spool.join(SPOOL_HOLDS_DIR))?; // legacy spool
    Ok(Fixture {
        a,
        victim_child: c,
        victim_root: mv.root(),
        limbo_root: ml.root(),
    })
}

#[test]
fn r66_c_fixture_non_mutation_differential_and_a_promotion() -> TestResult {
    let a_root = fresh_root("fixture_a")?;
    let b_root = fresh_root("fixture_b")?;
    let fx = build_fixture(&a_root)?;
    copy_tree(&a_root, &b_root)?;
    let before = tree_digest(&a_root)?;

    let sp = fss_object::inspect(a_root.join(LOCAL_SPOOL_DIR), &limits().spool)?;
    eprintln!(
        "R66 SPOOL holds_migration_pending={} missing_layout={} admitted={} corrupt={:?} orphaned={} foreign={:?}",
        sp.holds_migration_pending,
        sp.missing_layout,
        sp.report.admitted.len(),
        sp.report.corrupt,
        sp.report.orphaned_staging.len(),
        sp.report.foreign
    );
    assert_same_tree("spool::inspect", &before, &a_root)?;

    let rec = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let io: Arc<dyn SpoolIo> = rec.clone();
    let li = fss_publication::inspect_with_options(
        io,
        &a_root,
        limits(),
        None,
        WriterDetectionOptions::default(),
    )?;
    eprintln!(
        "R66 DEFAULT-INSPECT calls={} mutating={:?} trylockshared={}",
        rec.calls().len(),
        rec.mutating_calls(),
        rec.call_count(SpoolIoCall::TryLockShared)
    );
    assert!(rec.is_read_only());
    assert_same_tree("local::inspect_with_options(default)", &before, &a_root)?;

    let li_plain = fss_publication::inspect(&a_root, limits())?;
    assert_eq!(li_plain.report, li.report);
    assert_same_tree("local::inspect", &before, &a_root)?;

    let rec2 = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let io2: Arc<dyn SpoolIo> = rec2.clone();
    let li_probe = fss_publication::inspect_with_options(
        io2,
        &a_root,
        limits(),
        None,
        WriterDetectionOptions {
            probe_shared_lock: true,
            self_holds_lock: false,
        },
    )?;
    eprintln!(
        "R66 PROBE-INSPECT writer={:?} mutating={:?}",
        li_probe.writer_state,
        rec2.mutating_calls()
    );
    assert_same_tree("local::inspect(probe)", &before, &a_root)?;

    let good = fss_publication::read_verified(&a_root, fx.a, 1 << 20)?;
    assert_eq!(good, b"clip-a");
    let bad = fss_publication::read_verified(&a_root, fx.victim_child, 1 << 20);
    eprintln!("R66 READ_VERIFIED corrupt -> {bad:?}");
    assert!(bad.is_err());
    assert_same_tree("read_verified", &before, &a_root)?;

    eprintln!(
        "R66 INSPECT redundant_temps={:?} durability_not_resynced={} holds_migration_pending={} writer={:?} broken={:?} is_clean={}",
        li.redundant_temps,
        li.durability_not_resynced,
        li.holds_migration_pending,
        li.writer_state,
        li.broken_slots,
        li.is_clean()
    );

    // Differential against the mutating open on a copy of the same root.
    let mut pb = LocalRootPublisher::open(&b_root, limits())?;
    let open_report = pb.recovery_report().clone();
    if open_report != li.report {
        eprintln!(
            "R66 DIFFERENTIAL MISMATCH\n inspect={:#?}\n open={:#?}",
            li.report, open_report
        );
    } else {
        eprintln!(
            "R66 DIFFERENTIAL EQUAL broken_roots={} foreign={} orphaned_temps={:?} unreferenced={} spool_corrupt={}",
            open_report.broken_roots.len(),
            open_report.foreign.len(),
            open_report.orphaned_temps,
            open_report.unreferenced_objects.len(),
            open_report.spool.corrupt.len()
        );
    }
    for br in &open_report.broken_roots {
        eprintln!("R66 BROKEN {} {:?}", br.path.display(), br.reason);
    }
    assert_eq!(open_report, li.report);

    // A: Verified promotion must not launder the corrupt object.
    let st_c = pb.spool().state(fx.victim_child);
    let st_a = pb.spool().state(fx.a);
    let st_vr = pb.spool().state(fx.victim_root);
    let st_lr = pb.spool().state(fx.limbo_root);
    eprintln!(
        "R66 A-STATES corrupt_child={st_c:?} good_child={st_a:?} victim_manifest_body={st_vr:?} limbo_manifest_body={st_lr:?}"
    );
    assert_ne!(st_c, Some(SpoolObjectState::Verified));
    assert_eq!(st_a, Some(SpoolObjectState::Verified));
    let rd = pb.spool().read(fx.victim_child);
    eprintln!("R66 A-READ corrupt -> {rd:?}");
    assert!(rd.is_err());
    let retry = ObjectManifest::new("event_archive", [fx.victim_child], None)?;
    let pub_res = pb.publish(&slot("retry")?, &retry);
    eprintln!("R66 A-PUBLISH corrupt -> {pub_res:?}");
    assert!(pub_res.is_err());
    let ver = pb.verify_object(fx.victim_child);
    eprintln!("R66 A-VERIFY corrupt -> {ver:?}");
    assert!(ver.is_err());
    Ok(())
}

#[derive(Debug)]
struct FailingTable(io::ErrorKind);

impl LockTableSource for FailingTable {
    fn read_lock_table(&self, _max_bytes: usize) -> io::Result<String> {
        Err(io::Error::from(self.0))
    }
}

fn probe(
    root: &Path,
    table: Option<&dyn LockTableSource>,
    probe: bool,
    self_holds: bool,
) -> Result<(WriterState, Vec<SpoolIoCall>), Box<dyn Error>> {
    let rec = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let io: Arc<dyn SpoolIo> = rec.clone();
    let li = fss_publication::inspect_with_options(
        io,
        root,
        limits(),
        table,
        WriterDetectionOptions {
            probe_shared_lock: probe,
            self_holds_lock: self_holds,
        },
    )?;
    Ok((li.writer_state, rec.mutating_calls()))
}

#[test]
fn r66_b_writer_detection_with_lock_held() -> TestResult {
    let root = fresh_root("writer")?;
    let mut p = LocalRootPublisher::open(&root, limits())?;
    let a = p.stage_object(b"clip-w")?;
    p.verify_object(a)?;
    let m = ObjectManifest::new("event_archive", [a], None)?;
    p.publish(&slot("w")?, &m)?;
    let before = tree_digest(&root)?;
    let pid = std::process::id();

    let default = fss_publication::inspect(&root, limits())?;
    eprintln!(
        "R66 HELD default(proc_locks) -> {:?} (pid {pid}) roots={}",
        default.writer_state,
        default.report.roots.len()
    );
    let (s, calls) = probe(&root, None, false, false)?;
    eprintln!("R66 HELD default-recorded -> {s:?} mutating={calls:?}");
    assert!(calls.is_empty());
    assert!(s.is_held());

    let (s, calls) = probe(&root, None, true, false)?;
    eprintln!("R66 HELD probe -> {s:?} mutating={calls:?}");
    assert!(calls.is_empty());
    assert!(s.is_held());

    let (s, _) = probe(&root, None, true, true)?;
    eprintln!("R66 HELD probe+self_holds -> {s:?}");
    assert_eq!(s, WriterState::NotProbed);

    let (s, _) = probe(&root, None, false, true)?;
    eprintln!("R66 HELD proc_locks+self_holds -> {s:?}");
    assert!(s.is_held());

    let (s, _) = probe(
        &root,
        Some(&FailingTable(io::ErrorKind::NotFound)),
        false,
        false,
    )?;
    eprintln!("R66 HELD table NotFound -> {s:?}");
    assert_eq!(
        s,
        WriterState::Unknown {
            reason: UnknownLockReason::NoLockTable
        }
    );

    let (s, _) = probe(
        &root,
        Some(&FailingTable(io::ErrorKind::PermissionDenied)),
        false,
        false,
    )?;
    eprintln!("R66 HELD table PermissionDenied -> {s:?}");
    assert_eq!(
        s,
        WriterState::Unknown {
            reason: UnknownLockReason::Unreadable
        }
    );

    let big = StringLockTableSource("x".repeat(MAX_LOCK_TABLE_BYTES + 1));
    let (s, _) = probe(&root, Some(&big), false, false)?;
    eprintln!("R66 HELD table over budget -> {s:?}");
    assert_eq!(
        s,
        WriterState::Unknown {
            reason: UnknownLockReason::OverBudget
        }
    );

    let garbage = StringLockTableSource("garbage line\n1: FLOCK\n".to_string());
    let (s, _) = probe(&root, Some(&garbage), false, false)?;
    eprintln!("R66 HELD table garbage -> {s:?}");
    assert_eq!(
        s,
        WriterState::Unknown {
            reason: UnknownLockReason::ParseError
        }
    );

    assert_same_tree("writer probes (lock held)", &before, &root)?;
    assert!(default.writer_state.is_held());
    assert!(default.possibly_stale);
    assert!(default.possibly_in_flight);
    drop(p);

    let (s, _) = probe(&root, None, false, false)?;
    eprintln!("R66 FREE default -> {s:?}");
    assert_eq!(s, WriterState::not_observed());

    let (s, _) = probe(&root, None, true, false)?;
    eprintln!("R66 FREE probe -> {s:?}");
    assert_eq!(s, WriterState::not_held());

    fs::remove_file(root.join("LOCK"))?;
    let (s, calls) = probe(&root, None, true, false)?;
    eprintln!(
        "R66 NOLOCKFILE probe -> {s:?} mutating={calls:?} lock_recreated={}",
        root.join("LOCK").exists()
    );
    assert_eq!(s, WriterState::no_lock_file());
    assert!(calls.is_empty());
    assert!(!root.join("LOCK").exists());
    Ok(())
}

#[test]
fn r66_d_bounds_and_absent() -> TestResult {
    let root = fresh_root("bounds")?;
    let fx = build_fixture(&root)?;
    let tight = LocalPublicationLimits::new(8, 16, 8, 2, SpoolLimits::new(64, 1 << 20, 4096, 64));
    let r = fss_publication::inspect(&root, tight);
    eprintln!("R66 D scan limit 2 -> {:?}", r.as_ref().err());
    assert!(r.is_err());
    let r = fss_publication::read_verified(&root, fx.a, 2);
    eprintln!("R66 D read_verified max 2 -> {r:?}");
    assert!(r.is_err());

    let absent = fresh_root("absent")?;
    let r = fss_publication::inspect(&absent, limits());
    eprintln!(
        "R66 D absent root -> ok={} created={}",
        r.is_ok(),
        absent.exists()
    );
    assert!(r.is_ok());
    assert!(!absent.exists());

    let jdir = fresh_root("journal")?;
    fs::create_dir_all(&jdir)?;
    let big = jdir.join("huge.fssj");
    let f = File::create(&big)?;
    f.set_len(256 << 20)?;
    drop(f);
    let r = fss_ledger::inspect_durable(&big, "site", 1 << 20);
    eprintln!(
        "R66 D inspect_durable sparse 256MiB limit 1MiB -> {:?}",
        r.as_ref().err()
    );
    assert!(matches!(
        r,
        Err(fss_ledger::DurableLedgerError::OverBudget { .. })
    ));
    let link = jdir.join("link.fssj");
    std::os::unix::fs::symlink(&big, &link)?;
    let r = fss_ledger::inspect_durable(&link, "site", 1 << 20);
    eprintln!("R66 D inspect_durable symlink -> {:?}", r.as_ref().err());
    assert!(matches!(
        r,
        Err(fss_ledger::DurableLedgerError::InvalidLayout { .. })
    ));
    let missing = jdir.join("missing.fssj");
    let r = fss_ledger::inspect_durable(&missing, "site", 1 << 20);
    eprintln!(
        "R66 D inspect_durable missing -> ok={} created={}",
        r.is_ok(),
        missing.exists()
    );
    assert!(!missing.exists());
    assert!(matches!(
        r,
        Ok(fss_ledger::LedgerInspection {
            status: fss_ledger::DurableLedgerStatus::Absent,
            ..
        })
    ));
    Ok(())
}

#[test]
fn r66_broken_root_manifest_is_held_after_open() -> TestResult {
    let root = fresh_root("broken_manifest_held")?;
    let mut p = LocalRootPublisher::open(&root, limits())?;
    let a = p.stage_object(b"payload-content")?;
    p.verify_object(a)?;
    let m = ObjectManifest::new("event_archive", [a], None)?;
    let manifest_root = m.root();
    p.publish(&slot("broken_slot")?, &m)?;
    drop(p);

    // Create indeterminate marker for broken_slot
    fs::write(
        root.join(LOCAL_ROOTS_DIR).join(format!(
            "broken_slot{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"
        )),
        b"",
    )?;

    // Reopen publisher: mutating open succeeds and classifies slot as broken
    let mut p2 = LocalRootPublisher::open(&root, limits())?;
    assert!(
        p2.recovery_report()
            .broken_roots
            .iter()
            .any(|br| { br.path.to_string_lossy().contains("broken_slot") })
    );

    // Manifest root must still be verified and held in the spool
    assert_eq!(
        p2.spool().state(manifest_root),
        Some(SpoolObjectState::Verified)
    );
    // Holds refuse discard
    let discard_res = p2.spool_mut().discard_staged(manifest_root);
    assert!(discard_res.is_err());

    Ok(())
}
