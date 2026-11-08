#![forbid(unsafe_code)]
//! Namespace discovery shares the exact metadata reader's bounded, read-only final observation.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{HostSpoolIo, ObjectManifest, RecordingSpoolIo, SpoolIoCall, encode_spool_object};
use fss_publication::custody_audit::pinned_metadata::{
    NamespaceRootRecord, PinnedMetadataError, PinnedMetadataReader,
};
use fss_publication::custody_audit::{
    CustodyAuditError, CustodyAuditLimits, MAX_AUDIT_CATALOGUE_ENTRIES,
};
use fss_publication::{SlotName, root_record_bytes};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PREFIX: &str = "selected";

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new(name: &str) -> TestResult<Self> {
        for n in 0..64 {
            let root = std::env::temp_dir().join(format!(
                "fss-pinned-namespace-{name}-{}-{n}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    fs::create_dir(root.join("roots"))?;
                    fs::create_dir(root.join("tombstones"))?;
                    return Ok(Self { root });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary fixture names exhausted".into())
    }
    fn record(
        &self,
        slot: &str,
        root: ContentDigest,
        count: usize,
    ) -> TestResult<NamespaceRootRecord> {
        let slot = SlotName::parse(slot)?;
        let bytes = root_record_bytes(&slot, root, count)?;
        fs::write(self.root.join("roots").join(format!("{slot}.root")), &bytes)?;
        Ok(NamespaceRootRecord {
            slot,
            root,
            child_count: count as u64,
            record_digest: ContentDigest::sha256(&bytes),
        })
    }
    fn put(&self, bytes: &[u8]) -> TestResult {
        let digest = ContentDigest::sha256(bytes);
        let objects = self.root.join("spool/objects");
        fs::create_dir_all(&objects)?;
        fs::write(
            objects.join(digest.to_text().trim_start_matches("sha256:")),
            encode_spool_object(digest, bytes)?,
        )?;
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn limits() -> CustodyAuditLimits {
    CustodyAuditLimits {
        max_catalogue_entries: 8,
        max_objects: 8,
        max_edges: 8,
        max_object_bytes: 1024,
        max_read_bytes: 1024 * 1024,
        max_io_calls: 2048,
    }
}
fn audit(error: CustodyAuditError) -> PinnedMetadataError {
    PinnedMetadataError::Audit(error)
}

#[test]
fn sorted_inventory_ignores_unrelated_contents_and_never_hydrates_missing_objects() -> TestResult {
    let fixture = Fixture::new("inventory")?;
    let z = fixture.record("selected-z", ContentDigest::sha256(b"absent z"), 2)?;
    let a = fixture.record("selected-a", ContentDigest::sha256(b"absent a"), 1)?;
    fs::write(fixture.root.join("roots/unrelated.root"), b"invalid")?;
    fs::write(fixture.root.join("roots/unrelated.root.tmp"), b"pending")?;
    fs::create_dir(fixture.root.join("roots/unrelated-directory"))?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedMetadataReader::new(&io, &fixture.root, limits(), &|| false)?;
    let observation = reader.observe_namespace(PREFIX, 5, 2)?;
    assert_eq!(observation.roots, vec![a, z]);
    assert_eq!(observation.scanned_entries, 5);
    let usage = reader.finish()?;
    assert_eq!(usage.metadata_objects, 0);
    assert_eq!(usage.pinned_roots, 0);
    assert_eq!(usage.reference_checks, 0);
    assert_eq!(usage.io_calls, io.calls().len() as u64);
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 2);
    assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 12);
    assert_eq!(io.call_count(SpoolIoCall::EntryFileType), 4);
    assert_eq!(io.call_count(SpoolIoCall::OpenRead), 4);
    assert_eq!(io.call_count(SpoolIoCall::Read), 4);
    assert!(io.is_read_only());
    assert!(!fixture.root.join("spool").exists());
    assert!(!fixture.root.join("LOCK").exists());
    Ok(())
}

#[test]
fn final_inventory_refuses_added_removed_rebound_and_recounted_selected_records() -> TestResult {
    for scenario in ["added", "removed", "rebound", "recounted"] {
        let fixture = Fixture::new(scenario)?;
        let root = ContentDigest::sha256(b"original");
        fixture.record("selected-a", root, 1)?;
        let mut reader =
            PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &|| false)?;
        reader.observe_namespace(PREFIX, 16, 8)?;
        match scenario {
            "added" => {
                fixture.record("selected-b", ContentDigest::sha256(b"new"), 0)?;
            }
            "removed" => fs::remove_file(fixture.root.join("roots/selected-a.root"))?,
            "rebound" => {
                fixture.record("selected-a", ContentDigest::sha256(b"new"), 1)?;
            }
            _ => {
                fixture.record("selected-a", root, 2)?;
            }
        }
        assert_eq!(
            reader.finish(),
            Err(PinnedMetadataError::Changed),
            "{scenario}"
        );
    }
    Ok(())
}

#[test]
fn unrelated_membership_changes_do_not_invalidate_the_selected_namespace() -> TestResult {
    let fixture = Fixture::new("unrelated-churn")?;
    fixture.record("selected-a", ContentDigest::sha256(b"selected"), 0)?;
    fs::write(fixture.root.join("roots/unrelated-old.root"), b"bad")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedMetadataReader::new(&io, &fixture.root, limits(), &|| false)?;
    assert_eq!(reader.observe_namespace(PREFIX, 16, 8)?.scanned_entries, 2);
    fs::remove_file(fixture.root.join("roots/unrelated-old.root"))?;
    fs::write(
        fixture.root.join("roots/unrelated-new.root.indeterminate"),
        b"bad",
    )?;
    fs::create_dir(fixture.root.join("roots/unrelated-new-directory"))?;
    reader.finish()?;
    assert_eq!(io.call_count(SpoolIoCall::EntryFileType), 2);
    assert_eq!(io.call_count(SpoolIoCall::OpenRead), 2);
    Ok(())
}

#[test]
fn selected_pending_malformed_and_noncanonical_records_refuse_on_both_passes() -> TestResult {
    for final_pass in [false, true] {
        for scenario in [
            "tmp",
            "indeterminate",
            "suffix",
            "slot",
            "body",
            "trailing",
            "binding",
            "directory",
        ] {
            let fixture = Fixture::new(scenario)?;
            let mut reader =
                PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &|| false)?;
            if final_pass {
                reader.observe_namespace(PREFIX, 16, 8)?;
            }
            let ordinary = fixture.root.join("roots/selected-a.root");
            match scenario {
                "tmp" | "indeterminate" => fs::write(
                    fixture
                        .root
                        .join(format!("roots/selected-a.root.{scenario}")),
                    b"pending",
                )?,
                "suffix" => fs::write(fixture.root.join("roots/selected-a.foreign"), b"bad")?,
                "slot" => fs::write(fixture.root.join("roots/selected-A.root"), b"bad")?,
                "body" => fs::write(&ordinary, b"malformed")?,
                "trailing" => {
                    let mut bytes = root_record_bytes(
                        &SlotName::parse("selected-a")?,
                        ContentDigest::sha256(b"root"),
                        0,
                    )?;
                    bytes.push(0);
                    fs::write(&ordinary, bytes)?;
                }
                "binding" => fs::write(
                    &ordinary,
                    root_record_bytes(
                        &SlotName::parse("selected-b")?,
                        ContentDigest::sha256(b"root"),
                        0,
                    )?,
                )?,
                _ => fs::create_dir(&ordinary)?,
            }
            let result = if final_pass {
                reader.finish().map(|_| ())
            } else {
                reader.observe_namespace(PREFIX, 16, 8).map(|_| ())
            };
            let expected = if matches!(scenario, "tmp" | "indeterminate") {
                CustodyAuditError::PublicationInFlight
            } else {
                CustodyAuditError::CatalogueInvalid
            };
            assert_eq!(
                result,
                Err(audit(expected)),
                "{scenario}, final={final_pass}"
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn selected_symlinks_and_non_utf8_names_refuse_while_unrelated_ones_are_ignored() -> TestResult {
    use std::os::unix::ffi::OsStringExt;
    for final_pass in [false, true] {
        for selected in [false, true] {
            for symlink in [false, true] {
                let fixture = Fixture::new("foreign-entry")?;
                let mut reader =
                    PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &|| false)?;
                if final_pass {
                    reader.observe_namespace(PREFIX, 16, 8)?;
                }
                let stem = if selected {
                    "selected-a"
                } else {
                    "unrelated-a"
                };
                if symlink {
                    let target = fixture.root.join("outside-roots");
                    fs::write(
                        &target,
                        root_record_bytes(
                            &SlotName::parse(stem)?,
                            ContentDigest::sha256(b"root"),
                            0,
                        )?,
                    )?;
                    std::os::unix::fs::symlink(
                        &target,
                        fixture.root.join("roots").join(format!("{stem}.root")),
                    )?;
                } else {
                    let mut name = stem.as_bytes().to_vec();
                    name.extend_from_slice(b"\xff.root");
                    fs::write(
                        fixture
                            .root
                            .join("roots")
                            .join(std::ffi::OsString::from_vec(name)),
                        b"bad",
                    )?;
                }
                let result = if final_pass {
                    reader.finish().map(|_| ())
                } else {
                    reader
                        .observe_namespace(PREFIX, 16, 8)
                        .and_then(|_| reader.finish())
                        .map(|_| ())
                };
                if selected {
                    assert_eq!(result, Err(audit(CustodyAuditError::CatalogueInvalid)));
                } else {
                    result?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn all_entries_consume_scan_allowance_and_selected_records_have_an_independent_ceiling()
-> TestResult {
    let fixture = Fixture::new("scan-limits")?;
    fixture.record("selected-a", ContentDigest::sha256(b"a"), 0)?;
    fixture.record("selected-b", ContentDigest::sha256(b"b"), 0)?;
    for n in 0..3 {
        fs::write(fixture.root.join(format!("roots/foreign-{n}")), b"ignored")?;
    }
    for (scan, roots, dimension) in [
        (4, 2, "namespace_scan_entries"),
        (5, 1, "namespace_roots"),
        (0, 2, "namespace_scan_entries"),
    ] {
        let mut reader =
            PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &|| false)?;
        assert_eq!(
            reader.observe_namespace(PREFIX, scan, roots),
            Err(audit(CustodyAuditError::Limit(dimension)))
        );
        assert_eq!(
            reader.finish(),
            Err(audit(CustodyAuditError::Limit(dimension)))
        );
    }
    let mut reader = PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &|| false)?;
    assert!(reader.observe_namespace("absent", 5, 0)?.roots.is_empty());
    reader.finish()?;
    Ok(())
}

#[test]
fn invalid_preflight_does_no_io_and_started_observations_cannot_be_replaced() -> TestResult {
    let fixture = Fixture::new("single-observation")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedMetadataReader::new(&io, &fixture.root, limits(), &|| false)?;
    let before = io.calls().len();
    for (prefix, scan, roots) in [
        ("", 1, 1),
        ("../selected", 1, 1),
        ("selected*", 1, 1),
        (PREFIX, MAX_AUDIT_CATALOGUE_ENTRIES + 1, 1),
        (PREFIX, 1, MAX_AUDIT_CATALOGUE_ENTRIES + 1),
    ] {
        assert_eq!(
            reader.observe_namespace(prefix, scan, roots),
            Err(audit(CustodyAuditError::InvalidRequest))
        );
        assert_eq!(io.calls().len(), before);
    }
    reader.observe_namespace(PREFIX, 0, 0)?;
    let after = io.calls().len();
    assert_eq!(
        reader.observe_namespace("other", 16, 8),
        Err(audit(CustodyAuditError::InvalidRequest))
    );
    assert_eq!(io.calls().len(), after);
    reader.finish()?;

    fs::write(fixture.root.join("roots/selected-a.root"), b"bad")?;
    let mut reader = PinnedMetadataReader::new(&io, &fixture.root, limits(), &|| false)?;
    assert_eq!(
        reader.observe_namespace(PREFIX, 16, 8),
        Err(audit(CustodyAuditError::CatalogueInvalid))
    );
    fs::remove_file(fixture.root.join("roots/selected-a.root"))?;
    let after = io.calls().len();
    assert_eq!(
        reader.observe_namespace(PREFIX, 16, 8),
        Err(audit(CustodyAuditError::InvalidRequest))
    );
    assert_eq!(
        reader.finish(),
        Err(audit(CustodyAuditError::CatalogueInvalid))
    );
    assert_eq!(io.calls().len(), after);
    Ok(())
}

#[test]
fn inventory_and_pinned_metadata_share_one_allowance_through_both_final_passes() -> TestResult {
    let fixture = Fixture::new("shared-allowance")?;
    let metadata = b"typed metadata";
    let manifest = ObjectManifest::new(
        "namespace-metadata-test",
        [ContentDigest::sha256(b"absent source")],
        Some(ContentDigest::sha256(metadata)),
    )?;
    fixture.put(&manifest.canonical_bytes())?;
    fixture.put(metadata)?;
    let record = fixture.record("selected-a", manifest.root(), manifest.children().len())?;
    let observe = |allowance| {
        let mut reader =
            PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, allowance, &|| false)?;
        reader.observe_namespace(PREFIX, 1, 1)?;
        let pinned = reader.manifest(&record.slot, record.root)?;
        assert_eq!(reader.metadata(&pinned)?, metadata);
        reader.finish()
    };
    let usage = observe(limits())?;
    assert_eq!(usage.metadata_objects, 2);
    assert_eq!(usage.pinned_roots, 1);
    let exact = CustodyAuditLimits {
        max_read_bytes: usage.peak_reserved_read_bytes,
        max_io_calls: usage.io_calls,
        ..limits()
    };
    assert_eq!(observe(exact)?, usage);
    for (allowance, dimension) in [
        (
            CustodyAuditLimits {
                max_io_calls: exact.max_io_calls - 1,
                ..exact
            },
            "io_calls",
        ),
        (
            CustodyAuditLimits {
                max_read_bytes: exact.max_read_bytes - 1,
                ..exact
            },
            "read_bytes",
        ),
    ] {
        assert_eq!(
            observe(allowance),
            Err(audit(CustodyAuditError::Limit(dimension)))
        );
    }
    Ok(())
}

#[test]
fn cancellation_during_inventory_and_final_rescan_returns_no_complete_observation() -> TestResult {
    let fixture = Fixture::new("cancel")?;
    fixture.record("selected-a", ContentDigest::sha256(b"root"), 0)?;
    let calls = AtomicUsize::new(0);
    let count = || {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    let mut reader = PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &count)?;
    reader.observe_namespace(PREFIX, 1, 1)?;
    reader.finish()?;
    let total = calls.load(Ordering::SeqCst);
    for cancel_at in [0, 1, total / 4, total / 2, total - 1] {
        calls.store(0, Ordering::SeqCst);
        let cancelled = || calls.fetch_add(1, Ordering::SeqCst) >= cancel_at;
        let result = (|| {
            let mut reader =
                PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &cancelled)?;
            reader.observe_namespace(PREFIX, 1, 1)?;
            reader.finish()
        })();
        assert_eq!(result, Err(audit(CustodyAuditError::Cancelled)));
    }
    Ok(())
}
