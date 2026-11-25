#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "fss-forward-requests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}

fn receipt() -> ForwardBatchReceipt {
    ForwardBatchReceipt {
        commit_sequence: 17,
        history_root: digest("history-root"),
        state_root: digest("state-root"),
        replayed: false,
    }
}

fn assert_refused<T: std::fmt::Debug>(result: Result<T, DaemonError>, expected: &str) {
    match result.expect_err("operation must fail closed") {
        DaemonError::Ipc(IpcError::Refused { error_id, .. }) => {
            assert_eq!(error_id.as_str(), expected);
        }
        err => panic!("expected {expected}, received {err}"),
    }
}

#[test]
fn completed_receipt_replays_exactly_after_reopen() -> TestResult {
    let dir = TempDir::new()?;
    let key = digest("key");
    let request = digest("request");
    let store = ForwardRequestStore::open(&dir.0)?;
    assert_eq!(store.reserve(key, request)?, None);
    store.complete(key, request, receipt())?;
    drop(store);

    let reopened = ForwardRequestStore::open(&dir.0)?;
    let replay = reopened.reserve(key, request)?.expect("retained receipt");
    assert_eq!(
        replay,
        ForwardBatchReceipt {
            replayed: true,
            ..receipt()
        }
    );
    assert_refused(reopened.reserve(key, digest("different request")), CONFLICT);
    Ok(())
}

#[test]
fn pending_request_survives_reopen_without_permission_to_redispatch() -> TestResult {
    let dir = TempDir::new()?;
    let key = digest("pending");
    let request = digest("request");
    let store = ForwardRequestStore::open(&dir.0)?;
    assert_eq!(store.reserve(key, request)?, None);
    let (path, _) = store.paths(key)?;
    let before = fs::read(&path)?;
    drop(store);

    let reopened = ForwardRequestStore::open(&dir.0)?;
    assert_refused(reopened.reserve(key, request), RECONCILE);
    assert_refused(reopened.reserve(key, digest("changed")), CONFLICT);
    assert_eq!(fs::read(path)?, before);
    Ok(())
}

#[test]
fn concurrent_reservation_has_exactly_one_dispatch_owner() -> TestResult {
    let dir = TempDir::new()?;
    let store = Arc::new(ForwardRequestStore::open(&dir.0)?);
    let key = digest("concurrent");
    let request = digest("request");
    let claimed = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            handles.push(scope.spawn(move || store.reserve(key, request)));
        }
        handles
            .into_iter()
            .map(|handle| {
                let result = handle.join().expect("reservation worker panicked");
                usize::from(matches!(result, Ok(None)))
            })
            .sum::<usize>()
    });
    assert_eq!(claimed, 1);
    assert_refused(store.reserve(key, request), RECONCILE);
    Ok(())
}

#[test]
fn all_incomplete_record_prefixes_are_refused_and_preserved() -> TestResult {
    let dir = TempDir::new()?;
    let store = ForwardRequestStore::open(&dir.0)?;
    let key = digest("truncated");
    let request = digest("request");
    let record = Record {
        key,
        request,
        receipt: None,
    }
    .encode()?;
    let (path, _) = store.paths(key)?;
    for len in 0..record.len() {
        if path.exists() {
            fs::remove_file(&path)?;
        }
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path)?.write_all(&record[..len])?;
        assert_refused(store.reserve(key, request), RECONCILE);
        assert_eq!(fs::read(&path)?, &record[..len]);
    }
    Ok(())
}

#[test]
fn corrupt_or_oversized_completions_never_replay() -> TestResult {
    let dir = TempDir::new()?;
    let store = ForwardRequestStore::open(&dir.0)?;
    let key = digest("corrupt");
    let request = digest("request");
    assert_eq!(store.reserve(key, request)?, None);
    store.complete(key, request, receipt())?;
    let (_, completed) = store.paths(key)?;
    let mut bytes = fs::read(&completed)?;
    bytes[20] ^= 0x80;
    fs::write(&completed, &bytes)?;
    assert_refused(store.reserve(key, request), RECONCILE);
    assert_eq!(fs::read(&completed)?, bytes);

    OpenOptions::new()
        .write(true)
        .open(&completed)?
        .set_len(MAX_RECORD_BYTES + 1)?;
    assert_refused(store.reserve(key, request), RECONCILE);
    assert_eq!(fs::metadata(completed)?.len(), MAX_RECORD_BYTES + 1);
    Ok(())
}

#[test]
fn missing_or_mismatched_reservation_cannot_acquire_a_completion() -> TestResult {
    let dir = TempDir::new()?;
    let store = ForwardRequestStore::open(&dir.0)?;
    let key = digest("key");
    let request = digest("request");
    assert_refused(store.complete(key, request, receipt()), RECONCILE);
    assert_eq!(store.reserve(key, request)?, None);
    assert_refused(store.complete(key, digest("other"), receipt()), CONFLICT);
    assert_refused(store.reserve(key, request), RECONCILE);

    let (pending, completed) = store.paths(key)?;
    fs::remove_file(pending)?;
    write_new_record(
        &completed,
        &Record {
            key,
            request,
            receipt: Some(receipt()),
        },
    )?;
    assert_refused(store.reserve(key, request), RECONCILE);
    Ok(())
}

#[test]
fn lifecycle_and_trailing_bytes_are_checked_even_with_a_valid_checksum() -> TestResult {
    let key = digest("key");
    let request = digest("request");
    let record = Record {
        key,
        request,
        receipt: Some(receipt()),
    };
    let mut bytes = record.encode()?;
    bytes.truncate(bytes.len() - 32);
    bytes.push(0);
    let checksum = ContentDigest::sha256(&bytes);
    bytes.extend_from_slice(&checksum.bytes());
    assert_refused(Record::decode(&bytes), RECONCILE);

    let dir = TempDir::new()?;
    let store = ForwardRequestStore::open(&dir.0)?;
    let (pending, _) = store.paths(key)?;
    write_new_record(&pending, &record)?;
    assert_refused(store.reserve(key, request), RECONCILE);
    Ok(())
}

#[test]
fn older_receipts_survive_more_than_the_hot_cache_capacity() -> TestResult {
    let dir = TempDir::new()?;
    let store = ForwardRequestStore::open(&dir.0)?;
    for index in 0..1025 {
        let key = digest(&format!("key-{index}"));
        let request = digest(&format!("request-{index}"));
        assert_eq!(store.reserve(key, request)?, None);
        store.complete(key, request, receipt())?;
    }
    drop(store);
    let reopened = ForwardRequestStore::open(&dir.0)?;
    assert_eq!(
        reopened.reserve(digest("key-0"), digest("request-0"))?,
        Some(ForwardBatchReceipt {
            replayed: true,
            ..receipt()
        })
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn request_paths_reject_symlinks_and_public_permissions() -> TestResult {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let dir = TempDir::new()?;
    let outside = dir.0.join("outside");
    fs::create_dir(&outside)?;
    let request_dir = dir.0.join("forwarded-requests");
    symlink(&outside, &request_dir)?;
    assert!(ForwardRequestStore::open(&dir.0).is_err());
    fs::remove_file(&request_dir)?;
    fs::create_dir(&request_dir)?;
    fs::set_permissions(&request_dir, fs::Permissions::from_mode(0o755))?;
    assert!(ForwardRequestStore::open(&dir.0).is_err());
    fs::set_permissions(&request_dir, fs::Permissions::from_mode(0o700))?;
    let store = ForwardRequestStore::open(&dir.0)?;
    let key = digest("private");
    let request = digest("request");
    assert_eq!(store.reserve(key, request)?, None);
    let (pending, _) = store.paths(key)?;
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o644))?;
    assert_refused(store.reserve(key, request), RECONCILE);
    Ok(())
}
