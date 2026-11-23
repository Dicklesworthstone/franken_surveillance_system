#![forbid(unsafe_code)]

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_publication::LocalRootPublisher;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Directory(PathBuf);

impl Directory {
    fn new(label: &str) -> Result<Self, io::Error> {
        let path = std::env::temp_dir().join(format!(
            "fss-learning-cancellation-{label}-{}",
            std::process::id(),
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn is_cancelled<T>(result: &Result<T, DeploymentSessionError>) -> bool {
    matches!(
        result,
        Err(DeploymentSessionError::Time(SessionTimeError::Cancelled))
    )
}

#[test]
fn learning_admission_cancels_before_reading_an_absent_deployment() -> TestResult {
    let directory = Directory::new("admission")?;
    let request = InspectLearningRequest {
        session_id: SessionId::parse("session:cancelled-learning")?,
        principal: PrincipalId::parse("principal:cancelled-learning")?,
        publication_root: ContentDigest::sha256(b"unopened private learning"),
        view: AgentView::Forensic,
        budget_tokens: None,
    };
    let observed = std::cell::Cell::new(false);
    let result =
        inspect_learning_cancellable(&directory.0.join("absent"), &request, &|| true, |_, _| {
            observed.set(true);
        });
    assert!(is_cancelled(&result), "{result:?}");
    assert!(
        !observed.get(),
        "cancelled admission must not claim a verified observation"
    );
    assert!(fs::read_dir(&directory.0)?.next().is_none());
    Ok(())
}

#[test]
fn selected_learning_objects_stop_at_native_boundaries_and_discard_completed_bytes() -> TestResult {
    let directory = Directory::new("selected-object")?;
    let root = directory.0.join("publications");
    let moved = directory.0.join("unavailable-publications");
    let bytes = b"PRIVATE SELECTED LEARNING: do not deliver after cancellation";
    let mut publisher =
        LocalRootPublisher::open(&root, crate::deployment_session::publication_limits())?;
    let digest = publisher.stage_object(bytes)?;
    drop(publisher);

    let observations = AtomicUsize::new(0);
    let never = || {
        observations.fetch_add(1, Ordering::AcqRel);
        false
    };
    let mut reader = SelectedReader {
        directory: root.clone(),
        bytes_read: 0,
        files_read: 0,
        cancelled: &never,
    };
    assert_eq!(reader.object(digest, MAX_RECORD_BYTES)?, bytes);
    let checkpoints = observations.load(Ordering::Acquire);
    assert!(checkpoints >= 8);

    for cut in [0, checkpoints / 2, checkpoints - 1] {
        let observations = AtomicUsize::new(0);
        let renamed = AtomicBool::new(false);
        let cancelled = || {
            let observed = observations.fetch_add(1, Ordering::AcqRel);
            if observed == cut && cut == checkpoints - 1 {
                renamed.store(fs::rename(&root, &moved).is_ok(), Ordering::Release);
            }
            observed >= cut
        };
        let mut reader = SelectedReader {
            directory: root.clone(),
            bytes_read: 0,
            files_read: 0,
            cancelled: &cancelled,
        };
        let result = reader.object(digest, MAX_RECORD_BYTES);
        assert!(is_cancelled(&result), "{result:?}");
        // Sticky cancellation must dominate missing storage on every subsequent native entry.
        assert!(is_cancelled(&reader.object(digest, MAX_RECORD_BYTES)));
        assert!(is_cancelled(&reader.not_tombstoned(digest)));
        assert!(is_cancelled(&shared_publication_lock(&root, &cancelled)));
        if cut == checkpoints - 1 {
            assert!(
                renamed.load(Ordering::Acquire),
                "selected publication was not moved"
            );
        }
        if renamed.load(Ordering::Acquire) {
            fs::rename(&moved, &root)?;
        }
        assert_eq!(
            fss_publication::read_verified(&root, digest, MAX_RECORD_BYTES)?,
            bytes
        );
    }
    Ok(())
}
