#![forbid(unsafe_code)]

use super::*;
use crate::agent_orient::OrientLimits;
use crate::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};
use std::sync::atomic::{AtomicBool, Ordering};

fn limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 64 * 1024 * 1024,
        max_read_objects: 20_000,
    }
}

pub(super) struct Fixture {
    pub(super) cx: ReplayCx,
    pub(super) deployment: ReferenceDeployment,
    pub(super) request: RecordedDecodeRequest,
    pub(super) run: RecordedInference,
    _dir: Directory,
}
impl Fixture {
    pub(super) fn new(name: &str) -> TestResult<Self> {
        let (dir, cx, mut deployment, request, frame) = fixture(name)?;
        let run = RecordedInference::run_and_publish(
            &mut deployment,
            &request,
            &model(&frame, 0.25, true)?,
            budget(),
            &ScalarExecCx::new(),
            &cx,
        )?;
        Ok(Self {
            cx,
            deployment,
            request,
            run,
            _dir: dir,
        })
    }
}

// Include empty directories as well as all file bytes, so an immutable read cannot silently
// create staging, lock, journal, recovery or cache entries and still pass this comparison.
pub(super) fn snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    fn visit(
        root: &Path,
        path: &Path,
        entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>,
    ) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let name = path.strip_prefix(root)?.to_path_buf();
            if entry.file_type()?.is_dir() {
                entries.insert(name, None);
                visit(root, &path, entries)?;
            } else {
                entries.insert(name, Some(fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries)?;
    Ok(entries)
}

#[test]
fn live_writer_allows_immutable_inference_and_frame_replay_without_mutation() -> TestResult {
    let f = Fixture::new("immutable-live-writer")?;
    let before = snapshot(f.deployment.root())?;
    let source = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
    let restored = RecordedInference::open(&source, f.run.identity(), &f.request, &f.cx)?;
    assert_eq!(restored.receipt_bytes()?, f.run.receipt_bytes()?);
    assert_eq!(restored.output_bytes(), f.run.output_bytes());
    assert_eq!(restored.outputs(), f.run.outputs());
    assert_eq!(restored.authority_anchor(), f.run.authority_anchor());
    restored.verify_by_replay(&source, &f.request, budget(), &ScalarExecCx::new(), &f.cx)?;
    let frame = RecordedFrame::open(&source, &f.request, &f.cx)?;
    frame.verify_by_replay(
        &source,
        &f.request,
        &mut DecodeBudget::new(100_000_000),
        &f.cx,
    )?;
    source.revalidate()?;
    assert!(source.usage().read_bytes > 0);
    assert_eq!(snapshot(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn final_revalidation_shares_the_exact_original_byte_and_object_allowance() -> TestResult {
    let f = Fixture::new("immutable-budget")?;
    let before = snapshot(f.deployment.root())?;
    let measured = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
    RecordedInference::open(&measured, f.run.identity(), &f.request, &f.cx)?;
    measured.revalidate()?;
    let used = measured.usage();
    let exact = ImmutableRetainedReadLimits {
        // The native budget conservatively requires a remaining byte to probe the final
        // empty effects journal, even though that probe returns no payload bytes.
        max_read_bytes: usize::try_from(used.read_bytes)? + 1,
        max_read_objects: usize::try_from(used.read_objects)?,
        ..limits()
    };
    let admitted = ImmutableRetainedSource::open(f.deployment.root(), exact, &f.cx)?;
    RecordedInference::open(&admitted, f.run.identity(), &f.request, &f.cx)?;
    admitted.revalidate()?;
    assert_eq!(admitted.usage(), used);
    for short in [
        ImmutableRetainedReadLimits {
            max_read_bytes: exact.max_read_bytes - 1,
            ..exact
        },
        ImmutableRetainedReadLimits {
            max_read_objects: exact.max_read_objects - 1,
            ..exact
        },
    ] {
        let source = ImmutableRetainedSource::open(f.deployment.root(), short, &f.cx)?;
        RecordedInference::open(&source, f.run.identity(), &f.request, &f.cx)?;
        assert!(source.revalidate().is_err());
        // A failed final pass never starts another allowance on retry.
        assert!(source.revalidate().is_err());
    }
    assert!(
        ImmutableRetainedSource::open(
            f.deployment.root(),
            ImmutableRetainedReadLimits {
                max_read_bytes: 1,
                ..limits()
            },
            &f.cx,
        )
        .is_err()
    );
    assert_eq!(snapshot(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn corrupt_or_missing_selected_objects_are_refused_without_repair() -> TestResult {
    for kind in [
        "receipt",
        "model",
        "input",
        "output",
        "frame",
        "frame-receipt",
        "missing",
    ] {
        let f = Fixture::new(&format!("immutable-{kind}"))?;
        let digest = match kind {
            "receipt" => ContentDigest::sha256(&f.run.receipt_bytes()?),
            "model" => f.run.receipt.model,
            "input" => f.run.receipt.input,
            "frame" => f.run.receipt.frame,
            "frame-receipt" => f.run.receipt.frame_receipt,
            _ => f.run.receipt.output,
        };
        let path = f.deployment.publisher().spool().object_path(digest);
        if kind == "missing" {
            fs::remove_file(path)?;
        } else {
            let mut bytes = fs::read(&path)?;
            bytes[0] ^= 1;
            fs::write(path, bytes)?;
        }
        let before = snapshot(f.deployment.root())?;
        let source = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
        assert!(
            RecordedInference::open(&source, f.run.identity(), &f.request, &f.cx).is_err(),
            "{kind}"
        );
        assert_eq!(snapshot(f.deployment.root())?, before, "{kind}");
    }
    Ok(())
}

#[test]
fn final_revalidation_refuses_payload_tombstone_and_publication_races() -> TestResult {
    for kind in ["payload", "tombstone", "publication"] {
        let f = Fixture::new(&format!("immutable-race-{kind}"))?;
        let source = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
        RecordedInference::open(&source, f.run.identity(), &f.request, &f.cx)?;
        match kind {
            "payload" => {
                let path = f
                    .deployment
                    .publisher()
                    .spool()
                    .object_path(f.run.receipt.output);
                let mut bytes = fs::read(&path)?;
                bytes[0] ^= 1;
                fs::write(path, bytes)?;
            }
            "tombstone" => {
                let marker = f.deployment.root().join("objects/tombstones").join(format!(
                    "{}.tomb",
                    f.run.receipt.model.to_text().replacen(':', "-", 1),
                ));
                fs::write(marker, b"pending deletion")?;
            }
            _ => {
                let target = slot(f.run.identity())?;
                let manifest = f.run.receipt.manifest()?;
                let path = f
                    .deployment
                    .root()
                    .join("objects/roots")
                    .join(format!("{target}.root"));
                fs::write(
                    path,
                    fss_publication::root_record_bytes(
                        &target,
                        manifest.root(),
                        manifest.children().len() + 1,
                    )?,
                )?;
            }
        }
        let before = snapshot(f.deployment.root())?;
        assert!(source.revalidate().is_err(), "{kind}");
        let fresh = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
        assert!(
            RecordedInference::open(&fresh, f.run.identity(), &f.request, &f.cx).is_err(),
            "{kind}"
        );
        assert_eq!(snapshot(f.deployment.root())?, before, "{kind}");
    }
    Ok(())
}

#[test]
fn changed_authority_refuses_the_open_owner_but_preserves_historical_completion() -> TestResult {
    let mut f = Fixture::new("immutable-stale-authority")?;
    let root = f.deployment.root().to_path_buf();
    let source = ImmutableRetainedSource::open(&root, limits(), &f.cx)?;
    RecordedInference::open(&source, f.run.identity(), &f.request, &f.cx)?;
    let mut next = f.request.clone();
    next.segment_index = 1;
    RecordedFrame::decode_and_publish(
        &mut f.deployment,
        &next,
        &mut DecodeBudget::new(100_000_000),
        &f.cx,
    )?;
    let before = snapshot(&root)?;
    assert!(source.revalidate().is_err());
    assert!(RecordedInference::open(&source, f.run.identity(), &f.request, &f.cx).is_err());
    let fresh = ImmutableRetainedSource::open(&root, limits(), &f.cx)?;
    let restored = RecordedInference::open(&fresh, f.run.identity(), &f.request, &f.cx)?;
    assert_eq!(restored.authority_anchor(), f.run.authority_anchor());
    assert_ne!(restored.authority_anchor(), fresh.current_anchor());
    fresh.revalidate()?;
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn cancellation_before_payload_and_at_read_completion_never_returns_a_run() -> TestResult {
    let f = Fixture::new("immutable-cancellation")?;
    let before = snapshot(f.deployment.root())?;
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::SeqCst);
    let source =
        ImmutableRetainedSource::open_cancellable(f.deployment.root(), limits(), &f.cx, &probe)?;
    let opened = source.usage();
    cancelled.store(true, Ordering::SeqCst);
    assert!(RecordedInference::open(&source, f.run.identity(), &f.request, &f.cx).is_err());
    assert_eq!(source.usage(), opened);
    cancelled.store(false, Ordering::SeqCst);
    assert!(source.revalidate().is_err());
    f.cx.set_cancel_at_checkpoint("recorded_inference:read_complete");
    let source = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
    assert!(matches!(
        RecordedInference::open(&source, f.run.identity(), &f.request, &f.cx),
        Err(ModelRunError::Cancelled)
    ));
    assert_eq!(snapshot(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn authentic_historical_executor_profiles_remain_inspectable_but_cannot_replay() -> TestResult {
    let (_dir, cx, mut deployment, request, frame) = fixture("immutable-historical-runtime")?;
    let m = model(&frame, 0.25, true)?;
    let (mut receipt, input, output) = execute(&frame, &m, budget(), &ScalarExecCx::new())?;
    receipt.runtime = ContentDigest::sha256(b"retained earlier executor source profile");
    assert_ne!(receipt.runtime, executor_profile_digest());
    let encoded = receipt.encoded()?;
    let manifest = receipt.manifest()?;
    let target = slot(receipt.identity())?;
    for bytes in [
        m.encoded(),
        input.as_slice(),
        output.as_slice(),
        encoded.as_slice(),
    ] {
        let digest = deployment.publisher_mut().stage_object(bytes)?;
        deployment.publisher_mut().verify_object(digest)?;
    }
    deployment
        .publisher_mut()
        .stage_manifest(&target, &manifest)?;
    deployment.publish_and_commit(&target, &manifest, frame.receipt().capsule().capture, &cx)?;
    let mut children = manifest.children().to_vec();
    children.push(manifest.root());
    let completion = deployment.append_batch(
        batch_id(receipt.identity())?,
        vec![receipt.delta(&frame, manifest.root())?],
        children,
        &cx,
    )?;
    let before = snapshot(deployment.root())?;
    let source = ImmutableRetainedSource::open(deployment.root(), limits(), &cx)?;
    let restored = RecordedInference::open(&source, receipt.identity(), &request, &cx)?;
    assert_eq!(restored.executor_profile_digest(), receipt.runtime);
    assert_eq!(restored.receipt_bytes()?, encoded);
    assert_eq!(restored.output_bytes(), output);
    assert_eq!(restored.authority_anchor(), &completion);
    assert_ne!(
        restored.identity(),
        RecordedInference::identity_for(&frame, &m)
    );
    // A numeric checkpoint would observe cancellation and mark the executor drained. A runtime
    // mismatch must be rejected before reaching even that first numeric-execution boundary.
    let exec_cx = ScalarExecCx::new();
    exec_cx.request_cancellation();
    assert!(matches!(
        restored.verify_by_replay(&source, &request, budget(), &exec_cx, &cx),
        Err(ModelRunError::Mismatch)
    ));
    assert!(!exec_cx.is_drain_completed());
    source.revalidate()?;
    assert_eq!(snapshot(deployment.root())?, before);

    // Merely editing the stored runtime is not historical authority: the original receipt,
    // model-run identity, manifest, publication and final delta still bind the exact bytes.
    let receipt_path = deployment
        .publisher()
        .spool()
        .object_path(ContentDigest::sha256(&encoded));
    receipt.runtime = executor_profile_digest();
    fs::write(receipt_path, receipt.encoded()?)?;
    let before = snapshot(deployment.root())?;
    let source = ImmutableRetainedSource::open(deployment.root(), limits(), &cx)?;
    assert!(RecordedInference::open(&source, restored.identity(), &request, &cx).is_err());
    assert_eq!(snapshot(deployment.root())?, before);
    Ok(())
}
