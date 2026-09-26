#![forbid(unsafe_code)]
//! Real HTTP, native JPEG/model/head execution, ledgered publication and cold replay.
mod http_rgb_recording_support;
mod http_rgb_support;
mod privacy_live_support;
mod rgb_zone_support;
mod rgb_evidence_support;
mod http_rgb_evidence_support;
use http_rgb_recording_support::{Directory, session, attach};
use http_rgb_evidence_support::*;
use http_rgb_support::response;
use privacy_live_support::PrivacyDeployment;
use rgb_zone_support::{Test, jpeg, tracker, tracking_policy};
use rgb_evidence_support as fixture;
use fss_core::ContentDigest;
use fss_codec_mjpeg::DecodeBudget;
use fss_publication::{NeverCancel, RootLedgerOutcome};
use fss_reference::{ReferenceDeployment, ScalarExecCx};
use fss_reference::ingest::http_camera::HttpCameraOperation;
use fss_reference::ingest::http_camera::rgb::HttpRgbStep;
use fss_reference::ingest::http_rgb_recording::HttpRgbRecordingStep;
use fss_reference::ingest::http_rgb_evidence::*;
use fss_reference::ingest::rgb_archive::RgbArchiveError;
use fss_reference::ingest::http_archive::HttpWireArchive;
use fss_reference::ingest::http_replay::{HttpReplayAccess, HttpReplayLimits, HttpReplayStep, HttpWireReplay};
use fss_reference::ingest::http_replay::completion::VerifiedHttpCompletion;
use fss_reference::ingest::http_rgb_evidence_replay::*;

#[test]
fn every_live_result_is_ledgered_before_transfer_and_replays_after_all_owners_close() -> Test {
    let directory = Directory::new("evidence-cold")?;
    let cx = fixture::context(&directory.0)?;
    let privacy = PrivacyDeployment::new("http-evidence-cold")?;
    let mut b = Budgets::new();
    let graph = fixture::graph()?;
    let weights = fixture::weights();
    let model = imported(&graph, &weights, &cx, &mut b)?;
    let head = head(model.model())?;
    let mut owner = tracker(&head, tracking_policy())?;
    let mut publisher = directory.open()?;
    let (capture, camera, mut server) = session(model.model(), &head, &mut owner, response(&[jpeg(240), jpeg(240)], true), 257)?;
    let recording = attach(capture, &publisher, &camera, http_rgb_recording_support::limits())?;
    let mut r = HttpRgbEvidenceRecording::attach(recording, limits()).map_err(|_| "evidence attachment")?;
    let path = directory.0.join("derived");
    let mut deployment = ReferenceDeployment::open(&path, "site:http-rgb-evidence", &cx)?;
    let auth = ArchiveAuthority::new();
    let mut pins = Vec::new();
    for n in 1..=2 {
        assert_eq!(next(&mut r, &mut publisher, &camera, &mut server)?, HttpRgbRecordingStep::Analysis(HttpRgbStep::AwaitingContext));
        let result = analyze(&mut r, &publisher, &camera, n, privacy.mask(), &mut b)?;
        let (e, replay) = evidence(&r, &model, &head, privacy.mask(), &mut b, &cx)?;
        let pin = r.prepare_evidence(&e, &replay, retention(), &publisher, auth.access(&camera), &mut b.copy, &mut b.work, &cx)?;
        assert_eq!(pin.stages[0], result.inference());
        assert_eq!(pin.stages[1], result.detections());
        assert_eq!(pin.archive.capture, r.accepted_admission().ok_or("admission")?.source().capture);
        let source_counts = r.recording().capture().camera().totals();
        let copy_used = b.copy.used();
        assert_eq!(r.prepare_evidence(&e, &replay, retention(), &publisher, auth.access(&camera), &mut b.copy, &mut b.work, &cx)?, pin);
        assert_eq!(b.copy.used(), copy_used, "exact prepare retry must not re-encode");
        assert!(matches!(r.take_result(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.copy, &mut b.work, &cx), Err(HttpRgbEvidenceError::NotReady)));
        assert!(deployment.ledger().batches().len() == pins.len());
        assert_eq!(r.recording().work().transferred, pins.len() as u64);
        assert_eq!(r.poll(camera.access(&NeverCancel))?, HttpRgbRecordingStep::Analysis(HttpRgbStep::ResultReady(result)));
        assert_eq!(r.recording().capture().camera().totals(), source_counts);
        let mut wrong = pin;
        wrong.stages[1][0] ^= 1;
        assert!(matches!(r.commit_evidence(wrong, &publisher, &mut deployment, auth.access(&camera), &mut b.work, &cx), Err(HttpRgbEvidenceError::Mismatch)));
        let committed = r.commit_evidence(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.work, &cx)?;
        assert_eq!(committed.root, pin.archive.root);
        assert_eq!(committed.outcome, RootLedgerOutcome::Committed);
        let anchor = deployment.current_anchor().clone();
        assert_eq!(r.commit_evidence(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.work, &cx)?.outcome, RootLedgerOutcome::AlreadyLedgered);
        assert_eq!(deployment.current_anchor(), &anchor);
        assert_eq!(deployment.ledger().batches().len(), usize::from(n));
        let output = r.take_result(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.copy, &mut b.work, &cx)?;
        assert_eq!(output.receipt(), result);
        assert_eq!(r.last_delivered(), Some(pin));
        assert!(r.prepared().is_none());
        assert!(r.accepted_admission().is_none());
        pins.push(pin);
        drop(output);
    }
    let HttpRgbRecordingStep::CompletionPrepared(completion) = next(&mut r, &mut publisher, &camera, &mut server)? else { return Err("native terminal missing".into()); };
    r.commit_completion(completion, &mut publisher, camera.access(&NeverCancel))?;
    let source_scope = r.recording().scope();
    assert_eq!(pins[0].encoded, pins[1].encoded, "identical JPEG bytes must not alias exposures");
    assert_ne!(pins[0].exposure, pins[1].exposure);
    assert_ne!(pins[0].archive.evidence, pins[1].archive.evidence);
    drop(r.retire());
    assert_eq!(owner.tracker().exposure_count(), 2);
    drop(owner);
    drop(model);
    drop(graph);
    drop(weights);
    drop(deployment);
    drop(publisher);
    drop(server);
    // No live output, model, graph file, original envelope or open archive remains.
    let mut deployment = ReferenceDeployment::reopen(&path, "site:http-rgb-evidence", &cx)?;
    let publisher = directory.open()?;
    let original = HttpWireArchive::load(&publisher, source_scope, completion.wire, limits().source, &NeverCancel, &mut b.work)?;
    VerifiedHttpCompletion::load(&publisher, &original, completion, &NeverCancel, &mut b.work)?;
    let mut cursor = HttpWireReplay::new(&original, completion.wire, HttpReplayLimits {
        read_bytes: 17, // Deliberately different fragmentation from live acquisition.
        frames: 3, // One lookahead frame permits checking termination after exactly two.
        ..HttpReplayLimits::default()
    })?;
    let mut framing = DecodeBudget::new(rgb_zone_support::WORK);
    let mut cold_owner = None;
    let anchor = deployment.current_anchor().clone();
    for (index, pin) in pins.iter().copied().enumerate() {
        let mut found = false;
        for _ in 0..50000 {
            match cursor.step(HttpReplayAccess {
                publisher: &publisher, cancellation: &NeverCancel,
                work: &mut b.work, framing: &mut framing,
            })? {
                HttpReplayStep::FrameReady => { found = true; break; }
                HttpReplayStep::PrefixVerified | HttpReplayStep::WireLoaded { .. } | HttpReplayStep::Advanced => {}
                _ => return Err("cold source ended before the expected frame".into()),
            }
        }
        assert!(found, "cold source step bound");
        let source = HttpRgbEvidenceReplaySource {
            publisher: &publisher, scope: source_scope, tip: completion.wire,
            frame: cursor.pending_frame().ok_or("cold original missing")?,
            cancellation: &NeverCancel,
        };
        let decoded_before = b.decoder.used();
        // An identical JPEG from another HTTP part is NOT the selected exposure.
        let rival = pins[1 - index];
        assert!(matches!(restore_http_rgb_evidence(rival, source, &mut deployment, &auth, limits(), &mut b.copy, &mut b.work, &cx), Err(HttpRgbEvidenceReplayError::Mismatch)));
        let mut wrong = pin;
        wrong.wire.head = ContentDigest::sha256(b"rival source prefix");
        assert!(matches!(restore_http_rgb_evidence(wrong, source, &mut deployment, &auth, limits(), &mut b.copy, &mut b.work, &cx), Err(HttpRgbEvidenceReplayError::Mismatch)));
        auth.reads.set(false);
        assert!(matches!(restore_http_rgb_evidence(pin, source, &mut deployment, &auth, limits(), &mut b.copy, &mut b.work, &cx), Err(HttpRgbEvidenceReplayError::Denied)));
        auth.reads.set(true);
        assert_eq!(b.decoder.used(), decoded_before, "restore/source refusals cannot execute a decoder");
        let restored = restore_http_rgb_evidence(pin, source, &mut deployment, &auth, limits(), &mut b.copy, &mut b.work, &cx)?;
        assert_eq!(restored.pin(), pin);
        assert_eq!(b.decoder.used(), decoded_before, "restored bytes alone are not executed inference");
        auth.reads.set(false);
        assert!(matches!(restored.replay(privacy.mask(), fixture::limits(), &NeverCancel, &auth, &mut b.copy, &mut b.import, &mut b.decoder, &mut b.head, &cx, &ScalarExecCx::new()), Err(HttpRgbEvidenceReplayError::Denied)));
        assert_eq!(b.decoder.used(), decoded_before);
        auth.reads.set(true);
        if index == 0 {
            let mut wrong_result = pin;
            wrong_result.stages[0][0] ^= 1;
            // Restoration checks source bytes, not a stored assertion of computation.
            // Only executing the original model can check this false numerical claim.
            let wrong_restored = restore_http_rgb_evidence(wrong_result, source, &mut deployment, &auth, limits(), &mut b.copy, &mut b.work, &cx)?;
            assert!(matches!(wrong_restored.replay(privacy.mask(), fixture::limits(), &NeverCancel, &auth, &mut b.copy, &mut b.import, &mut b.decoder, &mut b.head, &cx, &ScalarExecCx::new()), Err(HttpRgbEvidenceReplayError::Mismatch)));
        }
        let replayed = restored.replay(privacy.mask(), fixture::limits(), &NeverCancel, &auth, &mut b.copy, &mut b.import, &mut b.decoder, &mut b.head, &cx, &ScalarExecCx::new())?;
        assert!(b.decoder.used() > decoded_before);
        assert_eq!(replayed.pin(), pin);
        let replay = replayed.evidence();
        assert_eq!(replay.run().inference().identity().bytes(), pin.stages[0]);
        assert_eq!(replay.run().report().digest().bytes(), pin.stages[1]);
        assert_eq!(replay.admission().source().exposure, pin.exposure);
        if cold_owner.is_none() {
            cold_owner = Some(tracker(replay.head(), tracking_policy())?);
            assert!(matches!(replayed.verify_temporal(cold_owner.as_ref().ok_or("cold tracker")?), Err(HttpRgbEvidenceReplayError::TemporalPending)));
        } else {
            // The previous observation's history is not silently accepted as this one.
            assert!(matches!(replayed.verify_temporal(cold_owner.as_ref().ok_or("cold tracker")?), Err(HttpRgbEvidenceReplayError::Mismatch)));
        }
        let cold = cold_owner.as_mut().ok_or("cold tracker")?;
        cold.observe(replay.run().inference(), replay.run().report(), replay.admission(), &mut b.temporal)?;
        assert_eq!(replayed.verify_temporal(cold)?.pin(), pin);
        let count = cold.tracker().exposure_count();
        assert_eq!(replayed.verify_temporal(cold)?.pin(), pin);
        assert_eq!(cold.tracker().exposure_count(), count, "verification never re-assimilates an exposure");
        let frame = cursor.take_frame(pin.ordinal, pin.encoded, HttpReplayAccess {
            publisher: &publisher, cancellation: &NeverCancel,
            work: &mut b.work, framing: &mut framing,
        })?;
        assert_eq!(ContentDigest::sha256(frame.part().bytes()).bytes(), pin.encoded);
    }
    let mut ended = false;
    for _ in 0..50000 {
        match cursor.step(HttpReplayAccess {
            publisher: &publisher, cancellation: &NeverCancel,
            work: &mut b.work, framing: &mut framing,
        })? {
            HttpReplayStep::Complete => { ended = true; break; }
            HttpReplayStep::PrefixVerified | HttpReplayStep::WireLoaded { .. } | HttpReplayStep::Advanced => {}
            _ => return Err("cold source did not end at its actual native boundary".into()),
        }
    }
    assert!(ended);
    assert_eq!(cursor.position().transferred_frames, 2);
    assert_eq!(cold_owner.ok_or("cold tracker")?.tracker().exposure_count(), 2);
    assert_eq!(deployment.current_anchor(), &anchor, "cold reconstruction is read-only");
    Ok(())
}

#[test]
fn write_and_read_revocation_keep_exact_prepared_and_native_ownership() -> Test {
    let directory = Directory::new("evidence-denied")?;
    let cx = fixture::context(&directory.0)?;
    let privacy = PrivacyDeployment::new("http-evidence-denied")?;
    let mut b = Budgets::new();
    let graph = fixture::graph()?;
    let weights = fixture::weights();
    let model = imported(&graph, &weights, &cx, &mut b)?;
    let head = head(model.model())?;
    let mut owner = tracker(&head, tracking_policy())?;
    let mut publisher = directory.open()?;
    let (capture, camera, mut server) = session(model.model(), &head, &mut owner, response(&[jpeg(240)], false), 4096)?;
    let recording = attach(capture, &publisher, &camera, http_rgb_recording_support::limits())?;
    let mut r = HttpRgbEvidenceRecording::attach(recording, limits()).map_err(|_| "evidence attachment")?;
    next(&mut r, &mut publisher, &camera, &mut server)?;
    let result = analyze(&mut r, &publisher, &camera, 1, privacy.mask(), &mut b)?;
    let (e, replay) = evidence(&r, &model, &head, privacy.mask(), &mut b, &cx)?;
    let mut deployment = ReferenceDeployment::open(&directory.0.join("derived"), "site:http-rgb-evidence", &cx)?;
    let auth = ArchiveAuthority::new();
    auth.writes.set(false);
    assert!(matches!(r.prepare_evidence(&e, &replay, retention(), &publisher, auth.access(&camera), &mut b.copy, &mut b.work, &cx), Err(HttpRgbEvidenceError::Archive(RgbArchiveError::Denied))));
    assert!(r.prepared().is_none());
    auth.writes.set(true);
    let pin = r.prepare_evidence(&e, &replay, retention(), &publisher, auth.access(&camera), &mut b.copy, &mut b.work, &cx)?;
    auth.writes.set(false);
    assert!(matches!(r.commit_evidence(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.work, &cx), Err(HttpRgbEvidenceError::Archive(RgbArchiveError::Denied))));
    assert!(r.published().is_none());
    assert_eq!(r.prepared(), Some(pin));
    assert!(deployment.ledger().batches().is_empty());
    assert_eq!(r.recording().capture().completion(), Some(result));
    auth.writes.set(true);
    r.commit_evidence(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.work, &cx)?;
    auth.reads.set(false);
    assert!(matches!(r.take_result(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.copy, &mut b.work, &cx), Err(HttpRgbEvidenceError::Archive(RgbArchiveError::Denied))));
    assert_eq!(r.published(), Some(pin));
    assert_eq!(r.recording().work().transferred, 0);
    assert!(r.recording().capture().completed().is_some());
    auth.reads.set(true);
    camera.deny(HttpCameraOperation::ReleaseResult);
    assert!(r.take_result(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.copy, &mut b.work, &cx).is_err());
    let retired = r.retire();
    let pending = retired.pending.ok_or("plan lost")?;
    assert_eq!(pending.pin, pin);
    assert!(pending.published);
    assert_eq!(retired.recording.capture.complete, Some(result));
    assert!(retired.recording.capture.source.frame.is_some());
    assert_eq!(retired.recording.work.transferred, 0);
    assert!(retired.admission.is_some());
    Ok(())
}

#[test]
fn lost_ledger_after_publication_blocks_delivery_until_exact_key_recovery() -> Test {
    let directory = Directory::new("evidence-ledger-gap")?;
    let cx = fixture::context(&directory.0)?;
    let privacy = PrivacyDeployment::new("http-evidence-ledger-gap")?;
    let mut b = Budgets::new();
    let graph = fixture::graph()?;
    let weights = fixture::weights();
    let model = imported(&graph, &weights, &cx, &mut b)?;
    let head = head(model.model())?;
    let mut owner = tracker(&head, tracking_policy())?;
    let mut publisher = directory.open()?;
    let (capture, camera, mut server) = session(model.model(), &head, &mut owner, response(&[jpeg(240)], true), 4096)?;
    let recording = attach(capture, &publisher, &camera, http_rgb_recording_support::limits())?;
    let mut r = HttpRgbEvidenceRecording::attach(recording, limits()).map_err(|_| "evidence attachment")?;
    next(&mut r, &mut publisher, &camera, &mut server)?;
    let result = analyze(&mut r, &publisher, &camera, 1, privacy.mask(), &mut b)?;
    let (e, replay) = evidence(&r, &model, &head, privacy.mask(), &mut b, &cx)?;
    let path = directory.0.join("derived");
    let mut deployment = ReferenceDeployment::open(&path, "site:http-rgb-evidence", &cx)?;
    let auth = ArchiveAuthority::new();
    let pin = r.prepare_evidence(&e, &replay, retention(), &publisher, auth.access(&camera), &mut b.copy, &mut b.work, &cx)?;
    r.commit_evidence(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.work, &cx)?;
    drop(deployment);
    // Exclusively test-owned fault injection: root survives, canonical append does not.
    std::fs::write(path.join("ledger/journal.fssj"), [])?;
    let mut deployment = ReferenceDeployment::reopen(&path, "site:http-rgb-evidence", &cx)?;
    assert!(matches!(r.take_result(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.copy, &mut b.work, &cx), Err(HttpRgbEvidenceError::Archive(RgbArchiveError::NotCommitted))));
    assert_eq!(r.recording().work().transferred, 0);
    assert_eq!(r.prepared(), Some(pin));
    assert_eq!(r.recording().capture().completion(), Some(result));
    let native_work = r.recording().capture().completed().ok_or("output lost")?.detection_run().inference().identity();
    r.commit_evidence(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.work, &cx)?;
    assert_eq!(deployment.ledger().batches().len(), 1);
    let output = r.take_result(pin, &publisher, &mut deployment, auth.access(&camera), &mut b.copy, &mut b.work, &cx)?;
    assert_eq!(output.analysis().detection_run().inference().identity(), native_work);
    assert_eq!(r.recording().work().transferred, 1);
    Ok(())
}
