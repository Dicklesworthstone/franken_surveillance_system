#![forbid(unsafe_code)]
//! Canonical imported recorder queries retain native evidence and narrow current source grants.

use super::immutable::filesystem;
use super::*;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{OperationId, PrincipalId, RuntimeGrant, TimestampNs};
use fss_reference::agent_recording_context::replay::retained::{
    RetainedRecordingReplayLimits, RetainedRecordingReplayRequest, RetainedReplaySourceReadPermit,
    query_retained_recordings_replay_in_deployment,
};
use fss_reference::agent_recording_context::replay::{
    RecordingReplayContextError, RecordingReplayContextRequest,
};
use std::sync::atomic::{AtomicU64, Ordering};

const PRINCIPAL: &str = "principal:canonical-retained-replay";

fn request(fixture: &Fixture, identity: ContentDigest) -> Test<RetainedRecordingReplayRequest> {
    let mut native = query(fixture);
    native.limits.max_results = 128;
    Ok(RetainedRecordingReplayRequest {
        import_identity: identity,
        replay: RecordingReplayContextRequest {
            replay: native,
            principal: PrincipalId::parse(PRINCIPAL)?,
            expected_anchor: None,
        },
    })
}

fn authority(
    request: &RetainedRecordingReplayRequest,
    limits: RetainedRecordingReplayLimits,
    deadline: Option<TimestampNs>,
    omitted: Option<&str>,
) -> Test<ContextAuthority> {
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:canonical-retained-replay".to_owned(),
        operation_id: OperationId::parse("operation:canonical-retained-replay")?,
        principal: request.replay.principal.as_str().to_owned(),
        capabilities: [
            "ADP-REPLAY-001",
            RuntimeGrant::AgentQuery.as_str(),
            RuntimeGrant::ReadMedia.as_str(),
        ]
        .into_iter()
        .filter(|capability| Some(*capability) != omitted)
        .map(str::to_owned)
        .collect(),
        deadline,
        priority: 10,
        budgets: limits.allowance()?,
        privacy_scope: "privacy:original-verification".to_owned(),
        retention_scope: "retention:no-new-retention".to_owned(),
        anchor_universe: request.replay.replay.scope.recording.anchor,
        generation: request.replay.replay.scope.recording.generation,
    })?)
}

#[test]
fn canonical_imported_avc_and_hevc_preserve_native_results_after_archive_loss() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut fixture = timestamp_fixture("canonical-retained-parity", codec)?;
        let imported = fixture.run()?.import;
        let request = request(&fixture, imported.import_identity)?;
        let native = query_replay_time(
            fixture.source.as_ref().ok_or("archive")?,
            &request.replay.replay,
            &NeverCancel,
        )?;
        let root = fixture.target()?.root().to_path_buf();
        let anchor = fixture.target()?.current_anchor().clone();
        drop(fixture.target.take());
        drop(fixture.source.take());
        fs::rename(
            fixture.directory.0.join("archive"),
            fixture.directory.0.join("unavailable-archive"),
        )?;
        let before = filesystem(&root)?;
        let limits = RetainedRecordingReplayLimits::default();
        let authority = authority(&request, limits, None, None)?;
        let now = || TimestampNs(0);
        let permit =
            RetainedReplaySourceReadPermit::authorize(&authority, &root, &request, limits, &now)?;
        let result = query_retained_recordings_replay_in_deployment(
            &root,
            &request,
            limits,
            Some(&permit),
            &|| false,
        )?;
        identical(&native, &result.report);
        assert_eq!(result.snapshot.anchor, anchor);
        assert_eq!(result.import_identity, imported.import_identity);
        assert_eq!(result.source_permit_digest, permit.digest());
        assert!(result.read_usage.read_bytes > result.report.source_bytes);
        assert!(result.read_usage.read_objects > 3);
        assert!(!result.report.receipt.publication_complete());
        assert_eq!(filesystem(&root)?, before);
    }
    Ok(())
}

#[test]
fn canonical_permit_cannot_move_to_another_root_import_query_principal_or_allowance() -> Test {
    let mut fixture = timestamp_fixture("canonical-retained-binding", RtspImportCodec::Avc)?;
    let imported = fixture.run()?.import;
    let request = request(&fixture, imported.import_identity)?;
    let root = fixture.target()?.root().to_path_buf();
    let limits = RetainedRecordingReplayLimits::default();
    let authority = authority(&request, limits, None, None)?;
    let now = || TimestampNs(0);
    let permit =
        RetainedReplaySourceReadPermit::authorize(&authority, &root, &request, limits, &now)?;
    drop(fixture.target.take());
    let moved = fixture.directory.0.join("unavailable-destination");
    fs::rename(&root, &moved)?;
    let before = filesystem(&moved)?;

    // Custody is deliberately absent. These must fail pure permit binding, rather than
    // attempting metadata recovery and only then discovering the unavailable destination.
    let other_root = fixture.directory.0.join("different-destination");
    assert!(matches!(
        query_retained_recordings_replay_in_deployment(
            &other_root,
            &request,
            limits,
            Some(&permit),
            &|| false,
        ),
        Err(RecordingReplayContextError::Unauthorized)
    ));
    for case in 0..4 {
        let mut changed = request.clone();
        let mut changed_limits = limits;
        match case {
            0 => changed.import_identity = ContentDigest::sha256(b"another completed import"),
            1 => changed.replay.replay.end_ns -= 1,
            2 => changed.replay.principal = PrincipalId::parse("principal:another-reader")?,
            _ => changed_limits.read.max_read_objects -= 1,
        }
        assert!(
            matches!(
                query_retained_recordings_replay_in_deployment(
                    &root,
                    &changed,
                    changed_limits,
                    Some(&permit),
                    &|| false,
                ),
                Err(RecordingReplayContextError::Unauthorized)
            ),
            "permit reuse case {case}"
        );
    }
    assert!(matches!(
        query_retained_recordings_replay_in_deployment(&root, &request, limits, None, &|| false,),
        Err(RecordingReplayContextError::Unauthorized)
    ));
    assert!(!root.exists());
    assert!(!other_root.exists());
    assert_eq!(filesystem(&moved)?, before);
    Ok(())
}

#[test]
fn canonical_capability_deadline_and_cancellation_denials_precede_source_io() -> Test {
    let mut fixture = timestamp_fixture("canonical-retained-admission", RtspImportCodec::Hevc)?;
    let imported = fixture.run()?.import;
    let request = request(&fixture, imported.import_identity)?;
    let root = fixture.target()?.root().to_path_buf();
    let limits = RetainedRecordingReplayLimits::default();
    drop(fixture.target.take());
    let moved = fixture.directory.0.join("unavailable-destination");
    fs::rename(&root, &moved)?;
    let before = filesystem(&moved)?;

    for missing in [
        "ADP-REPLAY-001",
        RuntimeGrant::AgentQuery.as_str(),
        RuntimeGrant::ReadMedia.as_str(),
    ] {
        let authority = authority(&request, limits, None, Some(missing))?;
        assert!(
            matches!(
                RetainedReplaySourceReadPermit::authorize(
                    &authority,
                    &root,
                    &request,
                    limits,
                    &|| TimestampNs(0),
                ),
                Err(RecordingReplayContextError::Unauthorized)
            ),
            "missing capability {missing}"
        );
    }

    let authority = authority(&request, limits, Some(TimestampNs(200)), None)?;
    let clock = AtomicU64::new(100);
    let now = || TimestampNs(i128::from(clock.load(Ordering::SeqCst)));
    // Authorization is pure: the exact root can be absent without being created or opened.
    let permit =
        RetainedReplaySourceReadPermit::authorize(&authority, &root, &request, limits, &now)?;
    assert!(matches!(
        query_retained_recordings_replay_in_deployment(
            &root,
            &request,
            limits,
            Some(&permit),
            &|| true,
        ),
        Err(RecordingReplayContextError::Cancelled)
    ));
    let deadline_permit =
        RetainedReplaySourceReadPermit::authorize(&authority, &root, &request, limits, &now)?;
    clock.store(200, Ordering::SeqCst);
    assert!(matches!(
        query_retained_recordings_replay_in_deployment(
            &root,
            &request,
            limits,
            Some(&deadline_permit),
            &|| false,
        ),
        Err(RecordingReplayContextError::Unauthorized)
    ));
    assert!(!root.exists());
    assert_eq!(filesystem(&moved)?, before);
    Ok(())
}
