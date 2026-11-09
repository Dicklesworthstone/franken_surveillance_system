#![forbid(unsafe_code)]
//! Conditional UTC candidate acquisition preserves clocks, original closure and uncertainty.

#[path = "recording_clock_contract/support.rs"]
mod clock_support;
mod collector_support;
#[path = "agent_recordings_utc_discovery_contract/support.rs"]
mod discovery_fixture;
mod hevc_catalog_support;
mod hevc_recording_support;
#[allow(dead_code)]
#[path = "support/import_integrity.rs"]
mod integrity;
mod recording_support;
#[path = "agent_recordings_utc_sessions_contract/support.rs"]
mod session_fixture;
#[path = "agent_recordings_utc_contract/support.rs"]
mod utc_support;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, PrincipalId, RootAuthoritySpec,
    TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_object::{HostSpoolIo, RecordingSpoolIo, SpoolIoCall};
use fss_publication::custody_audit::pinned_closure::{PinnedClosureReader, PinnedClosureUsage};
use fss_reference::agent_recording_context::utc_discover::{
    RecordingUtcDiscoveryContextLimits, RecordingUtcDiscoveryContextRequest,
};
use fss_reference::agent_recording_context::utc_sessions::{
    RecordingUtcSessionsContextLimits, RecordingUtcSessionsContextRequest,
};
use fss_reference::agent_recordings::RecordingQueryCodec::{Avc, Hevc};
use fss_reference::ingest::rtsp_import::query::utc::*;
use fss_reference::ingest::rtsp_import::query::{
    RtspQueryImportError, RtspQueryImportSettings, STAGE_QUERY_WINDOW,
};
use fss_reference::ingest::rtsp_import::{self, RtspImportCodec};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:utc-query-import";

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Destination {
    directory: Directory,
    root: PathBuf,
    cx: ReplayCx,
    owner: Option<ReferenceDeployment>,
}
impl Destination {
    fn new(name: &str) -> Test<Self> {
        let directory = Directory(integrity::directory(&format!("utc-import-{name}"))?);
        let root = directory.0.join("deployment");
        let cx = context(&root)?;
        let owner = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self {
            directory,
            root,
            cx,
            owner: Some(owner),
        })
    }
    fn owner(&self) -> Test<&ReferenceDeployment> {
        self.owner
            .as_ref()
            .ok_or_else(|| "destination owner".into())
    }
}
impl Drop for Destination {
    fn drop(&mut self) {
        drop(self.owner.take());
    }
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:utc-query-import".into(),
        operation_id: OperationId::parse("operation:utc-query-import")?,
        principal: "principal:utc-query-import".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "CAP-READ-MEDIA-001".into(),
            "CAP-OBJECT-STAGE-001".into(),
            "CAP-OBJECT-PUBLISH-001".into(),
            "CAP-RETENTION-COMMIT-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn settings() -> RtspQueryImportSettings {
    RtspQueryImportSettings {
        site: SITE.to_owned(),
        receive_time: TimestampNs(2_000_000_000),
        max_frames: rtsp_import::catalog::MAX_FRAMES,
        max_original_bytes: rtsp_import::catalog::MAX_ORIGINAL_BYTES,
        max_media_bytes: rtsp_import::catalog::MAX_MEDIA_BYTES,
        max_work: 1024 * 1024 * 1024,
    }
}

fn session_input(f: &session_fixture::Fixture) -> Test<RtspUtcQueryImportInput> {
    let mut recording = f.request.clone();
    recording.max_windows = 32;
    Ok(RtspUtcQueryImportInput::Sessions {
        request: RecordingUtcSessionsContextRequest {
            recording,
            principal: PrincipalId::parse("principal:utc-query-import")?,
            expected_anchor: None,
        },
        limits: RecordingUtcSessionsContextLimits::default(),
    })
}

fn discovery_input(f: &discovery_fixture::Fixture) -> Test<RtspUtcQueryImportInput> {
    let mut recording = f.request.clone();
    recording.max_windows = 32;
    Ok(RtspUtcQueryImportInput::Discovery {
        request: RecordingUtcDiscoveryContextRequest {
            recording,
            principal: PrincipalId::parse("principal:utc-query-import")?,
            expected_anchor: None,
        },
        limits: RecordingUtcDiscoveryContextLimits::default(),
    })
}

fn preview(
    destination: &Destination,
    archive: &Path,
    input: &RtspUtcQueryImportInput,
) -> Test<RtspUtcQueryImportPlan> {
    Ok(preview_rtsp_utc_query_import(
        &HostSpoolIo,
        &destination.root,
        archive,
        input,
        &settings(),
        &|| false,
    )?)
}

struct Owner {
    approved: ContentDigest,
    enabled: Cell<bool>,
}
impl Owner {
    fn new(plan: &RtspUtcQueryImportPlan) -> Self {
        Self {
            approved: plan.digest(),
            enabled: Cell::new(true),
        }
    }
}
impl RtspUtcQueryImportAuthority for Owner {
    fn permit_open(&self, plan: &RtspUtcQueryImportPlan) -> bool {
        self.enabled.get() && self.approved == plan.digest()
    }
    fn permit(&self, plan: &RtspUtcQueryImportPlan, destination: &ReferenceDeployment) -> bool {
        self.permit_open(plan)
            && destination.root() == plan.deployment_root()
            && destination.site_lineage() == SITE
    }
}

fn acquire(
    destination: &mut Destination,
    plan: &RtspUtcQueryImportPlan,
) -> Test<(
    Result<RtspUtcQueryImportReceipt, RtspUtcQueryImportFailure>,
    PinnedClosureUsage,
)> {
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader =
        PinnedClosureReader::new(&io, plan.archive_root(), plan.source_limits(), &|| false)?;
    let result = import_rtsp_utc_query_pinned(
        &io,
        &mut reader,
        destination.owner.as_mut().ok_or("destination owner")?,
        plan,
        &Owner::new(plan),
        &destination.cx,
        &mut WorkBudget::new(settings().max_work),
        &|| false,
    );
    let usage = reader.usage();
    if result.is_ok() {
        let final_usage = reader.finish()?;
        assert_eq!(final_usage.read_bytes, usage.read_bytes);
        assert_eq!(final_usage.objects, usage.objects);
        assert_eq!(final_usage.completed_roots, usage.completed_roots);
        assert_eq!(final_usage.io_calls, usage.io_calls);
    }
    assert!(io.is_read_only());
    Ok((result, usage))
}

fn retain_native_payloads(f: &session_fixture::Fixture) -> Test {
    for session in &f.sessions {
        for (_, window) in &session.windows {
            for (_, _, bytes) in window.plan().children() {
                f.put(bytes)?;
            }
        }
    }
    Ok(())
}

#[test]
fn mixed_sessions_acquire_unknown_time_candidates_with_original_scopes_and_cold_source_proof()
-> Test {
    let f = session_fixture::Fixture::new("acquire-mixed", &[Avc, Hevc], 2, 1, &[0])?;
    retain_native_payloads(&f)?;
    let mut destination = Destination::new("mixed")?;
    // This disjoint UTC predicate cannot exclude either unknown-clock source member.
    let input = session_input(&f)?;
    let before = integrity::snapshot(&f.root)?;
    let plan = preview(&destination, &f.root, &input)?;
    assert_eq!(integrity::snapshot(&f.root)?, before);
    assert_eq!(plan.windows().len(), 2);
    assert!(
        plan.windows()
            .iter()
            .all(|window| window.row.utc_interval.is_none()
                && window.row.clock_ordinal.is_none()
                && window.request.capture_origin.is_none())
    );
    let RtspUtcQueryImportObservation::Sessions(query) = plan.query() else {
        return Err("sessions observation".into());
    };
    assert_eq!(query.native.indexed_gaps, vec![0..1]);
    for window in plan.windows() {
        let session = &query.native.sessions[window.session_index.ok_or("session position")?];
        assert_eq!(window.scope, session.scope);
        assert_eq!(window.session_digest, Some(session.session_digest));
        assert_eq!(window.clock_root, session.clock_root);
        assert_eq!(window.clock_metadata_digest, session.clock_metadata_digest);
    }
    let (result, usage) = acquire(&mut destination, &plan)?;
    let result = result?;
    assert_eq!(usage.completed_roots, 2);
    assert_eq!(usage.objects, 10);
    assert_eq!(usage.edges, 8);
    assert!(usage.read_bytes <= plan.source_limits().max_read_bytes);
    assert_eq!(result.imports.len(), 2);
    assert_eq!(result.frames, 5); // One AVC picture plus four HEVC samples.
    assert_eq!(result.original_bytes, plan.original_bytes());
    let original_roots = result
        .imports
        .iter()
        .map(|row| row.selection.request.root)
        .collect::<BTreeSet<_>>();
    for imported in &result.imports {
        assert_eq!(imported.import.capture_time_label, "unknown");
        assert_eq!(imported.selection.row.utc_interval, None);
        let retained = RetainedFileImport::open(
            destination.owner()?,
            imported.import.import_identity,
            RetainedReadLimits::default(),
            &destination.cx,
        )?;
        assert_eq!(retained.manifest().capture_time_label, "unknown");
        assert_eq!(
            retained.verify_source(
                destination.owner()?,
                RetainedReadLimits::default(),
                &destination.cx
            )?,
            retained.manifest().input_sha256
        );
    }
    let spool = destination.owner()?.publisher().spool();
    for session in &f.sessions {
        assert!(!spool.digests().any(|digest| digest == session.clock.root()));
        for catalog in &session.catalogs {
            assert!(
                !spool
                    .digests()
                    .any(|digest| digest == catalog.manifest.root())
            );
        }
        for (_, native) in &session.windows {
            let native = native.plan();
            if original_roots.contains(&native.manifest().root()) {
                for (_, digest, bytes) in native.children() {
                    assert_eq!(spool.read(digest)?, bytes);
                }
            } else {
                assert!(
                    !spool
                        .digests()
                        .any(|digest| digest == native.manifest().root())
                );
            }
        }
    }
    let retired = Directory(f.root.with_extension("offline"));
    fs::rename(&f.root, &retired.0)?;
    drop(destination.owner.take());
    destination.cx = context(&destination.root)?;
    destination.owner = Some(ReferenceDeployment::open(
        &destination.root,
        SITE,
        &destination.cx,
    )?);
    for imported in &result.imports {
        let retained = RetainedFileImport::open(
            destination.owner()?,
            imported.import.import_identity,
            RetainedReadLimits::default(),
            &destination.cx,
        )?;
        assert_eq!(
            retained.verify_source(
                destination.owner()?,
                RetainedReadLimits::default(),
                &destination.cx
            )?,
            retained.manifest().input_sha256
        );
    }
    Ok(())
}

#[test]
fn canonical_session_order_and_each_interpretation_or_bound_have_exact_plan_identity() -> Test {
    let f = session_fixture::Fixture::new("plan-identity", &[Avc, Hevc], 2, 1, &[0])?;
    let destination = Destination::new("identity")?;
    let input = session_input(&f)?;
    let plan = preview(&destination, &f.root, &input)?;
    let mut reordered = input.clone();
    if let RtspUtcQueryImportInput::Sessions { request, .. } = &mut reordered {
        request.recording.sessions.reverse();
        for session in &mut request.recording.sessions {
            session.catalogs.reverse();
        }
    }
    assert_eq!(
        preview(&destination, &f.root, &reordered)?.digest(),
        plan.digest()
    );
    for variant in 0..6 {
        let mut changed = input.clone();
        let mut bounds = settings();
        if let RtspUtcQueryImportInput::Sessions { request, limits } = &mut changed {
            match variant {
                0 => request.recording.interval = 2..3,
                1 => request.principal = PrincipalId::parse("principal:other-utc-import")?,
                2 => limits.deployment_reads -= 1,
                3 => bounds.receive_time.0 += 1,
                4 => bounds.max_media_bytes -= 1,
                _ => bounds.max_work -= 1,
            }
        }
        let changed = preview_rtsp_utc_query_import(
            &HostSpoolIo,
            &destination.root,
            &f.root,
            &changed,
            &bounds,
            &|| false,
        )?;
        assert_ne!(changed.digest(), plan.digest());
        assert!(!Owner::new(&plan).permit_open(&changed));
    }
    Ok(())
}

#[test]
fn discovered_namespace_acquires_conditional_and_unknown_rows_without_unselected_payloads() -> Test
{
    for codec in [Avc, Hevc] {
        let f = discovery_fixture::Fixture::new("acquire-discovered", codec, 3, 2, &[0, 1])?;
        // The fixture selects the last known envelope plus the unknown third member.
        for (_, window) in f.windows.iter().skip(1) {
            for (_, _, bytes) in window.plan().children() {
                f.put(bytes)?;
            }
        }
        let selected_roots = f
            .windows
            .iter()
            .skip(1)
            .map(|(_, window)| window.plan().manifest().root())
            .collect::<BTreeSet<_>>();
        let selected_leaves = f
            .windows
            .iter()
            .skip(1)
            .flat_map(|(_, window)| window.plan().children().map(|(_, digest, _)| digest))
            .collect::<BTreeSet<_>>();
        for (_, digest, _) in f.windows[0].1.plan().children() {
            if !selected_leaves.contains(&digest) {
                fs::write(f.object(digest), b"unselected payload corruption")?;
            }
        }
        let mut destination = Destination::new("discovery")?;
        let plan = preview(&destination, &f.root, &discovery_input(&f)?)?;
        assert_eq!(plan.windows().len(), 2);
        assert!(plan.windows()[0].row.utc_interval.is_some());
        assert!(plan.windows()[1].row.utc_interval.is_none());
        assert!(plan.windows().iter().all(
            |window| window.session_index.is_none() && window.request.capture_origin.is_none()
        ));
        let before = integrity::snapshot(&f.root)?;
        let (result, usage) = acquire(&mut destination, &plan)?;
        let result = result?;
        assert_eq!(usage.completed_roots, 2);
        assert_eq!(integrity::snapshot(&f.root)?, before);
        assert_eq!(
            result
                .imports
                .iter()
                .map(|row| row.selection.request.root)
                .collect::<BTreeSet<_>>(),
            selected_roots
        );
        for imported in result.imports {
            assert_eq!(
                imported.import.codec,
                match codec {
                    Avc => RtspImportCodec::Avc,
                    Hevc => RtspImportCodec::Hevc,
                }
            );
            assert_eq!(imported.import.capture_time_label, "unknown");
            assert_eq!(imported.selection.clock_root, f.clock.root());
        }
    }
    Ok(())
}

#[path = "rtsp_utc_query_import_contract/refusals.rs"]
mod refusals;
