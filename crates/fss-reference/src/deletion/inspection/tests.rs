#![forbid(unsafe_code)]
//! Deterministic races after native reconstruction and before final verification.

use std::fs;
use std::path::PathBuf;

use fss_core::region::RootAuthoritySpec;
use fss_core::{BudgetVector, CaptureInterval, OperationId, SensorId, TimestampNs};

use super::*;
use crate::ReferenceDeployment;
use crate::deletion::holds::CAP_HOLD_COMMIT;
use crate::deletion::retention::policy::{
    PolicyChangeRequest, commit_policy_change, preview_policy_change,
};

type Test = Result<(), Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn post_reconstruction_policy_layout_and_committed_head_changes_withhold_the_result() -> Test {
    const SITE: &str = "site:retention-inspection-race";
    for change in ["policy", "layout", "head"] {
        let mut directory = None;
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-inspection-race-{change}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    directory = Some(Directory(path));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let directory = directory.ok_or("test directory capacity")?;
        let root = directory.0.join("deployment");
        let limits = inspection_limits();
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:retention-inspection".into(),
            operation_id: OperationId::parse("operation:retention-inspection")?,
            principal: "principal:retention-owner".into(),
            capabilities: vec![
                "ADP-REPLAY-001".into(),
                CAP_HOLD_PREPARE.into(),
                CAP_HOLD_COMMIT.into(),
            ],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(limits.max_read_bytes as u64)
                .storage_operations(limits.max_read_objects as u64)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let writer_cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut writer = ReferenceDeployment::open(&root, SITE, &writer_cx)?;
        let request = PolicyChangeRequest {
            sensor: SensorId::parse("sensor:empty")?,
            enabled: false,
            retain_for_ns: 10,
            max_retained_source_bytes: None,
            expected_policy: None,
            attested_now: CaptureInterval::new(TimestampNs(100), TimestampNs(100))?,
            reason: "Owner configuration".into(),
        };
        let preview = preview_policy_change(&writer, &request, &authority, &writer_cx)?;
        let record = commit_policy_change(
            &mut writer,
            &request,
            preview.record.approval(),
            &authority,
            &writer_cx,
        )?
        .record;
        let payload = writer.publisher().spool().object_path(record.digest());
        let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())?;
        let result = inspect(&root, &authority, limits, &cx, &|| false, |source| {
            let records = retained_policy_records(source, &cx)?;
            assert_eq!(records.as_slice(), std::slice::from_ref(&record));
            match change {
                "policy" => fs::write(&payload, b"changed after native reconstruction")
                    .map_err(FileIngestError::from)?,
                "layout" => fs::write(root.join("LAYOUT"), b"changed deployment layout")
                    .map_err(FileIngestError::from)?,
                _ => {
                    let mut revised = request.clone();
                    revised.expected_policy = Some(record.digest());
                    revised.retain_for_ns = 20;
                    let preview = preview_policy_change(&writer, &revised, &authority, &writer_cx)?;
                    commit_policy_change(
                        &mut writer,
                        &revised,
                        preview.record.approval(),
                        &authority,
                        &writer_cx,
                    )?;
                }
            }
            Ok::<_, PolicyError>(records)
        });
        assert!(
            result.is_err(),
            "{change} changed after reconstruction but escaped final verification"
        );
        cx.drain_and_finalize();
        writer_cx.drain_and_finalize();
    }
    Ok(())
}
