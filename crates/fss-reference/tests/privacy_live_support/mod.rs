#![forbid(unsafe_code)]
//! A real reference deployment retaining (or not) one sensor's privacy mask policy; live and
//! replay consumers name that sensor with the returned [`SensorMask`].
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId};
use fss_reference::ingest::privacy_mask::live::SensorMask;
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::path::PathBuf;

/// Site lineage of every privacy fixture deployment.
pub const SITE: &str = "site:privacy-live";

/// Owned temporary deployment; the directory is the test's own scratch space.
pub struct PrivacyDeployment {
    /// Scratch directory holding `deployment/` and any retained source files.
    pub root: PathBuf,
    /// Owner context of the deployment.
    pub cx: ReplayCx,
    /// The deployment retaining the sensor's mask authority.
    pub deployment: ReferenceDeployment,
    /// The fixture sensor (`sensor:privacy-live`).
    pub sensor: SensorId,
}

impl PrivacyDeployment {
    /// A fresh deployment in which the fixture sensor has no retained policy.
    pub fn new(tag: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut root = None;
        for n in 0..128_u32 {
            let path = std::env::temp_dir()
                .join(format!("fss-privacy-live-{tag}-{}-{n}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    root = Some(path);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        let root = root.ok_or("fixture directory bound")?;
        let deployment_root = root.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:privacy-live".into(),
            operation_id: OperationId::parse("operation:privacy-live")?,
            principal: "principal:privacy-live".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(4096)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        authority.validate()?;
        let cx = ReplayCx::from_context_authority(&authority, deployment_root.clone())?;
        let deployment = ReferenceDeployment::open(&deployment_root, SITE, &cx)?;
        Ok(Self {
            root,
            cx,
            deployment,
            sensor: SensorId::parse("sensor:privacy-live")?,
        })
    }

    /// The sensor's mask as live and replay consumers name it.
    pub fn mask(&self) -> SensorMask<'_> {
        SensorMask::new(&self.deployment, &self.sensor)
    }
}

impl Drop for PrivacyDeployment {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
