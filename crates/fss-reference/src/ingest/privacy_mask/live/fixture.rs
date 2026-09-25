#![forbid(unsafe_code)]
//! In-crate test fixture: a real deployment retaining (or not) one sensor's mask policy.

use std::path::PathBuf;

use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};

use super::super::{PrivacyMaskPolicy, declare_mask, preview_mask};
use super::SensorMask;
use crate::ingest::recorded_decode::{RecordedDecodeRequest, RecordedFrame};
use crate::ingest::{FileIngestAdapter, FileIngestRequest, RetainedReadLimits};
use crate::{ReferenceDeployment, ReplayCx};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const SITE: &str = "site:privacy-live-unit";

/// Owned temporary deployment for one test.
pub(crate) struct MaskFixture {
    root: PathBuf,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    sensor: SensorId,
    imports: u32,
}

impl MaskFixture {
    /// A fresh deployment whose fixture sensor has no retained policy.
    pub(crate) fn new(tag: &str) -> Result<Self> {
        let mut root = None;
        for n in 0..128_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-privacy-live-unit-{tag}-{}-{n}",
                std::process::id()
            ));
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
            trace_id: "trace:privacy-live-unit".into(),
            operation_id: OperationId::parse("operation:privacy-live-unit")?,
            principal: "principal:privacy-live-unit".into(),
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
            sensor: SensorId::parse("sensor:privacy-live-unit")?,
            imports: 0,
        })
    }

    /// The sensor as live consumers name it.
    pub(crate) fn mask(&self) -> SensorMask<'_> {
        SensorMask::new(&self.deployment, &self.sensor)
    }

    /// The owner permission grid that excludes exactly the currently masked pixels.
    pub(crate) fn grid(&self, dimensions: [u32; 2]) -> Result<Vec<u8>> {
        Ok(self.mask().resolve()?.allowed(dimensions)?)
    }

    /// Retains the next policy generation with its exact preview approval; returns its digest.
    pub(crate) fn declare(
        &mut self,
        resolution: [u32; 2],
        rectangles: &[[u32; 4]],
    ) -> Result<ContentDigest> {
        let policy = PrivacyMaskPolicy::new(self.sensor.clone(), resolution, rectangles)?;
        let preview = preview_mask(&self.deployment, &policy)?;
        Ok(declare_mask(&mut self.deployment, &policy, preview.approval, &self.cx)?.policy_digest)
    }

    /// Imports `jpeg` as a retained file of the sensor and returns the retained (fss-bgqkd)
    /// decode's luma digest under the sensor's current policy: the cross-check oracle.
    pub(crate) fn retained_luma_digest(
        &mut self,
        jpeg: &[u8],
        interpretation: ComponentInterpretation,
    ) -> Result<[u8; 32]> {
        self.imports += 1;
        let path = self.root.join(format!("retained-{}.mjpeg", self.imports));
        std::fs::write(&path, jpeg)?;
        let request = FileIngestRequest::new(
            path,
            self.sensor.clone(),
            StreamId::parse(format!("stream:privacy-live-unit-{}", self.imports))?,
        )
        .with_receive_time(TimestampNs(1_000_000_000));
        let imported = FileIngestAdapter::ingest(request, &self.cx, &mut self.deployment)?;
        let request = RecordedDecodeRequest {
            import_identity: imported.import_identity,
            segment_index: 0,
            interpretation,
            read_limits: RetainedReadLimits::default(),
            decode_limits: DecodeLimits::default(),
        };
        let frame = RecordedFrame::decode_and_publish(
            &mut self.deployment,
            &request,
            &mut DecodeBudget::new(1_000_000_000),
            &self.cx,
        )?;
        Ok(frame.receipt().codec().luma_sha256)
    }
}

impl Drop for MaskFixture {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
