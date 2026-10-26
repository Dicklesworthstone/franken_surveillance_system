#![forbid(unsafe_code)]
//! Strict direct-detector wrapper over the existing exact native camera/policy dialect.

use fss_core::{ContentDigest, DigestAlgorithm};

use crate::json_input::parse;

use super::super::{
    MAX_RETAINED_SUPERVISOR_PLAN_BYTES, RetainedDiscoveryRequest, RetainedSupervisorPlan,
};
use super::{Error, RETAINED_DETECTION_REQUEST_SCHEMA, Result, RetainedDetectionRequest};

impl RetainedDetectionRequest {
    /// Verify exact wrapper bytes before parsing or deployment access. The nested existing plan
    /// must have empty event and observation selections. Duplicate and unknown keys are refused.
    pub fn from_json(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RETAINED_SUPERVISOR_PLAN_BYTES {
            return Err(Error::Limit("detector discovery request bytes"));
        }
        if expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(Error::Plan("detector discovery request byte digest"));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::Plan("detector discovery request UTF-8"))?;
        let document = parse(text).map_err(|_| Error::Plan("detector discovery request JSON"))?;
        let top = document
            .object()
            .ok_or(Error::Plan("detector discovery request object"))?;
        if top.len() != 3
            || top
                .keys()
                .any(|key| !["schema", "maximum_catalog_reports", "plan"].contains(&key.as_str()))
        {
            return Err(Error::Plan("detector discovery request fields"));
        }
        if top.get("schema").and_then(|v| v.text()) != Some(RETAINED_DETECTION_REQUEST_SCHEMA) {
            return Err(Error::Plan("detector discovery request schema"));
        }
        let maximum = top
            .get("maximum_catalog_reports")
            .and_then(|v| v.integer())
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(Error::Plan("detector discovery catalog bound"))?;
        let template = RetainedSupervisorPlan::from_value(
            top.get("plan")
                .ok_or(Error::Plan("detector discovery plan"))?,
        )?;
        Self::new(RetainedDiscoveryRequest::new(template, maximum)?)
    }
}
