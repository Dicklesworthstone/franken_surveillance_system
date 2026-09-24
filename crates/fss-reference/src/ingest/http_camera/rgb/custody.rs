#![forbid(unsafe_code)]
//! Retain an exact raw HTTP read durably before releasing its parse barrier.
//!
//! This composes the existing HttpWireArchive and LocalRootPublisher; it does not
//! create another storage format or treat an acknowledgement as a custody proof.

use super::{
    HttpCameraAuthority, HttpCameraError, HttpCameraOperation, HttpRgbCapture, HttpWireReceipt,
};
use crate::ingest::http_archive::{
    HttpArchiveError, HttpWireArchive, HttpWirePin, HttpWirePublication,
};
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, PublishCancellation};

/// A source/storage refusal leaves the raw read unacknowledged. Storage failures
/// can have staged/visible effects; retain the prepared pin for explicit recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRgbCustodyError {
    /// Existing live camera authority refused before storage publication.
    Source(HttpCameraError),
    /// No unacknowledged original socket read is currently held.
    NotPending,
    /// Prepared source or expected archive root changed; no storage write occurred.
    PlanMismatch,
    /// Existing archive refused; its explicit error and recovery semantics remain.
    Archive(HttpArchiveError),
}
impl From<HttpCameraError> for HttpRgbCustodyError {
    fn from(error: HttpCameraError) -> Self {
        Self::Source(error)
    }
}
impl From<HttpArchiveError> for HttpRgbCustodyError {
    fn from(error: HttpArchiveError) -> Self {
        Self::Archive(error)
    }
}
impl std::fmt::Display for HttpRgbCustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP RGB source custody refused: {self:?}")
    }
}
impl std::error::Error for HttpRgbCustodyError {}

/// Exact source and expected durable root prepared before storage I/O. Persist
/// the pin independently before commit to resolve lost acknowledgements. This
/// local key grants no camera, retention, filesystem or effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRgbWirePlan {
    wire: HttpWireReceipt,
    pin: HttpWirePin,
}
impl HttpRgbWirePlan {
    /// Original source range/hash/receive-time and stream generation.
    pub fn wire(self) -> HttpWireReceipt {
        self.wire
    }
    /// Expected exact post-publication prefix, not a claim it is already durable.
    pub fn expected_pin(self) -> HttpWirePin {
        self.pin
    }
}

/// Borrowed original archive and publisher plus their explicit live authority and
/// work bounds. Possessing this struct does not widen any owner's permissions.
pub struct HttpRgbCustody<'a, 'cx> {
    /// Existing bounded immutable-original inventory, including its exact scope.
    pub archive: &'a mut HttpWireArchive,
    /// Existing root-last publisher with its own exclusive filesystem ownership.
    pub publisher: &'a mut LocalRootPublisher,
    /// Live storage authorization/deadline/cancellation probe used by publication.
    pub cancellation: &'a dyn PublishCancellation,
    /// Hash, inventory, memory and I/O precharge allowance; never automatically reset.
    pub work: &'a mut WorkBudget<'cx>,
}

/// Durable storage succeeded. The separate camera acknowledgement may still have
/// failed because authority changed; never discard this publication or resend a
/// request merely because acknowledgement is Err. Source retirement remains valid.
#[derive(Debug)]
pub struct HttpRgbWireCommit {
    publication: HttpWirePublication,
    acknowledgement: Result<(), HttpCameraError>,
}
impl HttpRgbWireCommit {
    /// Actual root-last publication receipt, not just the prepared expectation.
    pub fn publication(&self) -> &HttpWirePublication {
        &self.publication
    }
    /// Whether the original camera's parse barrier was released under live authority.
    pub fn acknowledgement(&self) -> Result<(), HttpCameraError> {
        self.acknowledgement
    }
    /// Transfer both outcomes without hiding successful storage behind a later error.
    pub fn into_parts(self) -> (HttpWirePublication, Result<(), HttpCameraError>) {
        (self.publication, self.acknowledgement)
    }
}

impl HttpRgbCapture<'_, '_> {
    /// Prepare the exact currently held raw read using the existing archive. No
    /// filesystem operation, camera acknowledgement or parsing occurs. The caller
    /// retains expected_pin() before allowing publication to resolve a lost return.
    pub fn prepare_wire_custody(
        &mut self,
        archive: &HttpWireArchive,
        now: u64,
        auth: &dyn HttpCameraAuthority,
        work: &mut WorkBudget<'_>,
    ) -> Result<HttpRgbWirePlan, HttpRgbCustodyError> {
        self.camera.admit(HttpCameraOperation::Poll, now, auth)?;
        let read = self
            .camera
            .pending_wire()
            .filter(|read| !read.acknowledged())
            .ok_or(HttpRgbCustodyError::NotPending)?;
        let plan = archive.prepare(read, work)?;
        let result = HttpRgbWirePlan {
            wire: read.receipt(),
            pin: plan.pin(),
        };
        self.camera.admit(HttpCameraOperation::Poll, now, auth)?;
        Ok(result)
    }

    /// Revalidate original bytes and exact expected root, then durably publish
    /// before acknowledging the camera. Any outer error leaves the raw read held.
    /// A storage error can leave staged or visible objects; resolve the prepared
    /// pin with the existing publisher/recovery contract, never blindly reconnect.
    ///
    /// Once publication succeeds, its receipt is returned even when live camera
    /// acknowledgement fails. There is no fallible allocation after publication.
    pub fn retain_wire(
        &mut self,
        expected: HttpRgbWirePlan,
        now: u64,
        auth: &dyn HttpCameraAuthority,
        custody: HttpRgbCustody<'_, '_>,
    ) -> Result<HttpRgbWireCommit, HttpRgbCustodyError> {
        self.camera.admit(HttpCameraOperation::Poll, now, auth)?;
        let read = self
            .camera
            .pending_wire()
            .filter(|read| !read.acknowledged())
            .ok_or(HttpRgbCustodyError::NotPending)?;
        if read.receipt() != expected.wire {
            return Err(HttpRgbCustodyError::PlanMismatch);
        }
        let plan = custody.archive.prepare(read, custody.work)?;
        if plan.pin() != expected.pin {
            return Err(HttpRgbCustodyError::PlanMismatch);
        }
        let publication = custody.archive.publish(
            &plan,
            custody.publisher,
            custody.cancellation,
            custody.work,
        )?;
        // The existing camera checks live authority before accepting this exact
        // read. A post-publication refusal must not hide the successful disk write.
        let acknowledgement = self.camera.acknowledge_wire(expected.wire, now, auth);
        Ok(HttpRgbWireCommit {
            publication,
            acknowledgement,
        })
    }
}
