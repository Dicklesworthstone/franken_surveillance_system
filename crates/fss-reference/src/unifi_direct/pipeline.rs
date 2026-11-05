#![forbid(unsafe_code)]
//! Task-owned UniFi TCP source, FLV framing and in-memory segment composition.
//!
//! This does not establish peer identity, listen for connections, publish
//! objects, or prove continuity. The caller must bind the source and recorder
//! to one authorized camera connection and generation, and retain or explicitly
//! account for every transferred source record and retirement remainder.

use super::{ingress, recording};
use asupersync::Cx;
use fss_container::InitializationSegment;
use fss_core::TimestampNs;
use fss_runtime::execution::TaskCx;
use std::fmt;

/// One bounded source and recorder step.
#[must_use]
#[derive(Debug)]
pub enum Step {
    /// One original-source or in-memory fragment result from the recorder.
    Recording(recording::Push),
    /// Bytes were appended but no complete source record is ready.
    Progress {
        /// Original bytes appended to the framer.
        appended: usize,
    },
    /// The peer closed its send side; retire to recover the unparsed tail.
    Eof,
    /// The configured connection byte limit was reached; retire the owner.
    LimitReached,
}

/// A refusal. A recording refusal may own an unaccepted original record.
#[must_use]
#[derive(Debug)]
pub enum Error {
    /// Source authority, framing, or I/O failed; source remains owned.
    Ingress(ingress::Error),
    /// The recorder refused a record; preserve `unaccepted` and retire.
    Recording(recording::Refusal),
    /// This owner has already ended or encountered a refusal.
    Stopped,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ingress(error) => write!(f, "UniFi recording source: {error}"),
            Self::Recording(refusal) => write!(f, "UniFi recording: {}", refusal.reason),
            Self::Stopped => write!(f, "UniFi recording owner stopped"),
        }
    }
}
impl std::error::Error for Error {}

/// Untransferred original source and recorder state at shutdown.
#[must_use]
#[derive(Debug)]
pub struct Retirement {
    /// Remaining TCP chunk and unparsed framing bytes.
    pub ingress: ingress::Retirement,
    /// Records held for the unfinished fragment.
    pub recorder: recording::Retirement,
}

/// One caller-bound source connection and recorder generation.
pub struct Pipeline {
    ingress: ingress::DirectIngress,
    recorder: recording::Recorder,
    stopped: bool,
}
impl Pipeline {
    /// Attach a recorder to a caller-owned ingress without performing I/O.
    /// The caller must bind both to the same authorized connection and generation.
    pub fn new(ingress: ingress::DirectIngress, recorder: recording::Recorder) -> Self {
        Self {
            ingress,
            recorder,
            stopped: false,
        }
    }

    /// Current in-memory MP4 initialization, if a configuration was observed.
    /// The caller must retain source custody and publish it before fragments.
    pub fn initialization(&self) -> Option<&InitializationSegment> {
        self.recorder.initialization()
    }

    /// Perform at most one source step and admit at most one resulting record.
    /// The caller supplies a current canonical timestamp, supervises the wait,
    /// and consumes each returned original record or explicit omission.
    pub async fn step(
        &mut self,
        task: &TaskCx<'_>,
        cx: &Cx,
        now: TimestampNs,
    ) -> Result<Step, Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        let source = match self.ingress.step(task, cx, now).await {
            Ok(source) => source,
            Err(error) => {
                self.stopped = true;
                return Err(Error::Ingress(error));
            }
        };
        match source {
            ingress::Step::Record(record) => match self.recorder.push(record) {
                Ok(result) => Ok(Step::Recording(result)),
                Err(refusal) => {
                    self.stopped = true;
                    Err(Error::Recording(refusal))
                }
            },
            ingress::Step::Progress { appended } => Ok(Step::Progress { appended }),
            ingress::Step::Eof => {
                self.stopped = true;
                Ok(Step::Eof)
            }
            ingress::Step::LimitReached => {
                self.stopped = true;
                Ok(Step::LimitReached)
            }
        }
    }

    /// Close the source and transfer every owner-held original byte.
    /// Already returned source records and a refusal's unaccepted record remain
    /// the caller's responsibility; buffered source prefixes may overlap.
    pub fn retire(self) -> Retirement {
        Retirement {
            ingress: self.ingress.retire(),
            recorder: self.recorder.retire(),
        }
    }
}
