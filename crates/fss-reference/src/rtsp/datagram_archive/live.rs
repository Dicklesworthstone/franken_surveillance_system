#![forbid(unsafe_code)]
//! Native source custody before further media progress.
//! AVC retains its existing owner; HEVC and JPEG framed input use the same archive.

use super::source::probe;
use super::*;
use crate::rtsp::avc_client::InterleavedSource;
use crate::rtsp::tcp::TcpBinding;
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

#[path = "live/capture.rs"]
mod capture;
pub use capture::*;

impl DatagramArchive {
    /// Prepare one actual opaque interleaved source, including malformed/probation packets.
    /// Never supply authentication or RTSP control-message bytes through this interface.
    pub fn prepare<'a>(
        &self,
        source: &'a InterleavedSource,
        budget: &mut WorkBudget<'_>,
    ) -> std::result::Result<PreparedDatagram<'a>, DatagramArchiveError> {
        self.prepare_bytes(
            source.channel(),
            source.received_ns(),
            source.payload(),
            budget,
        )
    }
}
