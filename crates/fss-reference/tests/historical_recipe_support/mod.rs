#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Existing encoded-source fixture plus actual opaque source observations appended later.
#[path = "../reconstruction_operation/support.rs"]
mod operation_support;
pub use operation_support::*;
use fss_publication::{LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::avc_client::{AvcClientPoll, authenticated::DigestAvcPoll};
use fss_reference::rtsp::datagram_archive::{DatagramArchive, DatagramPin};

pub fn current(p: &LocalRootPublisher) -> Test<DatagramArchive> {
    Ok(DatagramArchive::recover(p, source_scope()?, limits().source, None, &NeverCancel, &mut work())?)
}

pub fn append_source(p: &mut LocalRootPublisher, channel: u8, payload: &[u8]) -> Test<DatagramPin> {
    let mut archive = current(p)?;
    let now = archive.records().last().map_or(Some(100), |r| r.received_ns.checked_add(1))
        .ok_or("fixture receive time overflow")?;
    // Only the actual existing parser constructs an InterleavedSource. A fresh fixture
    // parser is not a claim about a reopened physical camera or renewed network authority.
    let mut parser = source::playing()?;
    let mut events = Vec::new();
    source::send(&mut parser, &source::interleaved(channel, payload), 4096, now, &mut events)?;
    let mut seen = 0;
    for event in events {
        let original = match event {
            DigestAvcPoll::Client { event, .. } => match *event {
                AvcClientPoll::Rtp { source, .. } | AvcClientPoll::Rtcp { source, .. } => Some(source),
                AvcClientPoll::Fault { source, .. } => source,
                _ => None,
            },
            _ => None,
        };
        if let Some(original) = original {
            assert_eq!(original.payload(), payload);
            let plan = archive.prepare(&original, &mut work())?;
            archive.publish(&plan, p, &NeverCancel, &mut work())?;
            seen += 1;
        }
    }
    assert_eq!(seen, 1);
    Ok(archive.pin())
}

pub fn append_tail(p: &mut LocalRootPublisher) -> Test<DatagramPin> {
    // Intentionally invalid RTCP is still retained original evidence. It must not be
    // counted, interpreted, or made into a gap by a recipe selecting an earlier prefix.
    append_source(p, 1, &[0, 0, 0])
}
