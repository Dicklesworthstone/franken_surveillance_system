#![forbid(unsafe_code)]
//! Ownership and capacity contracts for the UniFi session inbox.

use std::error::Error;

use fss_packet::extended_flv::{
    Limits,
    stream::{Framer, Next, SourceRecord},
};
use fss_reference::unifi_direct::{
    av_session_inbox::Inbox,
    av_unknown_worker_guard::{Advance, SessionDecision, SessionEvent, SessionObserver, Step},
    pipeline,
    recording::{Push, SourceDisposition},
    supervisor,
};

type Test = Result<(), Box<dyn Error>>;

fn header() -> Result<SourceRecord, Box<dyn Error>> {
    let mut framer = Framer::new(Limits::default(), 1024)?;
    framer.append(0, b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00")?;
    match framer.take()? {
        Next::Record(record) => Ok(record),
        Next::NeedMore => Err("header missing".into()),
    }
}

fn source_event(record: SourceRecord) -> SessionEvent {
    SessionEvent::Advance(Advance::Source(Step::Supervisor(supervisor::Step::Media(
        pipeline::Step::Recording(Push::Source {
            record,
            disposition: SourceDisposition::Header,
        }),
    ))))
}

fn source_bytes(event: &SessionEvent) -> Option<&[u8]> {
    match event {
        SessionEvent::Advance(Advance::Source(Step::Supervisor(supervisor::Step::Media(
            pipeline::Step::Recording(Push::Source { record, .. }),
        )))) => Some(record.bytes()),
        _ => None,
    }
}

#[test]
fn bounded_inbox_yields_and_preserves_original_source() -> Test {
    let mut inbox =
        Inbox::new("operation:camera-session", 7, 2, 13).map_err(|_| "inbox refused")?;
    assert_eq!(
        inbox.next_operation().ok_or("first id")?.as_str(),
        "operation:camera-session:0000000000000007"
    );
    assert_eq!(
        inbox.next_operation().ok_or("second id")?.as_str(),
        "operation:camera-session:0000000000000008"
    );
    assert_eq!(inbox.next_sequence(), Some(9));
    let decision = inbox
        .observe(source_event(header()?))
        .map_err(|_| "source refused")?;
    assert_eq!(decision, SessionDecision::Yield);
    assert_eq!((inbox.len(), inbox.source_bytes()), (1, 13));
    let event = inbox.take().ok_or("source missing")?;
    assert_eq!(
        source_bytes(&event),
        Some(b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00".as_slice())
    );
    assert!(inbox.is_empty());
    assert_eq!(inbox.source_bytes(), 0);
    Ok(())
}

#[test]
fn refusal_returns_original_event_and_queue_capacity_is_bounded() -> Test {
    let mut inbox = Inbox::new("operation:camera", 0, 1, 12).map_err(|_| "inbox refused")?;
    let event = match inbox.observe(source_event(header()?)) {
        Err(event) => event,
        Ok(_) => return Err("oversized record accepted".into()),
    };
    assert_eq!(source_bytes(&event).map(<[u8]>::len), Some(13));
    assert!(inbox.is_empty());
    assert_eq!(
        inbox
            .observe(SessionEvent::Advance(Advance::ArchiveStarted))
            .map_err(|_| "event refused")?,
        SessionDecision::Yield
    );
    let event = match inbox.observe(event) {
        Err(event) => event,
        Ok(_) => return Err("full inbox accepted source".into()),
    };
    assert_eq!(source_bytes(&event).map(<[u8]>::len), Some(13));
    assert!(matches!(
        inbox.take(),
        Some(SessionEvent::Advance(Advance::ArchiveStarted))
    ));
    Ok(())
}

#[test]
fn operation_namespace_and_sequence_are_bounded() -> Test {
    assert!(Inbox::new("", 0, 1, 1).is_err());
    assert!(Inbox::new(&"x".repeat(112), 0, 1, 1).is_err());
    assert!(Inbox::new("invalid space", 0, 1, 1).is_err());
    assert!(Inbox::new("valid", 0, 0, 1).is_err());
    assert!(Inbox::new("valid", 0, 1, 0).is_err());
    let mut inbox = Inbox::new("session", u64::MAX, 1, 1).map_err(|_| "inbox refused")?;
    assert_eq!(
        inbox.next_operation().ok_or("last id")?.as_str(),
        "session:ffffffffffffffff"
    );
    assert!(inbox.next_operation().is_none());
    assert_eq!(inbox.next_sequence(), None);
    Ok(())
}
