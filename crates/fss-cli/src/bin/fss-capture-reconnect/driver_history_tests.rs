#![forbid(unsafe_code)]
//! Real native capture, durable history pins, cold source verification, and release barriers.

use super::*;
use fss_geometry::WorkBudget;
use fss_object::{ObjectManifest, SPOOL_OBJECTS_DIR};
use fss_publication::{LOCAL_SPOOL_DIR, NeverCancel, SlotName, read_verified};
use fss_reference::http_reconnect_history::{
    BoundaryOutcome, ReconnectHistoryLimits, ReconnectHistoryPin, VerifiedReconnectHistory,
};

fn durable(options: &mut Options) {
    options.history_work = Some(1_000_000_000_000);
    options.approve = Some(options.approval());
}
fn limits(options: &Options) -> ReconnectHistoryLimits {
    ReconnectHistoryLimits {
        archive: options.archive,
        maximum_reads: options.archive.maximum_reads as u64 * options.generations.len() as u64,
        maximum_bytes: options.archive.maximum_bytes * options.generations.len() as u64,
    }
}
fn quoted<'a>(text: &'a str, key: &str) -> Result<&'a str, io::Error> {
    let marker = format!("\"{key}\":\"");
    text.split_once(marker.as_str())
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(value, _)| value)
        .ok_or_else(|| io::Error::other("saved test pin field"))
}
fn pin(row: &str) -> Result<ReconnectHistoryPin, Box<dyn std::error::Error>> {
    let tail = row
        .split_once("\"history_pin\":{")
        .ok_or("saved history pin")?
        .1;
    let connections = tail
        .split_once("\"connections\":")
        .ok_or("saved connection count")?
        .1
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .ok_or("saved connection value")?
        .parse()?;
    Ok(ReconnectHistoryPin {
        session: ContentDigest::parse(quoted(tail, "session")?)?,
        root: ContentDigest::parse(quoted(tail, "root")?)?,
        connections,
    })
}
fn slot(options: &Options, ordinal: u32) -> Result<SlotName, Box<dyn std::error::Error>> {
    Ok(SlotName::parse(&format!(
        "fsshrb1-{}-{ordinal}",
        options
            .approval()
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))?)
}

#[test]
fn complete_and_truncated_connections_publish_cold_verified_history_before_reconnect() -> TestResult
{
    for truncate in [false, true] {
        let directory = Directory::new("history-cold")?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut options = options(
            &directory.0.join("archive"),
            listener.local_addr()?,
            "40,50",
            if truncate { "no" } else { "yes" },
        )?;
        durable(&mut options);
        let (server, clock) = serve(
            listener,
            vec![if truncate { truncated() } else { response() }, response()],
            NO_STALL,
        );
        let mut out = Vec::new();
        assert_eq!(capture_with(&options, &mut out, || &clock), Ok(true));
        assert_eq!(joined(server)?, 2);
        let text = String::from_utf8(out)?;
        let prepared: Vec<_> = text
            .lines()
            .filter(|row| row.contains("\"kind\":\"history_prepared\""))
            .map(pin)
            .collect::<Result<_, _>>()?;
        let saved: Vec<_> = text
            .lines()
            .filter(|row| row.contains("\"kind\":\"history_durable\""))
            .map(pin)
            .collect::<Result<_, _>>()?;
        assert_eq!(prepared, saved);
        assert_eq!(saved.len(), 2);
        assert_eq!(saved[1].connections, 2);
        assert_eq!(saved[1].session, options.approval());
        let first_prepared = text
            .find("\"kind\":\"history_prepared\"")
            .ok_or("prepared")?;
        let first_durable = text.find("\"kind\":\"history_durable\"").ok_or("durable")?;
        let connected: Vec<_> = text.match_indices("\"kind\":\"connected\"").collect();
        assert_eq!(connected.len(), 2);
        assert!(first_prepared < first_durable && first_durable < connected[1].0);
        assert!(text.contains("\"pending_boundary\":null"));
        assert!(text.contains("\"event_published\":false"));
        let publisher = LocalRootPublisher::open(&options.root, storage_limits(&options))?;
        let history = VerifiedReconnectHistory::load(
            &publisher,
            saved[1],
            limits(&options),
            &NeverCancel,
            &mut WorkBudget::new(1_000_000_000_000),
        )?;
        assert_eq!(history.boundaries().len(), 2);
        assert_eq!(history.boundaries()[0].scope().stream.generation, 40);
        assert_eq!(history.boundaries()[1].scope().stream.generation, 50);
        assert_eq!(
            history.boundaries()[0].outcome(),
            if truncate {
                BoundaryOutcome::SourceFailed
            } else {
                BoundaryOutcome::NativeComplete
            }
        );
        assert_eq!(history.boundaries()[1].prior(), Some(saved[0]));
        // A fresh process may inspect this exact pin; it may not reacquire the occupied session.
        drop(publisher);
        let mut retry = Vec::new();
        assert_eq!(capture(&options, &mut retry), Ok(false));
        let retry = String::from_utf8(retry)?;
        assert!(retry.contains("Occupied"));
        assert!(retry.contains("\"connect_attempts\":0"));
    }
    Ok(())
}

struct RefusingSink {
    kind: &'static str,
    bytes: Vec<u8>,
}
impl Write for RefusingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let marker = format!("\"kind\":\"{}\"", self.kind);
        if bytes
            .windows(marker.len())
            .any(|part| part == marker.as_bytes())
        {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn refused_prepared_or_durable_output_never_releases_the_next_generation() -> TestResult {
    for kind in ["history_prepared", "history_durable"] {
        let directory = Directory::new("history-output")?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut options = options(
            &directory.0.join("archive"),
            listener.local_addr()?,
            "1,2",
            "yes",
        )?;
        durable(&mut options);
        let (server, clock) = serve(listener, vec![response(), response()], NO_STALL);
        let mut out = RefusingSink {
            kind,
            bytes: Vec::new(),
        };
        assert_eq!(
            capture_with(&options, &mut out, || &clock),
            Err("ERR-CAPTURE-RECONNECT-OUTPUT-001")
        );
        assert_eq!(joined(server)?, 1);
        let text = String::from_utf8(out.bytes)?;
        assert_eq!(text.matches("\"kind\":\"connected\"").count(), 1);
        assert!(!text.contains("\"kind\":\"finish\""));
        let publisher = LocalRootPublisher::open(&options.root, storage_limits(&options))?;
        if kind == "history_prepared" {
            assert!(publisher.root(&slot(&options, 1)?).is_none());
        } else {
            let expected = pin(text
                .lines()
                .find(|row| row.contains("\"kind\":\"history_prepared\""))
                .ok_or("prepared pin before lost output")?)?;
            let history = VerifiedReconnectHistory::load(
                &publisher,
                expected,
                limits(&options),
                &NeverCancel,
                &mut WorkBudget::new(1_000_000_000_000),
            )?;
            assert_eq!(history.boundaries().len(), 1);
            assert_eq!(history.boundaries()[0].scope().stream.generation, 1);
        }
        assert!(publisher.root(&slot(&options, 2)?).is_none());
    }
    Ok(())
}

struct DamagingSink<'a> {
    options: &'a Options,
    bytes: Vec<u8>,
    damaged: bool,
}
impl Write for DamagingSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.damaged {
            return Ok(());
        }
        let text = std::str::from_utf8(&self.bytes).map_err(io::Error::other)?;
        let Some(row) = text
            .lines()
            .find(|row| row.contains("\"kind\":\"history_durable\""))
        else {
            return Ok(());
        };
        let damage = (|| -> TestResult {
            let expected = pin(row)?;
            assert_eq!(expected.connections, 1);
            // Inspect exact retained manifests without opening a second publisher: the live
            // capture owner still holds its exclusive storage lock at this deliberate cut.
            let read = |digest| {
                read_verified(
                    &self.options.root,
                    digest,
                    self.options.archive.maximum_spool_object_bytes,
                )
            };
            let history = ObjectManifest::from_canonical_bytes(&read(expected.root)?)?;
            let wire_root = *history
                .children()
                .iter()
                .find(|digest| Some(**digest) != history.metadata_digest())
                .ok_or("original read root")?;
            let wire = ObjectManifest::from_canonical_bytes(&read(wire_root)?)?;
            let digest = *wire
                .children()
                .iter()
                .find(|digest| Some(**digest) != wire.metadata_digest())
                .ok_or("original bytes")?;
            assert!(!read(digest)?.is_empty());
            let path = self
                .options
                .root
                .join(LOCAL_SPOOL_DIR)
                .join(SPOOL_OBJECTS_DIR)
                .join(
                    digest
                        .bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                );
            let mut bytes = fs::read(&path)?;
            *bytes.last_mut().ok_or("nonempty raw read")? ^= 0x80;
            fs::write(path, bytes)?;
            Ok(())
        })();
        damage.map_err(|e| io::Error::other(e.to_string()))?;
        self.damaged = true;
        Ok(())
    }
}

#[test]
fn original_damage_after_durable_output_prevents_reconnect_and_preserves_pending_pin() -> TestResult
{
    let directory = Directory::new("history-source-damage")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut options = options(
        &directory.0.join("archive"),
        listener.local_addr()?,
        "10,20",
        "yes",
    )?;
    durable(&mut options);
    let (server, clock) = serve(listener, vec![response(), response()], NO_STALL);
    let mut out = DamagingSink {
        options: &options,
        bytes: Vec::new(),
        damaged: false,
    };
    assert_eq!(capture_with(&options, &mut out, || &clock), Ok(false));
    assert_eq!(joined(server)?, 1);
    assert!(out.damaged);
    let text = String::from_utf8(out.bytes)?;
    assert_eq!(text.matches("\"kind\":\"connected\"").count(), 1);
    assert!(text.contains("\"publication_acknowledged\":true"));
    assert!(text.contains("\"pending_boundary\":{\"history_pin\":"));
    assert!(text.contains("ERR-CAPTURE-RECONNECT-SOURCE-001"));
    assert!(text.contains("\"request_satisfied\":false"));
    Ok(())
}

#[test]
fn exhausted_history_allowance_refuses_before_tcp_and_cannot_refill_on_a_new_slot() -> TestResult {
    let directory = Directory::new("history-budget")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let mut options = options(
        &directory.0.join("archive"),
        listener.local_addr()?,
        "10,20",
        "yes",
    )?;
    options.history_work = Some(1);
    options.approve = Some(options.approval());
    let mut out = Vec::new();
    assert_eq!(capture(&options, &mut out), Ok(false));
    assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    let text = String::from_utf8(out)?;
    assert!(text.contains("\"connect_attempts\":0"));
    assert!(text.contains("\"work_remaining\":0"));
    assert!(text.contains("\"last_durable\":null"));
    Ok(())
}

#[test]
fn requested_frame_stop_keeps_current_prefix_separate_from_ended_connection_history() -> TestResult
{
    let directory = Directory::new("history-stop")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut options = options(
        &directory.0.join("archive"),
        listener.local_addr()?,
        "10,20",
        "yes",
    )?;
    options.stop_after = Some(1);
    durable(&mut options);
    let (server, clock) = serve(listener, vec![response(), response()], NO_STALL);
    let mut out = Vec::new();
    assert_eq!(capture_with(&options, &mut out, || &clock), Ok(true));
    assert_eq!(joined(server)?, 1);
    let text = String::from_utf8(out)?;
    assert!(!text.contains("\"kind\":\"history_prepared\""));
    assert!(text.contains("\"status\":\"requested_count_reached\""));
    assert!(text.contains("\"frames_taken\":1"));
    assert!(text.contains("\"last_durable\":null"));
    assert!(text.contains("\"pending_boundary\":null"));
    assert!(text.contains("\"current_prefix_separate\":true"));
    assert!(text.contains("\"capture_continuity\":false"));
    Ok(())
}
