#![forbid(unsafe_code)]
//! Keepalive selection belongs to the native capture owner, before automatic control.

use super::*;
use fss_reference::rtsp::client::ClientError;
use fss_reference::rtsp::hevc_client::HevcClientError;

fn due_command(f: &mut Fixture) -> Test<(u64, QueuedHevcRequest, Vec<u8>)> {
    let due = f.driver.next_wake_ns().ok_or("keepalive wake")?;
    for _ in 0..16 {
        match f.poll(SocketReadiness::default(), due)? {
            Step::ProtocolQueued { transport: None } => {}
            Step::Capture {
                event,
                connection: None,
            } => {
                if let HevcCapturePoll::Receiver(source) = *event
                    && matches!(source.as_ref(), Event::Client { event, work: None }
                        if matches!(event.as_ref(), HevcClientPoll::KeepAliveDue))
                {
                    let (queued, wire) = f.command(due)?;
                    return Ok((due, queued, wire));
                }
            }
            _ => return Err("unexpected progress before keepalive due".into()),
        }
    }
    Err("keepalive due event was lost".into())
}

fn assert_wire(wire: &[u8], command: ClientCommand) -> Test {
    let text = std::str::from_utf8(wire)?;
    assert!(text.starts_with(&format!("{} ", command.wire_method())));
    assert!(text.contains("\r\nSession: test-session\r\n"));
    let (_, body) = text.split_once("\r\n\r\n").ok_or("request headers")?;
    assert!(body.is_empty());
    if command == ClientCommand::KeepAliveGetParameter {
        assert!(text.contains("\r\nContent-Length: 0\r\n"));
    }
    Ok(())
}

#[test]
fn both_keepalive_methods_preserve_source_closed_recordings_across_native_chunking() -> Test {
    let mut identities = Vec::new();
    for chunk in [1, 7, 4096] {
        for digest in [false, true] {
            for method in [
                ClientCommand::KeepAlive,
                ClientCommand::KeepAliveGetParameter,
            ] {
                let mut f = Fixture::playing_with_keepalive(chunk, digest, method)?;
                assert_eq!(f.driver.keepalive_command(), method);
                let (due, queued, wire) = due_command(&mut f)?;
                assert_eq!(queued.command, method);
                assert_wire(&wire, method)?;
                f.reply(
                    &response(queued.cseq, "Session: test-session\r\n", ""),
                    due + 1,
                    Expected::State(ClientState::Playing),
                )?;
                assert!(!f.driver.needs_credentials());
                assert!(f.windows.is_empty());
                assert!(f.timed.is_empty());

                assert_eq!(
                    f.feed(&packet(0, 0, false, &nals()?[0]).bytes, due + 10, true)?,
                    Stop::Pending
                );
                for (i, packet) in input()?.iter().enumerate() {
                    assert_eq!(
                        f.feed(&packet.bytes, due + 20 + u64::try_from(i)?, true)?,
                        Stop::Pending
                    );
                }
                f.peer.shutdown(Shutdown::Write)?;
                let mut ended = false;
                for _ in 0..1000 {
                    match f.drain(due + 40, true)? {
                        Stop::Ended => {
                            ended = true;
                            break;
                        }
                        Stop::Pending => std::thread::yield_now(),
                        _ => return Err("keepalive changed clean media drain".into()),
                    }
                }
                assert!(ended);
                assert_eq!(f.timed.len(), 4);
                assert_eq!(f.windows.len(), 2);
                assert_eq!(f.transport.len(), 1);
                assert!(f.transport[0].totals.peer_eof);
                assert!(f.connections.is_empty());
                for window in &f.windows {
                    verify_hevc_recording(window.manifest(), window.objects(), &scope()?)?;
                }
                identities.push(
                    f.windows
                        .iter()
                        .map(|window| window.manifest().root())
                        .collect::<Vec<_>>(),
                );
                assert!(f.driver.cancel().is_none());
            }
        }
    }
    assert!(identities.windows(2).all(|pair| pair[0] == pair[1]));
    Ok(())
}

#[test]
fn selection_is_pure_and_freezes_when_the_first_request_is_queued_before_any_write() -> Test {
    let mut f = Fixture::new(7)?;
    assert_eq!(f.driver.keepalive_command(), ClientCommand::KeepAlive);
    let totals = f.driver.totals();
    let steps = f.driver.remaining_steps();
    let checks = f.authority.checks.get();
    let wake = f.driver.next_wake_ns();
    for invalid in [
        ClientCommand::Options,
        ClientCommand::Describe,
        ClientCommand::Setup,
        ClientCommand::Play,
        ClientCommand::Teardown,
    ] {
        let failure = f
            .driver
            .select_keepalive(invalid)
            .err()
            .ok_or("invalid selection")?;
        assert_eq!(
            failure.reason,
            LiveHevcRecordingError::Network(LiveHevcError::Configuration)
        );
        assert!(failure.retirement.is_none());
        assert_eq!(f.driver.keepalive_command(), ClientCommand::KeepAlive);
        assert_eq!(f.driver.totals(), totals);
        assert_eq!(f.driver.remaining_steps(), steps);
        assert_eq!(f.driver.next_wake_ns(), wake);
        assert_eq!(f.authority.checks.get(), checks);
    }
    f.driver
        .select_keepalive(ClientCommand::KeepAliveGetParameter)?;
    assert_eq!(f.driver.totals(), totals);
    assert_eq!(f.driver.remaining_steps(), steps);
    assert_eq!(f.authority.checks.get(), checks);
    let Step::Queued(queued) = f.poll(SocketReadiness::default(), 0)? else {
        return Err("first automatic request was not queued".into());
    };
    assert_eq!(queued.command, ClientCommand::Describe);
    assert_eq!(f.driver.totals().ok_or("totals")?.sent_bytes, 0);
    let totals = f.driver.totals();
    let steps = f.driver.remaining_steps();
    let checks = f.authority.checks.get();
    for method in [
        ClientCommand::KeepAlive,
        ClientCommand::KeepAliveGetParameter,
    ] {
        let failure = f
            .driver
            .select_keepalive(method)
            .err()
            .ok_or("late selection")?;
        assert!(failure.retirement.is_none());
        assert_eq!(
            f.driver.keepalive_command(),
            ClientCommand::KeepAliveGetParameter
        );
        assert_eq!(f.driver.totals(), totals);
        assert_eq!(f.driver.remaining_steps(), steps);
        assert_eq!(f.authority.checks.get(), checks);
    }
    let retired = f.driver.cancel().ok_or("retirement")?;
    let connection = retired.connection.ok_or("connection")?;
    assert!(connection.transport.request.is_some());
    assert_eq!(connection.transport.totals.sent_bytes, 0);
    Ok(())
}

#[test]
fn challenged_get_parameter_reuses_its_method_and_original_deadline() -> Test {
    let method = ClientCommand::KeepAliveGetParameter;
    let mut f = Fixture::playing_with_keepalive(7, false, method)?;
    let (due, unsigned, wire) = due_command(&mut f)?;
    assert_wire(&wire, method)?;
    assert!(!std::str::from_utf8(&wire)?.contains("Authorization:"));
    let deadline = f.driver.next_wake_ns().ok_or("request deadline")?;
    assert_eq!(deadline, due + 10_000_000_000);
    let raw = challenge(unsigned.cseq, "test-realm");
    f.reply(&raw, due + 1, Expected::Challenge)?;
    let (answer, wire) = f.command(due + 2)?;
    assert_eq!(answer.command, method);
    assert!(answer.cseq > unsigned.cseq);
    assert_eq!(
        answer
            .challenge
            .as_ref()
            .ok_or("challenge lost")?
            .expose_wire(),
        raw
    );
    assert_wire(&wire, method)?;
    let text = std::str::from_utf8(&wire)?;
    assert!(text.contains("Authorization: Digest "));
    assert!(!text.contains("test-password"));
    assert_eq!(f.driver.next_wake_ns(), Some(deadline));
    f.reply(
        &response(answer.cseq, "Session: test-session\r\n", ""),
        due + 3,
        Expected::State(ClientState::Playing),
    )?;
    assert_eq!(f.driver.keepalive_command(), method);
    assert!(!f.driver.needs_credentials());
    let retired = f.driver.cancel().ok_or("retirement")?;
    assert!(retired.connection.is_some());
    Ok(())
}

#[test]
fn rejected_get_parameter_preserves_the_response_and_never_falls_back_to_options() -> Test {
    let method = ClientCommand::KeepAliveGetParameter;
    let mut f = Fixture::playing_with_keepalive(7, true, method)?;
    let (due, queued, wire) = due_command(&mut f)?;
    assert_wire(&wire, method)?;
    let sent = f.driver.totals().ok_or("totals")?.sent_bytes;
    let raw = format!(
        "RTSP/1.0 405 Method Not Allowed\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n",
        queued.cseq
    )
    .into_bytes();
    f.peer.write_all(&raw)?;
    let mut stopped = false;
    for _ in 0..1000 {
        match f.drain(due + 1, true)? {
            Stop::Stopped => {
                stopped = true;
                break;
            }
            Stop::Pending => std::thread::yield_now(),
            _ => return Err("rejected keepalive did not stop capture".into()),
        }
    }
    assert!(stopped);
    let Some(HevcCapturePoll::Stopped { retained, .. }) = &f.terminal else {
        return Err("missing stopped capture".into());
    };
    let Some(Event::Client { event, .. }) = retained.event.as_deref() else {
        return Err("rejected control event was lost".into());
    };
    let HevcClientPoll::Fault {
        reason,
        source: Some(source),
        ..
    } = event.as_ref()
    else {
        return Err("rejected response was lost".into());
    };
    assert_eq!(
        *reason,
        HevcClientError::Session(ClientError::Rejected(405))
    );
    assert_eq!(source.expose_wire(), raw);
    assert_eq!(f.transport.len(), 1);
    assert_eq!(f.transport[0].totals.sent_bytes, sent);
    assert_eq!(f.driver.keepalive_command(), method);
    assert!(!f.driver.needs_credentials());
    assert!(f.driver.cancel().is_none());
    assert!(f.windows.is_empty());
    Ok(())
}
