#![forbid(unsafe_code)]
//! The caller's keepalive method is a whole-run selection, including fresh generations.

use super::*;

fn keepalive(f: &mut Fixture) -> Test<u64> {
    let due = f.driver.next_wake_ns().ok_or("keepalive wake")?;
    let mut due_seen = false;
    for _ in 0..16 {
        match f.poll(SocketReadiness::default(), due)? {
            Step::ProtocolQueued { transport: None } => {}
            Step::Capture {
                event,
                connection: None,
            } => {
                if let HevcCapturePoll::Receiver(source) = *event {
                    if matches!(source.as_ref(), Event::Client { event, work: None }
                        if matches!(event.as_ref(), HevcClientPoll::KeepAliveDue))
                    {
                        due_seen = true;
                        break;
                    }
                }
            }
            _ => return Err("unexpected progress before supervised keepalive".into()),
        }
    }
    assert!(due_seen);
    let (queued, wire) = f.command(due)?;
    assert_eq!(queued.command, ClientCommand::KeepAliveGetParameter);
    let text = std::str::from_utf8(&wire)?;
    assert!(text.starts_with("GET_PARAMETER "));
    assert!(text.contains("\r\nSession: test-session\r\n"));
    assert!(text.contains("\r\nContent-Length: 0\r\n"));
    assert!(text.ends_with("\r\n\r\n"));
    f.reply(
        &response(queued.cseq, "Session: test-session\r\n", ""),
        due + 1,
        Expected::State(ClientState::Playing),
    )?;
    assert!(!f.driver.needs_credentials());
    Ok(due)
}

#[test]
fn selection_before_the_first_attempt_is_pure_and_connect_freezes_it_before_control_io() -> Test {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let (live, recording, authority) = configs(listener.local_addr()?, 7, 1)?;
    let budget = ReconnectBudget::for_attempts(live.transport, live.max_steps, 2)?;
    let mut driver =
        SupervisedHevcRecording::new_with_budget(live.binding.clone(), policy(), budget, 0)?;
    assert_eq!(driver.keepalive_command(), ClientCommand::KeepAlive);
    let resources = driver.resource_budget();
    let status = driver.status();
    let wake = driver.next_wake_ns();
    for invalid in [
        ClientCommand::Options,
        ClientCommand::Describe,
        ClientCommand::Setup,
        ClientCommand::Play,
        ClientCommand::Teardown,
    ] {
        assert_eq!(
            driver.select_keepalive(invalid),
            Err(ReconnectRefusal::Configuration)
        );
        assert_eq!(driver.keepalive_command(), ClientCommand::KeepAlive);
        assert_eq!(driver.resource_budget(), resources);
        assert_eq!(driver.status(), status);
        assert_eq!(driver.next_wake_ns(), wake);
        assert!(driver.totals().is_none());
    }
    driver.select_keepalive(ClientCommand::KeepAliveGetParameter)?;
    driver.select_keepalive(ClientCommand::KeepAlive)?;
    driver.select_keepalive(ClientCommand::KeepAliveGetParameter)?;
    assert_eq!(driver.resource_budget(), resources);
    assert_eq!(driver.status(), status);
    assert_eq!(driver.next_wake_ns(), wake);
    assert_eq!(
        listener
            .accept()
            .err()
            .ok_or("selection opened a socket")?
            .kind(),
        ErrorKind::WouldBlock
    );
    driver.connect(live, recording, 0, &authority)?;
    let (_peer, _) = listener.accept()?;
    let resources = driver.resource_budget();
    let totals = driver.totals().ok_or("totals")?;
    assert_eq!(totals.sent_bytes, 0);
    assert_eq!(totals.read_calls, 0);
    for method in [
        ClientCommand::KeepAlive,
        ClientCommand::KeepAliveGetParameter,
    ] {
        assert_eq!(
            driver.select_keepalive(method),
            Err(ReconnectRefusal::Scope)
        );
        assert_eq!(driver.resource_budget(), resources);
        assert_eq!(driver.totals(), Some(totals));
        assert_eq!(
            driver.keepalive_command(),
            ClientCommand::KeepAliveGetParameter
        );
    }
    assert!(driver.cancel().is_some());
    assert_eq!(
        driver.select_keepalive(ClientCommand::KeepAliveGetParameter),
        Err(ReconnectRefusal::Scope)
    );
    assert_eq!(driver.resource_budget(), resources);
    Ok(())
}

#[test]
fn get_parameter_survives_real_eof_drain_backoff_and_fresh_generation_authentication() -> Test {
    for chunk in [1, 7, 4096] {
        for digest in [false, true] {
            let method = ClientCommand::KeepAliveGetParameter;
            let mut f = Fixture::new_with_keepalive(chunk, 2, method)?;
            f.negotiate(digest, 0)?;
            assert_eq!(f.driver.keepalive_command(), method);
            let due = keepalive(&mut f)?;
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
            assert_eq!(f.drain(due + 40, true, f.raw.len(), true)?, Stop::Ended);
            let old_key = f.authority.binding.key();
            assert_eq!(f.driver.status(), ReconnectStatus::Retired(old_key));
            assert_eq!(f.timed.len(), 4);
            assert_eq!(f.windows.len(), 2);
            assert_eq!(f.transports.len(), 1);
            assert!(f.transports[0].totals.peer_eof);
            let resources = f.driver.resource_budget();
            let roots: Vec<_> = f
                .windows
                .iter()
                .map(|window| window.manifest().root())
                .collect();
            assert_eq!(
                f.driver.select_keepalive(ClientCommand::KeepAlive),
                Err(ReconnectRefusal::Scope)
            );
            f.driver.acknowledge_retirement(due + 100, &f.authority)?;
            assert_eq!(f.driver.next_wake_ns(), Some(due + 110));
            for method in [
                ClientCommand::KeepAlive,
                ClientCommand::KeepAliveGetParameter,
            ] {
                assert_eq!(
                    f.driver.select_keepalive(method),
                    Err(ReconnectRefusal::Scope)
                );
                assert_eq!(f.driver.resource_budget(), resources);
                assert_eq!(
                    f.driver.keepalive_command(),
                    ClientCommand::KeepAliveGetParameter
                );
                assert_eq!(f.driver.next_wake_ns(), Some(due + 110));
                f.no_connection()?;
            }
            let (live, recording, authority) = configs(f.listener.local_addr()?, chunk, 2)?;
            let attempt = f.driver.connect(live, recording, due + 110, &authority)?;
            assert_eq!(attempt.ordinal, 2);
            assert_eq!(attempt.previous, Some((old_key, due + 100)));
            assert_eq!(attempt.key.generation, 2);
            let (peer, _) = f.listener.accept()?;
            setup_peer(&peer)?;
            f.peer = peer;
            f.authority = authority;
            f.negotiate(digest, due + 110)?;
            assert_eq!(f.driver.keepalive_command(), method);
            assert!(keepalive(&mut f)? > due);
            assert_eq!(f.driver.resource_budget().admitted_attempts(), 2);
            assert_eq!(
                roots,
                f.windows
                    .iter()
                    .map(|window| window.manifest().root())
                    .collect::<Vec<_>>()
            );
            for window in &f.windows {
                verify_hevc_recording(window.manifest(), window.objects(), &recording_scope(1)?)?;
                assert!(
                    verify_hevc_recording(
                        window.manifest(),
                        window.objects(),
                        &recording_scope(2)?
                    )
                    .is_err()
                );
            }
            let (key, retired) = f.driver.cancel().ok_or("second generation retirement")?;
            assert_eq!(key.generation, 2);
            assert!(retired.connection.is_some());
        }
    }
    Ok(())
}
