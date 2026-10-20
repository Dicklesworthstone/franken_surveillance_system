#![forbid(unsafe_code)]
//! Selected-SDP HEVC capture through the codec-pinned, independently journaled owner.

use fss_reference::rtsp::archive_pins::HevcArchivePinJournal;
use fss_reference::rtsp::hevc_client::pictures::{HevcPictureClientError, HevcPictureClientPoll};
use fss_reference::rtsp::hevc_client::{HevcClientError, HevcClientPoll};
use fss_reference::rtsp::hevc_recording_capture::live::AutomaticHevcRecordingStep;
use fss_reference::rtsp::hevc_recording_capture::{HevcCapturePoll, TimedHevcCapture};
use fss_reference::rtsp::hevc_recording_collector::HevcCollectionAdmission;
use fss_reference::rtsp::live_hevc::{LiveHevcError, LiveHevcStep};
use fss_reference::rtsp::live_hevc_archive::{
    JournaledLiveHevcArchive, LiveHevcArchiveError, LiveHevcArchiveFailure, LiveHevcArchiveStep,
};

use super::*;

#[path = "hevc_report.rs"]
mod reporting;
use reporting::released_bytes;

fn reason(error: &LiveHevcArchiveError) -> Failure {
    match error {
        LiveHevcArchiveError::Pins(_) | LiveHevcArchiveError::Archive(_) => Failure::Storage,
        LiveHevcArchiveError::Deadline
        | LiveHevcArchiveError::StoragePauseExpired
        | LiveHevcArchiveError::Authority(TcpDenial::Deadline) => Failure::Deadline,
        LiveHevcArchiveError::Authority(_) => Failure::Authority,
        LiveHevcArchiveError::WorkBudget => Failure::WorkBudget,
        LiveHevcArchiveError::Selection => Failure::Protocol,
        LiveHevcArchiveError::Network(error) => match error {
            LiveHevcError::Transport(
                TcpError::Deadline | TcpError::ReadDeadline | TcpError::Denied(TcpDenial::Deadline),
            ) => Failure::Deadline,
            LiveHevcError::Transport(TcpError::Denied(_)) => Failure::Authority,
            LiveHevcError::WorkBudget
            | LiveHevcError::Transport(TcpError::WorkBudget | TcpError::RequestBudget) => {
                Failure::WorkBudget
            }
            LiveHevcError::Protocol(HevcPictureClientError::Client(
                HevcClientError::Authentication(_) | HevcClientError::AuthenticationAtEof,
            )) => Failure::AuthenticationRefused,
            LiveHevcError::Transport(error) if abrupt_read_failure(error) => {
                Failure::ReadInterrupted
            }
            _ => Failure::Protocol,
        },
        LiveHevcArchiveError::Capture(CaptureError::Collection(CollectorError::Deadline)) => {
            Failure::Deadline
        }
        LiveHevcArchiveError::Capture(CaptureError::Collection(CollectorError::Timeline)) => {
            Failure::Timing
        }
        LiveHevcArchiveError::Capture(_) => Failure::Protocol,
        _ => Failure::State,
    }
}

#[cfg(test)]
#[test]
fn interruption_retry_hevc_mapping_preserves_source_failure_without_broad_io_retry() {
    for kind in [
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::NotConnected,
        io::ErrorKind::TimedOut,
        io::ErrorKind::WouldBlock,
    ] {
        for operation in [
            TcpOperation::Read,
            TcpOperation::Write,
            TcpOperation::Connect,
        ] {
            let transport = TcpError::Io { operation, kind };
            let expected = abrupt_read_failure(&transport);
            let error = LiveHevcArchiveError::Network(LiveHevcError::Transport(transport));
            let classified = reason(&error);
            assert_eq!(matches!(classified, Failure::ReadInterrupted), expected);
            assert_eq!(classified.code(), Failure::Protocol.code());
        }
    }
}

fn failure(error: LiveHevcArchiveFailure, stats: &mut Statistics) -> Failure {
    if let Some(retired) = &error.retirement {
        stats.hevc_retirement(retired);
    }
    reason(&error.reason)
}

fn backpressure(error: &LiveHevcArchiveFailure) -> bool {
    error.retirement.is_none()
        && matches!(
            &error.reason,
            LiveHevcArchiveError::Backpressure
                | LiveHevcArchiveError::Capture(CaptureError::Backpressure)
                | LiveHevcArchiveError::Capture(CaptureError::Collection(
                    CollectorError::Backpressure
                ))
                | LiveHevcArchiveError::Network(LiveHevcError::Backpressure)
                | LiveHevcArchiveError::Network(LiveHevcError::Protocol(
                    HevcPictureClientError::Backpressure
                ))
                | LiveHevcArchiveError::Network(LiveHevcError::Protocol(
                    HevcPictureClientError::Client(HevcClientError::Backpressure)
                ))
        )
}

fn client_failure(error: &HevcClientError) -> Failure {
    match error {
        HevcClientError::Authentication(_) | HevcClientError::AuthenticationAtEof => {
            Failure::AuthenticationRefused
        }
        _ => Failure::Protocol,
    }
}

/// Observe an original control/receiver event once, without printing its source bytes.
fn receiver<W: Write>(
    event: &HevcPictureClientPoll,
    options: &Options,
    stats: &mut Statistics,
    log: &mut Transcript<'_, W>,
) -> Result<(), Failure> {
    stats.hevc_event(event);
    match event {
        HevcPictureClientPoll::Client { event, .. } => match event.as_ref() {
            HevcClientPoll::AuthenticationRequired { .. } => {
                if options.authentication.is_none() {
                    return Err(Failure::Authentication);
                }
                stats.authentication_challenges += 1;
            }
            HevcClientPoll::Control {
                progress: ClientProgress::Accepted(state),
                ..
            } => {
                log.emit(
                    "protocol",
                    object(&[("state", string(state_name(*state)))]),
                    false,
                )?;
            }
            HevcClientPoll::Fault { reason, .. } => return Err(client_failure(reason)),
            HevcClientPoll::Rtp {
                retirement: Some(_),
                ..
            } => return Err(Failure::Protocol),
            HevcClientPoll::Ended { .. } => stats.input_ended = true,
            _ => {}
        },
        HevcPictureClientPoll::Fault { reason, .. } => {
            return Err(match reason {
                HevcPictureClientError::Client(error) => client_failure(error),
                _ => Failure::Protocol,
            });
        }
        _ => {}
    }
    Ok(())
}

fn begin_drain(
    capture: &mut JournaledLiveHevcArchive<'_, '_>,
    owner: &Owner<'_, '_>,
    stats: &mut Statistics,
) -> Result<(), Failure> {
    let retired = capture
        .finish_capture(owner.now()?, owner, owner)
        .map_err(|error| failure(error, stats))?;
    if let Some(retired) = &retired {
        stats.hevc_recording_retirement(retired);
    }
    owner.begin_drain()
}

fn drive<W: Write>(
    options: &Options,
    source: &mut Option<SourceCustody>,
    capture: &mut JournaledLiveHevcArchive<'_, '_>,
    owner: &Owner<'_, '_>,
    mut entropy: Option<&mut Entropy>,
    stats: &mut Statistics,
    log: &mut Transcript<'_, W>,
) -> Result<(), Failure> {
    let namespace = options.pin_scope().archive_namespace;
    let output = ArchiveOutput {
        namespace,
        codec: "hevc",
        owner,
    };
    let unsigned = DigestCredentials::new("unused", "").map_err(|_| Failure::Configuration)?;
    let mut timing =
        FixedTiming::with_reorder(options.frame_duration, options.max_reorder_pictures)
            .map_err(|_| Failure::Timing)?;
    let mut ready = false;
    let mut sealing = false;
    let mut sealed = false;
    let mut draining = false;
    let mut stop_cause = None;
    let mut progress = RecordingProgress::new(owner.supervision);
    loop {
        if stats.steps >= options.max_steps {
            return Err(Failure::WorkBudget);
        }
        stats.steps += 1;
        stats.hevc_observe(capture);
        let now = owner.now()?;
        owner.preview_pump();
        if !draining && let Some(interruption) = capture.interruption() {
            // The native owner has already retired the socket and replay-verified
            // the collected prefix. Do not synthesize finish_capture, another
            // request, a fresh credential lease, or successful duration completion.
            // Unresolved display timing must still refuse before publication.
            timing.finish().map_err(|_| Failure::Timing)?;
            owner.begin_drain()?;
            draining = true;
            sealing = false;
            ready = false;
            log.emit(
                "recording_interrupted",
                object(&[
                    ("codec", string("hevc")),
                    ("operation", string("read")),
                    ("error_kind", string(&format!("{:?}", interruption.kind))),
                    ("collected_pictures", stats.collected_pictures.to_string()),
                    ("source_eof_asserted", "false".into()),
                    ("capture_complete", "false".into()),
                    ("absence_certifiable", "false".into()),
                ]),
                false,
            )?;
        }
        if !draining && now >= owner.live_deadline {
            return Err(Failure::Deadline);
        }
        if !sealing
            && !draining
            && !stats.input_ended
            && let Some(stall) = progress
                .observe(
                    now,
                    capture.state() == ClientState::Playing,
                    ready,
                    stats.collected_pictures,
                )
                .map_err(|_| Failure::State)?
        {
            if stats.collected_pictures != 0 {
                timing.finish().map_err(|_| Failure::Timing)?;
            }
            owner.admit_stall(stall, capture.requires_authentication(), log)?;
            // A planned duration is not a progress failure. Both use the same explicit
            // seal, original-source accounting, independent pins and final catalog drain.
            stop_cause = Some(stall.cause);
            sealing = true;
        }
        if stats.collected_pictures == options.stop_after_pictures && !draining {
            // Do not label a prefix complete while future display positions remain unresolved.
            // The approved picture ceiling never grows implicitly to close a reorder group.
            timing.finish().map_err(|_| Failure::Timing)?;
            sealing = true;
        }
        if sealing && ready && !sealed {
            match capture.seal(now, owner, owner) {
                Ok(outcome) => {
                    stats.released_rtp_bytes += released_bytes(&outcome.released);
                    if outcome.window_ready {
                        sealed = true;
                        ready = false;
                    } else if stats.durable_pictures == stats.collected_pictures {
                        sealed = true;
                    } else {
                        return Err(Failure::State);
                    }
                }
                Err(error) if backpressure(&error) => ready = false,
                Err(error) => return Err(failure(error, stats)),
            }
        }
        if sealing && sealed && ready && !draining {
            if stats.durable_pictures != stats.collected_pictures {
                return Err(Failure::State);
            }
            begin_drain(capture, owner, stats)?;
            draining = true;
            ready = false;
        }
        // The automatic native owner must never receive placeholder credentials for a held
        // challenge, even when a camera chooses the unauthenticated placeholder realm.
        if capture.requires_authentication() && options.authentication.is_none() {
            return Err(Failure::Authentication);
        }
        let authenticated = if !sealing
            && !draining
            && capture.needs_credentials()
            && options.authentication.is_some()
        {
            Some(owner.authentication(entropy.as_deref_mut().ok_or(Failure::Entropy)?)?)
        } else {
            None
        };
        let (credentials, nonce) = authenticated
            .as_ref()
            .map_or((&unsigned, [0; 16]), |(credentials, nonce)| {
                (credentials, *nonce)
            });
        let step = match capture.poll(
            SocketReadiness {
                readable: !sealing && !draining,
                writable: !sealing && !draining,
            },
            credentials,
            nonce,
            owner.now()?,
            owner,
            owner,
        ) {
            Ok(step) => step,
            Err(error) if backpressure(&error) => continue,
            Err(error) => return Err(failure(error, stats)),
        };
        if let Err(error) = source_retention::observe_hevc(source, &step, owner, stats, log) {
            // The yielded native event may already own terminal state. Source
            // publication failure must not erase those obligations before cancel.
            match &step {
                LiveHevcArchiveStep::Recording(recording) => stats.hevc_stopped(recording),
                LiveHevcArchiveStep::Stopped { trigger, retained } => {
                    stats.hevc_stopped(trigger);
                    stats.hevc_retirement(retained);
                }
                _ => {}
            }
            return Err(error);
        }
        source_retention::account_pause(
            source,
            &mut progress,
            capture.state() == ClientState::Playing,
            ready,
            stats.collected_pictures,
        )?;
        match step {
            LiveHevcArchiveStep::Archive(progress) => match *progress {
                JournaledArchiveProgress::PinPersisted { receipt, .. } => {
                    stats.hevc_observe(capture);
                    log.emit(
                        "checkpoint_candidate",
                        object(&[
                            ("pin", pin_json(receipt.pin())),
                            ("journal_anchor", anchor_json(receipt.anchor())),
                            ("work_durable", "false".into()),
                        ]),
                        false,
                    )?;
                }
                JournaledArchiveProgress::WorkConfirmed {
                    work_receipt,
                    pin_receipt,
                    ..
                } => {
                    stats.hevc_observe(capture);
                    log.emit(
                        "checkpoint_durable",
                        object(&[
                            ("pin", pin_json(pin_receipt.pin())),
                            ("journal_anchor", anchor_json(pin_receipt.anchor())),
                            ("work_receipt", receipt_json(&work_receipt)),
                            ("normal_window_durable", "false".into()),
                        ]),
                        false,
                    )?;
                }
                JournaledArchiveProgress::Archive(progress) => {
                    archive_progress(
                        progress,
                        capture.snapshot(),
                        &output,
                        stats,
                        &mut ready,
                        log,
                    )?;
                }
            },
            LiveHevcArchiveStep::WindowAccepted(admission) => {
                let pending = capture.pending().ok_or(Failure::State)?;
                if pending.manifest().root() != admission.root || stats.pending_window.is_some() {
                    return Err(Failure::State);
                }
                stats.pending_window =
                    Some((admission.root, pending.objects().source.len() as u64));
                stats.pending_source_only_nals = pending.source_only_nals() as u64;
                owner.preview_stage(pending.publication_plan());
                ready = false;
                if sealing && sealed && !draining {
                    // Retire input before the final window's first checkpoint. No EOF boundary,
                    // new picture, network request or timing assertion is invented by this stop.
                    begin_drain(capture, owner, stats)?;
                    draining = true;
                }
                log.emit(
                    "window_accepted",
                    object(&[
                        ("ordinal", admission.ordinal.to_string()),
                        ("slot", string(admission.slot.as_str())),
                        ("root", string(&admission.root.to_text())),
                        ("durable", "false".into()),
                    ]),
                    false,
                )?;
            }
            LiveHevcArchiveStep::Finished { archive, cause } => {
                archive_progress(archive, capture.snapshot(), &output, stats, &mut ready, log)?;
                stats.hevc_observe(capture);
                if stats.collected_pictures != 0 {
                    timing.finish().map_err(|_| Failure::Timing)?;
                }
                return finish_attempt(cause, stop_cause, stats, options.stop_after_pictures, log);
            }
            LiveHevcArchiveStep::Recording(step) => match *step {
                AutomaticHevcRecordingStep::Queued(request) => {
                    let response = request.challenge.is_some();
                    let digest = response || stats.authentication_responses != 0;
                    if response {
                        stats.authentication_responses += 1;
                    }
                    if digest {
                        stats.digest_requests += 1;
                    }
                    log.emit(
                        "request_queued",
                        object(&[
                            ("command", string(command_name(request.command))),
                            ("method", string(request.command.wire_method())),
                            ("cseq", request.cseq.to_string()),
                            ("bytes", request.bytes.to_string()),
                            (
                                "authentication",
                                string(if digest { "digest" } else { "none" }),
                            ),
                            ("challenge_response", response.to_string()),
                        ]),
                        false,
                    )?;
                }
                AutomaticHevcRecordingStep::Network(step) => match step {
                    LiveHevcStep::Protocol { event, transport } => {
                        if let Some(transport) = &transport {
                            stats.hevc_transport(transport);
                        }
                        receiver(&event, options, stats, log)?;
                    }
                    LiveHevcStep::InputEnded => {
                        stats.input_ended = true;
                        log.emit(
                            "network_input_ended",
                            object(&[("capture_drained", "false".into())]),
                            false,
                        )?;
                    }
                    LiveHevcStep::Pending(wait) => owner.pause(wait.wake_at_ns)?,
                    LiveHevcStep::Ended => return Err(Failure::Protocol),
                    _ => {}
                },
                AutomaticHevcRecordingStep::ProtocolQueued { transport } => {
                    if let Some(transport) = &transport {
                        stats.hevc_transport(transport);
                    }
                }
                AutomaticHevcRecordingStep::Capture { event, connection } => {
                    if let Some(connection) = &connection {
                        stats.hevc_connection_retirement(connection);
                    }
                    match *event {
                        HevcCapturePoll::TimingRequired(request) => {
                            if sealing || draining {
                                return Err(Failure::State);
                            }
                            let selected =
                                timing.observe_hevc(request).map_err(|_| Failure::Timing)?;
                            let TimedHevcCapture { admission, event } = capture
                                .supply_timing(selected, owner.now()?, owner, owner)
                                .map_err(|error| failure(error, stats))?;
                            stats.hevc_event(&event);
                            match admission {
                                HevcCollectionAdmission::Accepted { released, .. } => {
                                    stats.released_rtp_bytes += released_bytes(&released);
                                    stats.collected_pictures += 1;
                                    log.emit(
                                        "picture_collected",
                                        object(&[
                                            ("picture", stats.collected_pictures.to_string()),
                                            ("rtp_timestamp", request.rtp_timestamp.to_string()),
                                            ("decode_time", selected.decode_time.to_string()),
                                            ("duration", selected.duration.to_string()),
                                            (
                                                "composition_offset",
                                                selected.composition_offset.to_string(),
                                            ),
                                            ("durable", "false".into()),
                                        ]),
                                        false,
                                    )?;
                                }
                                HevcCollectionAdmission::AwaitingIdr { released } => {
                                    stats.unselected_rtp_bytes += released_bytes(&released);
                                    stats.skipped_pictures += 1;
                                }
                            }
                        }
                        HevcCapturePoll::Receiver(event) => receiver(&event, options, stats, log)?,
                        HevcCapturePoll::Sealed(seal) => {
                            stats.released_rtp_bytes += released_bytes(&seal.released);
                            // Observed source end (EOF or EOB) seals only the complete prefix.
                            // Enter the drain allowance before admission/checkpoint I/O;
                            // physical TCP EOF is reported separately from the socket receipt.
                            stats.input_ended = true;
                            owner.begin_drain()?;
                            draining = true;
                        }
                        HevcCapturePoll::Ended { retained } => {
                            if let Some(retained) = &retained {
                                stats.hevc_capture_retirement(retained);
                            }
                            stats.input_ended = true;
                            owner.begin_drain()?;
                            draining = true;
                            ready = false;
                        }
                        HevcCapturePoll::Stopped { retained, .. } => {
                            stats.hevc_capture_retirement(&retained);
                            return Err(Failure::Protocol);
                        }
                        HevcCapturePoll::Window(window) => {
                            stats.prepared(window.publication_plan());
                            return Err(Failure::State);
                        }
                        HevcCapturePoll::Backpressure { .. } => return Err(Failure::Protocol),
                        HevcCapturePoll::Pending { .. } => {}
                    }
                }
                AutomaticHevcRecordingStep::Ended => return Err(Failure::Protocol),
            },
            LiveHevcArchiveStep::Stopped { trigger, retained } => {
                stats.hevc_stopped(&trigger);
                stats.hevc_retirement(&retained);
                return Err(reporting::stopped_failure(&trigger));
            }
            LiveHevcArchiveStep::Ended => return Err(Failure::State),
        }
        if owner.supervision.is_some() && !sealing && !draining && !stats.input_ended {
            let _ = progress
                .observe(
                    owner.now()?,
                    capture.state() == ClientState::Playing,
                    ready,
                    stats.collected_pictures,
                )
                .map_err(|_| Failure::State)?;
        }
    }
}

pub(super) fn run<W: Write>(
    options: &Options,
    pin_root: &Path,
    publisher: &mut LocalRootPublisher,
    owner: &Owner<'_, '_>,
    entropy: Option<&mut Entropy>,
    stats: &mut Statistics,
    log: &mut Transcript<'_, W>,
    source: &mut Option<SourceCustody>,
) -> Result<(), Failure> {
    let mut pins =
        HevcArchivePinJournal::create(pin_root, options.pin_scope(), options.pin_limits(), owner)
            .map_err(|_| Failure::Storage)?;
    stats.journal_anchor = Some(pins.anchor());
    stats.pins = pins.state().clone();
    let live = options
        .hevc_live_config()
        .map_err(|_| Failure::Configuration)?;
    let archive = options
        .hevc_archive_config()
        .map_err(|_| Failure::Configuration)?;
    let supplied = options
        .hevc_supplied_recording_config()
        .map_err(|_| Failure::Configuration)?;
    let mut capture = if let Some(recording) = supplied {
        JournaledLiveHevcArchive::connect_with_configuration(
            live,
            recording,
            archive,
            options.work_limits(),
            publisher,
            &mut pins,
            owner.now()?,
            owner,
            owner,
        )
    } else {
        JournaledLiveHevcArchive::connect(
            live,
            options
                .hevc_recording_config()
                .map_err(|_| Failure::Configuration)?,
            archive,
            options.work_limits(),
            publisher,
            &mut pins,
            owner.now()?,
            owner,
            owner,
        )
    }
    .map_err(|error| {
        stats.connection_attempted = error.connection_attempted;
        connect_failure(&error.reason)
    })?;
    stats.connection_attempted = true;
    // Pin the already-approved liveness method before the first automatic request.
    // Always run the normal retirement path, even if this pure selection is refused.
    let result = match capture.select_keepalive(options.keepalive) {
        Ok(()) => drive(options, source, &mut capture, owner, entropy, stats, log),
        Err(error) => Err(failure(error, stats)),
    };
    stats.hevc_observe(&capture);
    // Transfer all remaining ownership before any terminal sink operation.
    if let Some(retired) = capture.cancel() {
        stats.hevc_retirement(&retired);
    }
    result
}

// Only native Connect I/O, never an archive/authentication/authority refusal, can supply
// a transient observation. Existing single-attempt diagnostics retain their stable codes.
fn connect_failure(error: &LiveHevcArchiveError) -> Failure {
    match error {
        LiveHevcArchiveError::Pins(_) | LiveHevcArchiveError::Archive(_) => Failure::Storage,
        LiveHevcArchiveError::Network(LiveHevcError::Transport(TcpError::Io {
            operation: TcpOperation::Connect,
            kind:
                io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::TimedOut,
        })) => Failure::ConnectionUnavailable,
        _ => Failure::Connect,
    }
}

#[cfg(test)]
mod reconnect_tests {
    use super::*;

    #[test]
    fn timed_hevc_completion_requires_all_source_only_work_to_be_published() {
        let mut stats = Statistics {
            collected_pictures: 2,
            durable_pictures: 2,
            durable_windows: 1,
            indexed_windows: 1,
            snapshot_digest: Some(ContentDigest::sha256(b"finished HEVC archive")),
            ..Statistics::default()
        };
        assert!(
            finished_result(
                LiveArchiveCompletion::OwnerStopped,
                Some(StopCause::CaptureDuration),
                &stats,
                10,
            )
            .is_ok()
        );
        stats.pending_source_only_nals = 1;
        assert!(matches!(
            finished_result(
                LiveArchiveCompletion::OwnerStopped,
                Some(StopCause::CaptureDuration),
                &stats,
                10,
            ),
            Err(Failure::Storage)
        ));
    }

    #[test]
    fn only_typed_transient_connect_io_can_retry() {
        for operation in [
            TcpOperation::Connect,
            TcpOperation::Read,
            TcpOperation::Write,
        ] {
            for kind in [
                io::ErrorKind::ConnectionRefused,
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::ConnectionAborted,
                io::ErrorKind::TimedOut,
                io::ErrorKind::PermissionDenied,
                io::ErrorKind::InvalidInput,
            ] {
                let error = LiveHevcArchiveError::Network(LiveHevcError::Transport(TcpError::Io {
                    operation,
                    kind,
                }));
                assert_eq!(
                    matches!(connect_failure(&error), Failure::ConnectionUnavailable),
                    operation == TcpOperation::Connect
                        && matches!(
                            kind,
                            io::ErrorKind::ConnectionRefused
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::TimedOut
                        )
                );
            }
        }
        for denial in [
            TcpDenial::Unauthorized,
            TcpDenial::Revoked,
            TcpDenial::Cancelled,
            TcpDenial::Deadline,
            TcpDenial::Budget,
        ] {
            let error =
                LiveHevcArchiveError::Network(LiveHevcError::Transport(TcpError::Denied(denial)));
            assert!(matches!(connect_failure(&error), Failure::Connect));
        }
        for error in [
            LiveHevcArchiveError::Deadline,
            LiveHevcArchiveError::WorkBudget,
            LiveHevcArchiveError::Selection,
        ] {
            assert!(matches!(connect_failure(&error), Failure::Connect));
        }
    }
}
