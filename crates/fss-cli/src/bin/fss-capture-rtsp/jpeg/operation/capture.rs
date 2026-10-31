#![forbid(unsafe_code)]
//! One literal native connection; publish each actual datagram before the next protocol poll.

use super::*;
use crate::authentication::{CredentialLease, Entropy, SecretError};
use fss_reference::rtsp::RtspEvent;
use fss_reference::rtsp::client::{ClientCommand, ClientProgress, ClientState};
use fss_reference::rtsp::datagram_archive::DatagramArchive;
use fss_reference::rtsp::jpeg_client::{JpegClientPoll, JpegClientRetirement};
use fss_reference::rtsp::live_jpeg::{
    LiveJpegConnection, LiveJpegError, LiveJpegFailure, LiveJpegRetirement, LiveJpegStep,
};
use fss_reference::rtsp::tcp::{
    SocketReadiness, TcpAuthority, TcpBinding, TcpDenial, TcpOperation, TcpRetirement,
};

fn secret(error: SecretError) -> &'static str {
    match error {
        SecretError::Entropy => "ERR-CAPTURE-RTSP-ENTROPY-001",
        SecretError::Authority => "ERR-CAPTURE-RTSP-AUTHORITY-001",
        SecretError::Deadline => "ERR-CAPTURE-RTSP-DEADLINE-001",
        _ => "ERR-CAPTURE-RTSP-CREDENTIAL-001",
    }
}

struct Authority<'a> {
    owner: &'a dyn Owner,
    options: &'a Options,
    credential: Option<&'a CredentialLease>,
}
impl TcpAuthority for Authority<'_> {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), TcpDenial> {
        if binding != &self.options.scope.binding || deadline != self.options.timeout_ns {
            return Err(TcpDenial::Unauthorized);
        }
        let actual = self
            .owner
            .checkpoint(Effect::Network)
            .map_err(|_| TcpDenial::Cancelled)?;
        if actual < now || actual >= deadline {
            return Err(TcpDenial::Deadline);
        }
        if let Some(credential) = self.credential {
            credential
                .revalidate(&|| {
                    self.owner
                        .checkpoint(Effect::Secret)
                        .map(|_| ())
                        .map_err(|_| SecretError::Authority)
                })
                .map_err(|_| TcpDenial::Revoked)?;
        }
        Ok(())
    }
}

fn protocol_retired(report: &mut Report, retirement: &JpegClientRetirement) {
    report.remote_session_may_exist |= retirement.session.remote_session_may_exist;
    report.unretained_wire_bytes += retirement.wire.len() as u64;
    report.unretained_wire_bytes += retirement
        .retry
        .as_ref()
        .map_or(0, |f| f.expose_wire().len() as u64);
    if let Some(receiver) = &retirement.jpeg {
        retired(report, receiver);
    }
}
fn transport_retired(report: &mut Report, retirement: &TcpRetirement) {
    report.received_wire_bytes = retirement.totals.received_bytes;
    report.sent_wire_bytes = retirement.totals.sent_bytes;
    report.input_ended |= retirement.totals.peer_eof;
    report.unretained_wire_bytes += retirement
        .unread
        .as_ref()
        .map_or(0, |chunk| chunk.expose().len() as u64);
}
fn connection_retired(report: &mut Report, retirement: &LiveJpegRetirement) {
    protocol_retired(report, &retirement.protocol);
    transport_retired(report, &retirement.transport);
}
fn failure(report: &mut Report, failure: LiveJpegFailure) -> &'static str {
    if let Some(retirement) = failure.retirement {
        connection_retired(report, &retirement);
    }
    match failure.reason {
        LiveJpegError::WorkBudget => WORK,
        LiveJpegError::Configuration => STATE,
        _ => SOURCE,
    }
}

fn request(
    connection: &mut LiveJpegConnection,
    command: Option<ClientCommand>,
    authority: &Authority<'_>,
    entropy: &mut Option<Entropy>,
    report: &mut Report,
) -> Result<(), &'static str> {
    let now = authority.owner.checkpoint(Effect::Network)?;
    let result = if let Some(credential) = authority.credential {
        let check = || {
            authority
                .owner
                .checkpoint(Effect::Secret)
                .map(|_| ())
                .map_err(|_| SecretError::Authority)
        };
        credential.revalidate(&check).map_err(secret)?;
        let nonce = entropy
            .as_mut()
            .ok_or(STATE)?
            .next(&check)
            .map_err(secret)?;
        let credentials = credential.credentials().map_err(secret)?;
        match command {
            Some(command) => connection.request(command, &credentials, nonce, now, authority),
            None => connection.respond(&credentials, nonce, now, authority),
        }
    } else {
        let command = command.ok_or("ERR-CAPTURE-RTSP-AUTH-UNSUPPORTED-001")?;
        connection.request_unauthenticated(command, now, authority)
    };
    let _queued_request = result.map_err(|error| failure(report, error))?;
    Ok(())
}

pub(super) fn run(
    options: &Options,
    owner: &dyn Owner,
    out: &mut dyn Write,
    report: &mut Report,
    work: &mut WorkBudget<'_>,
    decode: &mut DecodeBudget<'_>,
) -> Result<(), &'static str> {
    let mut publisher = storage::open(options, owner)?;
    let mut archive =
        DatagramArchive::new(options.scope.clone(), options.archive).map_err(|_| STORAGE)?;
    report.pin = Some(archive.pin());
    let secret_check = || {
        owner
            .checkpoint(Effect::Secret)
            .map(|_| ())
            .map_err(|_| SecretError::Authority)
    };
    let credential = options
        .authentication
        .as_ref()
        .map(|a| CredentialLease::load(&a.credential_file, &secret_check))
        .transpose()
        .map_err(secret)?;
    let mut entropy = if credential.is_some() {
        Some(Entropy::open(&secret_check).map_err(secret)?)
    } else {
        None
    };
    let authority = Authority {
        owner,
        options,
        credential: credential.as_ref(),
    };
    let now = owner.checkpoint(Effect::Network)?;
    let mut connection = if credential.is_some() {
        LiveJpegConnection::connect(options.config(), now, &authority)
    } else {
        LiveJpegConnection::connect_unauthenticated(options.config(), now, &authority)
    }
    .map_err(|_| "ERR-CAPTURE-RTSP-CONNECT-001")?;
    let result = (|| {
        request(
            &mut connection,
            Some(ClientCommand::Describe),
            &authority,
            &mut entropy,
            report,
        )?;
        for _ in 0..options.max_steps {
            if report.pictures >= options.frames {
                return Ok(());
            }
            let now = owner.checkpoint(Effect::Network)?;
            report.steps += 1;
            let step = connection
                .poll(
                    SocketReadiness {
                        readable: true,
                        writable: true,
                    },
                    now,
                    &authority,
                )
                .map_err(|error| failure(report, error))?;
            match step {
                // The protocol owns the accepted bytes. This command deliberately stores
                // only typed interleaved datagrams, never opaque authentication/control TCP.
                LiveJpegStep::Wire(_) | LiveJpegStep::Write(_) => {}
                LiveJpegStep::InputEnded => report.input_ended = true,
                LiveJpegStep::Pending(wait) => owner.wait(wait.wake_at_ns)?,
                LiveJpegStep::Ended => return Err("ERR-CAPTURE-RTSP-SHORTFALL-001"),
                LiveJpegStep::Protocol { event, transport } => {
                    if let Some(transport) = transport {
                        transport_retired(report, &transport);
                    }
                    match *event {
                        JpegClientPoll::Control { progress, source } => match progress {
                            ClientProgress::Accepted(ClientState::Described) => {
                                work.charge(source.expose_wire().len() as u64)
                                    .map_err(|_| WORK)?;
                                let configuration = ContentDigest::sha256(source.expose_wire());
                                let selected = connection.media().ok_or(STATE)?;
                                report.configuration = Some(configuration);
                                report.reduced_rtcp = Some(selected.reduced_rtcp());
                                report.emit(
                                    owner,
                                    out,
                                    "configuration_accepted",
                                    object(&[
                                        (
                                            "configuration_evidence",
                                            string(&configuration.to_text()),
                                        ),
                                        ("payload_type", selected.payload_type().to_string()),
                                        ("reduced_rtcp", selected.reduced_rtcp().to_string()),
                                        ("description_bytes_retained", "false".into()),
                                        (
                                            "receive_clock",
                                            string(&options.scope.receive_clock.to_text()),
                                        ),
                                        ("capture_clock", "null".into()),
                                    ]),
                                )?;
                                request(
                                    &mut connection,
                                    Some(ClientCommand::Setup),
                                    &authority,
                                    &mut entropy,
                                    report,
                                )?;
                            }
                            ClientProgress::Accepted(ClientState::Ready) => request(
                                &mut connection,
                                Some(ClientCommand::Play),
                                &authority,
                                &mut entropy,
                                report,
                            )?,
                            _ => {}
                        },
                        JpegClientPoll::Rtp {
                            source,
                            admission,
                            retirement,
                        } => {
                            storage::retain(
                                &source,
                                &mut archive,
                                &mut publisher,
                                owner,
                                work,
                                report,
                                out,
                            )?;
                            report.emit(
                                owner,
                                out,
                                "rtp_admitted",
                                object(&[
                                    ("ordinal", archive.pin().datagrams.to_string()),
                                    (
                                        "disposition",
                                        string(&format!("{:?}", admission.transport.disposition)),
                                    ),
                                ]),
                            )?;
                            if let Some(retirement) = retirement {
                                protocol_retired(report, &retirement);
                                return Err(SOURCE);
                            }
                        }
                        JpegClientPoll::Rtcp { source, validation } => {
                            storage::retain(
                                &source,
                                &mut archive,
                                &mut publisher,
                                owner,
                                work,
                                report,
                                out,
                            )?;
                            report.rtcp_refusals += u64::from(validation.is_err());
                            report.emit(
                                owner,
                                out,
                                "rtcp_validated",
                                object(&[
                                    ("ordinal", archive.pin().datagrams.to_string()),
                                    ("valid", validation.is_ok().to_string()),
                                ]),
                            )?;
                        }
                        JpegClientPoll::Jpeg(event) => {
                            media(event, None, options, owner, out, report, decode)?
                        }
                        JpegClientPoll::AuthenticationRequired { .. } => {
                            request(&mut connection, None, &authority, &mut entropy, report)?
                        }
                        JpegClientPoll::KeepAliveDue => request(
                            &mut connection,
                            Some(ClientCommand::KeepAlive),
                            &authority,
                            &mut entropy,
                            report,
                        )?,
                        JpegClientPoll::Pending { wake_at_ns }
                        | JpegClientPoll::Backpressure { wake_at_ns } => owner.wait(wake_at_ns)?,
                        JpegClientPoll::Fault {
                            retirement, source, ..
                        } => {
                            protocol_retired(report, &retirement);
                            if let Some(source) = source {
                                if matches!(source.event(),RtspEvent::Interleaved {channel,..} if *channel == options.scope.channels.0 || *channel == options.scope.channels.1)
                                {
                                    storage::retain(
                                        &source,
                                        &mut archive,
                                        &mut publisher,
                                        owner,
                                        work,
                                        report,
                                        out,
                                    )?;
                                }
                            }
                            return Err(SOURCE);
                        }
                        JpegClientPoll::Ended {
                            media: final_media,
                            retirement,
                        } => {
                            if let Some(retirement) = retirement {
                                protocol_retired(report, &retirement);
                            }
                            if let Some(event) = final_media {
                                media(event, None, options, owner, out, report, decode)?;
                            }
                            return if report.pictures >= options.frames {
                                Ok(())
                            } else {
                                Err("ERR-CAPTURE-RTSP-SHORTFALL-001")
                            };
                        }
                    }
                }
            }
        }
        Err(WORK)
    })();
    // Owner stop, error and deadline all close the actual socket without sending an
    // unapproved cleanup request. Every remaining derivative/tail has explicit accounting.
    if let Some(retirement) = connection.cancel() {
        connection_retired(report, &retirement);
    }
    result
}
