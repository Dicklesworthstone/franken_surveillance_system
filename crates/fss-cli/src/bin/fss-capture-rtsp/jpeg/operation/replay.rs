#![forbid(unsafe_code)]
//! Reopen the exact complete prefix, drive real virtual receive time, and validate pixels.

use super::*;
use fss_reference::rtsp::datagram_archive::prefix::DatagramPrefix;
use fss_reference::rtsp::datagram_reconstruction::jpeg::{
    DatagramJpegReplay, JpegReplayBounds, JpegReplaySpec, JpegReplayStep,
};

pub(super) fn run(
    options: &Options,
    owner: &dyn Owner,
    out: &mut dyn Write,
    report: &mut Report,
    work: &mut WorkBudget<'_>,
    decode: &mut DecodeBudget<'_>,
) -> Result<(), &'static str> {
    let selection = options.replay.ok_or(STATE)?;
    let publisher = storage::open(options, owner)?;
    let cancel = storage::Cancellation {
        owner,
        write: false,
    };
    let prefix = DatagramPrefix::recover(
        &publisher,
        options.scope.clone(),
        options.archive,
        options.pin()?,
        &cancel,
        work,
    )
    .map_err(|_| STORAGE)?;
    report.pin = Some(prefix.pin());
    report.configuration = Some(selection.configuration);
    report.reduced_rtcp = Some(selection.reduced_rtcp);
    let mut replay = DatagramJpegReplay::new(
        prefix.archive(),
        JpegReplaySpec {
            payload_type: options.payload_type,
            reorder: options.reorder,
            jpeg: options.jpeg,
            reduced_rtcp: selection.reduced_rtcp,
            configuration_evidence: selection.configuration,
        },
        JpegReplayBounds {
            max_source_bytes: options.archive.max_payload_bytes,
            max_steps: options.max_steps,
            deadline_ns: options.timeout_ns,
        },
        owner.checkpoint(Effect::StorageRead)?,
    )
    .map_err(|_| SOURCE)?;
    report.emit(
        owner,
        out,
        "source_recovered",
        object(&[
            ("selected_prefix", report::pin(prefix.pin())),
            ("observed_storage_head", report::pin(prefix.observed_head())),
            ("interpretation", string(&replay.interpretation().to_text())),
            (
                "configuration_evidence",
                string(&selection.configuration.to_text()),
            ),
            ("capture_clock", "null".into()),
        ]),
    )?;
    let result = (|| {
        for _ in 0..options.max_steps {
            let now = owner.checkpoint(Effect::StorageRead)?;
            report.steps += 1;
            let step = match replay.step(&publisher, now, &cancel, work) {
                Ok(step) => step,
                Err(failure) => {
                    if let Some(retirement) = failure.retirement {
                        if let Some(receiver) = retirement.receiver {
                            retired(report, &receiver);
                        }
                        report.withheld_events += u64::from(retirement.withheld.is_some());
                    }
                    return Err(SOURCE);
                }
            };
            match step {
                JpegReplayStep::Rtp {
                    source,
                    admission,
                    retired: retirement,
                } => {
                    report.emit(
                        owner,
                        out,
                        "source_replayed",
                        object(&[
                            ("original", report::record(source.record())),
                            (
                                "disposition",
                                string(&format!("{:?}", admission.transport.disposition)),
                            ),
                        ]),
                    )?;
                    if let Some(retirement) = retirement {
                        retired(report, &retirement);
                        return Err(SOURCE);
                    }
                }
                JpegReplayStep::Rtcp { source, validation } => {
                    report.rtcp_refusals += u64::from(validation.is_err());
                    report.emit(
                        owner,
                        out,
                        "rtcp_replayed",
                        object(&[
                            ("original", report::record(source.record())),
                            ("valid", validation.is_ok().to_string()),
                        ]),
                    )?;
                }
                JpegReplayStep::InputRefused {
                    source,
                    error,
                    retired: retirement,
                } => {
                    retired(report, &retirement);
                    report.packet_refusals += 1;
                    report.emit(
                        owner,
                        out,
                        "source_refused",
                        object(&[
                            ("original", report::record(source.record())),
                            ("reason", string(&format!("{error:?}"))),
                        ]),
                    )?;
                    return Err(SOURCE);
                }
                JpegReplayStep::Media {
                    event, provenance, ..
                } => media(event, provenance, options, owner, out, report, decode)?,
                JpegReplayStep::ClockAdvanced { .. } => {}
                JpegReplayStep::PrefixExhausted {
                    retired: retirement,
                    ..
                } => {
                    retired(report, &retirement);
                    // Reverify custody at the final boundary. This cannot add later source
                    // to the selected interpretation or manufacture a future timer/EOF.
                    prefix
                        .revalidate(&publisher, &cancel, work)
                        .map_err(|_| STORAGE)?;
                    owner.checkpoint(Effect::StorageRead)?;
                    report.prefix_exhausted = true;
                    return Ok(());
                }
                JpegReplayStep::CodecEnded {
                    event,
                    retired: retirement,
                    ..
                } => {
                    retired(report, &retirement);
                    media(event, None, options, owner, out, report, decode)?;
                    return Err(SOURCE);
                }
                JpegReplayStep::Ended => return Err(STATE),
            }
        }
        Err(WORK)
    })();
    if let Some(retirement) = replay.cancel() {
        if let Some(receiver) = retirement.receiver {
            retired(report, &receiver);
        }
        report.withheld_events += u64::from(retirement.withheld.is_some());
    }
    result
}
