#![forbid(unsafe_code)]
//! One actual native capture/replay operation, with an explicit owner at every effect.

use std::io::Write;

use fss_codec_mjpeg::DecodeBudget;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::WorkBudget;
use fss_packet::jpeg::{JpegReceiveCancellation, JpegReceivePoll};
use fss_reference::rtsp::datagram_reconstruction::jpeg::JpegFrameProvenance;
use fss_reference::rtsp::jpeg_client::pictures::decode_luma_frame;

use super::plan::Options;
use fss_cli::json_output::{array, object, string};

#[path = "operation/capture.rs"]
mod capture;
#[path = "operation/replay.rs"]
mod replay;
#[path = "operation/report.rs"]
mod report;
#[path = "operation/storage.rs"]
mod storage;
pub(crate) use report::Report;

pub(crate) const SOURCE: &str = "ERR-CAPTURE-RTSP-SOURCE-001";
pub(crate) const STORAGE: &str = "ERR-CAPTURE-RTSP-STORAGE-001";
pub(crate) const WORK: &str = "ERR-CAPTURE-RTSP-WORK-001";
pub(crate) const OUTPUT: &str = "ERR-CAPTURE-RTSP-OUTPUT-001";
pub(crate) const STATE: &str = "ERR-CAPTURE-RTSP-STATE-001";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Effect {
    Clock,
    StorageRead,
    StorageWrite,
    Network,
    Secret,
    Output,
}

/// The actual runtime supplies current scoped authority, monotonic time and finite waits.
/// Tests can vary authority without substituting the transport, archive or decoder.
pub(crate) trait Owner {
    fn checkpoint(&self, effect: Effect) -> Result<u64, &'static str>;
    fn wait(&self, wake_at_ns: Option<u64>) -> Result<(), &'static str>;
}

pub(crate) fn run(options: &Options, owner: &dyn Owner, out: &mut dyn Write) -> Report {
    let mut report = Report::new(options);
    let mut source_work = WorkBudget::new(options.source_work);
    let mut decode_work = DecodeBudget::new(options.decode_work);
    report.result = (|| {
        options.admit()?;
        // A broken output sink cannot create a source store or contact a camera.
        report.emit(owner, out, "started", options.preview()?)?;
        if options.replay.is_some() {
            replay::run(
                options,
                owner,
                out,
                &mut report,
                &mut source_work,
                &mut decode_work,
            )
        } else {
            capture::run(
                options,
                owner,
                out,
                &mut report,
                &mut source_work,
                &mut decode_work,
            )
        }
    })();
    report.source_work = source_work.used();
    report.decode_work = decode_work.used();
    report
}

fn digest(bytes: [u8; 32]) -> String {
    string(&ContentDigest::new(DigestAlgorithm::Sha256, bytes).to_text())
}

fn retired(report: &mut Report, retirement: &JpegReceiveCancellation) {
    report.retired_queued_packets += retirement.queue.packets as u64;
    report.retired_queued_bytes += retirement.queue.bytes as u64;
    if let Some(fragment) = &retirement.fragment {
        report.discarded_images += 1;
        report.discarded_image_bytes += fragment.byte_len as u64;
    }
}

#[allow(clippy::too_many_arguments)]
fn media(
    event: JpegReceivePoll,
    provenance: Option<JpegFrameProvenance>,
    options: &Options,
    owner: &dyn Owner,
    out: &mut dyn Write,
    report: &mut Report,
    budget: &mut DecodeBudget<'_>,
) -> Result<(), &'static str> {
    match event {
        JpegReceivePoll::Packet {
            source,
            reconstruction,
        } => {
            let reconstruction = match reconstruction {
                Ok(output) => output,
                Err(error) => {
                    report.packet_refusals += 1;
                    report.emit(
                        owner,
                        out,
                        "reconstruction_refused",
                        object(&[
                            ("sequence", source.sequence().to_string()),
                            ("received_ns", source.received_ns().to_string()),
                            ("reason", string(&format!("{error:?}"))),
                        ]),
                    )?;
                    // The exact original was already retained. A malformed image does not
                    // prevent independently framed later images from being examined.
                    return Ok(());
                }
            };
            if let Some(discard) = reconstruction.discarded {
                report.discarded_images += 1;
                report.discarded_image_bytes += discard.byte_len as u64;
            }
            let Some(frame) = reconstruction.frame else {
                if provenance.is_some() {
                    return Err(STATE);
                }
                return Ok(());
            };
            if options.replay.is_some() && provenance.is_none() {
                return Err(STATE);
            }
            owner.checkpoint(Effect::Clock)?;
            let encoded = ContentDigest::sha256(frame.bytes());
            if provenance
                .as_ref()
                .is_some_and(|p| p.encoded_digest() != encoded)
            {
                return Err(STATE);
            }
            let picture = match decode_luma_frame(*frame, encoded.bytes(), options.decode, budget) {
                Ok(picture) => picture,
                Err(failure) => {
                    owner.checkpoint(Effect::Clock)?;
                    report.decode_refusals += 1;
                    report.emit(
                        owner,
                        out,
                        "decode_refused",
                        object(&[
                            ("encoded_digest", string(&encoded.to_text())),
                            (
                                "sequence_interval",
                                array(
                                    &failure
                                        .reconstruction
                                        .sequence_interval()
                                        .map(|n| n.to_string()),
                                ),
                            ),
                            ("reason", string(&format!("{:?}", failure.reason))),
                            ("partial_pixels_exposed", "false".into()),
                        ]),
                    )?;
                    if matches!(
                        failure.reason,
                        fss_codec_mjpeg::DecodeError::BudgetExhausted
                            | fss_codec_mjpeg::DecodeError::Cancelled
                    ) {
                        return Err(WORK);
                    }
                    return Ok(());
                }
            };
            // No late/cancelled result crosses the output boundary.
            owner.checkpoint(Effect::Clock)?;
            let receipt = picture.pixels().receipt();
            let frame = picture.reconstruction();
            let lineage = provenance.map(|p| {
                object(&[
                    ("digest", string(&p.digest().to_text())),
                    ("interpretation", string(&p.interpretation().to_text())),
                    ("source", report::pin(p.source())),
                    ("receive_clock", string(&p.receive_clock().to_text())),
                    ("capture_clock", "null".into()),
                    (
                        "dependencies",
                        array(
                            &p.dependencies()
                                .iter()
                                .map(|d| {
                                    object(&[
                                        ("sequence", d.sequence.to_string()),
                                        ("ordinal", d.record.pin.datagrams.to_string()),
                                        ("head", string(&d.record.pin.head.to_text())),
                                        (
                                            "payload_digest",
                                            string(&d.record.payload_digest.to_text()),
                                        ),
                                        ("payload_bytes", d.record.payload_bytes.to_string()),
                                        ("received_ns", d.record.received_ns.to_string()),
                                        ("channel", d.record.channel.to_string()),
                                    ])
                                })
                                .collect::<Vec<_>>(),
                        ),
                    ),
                ])
            });
            report.emit(
                owner,
                out,
                "picture_validated",
                object(&[
                    ("picture", (report.pictures + 1).to_string()),
                    ("encoded_digest", digest(receipt.encoded_sha256)),
                    ("luma_digest", digest(receipt.luma_sha256)),
                    ("decoder", digest(receipt.decoder)),
                    (
                        "interpretation",
                        string("RFC2435-full-range-YCbCr-native-luma"),
                    ),
                    (
                        "dimensions",
                        array(&picture.pixels().dimensions().map(|n| n.to_string())),
                    ),
                    (
                        "sequence_interval",
                        array(&frame.sequence_interval().map(|n| n.to_string())),
                    ),
                    ("rtp_timestamp", frame.timestamp().to_string()),
                    ("fragments", frame.fragments().to_string()),
                    ("mcus", receipt.mcus.to_string()),
                    ("entropy_blocks", receipt.entropy_blocks.to_string()),
                    ("restarts", receipt.restarts.to_string()),
                    ("pixels_retained", "false".into()),
                    ("capture_clock", "null".into()),
                    (
                        "source_provenance",
                        lineage.unwrap_or_else(|| "null".into()),
                    ),
                    (
                        "source_prefix",
                        report.pin.map_or_else(|| "null".into(), report::pin),
                    ),
                ]),
            )?;
            report.pictures += 1;
        }
        JpegReceivePoll::Gap { discarded, .. } => {
            report.delivery_gaps += 1;
            if let Some(discard) = discarded {
                report.discarded_images += 1;
                report.discarded_image_bytes += discard.byte_len as u64;
            }
        }
        JpegReceivePoll::JpegDiscarded(discard) => {
            report.discarded_images += 1;
            report.discarded_image_bytes += discard.byte_len as u64;
        }
        JpegReceivePoll::Ended { discarded } => {
            if let Some(discard) = discarded {
                report.discarded_images += 1;
                report.discarded_image_bytes += discard.byte_len as u64;
            }
        }
        JpegReceivePoll::Pending { .. } => {}
    }
    Ok(())
}
