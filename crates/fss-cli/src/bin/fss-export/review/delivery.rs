#![forbid(unsafe_code)]
//! Durable delivery before disclosure, followed by exact held-file reconciliation.

use std::io::{self, Write};

use fss_cli::agent_json::{evidence_anchor, object, string};
use fss_core::{CaptureInterval, ContentDigest, ContextAuthority};
use fss_reference::review_media::delivery::{
    ReviewDeliveryRecord, ReviewDeliveryState, begin_review_delivery, inspect_review_delivery,
    prepare_review_delivery, verify_review_delivery,
};
use fss_reference::review_media::{
    ReviewMediaError, ReviewMediaRecord, read_review_media, revalidate_review_media,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::super::RunResult;
use super::destination::Destination;
use super::options::{Action, Options};

const IO_CHUNK_BYTES: usize = 64 * 1024;
const MAX_REPORT_BYTES: usize = 64 * 1024;

fn refused(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn bounded(report: String) -> RunResult<String> {
    if report.len() > MAX_REPORT_BYTES {
        return Err(refused("review delivery report exceeds byte bound").into());
    }
    Ok(report)
}

fn interval(value: CaptureInterval) -> String {
    object(&[
        ("earliest", string(&value.earliest.0.to_string())),
        ("latest", string(&value.latest.0.to_string())),
    ])
}

fn state(value: Option<ReviewDeliveryState>) -> &'static str {
    match value {
        None => "not_started",
        Some(ReviewDeliveryState::Started) => "started_outcome_indeterminate",
        Some(ReviewDeliveryState::Verified) => "verified_local_file",
    }
}

fn preview_report(
    options: &Options,
    record: &ReviewMediaRecord,
    now: CaptureInterval,
    target: &Destination,
    preview: &fss_reference::review_media::delivery::ReviewDeliveryPreview,
    output_exists: bool,
) -> RunResult<String> {
    bounded(object(&[
        ("format", string("fss.review_media_cli.v1")),
        ("site", string(&options.site)),
        ("status", string("awaiting_file_approval")),
        ("review_root", string(&record.root().to_text())),
        ("record_digest", string(&record.digest().to_text())),
        ("media_digest", string(&record.media_digest().to_text())),
        ("media_bytes", record.media_bytes().to_string()),
        ("media_type", string("video/x-matroska")),
        ("delivery_id", string(&preview.identity().to_text())),
        ("delivery_state", string(state(preview.state()))),
        ("approval_digest", string(&preview.approval().to_text())),
        ("destination_binding", string(&target.binding().to_text())),
        ("recipient", string(&options.principal)),
        ("attested_now_ns", interval(now)),
        ("output_exists", output_exists.to_string()),
        ("file_written", "false".into()),
        (
            "delivery_receipt_in_deployment",
            (preview.state() == Some(ReviewDeliveryState::Verified)).to_string(),
        ),
        ("current_destination_verified", "false".into()),
        ("recipient_authenticated", "false".into()),
        ("trusted_clock_used", "false".into()),
        ("external_transport_performed", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ]))
}

fn record_report(
    options: &Options,
    record: &ReviewDeliveryRecord,
    status: &str,
    anchor: &fss_core::LedgerAnchor,
    file_written: bool,
    verified_now: bool,
) -> RunResult<String> {
    bounded(object(&[
        ("format", string("fss.review_media_cli.v1")),
        ("site", string(&options.site)),
        ("status", string(status)),
        ("delivery_id", string(&record.identity().to_text())),
        ("delivery_state", string(state(Some(record.state())))),
        ("delivery_record_digest", string(&record.digest().to_text())),
        ("review_root", string(&record.review_root().to_text())),
        (
            "record_digest",
            string(&record.review_record_digest().to_text()),
        ),
        ("media_digest", string(&record.media_digest().to_text())),
        ("media_bytes", record.media_bytes().to_string()),
        ("media_type", string("video/x-matroska")),
        (
            "destination_binding",
            string(&record.destination_binding().to_text()),
        ),
        ("recipient", string(record.recipient().as_str())),
        ("started_at_ns", interval(record.started_at())),
        (
            "verified_at_ns",
            record.verified_at().map_or_else(|| "null".into(), interval),
        ),
        ("authority_anchor", evidence_anchor(anchor)),
        ("file_written", file_written.to_string()),
        (
            "delivery_receipt_in_deployment",
            (record.state() == ReviewDeliveryState::Verified).to_string(),
        ),
        ("current_destination_verified", verified_now.to_string()),
        ("recipient_authenticated", "false".into()),
        ("trusted_clock_used", "false".into()),
        ("external_transport_performed", "false".into()),
        ("existing_copies_recalled", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ]))
}

pub(super) fn run(
    options: &Options,
    deployment: &mut ReferenceDeployment,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> RunResult<String> {
    let Action::Read {
        root,
        attested_now,
        output,
        approval,
    } = &options.action
    else {
        return Err(refused("review delivery requires an explicit read action").into());
    };
    let target = Destination::prepare(output, &options.root, cx)?;
    let preview = prepare_review_delivery(
        deployment,
        *root,
        target.binding(),
        *attested_now,
        authority,
        cx,
    )?;
    let exists = target.exists(cx)?;
    if exists && preview.state().is_none() {
        return Err(refused(
            "existing output has no matching recorded review delivery; refusing adoption",
        )
        .into());
    }
    let Some(approval) = approval else {
        return preview_report(
            options,
            preview.record(),
            *attested_now,
            &target,
            &preview,
            exists,
        );
    };
    if *approval != preview.approval() {
        return Err(refused(
            "review file approval does not match exact destination, grant and time",
        )
        .into());
    }
    let previous_state = preview.state();
    let progress = begin_review_delivery(
        deployment,
        *root,
        target.binding(),
        *attested_now,
        *approval,
        authority,
        cx,
    )?;
    // Every error from here leaves the durable attempt visible to review-delivery-show.
    // Existing attempts can only verify the old file: disappearance never triggers a resend.
    let mut file = if progress.started {
        let media = read_review_media(deployment, *root, *attested_now, authority, cx)?;
        revalidate_review_media(deployment, &media, *attested_now, authority, cx)?;
        let mut file = target.create(cx)?;
        for chunk in media.bytes().chunks(IO_CHUNK_BYTES) {
            cx.checkpoint("review_cli:write_screened_media")?;
            target.check_file(&file, cx)?;
            file.write_all(chunk)?;
        }
        target.sync(&file, cx)?;
        file
    } else {
        let file = target.open_existing(cx)?;
        target.sync(&file, cx)?;
        file
    };
    let receipt = verify_review_delivery(
        deployment,
        progress.record.identity(),
        target.binding(),
        *attested_now,
        &mut file,
        &mut |file| {
            target
                .check_file(file, cx)
                .map_err(|_| ReviewMediaError::CustodyMismatch)
        },
        authority,
        cx,
    )?;
    target.check_file(&file, cx)?;
    let status = if progress.started {
        "private_file_written"
    } else if previous_state == Some(ReviewDeliveryState::Verified) {
        "private_file_verified"
    } else {
        "private_file_reconciled"
    };
    record_report(
        options,
        &receipt.record,
        status,
        &receipt.anchor,
        progress.started,
        true,
    )
}

pub(super) fn show(
    options: &Options,
    deployment: &ReferenceDeployment,
    identity: ContentDigest,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> RunResult<String> {
    let record = inspect_review_delivery(deployment, identity, authority, cx)?
        .ok_or_else(|| refused("review delivery identity was not found"))?;
    record_report(
        options,
        &record,
        "recorded_delivery_state",
        deployment.current_anchor(),
        false,
        false,
    )
}
