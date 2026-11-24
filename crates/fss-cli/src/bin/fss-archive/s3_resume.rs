#![forbid(unsafe_code)]
//! Bounded continuation after a positively reconciled part acknowledgement.
//!
//! Provider evidence first passes through the durable multipart owner. The live
//! native adapter remains uncertain, so it is discarded together with the old
//! owner and journal lock before a fresh owner reads the confirmed checkpoint.
//! Missing evidence never grants retry permission or replenishes an allowance.

use std::io;
use std::sync::Arc;

use fss_core::{ObligationState, RegionTree, TimestampNs};
use fss_object::multipart::{
    CompletionReceipt, MultipartPhase, MultipartRecovery, MultipartTransport, TransportOperation,
    UploadIntent,
};
use fss_object::planner::plan_chunks;
use fss_object::upload_journal::FileUploadJournal;
use fss_object::uploader::StagedUpload;
use fss_reference::s3_upload::{NativeS3Transport, S3Credentials, S3Limits};

use super::s3_io::ScopedS3Io;
use super::{
    Command, Error, HostClock, MAX_SOURCE_BYTES, NoNetwork, Options, Report, Result, drive,
    journal_limits, report_recovery, verify_source, wall_now,
};

pub(super) enum Progress {
    Completed(CompletionReceipt),
    Reopen,
}

pub(super) fn upload_pass<T: MultipartTransport>(
    upload: &mut StagedUpload<'_, T>,
    tree: &mut RegionTree,
    source: &[u8],
) -> std::result::Result<Progress, ()> {
    let uploaded = upload.try_upload_chunks(
        tree,
        MAX_SOURCE_BYTES,
        || wall_now().unwrap_or(TimestampNs(0)),
        |chunk| {
            let start =
                usize::try_from(chunk.offset).map_err(|_| io::Error::other("source range"))?;
            let len = usize::try_from(chunk.len).map_err(|_| io::Error::other("source range"))?;
            let end = start
                .checked_add(len)
                .ok_or_else(|| io::Error::other("source range"))?;
            let range = source
                .get(start..end)
                .ok_or_else(|| io::Error::other("source range"))?;
            let mut part = Vec::new();
            part.try_reserve_exact(len)
                .map_err(|_| io::Error::other("source buffer"))?;
            part.extend_from_slice(range);
            Ok::<_, io::Error>(part)
        },
    );
    if uploaded.is_ok() {
        return upload
            .finish(tree, wall_now().map_err(|_| ())?)
            .map(Progress::Completed)
            .map_err(|_| ());
    }
    if upload.durability_failed()
        || upload.phase() != MultipartPhase::Uncertain(TransportOperation::UploadPart)
    {
        return Err(());
    }
    let confirmed = upload.confirmed_parts();
    let phase = upload
        .reconcile(tree, wall_now().map_err(|_| ())?)
        .map_err(|_| ())?;
    if upload.durability_failed()
        || phase != MultipartPhase::Uploading
        || upload.confirmed_parts() <= confirmed
    {
        return Err(());
    }
    Ok(Progress::Reopen)
}

pub(super) fn execute(
    options: &Options,
    local: &Arc<ScopedS3Io>,
    expected: UploadIntent,
) -> Result<Report> {
    let mut minimum = options
        .minimum
        .ok_or(Error::Runtime("minimum pin absent"))?;
    let maximum = plan_chunks(options.source_bytes, options.policy)
        .map_err(|_| Error::Runtime("object plan refused"))?
        .chunks
        .len();
    let mut source = None;
    let mut dispatched = false;
    // Every continuation must confirm at least one previously unconfirmed part.
    // One final pass may complete the object. Source and local work allowances
    // stay shared; each fresh transfer owner recovers only durable remaining work.
    for _ in 0..=maximum {
        let mut journal =
            FileUploadJournal::open(&options.journal, journal_limits(), local.clone(), minimum)
                .map_err(|_| {
                    Error::Runtime("exclusive journal reopen or minimum pin verification refused")
                })?;
        let recovery = MultipartRecovery::read(&journal, minimum)
            .map_err(|_| Error::Runtime("canonical upload recovery refused"))?;
        if recovery.intent() != &expected || recovery.original_budget() != options.transfer {
            return Err(Error::Runtime(
                "caller intent, source, route, plan or original allowance changed",
            ));
        }
        let confirmed_before = recovery.confirmed_parts();
        let head_before = recovery.head();
        let phase = recovery.phase();
        let mut report = if recovery
            .owner_state()
            .map_err(|_| Error::Runtime("upload ownership record refused"))?
            == Some(ObligationState::Indeterminate)
        {
            report_recovery(options, &recovery, expected.clone())?
        } else if matches!(phase, MultipartPhase::Completed | MultipartPhase::Aborted)
            || (phase == MultipartPhase::Prepared && options.command == Command::Abort)
        {
            drive(
                options,
                &mut journal,
                &mut NoNetwork,
                Some(recovery),
                expected.clone(),
                None,
            )?
        } else {
            // Pending uncertain parts are observed before opening the source.
            // Only a confirmed active checkpoint admits further source work.
            if source.is_none()
                && options.command == Command::Resume
                && matches!(phase, MultipartPhase::Prepared | MultipartPhase::Uploading)
                && recovery.confirmed_parts() < recovery.plan().chunks.len()
            {
                source = Some(verify_source(options, local)?);
            }
            let secret = local
                .read_credentials()
                .map_err(|_| Error::Runtime("private bounded credential file refused"))?;
            let credentials = S3Credentials::from_lines(secret)
                .map_err(|_| Error::Runtime("credential file format refused"))?;
            let mut transport = NativeS3Transport::from_recovery(
                options.endpoint.clone(),
                credentials,
                S3Limits::default(),
                HostClock,
                &recovery,
            )
            .map_err(|_| Error::Runtime("native transport recovery binding refused"))?;
            drive(
                options,
                &mut journal,
                &mut transport,
                Some(recovery),
                expected.clone(),
                source.as_deref(),
            )?
            // The transport and its credentials are dropped at this block boundary.
        };
        drop(journal);
        dispatched |= report.dispatch_requested;
        report.dispatch_requested = dispatched;
        report.source_verified |= source.is_some();
        if !report.resume_after_reconciliation {
            return Ok(report);
        }
        if options.command != Command::Resume
            || report.durability_failed
            || report.phase != MultipartPhase::Uploading
            || report.confirmed <= confirmed_before
            || report.head.sequence <= head_before.sequence
        {
            return Err(Error::Runtime(
                "durable part reconciliation made no forward progress",
            ));
        }
        minimum = report.head;
    }
    Err(Error::Runtime("bounded upload continuation exhausted"))
}
