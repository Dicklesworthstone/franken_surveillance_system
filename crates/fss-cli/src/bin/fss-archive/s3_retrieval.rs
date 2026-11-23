#![forbid(unsafe_code)]
//! Cold verification of a completed object's actual bytes, without reopening its
//! upload owner, reading the local source, or mutating historical upload evidence.

use super::*;
use fss_object::uploader::{
    RetrievalObservation, RetrievalOutcome, RetrievalReceipt, UploaderError,
};

struct Report {
    receipt: RetrievalReceipt,
    recovery: MultipartRecovery,
    provider_requested: bool,
    receipt_durable: bool,
    failure: Option<&'static str>,
}

fn authority(
    options: &Options,
    now: TimestampNs,
) -> Result<(AuthorityCx, AuthorityCx, RegionTree, RootAuthoritySpec)> {
    let request = options
        .observation
        .as_ref()
        .ok_or(Error::Runtime("retrieval observation options absent"))?;
    let grants = [
        RuntimeGrant::ReadMedia,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
    ];
    let mut child = spec(options, options.transfer, Some(options.deadline), &grants);
    child.operation_id = request.operation.clone();
    let (mut root, mut tree) = AuthorityCx::root(
        child.clone(),
        RegionId::new("region:archive-s3-retrieval-process")
            .map_err(|_| Error::Runtime("retrieval process identity refused"))?,
        RegionKind::Process,
        options.transfer,
        now,
    )
    .map_err(|_| Error::Runtime("retrieval process authority refused"))?;
    let mut scopes = GrantSet::empty();
    for grant in grants {
        scopes = scopes.with_scope(
            grant,
            [options.endpoint.resource().to_owned()]
                .into_iter()
                .collect(),
        );
    }
    root.narrow_grants(scopes)
        .map_err(|_| Error::Runtime("retrieval resource scope refused"))?;
    let property = root
        .scope_down(
            &mut tree,
            RegionId::new("region:archive-s3-retrieval-property")
                .map_err(|_| Error::Runtime("retrieval property identity refused"))?,
            RegionKind::Property,
            options.transfer,
            child.clone(),
            now,
        )
        .map_err(|_| Error::Runtime("retrieval property authority refused"))?;
    Ok((root, property, tree, child))
}

fn execute_in(options: &Options, local: &Arc<ScopedS3Io>) -> Result<Report> {
    let now = wall_now()?;
    if now >= options.deadline {
        return Err(Error::Runtime("retrieval deadline has already expired"));
    }
    let expected = expected_intent(options, now)?;
    let minimum = options
        .minimum
        .ok_or(Error::Runtime("retrieval minimum pin absent"))?;
    let journal =
        FileUploadJournal::open(&options.journal, journal_limits(), local.clone(), minimum)
            .map_err(|_| {
                Error::Runtime("exclusive retrieval source journal or minimum pin refused")
            })?;
    let recovery = MultipartRecovery::read(&journal, minimum)
        .map_err(|_| Error::Runtime("canonical retrieval source refused"))?;
    RetrievalObservation::validate_source(&recovery, &expected, options.source_digest)
        .map_err(|_| Error::Runtime("retrieval requires exact completed upload evidence"))?;
    local
        .preflight_observation_receipt()
        .map_err(|_| Error::Runtime("new immutable retrieval receipt destination refused"))?;
    let (mut root, mut property, mut tree, child) = authority(options, now)?;
    let mut owner = RetrievalObservation::begin(
        &mut property,
        &mut tree,
        &journal,
        &recovery,
        &expected,
        options.source_digest,
        child,
        now,
    )
    .map_err(|_| Error::Runtime("fresh read-media retrieval authority refused"))?;
    let mut provider_requested = false;
    let attempted = (|| -> Result<RetrievalReceipt> {
        let secret = local
            .read_credentials()
            .map_err(|_| Error::Runtime("private retrieval credential file refused"))?;
        let credentials = S3Credentials::from_lines(secret)
            .map_err(|_| Error::Runtime("retrieval credential format refused"))?;
        let mut transport = NativeS3Transport::from_recovery(
            options.endpoint.clone(),
            credentials,
            S3Limits::default(),
            HostClock,
            &recovery,
        )
        .map_err(|_| Error::Runtime("retrieval transport binding refused"))?;
        provider_requested = true;
        owner
            .verify(&mut tree, &mut transport, || {
                wall_now()
                    .map_err(|_| UploaderError::Authority("retrieval clock unavailable".into()))
            })
            .map_err(|_| Error::Runtime("independent retrieval was refused or did not verify"))
    })();
    let (receipt, mut failure) = match attempted {
        Ok(receipt) => (receipt, None),
        Err(_) => {
            let receipt = owner
                .settle(&mut tree, cleanup_time(owner.observed_at()))
                .map_err(|_| Error::Runtime("retrieval local settlement refused"))?;
            let failure = if receipt.outcome() == RetrievalOutcome::Mismatch {
                "retrieval_verification_mismatch"
            } else {
                "retrieval_attempt_refused"
            };
            (receipt, Some(failure))
        }
    };
    if !owner.is_settled() {
        return Err(Error::Runtime("retrieval owner did not finalize"));
    }
    drop(owner);
    let closed_at = cleanup_time(receipt.observed_at());
    close_parents(&mut root, &mut property, &mut tree, closed_at)?;
    recovery
        .validate_restore(&journal, closed_at)
        .map_err(|_| Error::Runtime("source journal changed during retrieval"))?;
    let bytes = receipt
        .encode()
        .map_err(|_| Error::Runtime("canonical retrieval receipt refused"))?;
    let receipt_durable = local.write_observation_receipt(&bytes).is_ok();
    if !receipt_durable {
        failure = Some("retrieval_receipt_durability_unconfirmed");
    }
    Ok(Report {
        receipt,
        recovery,
        provider_requested,
        receipt_durable,
        failure,
    })
}

fn cleanup_time(observed_at: TimestampNs) -> TimestampNs {
    wall_now().unwrap_or(observed_at).max(observed_at)
}

pub(super) fn execute(options: &Options) -> Result<(String, bool)> {
    let local = local_io(options, wall_now()?, Instant::now())?;
    let result = execute_in(options, &local);
    let work = local
        .consumed()
        .map_err(|_| Error::Runtime("retrieval local accounting refused"))?;
    let finalized = local
        .finalize()
        .map_err(|_| Error::Runtime("retrieval local files could not finalize"));
    let report = result?;
    finalized?;
    render(options, &report, work)
}

fn render(options: &Options, report: &Report, local_work: BudgetVector) -> Result<(String, bool)> {
    let receipt = &report.receipt;
    let recovery = &report.recovery;
    let minimum = options
        .minimum
        .ok_or(Error::Runtime("retrieval minimum pin absent"))?;
    let verified = receipt.outcome() == RetrievalOutcome::Verified;
    let outcome = match receipt.outcome() {
        RetrievalOutcome::Verified => "verified",
        RetrievalOutcome::Mismatch => "mismatch",
        RetrievalOutcome::Unknown => "unknown",
        RetrievalOutcome::NotObserved => "not_observed",
    };
    let digest = receipt
        .digest()
        .map_err(|_| Error::Runtime("canonical retrieval receipt digest refused"))?;
    let next = if !report.receipt_durable {
        "retain_source_pin_and_inspect_retrieval_receipt_before_new_verification"
    } else if verified {
        "retain_retrieval_receipt_before_separate_graph_or_replica_verification"
    } else {
        "retain_source_pin_and_authorize_a_new_bounded_verification_if_needed"
    };
    let mut rendered = object(&[
        ("schema", string("fss.s3_retrieval_observation_cli.v1")),
        ("kind", string("s3_retrieval_observation")),
        ("command", string("verify")),
        ("resource", string(recovery.intent().resource())),
        ("intent_digest", string(&receipt.intent_digest().to_text())),
        (
            "original_operation",
            string(receipt.source_operation().as_str()),
        ),
        (
            "observation_operation",
            string(receipt.operation().as_str()),
        ),
        (
            "source_digest",
            string(&receipt.expected_digest().to_text()),
        ),
        ("source_bytes", receipt.expected_bytes().to_string()),
        ("source_verified_this_invocation", "false".into()),
        ("plan_digest", string(&receipt.plan_digest().to_text())),
        ("manifest_root", string(&receipt.manifest_root().to_text())),
        ("minimum_sequence", minimum.sequence.to_string()),
        ("minimum_root", string(&minimum.root.to_text())),
        (
            "source_journal_sequence",
            recovery.head().sequence.to_string(),
        ),
        (
            "source_journal_head",
            string(&recovery.head().root.to_text()),
        ),
        ("original_phase", string("completed")),
        ("original_local_owner_state", string("verified")),
        (
            "original_completion_receipt_digest",
            string(&receipt.completion_digest().to_text()),
        ),
        ("original_upload_unchanged", "true".into()),
        ("original_upload_consumed", budget(&recovery.consumed())),
        (
            "original_upload_remaining",
            budget(&recovery.remaining_budget()),
        ),
        ("observation_outcome", string(outcome)),
        ("observation_allowance", budget(&options.transfer)),
        ("observation_consumed", budget(&receipt.consumed())),
        ("observed_at_ns", receipt.observed_at().0.to_string()),
        ("bytes_read", receipt.bytes_read().to_string()),
        ("verified_parts", receipt.verified_parts().to_string()),
        ("expected_parts", receipt.expected_parts().to_string()),
        ("attempted_ranges", receipt.attempted_ranges().to_string()),
        ("observation_receipt_digest", string(&digest.to_text())),
        (
            "observation_receipt_durable",
            report.receipt_durable.to_string(),
        ),
        (
            "provider_work_requested_this_invocation",
            report.provider_requested.to_string(),
        ),
        ("local_work", budget(&local_work)),
        (
            "error_kind",
            report.failure.map_or_else(|| "null".into(), string),
        ),
        ("next_action", string(next)),
        (
            "transport_profile",
            string("approved_local_plaintext_sigv4"),
        ),
        ("independent_retrievability_verified", verified.to_string()),
        ("graph_closure_verified", "false".into()),
        ("client_side_encryption_performed", "false".into()),
        ("replication_verified", "false".into()),
    ]);
    rendered.push('\n');
    if rendered.len() > MAX_REPORT_BYTES {
        return Err(Error::Runtime("retrieval report exceeds its bound"));
    }
    Ok((
        rendered,
        verified && report.receipt_durable && report.failure.is_none(),
    ))
}
