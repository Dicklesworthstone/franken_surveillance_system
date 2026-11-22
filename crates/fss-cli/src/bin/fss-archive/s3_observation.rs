#![forbid(unsafe_code)]
//! A fresh read-only completion observation never reopens the old upload owner.
//! Its immutable receipt names the exact old journal head and indeterminate proof.

use super::*;
use fss_object::uploader::{
    CompletionObservation, CompletionObservationOutcome, CompletionObservationReceipt,
};

struct Report {
    receipt: CompletionObservationReceipt,
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
        .ok_or(Error::Runtime("observation options absent"))?;
    let grants = [
        RuntimeGrant::ObserveStatus,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
    ];
    let mut child = spec(options, options.transfer, Some(options.deadline), &grants);
    child.operation_id = request.operation.clone();
    let (mut root, mut tree) = AuthorityCx::root(
        child.clone(),
        RegionId::new("region:archive-s3-observation-process")
            .map_err(|_| Error::Runtime("observation process identity refused"))?,
        RegionKind::Process,
        options.transfer,
        now,
    )
    .map_err(|_| Error::Runtime("observation process authority refused"))?;
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
        .map_err(|_| Error::Runtime("observation resource scope refused"))?;
    let property = root
        .scope_down(
            &mut tree,
            RegionId::new("region:archive-s3-observation-property")
                .map_err(|_| Error::Runtime("observation property identity refused"))?,
            RegionKind::Property,
            options.transfer,
            child.clone(),
            now,
        )
        .map_err(|_| Error::Runtime("observation property authority refused"))?;
    Ok((root, property, tree, child))
}

fn execute_in(options: &Options, local: &Arc<ScopedS3Io>) -> Result<Report> {
    let now = wall_now()?;
    if now >= options.deadline {
        return Err(Error::Runtime("observation deadline has already expired"));
    }
    let expected = expected_intent(options, now)?;
    let minimum = options
        .minimum
        .ok_or(Error::Runtime("observation minimum pin absent"))?;
    let journal =
        FileUploadJournal::open(&options.journal, journal_limits(), local.clone(), minimum)
            .map_err(|_| Error::Runtime("exclusive source journal or minimum pin refused"))?;
    let recovery = MultipartRecovery::read(&journal, minimum)
        .map_err(|_| Error::Runtime("canonical observation source refused"))?;
    CompletionObservation::validate_source(&recovery, &expected).map_err(|_| {
        Error::Runtime("observation requires exact indeterminate completion evidence")
    })?;
    local
        .preflight_observation_receipt()
        .map_err(|_| Error::Runtime("new immutable observation receipt destination refused"))?;
    let (mut root, mut property, mut tree, child) = authority(options, now)?;
    let mut owner = CompletionObservation::begin(
        &mut property,
        &mut tree,
        &journal,
        &recovery,
        &expected,
        child,
        now,
    )
    .map_err(|_| Error::Runtime("fresh read-only observation authority refused"))?;
    let mut provider_requested = false;
    let attempted = (|| -> Result<CompletionObservationReceipt> {
        let secret = local
            .read_credentials()
            .map_err(|_| Error::Runtime("private observation credential file refused"))?;
        let credentials = S3Credentials::from_lines(secret)
            .map_err(|_| Error::Runtime("observation credential format refused"))?;
        let mut transport = NativeS3Transport::from_recovery(
            options.endpoint.clone(),
            credentials,
            S3Limits::default(),
            HostClock,
            &recovery,
        )
        .map_err(|_| Error::Runtime("observation transport binding refused"))?;
        provider_requested = true;
        owner
            .observe(&mut tree, &mut transport, wall_now()?)
            .map_err(|_| Error::Runtime("completion observation was refused or inconclusive"))
    })();
    let (receipt, mut failure) = match attempted {
        Ok(receipt) => (receipt, None),
        Err(_) => (
            owner
                .settle(&mut tree, cleanup_time(owner.observed_at()))
                .map_err(|_| Error::Runtime("observation local settlement refused"))?,
            Some("observation_attempt_refused"),
        ),
    };
    if !owner.is_settled() {
        return Err(Error::Runtime("observation owner did not finalize"));
    }
    drop(owner);
    let closed_at = cleanup_time(receipt.observed_at());
    close_parents(&mut root, &mut property, &mut tree, closed_at)?;
    // The original owner and transfer allowance are never changed by this command.
    recovery
        .validate_restore(&journal, closed_at)
        .map_err(|_| Error::Runtime("source journal changed during observation"))?;
    let bytes = receipt
        .encode()
        .map_err(|_| Error::Runtime("canonical observation receipt refused"))?;
    let receipt_durable = local.write_observation_receipt(&bytes).is_ok();
    if !receipt_durable {
        failure = Some("observation_receipt_durability_unconfirmed");
    }
    Ok(Report {
        receipt,
        recovery,
        provider_requested,
        receipt_durable,
        failure,
    })
}

// Cleanup admits no new provider work. A failed or regressed host clock must
// not strand the already owned region; retain its latest verified boundary.
fn cleanup_time(observed_at: TimestampNs) -> TimestampNs {
    wall_now().unwrap_or(observed_at).max(observed_at)
}

pub(super) fn execute(options: &Options) -> Result<(String, bool)> {
    let local = local_io(options, wall_now()?, Instant::now())?;
    let result = execute_in(options, &local);
    let work = local
        .consumed()
        .map_err(|_| Error::Runtime("observation local accounting refused"))?;
    let finalized = local
        .finalize()
        .map_err(|_| Error::Runtime("observation local files could not finalize"));
    let report = result?;
    finalized?;
    render(options, &report, work)
}

fn render(options: &Options, report: &Report, local_work: BudgetVector) -> Result<(String, bool)> {
    let receipt = &report.receipt;
    let recovery = &report.recovery;
    let minimum = options
        .minimum
        .ok_or(Error::Runtime("observation minimum pin absent"))?;
    let completed = receipt.outcome() == CompletionObservationOutcome::Completed;
    let outcome = match receipt.outcome() {
        CompletionObservationOutcome::Completed => "completed",
        CompletionObservationOutcome::Unknown => "unknown",
        CompletionObservationOutcome::NotObserved => "not_observed",
    };
    let receipt_digest = receipt
        .digest()
        .map_err(|_| Error::Runtime("canonical observation receipt digest refused"))?;
    let next = if !report.receipt_durable {
        "retain_source_pin_and_inspect_observation_receipt_before_new_observation"
    } else if completed {
        "retain_observation_receipt_then_verify_independent_retrievability"
    } else {
        "retain_uncertainty_and_authorize_another_bounded_observation_if_needed"
    };
    let mut rendered = object(&[
        ("schema", string("fss.s3_completion_observation_cli.v1")),
        ("kind", string("s3_completion_observation")),
        ("command", string("reconcile")),
        ("resource", string(recovery.intent().resource())),
        (
            "intent_digest",
            string(&recovery.intent().digest().to_text()),
        ),
        (
            "original_operation",
            string(recovery.intent().operation().as_str()),
        ),
        (
            "observation_operation",
            string(
                options
                    .observation
                    .as_ref()
                    .ok_or(Error::Runtime("observation operation absent"))?
                    .operation
                    .as_str(),
            ),
        ),
        ("source_digest", string(&options.source_digest.to_text())),
        ("source_bytes", options.source_bytes.to_string()),
        ("source_verified_this_invocation", "false".into()),
        (
            "plan_digest",
            string(&recovery.intent().plan_digest().to_text()),
        ),
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
        ("original_phase", string("uncertain")),
        ("original_uncertain_operation", string("complete")),
        ("original_local_owner_state", string("indeterminate")),
        (
            "original_indeterminate_receipt_digest",
            string(&receipt.indeterminate_receipt_digest().to_text()),
        ),
        ("original_upload_consumed", budget(&recovery.consumed())),
        (
            "original_upload_remaining",
            budget(&recovery.remaining_budget()),
        ),
        ("observation_outcome", string(outcome)),
        ("observation_allowance", budget(&options.transfer)),
        ("observation_consumed", budget(&receipt.consumed())),
        ("observed_at_ns", receipt.observed_at().0.to_string()),
        (
            "observation_receipt_digest",
            string(&receipt_digest.to_text()),
        ),
        (
            "observation_receipt_durable",
            report.receipt_durable.to_string(),
        ),
        (
            "completion_receipt_digest",
            receipt
                .completion_digest()
                .map_or_else(|| "null".into(), |value| string(&value.to_text())),
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
        ("independent_retrievability_verified", "false".into()),
        ("graph_closure_verified", "false".into()),
        ("client_side_encryption_performed", "false".into()),
    ]);
    rendered.push('\n');
    if rendered.len() > MAX_REPORT_BYTES {
        return Err(Error::Runtime("observation report exceeds its bound"));
    }
    Ok((
        rendered,
        completed && report.receipt_durable && report.failure.is_none(),
    ))
}
