#![forbid(unsafe_code)]
//! Cold verification of a completed object's actual bytes, without reopening its
//! upload owner, reading the local source, or mutating historical upload evidence.

use super::*;
use fss_object::uploader::{
    CompletionObservationReceipt, RetrievalObservation, RetrievalOutcome, RetrievalReceipt,
    UploaderError, VerifiedRetrievalBytes,
};

struct Report {
    receipt: RetrievalReceipt,
    recovery: MultipartRecovery,
    provider_requested: bool,
    receipt_durable: bool,
    output: Option<RestoreOutputState>,
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
    let completion_observation = if let Some(input) = &options.completion_observation {
        let bytes = local
            .read_completion_observation()
            .map_err(|_| Error::Runtime("private bounded completion observation input refused"))?;
        if ContentDigest::sha256(&bytes) != input.digest {
            return Err(Error::Runtime(
                "completion observation independent digest mismatch",
            ));
        }
        let observation = CompletionObservationReceipt::decode(&bytes)
            .map_err(|_| Error::Runtime("canonical completion observation input refused"))?;
        RetrievalObservation::validate_observed_source(
            &recovery,
            &expected,
            options.source_digest,
            &observation,
            input.digest,
        )
        .map_err(|_| {
            Error::Runtime(
                "retrieval completion observation does not bind the exact indeterminate upload",
            )
        })?;
        Some((observation, input.digest))
    } else {
        RetrievalObservation::validate_source(&recovery, &expected, options.source_digest)
            .map_err(|_| Error::Runtime("retrieval requires exact completed upload evidence or a pinned completion observation"))?;
        None
    };
    local
        .preflight_observation_receipt()
        .map_err(|_| Error::Runtime("new immutable retrieval receipt destination refused"))?;
    if options.command == Command::Restore {
        local
            .preflight_restore_output()
            .map_err(|_| Error::Runtime("new private restoration output destination refused"))?;
    }
    let (mut root, mut property, mut tree, child) = authority(options, now)?;
    let mut owner = if let Some((observation, digest)) = &completion_observation {
        RetrievalObservation::begin_from_observation(
            &mut property,
            &mut tree,
            &journal,
            &recovery,
            &expected,
            options.source_digest,
            observation,
            *digest,
            child,
            now,
        )
    } else {
        RetrievalObservation::begin(
            &mut property,
            &mut tree,
            &journal,
            &recovery,
            &expected,
            options.source_digest,
            child,
            now,
        )
    }
    .map_err(|_| Error::Runtime("fresh read-media retrieval authority refused"))?;
    let mut provider_requested = false;
    let attempted = (|| -> Result<(RetrievalReceipt, Option<VerifiedRetrievalBytes>)> {
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
        if options.command == Command::Restore {
            let verified = owner
                .verify_with_bytes(&mut tree, &mut transport, || {
                    wall_now()
                        .map_err(|_| UploaderError::Authority("retrieval clock unavailable".into()))
                })
                .map_err(|_| Error::Runtime("independent restoration retrieval did not verify"))?;
            Ok((verified.receipt().clone(), Some(verified)))
        } else {
            owner
                .verify(&mut tree, &mut transport, || {
                    wall_now()
                        .map_err(|_| UploaderError::Authority("retrieval clock unavailable".into()))
                })
                .map(|receipt| (receipt, None))
                .map_err(|_| Error::Runtime("independent retrieval was refused or did not verify"))
        }
    })();
    let (receipt, verified_bytes, mut failure) = match attempted {
        Ok((receipt, verified)) => (receipt, verified, None),
        Err(_) => {
            let receipt = owner
                .settle(&mut tree, cleanup_time(owner.observed_at()))
                .map_err(|_| Error::Runtime("retrieval local settlement refused"))?;
            let failure = if receipt.outcome() == RetrievalOutcome::Mismatch {
                "retrieval_verification_mismatch"
            } else {
                "retrieval_attempt_refused"
            };
            (receipt, None, Some(failure))
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
    let mut output = (options.command == Command::Restore).then(RestoreOutputState::default);
    if let (Some(verified), Some(state)) = (verified_bytes.as_ref(), output.as_mut())
        && local.write_restored_object(verified, state).is_err()
    {
        failure = Some(if state.created {
            "restoration_output_durability_unconfirmed"
        } else {
            "restoration_output_refused"
        });
    }
    // Erase the retained media before receipt publication or rendering.
    drop(verified_bytes);
    let receipt_durable = local.write_observation_receipt(&bytes).is_ok();
    if !receipt_durable {
        failure = Some("retrieval_receipt_durability_unconfirmed");
    }
    Ok(Report {
        receipt,
        recovery,
        provider_requested,
        receipt_durable,
        output,
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
        .map_err(|_| Error::Runtime("retrieval local accounting refused"));
    let finalized = local
        .finalize()
        .map_err(|_| Error::Runtime("retrieval local files could not finalize"));
    let mut report = result?;
    if options.command == Command::Restore {
        if work.is_err() {
            report.failure = Some("restoration_local_accounting_unavailable");
        }
        if finalized.is_err() {
            report.failure = Some("restoration_local_settlement_refused");
        }
        render(options, &report, work.ok())
    } else {
        finalized?;
        render(options, &report, Some(work?))
    }
}

fn render(
    options: &Options,
    report: &Report,
    local_work: Option<BudgetVector>,
) -> Result<(String, bool)> {
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
    } else if report
        .output
        .is_some_and(|output| output.created && !output.durable)
    {
        "inspect_private_partial_output_before_authorizing_a_new_restore"
    } else if report.output.is_some_and(|output| output.durable) {
        "retain_restored_object_and_retrieval_receipt_before_separate_graph_or_replica_verification"
    } else if options.command == Command::Restore {
        "retain_source_pin_and_authorize_a_new_bounded_restore_if_needed"
    } else if verified {
        "retain_retrieval_receipt_before_separate_graph_or_replica_verification"
    } else {
        "retain_source_pin_and_authorize_a_new_bounded_verification_if_needed"
    };
    let observed = receipt.completion_observation_digest().is_some();
    let mut fields = vec![
        (
            "schema",
            string(if options.command == Command::Restore {
                "fss.s3_restoration_cli.v1"
            } else if observed {
                "fss.s3_retrieval_observation_cli.v2"
            } else {
                "fss.s3_retrieval_observation_cli.v1"
            }),
        ),
        (
            "kind",
            string(if options.command == Command::Restore {
                "s3_restoration"
            } else {
                "s3_retrieval_observation"
            }),
        ),
        ("command", string(options.command.name())),
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
        (
            "original_phase",
            string(if observed { "uncertain" } else { "completed" }),
        ),
        (
            "original_local_owner_state",
            string(if observed {
                "indeterminate"
            } else {
                "verified"
            }),
        ),
        (
            if observed {
                "observed_completion_receipt_digest"
            } else {
                "original_completion_receipt_digest"
            },
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
        (
            "local_work",
            local_work.map_or_else(|| "null".into(), |work| budget(&work)),
        ),
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
    ];
    if let (Some(observation), Some(indeterminate)) = (
        receipt.completion_observation_digest(),
        receipt.indeterminate_receipt_digest(),
    ) {
        fields.extend([
            ("original_uncertain_operation", string("complete")),
            (
                "completion_observation_digest",
                string(&observation.to_text()),
            ),
            (
                "original_indeterminate_receipt_digest",
                string(&indeterminate.to_text()),
            ),
        ]);
    }
    if let Some(output) = report.output {
        fields.extend([
            ("output_created", output.created.to_string()),
            ("output_verified", output.verified.to_string()),
            ("output_durable", output.durable.to_string()),
            ("restored_bytes", output.bytes.to_string()),
            (
                "restored_digest",
                output
                    .digest
                    .map_or_else(|| "null".into(), |digest| string(&digest.to_text())),
            ),
        ]);
    }
    let mut rendered = object(&fields);
    rendered.push('\n');
    if rendered.len() > MAX_REPORT_BYTES {
        return Err(Error::Runtime("retrieval report exceeds its bound"));
    }
    Ok((
        rendered,
        verified
            && report.receipt_durable
            && report.failure.is_none()
            && report.output.is_none_or(|output| output.durable),
    ))
}
