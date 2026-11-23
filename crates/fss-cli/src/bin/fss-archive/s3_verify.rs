#![forbid(unsafe_code)]
//! A separately authorized complete object read, with independent byte identity.
//! Upload journals and upload owners are deliberately not inputs to this command.

use super::*;
use fss_reference::s3_upload::verification::{
    MAX_VERIFIED_OBJECT_BYTES, S3ObjectPin, S3ReadClock, S3ReadIo, S3VerificationReceipt,
    verification_budget, verification_with_bytes_budget, verify_s3_object,
    verify_s3_object_with_bytes,
};

const READ_GRANTS: [RuntimeGrant; 3] = [
    RuntimeGrant::AdapterNet,
    RuntimeGrant::AdapterAuth,
    RuntimeGrant::ReadMedia,
];

pub(super) fn handles(args: &[OsString]) -> bool {
    args.first().is_some_and(|value| {
        value == OsStr::new("verify-s3-object") || value == OsStr::new("restore-s3-object")
    })
}

struct VerifyOptions {
    pin: S3ObjectPin,
    endpoint: S3Endpoint,
    credentials: PathBuf,
    receipt: PathBuf,
    restore_output: Option<PathBuf>,
    operation: OperationId,
    deadline: TimestampNs,
    transfer: BudgetVector,
    local: BudgetVector,
}

fn parse(args: &[OsString]) -> Result<VerifyOptions> {
    const ALLOWED: [&str; 18] = [
        "--object-sha256",
        "--object-bytes",
        "--peer",
        "--host",
        "--region",
        "--bucket",
        "--key",
        "--credentials",
        "--plaintext-approval",
        "--operation",
        "--deadline-ns",
        "--max-memory-bytes",
        "--max-wire-bytes",
        "--max-requests",
        "--max-local-bytes",
        "--max-local-operations",
        "--receipt",
        "--output",
    ];
    if !handles(args)
        || args.len() > 1 + ALLOWED.len() * 2
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(malformed("verification command or argument bound refused"));
    }
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or(Error::Argument(
            ERR_CLI_INVALID_UNICODE,
            "option name must be UTF-8",
        ))?;
        if !ALLOWED.contains(&key) {
            return Err(Error::Argument(
                ERR_CLI_UNKNOWN_OPTION,
                "unknown verification option",
            ));
        }
        if values.contains_key(key) {
            return Err(Error::Argument(
                ERR_CLI_DUPLICATE_OPTION,
                "duplicate verification option",
            ));
        }
        let value = pair
            .get(1)
            .filter(|value| {
                !value.is_empty() && !value.to_str().is_some_and(|value| value.starts_with("--"))
            })
            .ok_or(Error::Argument(
                ERR_CLI_MISSING_VALUE,
                "missing option value",
            ))?;
        values.insert(key, value.as_os_str());
    }
    let text = |key: &str| -> Result<&str> {
        values
            .get(key)
            .ok_or(Error::Argument(
                ERR_CLI_MISSING_VALUE,
                "required verification option missing",
            ))?
            .to_str()
            .ok_or(Error::Argument(
                ERR_CLI_INVALID_UNICODE,
                "option value must be UTF-8",
            ))
    };
    let number = |key: &str, minimum: u64, maximum: u64| -> Result<u64> {
        let raw = text(key)?;
        if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(malformed("bounded unsigned decimal integer required"));
        }
        let value = raw
            .parse::<u64>()
            .map_err(|_| malformed("integer overflow"))?;
        if !(minimum..=maximum).contains(&value) {
            return Err(malformed("numeric bound refused"));
        }
        Ok(value)
    };
    let digest = |key: &str| -> Result<ContentDigest> {
        let value = ContentDigest::parse(text(key)?)
            .map_err(|_| malformed("canonical SHA-256 digest required"))?;
        if value.algorithm() != DigestAlgorithm::Sha256
            || value.is_laboratory()
            || value.bytes() == [0; 32]
        {
            return Err(malformed("nonzero canonical SHA-256 digest required"));
        }
        Ok(value)
    };
    let path = |key: &str| -> Result<PathBuf> {
        let raw = text(key)?;
        let value = PathBuf::from(raw);
        if !value.is_absolute()
            || raw.chars().any(char::is_control)
            || value.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(malformed("absolute normalized path required"));
        }
        Ok(value)
    };
    let raw_deadline = text("--deadline-ns")?;
    if raw_deadline.is_empty() || !raw_deadline.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed("positive decimal deadline required"));
    }
    let deadline = TimestampNs(
        raw_deadline
            .parse::<i128>()
            .map_err(|_| malformed("deadline overflow"))?,
    );
    if deadline.0 == 0 {
        return Err(malformed("positive deadline required"));
    }
    let endpoint = S3Endpoint::new(
        text("--peer")?
            .parse::<SocketAddr>()
            .map_err(|_| malformed("pinned IP address and port required"))?,
        text("--host")?,
        text("--region")?,
        text("--bucket")?,
        text("--key")?,
        digest("--plaintext-approval")?,
    )
    .map_err(|_| malformed("local endpoint or explicit plaintext approval refused"))?;
    let credentials = path("--credentials")?;
    let receipt = path("--receipt")?;
    if receipt.starts_with(&credentials) || credentials.starts_with(&receipt) {
        return Err(malformed("receipt and credential paths must be separate"));
    }
    let restore_output = if args[0] == OsStr::new("restore-s3-object") {
        let output = path("--output")?;
        if [&credentials, &receipt]
            .into_iter()
            .any(|other| output.starts_with(other) || other.starts_with(&output))
        {
            return Err(malformed(
                "restoration output, receipt and credentials must be separate",
            ));
        }
        Some(output)
    } else {
        if values.contains_key("--output") {
            return Err(malformed("only restore-s3-object accepts an output file"));
        }
        None
    };
    let mut transfer = BudgetVector::ZERO;
    transfer.bytes = number("--max-memory-bytes", 1, 1024 * 1024 * 1024)?;
    transfer.network_bytes = number("--max-wire-bytes", 1, 1024 * 1024 * 1024)?;
    transfer.storage_operations = number("--max-requests", 1, 65_536)?;
    let mut local = BudgetVector::ZERO;
    local.latency_ms = (LOCAL_RUNTIME_NS / 1_000_000) as u64;
    local.bytes = number("--max-local-bytes", 1, 1024 * 1024 * 1024)?;
    local.storage_operations = number("--max-local-operations", 1, 4_000_000)?;
    let pin = S3ObjectPin {
        digest: digest("--object-sha256")?,
        bytes: number("--object-bytes", 0, MAX_VERIFIED_OBJECT_BYTES)?,
    };
    let minimum = if restore_output.is_some() {
        verification_with_bytes_budget(pin, S3Limits::default())
    } else {
        verification_budget(pin, S3Limits::default())
    }
    .map_err(|_| malformed("independent object identity or verification bounds refused"))?;
    if !minimum.fits_within(transfer) {
        return Err(malformed(
            "transfer allowance cannot cover a complete bounded verification",
        ));
    }
    Ok(VerifyOptions {
        pin,
        endpoint,
        credentials,
        receipt,
        restore_output,
        deadline,
        transfer,
        local,
        operation: OperationId::parse(text("--operation")?)
            .map_err(|_| malformed("invalid stable operation identity"))?,
    })
}

fn authority_spec(
    options: &VerifyOptions,
    allowance: BudgetVector,
    deadline: TimestampNs,
    grants: &[RuntimeGrant],
) -> RootAuthoritySpec {
    RootAuthoritySpec {
        trace_id: "trace:archive-s3-verification".into(),
        operation_id: options.operation.clone(),
        principal: PRINCIPAL.into(),
        capabilities: grants
            .iter()
            .map(|grant| grant.as_str().to_owned())
            .collect(),
        deadline: Some(deadline),
        priority: 10,
        budgets: allowance,
        privacy_scope: "privacy:owner-approved-local-object-read".into(),
        retention_scope: "retention:immutable-object-verification-receipt".into(),
        anchor_universe: options.pin.digest,
        generation: 1,
    }
}

fn local_io(options: &VerifyOptions, now: TimestampNs, started: Instant) -> Result<ScopedS3Io> {
    let deadline = TimestampNs(
        now.0
            .checked_add(LOCAL_RUNTIME_NS)
            .ok_or(Error::Runtime("local deadline overflow"))?,
    );
    let grants = [RuntimeGrant::AdapterAuth, RuntimeGrant::ObjectStage];
    let (authority, tree) = AuthorityCx::root(
        authority_spec(options, options.local, deadline, &grants),
        RegionId::new("region:archive-s3-verification-local")
            .map_err(|_| Error::Runtime("local region identity refused"))?,
        RegionKind::Process,
        options.local,
        now,
    )
    .map_err(|_| Error::Runtime("local receipt authority refused"))?;
    ScopedS3Io::verification(
        options.credentials.clone(),
        options.receipt.clone(),
        options
            .restore_output
            .as_ref()
            .map(|path| (path.clone(), options.deadline)),
        authority,
        tree,
        started,
        now,
    )
    .map_err(|_| Error::Runtime("scoped credential and receipt files refused"))
}

fn read_owners(
    options: &VerifyOptions,
    now: TimestampNs,
) -> Result<(AuthorityCx, AuthorityCx, AuthorityCx, RegionTree)> {
    let spec = authority_spec(options, options.transfer, options.deadline, &READ_GRANTS);
    let (mut root, mut tree) = AuthorityCx::root(
        spec.clone(),
        RegionId::new("region:archive-s3-verification-process")
            .map_err(|_| Error::Runtime("read process identity refused"))?,
        RegionKind::Process,
        options.transfer,
        now,
    )
    .map_err(|_| Error::Runtime("read process authority refused"))?;
    let mut scopes = GrantSet::empty();
    for grant in READ_GRANTS {
        scopes = scopes.with_scope(
            grant,
            [options.endpoint.resource().to_owned()]
                .into_iter()
                .collect(),
        );
    }
    root.narrow_grants(scopes)
        .map_err(|_| Error::Runtime("read resource scope refused"))?;
    let mut property = root
        .scope_down(
            &mut tree,
            RegionId::new("region:archive-s3-verification-property")
                .map_err(|_| Error::Runtime("read property identity refused"))?,
            RegionKind::Property,
            options.transfer,
            spec.clone(),
            now,
        )
        .map_err(|_| Error::Runtime("read property authority refused"))?;
    let reader = property
        .scope_down(
            &mut tree,
            RegionId::new("region:archive-s3-verification-object")
                .map_err(|_| Error::Runtime("read object identity refused"))?,
            RegionKind::ObjectStore,
            options.transfer,
            spec,
            now,
        )
        .map_err(|_| Error::Runtime("fresh object read authority refused"))?;
    Ok((root, property, reader, tree))
}

struct ReadClock {
    latest: TimestampNs,
}
impl S3ReadClock for ReadClock {
    fn now(&mut self, _authority: &AuthorityCx) -> std::result::Result<TimestampNs, S3Error> {
        let now = wall_now().map_err(|_| S3Error::Clock)?;
        // Remember the last valid upper boundary for cleanup only. Return the
        // actual clock value so the verifier still rejects a clock regression.
        self.latest = self.latest.max(now);
        Ok(now)
    }
}

struct Report {
    receipt: Option<S3VerificationReceipt>,
    durable: bool,
    consumed: BudgetVector,
    output: Option<RestoreOutputState>,
    failure: Option<&'static str>,
}

fn refusal(error: S3Error) -> &'static str {
    match error {
        S3Error::Integrity => "object_digest_mismatch",
        S3Error::Authority => "read_authority_refused",
        S3Error::Clock => "clock_refused",
        S3Error::Deadline => "read_deadline_reached",
        S3Error::Limit => "read_bound_reached",
        S3Error::Io => "object_read_io_refused",
        S3Error::Status(_) => "provider_status_refused",
        S3Error::Protocol => "range_or_version_proof_refused",
        S3Error::Configuration | S3Error::Binding | S3Error::Uncertain => {
            "read_configuration_refused"
        }
    }
}

fn execute_in(options: &VerifyOptions, local: &ScopedS3Io) -> Result<Report> {
    // Refuse occupied or unsafe custody before reading secrets or opening a socket.
    local
        .preflight_observation_receipt()
        .map_err(|_| Error::Runtime("new immutable verification receipt destination refused"))?;
    if options.restore_output.is_some() {
        local
            .preflight_restore_output()
            .map_err(|_| Error::Runtime("new private restoration output destination refused"))?;
    }
    let secret = local
        .read_credentials()
        .map_err(|_| Error::Runtime("private bounded credential file refused"))?;
    let credentials = S3Credentials::from_lines(secret)
        .map_err(|_| Error::Runtime("credential file format refused"))?;
    let now = wall_now()?;
    if now >= options.deadline {
        return Err(Error::Runtime("verification deadline has already expired"));
    }
    let (mut root, mut property, mut reader, mut tree) = read_owners(options, now)?;
    let mut clock = ReadClock { latest: now };
    let read_io = S3ReadIo {
        authority: &mut reader,
        tree: &tree,
        now,
    };
    let result = if options.restore_output.is_some() {
        verify_s3_object_with_bytes(
            &options.endpoint,
            &credentials,
            S3Limits::default(),
            &mut clock,
            read_io,
            options.pin,
        )
        .map(|object| (object.receipt().clone(), Some(object)))
    } else {
        verify_s3_object(
            &options.endpoint,
            &credentials,
            S3Limits::default(),
            &mut clock,
            read_io,
            options.pin,
        )
        .map(|receipt| (receipt, None))
    };
    let consumed = *reader.budget().consumed();
    // No new provider work is admitted during cleanup, including on error.
    let closed_at = wall_now().unwrap_or(clock.latest).max(clock.latest);
    reader
        .request_cancellation(&mut tree, closed_at)
        .and_then(|()| reader.begin_drain(&mut tree, closed_at))
        .and_then(|()| reader.finalize(&mut tree, closed_at).map(|_| ()))
        .map_err(|_| Error::Runtime("object read owner could not finalize"))?;
    property
        .release_scope_reservation(&tree, &mut reader)
        .map_err(|_| Error::Runtime("object read reservation remained owned"))?;
    close_parents(&mut root, &mut property, &mut tree, closed_at)?;
    let mut output = options
        .restore_output
        .as_ref()
        .map(|_| RestoreOutputState::default());
    let (receipt, verified_bytes) = match result {
        Ok(verified) => verified,
        Err(error) => {
            return Ok(Report {
                receipt: None,
                durable: false,
                consumed,
                output,
                failure: Some(refusal(error)),
            });
        }
    };
    let encoded = receipt
        .encode()
        .map_err(|_| Error::Runtime("canonical verification receipt refused"))?;
    let mut failure = None;
    if let (Some(verified), Some(state)) = (verified_bytes.as_ref(), output.as_mut())
        && local.write_verified_s3_object(verified, state).is_err()
    {
        failure = Some(if state.created {
            "restoration_output_durability_unconfirmed"
        } else {
            "restoration_output_refused"
        });
    }
    // Retained media is erased before receipt publication and bounded report rendering.
    drop(verified_bytes);
    let durable = local.write_observation_receipt(&encoded).is_ok();
    if !durable {
        failure = Some("verification_receipt_durability_unconfirmed");
    }
    Ok(Report {
        receipt: Some(receipt),
        durable,
        consumed,
        output,
        failure,
    })
}

fn execute(options: &VerifyOptions) -> Result<(String, bool)> {
    let started = Instant::now();
    let now = wall_now()?;
    if now >= options.deadline {
        return Err(Error::Runtime("verification deadline has already expired"));
    }
    let local = local_io(options, now, started)?;
    let attempted = execute_in(options, &local);
    let work = local
        .consumed()
        .map_err(|_| Error::Runtime("local accounting refused"));
    // Drain even when verification or local accounting failed.
    let finalized = local
        .finalize()
        .map_err(|_| Error::Runtime("local receipt owner could not finalize"));
    let mut report = attempted?;
    if options.restore_output.is_some() {
        // Preserve concrete output custody even if accounting or final cleanup failed.
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
    options: &VerifyOptions,
    report: &Report,
    local_work: Option<BudgetVector>,
) -> Result<(String, bool)> {
    let verified = report.receipt.is_some();
    let restoring = options.restore_output.is_some();
    let receipt_digest = report
        .receipt
        .as_ref()
        .map(S3VerificationReceipt::digest)
        .transpose()
        .map_err(|_| Error::Runtime("verification receipt identity refused"))?;
    let next = if report
        .output
        .is_some_and(|output| output.created && !output.durable)
    {
        "inspect_private_partial_output_before_authorizing_a_new_restore"
    } else if restoring && report.output.is_some_and(|output| output.durable) {
        if report.durable && report.failure.is_none() {
            "retain_restored_object_independent_identity_and_verification_receipt"
        } else {
            "retain_restored_object_and_inspect_receipt_or_local_settlement"
        }
    } else if restoring {
        "retain_independent_object_identity_and_inspect_refusal_before_another_bounded_restore"
    } else if report.durable {
        "retain_independent_object_identity_and_verification_receipt"
    } else if verified {
        "retain_object_identity_and_inspect_receipt_before_another_verification"
    } else {
        "retain_uncertainty_and_inspect_refusal_before_another_bounded_read"
    };
    let mut fields = vec![
        (
            "schema",
            string(if restoring {
                "fss.s3_object_restoration_cli.v1"
            } else {
                "fss.s3_object_verification_cli.v1"
            }),
        ),
        (
            "kind",
            string(if restoring {
                "s3_object_restoration"
            } else {
                "s3_object_verification"
            }),
        ),
        (
            "command",
            string(if restoring {
                "restore-s3-object"
            } else {
                "verify-s3-object"
            }),
        ),
        ("resource", string(options.endpoint.resource())),
        ("operation", string(options.operation.as_str())),
        ("object_digest", string(&options.pin.digest.to_text())),
        ("object_bytes", options.pin.bytes.to_string()),
        ("object_bytes_verified", verified.to_string()),
        (
            "verified_at_ns",
            report.receipt.as_ref().map_or_else(
                || "null".into(),
                |receipt| receipt.verified_at().0.to_string(),
            ),
        ),
        (
            "verification_receipt_digest",
            receipt_digest.map_or_else(|| "null".into(), |digest| string(&digest.to_text())),
        ),
        ("verification_receipt_durable", report.durable.to_string()),
        ("read_allowance", budget(&options.transfer)),
        ("read_consumed", budget(&report.consumed)),
        (
            "provider_work_requested_this_invocation",
            (report.consumed.storage_operations != 0).to_string(),
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
        ("graph_closure_verified", "false".into()),
        ("client_side_encryption_performed", "false".into()),
        (
            "raw_media_exported",
            report
                .output
                .is_some_and(|output| output.created)
                .to_string(),
        ),
    ];
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
        return Err(Error::Runtime("verification report exceeds its bound"));
    }
    Ok((
        rendered,
        verified
            && report.durable
            && report.failure.is_none()
            && report.output.is_none_or(|output| output.durable),
    ))
}

pub(super) fn dispatch(args: &[OsString]) -> ExitCode {
    match parse(args).and_then(|options| execute(&options)) {
        Ok((report, success)) => {
            if super::super::emit(&mut io::stdout().lock(), report.as_bytes()).is_err() {
                eprintln!(
                    "{ERR_CLI_RUNTIME_FAILURE}: verification report output failed; inspect the receipt"
                );
                return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
            }
            ExitCode::from(if success {
                ExitIdentity::SUCCESS.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            })
        }
        Err(error) => {
            let (code, status) = match &error {
                Error::Argument(code, _) => (*code, ExitIdentity::MALFORMED_VALUE),
                Error::Runtime(_) => (ERR_CLI_RUNTIME_FAILURE, ExitIdentity::RUNTIME_FAILURE),
            };
            eprintln!("{code}: {error}");
            ExitCode::from(status.code)
        }
    }
}
