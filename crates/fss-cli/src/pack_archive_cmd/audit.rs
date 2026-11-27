#![forbid(unsafe_code)]
//! Verify a pinned cold ciphertext archive without opening its decryption catalog.

use super::*;
use fss_pack::{
    ColdAuditConfig, ColdRetrievabilityVerdict, audit_cold_pack_retrievability_with_cancel,
};

type Response = (String, ExitIdentity);

pub(super) fn execute(args: &[ArgToken], control: &crate::RequestControl<'_>) -> Response {
    run(args, control).unwrap_or_else(|error| error)
}

fn run(args: &[ArgToken], control: &crate::RequestControl<'_>) -> Result<Response, Response> {
    let cancelled = || {
        err_json(
            "ERR-CLI-READ-CANCELLED-001",
            "cold archive audit cancelled",
            ExitIdentity::RUNTIME_FAILURE,
        )
    };
    let opts = parse_archive_opts("audit", args)?;
    let pin = opts.expected_manifest.ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "--expected-manifest is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    let local_manifest = if let Some(path) = &opts.manifest_file {
        let bytes = read_bounded_regular_file(
            path,
            MAX_COLD_MANIFEST_DOWNLOAD_BYTES as u64,
            "cold archive manifest",
        )?;
        let manifest =
            ColdPackArchiveManifest::from_canonical_bytes(&bytes).map_err(pack_err_to_json)?;
        if manifest.manifest_digest != pin {
            return Err(pack_err_to_json(PackError::DigestMismatch {
                expected: pin,
                actual: manifest.manifest_digest,
            }));
        }
        Some(manifest)
    } else {
        None
    };
    let endpoint = build_s3_endpoint(&opts)?;
    if control.is_cancelled() {
        return Err(cancelled());
    }
    let mut vault = open_archive_vault(&opts)?;
    let credentials = load_s3_credentials(&opts, &endpoint, "op:archive:audit", &vault);
    vault.lock();
    let mut transport =
        S3CompatiblePackTransport::new(endpoint, credentials?, ColdS3Limits::default())
            .map_err(pack_err_to_json)?;
    if control.is_cancelled() {
        return Err(cancelled());
    }
    let now = current_timestamp_ns();
    let manifest = match (local_manifest, opts.manifest_object_key.as_deref()) {
        (Some(manifest), None) => manifest,
        (None, Some(key)) => {
            fetch_cold_pack_manifest(&mut transport, key, pin, now).map_err(pack_err_to_json)?
        }
        _ => {
            return Err(err_json(
                "ERR-CLI-MALFORMED-VALUE-001",
                "expected exactly one manifest source",
                ExitIdentity::MALFORMED_VALUE,
            ));
        }
    };
    let mut config = ColdAuditConfig::default();
    if let Some(limit) = opts.audit_download_limit {
        config.max_download_bytes = limit;
    }
    if manifest.ciphertext_bytes > config.max_download_bytes as u64 {
        return Err(err_json(
            "ERR-PACK-ARCHIVE-001",
            "pinned ciphertext length exceeds the whole-object download budget",
            ExitIdentity::RUNTIME_FAILURE,
        ));
    }
    let receipt = audit_cold_pack_retrievability_with_cancel(
        &mut transport,
        &manifest,
        &config,
        now,
        &|| control.is_cancelled(),
    )
    .map_err(|e| {
        if matches!(e, PackError::Cancelled) {
            cancelled()
        } else {
            pack_err_to_json(e)
        }
    })?;
    if control.is_cancelled() {
        return Err(cancelled());
    }
    let exit = if receipt.verdict == ColdRetrievabilityVerdict::Verified {
        ExitIdentity::SUCCESS
    } else {
        ExitIdentity::RUNTIME_FAILURE
    };
    Ok((
        object(&[
            ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
            ("action", string("audit")),
            ("manifest_pin_verified", "true".to_owned()),
            ("audit", receipt.to_canonical_json()),
        ]),
        exit,
    ))
}
