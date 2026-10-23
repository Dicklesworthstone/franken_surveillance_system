#![forbid(unsafe_code)]
//! Preserve the shared read allowance's typed refusal across existing custody wrappers.

use fss_object::SpoolError;
use fss_reference::ingest::file_adapter::FileIngestError;
use fss_reference::ingest::package_event::PackageEventError;
use fss_reference::ingest::privacy_mask::PrivacyMaskError;
use fss_reference::ingest::recorded_decode::RecordedDecodeError;

use super::Error;

pub(super) fn package_error(error: PackageEventError) -> Error {
    let budget = match &error {
        PackageEventError::Spool(error) => spool(error),
        PackageEventError::Source(error) => decode(error),
        PackageEventError::Privacy(error) => privacy(error),
        PackageEventError::Reference(error) => chained(error.as_ref()),
        PackageEventError::Publication(error) => chained(error.as_ref()),
        _ => None,
    };
    match budget {
        Some(error) => Error::ReadBudget(error),
        None => Error::Package(error),
    }
}

fn spool(error: &SpoolError) -> Option<SpoolError> {
    match error {
        SpoolError::ReadBudgetExceeded {
            resource,
            current,
            requested,
            maximum,
        } => Some(SpoolError::ReadBudgetExceeded {
            resource: *resource,
            current: *current,
            requested: *requested,
            maximum: *maximum,
        }),
        _ => None,
    }
}

fn chained(mut error: &(dyn std::error::Error + 'static)) -> Option<SpoolError> {
    // Existing publication/reference errors expose their typed source. Do not classify
    // untrusted human error text, and do not allow a malformed source chain to loop.
    for _ in 0..16 {
        if let Some(error) = error.downcast_ref::<SpoolError>() {
            return spool(error);
        }
        error = error.source()?;
    }
    None
}

fn privacy(error: &PrivacyMaskError) -> Option<SpoolError> {
    match error {
        PrivacyMaskError::Spool(error) => spool(error),
        PrivacyMaskError::Reference(error) => chained(error.as_ref()),
        _ => None,
    }
}

fn decode(error: &RecordedDecodeError) -> Option<SpoolError> {
    match error {
        RecordedDecodeError::Spool(error) => spool(error),
        RecordedDecodeError::Source(error) => import(error),
        RecordedDecodeError::PrivacyMask(error) => privacy(error),
        RecordedDecodeError::Reference(error) => chained(error),
        RecordedDecodeError::Publication(error) => chained(error),
        _ => None,
    }
}

fn import(error: &FileIngestError) -> Option<SpoolError> {
    match error {
        FileIngestError::Spool(error) => spool(error),
        FileIngestError::CustodyUnavailable { source, .. } => spool(source),
        FileIngestError::Reference(error) => chained(error),
        FileIngestError::LocalPublication(error) => chained(error),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exhausted() -> SpoolError {
        SpoolError::ReadBudgetExceeded {
            resource: "stored_object_read_bytes",
            current: 99,
            requested: 2,
            maximum: 100,
        }
    }

    #[test]
    fn nested_source_and_privacy_limits_keep_the_supervisor_budget_identity() {
        let errors = [
            PackageEventError::Spool(exhausted()),
            PackageEventError::Privacy(Box::new(PrivacyMaskError::Spool(exhausted()))),
            PackageEventError::Source(Box::new(RecordedDecodeError::Source(Box::new(
                FileIngestError::Spool(exhausted()),
            )))),
            PackageEventError::Source(Box::new(RecordedDecodeError::Source(Box::new(
                FileIngestError::CustodyUnavailable {
                    segment_index: 0,
                    chunk_index: 0,
                    chunk: fss_core::ContentDigest::sha256(b"chunk"),
                    source: Box::new(exhausted()),
                },
            )))),
        ];
        for error in errors {
            let classified = package_error(error);
            assert_eq!(classified.stable_id(), "ERR-SUPERVISOR-RETAINED-LIMIT-001");
            assert!(matches!(classified, Error::ReadBudget(_)));
        }
    }

    #[test]
    fn deleted_and_private_sources_preserve_their_original_refusals() {
        let error = PackageEventError::Source(Box::new(RecordedDecodeError::Source(Box::new(
            FileIngestError::EvidenceDeleted {
                import_identity: fss_core::ContentDigest::sha256(b"import"),
                plan_digest: fss_core::ContentDigest::sha256(b"deletion"),
            },
        ))));
        assert_eq!(package_error(error).stable_id(), "ERR-EVIDENCE-DELETED-001");
        let error = PackageEventError::Privacy(Box::new(PrivacyMaskError::UnmaskedAccessRefused));
        let expected = error.stable_id();
        assert_eq!(package_error(error).stable_id(), expected);
    }
}
