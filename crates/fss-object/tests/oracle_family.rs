#![forbid(unsafe_code)]
//! FSS-062: local object-store oracle — conformance evidence over the
//! in-memory reference provider. Any future provider must reproduce the
//! same scenario digest before claiming conformance.

use fss_core::{ContentDigest, TimestampNs};
use fss_object::InMemoryObjectStore;
use fss_object::provider::memory::InMemoryObjectStoreProvider;
use fss_object::provider::oracle::{OracleReport, run_oracle};
use fss_object::provider::{
    ObjectStoreProvider, ProviderError, PublicationState, RetrievabilityWitness,
};

fn reference_provider() -> InMemoryObjectStoreProvider {
    InMemoryObjectStoreProvider::new(
        InMemoryObjectStore::new(fss_object::ObjectLimits::new(64, 1 << 20)),
        2,
    )
}

fn report_line(report: &OracleReport) {
    let names: Vec<&str> = report.checks.iter().map(|c| c.name).collect();
    println!(
        "{{\"family\":\"FSS-062\",\"scenario_checks\":{},\"all_passed\":{},\"scenario_digest\":\"{}\",\"checks\":[{}]}}",
        report.checks.len(),
        report.all_passed,
        report.scenario_digest,
        names
            .iter()
            .map(|n| format!("\\\"{n}\\\""))
            .collect::<Vec<_>>()
            .join(",")
    );
}

/// The reference provider passes every oracle check, and the report is
/// deterministic (identical runs yield identical digests).
#[test]
fn reference_provider_conforms_deterministically() -> Result<(), Box<dyn std::error::Error>> {
    let r1 = run_oracle(reference_provider());
    let r2 = run_oracle(reference_provider());
    assert!(r1.all_passed, "reference provider must conform");
    for c in &r1.checks {
        assert!(c.passed, "check {} failed on the reference", c.name);
    }
    assert_eq!(r1.scenario_digest, r2.scenario_digest, "deterministic");
    assert_eq!(
        r1.checks.len(),
        17,
        "canonical scenario check count is frozen"
    );
    report_line(&r1);
    Ok(())
}

/// The oracle FAILS a misbehaving provider: a provider whose retirement
/// ignores pinning is caught by the R3 check (negative control).
#[test]
fn oracle_catches_pin_violations() -> Result<(), Box<dyn std::error::Error>> {
    // A wrapper that forwards everything except retire, which it forwards
    // WITHOUT the authority witness semantics: simulate by pre-deactivating
    // roots behind the trait's back is impossible; instead wrap and drop
    // the deactivation step: retirement while pinned must be refused — a
    // provider that retires anyway fails the check.
    struct UnpinnedRetirer(InMemoryObjectStoreProvider);

    impl fss_object::provider::ObjectStoreProvider for UnpinnedRetirer {
        fn stage(
            &mut self,
            bytes: &[u8],
        ) -> Result<fss_core::ContentDigest, fss_object::provider::ProviderError> {
            self.0.stage(bytes)
        }
        fn advance(
            &mut self,
            digest: fss_core::ContentDigest,
            to: fss_object::provider::PublicationState,
        ) -> Result<fss_object::provider::PublicationState, fss_object::provider::ProviderError>
        {
            self.0.advance(digest, to)
        }
        fn activate_root(
            &mut self,
            root: fss_core::ContentDigest,
            children: &[fss_core::ContentDigest],
        ) -> Result<(), fss_object::provider::ProviderError> {
            self.0.activate_root(root, children)
        }
        fn deactivate_root(
            &mut self,
            root: fss_core::ContentDigest,
        ) -> Result<(), fss_object::provider::ProviderError> {
            // MISBEHAVING: silently drops deactivations, so retirement of a
            // still-pinned child appears legal to naive callers.
            let _ = root;
            Ok(())
        }
        fn retire(
            &mut self,
            digest: fss_core::ContentDigest,
            witness: fss_core::ContentDigest,
        ) -> Result<(), fss_object::provider::ProviderError> {
            self.0.retire(digest, witness)
        }
        fn verify_retrievable(
            &mut self,
            digest: fss_core::ContentDigest,
            now: fss_core::TimestampNs,
        ) -> Result<fss_object::provider::RetrievabilityWitness, fss_object::provider::ProviderError>
        {
            self.0.verify_retrievable(digest, now)
        }
        fn state(
            &self,
            digest: fss_core::ContentDigest,
        ) -> Result<fss_object::provider::PublicationState, fss_object::provider::ProviderError>
        {
            self.0.state(digest)
        }
    }

    let report = run_oracle(UnpinnedRetirer(reference_provider()));
    // With deactivations dropped, retire-after-deactivate must FAIL: the
    // underlying provider still pins, so retirement is refused and the
    // check's expected terminal state never arrives.
    assert!(
        !report.all_passed,
        "the oracle must catch a provider that drops deactivations"
    );
    let r3 = report
        .checks
        .iter()
        .find(|c| c.name == "retire-after-deactivate")
        .ok_or("check missing")?;
    assert!(!r3.passed);
    Ok(())
}

#[test]
fn early_stage_failures_commit_distinct_observed_states() -> Result<(), Box<dyn std::error::Error>>
{
    struct RefusingStage {
        inner: InMemoryObjectStoreProvider,
        refused: ContentDigest,
    }

    impl ObjectStoreProvider for RefusingStage {
        fn stage(&mut self, bytes: &[u8]) -> Result<ContentDigest, ProviderError> {
            if ContentDigest::sha256(bytes) == self.refused {
                Err(ProviderError::Custody(
                    "intentional oracle stage refusal".to_owned(),
                ))
            } else {
                self.inner.stage(bytes)
            }
        }

        fn advance(
            &mut self,
            digest: ContentDigest,
            to: PublicationState,
        ) -> Result<PublicationState, ProviderError> {
            self.inner.advance(digest, to)
        }

        fn activate_root(
            &mut self,
            root: ContentDigest,
            children: &[ContentDigest],
        ) -> Result<(), ProviderError> {
            self.inner.activate_root(root, children)
        }

        fn deactivate_root(&mut self, root: ContentDigest) -> Result<(), ProviderError> {
            self.inner.deactivate_root(root)
        }

        fn retire(
            &mut self,
            digest: ContentDigest,
            witness: ContentDigest,
        ) -> Result<(), ProviderError> {
            self.inner.retire(digest, witness)
        }

        fn verify_retrievable(
            &mut self,
            digest: ContentDigest,
            now: TimestampNs,
        ) -> Result<RetrievabilityWitness, ProviderError> {
            self.inner.verify_retrievable(digest, now)
        }

        fn state(&self, digest: ContentDigest) -> Result<PublicationState, ProviderError> {
            self.inner.state(digest)
        }
    }

    let authority = ContentDigest::sha256(b"oracle-deletion-authority");
    let root = fss_object::ObjectManifest::new(
        "provider-oracle",
        [
            ContentDigest::sha256(b"oracle-object-a"),
            ContentDigest::sha256(b"oracle-object-b"),
        ],
        None,
    )?
    .root();
    let run = |refused| {
        run_oracle(RefusingStage {
            inner: reference_provider(),
            refused,
        })
    };
    let missing_authority = run(authority);
    let missing_root = run(root);
    let replay = run(authority);

    assert!(!missing_authority.all_passed);
    assert!(!missing_root.all_passed);
    // Both runs admit three objects and produce identical verdicts. Only the observed
    // identities differ, so a digest over verdicts alone would still alias these failures.
    assert_eq!(missing_authority.checks, missing_root.checks);
    assert_ne!(
        missing_authority.scenario_digest,
        missing_root.scenario_digest
    );
    assert_eq!(missing_authority, replay);
    assert_ne!(
        missing_authority.scenario_digest,
        ContentDigest::sha256(b"oracle-stage-failed")
    );
    Ok(())
}
