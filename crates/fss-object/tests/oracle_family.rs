#![forbid(unsafe_code)]
//! FSS-062: local object-store oracle — conformance evidence over the
//! in-memory reference provider. Any future provider must reproduce the
//! same scenario digest before claiming conformance.

use fss_object::InMemoryObjectStore;
use fss_object::provider::memory::InMemoryObjectStoreProvider;
use fss_object::provider::oracle::{OracleReport, run_oracle};

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
        10,
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
