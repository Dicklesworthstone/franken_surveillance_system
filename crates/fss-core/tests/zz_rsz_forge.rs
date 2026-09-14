//! rsz: external crate in crates/fss-core/tests calling the doc(hidden) ctor (guard blind spot).
use fss_core::ReferenceLedger;
use fss_core::abstraction::{AuthoritativeLedger, AuthorityAnchor};

#[test]
fn rsz_forge_from_core_tests_dir() -> Result<(), Box<dyn std::error::Error>> {
    let fresh = ReferenceLedger::new("site:us-east:primary");
    let forged = AuthoritativeLedger::__durable_ledger_only_from_committed_anchor(
        fresh.current().anchor.clone(),
    )?;
    let _a = AuthorityAnchor::from_committed_head(&forged)?;
    println!("RSZ-F forged from fss-core/tests compiles and runs");
    Ok(())
}
