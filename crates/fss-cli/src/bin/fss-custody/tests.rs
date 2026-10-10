#![forbid(unsafe_code)]
//! Native publication bytes; the verified-snapshot seam is explicitly injected in these tests.
use super::*;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use fss_core::{
    CanonicalEncode, CaptureInterval, DecisionPath, EventEvidence, EventHypothesis,
    EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, ProbabilityInterval, TimestampNs,
};
use fss_object::{ObjectManifest, encode_spool_object};
use fss_publication::{SlotName, root_record_bytes};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn args(extra: &[&str]) -> Vec<OsString> {
    ["audit", "--root", "/unused", "--site", "site:audit", "--event-id", "event:fixture"]
        .into_iter().chain(extra.iter().copied()).map(OsString::from).collect()
}
fn request(extra: &[&str]) -> TestResult<Request> {
    parse(&args(extra)).map_err(|e| format!("{e:?}"))?.ok_or_else(|| "unexpected help".into())
}
struct Fixture { root: PathBuf, view: ReadView, leaf: ContentDigest }
impl Fixture {
    fn new(label: &str) -> TestResult<Self> {
        for n in 0..32 {
            let root = std::env::temp_dir().join(format!("fss-custody-cli-{label}-{}-{n}", std::process::id()));
            match fs::create_dir(&root) {
                Ok(()) => return Self::populate(root),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture names exhausted".into())
    }
    fn populate(root: PathBuf) -> TestResult<Self> {
        let publication = root.join(RELATIVE_PATH_OBJECTS);
        for dir in ["roots", "tombstones", "spool/objects"] { fs::create_dir_all(publication.join(dir))?; }
        let put = |bytes: &[u8]| -> TestResult<ContentDigest> {
            let d = ContentDigest::sha256(bytes);
            fs::write(publication.join("spool/objects").join(d.to_text().trim_start_matches("sha256:")), encode_spool_object(d, bytes)?)?;
            Ok(d)
        };
        let leaf = put(b"retained source, never printed")?;
        let policy = ContentDigest::sha256(b"reference policy");
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_owned(), event_id: EventId::parse("event:fixture")?,
            revision: 1, supersedes: None, state: EventState::Indeterminate, kind: EventKind::Unclassified,
            interval: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
            uncertainty_reason: Some("synthetic; source existence does not prove presence".to_owned()),
            zone_ids: vec!["fixture-zone".to_owned()], track_ids: vec![],
            probability: ProbabilityInterval { lower: 0.0, upper: 1.0, calibration_generation: None },
            evidence: vec![EventEvidence {
                digest: leaf, class: EvidenceClass::Observed, failure_domain: "sensor:fixture".to_owned(),
                supports: false, relation: EvidenceEdgeRelation::Contradicts, capsule_digest: None, identity_digest: None,
            }],
            model_receipts: vec![], decision_path: DecisionPath {
                policy_generation: policy, fingerprint: policy, abstained: true, abstention_reason: Some("unclassified".to_owned()),
            },
        };
        let event_bytes = put(&event.to_versioned_bytes()?)?;
        let manifest = ObjectManifest::new("event-fixture", [leaf, event_bytes], None)?;
        let event_root = put(&manifest.canonical_bytes())?;
        fs::write(publication.join("roots/event.root"), root_record_bytes(&SlotName::parse("event")?, event_root, 2)?)?;
        let view = ReadView {
            basis: Basis {
                site: "site:audit".to_owned(), position: HistoryPosition { commit_sequence: 0, effect_records: None },
                anchor: LedgerAnchor::genesis("site:audit"), ledger_root: policy, effect_root: policy,
                ledger_tail: true, effect_tail: false, event: event.event_id.clone(), event_root,
                revision_digest: event.revision_digest(), event_json: event.to_canonical_json(), denied: BTreeMap::new(),
            }, files: 3, bytes: 500,
        };
        Ok(Self { root, view, leaf })
    }
    fn request(&self) -> TestResult<Request> { let mut r = request(&[])?; r.root = self.root.clone(); Ok(r) }
    fn source_path(&self) -> PathBuf {
        self.root.join(RELATIVE_PATH_OBJECTS).join("spool/objects").join(self.leaf.to_text().trim_start_matches("sha256:"))
    }
    fn execute(&self, request: &Request) -> Result<(String, bool), Error> {
        execute_with(request, &HostSpoolIo, || Ok(self.view.clone()), &|| false)
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }
fn okay<T>(result: Result<T, Error>) -> TestResult<T> { result.map_err(|e| format!("{e:?}").into()) }

#[test]
fn strict_parser_rejects_missing_duplicate_foreign_and_overflow_options() -> TestResult {
    assert!(parse(&args(&[])).is_ok());
    for extra in [
        vec!["--site", "site:other"], vec!["--event-id", "event:other"], vec!["--unknown", "1"],
        vec!["--timeout-ms", "0"], vec!["--max-objects", "65537"], vec!["--max-read-bytes", "4294967297"],
        vec!["--max-edges", "18446744073709551616"], vec!["--max-io-calls", "-1"],
        vec!["--max-report-bytes", "1023"], vec!["--max-io-calls", "1", "--max-io-calls", "2"],
    ] { assert!(parse(&args(&extra)).is_err(), "{extra:?}"); }
    let mut missing = args(&[]); missing.truncate(5); assert!(parse(&missing).is_err());
    let r = request(&["--max-read-bytes", "0", "--max-objects", "0"])?;
    assert_eq!(r.limits.max_read_bytes, 0); assert_eq!(r.limits.max_objects, 0);
    Ok(())
}
#[test]
fn hard_argument_bounds_and_standalone_help_are_preserved() {
    assert!(matches!(parse(&["--help".into()]), Ok(None)));
    assert!(matches!(parse(&["audit".into(), "--help".into()]), Ok(None)));
    assert!(parse(&["--help".into(), "extra".into()]).is_err());
    assert!(parse(&vec!["x".into(); MAX_ARGS + 1]).is_err());
    let mut a = args(&[]); a[2] = "x".repeat(MAX_ARG_BYTES + 1).into(); assert!(parse(&a).is_err());
}
#[cfg(unix)]
#[test]
fn native_paths_are_preserved_but_event_ids_require_unicode() {
    use std::os::unix::ffi::OsStringExt;
    let mut a = args(&[]); a[2] = OsString::from_vec(b"/unused/\xff".to_vec()); assert!(parse(&a).is_ok());
    a[6] = OsString::from_vec(b"event:\xff".to_vec()); assert!(parse(&a).is_err());
}
#[test]
fn exact_current_root_and_identity_are_checked_before_audit_io() -> TestResult {
    let f = Fixture::new("pins")?;
    let mut r = f.request()?;
    r.expected = Some(ContentDigest::sha256(b"not the selected root"));
    assert_eq!(f.execute(&r), Err(Error::StaleRoot));
    r.expected = Some(f.view.basis.event_root); assert!(okay(f.execute(&r))?.1);
    r.site = "site:other".to_owned(); assert_eq!(f.execute(&r), Err(Error::SiteMismatch));
    r.site = "site:audit".to_owned(); r.event = EventId::parse("event:other")?;
    assert_eq!(f.execute(&r), Err(Error::EventNotFound));
    Ok(())
}
#[test]
fn native_payload_audit_preserves_complete_event_metadata_and_tails() -> TestResult {
    let f = Fixture::new("intact")?;
    let (report, intact) = okay(f.execute(&f.request()?))?;
    assert!(intact);
    assert!(report.contains(&format!("\"event_record\":{}", f.view.basis.event_json)));
    assert!(report.contains("\"ledger_tail_uncommitted\":true"));
    assert!(report.contains("\"status\":\"intact_at_observation\""));
    assert!(!report.contains("retained source, never printed"));
    assert_eq!(report, okay(f.execute(&f.request()?))?.0);
    Ok(())
}
#[test]
fn missing_and_corrupt_source_produce_complete_non_success_reports() -> TestResult {
    let f = Fixture::new("missing")?;
    fs::remove_file(f.source_path())?;
    let (report, intact) = okay(f.execute(&f.request()?))?;
    assert!(!intact); assert!(report.contains("\"state\":\"missing\""));
    assert!(report.contains("\"status\":\"custody_faults\""));
    fs::write(f.source_path(), b"broken envelope")?;
    let (report, intact) = okay(f.execute(&f.request()?))?;
    assert!(!intact); assert!(report.contains("\"state\":\"corrupt\""));
    Ok(())
}
#[test]
fn verified_deletion_basis_denies_existing_corrupt_payload() -> TestResult {
    let mut f = Fixture::new("denied")?;
    fs::write(f.source_path(), b"must not be read")?;
    f.view.basis.denied.insert(f.leaf, ContentDigest::sha256(b"verified deletion plan seam"));
    let (report, intact) = okay(f.execute(&f.request()?))?;
    assert!(!intact); assert!(report.contains("\"state\":\"deleted\""));
    assert!(!report.contains("\"state\":\"corrupt\""));
    Ok(())
}
#[test]
fn every_material_authority_change_during_audit_refuses_the_report() -> TestResult {
    let f = Fixture::new("changed")?;
    for change in 0..6 {
        let mut after = f.view.clone();
        let changed = ContentDigest::sha256(b"changed");
        match change {
            0 => after.basis.ledger_root = changed,
            1 => { after.basis.denied.insert(f.leaf, changed); }
            2 => after.basis.event_root = changed,
            3 => after.basis.effect_root = changed,
            4 => after.basis.ledger_tail = false,
            _ => after.basis.position.commit_sequence += 1,
        }
        let mut reads = 0;
        let r = execute_with(&f.request()?, &HostSpoolIo, || {
            reads += 1; Ok(if reads == 1 { f.view.clone() } else { after.clone() })
        }, &|| false);
        assert_eq!(r, Err(Error::BasisChanged)); assert_eq!(reads, 2);
    }
    Ok(())
}
#[test]
fn output_limits_include_final_newline_and_never_trim_faults() -> TestResult {
    let f = Fixture::new("report-bound")?;
    fs::remove_file(f.source_path())?;
    let mut r = f.request()?;
    let (report, _) = okay(f.execute(&r))?;
    r.report_limit = report.len(); assert_eq!(okay(f.execute(&r))?.0, report);
    r.report_limit -= 1; assert_eq!(f.execute(&r), Err(Error::OutputBound));
    Ok(())
}
#[test]
fn cancellation_before_read_and_at_custody_io_never_returns_an_intact_report() -> TestResult {
    let f = Fixture::new("cancel")?;
    let mut reads = 0;
    let r = execute_with(&f.request()?, &HostSpoolIo, || { reads += 1; Ok(f.view.clone()) }, &|| true);
    assert_eq!(r, Err(Error::Stopped)); assert_eq!(reads, 0);
    let checks = AtomicUsize::new(0);
    let r = execute_with(&f.request()?, &HostSpoolIo, || Ok(f.view.clone()), &|| checks.fetch_add(1, Ordering::SeqCst) > 12);
    assert_eq!(r, Err(Error::Audit(CustodyAuditError::Cancelled)));
    Ok(())
}
#[test]
fn unavailable_authority_never_falls_back_to_unbound_filesystem_roots() -> TestResult {
    let f = Fixture::new("authority")?;
    assert_eq!(execute_with(&f.request()?, &HostSpoolIo, || Err(Error::Source), &|| false), Err(Error::Source));
    // A publication tree without canonical deployment LAYOUT/history is not enough.
    assert_eq!(execute(&f.request()?, &|| false), Err(Error::Source));
    Ok(())
}
struct Interrupted;
impl Write for Interrupted {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::Interrupted.into()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
#[test]
fn bounded_output_delivery_does_not_retry_interruptions_forever() -> TestResult {
    assert!(emit(&mut Interrupted, b"not delivered").is_err());
    let mut output = Vec::new(); emit(&mut output, b"complete\n")?; assert_eq!(output, b"complete\n");
    Ok(())
}
