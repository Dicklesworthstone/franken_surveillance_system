#![forbid(unsafe_code)]
use super::*;

fn args() -> Vec<OsString> {
    let d = ContentDigest::sha256(b"recoverable-capture-approval").to_text();
    ["--root", "/tmp/fss-recoverable-capture-test", "--peer", "127.0.0.1:8000",
        "--host", "camera.invalid", "--target", "/video", "--source", &d,
        "--generations", "2,7", "--receive-clock", &d, "--retention-evidence", &d,
        "--owner-authorized", "yes", "--plaintext", "yes", "--retain-originals", "yes"]
        .into_iter().map(Into::into).collect()
}

#[test]
fn recovery_is_opt_in_and_explicit_no_preserves_existing_bytes() -> Result<(), &'static str> {
    let original = Options::parse(&args())?;
    assert!(!original.recoverable);
    let mut no = args(); no.extend(["--recoverable".into(), "no".into()]);
    let no = Options::parse(&no)?;
    assert!(!no.recoverable);
    assert_eq!(original.approval(), no.approval());
    assert_eq!(original.preview(), no.preview());
    assert!(!original.preview().contains("wire_recovery"));
    Ok(())
}

#[test]
fn recovery_changes_the_approval_for_raw_and_masked_capture() -> Result<(), &'static str> {
    for decoded in [false, true] {
        let mut original = args();
        if decoded {
            original.extend(["--decode", "grayscale", "--privacy-root", "/tmp/fss-recoverable-privacy",
                "--site", "site:privacy", "--sensor", "sensor:front"].map(Into::into));
        }
        let original = Options::parse(&original)?;
        let mut opted = args();
        if decoded {
            opted.extend(["--decode", "grayscale", "--privacy-root", "/tmp/fss-recoverable-privacy",
                "--site", "site:privacy", "--sensor", "sensor:front"].map(Into::into));
        }
        opted.extend(["--recoverable".into(), "yes".into()]);
        let approval = Options::parse(&opted)?.approval();
        assert_ne!(approval, original.approval());
        opted.extend(["--approve".into(), approval.to_text().into()]);
        let opted = Options::parse(&opted)?;
        assert_eq!(opted.approve, Some(opted.approval()));
        assert!(opted.preview().contains("save_key_before_publication_no_capture_resume"));
        // Recovery is metadata preservation, not a new generation or relaxed network policy.
        assert_eq!(opted.generations, original.generations);
        assert_eq!(opted.policy, original.policy);
        assert_eq!(opted.archive, original.archive);
    }
    Ok(())
}

#[test]
fn malformed_or_repeated_recovery_flags_are_refused() {
    for value in ["true", "false", "1", "YES", ""] {
        let mut a = args(); a.extend(["--recoverable".into(), value.into()]);
        assert!(Options::parse(&a).is_err());
    }
    let mut a = args(); a.extend(["--recoverable", "yes", "--recoverable", "no"].map(Into::into));
    assert!(Options::parse(&a).is_err());
}
