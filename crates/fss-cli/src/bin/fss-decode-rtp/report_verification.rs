#![forbid(unsafe_code)]
//! Read-only destinations for the existing native report producer. Saved JSON is never parsed.

use super::super::pgm_stream::private_output::PrivateOutputPath;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::ReplayCx;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[path = "report_verifier.rs"]
mod report_verifier;
use report_verifier::ReportVerifier;

pub(crate) trait ReportDestination {
    type Sink<'a>: Write
    where
        Self: 'a;
    fn check(&self, cx: &ReplayCx) -> io::Result<()>;
    fn create<'a>(&'a self, cx: &'a ReplayCx) -> io::Result<Self::Sink<'a>>;
    fn sync(&self, sink: &mut Self::Sink<'_>, cx: &ReplayCx) -> io::Result<()>;
}
impl ReportDestination for PrivateOutputPath {
    type Sink<'a> = File;
    fn check(&self, cx: &ReplayCx) -> io::Result<()> {
        PrivateOutputPath::check(self, cx)
    }
    fn create<'a>(&'a self, cx: &'a ReplayCx) -> io::Result<File> {
        PrivateOutputPath::create(self, cx)
    }
    fn sync(&self, sink: &mut File, cx: &ReplayCx) -> io::Result<()> {
        PrivateOutputPath::sync(self, sink, cx)
    }
}

/// Preserve native explicit parameters, while disallowing every export destination.
/// The original parser receives the input path only as its unused output setting;
/// the verification command never calls the export-path preparation wrapper.
pub(crate) fn arguments(
    args: &[OsString],
    native: &str,
) -> Result<(Vec<OsString>, ContentDigest), &'static str> {
    if args.is_empty()
        || args.len() > 257
        || args.len() % 2 != 1
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err("bounded paired verification options required");
    }
    let mut forwarded = vec![OsString::from(native)];
    let mut seen = BTreeSet::new();
    let mut input = None;
    let mut expected = None;
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or("UTF-8 option names required")?;
        if !seen.insert(key) {
            return Err("duplicate verification option");
        }
        if pair[1].is_empty() {
            return Err("option value required");
        }
        match key {
            "--report-in" => input = Some(pair[1].clone()),
            "--report-sha256" => {
                let digest: ContentDigest = pair[1]
                    .to_str()
                    .ok_or("UTF-8 digest required")?
                    .parse()
                    .map_err(|_| "independent report SHA-256 required")?;
                if digest.algorithm() != DigestAlgorithm::Sha256 {
                    return Err("independent report SHA-256 required");
                }
                expected = Some(digest);
            }
            "--report-out" | "--output" | "--receipts-out" | "--receipt-out" | "--manifest-out"
            | "--model-out" => return Err("report verification accepts no output paths"),
            _ => forwarded.extend_from_slice(pair),
        }
    }
    forwarded.push("--report-out".into());
    forwarded.push(input.ok_or("--report-in required")?);
    Ok((forwarded, expected.ok_or("--report-sha256 required")?))
}

fn checkpoint(cx: &ReplayCx) -> io::Result<()> {
    cx.checkpoint("rtp_report:verify")
        .map_err(|_| io::Error::other("report verification cancelled"))
}

#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    length: u64,
    modified: SystemTime,
    #[cfg(unix)]
    unix: (u64, u64, i64, i64, u32),
}
impl FileIdentity {
    fn of(metadata: &Metadata) -> io::Result<Self> {
        if !metadata.file_type().is_file() {
            return Err(io::Error::other(
                "report must be a regular file, not a symlink",
            ));
        }
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            unix: {
                use std::os::unix::fs::MetadataExt;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                    metadata.mode(),
                )
            },
        })
    }
}

pub(crate) struct VerificationPath {
    path: PathBuf,
    identity: FileIdentity,
    expected: ContentDigest,
    maximum: u64,
    verified: Cell<Option<u64>>,
}
impl VerificationPath {
    pub(crate) fn prepare(
        path: &Path,
        expected: ContentDigest,
        maximum: u64,
        cx: &ReplayCx,
    ) -> io::Result<Self> {
        checkpoint(cx)?;
        if expected.algorithm() != DigestAlgorithm::Sha256 || maximum == 0 {
            return Err(io::Error::other(
                "bounded independent report SHA-256 required",
            ));
        }
        let identity = FileIdentity::of(&fs::symlink_metadata(path)?)?;
        if identity.length == 0 || identity.length > maximum {
            return Err(io::Error::other(
                "saved report exceeds verification allowance or is empty",
            ));
        }
        let result = Self {
            path: path.to_path_buf(),
            identity,
            expected,
            maximum,
            verified: Cell::new(None),
        };
        result.check(cx)?;
        Ok(result)
    }
    pub(crate) fn verified_bytes(&self) -> Option<u64> {
        self.verified.get()
    }
}

pub(crate) struct VerificationWriter<'a> {
    verifier: ReportVerifier<File>,
    cx: &'a ReplayCx,
}
impl Write for VerificationWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.verifier.compare(bytes, &mut || checkpoint(self.cx))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        checkpoint(self.cx)
    }
}
impl ReportDestination for VerificationPath {
    type Sink<'a> = VerificationWriter<'a>;
    fn check(&self, cx: &ReplayCx) -> io::Result<()> {
        checkpoint(cx)?;
        if FileIdentity::of(&fs::symlink_metadata(&self.path)?)? != self.identity {
            return Err(io::Error::other(
                "saved report identity changed during verification",
            ));
        }
        Ok(())
    }
    fn create<'a>(&'a self, cx: &'a ReplayCx) -> io::Result<VerificationWriter<'a>> {
        self.check(cx)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // O_NOFOLLOW | O_NONBLOCK: a raced symlink/FIFO cannot redirect or block admission.
            options.custom_flags(0x20000 | 0x800);
        }
        let input = options.open(&self.path)?;
        if FileIdentity::of(&input.metadata()?)? != self.identity {
            return Err(io::Error::other("saved report changed while opening"));
        }
        self.check(cx)?;
        Ok(VerificationWriter {
            verifier: ReportVerifier::new(input, self.expected, self.maximum)?,
            cx,
        })
    }
    fn sync(&self, sink: &mut VerificationWriter<'_>, cx: &ReplayCx) -> io::Result<()> {
        self.check(cx)?;
        sink.verifier.finish(&mut || checkpoint(cx))?;
        self.check(cx)?;
        self.verified.set(Some(self.identity.length));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(extra: &[&str]) -> Vec<OsString> {
        let digest = ContentDigest::sha256(b"report").to_string();
        let mut args: Vec<_> = [
            "verify-detections",
            "--report-in",
            "saved.jsonl",
            "--report-sha256",
            &digest,
            "--custody",
            "current",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        args.extend(extra.iter().map(OsString::from));
        args
    }
    #[test]
    fn verification_preserves_explicit_native_arguments() -> Result<(), &'static str> {
        let (native, expected) = arguments(&args(&["--max-frames", "7"]), "detect")?;
        assert_eq!(native[0], "detect");
        assert_eq!(expected, ContentDigest::sha256(b"report"));
        assert_eq!(
            &native[native.len() - 2..],
            &[
                OsString::from("--report-out"),
                OsString::from("saved.jsonl")
            ]
        );
        assert!(
            native
                .windows(2)
                .any(|w| w == [OsString::from("--max-frames"), OsString::from("7")])
        );
        Ok(())
    }
    #[test]
    fn verification_rejects_exports_duplicates_and_missing_digest() {
        for key in [
            "--report-out",
            "--output",
            "--receipts-out",
            "--receipt-out",
            "--manifest-out",
            "--model-out",
            "--report-in",
            "--report-sha256",
        ] {
            assert!(arguments(&args(&[key, "anything"]), "detect").is_err());
        }
        let mut no_digest = args(&[]);
        no_digest.drain(3..5);
        assert!(arguments(&no_digest, "detect").is_err());
        assert!(arguments(&args(&["--max-frames"]), "detect").is_err());
    }
}

#[cfg(test)]
mod file_tests {
    use super::*;
    use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec};
    use std::sync::atomic::{AtomicU64, Ordering};
    type Result = std::result::Result<(), Box<dyn std::error::Error>>;
    struct Fixture {
        directory: PathBuf,
        cx: ReplayCx,
    }
    impl Fixture {
        fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "fss-report-verify-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory)?;
            let authority = ContextAuthority::new_root(RootAuthoritySpec {
                trace_id: "trace:verify-report-tests".into(),
                operation_id: OperationId::parse("operation:verify-report-tests")?,
                principal: "operator:verify-report-tests".into(),
                capabilities: vec!["ADP-REPLAY-001".into(), "ADP-FILE-001".into()],
                deadline: None,
                priority: 10,
                budgets: BudgetVector::default(),
                privacy_scope: "privacy:internal".into(),
                retention_scope: "retention:ephemeral".into(),
                anchor_universe: ContentDigest::sha256(b"verify-tests"),
                generation: 1,
            })?;
            let cx = ReplayCx::from_context_authority(&authority, &directory)?;
            Ok(Self { directory, cx })
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.cx.drain_and_finalize();
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    #[test]
    fn verified_destination_only_reads_original_file() -> Result {
        let f = Fixture::new()?;
        let path = f.directory.join("report");
        let bytes = b"header\nframe\ncomplete\n";
        fs::write(&path, bytes)?;
        let destination =
            VerificationPath::prepare(&path, ContentDigest::sha256(bytes), 100, &f.cx)?;
        let mut sink = destination.create(&f.cx)?;
        sink.write_all(bytes)?;
        assert_eq!(destination.verified_bytes(), None);
        destination.sync(&mut sink, &f.cx)?;
        assert_eq!(destination.verified_bytes(), Some(bytes.len() as u64));
        assert_eq!(fs::read(&path)?, bytes);
        assert!(destination.sync(&mut sink, &f.cx).is_err());
        Ok(())
    }
    #[test]
    fn replacement_during_reproduction_cannot_verify_cached_descriptor() -> Result {
        let f = Fixture::new()?;
        let path = f.directory.join("report");
        fs::write(&path, b"native")?;
        let destination =
            VerificationPath::prepare(&path, ContentDigest::sha256(b"native"), 100, &f.cx)?;
        let mut sink = destination.create(&f.cx)?;
        sink.write_all(b"native")?;
        let replacement = f.directory.join("replacement");
        fs::write(&replacement, b"native")?;
        fs::rename(&replacement, &path)?;
        assert!(destination.sync(&mut sink, &f.cx).is_err());
        assert_eq!(destination.verified_bytes(), None);
        Ok(())
    }
    #[test]
    fn empty_large_directory_and_symlink_inputs_refuse_without_output() -> Result {
        let f = Fixture::new()?;
        let path = f.directory.join("report");
        let expected = ContentDigest::sha256(b"native");
        fs::write(&path, b"")?;
        assert!(VerificationPath::prepare(&path, expected, 100, &f.cx).is_err());
        fs::write(&path, b"native")?;
        assert!(VerificationPath::prepare(&path, expected, 5, &f.cx).is_err());
        assert!(VerificationPath::prepare(&f.directory, expected, 100, &f.cx).is_err());
        #[cfg(unix)]
        {
            let link = f.directory.join("link");
            std::os::unix::fs::symlink(&path, &link)?;
            assert!(VerificationPath::prepare(&link, expected, 100, &f.cx).is_err());
        }
        assert_eq!(fs::read(&path)?, b"native");
        Ok(())
    }
    #[test]
    fn cancellation_blocks_final_verification() -> Result {
        let f = Fixture::new()?;
        let path = f.directory.join("report");
        fs::write(&path, b"native")?;
        let destination =
            VerificationPath::prepare(&path, ContentDigest::sha256(b"native"), 100, &f.cx)?;
        let mut sink = destination.create(&f.cx)?;
        sink.write_all(b"native")?;
        f.cx.set_cancel_at_checkpoint("rtp_report:verify");
        assert!(destination.sync(&mut sink, &f.cx).is_err());
        assert_eq!(destination.verified_bytes(), None);
        Ok(())
    }
    #[test]
    fn same_generic_owner_keeps_existing_export_behavior() -> Result {
        fn emit(destination: &impl ReportDestination, cx: &ReplayCx) -> io::Result<()> {
            let mut writer = destination.create(cx)?;
            writer.write_all(b"native")?;
            destination.sync(&mut writer, cx)
        }
        let f = Fixture::new()?;
        let root = f.directory.join("deployment");
        fs::create_dir(&root)?;
        let path = f.directory.join("new-report");
        let export = PrivateOutputPath::prepare(&path, &root, &f.cx)?;
        emit(&export, &f.cx)?;
        let verify =
            VerificationPath::prepare(&path, ContentDigest::sha256(b"native"), 100, &f.cx)?;
        emit(&verify, &f.cx)?;
        assert_eq!(fs::read(path)?, b"native");
        Ok(())
    }
}
