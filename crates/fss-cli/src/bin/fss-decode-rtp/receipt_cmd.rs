#![forbid(unsafe_code)]
//! Operator receipt streams over the existing owner-bound, privacy-projected native decoder.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::ingest::rtpdump::receipt_stream::{
    RtpReceiptStreamError, RtpReceiptStreamRequest, RtpReceiptStreamSummary, verify_receipt_stream,
    write_receipt_stream_with_frames,
};
use fss_reference::ingest::rtpdump::recovery::checked_decode::RtpCustodyDecodeLimits;
use fss_reference::ingest::rtpdump::recovery::checked_decode::receipt::RtpFrameReceiptLimits;
use fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest;
use fss_reference::ingest::rtpdump::recovery::inspect_rtp_import;
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::pgm_stream::private_output::PrivateOutputPath;
use super::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION, ExitIdentity, Options,
    ParseResult, Result, failure, pgm_stream,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Export,
    Verify,
}
struct ReceiptOptions {
    base: Options,
    mode: Mode,
    path: PathBuf,
    expected: Option<ContentDigest>,
    maximum_receipt: usize,
    maximum_stream: u64,
}

/// Returns None only for an existing command, leaving its parser and output unchanged.
pub(super) fn dispatch(args: &[OsString]) -> Option<ExitCode> {
    let mode = match args.first().and_then(|a| a.to_str()) {
        Some("receipts") => Mode::Export,
        Some("verify-receipts") => Mode::Verify,
        _ => return None,
    };
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        return Some(
            match io::stdout().lock().write_all(super::HELP.as_bytes()) {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
            },
        );
    }
    Some(match parse(args, mode) {
        Err((identity, reason)) => {
            eprintln!("{identity}: {reason}");
            ExitCode::from(2)
        }
        Ok(options) => {
            let ReceiptOptions {
                base,
                mode,
                path,
                expected,
                maximum_receipt,
                maximum_stream,
            } = options;
            let mut out = io::stdout().lock();
            let result = super::run_with(base, &mut out, |base, root, cx, out| {
                execute(
                    base,
                    mode,
                    &path,
                    expected,
                    maximum_receipt,
                    maximum_stream,
                    root,
                    cx,
                    out,
                )
            });
            match result {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(error) => {
                    let marker = if mode == Mode::Export {
                        "receipts_complete"
                    } else {
                        "receipts_verified"
                    };
                    let _ = writeln!(out, "{marker}=false\nexport_complete=false");
                    eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                    ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
                }
            }
        }
    })
}

fn parse(args: &[OsString], mode: Mode) -> ParseResult<ReceiptOptions> {
    let mut native = vec![OsString::from("decode")];
    let mut values = BTreeMap::new();
    let mut at = 1;
    while at < args.len() {
        let key = args[at]
            .to_str()
            .ok_or((ERR_CLI_INVALID_UNICODE, "option name must be UTF-8"))?;
        let value = args
            .get(at + 1)
            .ok_or((ERR_CLI_MISSING_VALUE, "option needs a value"))?;
        if [
            "--receipts-out",
            "--receipts-in",
            "--receipts-sha256",
            "--max-receipt-bytes",
            "--max-receipts-bytes",
        ]
        .contains(&key)
        {
            if (mode == Mode::Export && matches!(key, "--receipts-in" | "--receipts-sha256"))
                || (mode == Mode::Verify && key == "--receipts-out")
            {
                return Err((
                    ERR_CLI_UNKNOWN_OPTION,
                    "receipt option is not supported by this command",
                ));
            }
            if values.insert(key.to_owned(), value.clone()).is_some() {
                return Err((ERR_CLI_DUPLICATE_OPTION, "duplicate receipt option"));
            }
        } else {
            native.extend([args[at].clone(), value.clone()]);
        }
        at += 2;
    }
    let base = super::parse(&native)?.ok_or((ERR_CLI_MISSING_VALUE, "decode options required"))?;
    if base.custody_read_bytes.is_none() {
        return Err((
            ERR_CLI_MALFORMED_VALUE,
            "receipt commands require --custody current",
        ));
    }
    if mode == Mode::Verify && base.output.is_some() {
        return Err((
            ERR_CLI_UNKNOWN_OPTION,
            "verification does not accept pixel output",
        ));
    }
    let path = PathBuf::from(super::required(
        &values,
        if mode == Mode::Export {
            "--receipts-out"
        } else {
            "--receipts-in"
        },
    )?);
    let expected = if mode == Mode::Verify {
        let digest = super::digest(&values, "--receipts-sha256")?;
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err((
                ERR_CLI_MALFORMED_VALUE,
                "verification requires an independent SHA-256",
            ));
        }
        Some(digest)
    } else {
        None
    };
    let maximum_receipt = super::number(&values, "--max-receipt-bytes", 1024 * 1024_usize)?;
    let maximum_stream = super::number(&values, "--max-receipts-bytes", 32 * 1024 * 1024_u64)?;
    if !(1..=8 * 1024 * 1024).contains(&maximum_receipt)
        || !(1..=256 * 1024 * 1024).contains(&maximum_stream)
    {
        return Err((
            ERR_CLI_MALFORMED_VALUE,
            "receipt bounds exceed the native command profile",
        ));
    }
    Ok(ReceiptOptions {
        base,
        mode,
        path,
        expected,
        maximum_receipt,
        maximum_stream,
    })
}

fn execute(
    base: &Options,
    mode: Mode,
    path: &Path,
    expected: Option<ContentDigest>,
    maximum_receipt: usize,
    maximum_stream: u64,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> Result<()> {
    let deployment = ReferenceDeployment::reopen(root, &base.site, cx)?;
    let retained = inspect_rtp_import(base.source_root, 1, base.policy, cx, &deployment)?;
    let parameters = base
        .parameters
        .or(retained.h264_parameters(cx)?.unique_pair())
        .ok_or_else(|| {
            failure("select an exact in-source SPS/PPS pair; no unambiguous pair exists")
        })?;
    let request = RtpReceiptStreamRequest {
        decode: RetainedRtpDecodeRequest {
            parameters,
            ..base.decode
        },
        custody: RtpCustodyDecodeLimits {
            max_source_bytes: base.policy.max_source_bytes,
            max_records: base.policy.max_records,
            max_object_bytes: base.policy.max_object_bytes,
            max_read_bytes: base
                .custody_read_bytes
                .ok_or_else(|| failure("current custody required"))?,
            max_steps: base.steps,
            ..RtpCustodyDecodeLimits::default()
        },
        receipts: RtpFrameReceiptLimits {
            max_receipt_bytes: maximum_receipt,
            max_total_bytes: maximum_stream,
        },
        max_stream_bytes: maximum_stream,
    };
    writeln!(
        out,
        "operation={}\nsource_root={}\ncustody_mode=current\ncapture_time_class=unknown\nabsence_certifiable=false\ndecode_published=false",
        if mode == Mode::Export {
            "rtp_receipts_export"
        } else {
            "rtp_receipts_verification"
        },
        retained.root()
    )?;
    let mut pgm = None;
    let mut receipt_output = None;
    let result = match mode {
        Mode::Export => {
            let output = PrivateOutputPath::prepare(path, root, cx)?;
            if let Some(pixels) = &base.output {
                let pixel_path = PrivateOutputPath::prepare(pixels, root, cx)?;
                if pixel_path.destination() == output.destination() {
                    return Err(failure(
                        "receipt and pixel outputs must be different new files",
                    ));
                }
                pgm = Some(pgm_stream::PgmExport::prepare(
                    pixels,
                    root,
                    base.output_bytes,
                    request.decode.decode.max_groups,
                    cx,
                )?);
            }
            let mut writer = ReceiptWriter {
                path: output,
                file: None,
                cx,
            };
            let result = write_receipt_stream_with_frames(
                &retained,
                request,
                &mut writer,
                &deployment,
                cx,
                |frame, cx| {
                    if let Some(pgm) = &mut pgm {
                        pgm.frame(frame.dimensions(), frame.pixels(), cx)?;
                    }
                    Ok(())
                },
            );
            receipt_output = Some(writer);
            result
        }
        Mode::Verify => {
            let mut saved = open_saved(path, maximum_stream, cx)?;
            verify_receipt_stream(
                &retained,
                request,
                &mut saved,
                expected.ok_or_else(|| failure("expected digest required"))?,
                &deployment,
                cx,
            )
        }
    };
    let summary = match result {
        Ok(summary) => summary,
        Err(error) => {
            if let RtpReceiptStreamError::Incomplete(stats) = &error {
                super::statistics(*stats, out)?;
            }
            return Err(error.into());
        }
    };
    // Do not print either success marker until all requested outputs are synchronized.
    let pgm_receipt = pgm.map(|writer| writer.finish(cx)).transpose()?;
    if let Some(writer) = receipt_output {
        writer.finish()?;
    }
    report(&summary, out)?;
    if let Some(receipt) = pgm_receipt {
        writeln!(
            out,
            "export_complete=true\nexport_bytes={}\nexport_frames={}\nexport_sha256={}",
            receipt.bytes, receipt.frames, receipt.digest
        )?;
    }
    writeln!(
        out,
        "{}=true",
        if mode == Mode::Export {
            "receipts_complete"
        } else {
            "receipts_verified"
        }
    )?;
    Ok(())
}

fn report(summary: &RtpReceiptStreamSummary, out: &mut impl Write) -> io::Result<()> {
    super::statistics(summary.stats, out)?;
    writeln!(
        out,
        "receipts_sha256={}\nreceipts_bytes={}\nreceipt_payload_bytes={}\nreceipt_recipe={}\ncustody_read_bytes={}",
        summary.digest,
        summary.bytes,
        summary.receipt_bytes,
        summary.recipe,
        summary.custody_read_bytes
    )
}
struct ReceiptWriter<'a> {
    path: PrivateOutputPath,
    file: Option<File>,
    cx: &'a ReplayCx,
}
impl Write for ReceiptWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.path.check(self.cx)?;
        if self.file.is_none() {
            self.file = Some(self.path.create(self.cx)?);
        }
        let n = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("receipt writer absent"))?
            .write(bytes)?;
        self.path.check(self.cx)?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.path.check(self.cx)?;
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("receipt writer absent"))?
            .flush()
    }
}
impl ReceiptWriter<'_> {
    fn finish(self) -> io::Result<()> {
        let file = self
            .file
            .ok_or_else(|| io::Error::other("no complete receipt output"))?;
        self.path.sync(&file, self.cx)
    }
}

// The same per-architecture Linux UAPI values used by fss-export-package/file.rs.
// Do not assume arm64 and x86_64 O_NOFOLLOW values agree.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const OPEN_INPUT_FLAGS: i32 = 0o4_000 | 0o400_000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const OPEN_INPUT_FLAGS: i32 = 0o4_000 | 0o100_000;

fn open_saved(path: &Path, maximum: u64, cx: &ReplayCx) -> io::Result<File> {
    cx.checkpoint("rtpdump:receipt_file:open")
        .map_err(|_| io::Error::other("receipt input cancelled"))?;
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.len() == 0 || before.len() > maximum {
        return Err(io::Error::other("bounded regular receipt file required"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(OPEN_INPUT_FLAGS);
    }
    // As with existing native file commands, other targets require an owner-protected
    // input directory. Metadata checks do not promise hostile-directory race immunity.
    let file = options.open(path)?;
    let after = file.metadata()?;
    if !after.is_file() || after.len() != before.len() || after.len() > maximum {
        return Err(io::Error::other("receipt input changed during admission"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(io::Error::other("receipt input identity changed"));
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(mode: &str, extra: &[&str]) -> Vec<OsString> {
        let mut a: Vec<OsString> = [
            mode,
            "--root",
            "unused",
            "--site",
            "site:test",
            "--source-root",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        a.push(ContentDigest::sha256(b"source").to_string().into());
        a.extend(extra.iter().map(OsString::from));
        a
    }
    #[test]
    fn export_requires_explicit_custody_and_output() {
        assert!(
            parse(
                &args("receipts", &["--receipts-out", "saved"]),
                Mode::Export
            )
            .is_err()
        );
        assert!(parse(&args("receipts", &["--custody", "current"]), Mode::Export).is_err());
        assert!(
            parse(
                &args(
                    "receipts",
                    &["--custody", "current", "--receipts-out", "saved"]
                ),
                Mode::Export
            )
            .is_ok()
        );
    }
    #[test]
    fn verification_never_accepts_outputs_or_a_missing_independent_digest() {
        assert!(
            parse(
                &args(
                    "verify-receipts",
                    &["--custody", "current", "--receipts-in", "saved"]
                ),
                Mode::Verify
            )
            .is_err()
        );
        let digest = ContentDigest::sha256(b"saved").to_string();
        let mut a = args(
            "verify-receipts",
            &[
                "--custody",
                "current",
                "--receipts-in",
                "saved",
                "--receipts-sha256",
                &digest,
            ],
        );
        assert!(parse(&a, Mode::Verify).is_ok());
        a.extend(["--output".into(), "forbidden.pgm".into()]);
        assert!(parse(&a, Mode::Verify).is_err());
    }
    #[test]
    fn receipt_bounds_duplicates_and_unknown_options_refuse() {
        for extra in [
            vec!["--max-receipt-bytes", "0"],
            vec!["--max-receipt-bytes", "8388609"],
            vec!["--max-receipts-bytes", "268435457"],
            vec!["--receipts-out", "duplicate"],
            vec!["--receipts-in", "not-for-export"],
            vec!["--unknown", "1"],
        ] {
            let mut a = args(
                "receipts",
                &["--custody", "current", "--receipts-out", "saved"],
            );
            a.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&a, Mode::Export).is_err());
        }
    }
}
