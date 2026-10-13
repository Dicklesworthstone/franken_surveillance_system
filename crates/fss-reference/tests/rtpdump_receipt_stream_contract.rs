#![forbid(unsafe_code)]
//! Receipt streams are verified by real cold native reproduction, not a stored-claim parser.
mod rtpdump_support;
use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest;
use fss_reference::ingest::rtpdump::receipt_stream::*;
use fss_reference::ingest::rtpdump::recovery::{
    RecoveredRtpImport, RtpRecoveryPolicy, inspect_rtp_import,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use rtpdump_support::*;
use std::io::{self, Read, Write};

fn setup(
    label: &str,
    bytes: &[u8],
) -> Result<(ReferenceDeployment, RecoveredRtpImport, ReplayCx), Error> {
    let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    let dir = (0..1000)
        .find_map(|i| {
            let p = base.join(format!(
                "rtp-receipt-stream-{label}-{}-{i}",
                std::process::id()
            ));
            std::fs::create_dir(&p).ok().map(|()| p)
        })
        .ok_or("scratch directory")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:receipt-stream", &cx)?;
    let scope = RtpImportScope {
        sensor: SensorId::parse("sensor:receipt-stream")?,
        stream: StreamId::parse("stream:receipt-stream")?,
        receive_time: TimestampNs(1_000_000_000),
    };
    let root = publish_rtp_import(
        prepare_rtp_import(bytes, scope, config_for(7), RtpImportLimits::default(), &cx)?,
        &cx,
        &mut dep,
    )?
    .root();
    drop(dep);
    let dep = ReferenceDeployment::reopen(&dir, "site:receipt-stream", &cx)?;
    let retained = inspect_rtp_import(root, 42, RtpRecoveryPolicy::default(), &cx, &dep)?;
    Ok((dep, retained, cx))
}
fn request(retained: &RecoveredRtpImport, cx: &ReplayCx) -> Result<RtpReceiptStreamRequest, Error> {
    Ok(RtpReceiptStreamRequest::new(RetainedRtpDecodeRequest::new(
        retained
            .h264_parameters(cx)?
            .unique_pair()
            .ok_or("parameters")?,
    )))
}
struct ShortWriter {
    bytes: Vec<u8>,
    largest: usize,
    stop: Option<usize>,
}
impl Write for ShortWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.largest = self.largest.max(b.len());
        if self.stop.is_some_and(|n| self.bytes.len() >= n) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let n = b.len().min(13);
        self.bytes.extend_from_slice(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct ShortReader<'a> {
    bytes: &'a [u8],
    largest: usize,
}
impl Read for ShortReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.largest = self.largest.max(out.len());
        let n = self.bytes.len().min(out.len()).min(7);
        out[..n].copy_from_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        Ok(n)
    }
}

#[test]
fn complete_stream_reproduces_after_cold_open_and_new_ingress_with_short_io() -> TestResult {
    let (dep, retained, cx) = setup("cold", &real_dump(true))?;
    let before = dep.current_anchor().clone();
    let req = request(&retained, &cx)?;
    let mut writer = ShortWriter {
        bytes: Vec::new(),
        largest: 0,
        stop: None,
    };
    let written = write_receipt_stream(&retained, req, &mut writer, &dep, &cx)?;
    assert!(written.stats.complete());
    assert_eq!(written.stats.frames, 4);
    assert_eq!(written.digest, ContentDigest::sha256(&writer.bytes));
    assert_eq!(written.bytes, writer.bytes.len() as u64);
    assert!(written.custody_read_bytes > 0 && written.receipt_bytes < written.bytes);
    assert!(writer.largest <= 4096);
    let reopened = inspect_rtp_import(
        retained.root(),
        9999,
        RtpRecoveryPolicy::default(),
        &cx,
        &dep,
    )?;
    let mut reader = ShortReader {
        bytes: &writer.bytes,
        largest: 0,
    };
    let verified = verify_receipt_stream(&reopened, req, &mut reader, written.digest, &dep, &cx)?;
    assert_eq!(verified, written);
    assert!(reader.bytes.is_empty());
    assert!(reader.largest <= 4096);
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn tamper_truncation_reordering_duplication_and_extra_suffix_fail_even_when_rehashed() -> TestResult
{
    let (dep, retained, cx) = setup("tamper", &real_dump(false))?;
    let req = request(&retained, &cx)?;
    let mut bytes = Vec::new();
    let summary = write_receipt_stream(&retained, req, &mut bytes, &dep, &cx)?;
    let first = 8 + RTP_RECEIPT_STREAM_DOMAIN.len() + 4 + 33;
    let length = u64::from_be_bytes(bytes[first + 9..first + 17].try_into()?) as usize + 17;
    let second = first + length;
    let second_length =
        u64::from_be_bytes(bytes[second + 9..second + 17].try_into()?) as usize + 17;
    let mut swapped = bytes[..first].to_vec();
    swapped.extend_from_slice(&bytes[second..second + second_length]);
    swapped.extend_from_slice(&bytes[first..second]);
    swapped.extend_from_slice(&bytes[second + second_length..]);
    let mut changed = bytes.clone();
    changed[first + 20] ^= 1;
    let mut extra = bytes.clone();
    extra.push(0);
    let mut duplicate = bytes.clone();
    duplicate.splice(second..second, bytes[first..second].iter().copied());
    for bad in [
        Vec::new(),
        bytes[..first].to_vec(),
        bytes[..bytes.len() - 1].to_vec(),
        changed,
        extra,
        swapped,
        duplicate,
    ] {
        let expected = ContentDigest::sha256(&bad);
        assert!(matches!(
            verify_receipt_stream(&retained, req, &mut bad.as_slice(), expected, &dep, &cx),
            Err(RtpReceiptStreamError::Mismatch)
        ));
    }
    assert!(matches!(
        verify_receipt_stream(
            &retained,
            req,
            &mut bytes.as_slice(),
            ContentDigest::sha256(b"wrong"),
            &dep,
            &cx
        ),
        Err(RtpReceiptStreamError::Mismatch)
    ));
    assert_eq!(summary.stats.frames, 4);
    Ok(())
}

#[test]
fn changed_recipe_and_new_privacy_policy_cannot_verify_old_receipts() -> TestResult {
    let (mut dep, retained, cx) = setup("policy", &real_dump(true))?;
    let req = request(&retained, &cx)?;
    let mut bytes = Vec::new();
    let mut dimensions = [0; 2];
    let old = write_receipt_stream_with_frames(&retained, req, &mut bytes, &dep, &cx, |f, _| {
        dimensions = f.dimensions();
        Ok(())
    })?;
    let mut changed = req;
    changed.decode.decode.max_decode_calls -= 1;
    assert!(matches!(
        verify_receipt_stream(
            &retained,
            changed,
            &mut bytes.as_slice(),
            old.digest,
            &dep,
            &cx
        ),
        Err(RtpReceiptStreamError::Mismatch)
    ));
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:receipt-stream")?,
        dimensions,
        &[[0, 0, dimensions[0], dimensions[1]]],
    )?;
    let approval = preview_mask(&dep, &policy)?.approval;
    declare_mask(&mut dep, &policy, approval, &cx)?;
    let fresh = inspect_rtp_import(
        retained.root(),
        800,
        RtpRecoveryPolicy::default(),
        &cx,
        &dep,
    )?;
    assert!(matches!(
        verify_receipt_stream(&fresh, req, &mut bytes.as_slice(), old.digest, &dep, &cx),
        Err(RtpReceiptStreamError::Mismatch)
    ));
    let mut masked = Vec::new();
    let new = write_receipt_stream_with_frames(&fresh, req, &mut masked, &dep, &cx, |f, _| {
        assert!(f.pixels().iter().all(|x| *x == 16));
        assert!(f.cb().iter().chain(f.cr()).all(|x| *x == 128));
        Ok(())
    })?;
    assert_ne!(new.digest, old.digest);
    Ok(())
}

#[test]
fn incomplete_media_cannot_seal_or_verify_a_successful_prefix() -> TestResult {
    let mut bytes = real_dump(false);
    bytes.extend_from_slice(&[0, 20, 0]);
    let (dep, retained, cx) = setup("partial", &bytes)?;
    let req = request(&retained, &cx)?;
    let mut prefix = Vec::new();
    assert!(
        matches!(write_receipt_stream(&retained, req, &mut prefix, &dep, &cx),
        Err(RtpReceiptStreamError::Incomplete(stats)) if !stats.complete())
    );
    assert!(!prefix.is_empty());
    let digest = ContentDigest::sha256(&prefix);
    assert!(
        verify_receipt_stream(&retained, req, &mut prefix.as_slice(), digest, &dep, &cx).is_err()
    );
    Ok(())
}

#[test]
fn record_and_footer_budgets_refuse_without_certifying_shorter_streams() -> TestResult {
    let (dep, retained, cx) = setup("limit", &real_dump(false))?;
    let req = request(&retained, &cx)?;
    let mut bytes = Vec::new();
    let summary = write_receipt_stream(&retained, req, &mut bytes, &dep, &cx)?;
    for limit in [1, summary.bytes - 1] {
        let mut partial = Vec::new();
        assert!(matches!(
            write_receipt_stream(
                &retained,
                RtpReceiptStreamRequest {
                    max_stream_bytes: limit,
                    ..req
                },
                &mut partial,
                &dep,
                &cx
            ),
            Err(RtpReceiptStreamError::Limit)
        ));
        assert!(partial.len() < bytes.len());
        if limit == 1 {
            assert!(partial.is_empty());
        }
    }
    Ok(())
}

#[test]
fn cancellation_in_masked_frame_consumer_prevents_receipt_delivery() -> TestResult {
    let (dep, retained, cx) = setup("cancel", &real_dump(false))?;
    let req = request(&retained, &cx)?;
    let mut bytes = Vec::new();
    assert!(matches!(
        write_receipt_stream_with_frames(&retained, req, &mut bytes, &dep, &cx, |_, cx| {
            cx.request_cancellation();
            Ok(())
        }),
        Err(RtpReceiptStreamError::Cancelled)
    ));
    assert!(bytes.is_empty());
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn physical_write_failure_and_frame_consumer_failure_never_return_a_summary() -> TestResult {
    let (dep, retained, cx) = setup("io", &real_dump(false))?;
    let req = request(&retained, &cx)?;
    let mut writer = ShortWriter {
        bytes: Vec::new(),
        largest: 0,
        stop: Some(100),
    };
    assert!(matches!(
        write_receipt_stream(&retained, req, &mut writer, &dep, &cx),
        Err(RtpReceiptStreamError::Io(io::ErrorKind::BrokenPipe))
    ));
    let mut bytes = Vec::new();
    assert!(
        write_receipt_stream_with_frames(&retained, req, &mut bytes, &dep, &cx, |_, _| Err(
            io::ErrorKind::WriteZero.into()
        ))
        .is_err()
    );
    assert!(bytes.is_empty());
    Ok(())
}

#[test]
fn repeated_read_interruptions_are_bounded_and_cannot_reset_decode_work() -> TestResult {
    struct Interrupted(usize);
    impl Read for Interrupted {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0 += 1;
            Err(io::ErrorKind::Interrupted.into())
        }
    }
    let (dep, retained, cx) = setup("interrupt", &real_dump(false))?;
    let req = request(&retained, &cx)?;
    let mut reader = Interrupted(0);
    assert!(
        verify_receipt_stream(
            &retained,
            req,
            &mut reader,
            ContentDigest::sha256(b"saved"),
            &dep,
            &cx
        )
        .is_err()
    );
    assert!(reader.0 <= 64); // At most eight bounded read attempts per write retry.
    Ok(())
}
