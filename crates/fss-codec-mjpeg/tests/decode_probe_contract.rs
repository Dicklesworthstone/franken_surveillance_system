#![forbid(unsafe_code)]
//! The same request can cancel extraction and JPEG decoding without a timer task.

use fss_codec_mjpeg::{
    ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits, decode_luma,
};
use fss_core::ContentDigest;
use std::sync::atomic::{AtomicUsize, Ordering};

const JPEG: &[u8] = include_bytes!("fixtures/gray.jpg");

#[test]
fn a_borrowed_owner_probe_interrupts_real_decode_without_partial_pixels() {
    let checks = AtomicUsize::new(0);
    let probe = || checks.fetch_add(1, Ordering::Relaxed) >= 4;
    let mut work = DecodeBudget::with_cancellation_probe(10_000_000, &probe);
    let result = decode_luma(
        JPEG,
        ContentDigest::sha256(JPEG).bytes(),
        ComponentInterpretation::Grayscale,
        DecodeLimits::default(),
        &mut work,
    );
    assert!(matches!(result, Err(DecodeError::Cancelled)));
    assert_eq!(checks.load(Ordering::Relaxed), 5);
    assert!(work.used() > 0);
    assert!(work.remaining() > 0);
    assert_eq!(work.used() + work.remaining(), 10_000_000);
}

#[test]
fn an_uncancelled_probe_preserves_native_pixels_receipt_and_work() -> Result<(), DecodeError> {
    let hash = ContentDigest::sha256(JPEG).bytes();
    let mut old = DecodeBudget::new(10_000_000);
    let original = decode_luma(
        JPEG,
        hash,
        ComponentInterpretation::Grayscale,
        DecodeLimits::default(),
        &mut old,
    )?;
    let probe = || false;
    let mut new = DecodeBudget::with_cancellation_probe(10_000_000, &probe);
    let repeated = decode_luma(
        JPEG,
        hash,
        ComponentInterpretation::Grayscale,
        DecodeLimits::default(),
        &mut new,
    )?;
    assert_eq!(original.pixels(), repeated.pixels());
    assert_eq!(original.receipt(), repeated.receipt());
    assert_eq!(old.used(), new.used());
    assert_eq!(old.remaining(), new.remaining());
    Ok(())
}

#[test]
fn decoding_budget_retains_send_and_sync() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<DecodeBudget<'_>>();
}
