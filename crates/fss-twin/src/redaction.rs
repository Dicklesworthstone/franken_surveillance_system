#![forbid(unsafe_code)]
//! Owner-supplied redaction of a decoded luma plane, applied before any consumer sees it.
//!
//! This crate owns no privacy policy. The owner supplies an implementation (the reference
//! composition supplies its retained per-sensor privacy mask) and the native JPEG pipeline calls
//! it on the decoded plane immediately after decoding: rectification, foreground comparison,
//! screening, learned scanning and every decoded-plane digest see only the redacted plane. A
//! refusal stops the frame; nothing unredacted is returned instead.

/// Typed refusal of a redaction (for example a frame whose dimensions differ from the
/// resolution the owner's policy was declared for). The frame is not processed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedactionRefused;

impl std::fmt::Display for RedactionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("decoded-plane redaction refused")
    }
}
impl std::error::Error for RedactionRefused {}

/// In-place redaction of a tight row-major luma plane.
pub trait LumaRedaction {
    /// Identity of the applied redaction, recorded in the decode receipt.
    fn identity(&self) -> [u8; 32];
    /// Redact `luma` (exactly `width * height` samples) in place, or refuse the frame.
    fn redact(&self, luma: &mut [u8], dimensions: [u32; 2]) -> Result<(), RedactionRefused>;
}
