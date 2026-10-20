#![forbid(unsafe_code)]
//! Bounded H.265/HEVC access-unit/VPS/SPS/PPS parser (FSS-114).
//!
//! The HEVC twin of the H.264 access-unit layer ([`crate::access_unit`]):
//! groups an ordered stream of complete NALs into access units using
//! HEVC's simpler boundary signals —
//!
//!  1. An AUD (nal type 35) starts a new access unit.
//!  2. VPS (32), SPS (33), or PPS (34) following VCL data starts a new
//!     access unit (parameter sets belong to the next picture).
//!  3. A VCL NAL (types 0-31) whose `first_slice_segment_in_pic_flag`
//!     (the MSB of the first byte after the 2-byte NAL header) is set
//!     starts a new access unit — no Exp-Golomb needed; HEVC carries the
//!     picture-start bit literally.
//!  4. SEI (39/40) and other non-VCL NALs attach to the current unit.
//!
//! IDR detection: nal types 19 (IDR_W_RADL) and 20 (IDR_N_LP) mark an
//! instantaneous-decoding-refresh picture; CRA (21) is reported
//! separately as a clean-random-access point.
//!
//! Budget refusals are atomic: a refusal never discards a completed
//! access unit, and a single NAL larger than the byte budget is refused
//! before any state change.

/// Typed AU-parser refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum H265AccessUnitError {
    /// More NALs in one access unit than the configured budget.
    TooManyNals {
        /// The configured maximum.
        maximum: usize,
    },
    /// More total bytes than the configured budget.
    TooManyBytes {
        /// The configured maximum.
        maximum: usize,
    },
    /// A NAL shorter than the mandatory 2-byte HEVC header.
    TruncatedHeader,
}

impl std::fmt::Display for H265AccessUnitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyNals { maximum } => write!(f, "access unit exceeds {maximum} NALs"),
            Self::TooManyBytes { maximum } => write!(f, "access unit exceeds {maximum} bytes"),
            Self::TruncatedHeader => write!(f, "NAL shorter than the 2-byte HEVC header"),
        }
    }
}

impl std::error::Error for H265AccessUnitError {}

/// HEVC NAL type constants used by the boundary rules.
const NAL_VPS: u8 = 32;
const NAL_SPS: u8 = 33;
const NAL_PPS: u8 = 34;
const NAL_AUD: u8 = 35;
const NAL_IDR_W_RADL: u8 = 19;
const NAL_IDR_N_LP: u8 = 20;
const NAL_CRA: u8 = 21;

/// Budgets for one access unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H265AccessUnitLimits {
    /// Maximum NALs in one access unit.
    pub max_nals: usize,
    /// Maximum total payload bytes in one access unit.
    pub max_bytes: usize,
}

impl Default for H265AccessUnitLimits {
    fn default() -> Self {
        Self {
            max_nals: 256,
            max_bytes: 16 * 1024 * 1024,
        }
    }
}

/// One assembled HEVC access unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H265AccessUnit {
    /// The NALs of this access unit, in arrival order.
    pub nals: Vec<Vec<u8>>,
    /// Whether any NAL is an IDR picture (types 19/20).
    pub contains_idr: bool,
    /// Whether any NAL is a CRA picture (type 21).
    pub contains_cra: bool,
    /// Whether a VPS was observed in this unit.
    pub has_vps: bool,
    /// Whether an SPS was observed in this unit.
    pub has_sps: bool,
    /// Whether a PPS was observed in this unit.
    pub has_pps: bool,
}

/// HEVC NAL type from the 2-byte header.
fn nal_type(nal: &[u8]) -> Option<u8> {
    if nal.len() < 2 {
        return None;
    }
    Some((nal[0] >> 1) & 0x3F)
}

fn is_vcl(kind: u8) -> bool {
    kind < NAL_VPS
}

/// first_slice_segment_in_pic_flag: MSB of the byte after the 2-byte
/// header.
fn first_slice_segment(nal: &[u8]) -> Option<bool> {
    nal.get(2).map(|b| b & 0x80 != 0)
}

/// Streaming HEVC access-unit assembler over complete NALs.
#[derive(Debug)]
pub struct H265AccessUnitAssembler {
    limits: H265AccessUnitLimits,
    current: H265AccessUnit,
    saw_vcl: bool,
    emitted: usize,
}

impl H265AccessUnitAssembler {
    /// Opens an assembler with explicit budgets.
    pub fn new(limits: H265AccessUnitLimits) -> Result<Self, H265AccessUnitError> {
        Self::validate_limits(&limits)?;
        Ok(Self {
            limits,
            current: H265AccessUnit {
                nals: Vec::new(),
                contains_idr: false,
                contains_cra: false,
                has_vps: false,
                has_sps: false,
                has_pps: false,
            },
            saw_vcl: false,
            emitted: 0,
        })
    }

    fn validate_limits(limits: &H265AccessUnitLimits) -> Result<(), H265AccessUnitError> {
        if limits.max_nals == 0 || limits.max_bytes == 0 {
            return Err(H265AccessUnitError::TooManyNals {
                maximum: limits.max_nals,
            });
        }
        Ok(())
    }

    /// Total access units emitted so far.
    #[must_use]
    pub fn emitted(&self) -> usize {
        self.emitted
    }

    /// Feeds one complete NAL. Returns the COMPLETED previous access unit
    /// when this NAL starts a new one.
    ///
    /// # Errors
    /// Typed budget/header refusals; a refusal never discards a completed
    /// access unit.
    pub fn push(&mut self, nal: &[u8]) -> Result<Option<H265AccessUnit>, H265AccessUnitError> {
        if nal.len() < 2 {
            return Err(H265AccessUnitError::TruncatedHeader);
        }
        if nal.len() > self.limits.max_bytes {
            return Err(H265AccessUnitError::TooManyBytes {
                maximum: self.limits.max_bytes,
            });
        }
        let kind = nal_type(nal).ok_or(H265AccessUnitError::TruncatedHeader)?;
        let starts_new = match kind {
            NAL_AUD => true,
            NAL_VPS | NAL_SPS | NAL_PPS => self.saw_vcl,
            k if is_vcl(k) => {
                if !self.saw_vcl {
                    false
                } else {
                    first_slice_segment(nal).unwrap_or(false)
                }
            }
            _ => false,
        };
        // AU-level budgets BEFORE the split (post-split the receiving AU
        // is empty and the prechecked NAL always fits): a refusal leaves
        // the assembler untouched.
        if !starts_new {
            if self.current.nals.len() >= self.limits.max_nals {
                return Err(H265AccessUnitError::TooManyNals {
                    maximum: self.limits.max_nals,
                });
            }
            if self.current_byte_total() + nal.len() > self.limits.max_bytes {
                return Err(H265AccessUnitError::TooManyBytes {
                    maximum: self.limits.max_bytes,
                });
            }
        }
        let completed = if starts_new && !self.current.nals.is_empty() {
            let done = std::mem::replace(
                &mut self.current,
                H265AccessUnit {
                    nals: Vec::new(),
                    contains_idr: false,
                    contains_cra: false,
                    has_vps: false,
                    has_sps: false,
                    has_pps: false,
                },
            );
            self.saw_vcl = false;
            self.emitted += 1;
            Some(done)
        } else {
            None
        };
        if is_vcl(kind) {
            self.saw_vcl = true;
            if kind == NAL_IDR_W_RADL || kind == NAL_IDR_N_LP {
                self.current.contains_idr = true;
            }
            if kind == NAL_CRA {
                self.current.contains_cra = true;
            }
        }
        match kind {
            NAL_VPS => self.current.has_vps = true,
            NAL_SPS => self.current.has_sps = true,
            NAL_PPS => self.current.has_pps = true,
            _ => {}
        }
        self.current.nals.push(nal.to_vec());
        Ok(completed)
    }

    /// Flushes the trailing access unit (caller-driven stream end).
    #[must_use]
    pub fn flush(&mut self) -> Option<H265AccessUnit> {
        if self.current.nals.is_empty() {
            return None;
        }
        let done = std::mem::replace(
            &mut self.current,
            H265AccessUnit {
                nals: Vec::new(),
                contains_idr: false,
                contains_cra: false,
                has_vps: false,
                has_sps: false,
                has_pps: false,
            },
        );
        self.saw_vcl = false;
        self.emitted += 1;
        Some(done)
    }

    fn current_byte_total(&self) -> usize {
        self.current.nals.iter().map(Vec::len).sum::<usize>()
    }
}
