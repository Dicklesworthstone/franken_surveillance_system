#![forbid(unsafe_code)]
//! Bounded H.264 access-unit/SPS/PPS parser (FSS-113).
//!
//! Upstream layers deliberately deliver COMPLETE TRANSPORT NALs while
//! disclaiming access-unit completeness. This module is the explicit AU
//! layer: it groups an ordered NAL stream into access units using the
//! deterministic reference boundary rule set, and extracts the SPS/PPS
//! parameter sets it observes.
//!
//! Boundary rules (in precedence order, evaluated per arriving NAL):
//!  1. An AUD (type 9) starts a new access unit.
//!  2. An SPS (7) or PPS (8) that FOLLOWS VCL data starts a new access
//!     unit (parameter sets belong to the next picture).
//!  3. A VCL NAL (types 1-5) whose slice header's first `first_mb_in_slice`
//!     Exp-Golomb value is 0 starts a new access unit (a picture's first
//!     slice begins at macroblock 0).
//!  4. Nothing else splits: SEI (6), non-VCL tail NALs attach to the
//!     current access unit.
//!
//! Every access unit reports whether it contains an IDR picture and which
//! SPS/PPS ids it saw (parsed as the bounded pps_id/sps_id golombs).
//! Bounded: NAL count and byte budgets, typed refusals.

/// Typed AU-parser refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessUnitError {
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
}

impl std::fmt::Display for AccessUnitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyNals { maximum } => {
                write!(f, "access unit exceeds {maximum} NALs")
            }
            Self::TooManyBytes { maximum } => {
                write!(f, "access unit exceeds {maximum} bytes")
            }
        }
    }
}

impl std::error::Error for AccessUnitError {}

/// Budgets for one access unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessUnitLimits {
    /// Maximum NALs in one access unit.
    pub max_nals: usize,
    /// Maximum total payload bytes in one access unit.
    pub max_bytes: usize,
}

impl Default for AccessUnitLimits {
    fn default() -> Self {
        Self {
            max_nals: 256,
            max_bytes: 16 * 1024 * 1024,
        }
    }
}

/// One assembled access unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessUnit {
    /// The NALs of this access unit, in arrival order.
    pub nals: Vec<Vec<u8>>,
    /// Whether any NAL is an IDR slice (type 5).
    pub contains_idr: bool,
    /// SPS ids observed in this access unit.
    pub sps_ids: Vec<u8>,
    /// PPS ids referenced by slice headers in this access unit.
    pub pps_ids: Vec<u8>,
}

/// NAL type classification used by the boundary rules.
fn nal_type(nal: &[u8]) -> Option<u8> {
    if nal.is_empty() {
        return None;
    }
    Some(nal[0] & 0x1F)
}

/// Removes emulation-prevention bytes (0x000003 -> 0x0000) from a NAL
/// payload prefix. Bounded to the bytes the golomb reader can touch.
fn unescape_prefix(nal: &[u8], max: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(max.min(nal.len()));
    let mut zeros = 0;
    for &b in nal.iter().take(max + 4) {
        if zeros >= 2 && b == 0x03 {
            // Skip the prevention byte; the following byte keeps the count
            // reset so 0x000003xx cannot re-trigger.
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
        if out.len() == max {
            break;
        }
    }
    out
}

/// Minimal Exp-Golomb reader over the first bytes of a slice header.
struct Golomb<'a> {
    bytes: &'a [u8],
    bit: usize,
}

impl<'a> Golomb<'a> {
    fn read_bit(&mut self) -> Option<u32> {
        let index = self.bit / 8;
        if index >= self.bytes.len() {
            return None;
        }
        let offset = 7 - (self.bit % 8);
        self.bit += 1;
        Some(u32::from((self.bytes[index] >> offset) & 1))
    }

    /// Reads one unsigned Exp-Golomb code (ISO 14496-10 section 9.1).
    fn read_ue(&mut self) -> Option<u32> {
        let mut leading_zeros = 0u32;
        while self.read_bit()? == 0 {
            leading_zeros += 1;
            if leading_zeros > 31 {
                return None;
            }
        }
        let mut value = 1u64;
        for _ in 0..leading_zeros {
            value = (value << 1) | u64::from(self.read_bit()?);
        }
        u32::try_from(value - 1).ok()
    }
}

/// first_mb_in_slice of a VCL NAL: the first ue(v) after the 1-byte NAL
/// header (no extension assumed; extension presence would need SPS
/// context and only shifts the first slice of a picture, which still
/// reads 0 only for the picture start).
fn first_mb_in_slice(nal: &[u8]) -> Option<u32> {
    let payload = unescape_prefix(&nal[1..], 8);
    let mut golomb = Golomb {
        bytes: &payload,
        bit: 0,
    };
    golomb.read_ue()
}

/// pps_id of a slice header: first ue(v) then the second ue(v) is the pps
/// id. Returns both for clarity.
fn slice_header_ids(nal: &[u8]) -> Option<(u32, u32)> {
    let payload = unescape_prefix(&nal[1..], 8);
    let mut golomb = Golomb {
        bytes: &payload,
        bit: 0,
    };
    let first_mb = golomb.read_ue()?;
    let pps_id = golomb.read_ue()?;
    Some((first_mb, pps_id))
}

/// SPS id: first ue(v) after the header.
fn sps_id(nal: &[u8]) -> Option<u32> {
    let payload = unescape_prefix(&nal[1..], 8);
    let mut golomb = Golomb {
        bytes: &payload,
        bit: 0,
    };
    golomb.read_ue()
}

/// PPS payload ids: pps_id then sps_id (both ue(v)).
fn pps_ids(nal: &[u8]) -> Option<(u32, u32)> {
    let payload = unescape_prefix(&nal[1..], 8);
    let mut golomb = Golomb {
        bytes: &payload,
        bit: 0,
    };
    let pps = golomb.read_ue()?;
    let sps = golomb.read_ue()?;
    Some((pps, sps))
}

/// Streaming access-unit assembler over complete NALs (arrival order).
#[derive(Debug)]
pub struct AccessUnitAssembler {
    limits: AccessUnitLimits,
    current: AccessUnit,
    saw_vcl: bool,
    emitted: usize,
}

impl AccessUnitAssembler {
    /// Opens an assembler with explicit budgets.
    #[must_use]
    pub fn new(limits: AccessUnitLimits) -> Result<Self, AccessUnitError> {
        Self::validate_limits(&limits)?;
        Ok(Self {
            limits,
            current: AccessUnit {
                nals: Vec::new(),
                contains_idr: false,
                sps_ids: Vec::new(),
                pps_ids: Vec::new(),
            },
            saw_vcl: false,
            emitted: 0,
        })
    }

    fn validate_limits(limits: &AccessUnitLimits) -> Result<(), AccessUnitError> {
        if limits.max_nals == 0 || limits.max_bytes == 0 {
            return Err(AccessUnitError::TooManyNals {
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
    /// Typed budget refusals; the NAL is not consumed on refusal.
    pub fn push(&mut self, nal: &[u8]) -> Result<Option<AccessUnit>, AccessUnitError> {
        let kind = nal_type(nal).ok_or(AccessUnitError::TooManyNals {
            maximum: self.limits.max_nals,
        })?;
        // A single NAL larger than the byte budget can never fit ANY
        // access unit: refuse before any state changes.
        if nal.len() > self.limits.max_bytes {
            return Err(AccessUnitError::TooManyBytes {
                maximum: self.limits.max_bytes,
            });
        }
        let starts_new = match kind {
            9 => true,
            7 | 8 => self.saw_vcl,
            1..=5 => {
                if !self.saw_vcl {
                    false
                } else {
                    // A VCL NAL begins a picture iff its first slice
                    // starts at macroblock 0.
                    first_mb_in_slice(nal) == Some(0)
                }
            }
            _ => false,
        };
        // AU-level budgets are checked BEFORE the split decision: after a
        // split the receiving AU is empty (the prechecked single NAL
        // always fits), so a refusal here can only fire pre-split and
        // leaves the assembler untouched — a completed AU is never
        // discarded by a budget refusal.
        if !starts_new {
            if self.current.nals.len() >= self.limits.max_nals {
                return Err(AccessUnitError::TooManyNals {
                    maximum: self.limits.max_nals,
                });
            }
            if self.current_byte_total() + nal.len() > self.limits.max_bytes {
                return Err(AccessUnitError::TooManyBytes {
                    maximum: self.limits.max_bytes,
                });
            }
        }
        let completed = if starts_new && !self.current.nals.is_empty() {
            let done = std::mem::replace(
                &mut self.current,
                AccessUnit {
                    nals: Vec::new(),
                    contains_idr: false,
                    sps_ids: Vec::new(),
                    pps_ids: Vec::new(),
                },
            );
            self.saw_vcl = false;
            self.emitted += 1;
            Some(done)
        } else {
            None
        };
        if (1..=5).contains(&kind) {
            self.saw_vcl = true;
            if kind == 5 {
                self.current.contains_idr = true;
            }
            if let Some((_, pps)) = slice_header_ids(nal)
                && u8::try_from(pps).is_ok()
                && !self.current.pps_ids.contains(&(pps as u8))
            {
                self.current.pps_ids.push(pps as u8);
            }
        }
        match kind {
            7 => {
                if let Some(id) = sps_id(nal)
                    && u8::try_from(id).is_ok()
                    && !self.current.sps_ids.contains(&(id as u8))
                {
                    self.current.sps_ids.push(id as u8);
                }
            }
            8 => {
                if let Some((pps, _sps)) = pps_ids(nal)
                    && u8::try_from(pps).is_ok()
                    && !self.current.pps_ids.contains(&(pps as u8))
                {
                    self.current.pps_ids.push(pps as u8);
                }
            }
            _ => {}
        }
        self.current.nals.push(nal.to_vec());
        Ok(completed)
    }

    /// Flushes the trailing access unit (caller-driven stream end).
    #[must_use]
    pub fn flush(&mut self) -> Option<AccessUnit> {
        if self.current.nals.is_empty() {
            return None;
        }
        let done = std::mem::replace(
            &mut self.current,
            AccessUnit {
                nals: Vec::new(),
                contains_idr: false,
                sps_ids: Vec::new(),
                pps_ids: Vec::new(),
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
