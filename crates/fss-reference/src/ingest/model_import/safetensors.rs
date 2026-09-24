#![forbid(unsafe_code)]
//! Bounded data-only reader for the published Safetensors byte format.
//! No general JSON value tree, recursion, tensor code, or implicit dtype conversion.

use super::{ImportError, ImportLimits, WeightFloatPolicy};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const MAX_NAME: usize = 256;
const MAX_RANK: usize = 16;
const MAX_METADATA: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FloatType {
    F32,
    F16,
    Bf16,
}
impl FloatType {
    fn width(self) -> usize {
        if self == Self::F32 { 4 } else { 2 }
    }
}

#[derive(Debug)]
pub(super) struct Entry {
    pub shape: Vec<usize>,
    pub dtype: FloatType,
    pub start: usize,
    pub end: usize,
}

pub(super) struct Weights<'a> {
    pub entries: BTreeMap<String, Entry>,
    pub data: &'a [u8],
}

impl<'a> Weights<'a> {
    pub fn parse(bytes: &'a [u8], limits: &ImportLimits) -> Result<Self, ImportError> {
        let prefix: [u8; 8] = bytes
            .get(..8)
            .ok_or(ImportError::MalformedWeights)?
            .try_into()
            .map_err(|_| ImportError::MalformedWeights)?;
        let len = usize::try_from(u64::from_le_bytes(prefix)).map_err(|_| ImportError::Limit)?;
        if len == 0 || len > limits.maximum_header_bytes {
            return Err(ImportError::Limit);
        }
        let end = 8_usize.checked_add(len).ok_or(ImportError::Limit)?;
        let header = bytes.get(8..end).ok_or(ImportError::MalformedWeights)?;
        if header.first() != Some(&b'{') || std::str::from_utf8(header).is_err() {
            return Err(ImportError::MalformedWeights);
        }
        let mut p = Parser {
            bytes: header,
            at: 0,
        };
        p.expect(b'{')?;
        let mut entries = BTreeMap::new();
        let mut keys = BTreeSet::new();
        if !p.take(b'}') {
            loop {
                let key = p.string(MAX_NAME)?;
                if !keys.insert(key.clone()) {
                    return Err(ImportError::DuplicateKey);
                }
                p.expect(b':')?;
                if key == "__metadata__" {
                    p.metadata()?;
                } else {
                    if key.is_empty() || key.chars().any(char::is_control) {
                        return Err(ImportError::MalformedWeights);
                    }
                    if entries.len() >= limits.maximum_tensors {
                        return Err(ImportError::Limit);
                    }
                    entries.insert(key, p.entry()?);
                }
                if p.take(b'}') {
                    break;
                }
                p.expect(b',')?;
            }
        }
        // Safetensors permits space padding, not another document or hidden suffix.
        if p.bytes[p.at..].iter().any(|b| *b != b' ') {
            return Err(ImportError::MalformedWeights);
        }
        let data = bytes.get(end..).ok_or(ImportError::MalformedWeights)?;
        let mut spans: Vec<_> = entries.values().collect();
        spans.sort_by_key(|e| (e.start, e.end));
        let mut next = 0;
        for entry in spans {
            let elements = element_count(&entry.shape)?;
            let size = elements
                .checked_mul(entry.dtype.width())
                .ok_or(ImportError::Limit)?;
            if entry.start != next
                || entry.end < entry.start
                || entry.end > data.len()
                || entry.end - entry.start != size
            {
                return Err(ImportError::MalformedWeights);
            }
            next = entry.end;
        }
        if next != data.len() {
            return Err(ImportError::MalformedWeights);
        }
        Ok(Self { entries, data })
    }
}

pub(super) fn element_count(shape: &[usize]) -> Result<usize, ImportError> {
    if shape.contains(&0) {
        return Ok(0);
    }
    shape
        .iter()
        .try_fold(1_usize, |n, d| n.checked_mul(*d).ok_or(ImportError::Limit))
}

pub(super) fn value(
    dtype: FloatType,
    bytes: &[u8],
    policy: WeightFloatPolicy,
) -> Result<f32, ImportError> {
    let bits = match dtype {
        FloatType::F32 => u32::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| ImportError::MalformedWeights)?,
        ),
        FloatType::F16 | FloatType::Bf16 => {
            if policy != WeightFloatPolicy::ExpandFloat16 {
                return Err(ImportError::UnsupportedDType);
            }
            let half = u16::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| ImportError::MalformedWeights)?,
            );
            if dtype == FloatType::Bf16 {
                u32::from(half) << 16
            } else {
                expand_f16(half)
            }
        }
    };
    let value = f32::from_bits(bits);
    if !value.is_finite() {
        return Err(ImportError::NonFinite);
    }
    Ok(value)
}

// Every finite binary16 value is exactly representable in binary32. Preserve signed zeros
// and subnormals with integer bit construction; there is no rounding or host-math dependency.
fn expand_f16(bits: u16) -> u32 {
    let sign = u32::from(bits & 0x8000) << 16;
    let exponent = u32::from((bits >> 10) & 31);
    let mut fraction = u32::from(bits & 1023);
    match exponent {
        0 if fraction == 0 => sign,
        0 => {
            let mut e = 113_u32;
            while fraction & 1024 == 0 {
                fraction <<= 1;
                e -= 1;
            }
            sign | (e << 23) | ((fraction & 1023) << 13)
        }
        31 => sign | 0x7f80_0000 | (fraction << 13),
        _ => sign | ((exponent + 112) << 23) | (fraction << 13),
    }
}

impl Entry {
    pub fn width(&self) -> usize {
        self.dtype.width()
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Parser<'_> {
    fn ws(&mut self) {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.at += 1;
        }
    }
    fn take(&mut self, b: u8) -> bool {
        self.ws();
        if self.bytes.get(self.at) == Some(&b) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, b: u8) -> Result<(), ImportError> {
        if self.take(b) {
            Ok(())
        } else {
            Err(ImportError::MalformedWeights)
        }
    }
    fn byte(&mut self) -> Result<u8, ImportError> {
        let b = *self
            .bytes
            .get(self.at)
            .ok_or(ImportError::MalformedWeights)?;
        self.at += 1;
        Ok(b)
    }
    fn hex(&mut self) -> Result<u32, ImportError> {
        let mut out = 0;
        for _ in 0..4 {
            let b = self.byte()?;
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(ImportError::MalformedWeights),
            };
            out = out * 16 + u32::from(digit);
        }
        Ok(out)
    }
    fn string(&mut self, limit: usize) -> Result<String, ImportError> {
        self.expect(b'"')?;
        let mut result = String::new();
        loop {
            let b = self.byte()?;
            let ch = match b {
                b'"' => break,
                b'\\' => match self.byte()? {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{8}',
                    b'f' => '\u{c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => {
                        let first = self.hex()?;
                        let scalar = if (0xd800..=0xdbff).contains(&first) {
                            if self.byte()? != b'\\' || self.byte()? != b'u' {
                                return Err(ImportError::MalformedWeights);
                            }
                            let second = self.hex()?;
                            if !(0xdc00..=0xdfff).contains(&second) {
                                return Err(ImportError::MalformedWeights);
                            }
                            0x10000 + ((first - 0xd800) << 10) + second - 0xdc00
                        } else {
                            first
                        };
                        char::from_u32(scalar).ok_or(ImportError::MalformedWeights)?
                    }
                    _ => return Err(ImportError::MalformedWeights),
                },
                0..=31 => return Err(ImportError::MalformedWeights),
                32..=127 => char::from(b),
                _ => {
                    let width = match b {
                        0xc2..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf4 => 4,
                        _ => return Err(ImportError::MalformedWeights),
                    };
                    let raw = self
                        .bytes
                        .get(self.at - 1..self.at - 1 + width)
                        .ok_or(ImportError::MalformedWeights)?;
                    let tail =
                        std::str::from_utf8(raw).map_err(|_| ImportError::MalformedWeights)?;
                    let c = tail.chars().next().ok_or(ImportError::MalformedWeights)?;
                    self.at += c.len_utf8() - 1;
                    c
                }
            };
            if result
                .len()
                .checked_add(ch.len_utf8())
                .is_none_or(|n| n > limit)
            {
                return Err(ImportError::Limit);
            }
            result.push(ch);
        }
        Ok(result)
    }
    fn integer(&mut self) -> Result<usize, ImportError> {
        self.ws();
        let first = self.byte()?;
        if !first.is_ascii_digit() {
            return Err(ImportError::MalformedWeights);
        }
        let mut value = usize::from(first - b'0');
        if first == b'0' && self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
            return Err(ImportError::MalformedWeights);
        }
        while let Some(b) = self.bytes.get(self.at).copied().filter(u8::is_ascii_digit) {
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(usize::from(b - b'0')))
                .ok_or(ImportError::Limit)?;
            self.at += 1;
        }
        Ok(value)
    }
    fn integers(&mut self, limit: usize) -> Result<Vec<usize>, ImportError> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        if !self.take(b']') {
            loop {
                if values.len() >= limit {
                    return Err(ImportError::Limit);
                }
                values.push(self.integer()?);
                if self.take(b']') {
                    break;
                }
                self.expect(b',')?;
            }
        }
        Ok(values)
    }
    fn entry(&mut self) -> Result<Entry, ImportError> {
        self.expect(b'{')?;
        let mut dtype = None;
        let mut shape = None;
        let mut offsets = None;
        let mut seen = BTreeSet::new();
        loop {
            let key = self.string(MAX_NAME)?;
            if !seen.insert(key.clone()) {
                return Err(ImportError::DuplicateKey);
            }
            self.expect(b':')?;
            match key.as_str() {
                "dtype" => {
                    dtype = Some(match self.string(16)?.as_str() {
                        "F32" => FloatType::F32,
                        "F16" => FloatType::F16,
                        "BF16" => FloatType::Bf16,
                        _ => return Err(ImportError::UnsupportedDType),
                    })
                }
                "shape" => shape = Some(self.integers(MAX_RANK)?),
                "data_offsets" => offsets = Some(self.integers(2)?),
                _ => return Err(ImportError::MalformedWeights),
            }
            if self.take(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        let offsets = offsets.ok_or(ImportError::MalformedWeights)?;
        if offsets.len() != 2 {
            return Err(ImportError::MalformedWeights);
        }
        Ok(Entry {
            dtype: dtype.ok_or(ImportError::MalformedWeights)?,
            shape: shape.ok_or(ImportError::MalformedWeights)?,
            start: offsets[0],
            end: offsets[1],
        })
    }
    fn metadata(&mut self) -> Result<(), ImportError> {
        self.expect(b'{')?;
        let mut keys = BTreeSet::new();
        if !self.take(b'}') {
            loop {
                if keys.len() >= MAX_METADATA {
                    return Err(ImportError::Limit);
                }
                if !keys.insert(self.string(4096)?) {
                    return Err(ImportError::DuplicateKey);
                }
                self.expect(b':')?;
                let _ = self.string(4096)?;
                if self.take(b'}') {
                    break;
                }
                self.expect(b',')?;
            }
        }
        Ok(())
    }
}
