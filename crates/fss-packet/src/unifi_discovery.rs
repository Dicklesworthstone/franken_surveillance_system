#![forbid(unsafe_code)]
//! Bounded parsing of Ubiquiti v1 LAN discovery replies.
//!
//! A response, address, model string, or MAC is an unauthenticated claim. This
//! parser performs no network I/O, camera login, adoption, or credential
//! handling. Unknown fields (which may contain sensitive material) are never
//! exposed or formatted by this API. V2 and other packet forms are unsupported.

use std::fmt;

/// Observed v1 discovery query for one explicitly scoped network or device.
pub const V1_QUERY: [u8; 4] = [1, 0, 0, 0];
/// Ubiquiti discovery UDP destination port.
pub const PORT: u16 = 10001;
/// Maximum reply accepted by this bounded parser.
pub const MAX_DATAGRAM: usize = 8192;
const MAX_FIELDS: usize = 128;
const MAX_TEXT: usize = 128;

/// Payload-free reasons a discovery message cannot be interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Message size or declared length is invalid.
    Length,
    /// Version or message type is not the observed v1 reply.
    Unsupported,
    /// A TLV is truncated, oversized, duplicated, or has an invalid known shape.
    InvalidField,
    /// The message contains more fields than this parser admits.
    FieldLimit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi discovery refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// An untrusted device-family hypothesis, not an authenticated device identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceKind {
    /// Platform string has the observed UVC camera-family prefix.
    CameraCandidate,
    /// No supported camera platform claim was observed.
    OtherOrUnknown,
}

/// One advertised interface claim. Neither value is authenticated.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AddressClaim {
    /// Camera-advertised interface MAC address.
    pub mac: [u8; 6],
    /// Camera-advertised IPv4 address.
    pub ipv4: [u8; 4],
}
impl fmt::Debug for AddressClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressClaim").finish_non_exhaustive()
    }
}

/// Fully validated, borrowed reply. No raw or unknown fields are exposed.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Reply<'a> {
    fields: &'a [u8],
    platform: Option<&'a str>,
    firmware: Option<&'a str>,
    mac: Option<[u8; 6]>,
    address_count: usize,
}
impl<'a> Reply<'a> {
    /// Validate the complete datagram and every TLV before exposing any claims.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if !(4..=MAX_DATAGRAM).contains(&bytes.len()) {
            return Err(Error::Length);
        }
        if bytes[0..2] != [1, 0] {
            return Err(Error::Unsupported);
        }
        let claimed = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if claimed != bytes.len() - 4 {
            return Err(Error::Length);
        }
        let fields = &bytes[4..];
        let mut pos = 0;
        let mut count = 0;
        let mut platform = None;
        let mut firmware = None;
        let mut mac = None;
        let mut address_count = 0;
        while pos < fields.len() {
            let header = fields.get(pos..pos + 3).ok_or(Error::InvalidField)?;
            let field_type = header[0];
            let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
            pos += 3;
            let end = pos.checked_add(len).ok_or(Error::InvalidField)?;
            let value = fields.get(pos..end).ok_or(Error::InvalidField)?;
            pos = end;
            count += 1;
            if count > MAX_FIELDS {
                return Err(Error::FieldLimit);
            }
            match field_type {
                1 => {
                    if mac.is_some() || value.len() != 6 {
                        return Err(Error::InvalidField);
                    }
                    mac = Some(value.try_into().map_err(|_| Error::InvalidField)?);
                }
                2 => {
                    if value.len() != 10 {
                        return Err(Error::InvalidField);
                    }
                    address_count += 1;
                }
                3 => {
                    if firmware.is_some() {
                        return Err(Error::InvalidField);
                    }
                    firmware = Some(text(value)?);
                }
                12 => {
                    if platform.is_some() {
                        return Err(Error::InvalidField);
                    }
                    platform = Some(text(value)?);
                }
                _ => {}
            }
        }
        Ok(Self {
            fields,
            platform,
            firmware,
            mac,
            address_count,
        })
    }

    /// Camera-family hypothesis from the device-provided platform text only.
    pub fn kind(self) -> DeviceKind {
        if self
            .platform
            .is_some_and(|p| p == "UVC" || p.starts_with("UVC ") || p.starts_with("UVC-"))
        {
            DeviceKind::CameraCandidate
        } else {
            DeviceKind::OtherOrUnknown
        }
    }
    /// Untrusted platform text, if present. It must not grant adoption authority.
    pub fn platform(self) -> Option<&'a str> {
        self.platform
    }
    /// Untrusted firmware text, if present.
    pub fn firmware(self) -> Option<&'a str> {
        self.firmware
    }
    /// Unauthenticated advertised hardware address.
    pub fn mac(self) -> Option<[u8; 6]> {
        self.mac
    }
    /// Number of advertised interface address claims.
    pub fn address_count(self) -> usize {
        self.address_count
    }
    /// Iterate fully validated address claims without retaining unknown fields.
    pub fn addresses(self) -> Addresses<'a> {
        Addresses {
            fields: self.fields,
            pos: 0,
            remaining: self.address_count,
        }
    }
}
impl fmt::Debug for Reply<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("kind", &self.kind())
            .field("addresses", &self.address_count)
            .finish_non_exhaustive()
    }
}

fn text(value: &[u8]) -> Result<&str, Error> {
    if value.is_empty()
        || value.len() > MAX_TEXT
        || !value.iter().all(|&b| (0x20..=0x7e).contains(&b))
    {
        return Err(Error::InvalidField);
    }
    std::str::from_utf8(value).map_err(|_| Error::InvalidField)
}

/// Iterator over validated address claims in one reply.
pub struct Addresses<'a> {
    fields: &'a [u8],
    pos: usize,
    remaining: usize,
}
impl Iterator for Addresses<'_> {
    type Item = AddressClaim;
    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.fields.len() {
            let header = self.fields.get(self.pos..self.pos + 3)?;
            let kind = header[0];
            let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
            let start = self.pos + 3;
            let end = start.checked_add(len)?;
            let value = self.fields.get(start..end)?;
            self.pos = end;
            if kind == 2 {
                self.remaining -= 1;
                return Some(AddressClaim {
                    mac: value[..6].try_into().ok()?,
                    ipv4: value[6..].try_into().ok()?,
                });
            }
        }
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for Addresses<'_> {}
