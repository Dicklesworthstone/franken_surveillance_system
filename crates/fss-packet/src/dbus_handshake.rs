#![forbid(unsafe_code)]
//! Restricted D-Bus EXTERNAL authentication and `Hello` message framing.
//!
//! This implements a small, fail-closed local-bus handshake profile, not a
//! general D-Bus or BlueZ client. It performs no I/O, grants no authority and
//! does not authenticate a Bluetooth device. See the D-Bus specification:
//! <https://dbus.freedesktop.org/doc/dbus-specification.html>.

use std::fmt;

const MAX_AUTH_LINE: usize = 128;
const MAX_HELLO_MESSAGE: usize = 8192;

/// Maximum complete D-Bus message accepted by this restricted handshake.
pub const MAX_MESSAGE_BYTES: usize = MAX_HELLO_MESSAGE;

/// Payload-free refusal in the restricted handshake profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A size or arithmetic bound was exceeded.
    Limit,
    /// The input is malformed or violates the expected handshake.
    Invalid,
    /// The bus rejected authentication or returned an error.
    Rejected,
    /// A valid but unsupported header value needs a general D-Bus decoder.
    Unsupported,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "D-Bus handshake refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Encode the initial NUL and EXTERNAL request for an owner-supplied Unix UID.
/// The bus still validates the OS peer credentials; this is not proof of identity.
pub fn external_request(uid: u32) -> Vec<u8> {
    let digits = uid.to_string();
    let mut out = Vec::with_capacity(17 + digits.len() * 2);
    out.extend_from_slice(b"\0AUTH EXTERNAL ");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digits.bytes() {
        out.push(HEX[usize::from(byte >> 4)]);
        out.push(HEX[usize::from(byte & 15)]);
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// A complete bus authentication response. The server GUID is an unverified
/// local-bus claim; it does not identify a camera or establish peer trust.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthOk {
    /// Bytes consumed, leaving any later protocol bytes with the caller.
    pub consumed: usize,
    /// Decoded GUID bytes reported by the bus.
    pub guid: [u8; 16],
}
impl fmt::Debug for AuthOk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthOk")
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

/// Parse one bounded CRLF response. `None` means more bytes are needed.
pub fn parse_auth_ok(input: &[u8]) -> Result<Option<AuthOk>, Error> {
    let Some(end) = input.windows(2).position(|pair| pair == b"\r\n") else {
        return if input.len() >= MAX_AUTH_LINE {
            Err(Error::Limit)
        } else {
            Ok(None)
        };
    };
    if end + 2 > MAX_AUTH_LINE {
        return Err(Error::Limit);
    }
    let line = &input[..end];
    if line.starts_with(b"REJECTED") || line.starts_with(b"ERROR") {
        return Err(Error::Rejected);
    }
    let hex = line.strip_prefix(b"OK ").ok_or(Error::Invalid)?;
    if hex.len() != 32 {
        return Err(Error::Invalid);
    }
    let mut guid = [0; 16];
    for (index, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte: u8| -> Option<u8> {
            match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            }
        };
        guid[index] =
            digit(pair[0]).ok_or(Error::Invalid)? * 16 + digit(pair[1]).ok_or(Error::Invalid)?;
    }
    Ok(Some(AuthOk {
        consumed: end + 2,
        guid,
    }))
}

/// Command that ends text authentication without negotiating file descriptors.
pub const BEGIN: &[u8] = b"BEGIN\r\n";

fn pad(out: &mut Vec<u8>, alignment: usize) {
    let length = (out.len() + alignment - 1) & !(alignment - 1);
    out.resize(length, 0);
}
fn string_field(out: &mut Vec<u8>, code: u8, kind: u8, value: &[u8]) {
    pad(out, 8);
    out.extend_from_slice(&[code, 1, kind, 0]);
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    out.push(0);
}

fn bus_call(serial: u32, member: &[u8]) -> Result<Vec<u8>, Error> {
    if serial == 0 {
        return Err(Error::Invalid);
    }
    let mut out = vec![b'l', 1, 0, 1];
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&serial.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    string_field(&mut out, 1, b'o', b"/org/freedesktop/DBus");
    string_field(&mut out, 2, b's', b"org.freedesktop.DBus");
    string_field(&mut out, 3, b's', member);
    string_field(&mut out, 6, b's', b"org.freedesktop.DBus");
    Ok(out)
}
fn finish_header(out: &mut Vec<u8>) -> Result<(), Error> {
    let field_bytes = u32::try_from(out.len() - 16).map_err(|_| Error::Limit)?;
    out[12..16].copy_from_slice(&field_bytes.to_le_bytes());
    pad(out, 8);
    Ok(())
}
/// Encode a little-endian `org.freedesktop.DBus.Hello` method call.
/// Serial zero is invalid. This has no BlueZ or device-management effect.
pub fn hello(serial: u32) -> Result<Vec<u8>, Error> {
    let mut out = bus_call(serial, b"Hello")?;
    finish_header(&mut out)?;
    Ok(out)
}

/// Ask the local message bus whether the BlueZ service name has an owner.
/// This is read-only and does not discover, connect, or manage a device.
pub fn bluez_name_has_owner(serial: u32) -> Result<Vec<u8>, Error> {
    let mut out = bus_call(serial, b"NameHasOwner")?;
    pad(&mut out, 8);
    out.extend_from_slice(&[8, 1, b'g', 0, 1, b's', 0]);
    finish_header(&mut out)?;
    let body_at = out.len();
    out.extend_from_slice(&9u32.to_le_bytes());
    out.extend_from_slice(b"org.bluez\0");
    let body_len = u32::try_from(out.len() - body_at).map_err(|_| Error::Limit)?;
    out[4..8].copy_from_slice(&body_len.to_le_bytes());
    Ok(out)
}

/// Encode a read-only BlueZ ObjectManager snapshot request. The response is
/// untrusted; this call neither starts discovery nor connects to a device.
pub fn bluez_managed_objects(serial: u32) -> Result<Vec<u8>, Error> {
    if serial == 0 {
        return Err(Error::Invalid);
    }
    let mut out = vec![b'l', 1, 0, 1];
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&serial.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    string_field(&mut out, 1, b'o', b"/");
    string_field(&mut out, 2, b's', b"org.freedesktop.DBus.ObjectManager");
    string_field(&mut out, 3, b's', b"GetManagedObjects");
    string_field(&mut out, 6, b's', b"org.bluez");
    finish_header(&mut out)?;
    Ok(out)
}

fn read_u32(bytes: &[u8], at: usize, little: bool) -> Result<u32, Error> {
    let end = at.checked_add(4).ok_or(Error::Limit)?;
    let a: [u8; 4] = bytes
        .get(at..end)
        .ok_or(Error::Invalid)?
        .try_into()
        .map_err(|_| Error::Invalid)?;
    Ok(if little {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    })
}
fn aligned(at: usize, alignment: usize) -> Result<usize, Error> {
    Ok(at.checked_add(alignment - 1).ok_or(Error::Limit)? & !(alignment - 1))
}

/// Compute a bounded message length from the 16-byte fixed header. `None`
/// means the fixed header is incomplete; `Some` does not assert that the rest
/// of the message has arrived or that its fields or sender are valid.
pub fn declared_message_len(input: &[u8]) -> Result<Option<usize>, Error> {
    if input.len() < 16 {
        return Ok(None);
    }
    let little = match input[0] {
        b'l' => true,
        b'B' => false,
        _ => return Err(Error::Invalid),
    };
    if input[3] != 1 || read_u32(input, 8, little)? == 0 {
        return Err(Error::Invalid);
    }
    let body = usize::try_from(read_u32(input, 4, little)?).map_err(|_| Error::Limit)?;
    let fields = usize::try_from(read_u32(input, 12, little)?).map_err(|_| Error::Limit)?;
    let header = aligned(16usize.checked_add(fields).ok_or(Error::Limit)?, 8)?;
    let total = header.checked_add(body).ok_or(Error::Limit)?;
    if total > MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    Ok(Some(total))
}

/// A correlated `Hello` method return. Debug intentionally redacts the name.
pub struct HelloReply<'a> {
    name: &'a str,
    consumed: usize,
}
impl HelloReply<'_> {
    /// Bus-assigned unique name; this is not a camera identity.
    pub fn name(&self) -> &str {
        self.name
    }
    /// Exact number of bytes consumed from the supplied stream.
    pub fn consumed(&self) -> usize {
        self.consumed
    }
}
impl fmt::Debug for HelloReply<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelloReply")
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

struct ParsedReturn<'a> {
    little: bool,
    body_at: usize,
    total: usize,
    signature: &'a [u8],
}

fn parse_return(input: &[u8], expected_serial: u32) -> Result<Option<ParsedReturn<'_>>, Error> {
    if expected_serial == 0 {
        return Err(Error::Invalid);
    }
    if input.len() < 16 {
        return Ok(None);
    }
    let little = match input[0] {
        b'l' => true,
        b'B' => false,
        _ => return Err(Error::Invalid),
    };
    if input[3] != 1 || read_u32(input, 8, little)? == 0 {
        return Err(Error::Invalid);
    }
    let body_len = usize::try_from(read_u32(input, 4, little)?).map_err(|_| Error::Limit)?;
    let header_len = usize::try_from(read_u32(input, 12, little)?).map_err(|_| Error::Limit)?;
    let header_end = 16usize.checked_add(header_len).ok_or(Error::Limit)?;
    let body_at = aligned(header_end, 8)?;
    let total = body_at.checked_add(body_len).ok_or(Error::Limit)?;
    if total > MAX_HELLO_MESSAGE {
        return Err(Error::Limit);
    }
    if input.len() < total {
        return Ok(None);
    }
    if input[1] == 3 {
        return Err(Error::Rejected);
    }
    if input[1] != 2 || input[header_end..body_at].iter().any(|b| *b != 0) {
        return Err(Error::Invalid);
    }
    let mut position = 16;
    let mut reply = None;
    let mut signature = None;
    let mut seen = 0u16;
    while position < header_end {
        let next = aligned(position, 8)?;
        if next > header_end || input[position..next].iter().any(|b| *b != 0) {
            return Err(Error::Invalid);
        }
        position = next;
        if position >= header_end {
            return Err(Error::Invalid);
        }
        if position + 4 > header_end {
            return Err(Error::Invalid);
        }
        let code = *input.get(position).ok_or(Error::Invalid)?;
        let variant = input
            .get(position + 1..position + 4)
            .ok_or(Error::Invalid)?;
        if code == 0 || variant[0] != 1 || variant[2] != 0 {
            return Err(Error::Invalid);
        }
        if code <= 9 {
            let bit = 1u16 << code;
            if seen & bit != 0 {
                return Err(Error::Invalid);
            }
            seen |= bit;
        }
        let kind = variant[1];
        position += 4;
        match kind {
            b'u' => {
                position = aligned(position, 4)?;
                if position.checked_add(4).is_none_or(|end| end > header_end) {
                    return Err(Error::Invalid);
                }
                let value = read_u32(input, position, little)?;
                if code == 5 && reply.replace(value).is_some() {
                    return Err(Error::Invalid);
                }
                if code == 9 && value != 0 {
                    return Err(Error::Unsupported);
                }
                position += 4;
            }
            b's' | b'o' => {
                position = aligned(position, 4)?;
                if position.checked_add(4).is_none_or(|end| end > header_end) {
                    return Err(Error::Invalid);
                }
                let length = usize::try_from(read_u32(input, position, little)?)
                    .map_err(|_| Error::Limit)?;
                position += 4;
                let end = position.checked_add(length).ok_or(Error::Limit)?;
                if end >= header_end
                    || input[end] != 0
                    || std::str::from_utf8(&input[position..end]).is_err()
                    || input[position..end].contains(&0)
                {
                    return Err(Error::Invalid);
                }
                position = end + 1;
            }
            b'g' => {
                let length = usize::from(*input.get(position).ok_or(Error::Invalid)?);
                position += 1;
                let end = position.checked_add(length).ok_or(Error::Limit)?;
                if end >= header_end || input[end] != 0 {
                    return Err(Error::Invalid);
                }
                if code == 8 && signature.replace(&input[position..end]).is_some() {
                    return Err(Error::Invalid);
                }
                position = end + 1;
            }
            _ => return Err(Error::Unsupported),
        }
        let expected_kind = match code {
            1 => Some(b'o'),
            2..=4 | 6..=7 => Some(b's'),
            5 | 9 => Some(b'u'),
            8 => Some(b'g'),
            _ => None,
        };
        if expected_kind.is_some_and(|value| value != kind) {
            return Err(Error::Invalid);
        }
    }
    if reply != Some(expected_serial) {
        return Err(Error::Invalid);
    }
    Ok(Some(ParsedReturn {
        little,
        body_at,
        total,
        signature: signature.ok_or(Error::Invalid)?,
    }))
}

/// Parse a bounded, correlated `Hello` return. `None` means more stream bytes
/// are needed. Header variants outside the basic string/signature/u32 profile
/// are explicitly unsupported; use a general D-Bus decoder for other traffic.
pub fn parse_hello_reply(
    input: &[u8],
    expected_serial: u32,
) -> Result<Option<HelloReply<'_>>, Error> {
    let Some(reply) = parse_return(input, expected_serial)? else {
        return Ok(None);
    };
    if reply.signature != b"s" || reply.total - reply.body_at < 5 {
        return Err(Error::Invalid);
    }
    let name_len =
        usize::try_from(read_u32(input, reply.body_at, reply.little)?).map_err(|_| Error::Limit)?;
    let start = reply.body_at + 4;
    let end = start.checked_add(name_len).ok_or(Error::Limit)?;
    if name_len > 255 || end.checked_add(1) != Some(reply.total) || input[end] != 0 {
        return Err(Error::Invalid);
    }
    let name = std::str::from_utf8(&input[start..end]).map_err(|_| Error::Invalid)?;
    let suffix = name.strip_prefix(':').ok_or(Error::Invalid)?;
    if !suffix.contains('.')
        || suffix.split('.').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
    {
        return Err(Error::Invalid);
    }
    Ok(Some(HelloReply {
        name,
        consumed: reply.total,
    }))
}

/// A correlated bus response reporting whether `org.bluez` has an owner.
/// This does not establish adapter availability or camera identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BluezOwnerReply {
    /// Untrusted local-bus response.
    pub present: bool,
    /// Exact number of bytes consumed from the supplied stream.
    pub consumed: usize,
}

/// Parse a bounded `NameHasOwner` return for the caller's request serial.
/// `None` means more stream bytes are needed. Unsupported header variants are
/// refused rather than silently interpreted.
pub fn parse_bluez_owner_reply(
    input: &[u8],
    expected_serial: u32,
) -> Result<Option<BluezOwnerReply>, Error> {
    let Some(reply) = parse_return(input, expected_serial)? else {
        return Ok(None);
    };
    if reply.signature != b"b" || reply.total - reply.body_at != 4 {
        return Err(Error::Invalid);
    }
    let value = read_u32(input, reply.body_at, reply.little)?;
    let present = match value {
        0 => false,
        1 => true,
        _ => return Err(Error::Invalid),
    };
    Ok(Some(BluezOwnerReply {
        present,
        consumed: reply.total,
    }))
}

/// Body of a correlated ObjectManager response, without peer authentication or
/// interpretation of its nested values.
pub struct ManagedObjectsBody<'a> {
    /// Complete marshalled body; still requires bounded structural validation.
    pub body: &'a [u8],
    /// True for little-endian values; false for big-endian values.
    pub little_endian: bool,
    /// Total frame bytes consumed.
    pub consumed: usize,
}
impl fmt::Debug for ManagedObjectsBody<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedObjectsBody")
            .field("body_bytes", &self.body.len())
            .field("little_endian", &self.little_endian)
            .field("consumed", &self.consumed)
            .finish()
    }
}

/// Correlate a bounded ObjectManager response and expose its still-untrusted
/// body. Caller must independently authenticate the bus and intended sender.
pub fn parse_bluez_managed_objects_reply(
    input: &[u8],
    expected_serial: u32,
) -> Result<Option<ManagedObjectsBody<'_>>, Error> {
    let Some(reply) = parse_return(input, expected_serial)? else {
        return Ok(None);
    };
    if reply.signature != b"a{oa{sa{sv}}}" {
        return Err(Error::Invalid);
    }
    Ok(Some(ManagedObjectsBody {
        body: &input[reply.body_at..reply.total],
        little_endian: reply.little,
        consumed: reply.total,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(value: u32, little: bool) -> [u8; 4] {
        if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    }
    fn reply(little: bool) -> Vec<u8> {
        let mut out = vec![if little { b'l' } else { b'B' }, 2, 0, 1];
        out.extend_from_slice(&number(10, little));
        out.extend_from_slice(&number(2, little));
        out.extend_from_slice(&number(15, little));
        out.extend_from_slice(&[5, 1, b'u', 0]);
        out.extend_from_slice(&number(1, little));
        out.extend_from_slice(&[8, 1, b'g', 0, 1, b's', 0]);
        out.push(0);
        out.extend_from_slice(&number(5, little));
        out.extend_from_slice(b":1.42\0");
        out
    }

    #[test]
    fn external_auth_is_bounded_and_handles_fragmentation() -> Result<(), Error> {
        assert_eq!(external_request(1000), b"\0AUTH EXTERNAL 31303030\r\n");
        let line = b"OK 00112233445566778899aabbccddeeff\r\nextra";
        for split in 0..37 {
            assert_eq!(parse_auth_ok(&line[..split])?, None);
        }
        let accepted = parse_auth_ok(line)?.ok_or(Error::Invalid)?;
        assert_eq!(accepted.consumed, 37);
        assert_eq!(accepted.guid[0], 0);
        assert_eq!(accepted.guid[15], 255);
        assert!(matches!(
            parse_auth_ok(b"REJECTED EXTERNAL\r\n"),
            Err(Error::Rejected)
        ));
        assert!(matches!(
            parse_auth_ok(&[b'x'; MAX_AUTH_LINE]),
            Err(Error::Limit)
        ));
        assert!(matches!(parse_auth_ok(b"OK bad\r\n"), Err(Error::Invalid)));
        Ok(())
    }

    #[test]
    fn hello_is_bounded_and_serial_is_required() -> Result<(), Error> {
        assert!(matches!(hello(0), Err(Error::Invalid)));
        let out = hello(17)?;
        assert_eq!(out.len() % 8, 0);
        assert_eq!(&out[..4], b"l\x01\x00\x01");
        assert_eq!(read_u32(&out, 8, true)?, 17);
        assert_eq!(read_u32(&out, 4, true)?, 0);
        for split in 0..16 {
            assert_eq!(declared_message_len(&out[..split])?, None);
        }
        assert_eq!(declared_message_len(&out[..16])?, Some(out.len()));
        let query = bluez_name_has_owner(18)?;
        assert_eq!(read_u32(&query, 8, true)?, 18);
        assert_eq!(read_u32(&query, 4, true)?, 14);
        assert!(query.ends_with(b"org.bluez\0"));
        Ok(())
    }

    #[test]
    fn bluez_owner_reply_is_correlated_and_boolean() -> Result<(), Error> {
        for little in [true, false] {
            let mut wire = reply(little);
            wire[4..8].copy_from_slice(&number(4, little));
            wire[29] = b'b';
            wire.truncate(32);
            wire.extend_from_slice(&number(1, little));
            let decoded = parse_bluez_owner_reply(&wire, 1)?.ok_or(Error::Invalid)?;
            assert_eq!(
                decoded,
                BluezOwnerReply {
                    present: true,
                    consumed: wire.len()
                }
            );
            assert!(matches!(
                parse_bluez_owner_reply(&wire, 2),
                Err(Error::Invalid)
            ));
            for split in 0..wire.len() {
                assert!(parse_bluez_owner_reply(&wire[..split], 1)?.is_none());
            }
            wire[32..36].copy_from_slice(&number(0, little));
            assert!(
                !parse_bluez_owner_reply(&wire, 1)?
                    .ok_or(Error::Invalid)?
                    .present
            );
            wire[32..36].copy_from_slice(&number(2, little));
            assert!(matches!(
                parse_bluez_owner_reply(&wire, 1),
                Err(Error::Invalid)
            ));
        }
        Ok(())
    }

    #[test]
    fn hello_response_handles_both_endiannesses_and_partial_input() -> Result<(), Error> {
        for little in [true, false] {
            let wire = reply(little);
            for split in 0..wire.len() {
                assert!(parse_hello_reply(&wire[..split], 1)?.is_none());
            }
            let decoded = parse_hello_reply(&wire, 1)?.ok_or(Error::Invalid)?;
            assert_eq!(decoded.name(), ":1.42");
            assert_eq!(decoded.consumed(), wire.len());
            assert!(!format!("{decoded:?}").contains(":1.42"));
            assert!(matches!(parse_hello_reply(&wire, 2), Err(Error::Invalid)));
        }
        Ok(())
    }

    #[test]
    fn corrupt_or_unsupported_hello_replies_fail_closed() {
        let mut wire = reply(true);
        wire[18] = b'a';
        assert!(matches!(
            parse_hello_reply(&wire, 1),
            Err(Error::Unsupported)
        ));
        let mut wire = reply(true);
        wire[31] = 1;
        assert!(matches!(parse_hello_reply(&wire, 1), Err(Error::Invalid)));
        let mut wire = reply(true);
        wire[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(parse_hello_reply(&wire, 1), Err(Error::Limit)));
        let mut wire = reply(true);
        wire[1] = 3;
        assert!(matches!(parse_hello_reply(&wire, 1), Err(Error::Rejected)));
        let mut wire = reply(true);
        wire[36..41].copy_from_slice(b":1..2");
        assert!(matches!(parse_hello_reply(&wire, 1), Err(Error::Invalid)));
    }
}
