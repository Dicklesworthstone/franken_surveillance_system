#![forbid(unsafe_code)]
//! Private, bounded HTTP/1 response framing. It owns no network or auth policy.

use super::{HttpError, HttpLimits, HttpResponse};
use crate::rtsp::authentication::MAX_CHALLENGE_BYTES;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Head,
    Fixed(usize),
    UntilEof,
    ChunkSize,
    Chunk(usize),
    ChunkEnd,
    Trailers,
    Complete,
    Taken,
}

#[derive(Clone, Copy)]
enum Framing {
    Length(usize),
    Chunked,
    UntilEof,
}

struct Head {
    status: u16,
    content_type: Option<String>,
    digest_challenge: Option<String>,
    framing: Framing,
}

pub(super) struct Decoder {
    limits: HttpLimits,
    phase: Phase,
    control: Vec<u8>,
    body: Vec<u8>,
    head: Option<Head>,
    wire: usize,
    head_bytes: usize,
    interim: u8,
    chunks: usize,
    failure: Option<HttpError>,
}

impl Decoder {
    pub(super) fn new(limits: HttpLimits) -> Self {
        Self {
            limits,
            phase: Phase::Head,
            control: Vec::new(),
            body: Vec::new(),
            head: None,
            wire: 0,
            head_bytes: 0,
            interim: 0,
            chunks: 0,
            failure: None,
        }
    }

    pub(super) fn complete(&self) -> bool {
        self.phase == Phase::Complete && self.failure.is_none()
    }

    pub(super) fn push(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = self.consume(bytes);
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }

    fn consume(&mut self, mut bytes: &[u8]) -> Result<(), HttpError> {
        if self
            .wire
            .checked_add(bytes.len())
            .is_none_or(|total| total > self.limits.wire_bytes)
        {
            return Err(HttpError::Limit);
        }
        self.wire += bytes.len();
        while !bytes.is_empty() {
            match self.phase {
                Phase::Complete => return Err(HttpError::TrailingResponse),
                Phase::Taken => return Err(HttpError::Closed),
                Phase::Fixed(remaining) | Phase::Chunk(remaining) => {
                    let count = remaining.min(bytes.len());
                    self.append_body(&bytes[..count])?;
                    bytes = &bytes[count..];
                    self.phase = match self.phase {
                        Phase::Fixed(_) if count == remaining => Phase::Complete,
                        Phase::Fixed(_) => Phase::Fixed(remaining - count),
                        Phase::Chunk(_) if count == remaining => Phase::ChunkEnd,
                        _ => Phase::Chunk(remaining - count),
                    };
                }
                Phase::UntilEof => {
                    self.append_body(bytes)?;
                    bytes = &[];
                }
                Phase::Head | Phase::ChunkSize | Phase::ChunkEnd | Phase::Trailers => {
                    let byte = bytes[0];
                    bytes = &bytes[1..];
                    self.control_byte(byte)?;
                    match self.phase {
                        Phase::Head if self.control.ends_with(b"\r\n\r\n") => {
                            let head = parse_head(&self.control, self.limits.body_bytes)?;
                            self.control.fill(0);
                            self.control.clear();
                            if head.status < 200 {
                                self.interim += 1;
                                if self.interim > 8 {
                                    return Err(HttpError::Limit);
                                }
                            } else {
                                self.phase = match head.framing {
                                    Framing::Length(0) => Phase::Complete,
                                    Framing::Length(length) => Phase::Fixed(length),
                                    Framing::Chunked => Phase::ChunkSize,
                                    Framing::UntilEof => Phase::UntilEof,
                                };
                                self.head = Some(head);
                            }
                        }
                        Phase::ChunkSize if self.control.ends_with(b"\r\n") => {
                            let length = parse_chunk(&self.control[..self.control.len() - 2])?;
                            if length > self.limits.body_bytes.saturating_sub(self.body.len()) {
                                return Err(HttpError::Limit);
                            }
                            self.control.clear();
                            if length == 0 {
                                self.phase = Phase::Trailers;
                            } else {
                                self.chunks += 1;
                                if self.chunks > 4096 {
                                    return Err(HttpError::Limit);
                                }
                                self.phase = Phase::Chunk(length);
                            }
                        }
                        Phase::ChunkEnd if self.control.len() == 2 => {
                            if self.control != b"\r\n" {
                                return Err(HttpError::Malformed);
                            }
                            self.control.clear();
                            self.phase = Phase::ChunkSize;
                        }
                        Phase::Trailers
                            if self.control == b"\r\n" || self.control.ends_with(b"\r\n\r\n") =>
                        {
                            parse_trailers(&self.control)?;
                            self.control.fill(0);
                            self.control.clear();
                            self.phase = Phase::Complete;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    fn control_byte(&mut self, byte: u8) -> Result<(), HttpError> {
        if byte > 126
            || (byte < 32 && !matches!(byte, b'\r' | b'\n' | b'\t'))
            || byte == b'\n' && self.control.last() != Some(&b'\r')
            || self.control.last() == Some(&b'\r') && byte != b'\n'
        {
            return Err(HttpError::Malformed);
        }
        let limit = match self.phase {
            Phase::Head => {
                if self.head_bytes >= self.limits.header_bytes {
                    return Err(HttpError::Limit);
                }
                self.head_bytes += 1;
                self.limits.header_bytes
            }
            Phase::ChunkSize => 1024,
            Phase::ChunkEnd => 2,
            _ => self.limits.header_bytes,
        };
        if self.control.len() >= limit {
            return Err(HttpError::Limit);
        }
        self.control
            .try_reserve(1)
            .map_err(|_| HttpError::Allocation)?;
        self.control.push(byte);
        Ok(())
    }

    fn append_body(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
        if bytes.len() > self.limits.body_bytes.saturating_sub(self.body.len()) {
            return Err(HttpError::Limit);
        }
        self.body
            .try_reserve_exact(bytes.len())
            .map_err(|_| HttpError::Allocation)?;
        self.body.extend_from_slice(bytes);
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<(), HttpError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        match self.phase {
            Phase::Complete | Phase::UntilEof => {
                self.phase = Phase::Complete;
                Ok(())
            }
            Phase::Taken => Err(HttpError::Closed),
            _ => {
                self.failure = Some(HttpError::Truncated);
                Err(HttpError::Truncated)
            }
        }
    }

    pub(super) fn take_response(&mut self) -> Result<HttpResponse, HttpError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.phase == Phase::Taken {
            return Err(HttpError::Closed);
        }
        if self.phase != Phase::Complete {
            return Err(HttpError::NotComplete);
        }
        let head = self.head.take().ok_or(HttpError::NotComplete)?;
        self.phase = Phase::Taken;
        Ok(HttpResponse {
            status: head.status,
            content_type: head.content_type,
            digest_challenge: head.digest_challenge,
            body: std::mem::take(&mut self.body),
        })
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        self.control.fill(0);
        self.body.fill(0);
    }
}

fn parse_head(bytes: &[u8], body_limit: usize) -> Result<Head, HttpError> {
    let text = std::str::from_utf8(bytes).map_err(|_| HttpError::Malformed)?;
    let block = text.strip_suffix("\r\n\r\n").ok_or(HttpError::Malformed)?;
    let mut lines = block.split("\r\n");
    let status_line = lines.next().ok_or(HttpError::Malformed)?.as_bytes();
    if status_line.len() < 13
        || !(status_line.starts_with(b"HTTP/1.1 ") || status_line.starts_with(b"HTTP/1.0 "))
        || !status_line[9..12].iter().all(u8::is_ascii_digit)
        || status_line[12] != b' '
        || !status_line[13..]
            .iter()
            .all(|byte| (32..=126).contains(byte))
    {
        return Err(HttpError::Malformed);
    }
    let status = u16::from(status_line[9] - b'0') * 100
        + u16::from(status_line[10] - b'0') * 10
        + u16::from(status_line[11] - b'0');
    if !(100..=599).contains(&status) {
        return Err(HttpError::Malformed);
    }
    if status == 101 {
        return Err(HttpError::Unsupported);
    }
    let mut length = None;
    let mut transfer = false;
    let mut content_type = None;
    let mut digest_challenge = None;
    let mut encoding = false;
    for (index, line) in lines.enumerate() {
        if index >= 64 {
            return Err(HttpError::Limit);
        }
        let (name, value) = field(line)?;
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(HttpError::Malformed);
            }
            let value = decimal(value)?;
            if value > body_limit {
                return Err(HttpError::Limit);
            }
            length = Some(value);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer {
                return Err(HttpError::Malformed);
            }
            if !value.eq_ignore_ascii_case("chunked") {
                return Err(HttpError::Unsupported);
            }
            transfer = true;
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() || value.is_empty() {
                return Err(HttpError::Malformed);
            }
            if value.len() > 512 {
                return Err(HttpError::Limit);
            }
            content_type = Some(copy_text(value)?);
        } else if name.eq_ignore_ascii_case("content-encoding") {
            if encoding {
                return Err(HttpError::Malformed);
            }
            if !value.eq_ignore_ascii_case("identity") {
                return Err(HttpError::Unsupported);
            }
            encoding = true;
        } else if name.eq_ignore_ascii_case("www-authenticate") {
            if digest_challenge.is_some() {
                return Err(HttpError::Malformed);
            }
            if value.len() > MAX_CHALLENGE_BYTES {
                return Err(HttpError::Limit);
            }
            if !value
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Digest "))
            {
                return Err(HttpError::Unsupported);
            }
            digest_challenge = Some(copy_text(value)?);
        }
    }
    if transfer && (length.is_some() || status_line.starts_with(b"HTTP/1.0 "))
        || (status < 200 || status == 204) && (transfer || length.is_some())
        || status == 205 && (transfer || length.is_some_and(|value| value != 0))
    {
        return Err(HttpError::Malformed);
    }
    let framing = if status < 200 || matches!(status, 204 | 205 | 304) {
        if transfer {
            return Err(HttpError::Malformed);
        }
        Framing::Length(0)
    } else if transfer {
        Framing::Chunked
    } else if let Some(length) = length {
        Framing::Length(length)
    } else {
        Framing::UntilEof
    };
    Ok(Head {
        status,
        content_type,
        digest_challenge,
        framing,
    })
}

fn copy_text(value: &str) -> Result<String, HttpError> {
    let mut out = String::new();
    out.try_reserve_exact(value.len())
        .map_err(|_| HttpError::Allocation)?;
    out.push_str(value);
    Ok(out)
}

fn field(line: &str) -> Result<(&str, &str), HttpError> {
    let (name, value) = line.split_once(':').ok_or(HttpError::Malformed)?;
    if !token(name.as_bytes())
        || value
            .bytes()
            .any(|byte| byte > 126 || byte < 32 && byte != b'\t')
    {
        return Err(HttpError::Malformed);
    }
    Ok((name, value.trim_matches([' ', '\t'])))
}

fn token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
}

fn decimal(value: &str) -> Result<usize, HttpError> {
    if value.is_empty() {
        return Err(HttpError::Malformed);
    }
    value.bytes().try_fold(0_usize, |out, byte| {
        if !byte.is_ascii_digit() {
            return Err(HttpError::Malformed);
        }
        out.checked_mul(10)
            .and_then(|out| out.checked_add(usize::from(byte - b'0')))
            .ok_or(HttpError::Limit)
    })
}

fn parse_chunk(bytes: &[u8]) -> Result<usize, HttpError> {
    let size_end = bytes
        .iter()
        .position(|byte| *byte == b';')
        .unwrap_or(bytes.len());
    let size = &bytes[..size_end];
    if size.is_empty() || size.len() > 16 {
        return Err(HttpError::Malformed);
    }
    let length = size.iter().try_fold(0_usize, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(HttpError::Malformed),
        };
        value
            .checked_mul(16)
            .and_then(|value| value.checked_add(usize::from(digit)))
            .ok_or(HttpError::Limit)
    })?;
    chunk_extensions(&bytes[size_end..])?;
    Ok(length)
}

fn chunk_extensions(mut bytes: &[u8]) -> Result<(), HttpError> {
    while !bytes.is_empty() {
        bytes = bytes.strip_prefix(b";").ok_or(HttpError::Malformed)?;
        let end = bytes
            .iter()
            .position(|byte| matches!(byte, b'=' | b';'))
            .unwrap_or(bytes.len());
        if !token(&bytes[..end]) {
            return Err(HttpError::Malformed);
        }
        bytes = &bytes[end..];
        if bytes.starts_with(b"=") {
            bytes = &bytes[1..];
            if bytes.starts_with(b"\"") {
                bytes = &bytes[1..];
                loop {
                    let Some((&byte, rest)) = bytes.split_first() else {
                        return Err(HttpError::Malformed);
                    };
                    bytes = rest;
                    if byte == b'"' {
                        break;
                    }
                    if byte == b'\\' {
                        let Some((&escaped, rest)) = bytes.split_first() else {
                            return Err(HttpError::Malformed);
                        };
                        if !(32..=126).contains(&escaped) {
                            return Err(HttpError::Malformed);
                        }
                        bytes = rest;
                    } else if !(32..=126).contains(&byte) {
                        return Err(HttpError::Malformed);
                    }
                }
            } else {
                let end = bytes
                    .iter()
                    .position(|byte| *byte == b';')
                    .unwrap_or(bytes.len());
                if !token(&bytes[..end]) {
                    return Err(HttpError::Malformed);
                }
                bytes = &bytes[end..];
            }
        }
    }
    Ok(())
}

fn parse_trailers(bytes: &[u8]) -> Result<(), HttpError> {
    if bytes == b"\r\n" {
        return Ok(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| HttpError::Malformed)?;
    let block = text.strip_suffix("\r\n\r\n").ok_or(HttpError::Malformed)?;
    for (index, line) in block.split("\r\n").enumerate() {
        if index >= 64 {
            return Err(HttpError::Limit);
        }
        let (name, _) = field(line)?;
        if [
            "content-length",
            "transfer-encoding",
            "content-type",
            "content-encoding",
            "host",
            "connection",
            "trailer",
            "authorization",
            "www-authenticate",
            "proxy-authenticate",
            "proxy-authorization",
            "authentication-info",
            "location",
        ]
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
        {
            return Err(HttpError::Malformed);
        }
    }
    Ok(())
}
