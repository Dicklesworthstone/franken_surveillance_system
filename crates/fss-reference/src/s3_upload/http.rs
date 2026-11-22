#![forbid(unsafe_code)]
//! One owned socket and Asupersync's bounded HTTP/1 codec. The synchronous
//! MultipartTransport contract cannot spawn detached work. Every socket and
//! caller-clock boundary rechecks the same admitted child and finite deadline.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use asupersync::{
    bytes::BytesMut,
    codec::Decoder,
    http::h1::{Http1ClientCodec, Response},
};
use fss_core::{RuntimeGrant, TimestampNs};
use fss_object::multipart::TransportCx;
use zeroize::{Zeroize, Zeroizing};

use super::{S3Clock, S3Endpoint, S3Error, S3Limits};

pub(super) struct Reply(pub(super) Response);
impl Reply {
    pub(super) fn status(&self, expected: u16) -> Result<(), S3Error> {
        if self.0.status != expected {
            return Err(S3Error::Status(self.0.status));
        }
        Ok(())
    }

    pub(super) fn unique_header(&self, name: &str) -> Result<&str, S3Error> {
        let mut values = self
            .0
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str());
        let value = values.next().ok_or(S3Error::Protocol)?;
        if values.next().is_some()
            || self
                .0
                .trailers
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case(name))
        {
            return Err(S3Error::Protocol);
        }
        Ok(value)
    }
}
impl Drop for Reply {
    fn drop(&mut self) {
        self.0.body.zeroize();
        self.0.reason.zeroize();
        for (_, value) in self.0.headers.iter_mut().chain(self.0.trailers.iter_mut()) {
            value.zeroize();
        }
    }
}

struct Buffer(BytesMut);
impl Drop for Buffer {
    fn drop(&mut self) {
        self.0.as_mut().fill(0);
    }
}

struct Gate<'a, 'call, C> {
    endpoint: &'a S3Endpoint,
    clock: &'a mut C,
    cx: &'a mut TransportCx<'call>,
    deadline: TimestampNs,
    remaining: u64,
}
impl<C: S3Clock> Gate<'_, '_, C> {
    fn boundary(&mut self) -> Result<TimestampNs, S3Error> {
        if self.remaining == 0 {
            return Err(S3Error::Limit);
        }
        self.remaining -= 1;
        if self.cx.resource() != self.endpoint.resource() {
            return Err(S3Error::Binding);
        }
        self.cx
            .checkpoint(self.cx.now())
            .map_err(|_| S3Error::Authority)?;
        self.cx
            .authority()
            .require_grant_for(RuntimeGrant::AdapterAuth, self.endpoint.resource())
            .map_err(|_| S3Error::Authority)?;
        let now = self.clock.now(self.cx)?;
        if now < self.cx.now() {
            return Err(S3Error::Clock);
        }
        self.cx.checkpoint(now).map_err(|_| S3Error::Authority)?;
        if now >= self.deadline {
            return Err(S3Error::Deadline);
        }
        Ok(now)
    }

    fn timeout(&mut self, maximum: u64) -> Result<Duration, S3Error> {
        let now = self.boundary()?;
        let remaining = u64::try_from(self.deadline.0 - now.0).map_err(|_| S3Error::Clock)?;
        Ok(Duration::from_nanos(remaining.min(maximum)))
    }

    fn write(
        &mut self,
        socket: &mut TcpStream,
        mut bytes: &[u8],
        maximum: usize,
        timeout_ns: u64,
    ) -> Result<(), S3Error> {
        while !bytes.is_empty() {
            let timeout = self.timeout(timeout_ns)?;
            socket
                .set_write_timeout(Some(timeout))
                .map_err(|_| S3Error::Io)?;
            self.boundary()?;
            let count = bytes.len().min(maximum);
            match socket.write(&bytes[..count]) {
                Ok(0) => return Err(S3Error::Io),
                Ok(written) => bytes = &bytes[written..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(S3Error::Io),
            }
        }
        Ok(())
    }
}

fn validate_reply(response: &Reply) -> Result<(), S3Error> {
    if !(100..=599).contains(&response.0.status) || response.0.status == 101 {
        return Err(S3Error::Protocol);
    }
    // The codec correctly parses framed bodies. Its no-body fast path does not
    // validate these headers, so reject contradictory body framing here too.
    if response.0.status < 200 || response.0.status == 204 {
        if response
            .0
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        {
            return Err(S3Error::Protocol);
        }
        let lengths: Vec<_> = response
            .0
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .collect();
        if lengths.len() > 1 || lengths.first().is_some_and(|(_, value)| value != "0") {
            return Err(S3Error::Protocol);
        }
    }
    Ok(())
}

pub(super) fn exchange<C: S3Clock>(
    endpoint: &S3Endpoint,
    limits: S3Limits,
    clock: &mut C,
    cx: &mut TransportCx<'_>,
    admitted_at: TimestampNs,
    head: &[u8],
    body: &[u8],
) -> Result<Reply, S3Error> {
    let mut deadline = TimestampNs(
        admitted_at
            .0
            .checked_add(i128::from(limits.exchange_timeout_ns))
            .ok_or(S3Error::Clock)?,
    );
    if let Some(owner_deadline) = cx.deadline().map_err(|_| S3Error::Authority)? {
        deadline = deadline.min(owner_deadline);
    }
    let mut gate = Gate {
        endpoint,
        clock,
        cx,
        deadline,
        remaining: limits.io_calls,
    };
    let timeout = gate.timeout(limits.connect_timeout_ns)?;
    let mut socket =
        TcpStream::connect_timeout(&endpoint.peer, timeout).map_err(|_| S3Error::Io)?;
    gate.write(&mut socket, head, limits.io_bytes, limits.io_timeout_ns)?;
    gate.write(&mut socket, body, limits.io_bytes, limits.io_timeout_ns)?;

    let mut codec = Http1ClientCodec::new()
        .max_headers_size(limits.header_bytes)
        .max_body_size(limits.response_bytes)
        .max_trailers_size(limits.header_bytes);
    let mut buffer = Buffer(BytesMut::new());
    let mut input = Zeroizing::new(vec![0_u8; limits.io_bytes]);
    let mut total = 0_usize;
    let mut interim = 0_u8;
    loop {
        while let Some(response) = codec.decode(&mut buffer.0).map_err(|_| S3Error::Protocol)? {
            let response = Reply(response);
            validate_reply(&response)?;
            if response.0.status < 200 {
                interim += 1;
                if interim > 8 {
                    return Err(S3Error::Limit);
                }
            } else {
                if !buffer.0.is_empty() {
                    return Err(S3Error::Protocol);
                }
                gate.boundary()?;
                return Ok(response);
            }
        }
        let timeout = gate.timeout(limits.io_timeout_ns)?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|_| S3Error::Io)?;
        gate.boundary()?;
        let capacity = limits.io_bytes.min(limits.wire_bytes.saturating_sub(total));
        if capacity == 0 {
            return Err(S3Error::Limit);
        }
        match socket.read(&mut input[..capacity]) {
            Ok(0) => {
                let response = Reply(
                    codec
                        .decode_eof(&mut buffer.0)
                        .map_err(|_| S3Error::Protocol)?
                        .ok_or(S3Error::Protocol)?,
                );
                validate_reply(&response)?;
                if response.0.status < 200 || !buffer.0.is_empty() {
                    return Err(S3Error::Protocol);
                }
                gate.boundary()?;
                return Ok(response);
            }
            Ok(read) => {
                total = total.checked_add(read).ok_or(S3Error::Limit)?;
                buffer.0.extend_from_slice(&input[..read]);
                input[..read].fill(0);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(S3Error::Io),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn ambiguous_bodyless_and_duplicate_integrity_headers_refuse() {
        let response =
            Reply(Response::new(204, "No Content", vec![]).with_header("Content-Length", "1"));
        assert_eq!(validate_reply(&response), Err(S3Error::Protocol));
        let response = Reply(
            Response::new(200, "OK", vec![])
                .with_header("ETag", "a")
                .with_header("etag", "b"),
        );
        assert_eq!(response.unique_header("etag"), Err(S3Error::Protocol));
        let response = Reply(
            Response::new(200, "OK", vec![])
                .with_header("ETag", "a")
                .with_trailer("etag", "b"),
        );
        assert_eq!(response.unique_header("etag"), Err(S3Error::Protocol));
    }
}
