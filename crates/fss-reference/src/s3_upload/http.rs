#![forbid(unsafe_code)]
//! One owned socket and Asupersync's bounded HTTP/1 codec. The synchronous
//! MultipartTransport contract cannot spawn detached work. Every socket and
//! caller-clock boundary rechecks the same admitted child and finite deadline.

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use asupersync::{
    bytes::BytesMut,
    codec::Decoder,
    http::h1::{Http1Client, Http1ClientCodec, Request, Response},
    io::{AsyncRead, AsyncWrite, ReadBuf},
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
        self.optional_header(name)?.ok_or(S3Error::Protocol)
    }

    pub(super) fn optional_header(&self, name: &str) -> Result<Option<&str>, S3Error> {
        let mut values = self
            .0
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str());
        let value = values.next();
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

/// The same wire codec serves separately owned upload and media-read contexts.
/// Implementations must revalidate their real authority before reading a clock
/// and again after it, and must preserve the latest observed time on refusal.
pub(super) trait Boundary {
    fn checkpoint(&mut self) -> Result<TimestampNs, S3Error>;
    fn deadline(&self) -> Result<Option<TimestampNs>, S3Error>;
}

struct UploadBoundary<'a, 'call, C> {
    endpoint: &'a S3Endpoint,
    clock: &'a mut C,
    cx: &'a mut TransportCx<'call>,
}
impl<C: S3Clock> Boundary for UploadBoundary<'_, '_, C> {
    fn checkpoint(&mut self) -> Result<TimestampNs, S3Error> {
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
        Ok(now)
    }

    fn deadline(&self) -> Result<Option<TimestampNs>, S3Error> {
        self.cx.deadline().map_err(|_| S3Error::Authority)
    }
}

struct Gate<'a, B> {
    owner: &'a mut B,
    deadline: TimestampNs,
    remaining: u64,
}
impl<B: Boundary> Gate<'_, B> {
    fn boundary(&mut self) -> Result<TimestampNs, S3Error> {
        if self.remaining == 0 {
            return Err(S3Error::Limit);
        }
        self.remaining -= 1;
        let now = self.owner.checkpoint()?;
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

/// An already bounded, complete response header, with no external I/O. The
/// pinned Http1ClientCodec does not remember request methods; the pinned
/// Http1Client does, and therefore correctly ignores a HEAD Content-Length.
/// Its request encoder writes only a fixed, secret-free HEAD into this sink.
/// Every method is immediately Ready, so parsing uses exactly one poll and no
/// executor, task, socket, timer or alternate ownership tree.
struct HeadInput<'a>(&'a [u8]);
impl AsyncRead for HeadInput<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let count = self.0.len().min(out.remaining());
        out.put_slice(&self.0[..count]);
        self.0 = &self.0[count..];
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for HeadInput<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn decode_head(input: &mut BytesMut, limits: S3Limits) -> Result<Option<Reply>, S3Error> {
    let Some(end) = input.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        return if input.len() > limits.header_bytes {
            Err(S3Error::Limit)
        } else {
            Ok(None)
        };
    };
    let end = end.checked_add(4).ok_or(S3Error::Limit)?;
    if end > limits.header_bytes {
        return Err(S3Error::Limit);
    }
    let head = Buffer(input.split_to(end));

    // Informational responses are independently framed and validated by the
    // existing codec. The method-aware convenience API consumes them internally,
    // so it cannot return one isolated informational header by itself.
    let mut interim_input = Buffer(BytesMut::from(head.0.as_ref()));
    let mut interim_codec = Http1ClientCodec::new()
        .max_headers_size(limits.header_bytes)
        .max_body_size(0)
        .max_trailers_size(limits.header_bytes);
    if let Ok(Some(response)) = interim_codec.decode(&mut interim_input.0) {
        let response = Reply(response);
        if response.0.status < 200 {
            validate_reply(&response)?;
            return Ok(Some(response));
        }
    }

    let mut parsing = std::pin::pin!(Http1Client::request_with_io_and_max_body_size(
        HeadInput(head.0.as_ref()),
        Request::head("/").build(),
        0,
    ));
    let mut context = Context::from_waker(Waker::noop());
    let (response, remaining, _) = match parsing.as_mut().poll(&mut context) {
        Poll::Ready(Ok(result)) => result,
        Poll::Ready(Err(_)) | Poll::Pending => return Err(S3Error::Protocol),
    };
    let response = Reply(response);
    validate_reply(&response)?;
    if !remaining.0.is_empty()
        || !response.0.body.is_empty()
        || !response.0.trailers.is_empty()
        || response.optional_header("transfer-encoding")?.is_some()
    {
        return Err(S3Error::Protocol);
    }
    if let Some(length) = response.optional_header("content-length")? {
        if length.is_empty()
            || !length.bytes().all(|byte| byte.is_ascii_digit())
            || length.parse::<u64>().is_err()
        {
            return Err(S3Error::Protocol);
        }
    }
    Ok(Some(response))
}

pub(super) fn exchange<C: S3Clock>(
    endpoint: &S3Endpoint,
    limits: S3Limits,
    clock: &mut C,
    cx: &mut TransportCx<'_>,
    admitted_at: TimestampNs,
    head: &[u8],
    body: &[u8],
    head_response: bool,
) -> Result<Reply, S3Error> {
    let mut owner = UploadBoundary {
        endpoint,
        clock,
        cx,
    };
    exchange_with_boundary(
        endpoint,
        limits,
        &mut owner,
        admitted_at,
        head,
        body,
        head_response,
    )
}

pub(super) fn exchange_with_boundary<B: Boundary>(
    endpoint: &S3Endpoint,
    limits: S3Limits,
    owner: &mut B,
    admitted_at: TimestampNs,
    head: &[u8],
    body: &[u8],
    head_response: bool,
) -> Result<Reply, S3Error> {
    let mut deadline = TimestampNs(
        admitted_at
            .0
            .checked_add(i128::from(limits.exchange_timeout_ns))
            .ok_or(S3Error::Clock)?,
    );
    if let Some(owner_deadline) = owner.deadline()? {
        deadline = deadline.min(owner_deadline);
    }
    let mut gate = Gate {
        owner,
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
        loop {
            let response = if head_response {
                decode_head(&mut buffer.0, limits)?
            } else {
                codec
                    .decode(&mut buffer.0)
                    .map_err(|_| S3Error::Protocol)?
                    .map(Reply)
            };
            let Some(response) = response else {
                break;
            };
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
                if head_response {
                    return Err(S3Error::Protocol);
                }
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

    #[test]
    fn head_length_is_representation_metadata_and_interim_headers_stay_separate() {
        let limits = S3Limits::default();
        let mut bytes = BytesMut::from(
            b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5497558138880\r\nETag: opaque\r\n\r\n".as_slice(),
        );
        let interim = decode_head(&mut bytes, limits).unwrap().unwrap();
        assert_eq!(interim.0.status, 103);
        let response = decode_head(&mut bytes, limits).unwrap().unwrap();
        assert_eq!(response.0.status, 200);
        assert_eq!(
            response.unique_header("content-length").unwrap(),
            "5497558138880"
        );
        assert!(response.0.body.is_empty());
        assert!(bytes.is_empty());
    }

    #[test]
    fn head_rejects_ambiguous_framing_and_bounds_before_parsing() {
        let limits = S3Limits::default();
        for header in [
            "Content-Length: 3\r\nContent-Length: 3\r\n",
            "Content-Length: +3\r\n",
            "Content-Length: 18446744073709551616\r\n",
            "Content-Length: 3\r\nTransfer-Encoding: chunked\r\n",
            "Bad Header: value\r\n",
        ] {
            let mut bytes = BytesMut::from(format!("HTTP/1.1 200 OK\r\n{header}\r\n").as_bytes());
            assert!(decode_head(&mut bytes, limits).is_err(), "{header}");
        }
        let mut bytes = BytesMut::from(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n".as_slice());
        assert!(decode_head(&mut bytes, limits).unwrap().is_none());
        bytes.extend_from_slice(b"\r\n");
        assert!(decode_head(&mut bytes, limits).unwrap().is_some());
        let mut oversized = BytesMut::from(vec![b'a'; limits.header_bytes + 1].as_slice());
        assert!(matches!(
            decode_head(&mut oversized, limits),
            Err(S3Error::Limit)
        ));
    }
}
