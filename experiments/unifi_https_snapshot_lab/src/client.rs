#![forbid(unsafe_code)]
//! Isolated, already-handshaken rustls client over Asupersync 0.5 I/O.
//!
//! This is an interoperability experiment, not an admitted TLS boundary. The
//! selected provider uses ambient entropy; this module does not authenticate
//! a camera, supervise transport shutdown, or qualify a cryptographic provider.
//! The caller has completed and independently bounded the handshake.

use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use rustls::ClientConnection;
use std::{
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

const MAX_STEPS: usize = 32;
const MAX_PLAINTEXT: usize = 16 * 1024;
const TLS_BUFFER: usize = 64 * 1024;

struct Reader<'a, 'b, IO> {
    io: &'a mut IO,
    cx: &'a mut Context<'b>,
}
impl<IO: AsyncRead + Unpin> Read for Reader<'_, '_, IO> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let mut buffer = ReadBuf::new(output);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut buffer) {
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Ready(Ok(())) => Ok(buffer.filled().len()),
        }
    }
}
struct Writer<'a, 'b, IO> {
    io: &'a mut IO,
    cx: &'a mut Context<'b>,
}
impl<IO: AsyncWrite + Unpin> Write for Writer<'_, '_, IO> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, data) {
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
            Poll::Ready(result) => result,
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.io).poll_flush(self.cx) {
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
            Poll::Ready(result) => result,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Open,
    Closing,
    Failed,
    Closed,
}

/// A single already-handshaken owned TLS client connection; its underlying I/O must be task-metered.
pub struct Client<IO> {
    tls: ClientConnection,
    io: IO,
    state: State,
}
impl<IO> Client<IO> {
    /// Wrap a completed client handshake and owned transport.
    pub fn new(mut tls: ClientConnection, io: IO) -> Self {
        tls.set_buffer_limit(Some(TLS_BUFFER));
        Self {
            tls,
            io,
            state: State::Open,
        }
    }
    fn failure(&mut self, error: io::Error) -> io::Error {
        self.state = State::Failed;
        error
    }
}
impl<IO: AsyncRead + AsyncWrite + Unpin> Client<IO> {
    fn write_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let result = self.tls.write_tls(&mut Writer {
            io: &mut self.io,
            cx,
        });
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            other => Poll::Ready(other),
        }
    }
    fn read_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let result = self.tls.read_tls(&mut Reader {
            io: &mut self.io,
            cx,
        });
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            other => Poll::Ready(other),
        }
    }
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for _ in 0..MAX_STEPS {
            if !self.tls.wants_write() {
                return match Pin::new(&mut self.io).poll_flush(cx) {
                    Poll::Ready(Err(error)) => Poll::Ready(Err(self.failure(error))),
                    other => other,
                };
            }
            match self.write_tls(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(self.failure(error))),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(self.failure(io::ErrorKind::WriteZero.into())));
                }
                Poll::Ready(Ok(_)) => (),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for Client<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.state != State::Open {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TLS stream not open",
            )));
        }
        for _ in 0..MAX_STEPS {
            match self.tls.reader().read(output.unfilled()) {
                Ok(n) => {
                    output.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                Err(error) => return Poll::Ready(Err(self.failure(error))),
            }
            match self.read_tls(cx) {
                Poll::Pending => {
                    if self.tls.wants_write() {
                        if let Poll::Ready(Err(error)) = self.poll_drain(cx) {
                            return Poll::Ready(Err(error));
                        }
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(self.failure(error))),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(self.failure(io::ErrorKind::UnexpectedEof.into())));
                }
                Poll::Ready(Ok(_)) => {
                    if self.tls.process_new_packets().is_err() {
                        return Poll::Ready(Err(self.failure(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "TLS record rejected",
                        ))));
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Client<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.state != State::Open {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TLS stream not open",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => (),
        }
        match self
            .tls
            .writer()
            .write(&input[..input.len().min(MAX_PLAINTEXT)])
        {
            Ok(0) => Poll::Ready(Err(self.failure(io::ErrorKind::WriteZero.into()))),
            Ok(n) => Poll::Ready(Ok(n)),
            Err(error) => Poll::Ready(Err(self.failure(error))),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !matches!(self.state, State::Open | State::Closing) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TLS stream not open",
            )));
        }
        self.poll_drain(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Open => {
                self.tls.send_close_notify();
                self.state = State::Closing;
            }
            State::Closing => (),
            State::Closed => return Poll::Ready(Ok(())),
            _ => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "TLS stream not open",
                )));
            }
        }
        match self.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => (),
        }
        match Pin::new(&mut self.io).poll_shutdown(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.failure(error))),
            Poll::Ready(Ok(())) => {
                self.state = State::Closed;
                Poll::Ready(Ok(()))
            }
        }
    }
}
