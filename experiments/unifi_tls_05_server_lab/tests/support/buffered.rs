#![forbid(unsafe_code)]
//! Fixture transport that requires a flush before a full buffer can advance.

use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::{
    cell::Cell,
    io,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, Waker},
};

pub struct Buffered<IO> {
    inner: IO,
    pending: Vec<u8>,
    offset: usize,
    limit: usize,
    blocked: Rc<Cell<usize>>,
    waiter: Option<Waker>,
}

impl<IO> Buffered<IO> {
    pub fn new(inner: IO, limit: usize, blocked: Rc<Cell<usize>>) -> Self {
        assert!(limit > 0);
        Self {
            inner,
            pending: Vec::with_capacity(limit),
            offset: 0,
            limit,
            blocked,
            waiter: None,
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Buffered<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Buffered<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending.len() == self.limit {
            self.blocked.set(self.blocked.get() + 1);
            self.waiter = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = bytes.len().min(self.limit - self.pending.len());
        self.pending.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.offset < this.pending.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => this.offset += n,
            }
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let progressed = !this.pending.is_empty();
                this.pending.clear();
                this.offset = 0;
                if progressed {
                    if let Some(waiter) = this.waiter.take() {
                        waiter.wake();
                    }
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}
