#![forbid(unsafe_code)]
//! Experimental task-bound TLS 1.3 entropy owner. Not a production boundary.

use crate::server::Server;
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite, ReadBuf},
};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_reference::unifi_direct::metered::MeteredClock;
use fss_runtime::execution::TaskCx;
use rustls::{
    NamedGroup, ServerConfig, ServerConnection,
    crypto::{CompletedKeyExchange, GetRandomFailed, ScopedClientKx, ScopedServerKx, SecureRandom},
};
use std::{
    fmt,
    fs::OpenOptions,
    future::{Future, poll_fn},
    io::{self, Read},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_ENTROPY: usize = 4096;
const MAX_READ: usize = 16 * 1024;
const O_NOFOLLOW: i32 = 0x20000;
const O_CLOEXEC: i32 = 0x80000;

pub(crate) fn admitted<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    resource: &str,
    cost: &BudgetVector,
) -> io::Result<()> {
    if !clock.matches(task, cx) || resource.is_empty() || resource.len() > 1024 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    cx.checkpoint().map_err(|_| io::ErrorKind::Interrupted)?;
    let now = clock.now()?;
    task.checkpoint_for(RuntimeGrant::AdapterAuth, resource, now, cost)
        .map_err(|_| io::ErrorKind::PermissionDenied)?;
    cx.checkpoint().map_err(|_| io::ErrorKind::Interrupted)?;
    Ok(())
}

struct Pool {
    cx: Cx,
    data: Vec<AtomicU8>,
    cursor: AtomicUsize,
    live: AtomicBool,
}
impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskEntropy").finish_non_exhaustive()
    }
}
impl Pool {
    fn acquire<'task>(
        task: &TaskCx<'task>,
        cx: &Cx,
        clock: MeteredClock<'_, 'task>,
        resource: &str,
        len: usize,
    ) -> io::Result<Self> {
        if !(1..=MAX_ENTROPY).contains(&len) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut cost = BudgetVector::ZERO;
        cost.bytes = len as u64;
        admitted(task, cx, clock, resource, &cost)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        bytes.resize(len, 0);
        let mut bytes = Zeroizing::new(bytes);
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open("/dev/urandom")?;
        admitted(task, cx, clock, resource, &BudgetVector::ZERO)?;
        let metadata = source.metadata()?;
        if !metadata.file_type().is_char_device() || metadata.rdev() != 0x109 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut offset = 0;
        for _ in 0..16 {
            admitted(task, cx, clock, resource, &BudgetVector::ZERO)?;
            let result = source.read(&mut bytes[offset..]);
            admitted(task, cx, clock, resource, &BudgetVector::ZERO)?;
            match result {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    offset += n;
                    if offset == len {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
                Err(e) => return Err(e),
            }
        }
        if offset != len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Self::from_bytes(cx, bytes)
    }
    fn from_bytes(cx: &Cx, bytes: Zeroizing<Vec<u8>>) -> io::Result<Self> {
        let mut data = Vec::new();
        data.try_reserve_exact(bytes.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        data.extend(bytes.iter().copied().map(AtomicU8::new));
        Ok(Self {
            cx: cx.clone(),
            data,
            cursor: AtomicUsize::new(0),
            live: AtomicBool::new(true),
        })
    }
    fn close(&self) {
        self.live.store(false, Ordering::SeqCst);
        for byte in &self.data {
            byte.store(0, Ordering::SeqCst);
        }
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.close();
    }
}
impl SecureRandom for Pool {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        output.zeroize();
        if !self.live.load(Ordering::SeqCst) || self.cx.checkpoint().is_err() {
            self.close();
            return Err(GetRandomFailed);
        }
        let start = match self
            .cursor
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |start| {
                start
                    .checked_add(output.len())
                    .filter(|end| *end <= self.data.len())
            }) {
            Ok(start) => start,
            Err(_) => {
                self.close();
                return Err(GetRandomFailed);
            }
        };
        let end = start + output.len();
        for (dest, byte) in output.iter_mut().zip(&self.data[start..end]) {
            *dest = byte.swap(0, Ordering::SeqCst);
        }
        if !self.live.load(Ordering::SeqCst) || self.cx.checkpoint().is_err() {
            output.zeroize();
            self.close();
            return Err(GetRandomFailed);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ServerGroups;
impl ScopedServerKx for ServerGroups {
    fn start_and_complete(
        &self,
        group: NamedGroup,
        peer: &[u8],
        random: &dyn SecureRandom,
    ) -> Result<CompletedKeyExchange, rustls::Error> {
        match group {
            NamedGroup::X25519 if peer.len() == 32 => (),
            NamedGroup::secp256r1 if peer.len() == 65 && peer.first() == Some(&4) => {
                p256::PublicKey::from_sec1_bytes(peer)
                    .map_err(|_| rustls::Error::General("invalid peer".into()))?;
            }
            NamedGroup::X25519 | NamedGroup::secp256r1 => {
                return Err(rustls::Error::General("invalid peer".into()));
            }
            _ => return Err(rustls::Error::General("unsupported scoped group".into())),
        }
        let exchange = client::ScopedGroups.start(group, random)?;
        let pub_key = exchange.pub_key().to_vec();
        let secret = exchange.complete(peer)?;
        Ok(CompletedKeyExchange {
            group,
            pub_key,
            secret,
        })
    }
}

/// A non-cloneable connection that owns its distinct entropy lease.
pub struct Session<'scope, 'task, IO> {
    inner: Server<IO>,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    resource: &'scope str,
    entropy: Arc<Pool>,
}
impl<IO> Drop for Session<'_, '_, IO> {
    fn drop(&mut self) {
        self.entropy.close();
    }
}
impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Session<'scope, 'task, IO> {
    /// Consume a configuration and task-owned transport; callers bound the deadline.
    pub async fn accept(
        config: ServerConfig,
        io: IO,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &'scope str,
        entropy_bytes: usize,
    ) -> io::Result<Self> {
        if config.scoped_random.is_some() || config.scoped_kx.is_some() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let entropy = Arc::new(Pool::acquire(task, cx, clock, resource, entropy_bytes)?);
        Self::accept_pool(config, io, task, cx, clock, resource, entropy).await
    }
    /// Accept using a previously drained, task-bound entropy lease.
    pub async fn accept_with_lease(
        config: ServerConfig,
        io: IO,
        lease: offload::Lease<'scope, 'task>,
    ) -> io::Result<Self> {
        let (task, cx, clock, resource, entropy) = lease.into_parts()?;
        Self::accept_pool(config, io, task, cx, clock, resource, entropy).await
    }
    async fn accept_pool(
        mut config: ServerConfig,
        io: IO,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &'scope str,
        entropy: Arc<Pool>,
    ) -> io::Result<Self> {
        if config.scoped_random.is_some() || config.scoped_kx.is_some() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        admitted(task, cx, clock, resource, &BudgetVector::ZERO)?;
        config.scoped_random = Some(entropy.clone());
        config.scoped_kx = Some(Arc::new(ServerGroups));
        let connection =
            ServerConnection::new(Arc::new(config)).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut handshake = Box::pin(Server::new(connection, io).handshake(cx));
        let result = poll_fn(|context| {
            if let Err(error) = admitted(task, cx, clock, resource, &BudgetVector::ZERO) {
                return Poll::Ready(Err(error));
            }
            match handshake.as_mut().poll(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(server)) => {
                    match admitted(task, cx, clock, resource, &BudgetVector::ZERO) {
                        Ok(()) => Poll::Ready(Ok(server)),
                        Err(error) => Poll::Ready(Err(error)),
                    }
                }
            }
        })
        .await;
        match result {
            Ok(inner) => Ok(Self {
                inner,
                task,
                cx,
                clock,
                resource,
                entropy,
            }),
            Err(error) => {
                entropy.close();
                Err(error)
            }
        }
    }
    /// Irreversibly fence this session and erase its remaining entropy.
    pub fn request_stop(&mut self) {
        self.entropy.close();
    }
    fn check(&self) -> io::Result<()> {
        if !self.entropy.live.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        admitted(
            self.task,
            self.cx,
            self.clock,
            self.resource,
            &BudgetVector::ZERO,
        )
    }
    fn fence(&self) {
        self.entropy.close();
    }
}
impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for Session<'_, '_, IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.check() {
            self.fence();
            return Poll::Ready(Err(error));
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut bytes = Zeroizing::new([0u8; MAX_READ]);
        let mut tmp = ReadBuf::new(&mut bytes[..output.remaining().min(MAX_READ)]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp) {
            Poll::Ready(Ok(())) => {
                if let Err(error) = self.check() {
                    self.fence();
                    return Poll::Ready(Err(error));
                }
                output.put_slice(tmp.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Session<'_, '_, IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.check() {
            self.fence();
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut self.inner).poll_write(cx, input);
        if let Err(error) = self.check() {
            self.fence();
            return Poll::Ready(Err(error));
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check() {
            self.fence();
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if let Err(error) = self.check() {
            self.fence();
            return Poll::Ready(Err(error));
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check() {
            self.fence();
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        if let Err(error) = self.check() {
            self.fence();
            return Poll::Ready(Err(error));
        }
        result
    }
}

/// Task-bound client side of the experimental TLS boundary.
pub mod client;
/// Explicitly owned and drainable blocking-pool entropy acquisition.
pub mod offload;

#[cfg(test)]
mod entropy_tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn fixture(cx: Cx, input: &[u8]) -> Arc<Pool> {
        Arc::new(Pool {
            cx,
            data: input.iter().copied().map(AtomicU8::new).collect(),
            cursor: AtomicUsize::new(0),
            live: AtomicBool::new(true),
        })
    }
    fn erased(pool: &Pool) -> bool {
        pool.data
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
    }
    fn run(test: impl FnOnce(Cx)) {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                test(Cx::current().unwrap());
            });
    }
    #[test]
    fn p256_server_agrees_and_refuses_bad_points_before_entropy() {
        run(|cx| {
            let client_rng = fixture(cx.clone(), &[1; 64]);
            let server_rng = fixture(cx, &[2; 64]);
            for peer in [&[][..], &[0; 65][..], &[4; 65][..]] {
                assert!(
                    ServerGroups
                        .start_and_complete(NamedGroup::secp256r1, peer, server_rng.as_ref())
                        .is_err()
                );
                assert_eq!(server_rng.cursor.load(Ordering::SeqCst), 0);
            }
            assert!(
                ServerGroups
                    .start_and_complete(NamedGroup::X25519, &[0; 31], server_rng.as_ref())
                    .is_err()
            );
            assert_eq!(server_rng.cursor.load(Ordering::SeqCst), 0);
            let client = client::ScopedGroups
                .start(NamedGroup::secp256r1, client_rng.as_ref())
                .unwrap();
            let server = ServerGroups
                .start_and_complete(NamedGroup::secp256r1, client.pub_key(), server_rng.as_ref())
                .unwrap();
            let shared = client.complete(&server.pub_key).unwrap();
            assert_eq!(shared.secret_bytes(), server.secret.secret_bytes());
            assert_eq!(server_rng.cursor.load(Ordering::SeqCst), 32);
        });
    }
    #[test]
    fn close_is_idempotent_and_erases_every_byte() {
        run(|cx| {
            let pool = fixture(cx, &[0x5a; 64]);
            let mut used = [0; 16];
            pool.fill(&mut used).unwrap();
            assert_eq!(used, [0x5a; 16]);
            pool.close();
            pool.close();
            assert!(erased(&pool));
            let mut output = [0xa5; 4];
            assert!(pool.fill(&mut output).is_err());
            assert_eq!(output, [0; 4]);
        });
    }
    #[test]
    fn cancellation_fences_and_erases_the_lease() {
        run(|cx| {
            let pool = fixture(cx.clone(), &[0x5a; 64]);
            cx.cancel_fast(asupersync::types::CancelKind::User);
            let mut output = [0xa5; 8];
            assert!(pool.fill(&mut output).is_err());
            assert_eq!(output, [0; 8]);
            assert!(erased(&pool));
        });
    }
    #[test]
    fn exhaustion_fences_and_clears_unused_bytes() {
        run(|cx| {
            let pool = fixture(cx, &[0x5a; 16]);
            let mut output = [0xa5; 17];
            assert!(pool.fill(&mut output).is_err());
            assert_eq!(output, [0; 17]);
            assert!(erased(&pool));
            let mut later = [0xa5; 1];
            assert!(pool.fill(&mut later).is_err());
            assert_eq!(later, [0; 1]);
        });
    }
    #[test]
    fn concurrent_fills_claim_disjoint_bytes() {
        run(|cx| {
            let input: Vec<_> = (0u8..64).collect();
            let pool = fixture(cx, &input);
            let gate = Arc::new(Barrier::new(3));
            let (a, b) = std::thread::scope(|scope| {
                let first = pool.clone();
                let first_gate = gate.clone();
                let a = scope.spawn(move || {
                    let mut out = [0; 32];
                    first_gate.wait();
                    first.fill(&mut out).unwrap();
                    out
                });
                let second = pool.clone();
                let second_gate = gate.clone();
                let b = scope.spawn(move || {
                    let mut out = [0; 32];
                    second_gate.wait();
                    second.fill(&mut out).unwrap();
                    out
                });
                gate.wait();
                (a.join().unwrap(), b.join().unwrap())
            });
            let mut combined = [a.as_slice(), b.as_slice()].concat();
            combined.sort_unstable();
            assert_eq!(combined, input);
            assert!(erased(&pool));
        });
    }
    #[test]
    fn concurrent_close_leaves_no_bytes_or_partial_success() {
        run(|cx| {
            for _ in 0..128 {
                let pool = fixture(cx.clone(), &[0x5a; 64]);
                let gate = Arc::new(Barrier::new(2));
                let (result, output) = std::thread::scope(|scope| {
                    let other = pool.clone();
                    let ready = gate.clone();
                    let worker = scope.spawn(move || {
                        let mut output = [0xa5; 64];
                        ready.wait();
                        let result = other.fill(&mut output);
                        (result, output)
                    });
                    gate.wait();
                    pool.close();
                    worker.join().unwrap()
                });
                if result.is_ok() {
                    assert_eq!(output, [0x5a; 64]);
                } else {
                    assert_eq!(output, [0; 64]);
                }
                assert!(erased(&pool));
                let mut later = [0xa5; 1];
                assert!(pool.fill(&mut later).is_err());
                assert_eq!(later, [0; 1]);
            }
        });
    }
}
