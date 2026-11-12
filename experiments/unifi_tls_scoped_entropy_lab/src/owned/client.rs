#![forbid(unsafe_code)]
//! Experimental scoped-entropy TLS client. Not admitted for real cameras.
use super::{Pool, admitted};
use crate::client_handshake::Client;
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite, ReadBuf},
};
use fss_core::BudgetVector;
use fss_reference::unifi_direct::metered::MeteredClock;
use fss_runtime::execution::TaskCx;
use rustls::{
    ClientConfig, ClientConnection, NamedGroup,
    crypto::{ActiveKeyExchange, ScopedClientKx, SecureRandom, SharedSecret},
    pki_types::ServerName,
};
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
const MAX_READ: usize = 16 * 1024;
#[derive(Debug)]
pub(super) struct ScopedGroups;
struct Exchange {
    secret: StaticSecret,
    public: [u8; 32],
}
struct P256Exchange {
    secret: p256::SecretKey,
    public: Vec<u8>,
}
impl ScopedClientKx for ScopedGroups {
    fn start(
        &self,
        group: NamedGroup,
        random: &dyn SecureRandom,
    ) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        if group == NamedGroup::secp256r1 {
            use p256::elliptic_curve::sec1::ToSec1Point;
            for _ in 0..16 {
                let mut bytes = Zeroizing::new([0u8; 32]);
                random
                    .fill(&mut *bytes)
                    .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
                if let Ok(secret) = p256::SecretKey::from_slice(&*bytes) {
                    let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
                    return Ok(Box::new(P256Exchange { secret, public }));
                }
            }
            return Err(rustls::Error::FailedToGetRandomBytes);
        }
        if group != NamedGroup::X25519 {
            return Err(rustls::Error::General("unsupported scoped group".into()));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        random
            .fill(&mut *bytes)
            .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let secret = StaticSecret::from(*bytes);
        let public = *PublicKey::from(&secret).as_bytes();
        Ok(Box::new(Exchange { secret, public }))
    }
}
impl ActiveKeyExchange for P256Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        if peer.len() != 65 || peer.first() != Some(&4) {
            return Err(rustls::Error::General("invalid peer".into()));
        }
        let peer = p256::PublicKey::from_sec1_bytes(peer)
            .map_err(|_| rustls::Error::General("invalid peer".into()))?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SharedSecret::from(shared.raw_secret_bytes().as_slice()))
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}
impl ActiveKeyExchange for Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::General("invalid peer".into()))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(rustls::Error::General("invalid shared secret".into()));
        }
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}
/// A non-cloneable connection that owns its distinct entropy lease.
pub struct Session<'scope, 'task, IO> {
    inner: Client<IO>,
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
    /// The caller owns peer identity and certificate/clock authority.
    pub async fn connect(
        config: ClientConfig,
        name: ServerName<'static>,
        io: IO,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &'scope str,
        entropy_bytes: usize,
    ) -> io::Result<Self> {
        if config.scoped_random.is_some() || config.scoped_kx.is_some() || config.enable_early_data
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let entropy = Arc::new(Pool::acquire(task, cx, clock, resource, entropy_bytes)?);
        Self::connect_pool(config, name, io, task, cx, clock, resource, entropy).await
    }
    /// Connect using a previously drained, task-bound entropy lease.
    pub async fn connect_with_lease(
        config: ClientConfig,
        name: ServerName<'static>,
        io: IO,
        lease: super::offload::Lease<'scope, 'task>,
    ) -> io::Result<Self> {
        let (task, cx, clock, resource, entropy) = lease.into_parts()?;
        Self::connect_pool(config, name, io, task, cx, clock, resource, entropy).await
    }
    async fn connect_pool(
        mut config: ClientConfig,
        name: ServerName<'static>,
        io: IO,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &'scope str,
        entropy: Arc<Pool>,
    ) -> io::Result<Self> {
        if config.scoped_random.is_some() || config.scoped_kx.is_some() || config.enable_early_data
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Client sessions in this lab never share or store resumption state.
        config.resumption = rustls::client::Resumption::disabled();
        config.scoped_random = Some(entropy.clone());
        config.scoped_kx = Some(Arc::new(ScopedGroups));
        admitted(task, cx, clock, resource, &BudgetVector::ZERO)?;
        let connection = ClientConnection::new(Arc::new(config), name)
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        admitted(task, cx, clock, resource, &BudgetVector::ZERO)?;
        let mut handshake = Box::pin(Client::new(connection, io).handshake(cx));
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

#[cfg(test)]
mod p256_tests {
    use super::*;

    #[derive(Debug)]
    struct Fixed(u8);
    impl SecureRandom for Fixed {
        fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
            bytes.fill(self.0);
            Ok(())
        }
    }

    #[test]
    fn p256_scoped_exchange_agrees_and_rejects_malformed_peer() {
        let a = ScopedGroups
            .start(NamedGroup::secp256r1, &Fixed(1))
            .unwrap();
        let b = ScopedGroups
            .start(NamedGroup::secp256r1, &Fixed(2))
            .unwrap();
        let a_public = a.pub_key().to_vec();
        let b_public = b.pub_key().to_vec();
        assert_eq!(a_public.len(), 65);
        assert_eq!(a_public[0], 4);
        let a_secret = a.complete(&b_public).unwrap();
        let b_secret = b.complete(&a_public).unwrap();
        assert_eq!(a_secret.secret_bytes(), b_secret.secret_bytes());
        for peer in [vec![], vec![0; 65], vec![4; 65]] {
            let exchange = ScopedGroups
                .start(NamedGroup::secp256r1, &Fixed(1))
                .unwrap();
            assert!(exchange.complete(&peer).is_err());
        }
        assert!(
            ScopedGroups
                .start(NamedGroup::secp256r1, &Fixed(0))
                .is_err()
        );
    }
}
