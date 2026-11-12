#![forbid(unsafe_code)]
//! Unqualified laboratory TLS provider for the shared fleet acceptor.

use std::{future::Future, io, pin::Pin, sync::Arc};

use asupersync::Cx;
use fss_reference::unifi_direct::{controller_acceptor::Transport, controller_listener::Routed};
use rustls::{ServerConfig, ServerConnection};

use crate::server::Server;

/// Caller-selected laboratory server configuration, not an admitted provider.
#[derive(Clone)]
pub struct LabTls(pub Arc<ServerConfig>);

impl<'scope, 'task, 'policy> Transport<'scope, 'task, 'policy> for LabTls
where
    'task: 'scope,
    'policy: 'scope,
{
    type Stream = Server<Routed<'scope, 'task, 'policy>>;
    type Handshake = Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + 'scope>>;

    fn handshake(&self, cx: &'scope Cx, route: Routed<'scope, 'task, 'policy>) -> Self::Handshake {
        let config = self.0.clone();
        Box::pin(async move {
            let connection = ServerConnection::new(config)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            Server::new(connection, route).handshake(cx).await
        })
    }
}
