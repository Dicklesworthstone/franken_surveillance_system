#![forbid(unsafe_code)]
//! Experimental bridge from FSS fleet routes to task-owned TLS. Not admitted.

use crate::owned::Session;
use asupersync::Cx;
use fss_reference::unifi_direct::{controller_acceptor::Transport, controller_listener::Routed};
use fss_runtime::execution::TaskCx;
use rustls::ServerConfig;
use std::{future::Future, io, pin::Pin, sync::Arc};

/// Caller-owned resources and configuration live at least as long as each route.
/// Resources must be taken from the independently authorized fleet inventory;
/// a claimed address or MAC does not authenticate a physical camera.
#[derive(Clone)]
pub struct FleetTls<'scope, 'task> {
    config: Arc<ServerConfig>,
    task: &'scope TaskCx<'task>,
    resources: &'scope [String],
    entropy_bytes: usize,
}
impl<'scope, 'task> FleetTls<'scope, 'task> {
    /// Make one bounded fleet transport. Tickets and already-scoped hooks are
    /// refused because this experiment has not qualified their entropy paths.
    pub fn new(
        config: ServerConfig,
        task: &'scope TaskCx<'task>,
        resources: &'scope [String],
        entropy_bytes: usize,
    ) -> io::Result<Self> {
        if config.scoped_random.is_some()
            || config.scoped_kx.is_some()
            || config.send_tls13_tickets != 0
            || resources.is_empty()
            || resources.len() > 128
            || !(64..=4096).contains(&entropy_bytes)
            || resources
                .iter()
                .any(|resource| resource.is_empty() || resource.len() > 1024)
            || resources
                .iter()
                .enumerate()
                .any(|(index, resource)| resources[..index].contains(resource))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            config: Arc::new(config),
            task,
            resources,
            entropy_bytes,
        })
    }
}
impl<'scope, 'task, 'policy> Transport<'scope, 'task, 'policy> for FleetTls<'scope, 'task>
where
    'task: 'scope,
    'policy: 'scope,
{
    type Stream = Session<'scope, 'task, Routed<'scope, 'task, 'policy>>;
    type Handshake = Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + 'scope>>;

    fn handshake(&self, cx: &'scope Cx, route: Routed<'scope, 'task, 'policy>) -> Self::Handshake {
        let task = self.task;
        let resources = self.resources;
        let clock = route.clock();
        let admitted_resource = resources
            .iter()
            .find(|resource| resource.as_str() == route.resource())
            .map(String::as_str);
        let same_context = route.matches_context(cx) && clock.matches(task, cx);
        let config = self.config.clone();
        let entropy_bytes = self.entropy_bytes;
        Box::pin(async move {
            if !same_context {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let resource = admitted_resource.ok_or(io::ErrorKind::PermissionDenied)?;
            Session::accept(
                (*config).clone(),
                route,
                task,
                cx,
                clock,
                resource,
                entropy_bytes,
            )
            .await
        })
    }
}
