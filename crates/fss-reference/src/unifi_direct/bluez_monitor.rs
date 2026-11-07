#![forbid(unsafe_code)]
//! Task-owned composition of a BlueZ subscription, inventory and scan.
//!
//! The caller must independently admit the bus, adapter and candidate service
//! policy. This owner does not authenticate, adopt or configure a device.
//! Dropping a future can interrupt an active scan; only an acknowledged stop
//! verifies that this connection released its discovery session.

use super::{bluez_bus, bluez_registry};
use asupersync::io::{AsyncRead, AsyncWrite};
use std::{fmt, time::Duration};

const MAX_WAIT: Duration = Duration::from_secs(30);

/// Configuration refused before an active monitor can be returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartError {
    /// Wait durations are zero or exceed the bounded operation profile.
    Configuration,
    /// The bus operation failed, including an uncertain scan-start effect.
    Bus(bluez_bus::Error),
    /// The baseline could not safely seed a device projection.
    Registry(bluez_registry::Error),
}
impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueZ monitor start refused: {self:?}")
    }
}
impl std::error::Error for StartError {}

/// Why an observation epoch ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// The owner requested a stop.
    Stopped,
    /// The transport, scan or policy failed while observing.
    Observation(bluez_bus::Error),
    /// A signal could not be reconciled with the device projection.
    Projection(bluez_registry::Error),
}

/// What was established about the connection's discovery stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stop {
    /// The original BlueZ owner acknowledged the stop on this connection.
    Acknowledged,
    /// A stop was not acknowledged or could not be attempted.
    Uncertain,
}

/// A retired, permanently gapped projection and its scan-stop outcome.
pub struct Retired {
    /// Historical claims. Every retained assessment is now `Gap`.
    pub registry: bluez_registry::Registry,
    /// Why the observation ended.
    pub reason: Reason,
    /// Whether scan cleanup was acknowledged.
    pub stop: Stop,
}
impl fmt::Debug for Retired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Retired")
            .field("registry", &self.registry)
            .field("reason", &self.reason)
            .field("stop", &self.stop)
            .finish()
    }
}

/// A live scan and projection owned together by one task and bus connection.
#[must_use = "an active monitor must be explicitly stopped"]
pub struct Monitor<'scope, 'task, 'policy, IO> {
    scan: bluez_bus::Discovering<'scope, 'task, 'policy, IO>,
    registry: bluez_registry::Registry,
    event_wait: Duration,
    stop_wait: Duration,
}

fn valid_wait(wait: Duration) -> bool {
    !wait.is_zero() && wait <= MAX_WAIT
}

impl<'scope, 'task, 'policy, IO: AsyncRead + AsyncWrite + Unpin>
    Monitor<'scope, 'task, 'policy, IO>
{
    /// Obtain a no-overlap baseline, then start discovery on that same watch.
    /// Candidate services are explicit caller policy; they are not identity.
    pub async fn start(
        watch: bluez_bus::Watch<'scope, 'task, 'policy, IO>,
        adapter: &str,
        candidate_services: &[&str],
        operation_wait: Duration,
        event_wait: Duration,
        stop_wait: Duration,
    ) -> Result<Self, StartError> {
        if !valid_wait(operation_wait) || !valid_wait(event_wait) || !valid_wait(stop_wait) {
            return Err(StartError::Configuration);
        }
        let (watch, inventory) = watch
            .inventory(operation_wait)
            .await
            .map_err(StartError::Bus)?;
        let registry =
            bluez_registry::Registry::new(watch.owner(), adapter, inventory, candidate_services)
                .map_err(StartError::Registry)?;
        let scan = watch
            .start_discovery(adapter, operation_wait)
            .await
            .map_err(StartError::Bus)?;
        Ok(Self {
            scan,
            registry,
            event_wait,
            stop_wait,
        })
    }

    /// Claims through the last processed change. Unread events can make them
    /// stale; separately revalidate identity and authority before any effect.
    pub fn registry(&self) -> &bluez_registry::Registry {
        &self.registry
    }

    /// Observe one change or a bounded idle window. Projection failure attempts
    /// an explicit stop; transport failure retires with cleanup uncertain.
    pub async fn next_change(self) -> Result<(Self, bool), Retired> {
        let Self {
            scan,
            mut registry,
            event_wait,
            stop_wait,
        } = self;
        let (scan, change) = match scan.next_change(event_wait).await {
            Ok(result) => result,
            Err(error) => {
                registry.mark_gap();
                return Err(Retired {
                    registry,
                    reason: Reason::Observation(error),
                    stop: Stop::Uncertain,
                });
            }
        };
        if let Some(change) = change {
            if let Err(error) = registry.apply(&change) {
                registry.mark_gap();
                let stop = if scan.stop(stop_wait).await.is_ok() {
                    Stop::Acknowledged
                } else {
                    Stop::Uncertain
                };
                return Err(Retired {
                    registry,
                    reason: Reason::Projection(error),
                    stop,
                });
            }
            Ok((
                Self {
                    scan,
                    registry,
                    event_wait,
                    stop_wait,
                },
                true,
            ))
        } else {
            Ok((
                Self {
                    scan,
                    registry,
                    event_wait,
                    stop_wait,
                },
                false,
            ))
        }
    }

    /// Stop the scan and retire the projection, regardless of stop outcome.
    pub async fn stop(self) -> Retired {
        let Self {
            scan,
            mut registry,
            stop_wait,
            ..
        } = self;
        let stop = if scan.stop(stop_wait).await.is_ok() {
            Stop::Acknowledged
        } else {
            Stop::Uncertain
        };
        registry.mark_gap();
        Retired {
            registry,
            reason: Reason::Stopped,
            stop,
        }
    }
}
