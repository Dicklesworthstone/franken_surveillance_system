#![forbid(unsafe_code)]
//! Task-owned local D-Bus observation and explicitly admitted BlueZ operations.
//!
//! The caller supplies an already connected, independently admitted local bus
//! stream. An optional read-only snapshot can report untrusted adapter paths.
//! Optional discovery and device-connection operations have external effects;
//! they do not establish Bluetooth identity or configure Wi-Fi. One-shot
//! observations retire the stream; a watch holds it until dropped or retired.

use super::{
    bluez_gatt_management as gatt_management,
    metered::{MeteredClock, MeteredIo},
};
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::timeout_at,
};
use fss_core::{BudgetVector, ContentDigest, OperationId, RuntimeGrant};
use fss_packet::{
    dbus_bluez_signal as signals, dbus_handshake as wire, dbus_object_manager as object_manager,
};
use fss_runtime::{effect::CommittedEffect, execution::TaskCx};
use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

const MAX_WAIT: Duration = Duration::from_secs(30);
const MAX_SIGNALS: usize = 8;
const MAX_AUTH_BYTES: usize = 128;

/// Handshake stage passed to the caller's current policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Authenticate the local Unix peer using the owner-supplied UID.
    Authentication,
    /// Register this transient connection with the bus.
    Hello,
    /// Ask the bus whether its `org.bluez` name has an owner.
    BluezPresence,
    /// Request a single read-only ObjectManager snapshot from BlueZ.
    BluezInventory,
    /// Resolve and subscribe to BlueZ signals.
    BluezSubscribe,
    /// Receive a change from an existing subscription.
    BluezWatch,
    /// Acquire a discovery session on a specifically admitted adapter.
    BluezDiscoveryStart,
    /// Release a discovery session acquired by this connection.
    BluezDiscoveryStop,
    /// Connect one independently admitted BlueZ device.
    BluezDeviceConnect,
    /// Disconnect an admitted device and its profiles.
    BluezDeviceDisconnect,
    /// Read GATT object claims for the explicitly admitted device.
    BluezGattInventory,
    /// Start a notification session on an admitted characteristic.
    BluezNotifyStart,
    /// Receive a change while a notification session is active.
    BluezNotifyRead,
    /// Stop this connection's notification session.
    BluezNotifyStop,
    /// Send a separately authorized management-negotiation characteristic write.
    BluezManagementWrite,
}

/// Independently authorized local bus policy. It must bind the connected socket
/// and resource to the intended local bus and remain bounded and nonblocking.
pub trait Admission {
    /// Revalidate the exact operation on every transport poll.
    fn permits(&self, resource: &str, stage: Stage) -> bool;
}

/// Payload-free refusal. Borrowed device operations retain their watch and
/// fence it when effects or bus framing are uncertain; consuming operations
/// retire their connection on error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Clock, task, resource or deadline did not match the supplied transport.
    Configuration,
    /// Current task or local-bus policy denied I/O.
    Denied,
    /// Cancellation or the total deadline interrupted the exchange.
    Interrupted,
    /// Socket I/O failed or ended early.
    Io(io::ErrorKind),
    /// The restricted D-Bus profile refused the received bytes.
    Protocol(wire::Error),
    /// ObjectManager body validation failed; no partial inventory is returned.
    Inventory(object_manager::Error),
    /// A signal failed scope or body validation.
    Signal(signals::Error),
    /// The bus announced an owner change; the observation epoch is retired.
    OwnerChanged,
    /// A discovery call may have taken effect but its result is unknown.
    DiscoveryUncertain,
    /// A device connection call may have taken effect or its framing was lost.
    DeviceUncertain,
    /// GATT object claims were incomplete, ambiguous, or unsupported.
    GattSelection(object_manager::GattSelectionError),
    /// Changes overlap the requested GATT snapshot and require reconciliation.
    GattOverlap,
    /// A device or GATT change invalidated the selected endpoint claims.
    GattStale,
    /// A notification operation or framing has an unresolved outcome.
    NotificationUncertain,
    /// The bus reported no current owner for the BlueZ service name.
    BluezUnavailable,
    /// Allocation or the bounded signal count was exhausted.
    Limit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueZ bus observation refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// One current bus response; it does not prove an adapter or camera exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    /// The admitted bus reported an owner for `org.bluez`.
    pub bluez_name_owned: bool,
    /// Number of bounded signal frames discarded during the handshake.
    pub signals_skipped: usize,
}

/// One untrusted, bounded inventory snapshot, not a discovery coverage claim.
pub struct InventoryObservation {
    /// Current name observation and discarded signal count.
    pub bus: Observation,
    /// Claimed adapter paths. They are not verified device identities.
    pub adapter_paths: Vec<String>,
    /// Claimed Bluetooth device paths. They are not verified camera identities.
    pub device_paths: Vec<String>,
    /// Service-list claims corresponding to the returned device paths.
    pub device_claims: Vec<DeviceClaim>,
    /// Number of completely decoded objects in the snapshot.
    pub objects: usize,
}

/// Untrusted service information for one cached Bluetooth device.
pub struct DeviceClaim {
    /// Claimed device path; it does not establish identity or authorization.
    pub path: String,
    /// Claimed UUID strings, or `None` when the property was not observed.
    pub service_uuids: Option<Vec<String>>,
}
impl DeviceClaim {
    /// Check the observed list case-insensitively; this is not identity proof.
    /// `None` means that no service-list property was observed.
    pub fn claims_service(&self, service: &str) -> Option<bool> {
        self.service_uuids
            .as_ref()
            .map(|uuids| uuids.iter().any(|uuid| uuid.eq_ignore_ascii_case(service)))
    }
}
impl fmt::Debug for DeviceClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceClaim")
            .field("service_uuids_present", &self.service_uuids.is_some())
            .field("service_count", &self.service_uuids.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for InventoryObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InventoryObservation")
            .field("bus", &self.bus)
            .field("adapter_count", &self.adapter_paths.len())
            .field("device_count", &self.device_paths.len())
            .field("objects", &self.objects)
            .finish()
    }
}

struct Guarded<'a, 'scope, 'task, IO> {
    io: &'a mut MeteredIo<'scope, 'task, IO>,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    admission: &'a dyn Admission,
    resource: &'a str,
    stage: Stage,
}
impl<IO> Guarded<'_, '_, '_, IO> {
    fn check(&self) -> io::Result<()> {
        if !self.admission.permits(self.resource, self.stage) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let now = self.clock.now().map_err(|_| io::ErrorKind::Interrupted)?;
        self.task
            .checkpoint_for(
                RuntimeGrant::ObserveStatus,
                self.resource,
                now,
                &BudgetVector::ZERO,
            )
            .map_err(|_| io::ErrorKind::PermissionDenied.into())
    }
}
impl<IO: AsyncRead + Unpin> AsyncRead for Guarded<'_, '_, '_, IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut *self.io).poll_read(cx, buf)
    }
}
impl<IO: AsyncWrite + Unpin> AsyncWrite for Guarded<'_, '_, '_, IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        Pin::new(&mut *self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut *self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut *self.io).poll_shutdown(cx)
    }
}

// Read-side guard for an active scan: both the bus observation authority and
// the specific adapter's authority remain current at each transport poll.
struct ScanGuarded<'a, 'scope, 'task, IO> {
    bus: Guarded<'a, 'scope, 'task, IO>,
    adapter: &'a str,
}

// GATT I/O requires the bus, device, and exact characteristic grants at each
// poll, so a revoked characteristic cannot continue using a live device grant.
struct GattGuarded<'a, 'scope, 'task, IO> {
    device: ScanGuarded<'a, 'scope, 'task, IO>,
    characteristic: &'a str,
}

/// Live authority must independently bind the device identity, transport,
/// current lease, and exact request to the registered management-negotiation
/// effect. It must reject arbitrary camera settings and credential provisioning.
/// The check is repeated before each transport poll and must be nonblocking.
pub trait GattManagementAuthority {
    /// Revalidate the exact plan and one-use committed permit.
    fn permits(
        &self,
        plan: &gatt_management::Plan,
        current: gatt_management::Preconditions,
        permit: &CommittedEffect,
    ) -> bool;
}

struct GattManagementGuarded<'a, 'scope, 'task, IO> {
    io: GattGuarded<'a, 'scope, 'task, IO>,
    notify: &'a str,
    cx: &'a Cx,
    plan: &'a gatt_management::Plan,
    current: gatt_management::Preconditions,
    permit: &'a CommittedEffect,
    authority: &'a dyn GattManagementAuthority,
}
impl<IO> GattManagementGuarded<'_, '_, '_, IO> {
    fn check(&self) -> io::Result<()> {
        self.io.check()?;
        self.io.check_notification_access(self.notify)?;
        if self.cx.checkpoint().is_err()
            || !self.authority.permits(self.plan, self.current, self.permit)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}
impl<IO: AsyncRead + Unpin> AsyncRead for GattManagementGuarded<'_, '_, '_, IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl<IO: AsyncWrite + Unpin> AsyncWrite for GattManagementGuarded<'_, '_, '_, IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
impl<IO> GattGuarded<'_, '_, '_, IO> {
    fn check_notification_access(&self, notify: &str) -> io::Result<()> {
        if !self
            .device
            .bus
            .admission
            .permits(notify, Stage::BluezNotifyRead)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let now = self
            .device
            .bus
            .clock
            .now()
            .map_err(|_| io::ErrorKind::Interrupted)?;
        self.device
            .bus
            .task
            .checkpoint_for(RuntimeGrant::AdapterNet, notify, now, &BudgetVector::ZERO)
            .map_err(|_| io::ErrorKind::PermissionDenied.into())
    }
    fn check(&self) -> io::Result<()> {
        self.device.check()?;
        if !self
            .device
            .bus
            .admission
            .permits(self.characteristic, self.device.bus.stage)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let now = self
            .device
            .bus
            .clock
            .now()
            .map_err(|_| io::ErrorKind::Interrupted)?;
        self.device
            .bus
            .task
            .checkpoint_for(
                RuntimeGrant::AdapterNet,
                self.characteristic,
                now,
                &BudgetVector::ZERO,
            )
            .map_err(|_| io::ErrorKind::PermissionDenied.into())
    }
}
impl<IO: AsyncRead + Unpin> AsyncRead for GattGuarded<'_, '_, '_, IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.device).poll_read(cx, buf)
    }
}
impl<IO: AsyncWrite + Unpin> AsyncWrite for GattGuarded<'_, '_, '_, IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        Pin::new(&mut self.device).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.device).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.device).poll_shutdown(cx)
    }
}
impl<IO> ScanGuarded<'_, '_, '_, IO> {
    fn check(&self) -> io::Result<()> {
        self.bus.check()?;
        if !self.bus.admission.permits(self.adapter, self.bus.stage) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let now = self
            .bus
            .clock
            .now()
            .map_err(|_| io::ErrorKind::Interrupted)?;
        self.bus
            .task
            .checkpoint_for(
                RuntimeGrant::AdapterNet,
                self.adapter,
                now,
                &BudgetVector::ZERO,
            )
            .map_err(|_| io::ErrorKind::PermissionDenied.into())
    }
}
impl<IO: AsyncWrite + Unpin> AsyncWrite for ScanGuarded<'_, '_, '_, IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        Pin::new(&mut self.bus).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.bus).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.bus).poll_shutdown(cx)
    }
}
impl<IO: AsyncRead + Unpin> AsyncRead for ScanGuarded<'_, '_, '_, IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.bus).poll_read(cx, buf)
    }
}

fn io_error(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::PermissionDenied => Error::Denied,
        io::ErrorKind::Interrupted => Error::Interrupted,
        kind => Error::Io(kind),
    }
}
async fn read_exact<IO: AsyncRead + Unpin>(io: &mut IO, bytes: &mut [u8]) -> Result<(), Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = io.read(&mut bytes[offset..]).await.map_err(io_error)?;
        if count == 0 {
            return Err(Error::Io(io::ErrorKind::UnexpectedEof));
        }
        offset += count;
    }
    Ok(())
}
async fn message<IO: AsyncRead + Unpin>(io: &mut IO) -> Result<Vec<u8>, Error> {
    let mut header = [0u8; 16];
    read_exact(io, &mut header).await?;
    let total = wire::declared_message_len(&header)
        .map_err(Error::Protocol)?
        .ok_or(Error::Protocol(wire::Error::Invalid))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| Error::Limit)?;
    bytes.extend_from_slice(&header);
    bytes.resize(total, 0);
    read_exact(io, &mut bytes[16..]).await?;
    Ok(bytes)
}

// A timeout before any frame byte leaves the stream reusable. Once a frame
// starts, a timeout is an interruption and the caller must retire the stream.
async fn message_or_idle<IO: AsyncRead + Unpin>(
    cx: &Cx,
    io: &mut IO,
    wait: Duration,
) -> Result<Option<Vec<u8>>, Error> {
    let deadline = cx.now() + wait;
    let mut header = [0u8; 16];
    let first = match timeout_at(deadline, io.read(&mut header)).await {
        Ok(result) => result.map_err(io_error)?,
        Err(_) => return Ok(None),
    };
    if first == 0 {
        return Err(Error::Io(io::ErrorKind::UnexpectedEof));
    }
    timeout_at(deadline, read_exact(io, &mut header[first..]))
        .await
        .map_err(|_| Error::Interrupted)??;
    let total = wire::declared_message_len(&header)
        .map_err(Error::Protocol)?
        .ok_or(Error::Protocol(wire::Error::Invalid))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| Error::Limit)?;
    bytes.extend_from_slice(&header);
    bytes.resize(total, 0);
    timeout_at(deadline, read_exact(io, &mut bytes[16..]))
        .await
        .map_err(|_| Error::Interrupted)??;
    Ok(Some(bytes))
}

async fn response<IO: AsyncRead + Unpin>(
    io: &mut IO,
    skipped: &mut usize,
) -> Result<Vec<u8>, Error> {
    loop {
        let frame = message(io).await?;
        if frame[1] != 4 {
            return Ok(frame);
        }
        if *skipped == MAX_SIGNALS {
            return Err(Error::Limit);
        }
        *skipped += 1;
    }
}

/// Run one bounded observation over an already connected and admitted stream.
/// The caller must separately authorize socket connection, bind the path to the
/// local system bus, supply its own Unix UID, and enforce any wider time budget.
/// A partial write or read cannot be retried on this connection: it is dropped.
pub async fn observe<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    io: MeteredIo<'scope, 'task, IO>,
    admission: &dyn Admission,
    uid: u32,
    wait: Duration,
) -> Result<Observation, Error> {
    let input = ObservationInput {
        cx,
        task,
        clock,
        io,
        admission,
        uid,
        wait,
    };
    let (observation, _) = observe_inner(input, false).await?;
    Ok(observation)
}

/// Observe BlueZ and obtain one read-only, bounded adapter inventory. This is
/// a transient snapshot: skipped signals and connection retirement mean it is
/// not continuous discovery or evidence that unlisted devices are absent.
pub async fn observe_inventory<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    io: MeteredIo<'scope, 'task, IO>,
    admission: &dyn Admission,
    uid: u32,
    wait: Duration,
) -> Result<InventoryObservation, Error> {
    let input = ObservationInput {
        cx,
        task,
        clock,
        io,
        admission,
        uid,
        wait,
    };
    let (bus, inventory) = observe_inner(input, true).await?;
    let ParsedInventory {
        adapter_paths,
        device_paths,
        device_claims,
        objects,
    } = inventory.ok_or(Error::Configuration)?;
    Ok(InventoryObservation {
        bus,
        adapter_paths,
        device_paths,
        device_claims,
        objects,
    })
}

struct ObservationInput<'scope, 'task, 'policy, IO> {
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    io: MeteredIo<'scope, 'task, IO>,
    admission: &'policy dyn Admission,
    uid: u32,
    wait: Duration,
}

struct ParsedInventory {
    adapter_paths: Vec<String>,
    device_paths: Vec<String>,
    device_claims: Vec<DeviceClaim>,
    objects: usize,
}

async fn observe_inner<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    input: ObservationInput<'scope, 'task, '_, IO>,
    inventory: bool,
) -> Result<(Observation, Option<ParsedInventory>), Error> {
    let ObservationInput {
        cx,
        task,
        clock,
        mut io,
        admission,
        uid,
        wait,
    } = input;
    if wait.is_zero()
        || wait > MAX_WAIT
        || !clock.matches(task, cx)
        || !clock.same_mapping(&io.clock())
    {
        return Err(Error::Configuration);
    }
    let resource = io.resource().to_owned();
    let mut guarded = Guarded {
        io: &mut io,
        task,
        clock,
        admission,
        resource: &resource,
        stage: Stage::Authentication,
    };
    let exchange = async {
        guarded
            .write_all(&wire::external_request(uid))
            .await
            .map_err(io_error)?;
        guarded.flush().await.map_err(io_error)?;
        let mut line = Vec::new();
        line.try_reserve_exact(MAX_AUTH_BYTES)
            .map_err(|_| Error::Limit)?;
        loop {
            if wire::parse_auth_ok(&line)
                .map_err(Error::Protocol)?
                .is_some()
            {
                break;
            }
            if line.len() == MAX_AUTH_BYTES {
                return Err(Error::Limit);
            }
            let mut byte = [0u8; 1];
            read_exact(&mut guarded, &mut byte).await?;
            line.push(byte[0]);
        }
        guarded.write_all(wire::BEGIN).await.map_err(io_error)?;
        guarded.stage = Stage::Hello;
        guarded
            .write_all(&wire::hello(1).map_err(Error::Protocol)?)
            .await
            .map_err(io_error)?;
        guarded.flush().await.map_err(io_error)?;
        let mut skipped = 0;
        let hello = response(&mut guarded, &mut skipped).await?;
        let parsed = wire::parse_hello_reply(&hello, 1)
            .map_err(Error::Protocol)?
            .ok_or(Error::Protocol(wire::Error::Invalid))?;
        if parsed.consumed() != hello.len() {
            return Err(Error::Protocol(wire::Error::Invalid));
        }
        guarded.stage = Stage::BluezPresence;
        guarded
            .write_all(&wire::bluez_name_has_owner(2).map_err(Error::Protocol)?)
            .await
            .map_err(io_error)?;
        guarded.flush().await.map_err(io_error)?;
        let reply = response(&mut guarded, &mut skipped).await?;
        let owner = wire::parse_bluez_owner_reply(&reply, 2)
            .map_err(Error::Protocol)?
            .ok_or(Error::Protocol(wire::Error::Invalid))?;
        if owner.consumed != reply.len() {
            return Err(Error::Protocol(wire::Error::Invalid));
        }
        if inventory && !owner.present {
            return Err(Error::BluezUnavailable);
        }
        let inventory = if inventory {
            guarded.stage = Stage::BluezInventory;
            guarded
                .write_all(&wire::bluez_managed_objects(3).map_err(Error::Protocol)?)
                .await
                .map_err(io_error)?;
            guarded.flush().await.map_err(io_error)?;
            let frame = response(&mut guarded, &mut skipped).await?;
            let body = wire::parse_bluez_managed_objects_reply(&frame, 3)
                .map_err(Error::Protocol)?
                .ok_or(Error::Protocol(wire::Error::Invalid))?;
            if body.consumed != frame.len() {
                return Err(Error::Protocol(wire::Error::Invalid));
            }
            Some(parse_inventory(body)?)
        } else {
            None
        };
        guarded.check().map_err(io_error)?;
        Ok((
            Observation {
                bluez_name_owned: owner.present,
                signals_skipped: skipped,
            },
            inventory,
        ))
    };
    timeout_at(cx.now() + wait, exchange)
        .await
        .map_err(|_| Error::Interrupted)?
}

fn parse_inventory(body: wire::ManagedObjectsBody<'_>) -> Result<ParsedInventory, Error> {
    let endian = if body.little_endian {
        object_manager::Endian::Little
    } else {
        object_manager::Endian::Big
    };
    let parsed = object_manager::parse_inventory(body.body, endian).map_err(Error::Inventory)?;
    let mut device_claims = Vec::new();
    device_claims
        .try_reserve_exact(parsed.device_claims().len())
        .map_err(|_| Error::Limit)?;
    for claim in parsed.device_claims() {
        let mut path = String::new();
        path.try_reserve_exact(claim.path().len())
            .map_err(|_| Error::Limit)?;
        path.push_str(claim.path());
        device_claims.push(DeviceClaim {
            path,
            service_uuids: claim.service_uuids().map(own_paths).transpose()?,
        });
    }
    Ok(ParsedInventory {
        adapter_paths: own_paths(parsed.adapter_paths())?,
        device_paths: own_paths(parsed.device_paths())?,
        device_claims,
        objects: parsed.objects(),
    })
}

fn own_paths(paths: &[&str]) -> Result<Vec<String>, Error> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(paths.len())
        .map_err(|_| Error::Limit)?;
    for path in paths {
        let mut owned = String::new();
        owned
            .try_reserve_exact(path.len())
            .map_err(|_| Error::Limit)?;
        owned.push_str(path);
        result.push(owned);
    }
    Ok(result)
}

const MAX_QUEUED_CHANGES: usize = 32;

/// A validated change frame. Its contents are untrusted claims, not camera identity.
pub struct ChangeFrame(Vec<u8>, Option<(Arc<()>, u64)>);
#[cfg(test)]
pub(super) fn test_change_frame(bytes: Vec<u8>) -> ChangeFrame {
    ChangeFrame(bytes, None)
}
impl fmt::Debug for ChangeFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangeFrame").finish_non_exhaustive()
    }
}
impl ChangeFrame {
    /// Decode the frame under the session's current, independently resolved scope.
    pub fn decode<'a>(&'a self, owner: &str) -> Result<signals::Event<'a>, signals::Error> {
        signals::parse(
            &self.0,
            &signals::Scope {
                owner,
                namespace: "/org/bluez",
                manager_path: "/",
            },
        )
    }
}

/// A task-owned signal subscription. Dropping it closes the bus connection and
/// releases its matches; it does not prove an admitted device was disconnected.
/// No snapshot, Bluetooth scan, or authenticated device identity is implied.
/// While notifications are active, use the borrowed notification methods;
/// consuming watch methods refuse and consume the watch on error, leaving
/// notification cleanup unresolved.
#[must_use = "retain or explicitly dispose of device connection obligations"]
pub struct Watch<'scope, 'task, 'policy, IO> {
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    io: MeteredIo<'scope, 'task, IO>,
    admission: &'policy dyn Admission,
    resource: String,
    owner: String,
    queued: VecDeque<ChangeFrame>,
    next_serial: u32,
    device_state: DeviceLinkState,
    device_path: Option<String>,
    gatt_binding: Option<GattEndpoints>,
    gatt_stale: bool,
    notification_state: NotificationState,
    notification_epoch: Option<Arc<()>>,
    next_notification_sequence: u64,
    framed_management_reservation: Option<Arc<()>>,
}

/// Why a notification-frame owner stopped or refused an input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationFramesError {
    /// The watch, notification epoch or selected endpoints no longer match.
    Scope,
    /// A previous change still belongs to this owner.
    Pending,
    /// A change arrived out of order or its earlier change was not supplied.
    Sequence,
    /// The owner was fenced after an incomplete or invalid frame.
    Fenced,
    /// The bounded UniFi packet framer refused the input.
    Framing(fss_packet::unifi_ble::FailureKind),
    /// A previously validated BlueZ change could not be decoded again.
    Decode,
    /// The requested maximum frame size was invalid.
    Configuration,
    /// Task authority or the bounded decode/allocation budget was unavailable.
    Budget,
}
impl fmt::Display for NotificationFramesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueZ notification framing refused: {self:?}")
    }
}
impl std::error::Error for NotificationFramesError {}

/// An input refused before being consumed; the original change remains owned.
#[must_use]
#[derive(Debug)]
pub struct NotificationFramesRefusal {
    /// Payload-free refusal reason.
    pub reason: NotificationFramesError,
    /// The original BlueZ change, unchanged and still caller-owned.
    pub change: ChangeFrame,
}

/// A completed packet, the original inspected change, or a request for input.
#[must_use]
#[derive(Debug)]
pub enum NotificationFramesStep {
    /// One complete length-framed packet. It is not authenticated or decoded.
    Packet(fss_packet::unifi_ble::Bytes),
    /// The complete original BlueZ change for the caller's inventory handling.
    Change(ChangeFrame),
    /// No change is currently held; a partial packet may still be buffered.
    NeedChange,
}

/// All remaining input after the caller retires a notification-frame owner.
#[must_use]
pub struct NotificationFramesRetirement {
    /// Incomplete or refused packet prefix, including its original length bytes.
    pub packet_prefix: fss_packet::unifi_ble::Bytes,
    /// Original change and the count of its value bytes already accepted, if any.
    pub pending_change: Option<(ChangeFrame, usize)>,
    /// A framing or decoding failure prevented further processing.
    pub fenced: bool,
}

/// Bounded, single-owner composition of one notification epoch and BLE framer.
///
/// Every accepted change must have been returned by this exact watch during
/// the same active subscription. Original changes are returned for separate
/// inventory handling; unrelated changes are never consumed as packet bytes.
/// Local epoch binding is not device identity, continuity or peer authentication.
pub struct NotificationFrames {
    epoch: Arc<()>,
    next_sequence: u64,
    framer: fss_packet::unifi_ble::Framer,
    maximum: u64,
    frame_started: bool,
    pending: Option<(ChangeFrame, usize)>,
    fenced: bool,
}

impl NotificationFrames {
    /// Bind to the current active, non-stale selection without performing I/O.
    pub fn new<IO>(
        watch: &Watch<'_, '_, '_, IO>,
        endpoints: &GattEndpoints,
        maximum: usize,
    ) -> Result<Self, NotificationFramesError> {
        let epoch = watch
            .notification_epoch
            .as_ref()
            .ok_or(NotificationFramesError::Scope)?;
        if watch.notification_state != NotificationState::Active
            || watch.device_state != DeviceLinkState::ConnectAcknowledged
            || watch.gatt_stale
            || watch.gatt_binding.as_ref() != Some(endpoints)
            || watch.next_notification_sequence != 0
        {
            return Err(NotificationFramesError::Scope);
        }
        let result = Self {
            epoch: Arc::clone(epoch),
            next_sequence: 0,
            framer: fss_packet::unifi_ble::Framer::new(maximum)
                .ok_or(NotificationFramesError::Configuration)?,
            maximum: u64::try_from(maximum).map_err(|_| NotificationFramesError::Configuration)?,
            frame_started: false,
            pending: None,
            fenced: false,
        };
        if !result.current(watch, endpoints) {
            return Err(NotificationFramesError::Scope);
        }
        Ok(result)
    }

    fn current<IO>(&self, watch: &Watch<'_, '_, '_, IO>, endpoints: &GattEndpoints) -> bool {
        let Some(device) = watch.device_path.as_deref() else {
            return false;
        };
        if !(watch.notification_state == NotificationState::Active
            && watch.device_state == DeviceLinkState::ConnectAcknowledged
            && !watch.gatt_stale
            && watch.gatt_binding.as_ref() == Some(endpoints)
            && watch
                .notification_epoch
                .as_ref()
                .is_some_and(|epoch| Arc::ptr_eq(epoch, &self.epoch)))
        {
            return false;
        }
        if watch.cx.checkpoint().is_err() {
            return false;
        }
        for (resource, grant) in [
            (watch.resource.as_str(), RuntimeGrant::ObserveStatus),
            (device, RuntimeGrant::AdapterNet),
            (endpoints.notify.as_str(), RuntimeGrant::AdapterNet),
        ] {
            if !watch.admission.permits(resource, Stage::BluezNotifyRead) {
                return false;
            }
            let Ok(now) = watch.clock.now() else {
                return false;
            };
            if watch
                .task
                .checkpoint_for(grant, resource, now, &BudgetVector::ZERO)
                .is_err()
            {
                return false;
            }
        }
        true
    }

    /// Transfer one change returned by this exact watch. Refusal returns it intact.
    pub fn submit<IO>(
        &mut self,
        watch: &Watch<'_, '_, '_, IO>,
        endpoints: &GattEndpoints,
        change: ChangeFrame,
    ) -> Result<(), NotificationFramesRefusal> {
        let reason = if self.fenced {
            Some(NotificationFramesError::Fenced)
        } else if !self.current(watch, endpoints)
            || !change
                .1
                .as_ref()
                .is_some_and(|(epoch, _)| Arc::ptr_eq(epoch, &self.epoch))
        {
            Some(NotificationFramesError::Scope)
        } else if change
            .1
            .as_ref()
            .is_some_and(|(_, sequence)| *sequence != self.next_sequence)
        {
            Some(NotificationFramesError::Sequence)
        } else if self.pending.is_some() {
            Some(NotificationFramesError::Pending)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(NotificationFramesRefusal { reason, change });
        }
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            self.fenced = true;
            return Err(NotificationFramesRefusal {
                reason: NotificationFramesError::Fenced,
                change,
            });
        };
        self.next_sequence = next_sequence;
        self.pending = Some((change, 0));
        Ok(())
    }

    /// Drain one packet or return the original change; bounded backpressure
    /// requires draining a change before submitting the next one.
    pub fn next<IO>(
        &mut self,
        watch: &Watch<'_, '_, '_, IO>,
        endpoints: &GattEndpoints,
    ) -> Result<NotificationFramesStep, NotificationFramesError> {
        if self.fenced {
            return Err(NotificationFramesError::Fenced);
        }
        if !self.current(watch, endpoints) {
            return Err(NotificationFramesError::Scope);
        }
        let Some((frame, offset)) = self.pending.as_mut() else {
            return Ok(NotificationFramesStep::NeedChange);
        };
        let now = watch
            .clock
            .now()
            .map_err(|_| NotificationFramesError::Budget)?;
        let mut decode_cost = BudgetVector::ZERO;
        decode_cost.bytes =
            u64::try_from(frame.0.len()).map_err(|_| NotificationFramesError::Budget)?;
        watch
            .task
            .checkpoint_for(
                RuntimeGrant::ObserveStatus,
                &watch.resource,
                now,
                &decode_cost,
            )
            .map_err(|_| NotificationFramesError::Budget)?;
        let event = match frame.decode(&watch.owner) {
            Ok(event) => event,
            Err(_) => {
                self.fenced = true;
                return Err(NotificationFramesError::Decode);
            }
        };
        if let signals::Event::Properties { path, change } = event
            && path == endpoints.notify
            && change.interface == "org.bluez.GattCharacteristic1"
            && let object_manager::GattValueChange::Present(value) = change.gatt_value
            && *offset < value.len()
        {
            if !self.frame_started {
                if watch.cx.checkpoint().is_err()
                    || !watch
                        .admission
                        .permits(&endpoints.notify, Stage::BluezNotifyRead)
                {
                    return Err(NotificationFramesError::Budget);
                }
                let now = watch
                    .clock
                    .now()
                    .map_err(|_| NotificationFramesError::Budget)?;
                let mut cost = BudgetVector::ZERO;
                cost.bytes = self.maximum;
                watch
                    .task
                    .checkpoint_for(RuntimeGrant::AdapterNet, &endpoints.notify, now, &cost)
                    .map_err(|_| NotificationFramesError::Budget)?;
                self.frame_started = true;
            }
            match self.framer.feed(&value[*offset..]) {
                Ok(fed) => {
                    *offset += fed.consumed;
                    if fed.complete {
                        self.frame_started = false;
                        if let Some(packet) = self.framer.take() {
                            return Ok(NotificationFramesStep::Packet(packet));
                        }
                        self.fenced = true;
                        return Err(NotificationFramesError::Decode);
                    }
                }
                Err(error) => {
                    *offset += error.consumed;
                    self.fenced = true;
                    return Err(NotificationFramesError::Framing(error.kind));
                }
            }
        }
        // A partial packet has consumed the entire current value. Return the
        // original change, but remove its one-use notification admission.
        let (mut frame, _) = self.pending.take().ok_or(NotificationFramesError::Decode)?;
        frame.1 = None;
        Ok(NotificationFramesStep::Change(frame))
    }

    /// Preserve an unfinished packet and original change when stopping.
    pub fn retire(self) -> NotificationFramesRetirement {
        NotificationFramesRetirement {
            packet_prefix: self.framer.retire(),
            pending_change: self.pending,
            fenced: self.fenced,
        }
    }
}

fn within(path: &str, parent: &str) -> bool {
    path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|tail| tail.starts_with('/'))
}

// Conservative: values and a positive Notifying claim on the selected
// characteristic may be delivered; other selected-device changes require a
// fresh snapshot. Unrelated devices do not invalidate this selection.
fn invalidates_gatt(event: &signals::Event<'_>, device: &str, notify: &str) -> bool {
    let adapter = device
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("");
    match event {
        signals::Event::Added(value) => value.path == adapter || within(value.path, device),
        signals::Event::Removed(value) => value.path == adapter || within(value.path, device),
        signals::Event::Properties { path, change } => {
            if *path == notify
                && change.interface == "org.bluez.GattCharacteristic1"
                && (matches!(
                    change.gatt_value,
                    object_manager::GattValueChange::Present(_)
                ) || (matches!(
                    change.gatt_value,
                    object_manager::GattValueChange::Unchanged
                ) && change.gatt_notifying_active))
                && !change.gatt_other_changed
            {
                false
            } else {
                *path == adapter || within(path, device)
            }
        }
    }
}

/// Local observation of this watch's device-link operations. An acknowledgment
/// is not a current connection guarantee or proof of remote device identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceLinkState {
    /// No device connection has been requested by this watch.
    Unlinked,
    /// BlueZ acknowledged the connect call; the link may have changed since.
    ConnectAcknowledged,
    /// A call was interrupted or could not be correlated; further bus I/O is fenced.
    Uncertain,
}

/// Local outcome of this watch's notification-session operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationState {
    /// No notification session is held by this watch.
    Inactive,
    /// BlueZ acknowledged notification start; delivery is not guaranteed.
    Active,
    /// A call or a read was interrupted, so cleanup and framing are unresolved.
    Uncertain,
}

/// Refusal before an authorized GATT negotiation write is claimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GattManagementRefusalReason {
    /// The session, selected endpoints, mode, serial, or wait is not current.
    Session,
    /// A change awaits reconciliation or the selection became stale.
    Stale,
    /// The committed permit has no journal-backed owner.
    JournalRequired,
    /// The permit does not match this effect, request, conditions, resource or lease.
    PermitMismatch,
    /// Fresh conditions or the independent semantic/identity authority refused.
    Denied,
    /// The one-use permit was already claimed.
    PermitUsed,
}

/// A pre-dispatch refusal retains the caller's permit for reconciliation.
#[must_use]
#[derive(Debug)]
pub struct GattManagementRefusal {
    /// Reason no new dispatch was claimed.
    pub reason: GattManagementRefusalReason,
    /// Original permit; a previously claimed permit must not be reused.
    pub permit: CommittedEffect,
}

/// Locally observed outcome; neither result verifies the camera's state.
#[must_use]
#[derive(Debug)]
pub enum GattManagementWrite {
    /// BlueZ returned a correlated success; the effect remains to be reconciled.
    Acknowledged {
        /// Claimed permit retained for independent reconciliation.
        permit: CommittedEffect,
    },
    /// Dispatch, reply framing, authority or cancellation became uncertain.
    Indeterminate {
        /// Claimed permit retained for independent reconciliation.
        permit: CommittedEffect,
    },
}

struct GattDispatchOptions<'a> {
    wait: Duration,
    reservation: Option<&'a Arc<()>>,
}

/// Caller-owned GATT endpoint claims from one correlated BlueZ snapshot.
/// These paths are untrusted, can become stale, and confer no operation authority.
#[derive(Eq, PartialEq)]
pub struct GattEndpoints {
    service: String,
    notify: String,
    write: String,
    mode: object_manager::GattWriteMode,
}
impl GattEndpoints {
    /// Claimed service object path.
    pub fn service(&self) -> &str {
        &self.service
    }
    /// Claimed notification or indication object path.
    pub fn notify(&self) -> &str {
        &self.notify
    }
    /// Claimed write object path.
    pub fn write(&self) -> &str {
        &self.write
    }
    /// Write mode required by the selected characteristic claim.
    pub fn write_mode(&self) -> object_manager::GattWriteMode {
        self.mode
    }
}
impl fmt::Debug for GattEndpoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GattEndpoints").finish_non_exhaustive()
    }
}

/// Local lifecycle of one fragmented management-negotiation packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramedManagementState {
    /// The next fragment may be prepared.
    Ready,
    /// A fragment plan awaits its separately committed permit.
    Prepared,
    /// Dispatch was armed; dropping its future requires reconciliation.
    InFlight,
    /// Every fragment was acknowledged locally, not verified by the camera.
    Complete,
    /// A result or cursor state is uncertain; do not continue this packet.
    Fenced,
}

/// Payload-free refusal while preparing a fragmented negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramedManagementError {
    /// Watch, endpoint, session, mode or authority is no longer current.
    Scope,
    /// A BlueZ change must be examined before another fragment is prepared.
    QueuedChange,
    /// The local packet lifecycle does not permit this operation.
    State,
    /// Task or bounded allocation budget refused the work.
    Budget,
    /// The supplied frame or cursor state was invalid.
    Cursor(fss_packet::unifi_ble::WriteError),
    /// Exact request or precondition encoding failed.
    Plan(gatt_management::Error),
}
impl fmt::Display for FramedManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueZ framed management refused: {self:?}")
    }
}
impl std::error::Error for FramedManagementError {}

/// Preserved packet, pending plan and operation after an explicit retirement.
#[must_use]
pub struct FramedManagementRetirement<'frame> {
    /// Original frame and acknowledged/pending byte ranges.
    pub cursor: fss_packet::unifi_ble::WriteRetirement<'frame>,
    /// Exact unconsumed fragment plan, if one was prepared.
    pub plan: Option<gatt_management::Plan>,
    /// Last operation armed for dispatch, including a dropped future.
    pub operation: Option<OperationId>,
    /// Whether continuation or reconciliation is required.
    pub state: FramedManagementState,
    /// This watch remains reserved because the packet may be incomplete.
    pub reservation_retained: bool,
}

/// Task-owned fragment coordinator for one already-framed negotiation packet.
///
/// Each fragment requires its own journal-backed, one-use management permit.
/// The caller must independently validate the packet's semantics and device
/// identity. This does not authorize Wi-Fi credentials, arbitrary settings,
/// retry an uncertain write, or prove the peer received the complete packet.
pub struct FramedManagement<'frame> {
    epoch: Arc<()>,
    reservation: Arc<()>,
    cursor: fss_packet::unifi_ble::WriteCursor<'frame>,
    frame_digest: ContentDigest,
    total: usize,
    offset: usize,
    pending_len: usize,
    current: gatt_management::Preconditions,
    plan: Option<gatt_management::Plan>,
    operation: Option<OperationId>,
    state: FramedManagementState,
}
impl<'frame> FramedManagement<'frame> {
    /// Bind a bounded, non-secret frame to this active write-with-response
    /// notification session. The payload limit is caller-established, not an
    /// automatically negotiated ATT MTU. No device I/O is performed.
    pub fn new<IO>(
        watch: &mut Watch<'_, '_, '_, IO>,
        endpoints: &GattEndpoints,
        frame: &'frame [u8],
        maximum_chunk: usize,
        current: gatt_management::Preconditions,
    ) -> Result<Self, FramedManagementError> {
        let epoch = watch
            .notification_epoch
            .as_ref()
            .ok_or(FramedManagementError::Scope)?;
        if watch.notification_state != NotificationState::Active
            || watch.device_state != DeviceLinkState::ConnectAcknowledged
            || watch.gatt_stale
            || watch.gatt_binding.as_ref() != Some(endpoints)
            || watch.framed_management_reservation.is_some()
            || endpoints.mode != object_manager::GattWriteMode::Request
            || maximum_chunk > 512
            || watch.cx.checkpoint().is_err()
            || !watch
                .admission
                .permits(&endpoints.write, Stage::BluezManagementWrite)
        {
            return Err(FramedManagementError::Scope);
        }
        let cursor = fss_packet::unifi_ble::WriteCursor::new(frame, maximum_chunk)
            .map_err(FramedManagementError::Cursor)?;
        let mut cost = BudgetVector::ZERO;
        cost.bytes = u64::try_from(frame.len()).map_err(|_| FramedManagementError::Budget)?;
        let now = watch
            .clock
            .now()
            .map_err(|_| FramedManagementError::Budget)?;
        watch
            .task
            .checkpoint_for(RuntimeGrant::AdapterNet, &endpoints.write, now, &cost)
            .map_err(|_| FramedManagementError::Budget)?;
        let epoch = Arc::clone(epoch);
        let reservation = Arc::new(());
        watch.framed_management_reservation = Some(Arc::clone(&reservation));
        Ok(Self {
            epoch,
            reservation,
            cursor,
            frame_digest: ContentDigest::sha256(frame),
            total: frame.len(),
            offset: 0,
            pending_len: 0,
            current,
            plan: None,
            operation: None,
            state: FramedManagementState::Ready,
        })
    }

    /// Current local progress; acknowledgment is not remote verification.
    pub fn state(&self) -> FramedManagementState {
        self.state
    }

    fn current<IO>(&self, watch: &Watch<'_, '_, '_, IO>, endpoints: &GattEndpoints) -> bool {
        watch.notification_state == NotificationState::Active
            && watch.device_state == DeviceLinkState::ConnectAcknowledged
            && !watch.gatt_stale
            && watch.gatt_binding.as_ref() == Some(endpoints)
            && endpoints.mode == object_manager::GattWriteMode::Request
            && watch
                .framed_management_reservation
                .as_ref()
                .is_some_and(|token| Arc::ptr_eq(token, &self.reservation))
            && watch
                .notification_epoch
                .as_ref()
                .is_some_and(|epoch| Arc::ptr_eq(epoch, &self.epoch))
    }

    /// Prepare one exact fragment plan for the caller's effect coordinator.
    /// Drain queued BlueZ changes before preparing a further fragment.
    pub fn prepare<IO>(
        &mut self,
        watch: &Watch<'_, '_, '_, IO>,
        endpoints: &GattEndpoints,
    ) -> Result<Option<&gatt_management::Plan>, FramedManagementError> {
        if self.state == FramedManagementState::Complete {
            return Ok(None);
        }
        if self.state != FramedManagementState::Ready {
            return Err(FramedManagementError::State);
        }
        if !self.current(watch, endpoints) {
            self.state = FramedManagementState::Fenced;
            return Err(FramedManagementError::Scope);
        }
        if !watch.queued.is_empty() {
            return Err(FramedManagementError::QueuedChange);
        }
        let device = watch
            .device_path
            .as_deref()
            .ok_or(FramedManagementError::Scope)?;
        if watch.next_serial.checked_add(1).is_none() {
            self.state = FramedManagementState::Fenced;
            return Err(FramedManagementError::Scope);
        }
        if watch.cx.checkpoint().is_err()
            || !watch
                .admission
                .permits(&endpoints.write, Stage::BluezManagementWrite)
        {
            return Err(FramedManagementError::Scope);
        }
        let now = watch
            .clock
            .now()
            .map_err(|_| FramedManagementError::Budget)?;
        let mut cost = BudgetVector::ZERO;
        cost.bytes = 8192;
        watch
            .task
            .checkpoint_for(RuntimeGrant::AdapterNet, &endpoints.write, now, &cost)
            .map_err(|_| FramedManagementError::Budget)?;
        let Some(chunk) = self
            .cursor
            .prepare()
            .map_err(FramedManagementError::Cursor)?
        else {
            self.state = FramedManagementState::Complete;
            return Ok(None);
        };
        let Some(end) = self.offset.checked_add(chunk.len()) else {
            let _ = self
                .cursor
                .resolve(fss_packet::unifi_ble::WriteOutcome::DefinitelyNotSubmitted);
            self.state = FramedManagementState::Fenced;
            return Err(FramedManagementError::State);
        };
        let plan = gatt_management::Plan::new(
            watch.next_serial,
            &watch.owner,
            device,
            &endpoints.write,
            object_manager::GattWriteMode::Request,
            chunk,
            self.current,
        )
        .and_then(|plan| plan.bind_fragment(self.frame_digest, self.total, self.offset..end));
        match plan {
            Ok(plan) => {
                self.pending_len = chunk.len();
                self.plan = Some(plan);
                self.state = FramedManagementState::Prepared;
                Ok(self.plan.as_ref())
            }
            Err(error) => {
                self.cursor
                    .resolve(fss_packet::unifi_ble::WriteOutcome::DefinitelyNotSubmitted)
                    .map_err(FramedManagementError::Cursor)?;
                Err(FramedManagementError::Plan(error))
            }
        }
    }

    /// Arm one fragment before returning its dispatch future. Dropping the
    /// future even before its first poll leaves the operation and range in
    /// `InFlight`; the caller must reconcile the journal rather than retry.
    pub fn dispatch<'a, 'scope, 'task, 'policy, IO>(
        &'a mut self,
        watch: &'a mut Watch<'scope, 'task, 'policy, IO>,
        endpoints: &'a GattEndpoints,
        permit: CommittedEffect,
        authority: &'a dyn GattManagementAuthority,
        wait: Duration,
    ) -> Result<
        impl Future<Output = Result<GattManagementWrite, GattManagementRefusal>> + 'a,
        GattManagementRefusal,
    >
    where
        IO: AsyncRead + AsyncWrite + Unpin + 'a,
        'frame: 'a,
        'scope: 'a,
        'task: 'a,
        'policy: 'a,
    {
        if self.state != FramedManagementState::Prepared
            || self.plan.is_none()
            || !self.current(watch, endpoints)
            || wait.is_zero()
            || wait > MAX_WAIT
            || !watch.cx.has_timer()
        {
            return Err(GattManagementRefusal {
                reason: GattManagementRefusalReason::Session,
                permit,
            });
        }
        let Some(plan) = self.plan.as_ref() else {
            return Err(GattManagementRefusal {
                reason: GattManagementRefusalReason::Session,
                permit,
            });
        };
        if !watch.queued.is_empty() {
            return Err(GattManagementRefusal {
                reason: GattManagementRefusalReason::Stale,
                permit,
            });
        }
        let Some(device) = watch.device_path.as_deref() else {
            return Err(GattManagementRefusal {
                reason: GattManagementRefusalReason::Session,
                permit,
            });
        };
        if !plan.matches(
            watch.next_serial,
            &watch.owner,
            device,
            &endpoints.write,
            endpoints.mode,
        ) {
            return Err(GattManagementRefusal {
                reason: GattManagementRefusalReason::Session,
                permit,
            });
        }
        if !permit.journal_backed() {
            return Err(GattManagementRefusal {
                reason: GattManagementRefusalReason::JournalRequired,
                permit,
            });
        }
        if permit.prepared().effect_class() != gatt_management::EFFECT_CLASS
            || permit.prepared().request_digest() != plan.request_digest()
            || permit.prepared().precondition_digest() != plan.precondition_digest()
            || permit.resource() != plan.resource()
            || permit.fence() != plan.fence()
        {
            return Err(GattManagementRefusal {
                reason: GattManagementRefusalReason::PermitMismatch,
                permit,
            });
        }
        self.operation = Some(permit.operation().clone());
        self.state = FramedManagementState::InFlight;
        Ok(async move {
            let Some(plan) = self.plan.as_ref() else {
                self.state = FramedManagementState::Fenced;
                return Err(GattManagementRefusal {
                    reason: GattManagementRefusalReason::Session,
                    permit,
                });
            };
            match watch
                .dispatch_gatt_management_inner(
                    endpoints,
                    plan,
                    self.current,
                    permit,
                    authority,
                    GattDispatchOptions {
                        wait,
                        reservation: Some(&self.reservation),
                    },
                )
                .await
            {
                Err(refusal) => {
                    if refusal.reason == GattManagementRefusalReason::PermitUsed {
                        let _ = self
                            .cursor
                            .resolve(fss_packet::unifi_ble::WriteOutcome::Indeterminate);
                        self.state = FramedManagementState::Fenced;
                    } else {
                        self.operation = None;
                        self.state = FramedManagementState::Prepared;
                    }
                    Err(refusal)
                }
                Ok(GattManagementWrite::Acknowledged { permit }) => {
                    if self
                        .cursor
                        .resolve(fss_packet::unifi_ble::WriteOutcome::Acknowledged)
                        .is_err()
                    {
                        self.state = FramedManagementState::Fenced;
                        return Ok(GattManagementWrite::Indeterminate { permit });
                    }
                    self.offset += self.pending_len;
                    self.pending_len = 0;
                    self.plan = None;
                    self.operation = None;
                    self.state = if self.offset == self.total {
                        FramedManagementState::Complete
                    } else {
                        FramedManagementState::Ready
                    };
                    Ok(GattManagementWrite::Acknowledged { permit })
                }
                Ok(GattManagementWrite::Indeterminate { permit }) => {
                    let _ = self
                        .cursor
                        .resolve(fss_packet::unifi_ble::WriteOutcome::Indeterminate);
                    self.state = FramedManagementState::Fenced;
                    Ok(GattManagementWrite::Indeterminate { permit })
                }
            }
        })
    }

    /// Preserve the original frame, local range and any armed operation.
    pub fn retire<IO>(
        self,
        watch: &mut Watch<'_, '_, '_, IO>,
    ) -> FramedManagementRetirement<'frame> {
        let matches = watch
            .framed_management_reservation
            .as_ref()
            .is_some_and(|token| Arc::ptr_eq(token, &self.reservation));
        let release = matches
            && (self.state == FramedManagementState::Complete
                || (self.state == FramedManagementState::Ready && self.offset == 0));
        if release {
            watch.framed_management_reservation = None;
        }
        FramedManagementRetirement {
            cursor: self.cursor.retire(),
            plan: self.plan,
            operation: self.operation,
            state: self.state,
            reservation_retained: !release,
        }
    }
}

/// An acquired adapter scan. The owner must explicitly stop it on the same
/// connection. If this is dropped or cancellation prevents an acknowledged
/// stop, cleanup remains uncertain even though the bus connection closes.
#[must_use = "a discovery session must be explicitly stopped"]
pub struct Discovering<'scope, 'task, 'policy, IO> {
    watch: Watch<'scope, 'task, 'policy, IO>,
    adapter: String,
}

/// Snapshot taken after the matches were installed, with any changes retained.
/// Overlap means callers must reconcile affected objects before treating the
/// snapshot and queued changes as a current state.
pub struct WatchInventory {
    /// Claimed BlueZ adapter paths.
    pub adapter_paths: Vec<String>,
    /// Claimed Bluetooth device paths.
    pub device_paths: Vec<String>,
    /// Service UUID claims from the snapshot.
    pub device_claims: Vec<DeviceClaim>,
    /// Number of objects in the snapshot.
    pub objects: usize,
    /// Changes queued before the snapshot reply, including earlier changes.
    pub overlapping_changes: usize,
}
impl fmt::Debug for WatchInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchInventory")
            .field("adapter_count", &self.adapter_paths.len())
            .field("device_count", &self.device_paths.len())
            .field("objects", &self.objects)
            .field("overlapping_changes", &self.overlapping_changes)
            .finish()
    }
}

fn accept_change(frame: Vec<u8>, owner: &str) -> Result<ChangeFrame, Error> {
    let header = wire::parse_signal(&frame)
        .map_err(Error::Protocol)?
        .ok_or(Error::Protocol(wire::Error::Invalid))?;
    if header.consumed != frame.len() {
        return Err(Error::Protocol(wire::Error::Invalid));
    }
    // A name-owner notification terminates this epoch, including when its
    // body is malformed. Never continue using a potentially stale owner.
    if header.interface == "org.freedesktop.DBus" && header.member == "NameOwnerChanged" {
        return Err(Error::OwnerChanged);
    }
    signals::parse(
        &frame,
        &signals::Scope {
            owner,
            namespace: "/org/bluez",
            manager_path: "/",
        },
    )
    .map_err(Error::Signal)?;
    Ok(ChangeFrame(frame, None))
}

async fn watch_response<IO: AsyncRead + Unpin>(
    io: &mut IO,
    owner: &str,
    queued: &mut VecDeque<ChangeFrame>,
) -> Result<Vec<u8>, Error> {
    loop {
        let frame = message(io).await?;
        if frame[1] != 4 {
            return Ok(frame);
        }
        if queued.len() == MAX_QUEUED_CHANGES {
            return Err(Error::Limit);
        }
        let change = accept_change(frame, owner)?;
        queued.try_reserve(1).map_err(|_| Error::Limit)?;
        queued.push_back(change);
    }
}

/// Open a bounded, live subscription on an already admitted bus stream.
/// Signals interleaved with subscription replies are retained in wire order.
/// Initial hello signals precede the subscription and are not discovery data.
/// A current owner is resolved both before and after installing matches.
pub async fn open_watch<'scope, 'task, 'policy, IO: AsyncRead + AsyncWrite + Unpin>(
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    mut io: MeteredIo<'scope, 'task, IO>,
    admission: &'policy dyn Admission,
    uid: u32,
    wait: Duration,
) -> Result<Watch<'scope, 'task, 'policy, IO>, Error> {
    if wait.is_zero()
        || wait > MAX_WAIT
        || !clock.matches(task, cx)
        || !clock.same_mapping(&io.clock())
    {
        return Err(Error::Configuration);
    }
    let resource = io.resource().to_owned();
    let mut guarded = Guarded {
        io: &mut io,
        task,
        clock,
        admission,
        resource: &resource,
        stage: Stage::Authentication,
    };
    let exchange = async {
        guarded
            .write_all(&wire::external_request(uid))
            .await
            .map_err(io_error)?;
        guarded.flush().await.map_err(io_error)?;
        let mut line = Vec::new();
        line.try_reserve_exact(MAX_AUTH_BYTES)
            .map_err(|_| Error::Limit)?;
        loop {
            if wire::parse_auth_ok(&line)
                .map_err(Error::Protocol)?
                .is_some()
            {
                break;
            }
            if line.len() == MAX_AUTH_BYTES {
                return Err(Error::Limit);
            }
            let mut byte = [0u8; 1];
            read_exact(&mut guarded, &mut byte).await?;
            line.push(byte[0]);
        }
        guarded.write_all(wire::BEGIN).await.map_err(io_error)?;
        guarded.stage = Stage::Hello;
        guarded
            .write_all(&wire::hello(1).map_err(Error::Protocol)?)
            .await
            .map_err(io_error)?;
        guarded.flush().await.map_err(io_error)?;
        let mut skipped = 0;
        let frame = response(&mut guarded, &mut skipped).await?;
        let reply = wire::parse_hello_reply(&frame, 1)
            .map_err(Error::Protocol)?
            .ok_or(Error::Protocol(wire::Error::Invalid))?;
        if reply.consumed() != frame.len() {
            return Err(Error::Protocol(wire::Error::Invalid));
        }
        guarded.stage = Stage::BluezSubscribe;
        guarded
            .write_all(&wire::bluez_get_name_owner(2).map_err(Error::Protocol)?)
            .await
            .map_err(io_error)?;
        guarded.flush().await.map_err(io_error)?;
        let frame = response(&mut guarded, &mut skipped).await?;
        let reply = wire::parse_bluez_get_name_owner_reply(&frame, 2)
            .map_err(Error::Protocol)?
            .ok_or(Error::Protocol(wire::Error::Invalid))?;
        if reply.consumed() != frame.len() {
            return Err(Error::Protocol(wire::Error::Invalid));
        }
        let owner = reply.name().to_owned();
        let mut queued = VecDeque::new();
        for (serial, kind) in [
            (3, wire::BluezMatch::OwnerChange),
            (4, wire::BluezMatch::Interfaces),
            (5, wire::BluezMatch::Properties),
        ] {
            let request = wire::bluez_add_match(serial, &owner, "/org/bluez", "/", kind)
                .map_err(Error::Protocol)?;
            guarded.write_all(&request).await.map_err(io_error)?;
            guarded.flush().await.map_err(io_error)?;
            let frame = watch_response(&mut guarded, &owner, &mut queued).await?;
            if wire::parse_empty_method_reply(&frame, serial).map_err(Error::Protocol)?
                != Some(frame.len())
            {
                return Err(Error::Protocol(wire::Error::Invalid));
            }
        }
        guarded
            .write_all(&wire::bluez_get_name_owner(6).map_err(Error::Protocol)?)
            .await
            .map_err(io_error)?;
        guarded.flush().await.map_err(io_error)?;
        let frame = watch_response(&mut guarded, &owner, &mut queued).await?;
        let reply = wire::parse_bluez_get_name_owner_reply(&frame, 6)
            .map_err(Error::Protocol)?
            .ok_or(Error::Protocol(wire::Error::Invalid))?;
        if reply.consumed() != frame.len() || reply.name() != owner {
            return Err(Error::OwnerChanged);
        }
        guarded.check().map_err(io_error)?;
        Ok((owner, queued))
    };
    let (owner, queued) = timeout_at(cx.now() + wait, exchange)
        .await
        .map_err(|_| Error::Interrupted)??;
    Ok(Watch {
        cx,
        task,
        clock,
        io,
        admission,
        resource,
        owner,
        queued,
        next_serial: 7,
        device_state: DeviceLinkState::Unlinked,
        device_path: None,
        gatt_binding: None,
        gatt_stale: false,
        notification_state: NotificationState::Inactive,
        notification_epoch: None,
        next_notification_sequence: 0,
        framed_management_reservation: None,
    })
}

impl<'scope, 'task, 'policy, IO: AsyncRead + AsyncWrite + Unpin> Watch<'scope, 'task, 'policy, IO> {
    /// The admitted unique sender used when decoding a returned frame.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Number of already-received changes awaiting caller reconciliation.
    /// New signals can arrive at any time, including after this observation.
    pub fn pending_changes(&self) -> usize {
        self.queued.len()
    }

    /// Inspect the local device-operation state without exposing the device path.
    pub fn device_link_state(&self) -> DeviceLinkState {
        self.device_state
    }

    /// The exact caller-supplied path retained for an acknowledged or uncertain
    /// operation. The path is an untrusted identifier, not proof of identity.
    pub fn device_link_path(&self) -> Option<&str> {
        self.device_path.as_deref()
    }

    /// Local notification-session state; it is not a delivery guarantee.
    pub fn notification_state(&self) -> NotificationState {
        self.notification_state
    }

    /// Whether an observed change invalidated the selected GATT claims. Check
    /// this before consuming the just-returned frame as notification data.
    pub fn gatt_selection_stale(&self) -> bool {
        self.gatt_stale
    }

    /// Next local call serial, for preparing an exact effect binding. Another
    /// call may advance it before dispatch; the dispatcher rechecks it.
    pub fn next_gatt_serial(&self) -> u32 {
        self.next_serial
    }

    fn require_no_notifications(&self) -> Result<(), Error> {
        match self.notification_state {
            NotificationState::Inactive => Ok(()),
            NotificationState::Active => Err(Error::Configuration),
            NotificationState::Uncertain => Err(Error::NotificationUncertain),
        }
    }

    /// Select caller-specified GATT UUIDs from a correlated snapshot for the
    /// acknowledged device. The caller must drain and reconcile overlapping
    /// changes, and revalidate the selected paths before any subsequent use.
    /// Cancellation after submission fences the watch because D-Bus framing may
    /// be partial. This operation never connects or writes to the device.
    pub async fn select_gatt(
        &mut self,
        service_uuid: &str,
        notify_uuid: &str,
        write_uuid: &str,
        mode: object_manager::GattWriteMode,
        wait: Duration,
    ) -> Result<GattEndpoints, Error> {
        self.require_no_notifications()?;
        match self.device_state {
            DeviceLinkState::ConnectAcknowledged => {}
            DeviceLinkState::Uncertain => return Err(Error::DeviceUncertain),
            DeviceLinkState::Unlinked => return Err(Error::Configuration),
        }
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(Error::Configuration);
        }
        if !self.queued.is_empty() {
            return Err(Error::GattOverlap);
        }
        let device = self.device_path.as_deref().ok_or(Error::Configuration)?;
        let serial = self.next_serial;
        let next = serial.checked_add(1).ok_or(Error::Limit)?;
        let request =
            wire::bluez_managed_objects_for_owner(serial, &self.owner).map_err(Error::Protocol)?;
        let mut guarded = ScanGuarded {
            bus: Guarded {
                io: &mut self.io,
                task: self.task,
                clock: self.clock,
                admission: self.admission,
                resource: &self.resource,
                stage: Stage::BluezGattInventory,
            },
            adapter: device,
        };
        guarded.check().map_err(io_error)?;
        self.next_serial = next;
        self.gatt_binding = None;
        self.device_state = DeviceLinkState::Uncertain;
        let exchange = async {
            guarded
                .write_all(&request)
                .await
                .map_err(|_| Error::DeviceUncertain)?;
            guarded.flush().await.map_err(|_| Error::DeviceUncertain)?;
            let frame = watch_response(&mut guarded, &self.owner, &mut self.queued)
                .await
                .map_err(|_| Error::DeviceUncertain)?;
            let body = wire::parse_bluez_managed_objects_reply(&frame, serial)
                .map_err(|_| Error::DeviceUncertain)?
                .ok_or(Error::DeviceUncertain)?;
            if body.consumed != frame.len() || body.sender != Some(self.owner.as_str()) {
                return Err(Error::DeviceUncertain);
            }
            guarded.check().map_err(|_| Error::DeviceUncertain)?;
            Ok(frame)
        };
        let frame = timeout_at(self.cx.now() + wait, exchange)
            .await
            .map_err(|_| Error::DeviceUncertain)??;
        self.device_state = DeviceLinkState::ConnectAcknowledged;
        if !self.queued.is_empty() {
            return Err(Error::GattOverlap);
        }
        let body = wire::parse_bluez_managed_objects_reply(&frame, serial)
            .map_err(Error::Protocol)?
            .ok_or(Error::Protocol(wire::Error::Invalid))?;
        let endian = if body.little_endian {
            object_manager::Endian::Little
        } else {
            object_manager::Endian::Big
        };
        let snapshot = object_manager::parse_gatt_snapshot(body.body, endian, device)
            .map_err(Error::Inventory)?;
        let selected = snapshot
            .select(service_uuid, notify_uuid, write_uuid, mode)
            .map_err(Error::GattSelection)?;
        let copy = |value: &str| -> Result<String, Error> {
            let mut result = String::new();
            result
                .try_reserve_exact(value.len())
                .map_err(|_| Error::Limit)?;
            result.push_str(value);
            Ok(result)
        };
        let endpoints = GattEndpoints {
            service: copy(selected.service())?,
            notify: copy(selected.notify())?,
            write: copy(selected.write())?,
            mode,
        };
        self.gatt_binding = Some(GattEndpoints {
            service: copy(&endpoints.service)?,
            notify: copy(&endpoints.notify)?,
            write: copy(&endpoints.write)?,
            mode,
        });
        self.gatt_stale = false;
        Ok(endpoints)
    }

    /// Start notifications on the exact characteristic selected by this watch.
    /// The caller must reconcile intervening changes; a returned acknowledgment
    /// is not proof of camera identity or guaranteed delivery.
    pub async fn start_notify(
        &mut self,
        endpoints: &GattEndpoints,
        wait: Duration,
    ) -> Result<(), Error> {
        self.notify_call(endpoints, wire::NotifyMethod::Start, wait)
            .await
    }

    /// Stop the notification session explicitly. BlueZ sessions can be shared;
    /// this releases only the session associated with this call and bus client.
    pub async fn stop_notify(
        &mut self,
        endpoints: &GattEndpoints,
        wait: Duration,
    ) -> Result<(), Error> {
        self.notify_call(endpoints, wire::NotifyMethod::Stop, wait)
            .await
    }

    async fn notify_call(
        &mut self,
        endpoints: &GattEndpoints,
        method: wire::NotifyMethod,
        wait: Duration,
    ) -> Result<(), Error> {
        if self.device_state == DeviceLinkState::Uncertain {
            return Err(Error::DeviceUncertain);
        }
        if self.device_state != DeviceLinkState::ConnectAcknowledged
            || self.gatt_binding.as_ref() != Some(endpoints)
        {
            return Err(Error::Configuration);
        }
        if self.gatt_stale && method == wire::NotifyMethod::Start {
            return Err(Error::GattStale);
        }
        match (method, self.notification_state) {
            (_, NotificationState::Uncertain) => return Err(Error::NotificationUncertain),
            (wire::NotifyMethod::Start, NotificationState::Inactive) if self.queued.is_empty() => {}
            (wire::NotifyMethod::Start, NotificationState::Inactive) => {
                return Err(Error::GattOverlap);
            }
            (wire::NotifyMethod::Stop, NotificationState::Active) => {}
            _ => return Err(Error::Configuration),
        }
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(Error::Configuration);
        }
        let device = self.device_path.as_deref().ok_or(Error::Configuration)?;
        let serial = self.next_serial;
        let next = serial.checked_add(1).ok_or(Error::Limit)?;
        let request =
            wire::bluez_gatt_notify(serial, &self.owner, device, &endpoints.notify, method)
                .map_err(Error::Protocol)?;
        let stage = match method {
            wire::NotifyMethod::Start => Stage::BluezNotifyStart,
            wire::NotifyMethod::Stop => Stage::BluezNotifyStop,
        };
        let mut guarded = GattGuarded {
            device: ScanGuarded {
                bus: Guarded {
                    io: &mut self.io,
                    task: self.task,
                    clock: self.clock,
                    admission: self.admission,
                    resource: &self.resource,
                    stage,
                },
                adapter: device,
            },
            characteristic: &endpoints.notify,
        };
        guarded.check().map_err(io_error)?;
        self.next_serial = next;
        self.notification_state = NotificationState::Uncertain;
        let exchange = async {
            guarded
                .write_all(&request)
                .await
                .map_err(|_| Error::NotificationUncertain)?;
            guarded
                .flush()
                .await
                .map_err(|_| Error::NotificationUncertain)?;
            let frame = watch_response(&mut guarded, &self.owner, &mut self.queued)
                .await
                .map_err(|_| Error::NotificationUncertain)?;
            if wire::parse_empty_method_reply_from(&frame, serial, &self.owner)
                .map_err(|_| Error::NotificationUncertain)?
                != Some(frame.len())
            {
                return Err(Error::NotificationUncertain);
            }
            guarded.check().map_err(|_| Error::NotificationUncertain)?;
            Ok(())
        };
        timeout_at(self.cx.now() + wait, exchange)
            .await
            .map_err(|_| Error::NotificationUncertain)??;
        self.notification_state = match method {
            wire::NotifyMethod::Start => NotificationState::Active,
            wire::NotifyMethod::Stop => NotificationState::Inactive,
        };
        self.notification_epoch = match method {
            wire::NotifyMethod::Start => Some(Arc::new(())),
            wire::NotifyMethod::Stop => None,
        };
        self.next_notification_sequence = 0;
        if method == wire::NotifyMethod::Stop && self.gatt_stale {
            self.gatt_binding = None;
        }
        Ok(())
    }

    /// Receive one owner-scoped BlueZ change while notifications are active.
    /// Returns `None` only for a fully idle deadline. The caller must examine
    /// every change, check `gatt_selection_stale` before accepting its bytes,
    /// bind values to the selected characteristic, and preserve the frame and
    /// any unconsumed bytes. A related change is returned once, then further
    /// reads are fenced; explicit stop remains available. Cancellation fences
    /// this watch because a partial D-Bus frame may have been consumed.
    pub async fn next_notify_change(
        &mut self,
        endpoints: &GattEndpoints,
        wait: Duration,
    ) -> Result<Option<ChangeFrame>, Error> {
        if self.device_state == DeviceLinkState::Uncertain {
            return Err(Error::DeviceUncertain);
        }
        if self.device_state != DeviceLinkState::ConnectAcknowledged
            || self.gatt_binding.as_ref() != Some(endpoints)
        {
            return Err(Error::Configuration);
        }
        if self.notification_state == NotificationState::Uncertain {
            return Err(Error::NotificationUncertain);
        }
        if self.gatt_stale {
            return Err(Error::GattStale);
        }
        if self.notification_state != NotificationState::Active || wait.is_zero() || wait > MAX_WAIT
        {
            return Err(Error::Configuration);
        }
        let device = self.device_path.as_deref().ok_or(Error::Configuration)?;
        let mut guarded = GattGuarded {
            device: ScanGuarded {
                bus: Guarded {
                    io: &mut self.io,
                    task: self.task,
                    clock: self.clock,
                    admission: self.admission,
                    resource: &self.resource,
                    stage: Stage::BluezNotifyRead,
                },
                adapter: device,
            },
            characteristic: &endpoints.notify,
        };
        guarded.check().map_err(io_error)?;
        self.notification_state = NotificationState::Uncertain;
        if self.next_notification_sequence == u64::MAX {
            return Err(Error::Limit);
        }
        let mut change = if let Some(frame) = self.queued.pop_front() {
            Some(frame)
        } else {
            match message_or_idle(self.cx, &mut guarded, wait)
                .await
                .map_err(|_| Error::NotificationUncertain)?
            {
                None => None,
                Some(frame) if frame[1] == 4 => Some(
                    accept_change(frame, &self.owner).map_err(|_| Error::NotificationUncertain)?,
                ),
                Some(_) => return Err(Error::NotificationUncertain),
            }
        };
        if guarded.check().is_err() {
            if let Some(frame) = change {
                self.queued.push_front(frame);
            }
            return Err(Error::NotificationUncertain);
        }
        if let Some(frame) = &change {
            let event = frame
                .decode(&self.owner)
                .map_err(|_| Error::NotificationUncertain)?;
            self.gatt_stale = invalidates_gatt(&event, device, &endpoints.notify);
        }
        if let Some(frame) = &mut change {
            frame.1 = Some((
                Arc::clone(
                    self.notification_epoch
                        .as_ref()
                        .ok_or(Error::NotificationUncertain)?,
                ),
                self.next_notification_sequence,
            ));
            self.next_notification_sequence += 1;
        }
        self.notification_state = NotificationState::Active;
        Ok(change)
    }

    /// Send one separately committed and independently authorized management
    /// negotiation write. This does not authorize Wi-Fi provisioning or other
    /// settings, authenticate a device, or settle the effect. A dropped or
    /// interrupted future after the dispatch claim fences this watch and leaves
    /// the journaled obligation for reconciliation; it is never retried here.
    pub async fn dispatch_gatt_management(
        &mut self,
        endpoints: &GattEndpoints,
        plan: &gatt_management::Plan,
        current: gatt_management::Preconditions,
        permit: CommittedEffect,
        authority: &dyn GattManagementAuthority,
        wait: Duration,
    ) -> Result<GattManagementWrite, GattManagementRefusal> {
        self.dispatch_gatt_management_inner(
            endpoints,
            plan,
            current,
            permit,
            authority,
            GattDispatchOptions {
                wait,
                reservation: None,
            },
        )
        .await
    }

    async fn dispatch_gatt_management_inner(
        &mut self,
        endpoints: &GattEndpoints,
        plan: &gatt_management::Plan,
        current: gatt_management::Preconditions,
        mut permit: CommittedEffect,
        authority: &dyn GattManagementAuthority,
        options: GattDispatchOptions<'_>,
    ) -> Result<GattManagementWrite, GattManagementRefusal> {
        let GattDispatchOptions { wait, reservation } = options;
        macro_rules! refuse {
            ($reason:expr) => {
                return Err(GattManagementRefusal {
                    reason: $reason,
                    permit,
                })
            };
        }
        if !match (&self.framed_management_reservation, reservation) {
            (None, None) => true,
            (Some(active), Some(token)) => Arc::ptr_eq(active, token),
            _ => false,
        } {
            refuse!(GattManagementRefusalReason::Session);
        }
        if self.device_state != DeviceLinkState::ConnectAcknowledged
            || self.notification_state != NotificationState::Active
            || self.gatt_binding.as_ref() != Some(endpoints)
            || wait.is_zero()
            || wait > MAX_WAIT
            || !self.cx.has_timer()
        {
            refuse!(GattManagementRefusalReason::Session);
        }
        if self.gatt_stale || !self.queued.is_empty() {
            refuse!(GattManagementRefusalReason::Stale);
        }
        let Some(device) = self.device_path.as_deref() else {
            refuse!(GattManagementRefusalReason::Session);
        };
        if !plan.matches(
            self.next_serial,
            &self.owner,
            device,
            &endpoints.write,
            endpoints.mode,
        ) {
            refuse!(GattManagementRefusalReason::Session);
        }
        if !permit.journal_backed() {
            refuse!(GattManagementRefusalReason::JournalRequired);
        }
        if permit.prepared().effect_class() != gatt_management::EFFECT_CLASS
            || permit.prepared().request_digest() != plan.request_digest()
            || permit.prepared().precondition_digest() != plan.precondition_digest()
            || permit.resource() != plan.resource()
            || permit.fence() != plan.fence()
        {
            refuse!(GattManagementRefusalReason::PermitMismatch);
        }
        if plan.check_current(current).is_err()
            || self.cx.checkpoint().is_err()
            || !authority.permits(plan, current, &permit)
        {
            refuse!(GattManagementRefusalReason::Denied);
        }
        let serial = self.next_serial;
        let Some(next) = serial.checked_add(1) else {
            refuse!(GattManagementRefusalReason::Session);
        };
        let guarded = GattGuarded {
            device: ScanGuarded {
                bus: Guarded {
                    io: &mut self.io,
                    task: self.task,
                    clock: self.clock,
                    admission: self.admission,
                    resource: &self.resource,
                    stage: Stage::BluezManagementWrite,
                },
                adapter: device,
            },
            characteristic: &endpoints.write,
        };
        if guarded.check().is_err()
            || guarded
                .check_notification_access(&endpoints.notify)
                .is_err()
        {
            refuse!(GattManagementRefusalReason::Denied);
        }
        if !permit.try_claim_dispatch() {
            refuse!(GattManagementRefusalReason::PermitUsed);
        }
        self.next_serial = next;
        self.notification_state = NotificationState::Uncertain;
        let exchange = async {
            let mut guarded = GattManagementGuarded {
                io: guarded,
                notify: &endpoints.notify,
                cx: self.cx,
                plan,
                current,
                permit: &permit,
                authority,
            };
            guarded
                .write_all(plan.message_bytes())
                .await
                .map_err(|_| ())?;
            guarded.flush().await.map_err(|_| ())?;
            let frame = watch_response(&mut guarded, &self.owner, &mut self.queued)
                .await
                .map_err(|_| ())?;
            if wire::parse_empty_method_reply_from(&frame, serial, &self.owner).map_err(|_| ())?
                != Some(frame.len())
            {
                return Err(());
            }
            guarded.check().map_err(|_| ())?;
            Ok(())
        };
        match timeout_at(self.cx.now() + wait, exchange).await {
            Ok(Ok(())) => {
                self.notification_state = NotificationState::Active;
                Ok(GattManagementWrite::Acknowledged { permit })
            }
            _ => Ok(GattManagementWrite::Indeterminate { permit }),
        }
    }

    /// Ask BlueZ to connect one specifically admitted device. The watch remains
    /// caller-owned across cancellation; once a call might have been written,
    /// cancellation or an uncorrelated reply fences it as uncertain. A success
    /// is a BlueZ acknowledgment, not proof of identity or GATT readiness.
    /// This in-memory fence is not a durable journal or crash recovery.
    pub async fn connect_device(&mut self, device: &str, wait: Duration) -> Result<(), Error> {
        self.device_call(device, wire::DeviceMethod::Connect, wait)
            .await
    }

    /// Explicitly disconnect the same device after an acknowledged connect.
    /// BlueZ may disconnect other clients' profiles too; independent policy
    /// must authorize that effect. No automatic cleanup or retry is implied.
    pub async fn disconnect_device(&mut self, device: &str, wait: Duration) -> Result<(), Error> {
        self.device_call(device, wire::DeviceMethod::Disconnect, wait)
            .await
    }

    async fn device_call(
        &mut self,
        device: &str,
        method: wire::DeviceMethod,
        wait: Duration,
    ) -> Result<(), Error> {
        self.require_no_notifications()?;
        match (method, self.device_state) {
            (_, DeviceLinkState::Uncertain) => return Err(Error::DeviceUncertain),
            (wire::DeviceMethod::Connect, DeviceLinkState::Unlinked) => {}
            (wire::DeviceMethod::Disconnect, DeviceLinkState::ConnectAcknowledged)
                if self.device_path.as_deref() == Some(device) => {}
            _ => return Err(Error::Configuration),
        }
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(Error::Configuration);
        }
        let serial = self.next_serial;
        let next = serial.checked_add(1).ok_or(Error::Limit)?;
        let request = wire::bluez_device_connection(serial, &self.owner, device, method)
            .map_err(Error::Protocol)?;
        let stage = match method {
            wire::DeviceMethod::Connect => Stage::BluezDeviceConnect,
            wire::DeviceMethod::Disconnect => Stage::BluezDeviceDisconnect,
        };
        let mut saved_path = String::new();
        saved_path
            .try_reserve_exact(device.len())
            .map_err(|_| Error::Limit)?;
        saved_path.push_str(device);
        let mut guarded = ScanGuarded {
            bus: Guarded {
                io: &mut self.io,
                task: self.task,
                clock: self.clock,
                admission: self.admission,
                resource: &self.resource,
                stage,
            },
            adapter: device,
        };
        guarded.check().map_err(io_error)?;
        self.next_serial = next;
        self.device_path = Some(saved_path);
        self.gatt_binding = None;
        // Set this before the first awaited write so dropping the future cannot
        // make a partially submitted operation appear safe to retry.
        self.device_state = DeviceLinkState::Uncertain;
        let exchange = async {
            guarded
                .write_all(&request)
                .await
                .map_err(|_| Error::DeviceUncertain)?;
            guarded.flush().await.map_err(|_| Error::DeviceUncertain)?;
            let frame = watch_response(&mut guarded, &self.owner, &mut self.queued)
                .await
                .map_err(|_| Error::DeviceUncertain)?;
            if wire::parse_empty_method_reply_from(&frame, serial, &self.owner)
                .map_err(|_| Error::DeviceUncertain)?
                != Some(frame.len())
            {
                return Err(Error::DeviceUncertain);
            }
            guarded.check().map_err(|_| Error::DeviceUncertain)?;
            Ok(())
        };
        timeout_at(self.cx.now() + wait, exchange)
            .await
            .map_err(|_| Error::DeviceUncertain)??;
        match method {
            wire::DeviceMethod::Connect => self.device_state = DeviceLinkState::ConnectAcknowledged,
            wire::DeviceMethod::Disconnect => {
                self.device_state = DeviceLinkState::Unlinked;
                self.device_path = None;
            }
        }
        Ok(())
    }

    /// Start a scan only on an independently admitted adapter path. The caller
    /// must use the returned handle to stop the session on the same connection.
    /// Interruption after a call was attempted is reported as uncertain.
    pub async fn start_discovery(
        mut self,
        adapter: &str,
        wait: Duration,
    ) -> Result<Discovering<'scope, 'task, 'policy, IO>, Error> {
        self.require_no_notifications()?;
        if self.device_state == DeviceLinkState::Uncertain {
            return Err(Error::DeviceUncertain);
        }
        self.gatt_binding = None;
        let watch = self
            .discovery_call(adapter, wire::DiscoveryMethod::Start, wait)
            .await?;
        Ok(Discovering {
            watch,
            adapter: adapter.to_owned(),
        })
    }

    async fn discovery_call(
        mut self,
        adapter: &str,
        method: wire::DiscoveryMethod,
        wait: Duration,
    ) -> Result<Self, Error> {
        let stopping = method == wire::DiscoveryMethod::Stop;
        let fail = |error| {
            if stopping {
                Error::DiscoveryUncertain
            } else {
                error
            }
        };
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(fail(Error::Configuration));
        }
        let serial = self.next_serial;
        self.next_serial = serial.checked_add(1).ok_or_else(|| fail(Error::Limit))?;
        let request = wire::bluez_adapter_discovery(serial, &self.owner, adapter, method)
            .map_err(|e| fail(Error::Protocol(e)))?;
        let stage = if stopping {
            Stage::BluezDiscoveryStop
        } else {
            Stage::BluezDiscoveryStart
        };
        if !self.admission.permits(adapter, stage) {
            return Err(fail(Error::Denied));
        }
        let now = self.clock.now().map_err(|_| fail(Error::Interrupted))?;
        self.task
            .checkpoint_for(RuntimeGrant::AdapterNet, adapter, now, &BudgetVector::ZERO)
            .map_err(|_| fail(Error::Denied))?;
        let mut guarded = ScanGuarded {
            bus: Guarded {
                io: &mut self.io,
                task: self.task,
                clock: self.clock,
                admission: self.admission,
                resource: &self.resource,
                stage,
            },
            adapter,
        };
        guarded.check().map_err(|e| fail(io_error(e)))?;
        let exchange = async {
            guarded
                .write_all(&request)
                .await
                .map_err(|_| Error::DiscoveryUncertain)?;
            guarded
                .flush()
                .await
                .map_err(|_| Error::DiscoveryUncertain)?;
            let frame = watch_response(&mut guarded, &self.owner, &mut self.queued)
                .await
                .map_err(|_| Error::DiscoveryUncertain)?;
            if wire::parse_empty_method_reply_from(&frame, serial, &self.owner)
                .map_err(|_| Error::DiscoveryUncertain)?
                != Some(frame.len())
            {
                return Err(Error::DiscoveryUncertain);
            }
            guarded.check().map_err(|_| Error::DiscoveryUncertain)?;
            Ok(())
        };
        timeout_at(self.cx.now() + wait, exchange)
            .await
            .map_err(|_| Error::DiscoveryUncertain)??;
        Ok(self)
    }

    /// Request the baseline on this subscribed connection. The unique owner is
    /// both the destination and required sender; interleaved changes are kept.
    /// An overlap is explicit because snapshot and changes may describe the
    /// same mutation and must not be blindly replayed as an ordered delta.
    pub async fn inventory(mut self, wait: Duration) -> Result<(Self, WatchInventory), Error> {
        self.require_no_notifications()?;
        if self.device_state == DeviceLinkState::Uncertain {
            return Err(Error::DeviceUncertain);
        }
        self.gatt_binding = None;
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(Error::Configuration);
        }
        let serial = self.next_serial;
        self.next_serial = serial.checked_add(1).ok_or(Error::Limit)?;
        let mut guarded = Guarded {
            io: &mut self.io,
            task: self.task,
            clock: self.clock,
            admission: self.admission,
            resource: &self.resource,
            stage: Stage::BluezInventory,
        };
        let exchange = async {
            let request = wire::bluez_managed_objects_for_owner(serial, &self.owner)
                .map_err(Error::Protocol)?;
            guarded.write_all(&request).await.map_err(io_error)?;
            guarded.flush().await.map_err(io_error)?;
            let frame = watch_response(&mut guarded, &self.owner, &mut self.queued).await?;
            let body = wire::parse_bluez_managed_objects_reply(&frame, serial)
                .map_err(Error::Protocol)?
                .ok_or(Error::Protocol(wire::Error::Invalid))?;
            if body.consumed != frame.len() || body.sender != Some(self.owner.as_str()) {
                return Err(Error::Protocol(wire::Error::Invalid));
            }
            let parsed = parse_inventory(body)?;
            guarded.check().map_err(io_error)?;
            Ok(WatchInventory {
                adapter_paths: parsed.adapter_paths,
                device_paths: parsed.device_paths,
                device_claims: parsed.device_claims,
                objects: parsed.objects,
                overlapping_changes: self.queued.len(),
            })
        };
        let inventory = timeout_at(self.cx.now() + wait, exchange)
            .await
            .map_err(|_| Error::Interrupted)??;
        Ok((self, inventory))
    }

    /// Consume the session and return it with the next ordered change.
    /// On timeout, cancellation, revocation, owner change or any protocol
    /// failure, the stream is dropped: a partial frame is never retried.
    pub async fn next_change(mut self, wait: Duration) -> Result<(Self, ChangeFrame), Error> {
        self.require_no_notifications()?;
        if self.device_state == DeviceLinkState::Uncertain {
            return Err(Error::DeviceUncertain);
        }
        self.gatt_binding = None;
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(Error::Configuration);
        }
        let mut guarded = Guarded {
            io: &mut self.io,
            task: self.task,
            clock: self.clock,
            admission: self.admission,
            resource: &self.resource,
            stage: Stage::BluezWatch,
        };
        guarded.check().map_err(io_error)?;
        let change = if let Some(frame) = self.queued.pop_front() {
            frame
        } else {
            let frame = timeout_at(self.cx.now() + wait, message(&mut guarded))
                .await
                .map_err(|_| Error::Interrupted)??;
            if frame[1] != 4 {
                return Err(Error::Protocol(wire::Error::Invalid));
            }
            accept_change(frame, &self.owner)?
        };
        guarded.check().map_err(io_error)?;
        Ok((self, change))
    }
}

impl<'scope, 'task, 'policy, IO: AsyncRead + AsyncWrite + Unpin>
    Discovering<'scope, 'task, 'policy, IO>
{
    /// The unique BlueZ sender associated with this discovery session.
    pub fn owner(&self) -> &str {
        &self.watch.owner
    }

    /// Wait for one ordered change, returning `None` on an idle deadline only
    /// if no frame byte was consumed. This keeps the scan available for stop.
    /// Any uncertain frame or lost authority retires it with an uncertain
    /// discovery outcome, never as a successful idle period.
    pub async fn next_change(
        mut self,
        wait: Duration,
    ) -> Result<(Self, Option<ChangeFrame>), Error> {
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(Error::DiscoveryUncertain);
        }
        let watch = &mut self.watch;
        let mut guarded = ScanGuarded {
            bus: Guarded {
                io: &mut watch.io,
                task: watch.task,
                clock: watch.clock,
                admission: watch.admission,
                resource: &watch.resource,
                stage: Stage::BluezWatch,
            },
            adapter: &self.adapter,
        };
        guarded.check().map_err(|_| Error::DiscoveryUncertain)?;
        let change = if let Some(frame) = watch.queued.pop_front() {
            Some(frame)
        } else {
            match message_or_idle(watch.cx, &mut guarded, wait)
                .await
                .map_err(|_| Error::DiscoveryUncertain)?
            {
                None => None,
                Some(frame) if frame[1] == 4 => Some(
                    accept_change(frame, &watch.owner).map_err(|_| Error::DiscoveryUncertain)?,
                ),
                Some(_) => return Err(Error::DiscoveryUncertain),
            }
        };
        guarded.check().map_err(|_| Error::DiscoveryUncertain)?;
        Ok((self, change))
    }

    /// Release exactly this connection's scan session and verify its reply.
    /// If cleanup cannot be verified, return `DiscoveryUncertain`.
    pub async fn stop(self, wait: Duration) -> Result<Watch<'scope, 'task, 'policy, IO>, Error> {
        self.watch
            .discovery_call(&self.adapter, wire::DiscoveryMethod::Stop, wait)
            .await
    }
}
