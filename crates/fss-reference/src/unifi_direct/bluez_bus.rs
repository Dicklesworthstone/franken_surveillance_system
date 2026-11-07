#![forbid(unsafe_code)]
//! Task-owned, read-only local D-Bus and BlueZ inventory observations.
//!
//! The caller supplies an already connected, independently admitted local bus
//! stream. An optional read-only snapshot can report untrusted adapter paths.
//! It does not start discovery, contact cameras, establish Bluetooth identity,
//! or configure Wi-Fi. One-shot observations retire the stream; a watch holds
//! it until the caller drops it or an operation fails.

use super::metered::{MeteredClock, MeteredIo};
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::timeout_at,
};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_packet::{
    dbus_bluez_signal as signals, dbus_handshake as wire, dbus_object_manager as object_manager,
};
use fss_runtime::execution::TaskCx;
use std::{
    collections::VecDeque,
    fmt, io,
    pin::Pin,
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
}

/// Independently authorized local bus policy. It must bind the connected socket
/// and resource to the intended local bus and remain bounded and nonblocking.
pub trait Admission {
    /// Revalidate the exact operation on every transport poll.
    fn permits(&self, resource: &str, stage: Stage) -> bool;
}

/// Payload-free refusal. Every error retires the connection.
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
pub struct ChangeFrame(Vec<u8>);
#[cfg(test)]
pub(super) fn test_change_frame(bytes: Vec<u8>) -> ChangeFrame {
    ChangeFrame(bytes)
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

/// A task-owned signal subscription. Dropping it closes the connection and
/// releases its bus matches. No snapshot or active Bluetooth scan is implied.
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
    Ok(ChangeFrame(frame))
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
    })
}

impl<'scope, 'task, 'policy, IO: AsyncRead + AsyncWrite + Unpin> Watch<'scope, 'task, 'policy, IO> {
    /// The admitted unique sender used when decoding a returned frame.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Start a scan only on an independently admitted adapter path. The caller
    /// must use the returned handle to stop the session on the same connection.
    /// Interruption after a call was attempted is reported as uncertain.
    pub async fn start_discovery(
        self,
        adapter: &str,
        wait: Duration,
    ) -> Result<Discovering<'scope, 'task, 'policy, IO>, Error> {
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
