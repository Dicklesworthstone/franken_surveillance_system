#![forbid(unsafe_code)]
//! Bounded cached-neighbor hints for owner-scoped UniFi discovery.
//!
//! Cache entries are unauthenticated hints and cannot establish device identity
//! or network absence. The caller supplies an interface and subnet, and must
//! separately authenticate each candidate before sending credentials or effects.

use super::super::metered::MeteredClock;
use asupersync::Cx;
use fss_core::{BudgetVector, RuntimeGrant};
use fss_runtime::execution::TaskCx;
use std::{
    collections::BTreeSet,
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
};

const MAX_BYTES: usize = 128 * 1024;
const MAX_WINDOWS: usize = 4;
const HOSTS_PER_WINDOW: usize = 62;

/// Bounded neighbor-cache or query-plan refusal without source addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Scope, interface, packet port, or address is invalid.
    Configuration,
    /// The explicit task or runtime denied this observation.
    Authority,
    /// The platform does not expose the supported neighbor cache.
    Unavailable,
    /// Local I/O, allocation, or encoding failed.
    Input,
    /// Input or planned queries exceed the finite bound.
    Limit,
    /// The worker did not complete or its outcome is unknown.
    Worker,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "neighbor discovery refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Explicit interface/subnet and UDP port; this grants no network authority.
#[derive(Clone, Copy, Debug)]
pub struct Scope {
    bind: Ipv4Addr,
    mask: u32,
    port: u16,
}
impl Scope {
    /// Require a subnet contained entirely in a private or link-local range.
    pub fn new(bind: Ipv4Addr, prefix: u8, port: u16) -> Result<Self, Error> {
        if !(1..=30).contains(&prefix) || port == 0 || !(bind.is_private() || bind.is_link_local())
        {
            return Err(Error::Configuration);
        }
        let mask = u32::MAX << (32 - prefix);
        let network = u32::from(bind) & mask;
        // Checking only the bind address is insufficient: a broad prefix can
        // include public addresses, and its directed broadcast can leave the
        // owner's local address range. Require the entire subnet to fit.
        let local_ranges = [
            (u32::from(Ipv4Addr::new(10, 0, 0, 0)), 8),
            (u32::from(Ipv4Addr::new(172, 16, 0, 0)), 12),
            (u32::from(Ipv4Addr::new(192, 168, 0, 0)), 16),
            (u32::from(Ipv4Addr::new(169, 254, 0, 0)), 16),
        ];
        if !local_ranges.into_iter().any(|(base, range_prefix)| {
            prefix >= range_prefix && network & (u32::MAX << (32 - range_prefix)) == base
        }) {
            return Err(Error::Configuration);
        }
        let host = u32::from(bind) & !mask;
        if host == 0 || host == !mask {
            return Err(Error::Configuration);
        }
        Ok(Self { bind, mask, port })
    }
    fn host(self, address: Ipv4Addr) -> bool {
        let bits = u32::from(address);
        (address.is_private() || address.is_link_local())
            && address != self.bind
            && bits & self.mask == u32::from(self.bind) & self.mask
            && bits & !self.mask != 0
            && bits & !self.mask != !self.mask
    }
}
fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

/// Parse complete neighbor hints from one selected interface; duplicates collapse.
pub fn parse(input: &str, interface: &str, scope: Scope) -> Result<Vec<Ipv4Addr>, Error> {
    if !valid_interface(interface) {
        return Err(Error::Configuration);
    }
    if input.len() > MAX_BYTES {
        return Err(Error::Limit);
    }
    let mut lines = input.lines();
    if !lines
        .next()
        .is_some_and(|line| line.starts_with("IP address"))
    {
        return Err(Error::Input);
    }
    let mut hosts = BTreeSet::new();
    for line in lines {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 6 {
            return Err(Error::Input);
        }
        if fields[5] != interface {
            continue;
        }
        let flags = fields[2]
            .strip_prefix("0x")
            .and_then(|x| u32::from_str_radix(x, 16).ok())
            .ok_or(Error::Input)?;
        if flags & 2 == 0 {
            continue;
        }
        let address: Ipv4Addr = fields[0].parse().map_err(|_| Error::Input)?;
        if scope.host(address) {
            hosts.insert(address);
        }
        if hosts.len() > MAX_WINDOWS * HOSTS_PER_WINDOW {
            return Err(Error::Limit);
        }
    }
    Ok(hosts.into_iter().collect())
}

/// Plan bounded broadcast and unicast windows without silently dropping hints.
pub fn plans(
    scope: Scope,
    neighbors: &[Ipv4Addr],
    hint: Option<Ipv4Addr>,
) -> Result<Vec<Vec<SocketAddrV4>>, Error> {
    let mut hosts = BTreeSet::new();
    if let Some(address) = hint {
        if !scope.host(address) {
            return Err(Error::Configuration);
        }
        hosts.insert(address);
    }
    for &address in neighbors {
        if !scope.host(address) {
            return Err(Error::Configuration);
        }
        hosts.insert(address);
        if hosts.len() > MAX_WINDOWS * HOSTS_PER_WINDOW {
            return Err(Error::Limit);
        }
    }
    let hosts: Vec<_> = hosts.into_iter().collect();
    let count = hosts.len().div_ceil(HOSTS_PER_WINDOW).max(1);
    if count > MAX_WINDOWS {
        return Err(Error::Limit);
    }
    let directed = Ipv4Addr::from(u32::from(scope.bind) | !scope.mask);
    let mut plans = Vec::new();
    for i in 0..count {
        let mut targets = vec![
            SocketAddrV4::new(directed, scope.port),
            SocketAddrV4::new(Ipv4Addr::BROADCAST, scope.port),
        ];
        let from = i * HOSTS_PER_WINDOW;
        let to = (from + HOSTS_PER_WINDOW).min(hosts.len());
        targets.extend(
            hosts[from..to]
                .iter()
                .map(|address| SocketAddrV4::new(*address, scope.port)),
        );
        plans.push(targets);
    }
    Ok(plans)
}

/// Read complete cached neighbors in a task-owned blocking operation and drain it.
#[cfg(target_os = "linux")]
pub async fn read<'scope, 'task>(
    owner: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    resource: &str,
    interface: &str,
    scope: Scope,
) -> Result<Vec<Ipv4Addr>, Error> {
    use fss_runtime::drained_blocking::{self, WorkOutcome};
    use std::io::Read;
    if !clock.matches(owner, cx) || !valid_interface(interface) {
        return Err(Error::Configuration);
    }
    cx.checkpoint().map_err(|_| Error::Authority)?;
    let cost = BudgetVector::builder()
        .bytes((MAX_BYTES + 1) as u64)
        .build()
        .map_err(|_| Error::Configuration)?;
    owner
        .checkpoint_for(
            RuntimeGrant::AdapterNet,
            resource,
            clock.now().map_err(|_| Error::Authority)?,
            &cost,
        )
        .map_err(|_| Error::Authority)?;
    let interface = interface.to_owned();
    let work = move |child: Cx| {
        child.checkpoint().map_err(|_| Error::Authority)?;
        let file = std::fs::File::open("/proc/net/arp").map_err(|_| Error::Unavailable)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_BYTES + 1)
            .map_err(|_| Error::Input)?;
        file.take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Input)?;
        child.checkpoint().map_err(|_| Error::Authority)?;
        if bytes.len() > MAX_BYTES {
            return Err(Error::Limit);
        }
        parse(
            std::str::from_utf8(&bytes).map_err(|_| Error::Input)?,
            &interface,
            scope,
        )
    };
    let mut worker = drained_blocking::start(cx, work).map_err(|_| Error::Worker)?;
    let receipt = worker.join().await.ok_or(Error::Worker)?;
    if receipt.runtime.is_err() {
        return Err(Error::Worker);
    }
    owner
        .checkpoint_for(
            RuntimeGrant::AdapterNet,
            resource,
            clock.now().map_err(|_| Error::Authority)?,
            &BudgetVector::ZERO,
        )
        .map_err(|_| Error::Authority)?;
    match receipt.work {
        WorkOutcome::Finished(result) => result,
        _ => Err(Error::Worker),
    }
}

/// Other platforms have no supported native cache implementation here.
#[cfg(not(target_os = "linux"))]
pub async fn read<'scope, 'task>(
    _: &'scope TaskCx<'task>,
    _: &'scope Cx,
    _: MeteredClock<'scope, 'task>,
    _: &str,
    _: &str,
    _: Scope,
) -> Result<Vec<Ipv4Addr>, Error> {
    Err(Error::Unavailable)
}
