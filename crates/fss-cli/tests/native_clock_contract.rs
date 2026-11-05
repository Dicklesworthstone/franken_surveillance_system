#![forbid(unsafe_code)]
//! Native local-daemon ownership, exact-datagram and permanent-stop contracts.

use std::cell::Cell;
use std::error::Error;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fss_cli::native_clock::{
    ClockIo, ERR_NATIVE_CLOCK_CLOSED, ERR_NATIVE_CLOCK_CONTINUITY, ERR_NATIVE_CLOCK_DEADLINE,
    ERR_NATIVE_CLOCK_PROOF, ERR_NATIVE_CLOCK_REPLY, MAX_NETWORK_BYTES, MAX_RECEIVE_POLLS,
    SynchronizedClock,
};

type Test<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const DENIED: &str = "fixture-clock-authority-revoked";
const OFFSET_NS: u64 = 2_000_000_000;
const OWNER_DEADLINE_NS: u64 = 120_000_000_000;

struct Owner {
    start: Instant,
    denied: Cell<bool>,
    shift_ns: Cell<u64>,
    bytes: Cell<u64>,
    waits: Cell<u64>,
    frozen: bool,
}

impl Owner {
    fn new(frozen: bool) -> Self {
        Self {
            start: Instant::now(),
            denied: Cell::new(false),
            shift_ns: Cell::new(0),
            bytes: Cell::new(0),
            waits: Cell::new(0),
            frozen,
        }
    }
    fn admit(&self) -> Result<(), &'static str> {
        if self.denied.get() {
            return Err(DENIED);
        }
        Ok(())
    }
}

impl ClockIo for Owner {
    fn now(&self) -> Result<u64, &'static str> {
        self.admit()?;
        if self.frozen {
            return Ok(0);
        }
        u64::try_from(self.start.elapsed().as_nanos())
            .ok()
            .and_then(|now| now.checked_add(self.shift_ns.get()))
            .ok_or("fixture monotonic overflow")
    }
    fn network_admit(&self) -> Result<(), &'static str> {
        self.admit()
    }
    fn network_bytes(&self, bytes: u64) -> Result<(), &'static str> {
        let total = self.bytes.get() + bytes;
        self.bytes.set(total);
        self.admit()?;
        if total > MAX_NETWORK_BYTES {
            return Err("fixture UDP allowance exceeded");
        }
        Ok(())
    }
    fn wait(&self, deadline_ns: u64) -> Result<(), &'static str> {
        self.admit()?;
        self.waits.set(self.waits.get() + 1);
        if !self.frozen {
            let now = self.now()?;
            thread::sleep(Duration::from_nanos(
                deadline_ns.saturating_sub(now).min(1_000_000),
            ));
            self.admit()?;
        }
        Ok(())
    }
}

struct NoIo;
impl ClockIo for NoIo {
    fn now(&self) -> Result<u64, &'static str> {
        panic!("closed or poisoned clock read its owner")
    }
    fn network_admit(&self) -> Result<(), &'static str> {
        panic!("unexpected network authority request")
    }
    fn network_bytes(&self, _: u64) -> Result<(), &'static str> {
        panic!("unexpected UDP payload accounting")
    }
    fn wait(&self, _: u64) -> Result<(), &'static str> {
        panic!("unexpected wait")
    }
}

fn unix_now() -> Test<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    )?)
}

// Independent server-side wire encoder; no request/evaluation helper is used to
// manufacture the evidence that the native client is expected to accept.
fn timestamp(unix_ns: u64) -> [u8; 8] {
    let seconds = (unix_ns / 1_000_000_000 + 2_208_988_800) as u32;
    let fraction = ((u128::from(unix_ns % 1_000_000_000) << 32) / 1_000_000_000) as u32;
    let mut bytes = [0; 8];
    bytes[..4].copy_from_slice(&seconds.to_be_bytes());
    bytes[4..].copy_from_slice(&fraction.to_be_bytes());
    bytes
}

#[derive(Clone, Copy)]
enum Reply {
    Valid,
    WrongOrigin,
    PendingLeap,
    Truncated,
    Oversized,
}

struct Wire {
    request: [u8; 48],
    reply: Vec<u8>,
}

fn no_request(socket: &UdpSocket) -> Test {
    socket.set_nonblocking(true)?;
    match socket.recv_from(&mut [0; 128]) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("unexpected request or automatic retry".into()),
    }
}

fn daemon(socket: &UdpSocket, behavior: Reply) -> Test<Wire> {
    let mut request = [0; 49];
    let (length, sender) = socket.recv_from(&mut request)?;
    let received = unix_now()? + OFFSET_NS;
    assert_eq!(length, 48);
    assert_eq!(request[0], 0x23);
    assert!(request[1..40].iter().all(|byte| *byte == 0));
    let request: [u8; 48] = request[..length].try_into()?;
    let mut reply = vec![0; 48];
    reply[0] = 0x24;
    reply[1] = 2;
    reply[2] = 4;
    reply[3] = (-20_i8) as u8;
    reply[11] = 1; // One unsigned 16.16 root-dispersion unit.
    reply[12..16].copy_from_slice(b"LOCL");
    reply[16..24].copy_from_slice(&timestamp(received - 1_000_000_000));
    reply[24..32].copy_from_slice(&request[40..48]);
    reply[32..40].copy_from_slice(&timestamp(received));
    reply[40..48].copy_from_slice(&timestamp(unix_now()? + OFFSET_NS));
    match behavior {
        Reply::Valid => {}
        Reply::WrongOrigin => reply[31] ^= 1,
        Reply::PendingLeap => reply[0] |= 0x40,
        Reply::Truncated => reply.truncate(47),
        Reply::Oversized => reply.extend_from_slice(&[0; 96]),
    }
    assert_eq!(socket.send_to(&reply, sender)?, reply.len());
    Ok(Wire { request, reply })
}

fn exchange(
    owner: &Owner,
    behavior: Reply,
) -> Test<(Result<SynchronizedClock, &'static str>, Wire)> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    let peer = socket.local_addr()?;
    thread::scope(|scope| {
        let server = scope.spawn(|| daemon(&socket, behavior));
        let clock = SynchronizedClock::begin(peer, OWNER_DEADLINE_NS, owner);
        let wire = server.join().map_err(|_| "time fixture panicked")??;
        no_request(&socket)?;
        Ok((clock, wire))
    })
}

#[test]
fn one_real_exchange_uses_the_owner_epoch_and_preserves_exact_evidence() -> Test {
    let owner = Owner::new(false);
    let (clock, wire) = exchange(&owner, Reply::Valid)?;
    let mut clock = clock?;
    let retained = clock.exchange();
    assert_eq!(retained.request, wire.request);
    assert_eq!(retained.reply.as_slice(), wire.reply.as_slice());
    assert_eq!(owner.bytes.get(), 96);
    let correlation = retained.correlation()?;
    assert!(correlation.offset_interval().lower_ns <= OFFSET_NS as i64);
    assert!(correlation.offset_interval().upper_ns >= OFFSET_NS as i64);
    let intermediate = clock.sample(&owner)?;
    let terminal = clock.finish(&owner)?;
    assert!(intermediate.monotonic_after_ns <= terminal.monotonic_before_ns);
    let mut replay = retained.correlation()?;
    replay.observe_later_sample(intermediate)?;
    replay.observe_later_sample(terminal)?;
    assert!(replay.project(intermediate.monotonic_after_ns).is_ok());
    assert_eq!(clock.sample(&NoIo), Err(ERR_NATIVE_CLOCK_CLOSED));
    assert_eq!(clock.finish(&NoIo), Err(ERR_NATIVE_CLOCK_CLOSED));
    assert_eq!(clock.exchange(), retained);
    Ok(())
}

#[test]
fn authority_epoch_and_deadline_failures_poison_without_any_later_io() -> Test {
    for failure in 0..3 {
        let owner = Owner::new(false);
        let (clock, _) = exchange(&owner, Reply::Valid)?;
        let mut clock = clock?;
        let expected = match failure {
            0 => {
                owner.denied.set(true);
                DENIED
            }
            1 => {
                // Change the supplied monotonic epoch without changing the wall
                // clock. Such samples must not rebase the retained correlation.
                owner.shift_ns.set(1_000_000_000);
                ERR_NATIVE_CLOCK_CONTINUITY
            }
            _ => {
                owner.shift_ns.set(OWNER_DEADLINE_NS);
                ERR_NATIVE_CLOCK_DEADLINE
            }
        };
        assert_eq!(clock.sample(&owner), Err(expected));
        assert_eq!(clock.sample(&NoIo), Err(expected));
        assert_eq!(clock.finish(&NoIo), Err(expected));
        assert_eq!(owner.bytes.get(), 96);
    }
    Ok(())
}

#[test]
fn malformed_datagrams_end_the_single_exchange_without_retry() -> Test {
    for (behavior, expected, bytes) in [
        (Reply::WrongOrigin, ERR_NATIVE_CLOCK_PROOF, 96),
        (Reply::PendingLeap, ERR_NATIVE_CLOCK_PROOF, 96),
        (Reply::Truncated, ERR_NATIVE_CLOCK_REPLY, 95),
        (Reply::Oversized, ERR_NATIVE_CLOCK_REPLY, MAX_NETWORK_BYTES),
    ] {
        let owner = Owner::new(false);
        let (result, _) = exchange(&owner, behavior)?;
        assert_eq!(result.err(), Some(expected));
        assert_eq!(owner.bytes.get(), bytes);
    }
    Ok(())
}

#[test]
fn invalid_peer_and_revoked_authority_never_send_a_request() -> Test {
    for peer in ["192.0.2.1:123", "127.0.0.1:0", "[::ffff:127.0.0.1]:123"] {
        let peer: SocketAddr = peer.parse()?;
        assert_eq!(
            SynchronizedClock::begin(peer, OWNER_DEADLINE_NS, &NoIo).err(),
            Some(ERR_NATIVE_CLOCK_PROOF)
        );
    }
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let owner = Owner::new(false);
    owner.denied.set(true);
    assert_eq!(
        SynchronizedClock::begin(socket.local_addr()?, OWNER_DEADLINE_NS, &owner).err(),
        Some(DENIED)
    );
    no_request(&socket)?;
    owner.denied.set(false);
    assert_eq!(
        SynchronizedClock::begin(socket.local_addr()?, 0, &owner).err(),
        Some(ERR_NATIVE_CLOCK_DEADLINE)
    );
    no_request(&socket)?;
    assert_eq!(owner.bytes.get(), 0);
    Ok(())
}

#[test]
fn even_a_nonadvancing_owner_cannot_remove_the_receive_poll_bound() -> Test {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let owner = Owner::new(true);
    assert_eq!(
        SynchronizedClock::begin(socket.local_addr()?, OWNER_DEADLINE_NS, &owner).err(),
        Some(ERR_NATIVE_CLOCK_DEADLINE)
    );
    assert_eq!(owner.waits.get(), MAX_RECEIVE_POLLS);
    assert_eq!(owner.bytes.get(), 48);
    socket.set_nonblocking(true)?;
    let (length, _) = socket.recv_from(&mut [0; 49])?;
    assert_eq!(length, 48);
    no_request(&socket)?;
    Ok(())
}

#[test]
fn post_send_revocation_preserves_the_accepted_payload_charge_without_retry() -> Test {
    struct RevokeAfterSend {
        owner: Owner,
        network_checks: Cell<u64>,
    }
    impl ClockIo for RevokeAfterSend {
        fn now(&self) -> Result<u64, &'static str> {
            self.owner.now()
        }
        fn network_admit(&self) -> Result<(), &'static str> {
            let calls = self.network_checks.get() + 1;
            self.network_checks.set(calls);
            // Bind, connect and nonblocking each have pre/post admission; the
            // next two checks bracket the one actual request transmission.
            if calls == 8 {
                self.owner.denied.set(true);
            }
            self.owner.network_admit()
        }
        fn network_bytes(&self, bytes: u64) -> Result<(), &'static str> {
            self.owner.network_bytes(bytes)
        }
        fn wait(&self, _: u64) -> Result<(), &'static str> {
            panic!("post-send denial must not poll or retry")
        }
    }
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let owner = RevokeAfterSend {
        owner: Owner::new(false),
        network_checks: Cell::new(0),
    };
    assert_eq!(
        SynchronizedClock::begin(socket.local_addr()?, OWNER_DEADLINE_NS, &owner).err(),
        Some(DENIED)
    );
    assert_eq!(owner.network_checks.get(), 8);
    assert_eq!(owner.owner.bytes.get(), 48);
    socket.set_nonblocking(true)?;
    let mut request = [0; 49];
    let (length, _) = socket.recv_from(&mut request)?;
    assert_eq!(length, 48);
    assert_eq!(request[0], 0x23);
    no_request(&socket)?;
    Ok(())
}
