#![forbid(unsafe_code)]
//! Read-only diagnostic for one local-bus NameAcquired signal.
#[allow(dead_code)]
#[path = "../dbus_handshake.rs"]
mod wire;
use std::{
    error::Error,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    time::Duration,
};
fn message(bus: &mut UnixStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut header = [0; 16];
    bus.read_exact(&mut header)?;
    let total = wire::declared_message_len(&header)?.ok_or("short header")?;
    let mut frame = header.to_vec();
    frame.resize(total, 0);
    bus.read_exact(&mut frame[16..])?;
    Ok(frame)
}
fn main() -> Result<(), Box<dyn Error>> {
    let uid = std::fs::metadata("/proc/self")?.uid();
    let mut bus = UnixStream::connect("/run/dbus/system_bus_socket")?;
    bus.set_read_timeout(Some(Duration::from_secs(4)))?;
    bus.set_write_timeout(Some(Duration::from_secs(4)))?;
    bus.write_all(&wire::external_request(uid))?;
    let mut line = Vec::new();
    while wire::parse_auth_ok(&line)?.is_none() {
        if line.len() >= 128 {
            return Err("auth bound".into());
        }
        let mut byte = [0];
        bus.read_exact(&mut byte)?;
        line.push(byte[0]);
    }
    bus.write_all(wire::BEGIN)?;
    bus.write_all(&wire::hello(1)?)?;
    bus.write_all(&wire::bluez_name_has_owner(2)?)?;
    let mut hello = false;
    let mut signal = false;
    let mut owner = false;
    for _ in 0..8 {
        let frame = message(&mut bus)?;
        match frame[1] {
            4 => {
                let event = wire::parse_signal(&frame)?.ok_or("incomplete signal")?;
                if event.consumed != frame.len() {
                    return Err("signal boundary".into());
                }
                if event.interface == "org.freedesktop.DBus"
                    && event.member == "NameAcquired"
                    && event.signature == b"s"
                {
                    signal = true;
                }
            }
            2 => {
                if !hello && wire::parse_hello_reply(&frame, 1).is_ok() {
                    hello = true;
                } else {
                    let parsed =
                        wire::parse_bluez_owner_reply(&frame, 2)?.ok_or("owner incomplete")?;
                    owner = parsed.present;
                }
            }
            _ => return Err("unexpected frame".into()),
        }
        if hello && signal && owner {
            break;
        }
    }
    if !(hello && signal && owner) {
        return Err("expected observations missing".into());
    }
    println!(
        "signal_header_live=passed bus_signal=NameAcquired bluez_owner=true scan_calls=none camera_calls=none"
    );
    Ok(())
}
