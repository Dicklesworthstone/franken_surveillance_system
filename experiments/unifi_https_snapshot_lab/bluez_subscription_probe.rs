#![forbid(unsafe_code)]
//! Short-lived system-bus subscription diagnostic; no Bluetooth scan.
#[allow(dead_code)]
#[path = "../dbus_handshake.rs"]
mod wire;
use std::{
    error::Error,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    time::Duration,
};
fn receive(bus: &mut UnixStream, signals: &mut usize) -> Result<Vec<u8>, Box<dyn Error>> {
    for _ in 0..16 {
        let mut header = [0; 16];
        bus.read_exact(&mut header)?;
        let total = wire::declared_message_len(&header)?.ok_or("short header")?;
        let mut frame = header.to_vec();
        frame.resize(total, 0);
        bus.read_exact(&mut frame[16..])?;
        if frame[1] != 4 {
            return Ok(frame);
        }
        let signal = wire::parse_signal(&frame)?.ok_or("short signal")?;
        if signal.consumed != frame.len() {
            return Err("signal boundary".into());
        }
        if signal.interface == "org.freedesktop.DBus" && signal.member == "NameOwnerChanged" {
            return Err("owner changed during diagnostic".into());
        }
        *signals += 1;
    }
    Err("signal bound".into())
}
fn main() -> Result<(), Box<dyn Error>> {
    let uid = std::fs::metadata("/proc/self")?.uid();
    let mut bus = UnixStream::connect("/run/dbus/system_bus_socket")?;
    bus.set_read_timeout(Some(Duration::from_secs(5)))?;
    bus.set_write_timeout(Some(Duration::from_secs(5)))?;
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
    let mut signals = 0;
    let frame = receive(&mut bus, &mut signals)?;
    let hello = wire::parse_hello_reply(&frame, 1)?.ok_or("hello incomplete")?;
    if hello.consumed() != frame.len() {
        return Err("hello boundary".into());
    }
    bus.write_all(&wire::bluez_get_name_owner(2)?)?;
    let frame = receive(&mut bus, &mut signals)?;
    let owner = wire::parse_bluez_get_name_owner_reply(&frame, 2)?.ok_or("owner incomplete")?;
    if owner.consumed() != frame.len() {
        return Err("owner boundary".into());
    }
    let owner = owner.name().to_owned();
    for (serial, kind) in [
        (3, wire::BluezMatch::OwnerChange),
        (4, wire::BluezMatch::Interfaces),
        (5, wire::BluezMatch::Properties),
    ] {
        bus.write_all(&wire::bluez_add_match(
            serial,
            &owner,
            "/org/bluez",
            "/",
            kind,
        )?)?;
        let frame = receive(&mut bus, &mut signals)?;
        if wire::parse_empty_method_reply(&frame, serial)? != Some(frame.len()) {
            return Err("match reply boundary".into());
        }
    }
    bus.write_all(&wire::bluez_get_name_owner(6)?)?;
    let frame = receive(&mut bus, &mut signals)?;
    let current =
        wire::parse_bluez_get_name_owner_reply(&frame, 6)?.ok_or("owner recheck incomplete")?;
    if current.consumed() != frame.len() || current.name() != owner {
        return Err("owner changed".into());
    }
    println!(
        "short_bus_subscription=passed matches=3 owner_rechecked=true signals_observed={signals} scan_calls=none camera_calls=none"
    );
    Ok(())
}
