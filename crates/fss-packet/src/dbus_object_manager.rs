#![forbid(unsafe_code)]
//! Bounded D-Bus ObjectManager and property-change body parsing for BlueZ.
//!
//! The caller must separately bind the complete body to a correlated response
//! with signature `a{oa{sa{sv}}}` and to an admitted bus and service owner.
//! Paths and properties are untrusted claims, not camera identities or coverage.
//! Unsupported values, ambiguity, limits and truncation refuse the entire body.

use std::fmt;

const MAX_BODY: usize = 1024 * 1024;
const MAX_SIGNATURE: usize = 255;
const MAX_DEPTH: usize = 32;
const MAX_VALUES: usize = 16_384;
const MAX_OBJECTS: usize = 1024;
const MAX_INTERFACES: usize = 256;
const MAX_PROPERTIES: usize = 512;
const MAX_SERVICE_UUIDS: usize = 256;

/// A bounded ObjectManager decoding refusal without payload contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Truncation, malformed padding, duplicate keys, or invalid encoding.
    Invalid,
    /// An explicit size, nesting or work limit was reached.
    Limit,
    /// A valid-looking type outside this profile requires another decoder.
    Unsupported,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "D-Bus ObjectManager body refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Correlated body byte order supplied by the framing owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    /// Little-endian message.
    Little,
    /// Big-endian message.
    Big,
}

/// Adapter and device paths claimed by the supplied, complete inventory body.
/// The source remains untrusted, and this snapshot is not ongoing coverage.
pub struct Inventory<'a> {
    adapter_paths: Vec<&'a str>,
    device_paths: Vec<&'a str>,
    device_claims: Vec<DeviceClaim<'a>>,
    objects: usize,
}

/// One untrusted BlueZ device claim and its optional service-list property.
/// Missing properties are unknown; an empty list is only a snapshot claim.
pub struct DeviceClaim<'a> {
    path: &'a str,
    service_uuids: Option<Vec<&'a str>>,
}
impl<'a> DeviceClaim<'a> {
    /// Claimed D-Bus device path, not an authenticated device identity.
    pub fn path(&self) -> &'a str {
        self.path
    }
    /// Claimed UUID strings; `None` means the property was not observed.
    pub fn service_uuids(&self) -> Option<&[&'a str]> {
        self.service_uuids.as_deref()
    }
    /// Check the reported list case-insensitively. A match is a claim only;
    /// `None` means no list was observed and `Some(false)` is snapshot-limited.
    pub fn claims_service(&self, service: &str) -> Option<bool> {
        self.service_uuids
            .as_ref()
            .map(|uuids| uuids.iter().any(|uuid| uuid.eq_ignore_ascii_case(service)))
    }
}
impl fmt::Debug for DeviceClaim<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceClaim")
            .field("service_uuids_present", &self.service_uuids.is_some())
            .field("service_count", &self.service_uuids.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}
impl<'a> Inventory<'a> {
    /// Claimed BlueZ adapter object paths, in received order.
    pub fn adapter_paths(&self) -> &[&'a str] {
        &self.adapter_paths
    }
    /// Claimed Bluetooth device object paths, in received order. These do not
    /// establish device identity, current reachability or owner authorization.
    pub fn device_paths(&self) -> &[&'a str] {
        &self.device_paths
    }
    /// Per-device claims in the same order as [`Self::device_paths`].
    pub fn device_claims(&self) -> &[DeviceClaim<'a>] {
        &self.device_claims
    }
    /// Number of complete object entries parsed.
    pub fn objects(&self) -> usize {
        self.objects
    }
}
impl fmt::Debug for Inventory<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inventory")
            .field("adapters", &self.adapter_paths.len())
            .field("devices", &self.device_paths.len())
            .field("objects", &self.objects)
            .finish()
    }
}

fn basic_key(b: u8) -> bool {
    matches!(
        b,
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b's' | b'o' | b'g'
    )
}
fn alignment(b: u8) -> Result<usize, Error> {
    match b {
        b'y' | b'g' | b'v' => Ok(1),
        b'n' | b'q' => Ok(2),
        b'b' | b'i' | b'u' | b's' | b'o' | b'a' => Ok(4),
        b'x' | b't' | b'd' | b'(' | b'{' => Ok(8),
        b'h' => Err(Error::Unsupported),
        _ => Err(Error::Invalid),
    }
}

// Return the end of exactly one complete type, without constructing an AST.
fn type_end(s: &[u8], at: usize, depth: usize, dict_ok: bool) -> Result<usize, Error> {
    if depth > MAX_DEPTH {
        return Err(Error::Limit);
    }
    let first = *s.get(at).ok_or(Error::Invalid)?;
    match first {
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b's' | b'o' | b'g'
        | b'v' => Ok(at + 1),
        b'h' => Err(Error::Unsupported),
        b'a' => type_end(s, at + 1, depth + 1, true),
        b'(' => {
            let mut p = at + 1;
            let start = p;
            while *s.get(p).ok_or(Error::Invalid)? != b')' {
                p = type_end(s, p, depth + 1, false)?;
            }
            if p == start {
                return Err(Error::Invalid);
            }
            Ok(p + 1)
        }
        b'{' if dict_ok => {
            let key = *s.get(at + 1).ok_or(Error::Invalid)?;
            if !basic_key(key) {
                return Err(Error::Invalid);
            }
            let p = type_end(s, at + 2, depth + 1, false)?;
            if s.get(p) != Some(&b'}') {
                return Err(Error::Invalid);
            }
            Ok(p + 1)
        }
        _ => Err(Error::Invalid),
    }
}
fn validate_signature(s: &[u8], single: bool) -> Result<(), Error> {
    if s.len() > MAX_SIGNATURE || (single && s.is_empty()) {
        return Err(Error::Invalid);
    }
    let mut p = 0;
    let mut count = 0;
    while p < s.len() {
        p = type_end(s, p, 0, false)?;
        count += 1;
    }
    if single && count != 1 {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn object_path(s: &str) -> bool {
    if s == "/" {
        return true;
    }
    s.starts_with('/')
        && !s.ends_with('/')
        && s[1..].split('/').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
    endian: Endian,
    values: usize,
}
impl<'a> Cursor<'a> {
    fn count(&mut self) -> Result<(), Error> {
        self.values = self.values.checked_add(1).ok_or(Error::Limit)?;
        if self.values > MAX_VALUES {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    }
    fn pad(&mut self, alignment: usize) -> Result<(), Error> {
        let end = self.at.checked_add(alignment - 1).ok_or(Error::Limit)? & !(alignment - 1);
        let pad = self.data.get(self.at..end).ok_or(Error::Invalid)?;
        if pad.iter().any(|b| *b != 0) {
            return Err(Error::Invalid);
        }
        self.at = end;
        Ok(())
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Limit)?;
        let value = self.data.get(self.at..end).ok_or(Error::Invalid)?;
        self.at = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        self.pad(4)?;
        let value: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::Invalid)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(value),
            Endian::Big => u32::from_be_bytes(value),
        })
    }
    fn string(&mut self, path: bool) -> Result<&'a str, Error> {
        let n = usize::try_from(self.u32()?).map_err(|_| Error::Limit)?;
        let bytes = self.take(n)?;
        if self.take(1)? != [0] || bytes.contains(&0) {
            return Err(Error::Invalid);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Invalid)?;
        if path && !object_path(text) {
            return Err(Error::Invalid);
        }
        Ok(text)
    }
    fn signature(&mut self, single: bool) -> Result<&'a [u8], Error> {
        let n = usize::from(self.take(1)?[0]);
        let value = self.take(n)?;
        if self.take(1)? != [0] {
            return Err(Error::Invalid);
        }
        validate_signature(value, single)?;
        Ok(value)
    }
    fn array(&mut self, elem_align: usize) -> Result<usize, Error> {
        let bytes = usize::try_from(self.u32()?).map_err(|_| Error::Limit)?;
        self.pad(elem_align)?;
        let end = self.at.checked_add(bytes).ok_or(Error::Limit)?;
        if end > self.data.len() {
            return Err(Error::Invalid);
        }
        Ok(end)
    }
    fn service_list(&mut self, parent_end: usize) -> Result<Vec<&'a str>, Error> {
        self.count()?;
        if self.signature(true)? != b"as" {
            return Err(Error::Invalid);
        }
        self.count()?;
        let end = self.array(4)?;
        if end > parent_end {
            return Err(Error::Invalid);
        }
        let mut uuids = Vec::new();
        while self.at < end {
            self.count()?;
            if uuids.len() == MAX_SERVICE_UUIDS {
                return Err(Error::Limit);
            }
            uuids.push(self.string(false)?);
            if self.at > end {
                return Err(Error::Invalid);
            }
        }
        Ok(uuids)
    }
    fn skip(&mut self, sig: &[u8], at: usize, depth: usize) -> Result<usize, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Limit);
        }
        self.count()?;
        let first = *sig.get(at).ok_or(Error::Invalid)?;
        let end = type_end(sig, at, depth, true)?;
        self.pad(alignment(first)?)?;
        match first {
            b'y' => {
                self.take(1)?;
            }
            b'n' | b'q' => {
                self.take(2)?;
            }
            b'i' | b'u' => {
                self.take(4)?;
            }
            b'b' => {
                let b = self.u32()?;
                if b > 1 {
                    return Err(Error::Invalid);
                }
            }
            b'x' | b't' | b'd' => {
                self.take(8)?;
            }
            b's' => {
                self.string(false)?;
            }
            b'o' => {
                self.string(true)?;
            }
            b'g' => {
                self.signature(false)?;
            }
            b'v' => {
                let inner = self.signature(true)?;
                if self.skip(inner, 0, depth + 1)? != inner.len() {
                    return Err(Error::Invalid);
                }
            }
            b'a' => {
                let inner = at + 1;
                let limit = self.array(alignment(*sig.get(inner).ok_or(Error::Invalid)?)?)?;
                while self.at < limit {
                    let before = self.at;
                    let _ = self.skip(sig, inner, depth + 1)?;
                    if self.at <= before || self.at > limit {
                        return Err(Error::Invalid);
                    }
                }
            }
            b'(' | b'{' => {
                let mut p = at + 1;
                while p < end - 1 {
                    p = self.skip(sig, p, depth + 1)?;
                }
                if p != end - 1 {
                    return Err(Error::Invalid);
                }
            }
            _ => return Err(Error::Invalid),
        }
        Ok(end)
    }
}

fn interfaces<'a>(
    c: &mut Cursor<'a>,
    path: &'a str,
    parent_end: usize,
) -> Result<(bool, Option<DeviceClaim<'a>>), Error> {
    let mut names = Vec::new();
    let mut adapter = false;
    let mut device = None;
    let interface_end = c.array(8)?;
    if interface_end > parent_end {
        return Err(Error::Invalid);
    }
    while c.at < interface_end {
        c.count()?;
        c.pad(8)?;
        if c.at >= interface_end || names.len() == MAX_INTERFACES {
            return Err(Error::Limit);
        }
        let interface = c.string(false)?;
        if interface.is_empty() || names.contains(&interface) {
            return Err(Error::Invalid);
        }
        names.push(interface);
        let property_end = c.array(8)?;
        if property_end > interface_end {
            return Err(Error::Invalid);
        }
        let mut properties = Vec::new();
        let mut service_uuids = None;
        while c.at < property_end {
            c.count()?;
            c.pad(8)?;
            if c.at >= property_end || properties.len() == MAX_PROPERTIES {
                return Err(Error::Limit);
            }
            let name = c.string(false)?;
            if name.is_empty() || properties.contains(&name) {
                return Err(Error::Invalid);
            }
            properties.push(name);
            if interface == "org.bluez.Device1" && name == "UUIDs" {
                service_uuids = Some(c.service_list(property_end)?);
            } else {
                c.skip(b"v", 0, 0)?;
            }
            if c.at > property_end {
                return Err(Error::Invalid);
            }
        }
        if c.at != property_end {
            return Err(Error::Invalid);
        }
        if interface == "org.bluez.Adapter1" {
            adapter = true;
        }
        if interface == "org.bluez.Device1" {
            device = Some(DeviceClaim {
                path,
                service_uuids,
            });
        }
    }
    if c.at != interface_end {
        return Err(Error::Invalid);
    }
    Ok((adapter, device))
}

/// Decode one entire ObjectManager method-return body with the fixed signature
/// `a{oa{sa{sv}}}`. The caller must authenticate/correlate framing separately.
/// A refusal produces no partial inventory and never means no adapter exists.
pub fn parse_inventory(body: &[u8], endian: Endian) -> Result<Inventory<'_>, Error> {
    if body.len() > MAX_BODY {
        return Err(Error::Limit);
    }
    let mut c = Cursor {
        data: body,
        at: 0,
        endian,
        values: 0,
    };
    let mut object_paths = Vec::new();
    let mut adapters = Vec::new();
    let mut devices = Vec::new();
    let mut device_claims = Vec::new();
    let outer = c.array(8)?;
    while c.at < outer {
        c.count()?;
        c.pad(8)?;
        if c.at >= outer || object_paths.len() == MAX_OBJECTS {
            return Err(Error::Limit);
        }
        let path = c.string(true)?;
        if object_paths.contains(&path) {
            return Err(Error::Invalid);
        }
        object_paths.push(path);
        let (adapter, device) = interfaces(&mut c, path, outer)?;
        if adapter {
            adapters.push(path);
        }
        if let Some(device) = device {
            devices.push(path);
            device_claims.push(device);
        }
    }
    if c.at != outer || outer != body.len() {
        return Err(Error::Invalid);
    }
    Ok(Inventory {
        adapter_paths: adapters,
        device_paths: devices,
        device_claims,
        objects: object_paths.len(),
    })
}

/// One untrusted `InterfacesAdded` body. This is a partial change, not a
/// complete object snapshot; the caller must bind the signal's source/header.
pub struct InterfacesAdded<'a> {
    /// Object path claimed in the signal body.
    pub path: &'a str,
    /// Whether this signal included the BlueZ adapter interface.
    pub adapter_added: bool,
    /// Device interface properties, when this signal included that interface.
    pub device: Option<DeviceClaim<'a>>,
}
impl fmt::Debug for InterfacesAdded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfacesAdded")
            .field("adapter_added", &self.adapter_added)
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

/// Decode a complete `InterfacesAdded` body with signature `oa{sa{sv}}`.
/// This does not validate the enclosing signal's sender, member or object path.
pub fn parse_interfaces_added(body: &[u8], endian: Endian) -> Result<InterfacesAdded<'_>, Error> {
    if body.len() > MAX_BODY {
        return Err(Error::Limit);
    }
    let mut c = Cursor {
        data: body,
        at: 0,
        endian,
        values: 0,
    };
    let path = c.string(true)?;
    let (adapter_added, device) = interfaces(&mut c, path, body.len())?;
    if c.at != body.len() {
        return Err(Error::Invalid);
    }
    Ok(InterfacesAdded {
        path,
        adapter_added,
        device,
    })
}

fn string_array<'a>(c: &mut Cursor<'a>, limit: usize) -> Result<Vec<&'a str>, Error> {
    let end = c.array(4)?;
    if end > limit {
        return Err(Error::Invalid);
    }
    let mut values = Vec::new();
    while c.at < end {
        c.count()?;
        if values.len() == MAX_PROPERTIES {
            return Err(Error::Limit);
        }
        let value = c.string(false)?;
        if value.is_empty() || values.contains(&value) || c.at > end {
            return Err(Error::Invalid);
        }
        values.push(value);
    }
    Ok(values)
}

/// Untrusted interface-removal claims for one object, not device absence.
pub struct InterfacesRemoved<'a> {
    /// Object path claimed by the signal.
    pub path: &'a str,
    interfaces: Vec<&'a str>,
}
impl<'a> InterfacesRemoved<'a> {
    /// All interface names claimed removed, in wire order.
    pub fn interfaces(&self) -> &[&'a str] {
        &self.interfaces
    }
}
impl fmt::Debug for InterfacesRemoved<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfacesRemoved")
            .field("interface_count", &self.interfaces.len())
            .finish_non_exhaustive()
    }
}

/// Decode a complete `InterfacesRemoved` body with signature `oas`.
pub fn parse_interfaces_removed(
    body: &[u8],
    endian: Endian,
) -> Result<InterfacesRemoved<'_>, Error> {
    if body.len() > MAX_BODY {
        return Err(Error::Limit);
    }
    let mut c = Cursor {
        data: body,
        at: 0,
        endian,
        values: 0,
    };
    let path = c.string(true)?;
    let interfaces = string_array(&mut c, body.len())?;
    if c.at != body.len() {
        return Err(Error::Invalid);
    }
    Ok(InterfacesRemoved { path, interfaces })
}

/// A change to the Device1 service list. Invalidated and unchanged are not an
/// empty list, and even a present list remains an unverified observation.
pub enum ServiceChange<'a> {
    /// The signal did not mention the service list.
    Unchanged,
    /// The service list was invalidated without a replacement value.
    Invalidated,
    /// A replacement list was supplied; it may be empty.
    Present(Vec<&'a str>),
}
impl fmt::Debug for ServiceChange<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged => f.write_str("Unchanged"),
            Self::Invalidated => f.write_str("Invalidated"),
            Self::Present(uuids) => f.debug_tuple("Present").field(&uuids.len()).finish(),
        }
    }
}

/// Untrusted properties-change body; the affected object path is carried by
/// the enclosing D-Bus header and must be independently bound by the caller.
pub struct PropertiesChanged<'a> {
    /// Interface whose properties were reported changed.
    pub interface: &'a str,
    /// Device1 service-list change, or unchanged for another interface.
    pub services: ServiceChange<'a>,
}
impl fmt::Debug for PropertiesChanged<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PropertiesChanged")
            .field("services", &self.services)
            .finish_non_exhaustive()
    }
}

/// Decode a complete `PropertiesChanged` body with signature `sa{sv}as`.
/// Changed and invalidated properties may not overlap in one accepted signal.
pub fn parse_properties_changed(
    body: &[u8],
    endian: Endian,
) -> Result<PropertiesChanged<'_>, Error> {
    if body.len() > MAX_BODY {
        return Err(Error::Limit);
    }
    let mut c = Cursor {
        data: body,
        at: 0,
        endian,
        values: 0,
    };
    let interface = c.string(false)?;
    if interface.is_empty() {
        return Err(Error::Invalid);
    }
    let end = c.array(8)?;
    let mut changed = Vec::new();
    let mut services = ServiceChange::Unchanged;
    while c.at < end {
        c.count()?;
        c.pad(8)?;
        if c.at >= end || changed.len() == MAX_PROPERTIES {
            return Err(Error::Limit);
        }
        let name = c.string(false)?;
        if name.is_empty() || changed.contains(&name) {
            return Err(Error::Invalid);
        }
        changed.push(name);
        if interface == "org.bluez.Device1" && name == "UUIDs" {
            services = ServiceChange::Present(c.service_list(end)?);
        } else {
            c.skip(b"v", 0, 0)?;
        }
        if c.at > end {
            return Err(Error::Invalid);
        }
    }
    let invalidated = string_array(&mut c, body.len())?;
    if c.at != body.len() || invalidated.iter().any(|name| changed.contains(name)) {
        return Err(Error::Invalid);
    }
    if interface == "org.bluez.Device1" && invalidated.contains(&"UUIDs") {
        services = ServiceChange::Invalidated;
    }
    Ok(PropertiesChanged {
        interface,
        services,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Writer {
        data: Vec<u8>,
        endian: Endian,
    }
    impl Writer {
        fn new(endian: Endian) -> Self {
            Self {
                data: Vec::new(),
                endian,
            }
        }
        fn pad(&mut self, n: usize) {
            while self.data.len() % n != 0 {
                self.data.push(0);
            }
        }
        fn number(&mut self, n: u32) {
            self.pad(4);
            self.data.extend_from_slice(&match self.endian {
                Endian::Little => n.to_le_bytes(),
                Endian::Big => n.to_be_bytes(),
            });
        }
        fn text(&mut self, s: &str) {
            self.number(s.len() as u32);
            self.data.extend_from_slice(s.as_bytes());
            self.data.push(0);
        }
        fn sig(&mut self, s: &str) {
            self.data.push(s.len() as u8);
            self.data.extend_from_slice(s.as_bytes());
            self.data.push(0);
        }
        fn array(&mut self, a: usize) -> (usize, usize) {
            self.pad(4);
            let at = self.data.len();
            self.number(0);
            self.pad(a);
            (at, self.data.len())
        }
        fn finish(&mut self, mark: (usize, usize)) {
            let len = (self.data.len() - mark.1) as u32;
            let bytes = match self.endian {
                Endian::Little => len.to_le_bytes(),
                Endian::Big => len.to_be_bytes(),
            };
            self.data[mark.0..mark.0 + 4].copy_from_slice(&bytes);
        }
        fn prop(&mut self, name: &str, sig: &str) {
            self.pad(8);
            self.text(name);
            self.sig(sig);
        }
    }
    fn inventory(endian: Endian, duplicate: bool) -> Vec<u8> {
        let mut w = Writer::new(endian);
        let outer = w.array(8);
        for object in 0..2 {
            w.pad(8);
            w.text(if object == 0 || duplicate {
                "/org/bluez/hci0"
            } else {
                "/org/bluez/hci0/dev_AA"
            });
            let interfaces = w.array(8);
            w.pad(8);
            w.text(if object == 0 {
                "org.bluez.Adapter1"
            } else {
                "org.bluez.Device1"
            });
            let props = w.array(8);
            w.prop("Powered", "b");
            w.number(1);
            w.prop("Alias", "s");
            w.text("fixture");
            w.prop("Version", "q");
            w.pad(2);
            w.data.extend_from_slice(&match endian {
                Endian::Little => 2_u16.to_le_bytes(),
                Endian::Big => 2_u16.to_be_bytes(),
            });
            w.prop("UUIDs", "as");
            let strings = w.array(4);
            w.text("alpha");
            w.text("beta");
            w.finish(strings);
            w.prop("Extra", "a{sv}");
            let dict = w.array(8);
            w.pad(8);
            w.text("Nested");
            w.sig("ay");
            let bytes = w.array(1);
            w.data.extend_from_slice(&[1, 2, 3]);
            w.finish(bytes);
            w.finish(dict);
            w.finish(props);
            w.finish(interfaces);
        }
        w.finish(outer);
        w.data
    }
    #[test]
    fn parses_nested_variants_and_both_endiannesses() -> Result<(), Error> {
        for endian in [Endian::Little, Endian::Big] {
            let data = inventory(endian, false);
            let out = parse_inventory(&data, endian)?;
            assert_eq!(out.objects(), 2);
            assert_eq!(out.adapter_paths(), &["/org/bluez/hci0"]);
            assert_eq!(out.device_paths(), &["/org/bluez/hci0/dev_AA"]);
            assert_eq!(out.device_claims().len(), 1);
            let claim = &out.device_claims()[0];
            assert_eq!(claim.path(), "/org/bluez/hci0/dev_AA");
            assert_eq!(claim.service_uuids(), Some(["alpha", "beta"].as_slice()));
            assert_eq!(claim.claims_service("ALPHA"), Some(true));
            assert_eq!(claim.claims_service("other"), Some(false));
            assert!(!format!("{claim:?}").contains("alpha"));
            assert!(!format!("{out:?}").contains("hci0"));
        }
        Ok(())
    }
    #[test]
    fn every_truncation_is_refused_without_partial_results() {
        let data = inventory(Endian::Little, false);
        for end in 0..data.len() {
            assert!(
                parse_inventory(&data[..end], Endian::Little).is_err(),
                "truncation {end}"
            );
        }
    }
    #[test]
    fn duplicate_object_or_trailing_data_is_refused() {
        let data = inventory(Endian::Little, true);
        assert!(matches!(
            parse_inventory(&data, Endian::Little),
            Err(Error::Invalid)
        ));
        let mut data = inventory(Endian::Little, false);
        data.push(0);
        assert!(matches!(
            parse_inventory(&data, Endian::Little),
            Err(Error::Invalid)
        ));
    }
    #[test]
    fn invalid_variant_signature_and_boolean_fail_closed() {
        let mut data = inventory(Endian::Little, false);
        let i = data.windows(3).position(|w| w == b"\x01b\0");
        assert!(i.is_some());
        if let Some(i) = i {
            data[i + 1] = b'h';
            assert!(matches!(
                parse_inventory(&data, Endian::Little),
                Err(Error::Unsupported)
            ));
        }
        let mut data = inventory(Endian::Little, false);
        let i = data.windows(3).position(|w| w == b"\x01b\0");
        if let Some(i) = i {
            let at = (i + 3 + 3) & !3;
            data[at..at + 4].copy_from_slice(&2_u32.to_le_bytes());
            assert!(matches!(
                parse_inventory(&data, Endian::Little),
                Err(Error::Invalid)
            ));
        }
    }
    #[test]
    fn malformed_signatures_and_excessive_nesting_are_refused() {
        for signature in [b"{".as_slice(), b"a{vv}", b"a{sv", b"()", b"a", b"is"] {
            assert!(validate_signature(signature, true).is_err());
        }
        let mut nested = vec![b'a'; MAX_DEPTH + 2];
        nested.push(b'y');
        assert_eq!(validate_signature(&nested, true), Err(Error::Limit));
        assert!(validate_signature(b"a{oa{sa{sv}}}", true).is_ok());
    }

    #[test]
    fn absent_and_empty_service_lists_remain_distinct() -> Result<(), Error> {
        for present in [false, true] {
            let mut w = Writer::new(Endian::Little);
            let outer = w.array(8);
            w.pad(8);
            w.text("/org/bluez/hci0/dev_AA");
            let interfaces = w.array(8);
            w.pad(8);
            w.text("org.bluez.Device1");
            let props = w.array(8);
            if present {
                w.prop("UUIDs", "as");
                let values = w.array(4);
                w.finish(values);
            }
            w.finish(props);
            w.finish(interfaces);
            w.finish(outer);
            let inventory = parse_inventory(&w.data, Endian::Little)?;
            let claim = &inventory.device_claims()[0];
            assert_eq!(
                claim.claims_service("alpha"),
                if present { Some(false) } else { None }
            );
        }
        Ok(())
    }

    #[test]
    fn wrong_service_property_type_refuses_whole_snapshot() {
        let mut w = Writer::new(Endian::Little);
        let outer = w.array(8);
        w.pad(8);
        w.text("/org/bluez/hci0/dev_AA");
        let interfaces = w.array(8);
        w.pad(8);
        w.text("org.bluez.Device1");
        let props = w.array(8);
        w.prop("UUIDs", "s");
        w.text("not an array");
        w.finish(props);
        w.finish(interfaces);
        w.finish(outer);
        assert!(matches!(
            parse_inventory(&w.data, Endian::Little),
            Err(Error::Invalid)
        ));
    }

    fn added_signal(endian: Endian) -> Vec<u8> {
        let mut w = Writer::new(endian);
        w.text("/org/bluez/hci0/dev_AA");
        let interfaces = w.array(8);
        w.pad(8);
        w.text("org.bluez.Device1");
        let properties = w.array(8);
        w.prop("UUIDs", "as");
        let values = w.array(4);
        w.text("0c430d0c-00ef-4367-bc6f-ca7c51e6b61f");
        w.finish(values);
        w.finish(properties);
        w.finish(interfaces);
        w.data
    }

    fn removed_signal(endian: Endian, duplicate: bool) -> Vec<u8> {
        let mut w = Writer::new(endian);
        w.text("/org/bluez/hci0/dev_AA");
        let interfaces = w.array(4);
        w.text("org.bluez.Device1");
        if duplicate {
            w.text("org.bluez.Device1");
        }
        w.finish(interfaces);
        w.data
    }

    fn changed_signal(endian: Endian, changed: bool, invalidated: bool) -> Vec<u8> {
        let mut w = Writer::new(endian);
        w.text("org.bluez.Device1");
        let properties = w.array(8);
        if changed {
            w.prop("UUIDs", "as");
            let values = w.array(4);
            w.text("Example-Service");
            w.finish(values);
        }
        w.finish(properties);
        let invalid = w.array(4);
        if invalidated {
            w.text("UUIDs");
        }
        w.finish(invalid);
        w.data
    }

    #[test]
    fn added_and_removed_signals_keep_bounded_untrusted_claims() -> Result<(), Error> {
        for endian in [Endian::Little, Endian::Big] {
            let added = added_signal(endian);
            let parsed = parse_interfaces_added(&added, endian)?;
            assert_eq!(parsed.path, "/org/bluez/hci0/dev_AA");
            let device = parsed.device.as_ref().ok_or(Error::Invalid)?;
            assert_eq!(
                device.claims_service("0C430D0C-00EF-4367-BC6F-CA7C51E6B61F"),
                Some(true)
            );
            assert!(!format!("{parsed:?}").contains("dev_AA"));
            for split in 0..added.len() {
                assert!(parse_interfaces_added(&added[..split], endian).is_err());
            }
            let removed = removed_signal(endian, false);
            let parsed = parse_interfaces_removed(&removed, endian)?;
            assert_eq!(parsed.interfaces(), &["org.bluez.Device1"]);
            assert!(!format!("{parsed:?}").contains("dev_AA"));
            for split in 0..removed.len() {
                assert!(parse_interfaces_removed(&removed[..split], endian).is_err());
            }
            assert!(parse_interfaces_removed(&removed_signal(endian, true), endian).is_err());
        }
        Ok(())
    }

    #[test]
    fn property_signals_preserve_changed_invalidated_and_unknown_states() -> Result<(), Error> {
        for endian in [Endian::Little, Endian::Big] {
            let changed = changed_signal(endian, true, false);
            let parsed = parse_properties_changed(&changed, endian)?;
            match &parsed.services {
                ServiceChange::Present(values) => assert_eq!(values, &["Example-Service"]),
                _ => return Err(Error::Invalid),
            }
            assert!(!format!("{parsed:?}").contains("Example-Service"));
            for split in 0..changed.len() {
                assert!(parse_properties_changed(&changed[..split], endian).is_err());
            }
            let invalid = changed_signal(endian, false, true);
            assert!(matches!(
                parse_properties_changed(&invalid, endian)?.services,
                ServiceChange::Invalidated
            ));
            let untouched = changed_signal(endian, false, false);
            assert!(matches!(
                parse_properties_changed(&untouched, endian)?.services,
                ServiceChange::Unchanged
            ));
            assert!(parse_properties_changed(&changed_signal(endian, true, true), endian).is_err());
        }
        Ok(())
    }
}
