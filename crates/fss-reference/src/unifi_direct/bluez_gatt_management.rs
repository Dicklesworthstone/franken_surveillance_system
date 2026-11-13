#![forbid(unsafe_code)]
//! Inert bindings for one camera-management negotiation write over BlueZ.
//!
//! No camera identity or management semantics are established here. The
//! dispatcher must independently verify both against the exact bytes and the
//! registered management effect. This profile does not authorize provisioning
//! Wi-Fi, transmitting plaintext credentials, or changing arbitrary settings.

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_packet::{dbus_handshake as wire, dbus_object_manager::GattWriteMode};
use std::{fmt, ops::Range};

/// Registered effect only for independently validated management negotiation.
pub const EFFECT_CLASS: &str = "EFFECT-CAMERA-MANAGEMENT-001";
const DOMAIN: &str = "fss.unifi-direct.bluez-management-preconditions.v1";
const FRAGMENT_DOMAIN: &str = "fss.unifi-direct.bluez-management-fragment.v1";

/// Caller-supplied claims that an independent authority must revalidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preconditions {
    /// Independently established camera identity binding.
    pub camera: ContentDigest,
    /// Exact current device and transport admission decision.
    pub peer_admission: ContentDigest,
    /// Nonzero generation of the owned Bluetooth management session.
    pub session_generation: u64,
    /// Current camera lease fence.
    pub lease_fence: u64,
}

/// Payload-free plan refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A camera, admission, session or lease claim is invalid or stale.
    Preconditions,
    /// The scoped D-Bus write could not be encoded.
    Encoding(wire::Error),
    /// Canonical encoding or bounded allocation failed.
    Limit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueZ management write refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Immutable encoded request and effect bindings. Contents may be sensitive;
/// no secure erasure is promised. This plan does not itself grant authority.
pub struct Plan {
    serial: u32,
    owner: String,
    device: String,
    characteristic: String,
    mode: GattWriteMode,
    message: wire::GattWrite,
    camera: ContentDigest,
    fence: u64,
    request: ContentDigest,
    base_preconditions: ContentDigest,
    preconditions: ContentDigest,
    fragment_bound: bool,
}
impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plan").finish_non_exhaustive()
    }
}
impl Plan {
    /// Bind exact bytes and caller claims for a separately authorized
    /// management-negotiation effect. No interpretation of `value` is made;
    /// the live authority must independently establish its allowed semantics.
    /// Do not place plaintext secrets in this plan or its effect journal.
    pub fn new(
        serial: u32,
        owner: &str,
        device: &str,
        characteristic: &str,
        mode: GattWriteMode,
        value: &[u8],
        current: Preconditions,
    ) -> Result<Self, Error> {
        let preconditions = preconditions_digest(owner, device, characteristic, mode, current)?;
        let message = wire::bluez_gatt_write(serial, owner, device, characteristic, mode, value)
            .map_err(Error::Encoding)?;
        let request = ContentDigest::sha256(message.as_bytes());
        Ok(Self {
            serial,
            owner: own(owner)?,
            device: own(device)?,
            characteristic: own(characteristic)?,
            mode,
            message,
            camera: current.camera,
            fence: current.lease_fence,
            request,
            base_preconditions: preconditions,
            preconditions,
            fragment_bound: false,
        })
    }
    /// Bind one write-with-response fragment to its complete length-framed
    /// negotiation packet and exact byte range. This constructs an inert plan;
    /// it does not prove earlier fragments were sent or authorize credentials.
    pub fn for_fragment(
        serial: u32,
        owner: &str,
        device: &str,
        characteristic: &str,
        frame: &[u8],
        range: Range<usize>,
        current: Preconditions,
    ) -> Result<Self, Error> {
        if frame.len() < 2
            || frame.len() > usize::from(u16::MAX)
            || usize::from(u16::from_be_bytes([frame[0], frame[1]])) != frame.len()
            || range.start >= range.end
            || range.end > frame.len()
            || range.end - range.start > 512
        {
            return Err(Error::Limit);
        }
        Self::new(
            serial,
            owner,
            device,
            characteristic,
            GattWriteMode::Request,
            &frame[range.clone()],
            current,
        )?
        .bind_fragment(ContentDigest::sha256(frame), frame.len(), range)
    }

    pub(super) fn bind_fragment(
        mut self,
        frame: ContentDigest,
        total: usize,
        range: Range<usize>,
    ) -> Result<Self, Error> {
        if !valid_digest(frame)
            || total < 2
            || total > usize::from(u16::MAX)
            || range.start >= range.end
            || range.end > total
            || range.end - range.start > 512
            || self.mode != GattWriteMode::Request
            || self.fragment_bound
        {
            return Err(Error::Preconditions);
        }
        let mut e = CanonicalEncoder::new();
        e.text(FRAGMENT_DOMAIN);
        e.digest(self.preconditions);
        e.digest(frame);
        e.u64(u64::try_from(total).map_err(|_| Error::Limit)?);
        e.u64(u64::try_from(range.start).map_err(|_| Error::Limit)?);
        e.u64(u64::try_from(range.end).map_err(|_| Error::Limit)?);
        self.preconditions = ContentDigest::sha256(&e.finish_checked().map_err(|_| Error::Limit)?);
        self.fragment_bound = true;
        Ok(self)
    }
    /// Exact encoded request digest for an effect preparation.
    pub fn request_digest(&self) -> ContentDigest {
        self.request
    }
    /// Bound identity, session, endpoint and lease claims for preparation.
    pub fn precondition_digest(&self) -> ContentDigest {
        self.preconditions
    }
    /// Camera resource identity for the effect lease.
    pub fn resource(&self) -> String {
        format!("camera:{}", self.camera.to_text())
    }
    /// Lease fence bound at preparation.
    pub fn fence(&self) -> u64 {
        self.fence
    }
    /// Exact encoded bytes for the independent semantic and identity authority.
    /// These bytes can contain sensitive traffic and must not be logged.
    pub fn message_bytes(&self) -> &[u8] {
        self.message.as_bytes()
    }
    /// Compare fresh caller claims without asserting their authenticity.
    pub fn check_current(&self, current: Preconditions) -> Result<(), Error> {
        let base = preconditions_digest(
            &self.owner,
            &self.device,
            &self.characteristic,
            self.mode,
            current,
        )?;
        if base != self.base_preconditions {
            return Err(Error::Preconditions);
        }
        Ok(())
    }
    pub(super) fn matches(
        &self,
        serial: u32,
        owner: &str,
        device: &str,
        characteristic: &str,
        mode: GattWriteMode,
    ) -> bool {
        self.serial == serial
            && self.owner == owner
            && self.device == device
            && self.characteristic == characteristic
            && self.mode == mode
    }
}

fn own(value: &str) -> Result<String, Error> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| Error::Limit)?;
    result.push_str(value);
    Ok(result)
}
fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256
        && !value.is_laboratory()
        && value.bytes() != [0; 32]
}
fn preconditions_digest(
    owner: &str,
    device: &str,
    characteristic: &str,
    mode: GattWriteMode,
    current: Preconditions,
) -> Result<ContentDigest, Error> {
    if !valid_digest(current.camera)
        || !valid_digest(current.peer_admission)
        || current.session_generation == 0
        || current.lease_fence == 0
        || owner.len() > 255
        || device.len() > 255
        || characteristic.len() > 255
    {
        return Err(Error::Preconditions);
    }
    let mut e = CanonicalEncoder::new();
    e.text(DOMAIN);
    e.text(EFFECT_CLASS);
    e.digest(current.camera);
    e.digest(current.peer_admission);
    e.u64(current.session_generation);
    e.u64(current.lease_fence);
    e.text(owner);
    e.text(device);
    e.text(characteristic);
    e.text(match mode {
        GattWriteMode::Request => "request",
        GattWriteMode::Command => "command",
    });
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| Error::Limit)?,
    ))
}
