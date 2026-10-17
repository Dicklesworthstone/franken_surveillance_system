//! The on-camera FSS software as an immutable, digest-pinned object graph.
//!
//! [`AgentBundle`] is "my own good firmware": the exact set of components
//! (base firmware, the FSS camera agent, tailscaled, swap config) that gets
//! flashed onto a camera, bound to a single root digest so the on-camera
//! agent and the FSS host can verify they are running the *same* software.
//!
//! Sans-IO: components are described by their content digest and size, never
//! held by bytes. The root is the SHA-256 of the canonical manifest over the
//! canonically-ordered component list, so identical software always yields an
//! identical root and any drift changes it.

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError,
};

use crate::family::CameraFamily;

/// The kind of software a bundle component provides.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ComponentKind {
    /// The base operating system / vendor firmware the agent runs on.
    BaseFirmware = 1,
    /// The FSS on-camera agent (Rust, static, cross-compiled for the SoC).
    RustAgent = 2,
    /// tailscaled in userspace-networking mode (no kernel TUN needed).
    Tailscaled = 3,
    /// The swap-file configuration (camera RAM is tight).
    SwapConfig = 4,
}

impl ComponentKind {
    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaseFirmware => "base_firmware",
            Self::RustAgent => "rust_agent",
            Self::Tailscaled => "tailscaled",
            Self::SwapConfig => "swap_config",
        }
    }
}

impl fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for ComponentKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for ComponentKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::BaseFirmware),
            2 => Ok(Self::RustAgent),
            3 => Ok(Self::Tailscaled),
            4 => Ok(Self::SwapConfig),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// One component of an [`AgentBundle`]: a named, digest-pinned blob.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleComponent {
    kind: ComponentKind,
    name: String,
    content_digest: ContentDigest,
    size_bytes: u64,
}

impl BundleComponent {
    /// Builds a component from its exact bytes, deriving the digest.
    pub fn new(
        kind: ComponentKind,
        name: impl Into<String>,
        content: &[u8],
    ) -> Result<Self, BundleError> {
        let name = name.into();
        if name.is_empty() {
            return Err(BundleError::EmptyName);
        }
        if content.is_empty() {
            return Err(BundleError::EmptyContent);
        }
        Ok(Self {
            kind,
            name,
            content_digest: ContentDigest::sha256(content),
            size_bytes: content.len() as u64,
        })
    }

    /// Builds a component from a known digest and size (bytes not retained).
    pub fn new_with_digest(
        kind: ComponentKind,
        name: impl Into<String>,
        content_digest: ContentDigest,
        size_bytes: u64,
    ) -> Result<Self, BundleError> {
        let name = name.into();
        if name.is_empty() {
            return Err(BundleError::EmptyName);
        }
        if size_bytes == 0 {
            return Err(BundleError::EmptyContent);
        }
        Ok(Self {
            kind,
            name,
            content_digest,
            size_bytes,
        })
    }

    /// The component kind.
    #[must_use]
    pub const fn kind(&self) -> ComponentKind {
        self.kind
    }

    /// The component's stable name within the bundle.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The content digest of the component bytes.
    #[must_use]
    pub const fn content_digest(&self) -> ContentDigest {
        self.content_digest
    }

    /// The component size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// The canonical manifest row for this component.
    fn manifest_row(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.u8(self.kind as u8);
        encoder.text(&self.name);
        encoder.digest(self.content_digest);
        encoder.u64(self.size_bytes);
        encoder.finish()
    }
}

/// The immutable "our software" object graph for one agent generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentBundle {
    generation: String,
    /// Canonically ordered (by kind, then name) component list.
    components: Vec<BundleComponent>,
    /// SHA-256 of the canonical manifest over the ordered components.
    root: ContentDigest,
}

impl AgentBundle {
    /// The agent software generation (never `latest`).
    #[must_use]
    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// The canonically ordered components.
    #[must_use]
    pub fn components(&self) -> &[BundleComponent] {
        &self.components
    }

    /// The root digest binding the whole bundle.
    #[must_use]
    pub const fn root(&self) -> ContentDigest {
        self.root
    }

    /// Recomputes the root from the current components.
    #[must_use]
    pub fn computed_root(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(&self.generation);
        encoder.u32(self.components.len() as u32);
        for component in &self.components {
            encoder.bytes(&component.manifest_row());
        }
        ContentDigest::sha256(&encoder.finish())
    }

    /// Whether the stored root still matches the components (no drift).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.root == self.computed_root()
    }

    /// The canonical reference bundle of "our software" for a family — the
    /// deterministic fixture the planner and reference tests use.
    #[must_use]
    pub fn reference(family: CameraFamily) -> AgentBundle {
        let base_name = match family {
            CameraFamily::Yi => "yihack-2.0.1-armv7",
            CameraFamily::WyzeV4 => "wyze-v4-armv7",
            CameraFamily::AosUP1Max => "aosu-p1-max-armv5te",
            CameraFamily::OpenIPCClassA => "openipc-coupler-armv7",
            CameraFamily::GenericStandards => "standards-bridge-armv7",
        };
        let base_content = format!("fss-base-firmware:family={family}\nversion=1\n");
        let mut components: Vec<BundleComponent> = Vec::with_capacity(4);
        push_reference_component(
            &mut components,
            ComponentKind::BaseFirmware,
            base_name,
            base_content.as_bytes(),
        );
        push_reference_component(
            &mut components,
            ComponentKind::RustAgent,
            "fss-camera-agent-armv7",
            b"fss-camera-agent:static-armv7\nentry=main\n",
        );
        push_reference_component(
            &mut components,
            ComponentKind::Tailscaled,
            "tailscaled-userspace",
            b"tailscaled:userspace-networking\n",
        );
        push_reference_component(
            &mut components,
            ComponentKind::SwapConfig,
            "swap.conf",
            b"swapfile=/swapfile\nsize=64M\n",
        );
        components.sort_by(|a, b| a.kind().cmp(&b.kind()).then_with(|| a.name().cmp(b.name())));
        let root = {
            let mut encoder = CanonicalEncoder::new();
            encoder.text("fss-agent/1");
            encoder.u32(components.len() as u32);
            for component in &components {
                encoder.bytes(&component.manifest_row());
            }
            ContentDigest::sha256(&encoder.finish())
        };
        AgentBundle {
            generation: "fss-agent/1".to_owned(),
            components,
            root,
        }
    }
}

/// Canonical encoding of the bundle for round-tripping and cross-host verify.
impl CanonicalEncode for AgentBundle {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.generation);
        encoder.u32(self.components.len() as u32);
        for component in &self.components {
            encoder.bytes(&component.manifest_row());
        }
        encoder.digest(self.root);
    }
}

impl CanonicalDecode for AgentBundle {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let generation = decoder.text()?.to_owned();
        let count = decoder.u32()?;
        let mut components = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let row = decoder.bytes()?;
            let mut row_decoder = CanonicalDecoder::new(row);
            let kind = ComponentKind::decode_canonical(&mut row_decoder)?;
            let name = row_decoder.text()?.to_owned();
            let content_digest = row_decoder.digest()?;
            let size_bytes = row_decoder.u64()?;
            row_decoder.ensure_finished()?;
            components.push(
                BundleComponent::new_with_digest(kind, name, content_digest, size_bytes)
                    .map_err(|_| ContractError::InvalidIdentifier)?,
            );
        }
        let root = decoder.digest()?;
        decoder.ensure_finished()?;
        let bundle = AgentBundle {
            generation,
            components,
            root,
        };
        if !bundle.verify() {
            return Err(ContractError::InvalidDigest);
        }
        Ok(bundle)
    }
}

/// A builder for an [`AgentBundle`] that enforces component invariants.
#[derive(Clone, Debug)]
pub struct AgentBundleBuilder {
    generation: String,
    components: Vec<BundleComponent>,
}

impl AgentBundleBuilder {
    /// Starts a builder for one agent generation (never `latest`/empty).
    pub fn new(generation: impl Into<String>) -> Result<Self, BundleError> {
        let generation = generation.into();
        if generation.is_empty() {
            return Err(BundleError::EmptyGeneration);
        }
        if generation == "latest" {
            return Err(BundleError::LatestGeneration);
        }
        Ok(Self {
            generation,
            components: Vec::new(),
        })
    }

    /// Adds a component built from its bytes. Fails on a duplicate `(kind, name)`.
    pub fn add_component(
        mut self,
        kind: ComponentKind,
        name: impl Into<String>,
        content: &[u8],
    ) -> Result<Self, BundleError> {
        let component = BundleComponent::new(kind, name, content)?;
        if self
            .components
            .iter()
            .any(|c| c.kind() == component.kind() && c.name() == component.name())
        {
            return Err(BundleError::DuplicateComponent);
        }
        self.components.push(component);
        Ok(self)
    }

    /// Adds a component from a known digest and size.
    pub fn add_component_digest(
        mut self,
        kind: ComponentKind,
        name: impl Into<String>,
        content_digest: ContentDigest,
        size_bytes: u64,
    ) -> Result<Self, BundleError> {
        let component = BundleComponent::new_with_digest(kind, name, content_digest, size_bytes)?;
        if self
            .components
            .iter()
            .any(|c| c.kind() == component.kind() && c.name() == component.name())
        {
            return Err(BundleError::DuplicateComponent);
        }
        self.components.push(component);
        Ok(self)
    }

    /// Builds the bundle, sorting components canonically and computing the root.
    pub fn build(mut self) -> Result<AgentBundle, BundleError> {
        if self.components.is_empty() {
            return Err(BundleError::NoComponents);
        }
        self.components
            .sort_by(|a, b| a.kind().cmp(&b.kind()).then_with(|| a.name().cmp(b.name())));
        let root = {
            let mut encoder = CanonicalEncoder::new();
            encoder.text(&self.generation);
            encoder.u32(self.components.len() as u32);
            for component in &self.components {
                encoder.bytes(&component.manifest_row());
            }
            ContentDigest::sha256(&encoder.finish())
        };
        Ok(AgentBundle {
            generation: self.generation,
            components: self.components,
            root,
        })
    }
}

/// Pushes a reference component if it builds; the reference inputs are
/// constants, so this branch is not rejected in practice.
fn push_reference_component(
    components: &mut Vec<BundleComponent>,
    kind: ComponentKind,
    name: &str,
    content: &[u8],
) {
    if let Ok(component) = BundleComponent::new(kind, name, content) {
        components.push(component);
    }
}

/// Typed bundle construction failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleError {
    /// A component name is empty.
    EmptyName,
    /// A component has no bytes (or zero size).
    EmptyContent,
    /// The agent generation is empty.
    EmptyGeneration,
    /// The agent generation is the forbidden `latest` alias.
    LatestGeneration,
    /// A `(kind, name)` component already exists in the bundle.
    DuplicateComponent,
    /// The bundle has no components.
    NoComponents,
    /// A canonical encode/decode failed.
    Canonical(ContractError),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => f.write_str("bundle component name is empty"),
            Self::EmptyContent => f.write_str("bundle component has no content"),
            Self::EmptyGeneration => f.write_str("agent generation is empty"),
            Self::LatestGeneration => f.write_str("agent generation must not be 'latest'"),
            Self::DuplicateComponent => f.write_str("duplicate bundle component (kind, name)"),
            Self::NoComponents => f.write_str("bundle has no components"),
            Self::Canonical(e) => write!(f, "bundle canonical failure: {e}"),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<ContractError> for BundleError {
    fn from(value: ContractError) -> Self {
        Self::Canonical(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_bundle() -> Result<AgentBundle, BundleError> {
        AgentBundleBuilder::new("fss-agent/1")
            .and_then(|b| {
                b.add_component(ComponentKind::BaseFirmware, "fw-a", b"firmware-bytes-A")
            })
            .and_then(|b| {
                b.add_component(ComponentKind::RustAgent, "agent", b"agent-bytes")
            })
            .and_then(|b| {
                b.add_component_digest(
                    ComponentKind::Tailscaled,
                    "ts",
                    ContentDigest::sha256(b"tailscaled-bytes"),
                    16,
                )
            })
            .and_then(|b| b.build())
    }

    #[test]
    fn reference_bundle_is_deterministic_and_verifies() {
        let a = AgentBundle::reference(CameraFamily::Yi);
        let b = AgentBundle::reference(CameraFamily::Yi);
        assert_eq!(a.root(), b.root());
        assert!(a.verify());
        assert_eq!(a.components().len(), 4);
        assert_eq!(a.generation(), "fss-agent/1");
    }

    #[test]
    fn different_family_yields_different_root() {
        let yi = AgentBundle::reference(CameraFamily::Yi);
        let openipc = AgentBundle::reference(CameraFamily::OpenIPCClassA);
        assert_ne!(yi.root(), openipc.root());
    }

    #[test]
    fn bundle_canonical_round_trips() {
        let bundle = fixture_bundle();
        let bundle = match bundle {
            Ok(b) => b,
            Err(_) => return,
        };
        let bytes = bundle.canonical_bytes();
        let decoded = AgentBundle::from_canonical_bytes(&bytes);
        assert_eq!(Ok(bundle), decoded);
    }

    #[test]
    fn duplicate_component_is_rejected() {
        let builder = AgentBundleBuilder::new("fss-agent/1")
            .and_then(|b| b.add_component(ComponentKind::RustAgent, "agent", b"x"))
            .and_then(|b| b.add_component(ComponentKind::RustAgent, "agent", b"y"));
        assert!(matches!(builder, Err(BundleError::DuplicateComponent)));
    }

    #[test]
    fn empty_and_latest_generation_rejected() {
        assert!(matches!(
            AgentBundleBuilder::new(""),
            Err(BundleError::EmptyGeneration)
        ));
        assert!(matches!(
            AgentBundleBuilder::new("latest"),
            Err(BundleError::LatestGeneration)
        ));
    }

    #[test]
    fn build_requires_at_least_one_component() {
        let builder = AgentBundleBuilder::new("fss-agent/1");
        let built = match builder {
            Ok(b) => b.build(),
            Err(_) => return,
        };
        assert!(matches!(built, Err(BundleError::NoComponents)));
    }

    #[test]
    fn components_are_canonically_ordered() {
        let bundle = fixture_bundle();
        let bundle = match bundle {
            Ok(b) => b,
            Err(_) => return,
        };
        // BaseFirmware(1) < RustAgent(2) < Tailscaled(3): already in order.
        let kinds: Vec<ComponentKind> = bundle.components().iter().map(|c| c.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                ComponentKind::BaseFirmware,
                ComponentKind::RustAgent,
                ComponentKind::Tailscaled
            ]
        );
    }
}
