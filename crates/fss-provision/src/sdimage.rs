//! Deterministic FAT32 SD-image layout for the SD-updater flash class (LAB-
//! PROVISION-001).
//!
//! yi-hack (and the SD-updater class generally) flashes from a FAT32 card: the
//! owner inserts a pre-written card and the camera's own updater copies the
//! files at power-on. This module produces that card's exact layout — paths,
//! sizes, content digests — from an [`AgentBundle`], with a stable image
//! digest, so the physical act of writing the card is a mechanical copy of a
//! verified plan.
//!
//! This is a **reference layout**: the deterministic, digest-pinned shape the
//! planner and reference tests use. The exact per-release file names that a
//! specific yi-hack variant's updater expects are qualified against that
//! release's own layout (a fixture) once the owner reads the label; the model
//! here never claims to be that layout, only the canonical form of it.
//!
//! Sans-IO: bytes in (a bundle), a verified plan out. No filesystem is opened.

use core::fmt;

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::bundle::{AgentBundle, ComponentKind};
use crate::family::CameraFamily;

/// Minimum sane card capacity admitted (64 MiB).
pub const MIN_SDCARD_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum card capacity admitted (256 GiB).
pub const MAX_SDCARD_BYTES: u64 = 256 * 1024 * 1024 * 1024;
/// Reserved FAT/directory overhead subtracted from capacity (1 MiB).
pub const SDCARD_OVERHEAD_BYTES: u64 = 1024 * 1024;
/// Maximum VFAT long-path length in bytes.
pub const MAX_PATH_BYTES: usize = 255;

/// One file in the SD image: a path, its size, and its content digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageEntry {
    path: String,
    size_bytes: u64,
    content_digest: ContentDigest,
}

impl ImageEntry {
    const fn new(path: String, size_bytes: u64, content_digest: ContentDigest) -> Self {
        Self {
            path,
            size_bytes,
            content_digest,
        }
    }

    /// The file path relative to the FAT32 root.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The file size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// The content digest of the file bytes.
    #[must_use]
    pub const fn content_digest(&self) -> ContentDigest {
        self.content_digest
    }

    fn canonical_row(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(&self.path);
        encoder.u64(self.size_bytes);
        encoder.digest(self.content_digest);
        encoder.finish()
    }
}

/// A verified, digest-pinned FAT32 image plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdImagePlan {
    family: CameraFamily,
    /// The selected release (e.g. a yi-hack variant handle).
    release: String,
    /// Canonically ordered (by path) file entries.
    entries: Vec<ImageEntry>,
    /// Sum of all entry sizes.
    total_bytes: u64,
    /// The card capacity the plan was sized against.
    card_capacity_bytes: u64,
    /// SHA-256 of the canonical manifest over the ordered entries.
    image_digest: ContentDigest,
}

impl SdImagePlan {
    /// The family the image is for.
    #[must_use]
    pub const fn family(&self) -> CameraFamily {
        self.family
    }

    /// The selected release.
    #[must_use]
    pub fn release(&self) -> &str {
        &self.release
    }

    /// The canonically ordered file entries.
    #[must_use]
    pub fn entries(&self) -> &[ImageEntry] {
        &self.entries
    }

    /// The total size of all entries in bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// The card capacity the plan was sized against.
    #[must_use]
    pub const fn card_capacity_bytes(&self) -> u64 {
        self.card_capacity_bytes
    }

    /// The image digest binding the whole layout.
    #[must_use]
    pub const fn image_digest(&self) -> ContentDigest {
        self.image_digest
    }

    /// Whether the stored digest still matches the layout (no drift).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.image_digest == self.computed_digest()
    }

    /// Recomputes the image digest from the current fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.u8(self.family as u8);
        encoder.text(&self.release);
        encoder.u32(self.entries.len() as u32);
        for entry in &self.entries {
            encoder.bytes(&entry.canonical_row());
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Typed SD-image layout failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdImageError {
    /// The release handle is empty.
    EmptyRelease,
    /// The card capacity is outside the admitted range.
    BadCapacity {
        /// The rejected card capacity in bytes.
        capacity_bytes: u64,
    },
    /// The bundle produced no files.
    NoEntries,
    /// Two entries would occupy the same path.
    DuplicatePath(String),
    /// A path exceeds the VFAT long-path bound.
    PathTooLong(String),
    /// The layout does not fit the card after overhead.
    ImageTooLarge {
        /// The total size of all entries in bytes.
        total_bytes: u64,
        /// The card capacity in bytes.
        capacity_bytes: u64,
    },
}

impl fmt::Display for SdImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRelease => f.write_str("release handle is empty"),
            Self::BadCapacity { capacity_bytes } => {
                write!(f, "card capacity {capacity_bytes} outside admitted range")
            }
            Self::NoEntries => f.write_str("bundle produced no image entries"),
            Self::DuplicatePath(path) => write!(f, "duplicate image path {path}"),
            Self::PathTooLong(path) => write!(f, "image path too long: {path}"),
            Self::ImageTooLarge {
                total_bytes,
                capacity_bytes,
            } => write!(f, "image {total_bytes}B does not fit a {capacity_bytes}B card"),
        }
    }
}

impl std::error::Error for SdImageError {}

/// The directory (relative to root) a component kind lands in.
fn directory_for_kind(kind: ComponentKind) -> &'static str {
    match kind {
        ComponentKind::BaseFirmware => "firmware",
        ComponentKind::RustAgent => "agent",
        ComponentKind::Tailscaled => "tailscale",
        ComponentKind::SwapConfig => "config",
    }
}

/// A builder that lays out a FAT32 image for a card of a fixed capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdImageBuilder {
    capacity_bytes: u64,
}

impl SdImageBuilder {
    /// Creates a builder for a card of the given capacity, failing closed if
    /// the capacity is not in the admitted range.
    pub const fn new(capacity_bytes: u64) -> Result<Self, SdImageError> {
        let builder = Self { capacity_bytes };
        if capacity_bytes < MIN_SDCARD_BYTES || capacity_bytes > MAX_SDCARD_BYTES {
            return Err(SdImageError::BadCapacity { capacity_bytes });
        }
        Ok(builder)
    }

    /// The card capacity this builder sizes against.
    #[must_use]
    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    /// Builds the image plan for a release from a bundle.
    pub fn build(
        &self,
        family: CameraFamily,
        release: impl Into<String>,
        bundle: &AgentBundle,
    ) -> Result<SdImagePlan, SdImageError> {
        let release = release.into();
        if release.is_empty() {
            return Err(SdImageError::EmptyRelease);
        }

        let mut entries: Vec<ImageEntry> = Vec::with_capacity(bundle.components().len());
        let mut total_bytes: u64 = 0;
        for component in bundle.components() {
            let path = format!("/{}/{}", directory_for_kind(component.kind()), component.name());
            if path.len() > MAX_PATH_BYTES {
                return Err(SdImageError::PathTooLong(path));
            }
            if entries.iter().any(|e| e.path() == path) {
                return Err(SdImageError::DuplicatePath(path));
            }
            total_bytes = total_bytes
                .checked_add(component.size_bytes())
                .ok_or(SdImageError::ImageTooLarge {
                    total_bytes: u64::MAX,
                    capacity_bytes: self.capacity_bytes,
                })?;
            entries.push(ImageEntry::new(
                path,
                component.size_bytes(),
                component.content_digest(),
            ));
        }

        if entries.is_empty() {
            return Err(SdImageError::NoEntries);
        }

        let available = self
            .capacity_bytes
            .checked_sub(SDCARD_OVERHEAD_BYTES)
            .ok_or(SdImageError::ImageTooLarge {
                total_bytes,
                capacity_bytes: self.capacity_bytes,
            })?;
        if total_bytes > available {
            return Err(SdImageError::ImageTooLarge {
                total_bytes,
                capacity_bytes: self.capacity_bytes,
            });
        }

        entries.sort_by(|a, b| a.path().cmp(b.path()));
        let image_digest = {
            let mut encoder = CanonicalEncoder::new();
            encoder.u8(family as u8);
            encoder.text(&release);
            encoder.u32(entries.len() as u32);
            for entry in &entries {
                encoder.bytes(&entry.canonical_row());
            }
            ContentDigest::sha256(&encoder.finish())
        };

        Ok(SdImagePlan {
            family,
            release,
            entries,
            total_bytes,
            card_capacity_bytes: self.capacity_bytes,
            image_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARD_8_GIB: u64 = 8 * 1024 * 1024 * 1024;

    fn yi_bundle() -> AgentBundle {
        AgentBundle::reference(CameraFamily::Yi)
    }

    #[test]
    fn image_is_deterministic_and_verifies() {
        let builder = SdImageBuilder::new(CARD_8_GIB);
        let builder = match builder {
            Ok(b) => b,
            Err(_) => return,
        };
        let plan_a = builder.build(CameraFamily::Yi, "yihack-2.0.1-armv7", &yi_bundle());
        let plan_b = builder.build(CameraFamily::Yi, "yihack-2.0.1-armv7", &yi_bundle());
        let (plan_a, plan_b) = match (plan_a, plan_b) {
            (Ok(a), Ok(b)) => (a, b),
            _ => return,
        };
        assert_eq!(plan_a.image_digest(), plan_b.image_digest());
        assert!(plan_a.verify());
        assert_eq!(plan_a.entries().len(), 4);
        // Paths are canonically ordered and each lands in its kind directory.
        assert!(plan_a.entries()[0].path().starts_with('/'));
    }

    #[test]
    fn different_release_or_family_changes_digest() {
        let builder = SdImageBuilder::new(CARD_8_GIB);
        let builder = match builder {
            Ok(b) => b,
            Err(_) => return,
        };
        let yi_a = builder.build(CameraFamily::Yi, "rel-a", &yi_bundle());
        let yi_b = builder.build(CameraFamily::Yi, "rel-b", &yi_bundle());
        let yi_openipc = builder.build(CameraFamily::OpenIPCClassA, "rel-a", &yi_bundle());
        if let (Ok(a), Ok(b), Ok(c)) = (yi_a, yi_b, yi_openipc) {
            assert_ne!(a.image_digest(), b.image_digest());
            assert_ne!(a.image_digest(), c.image_digest());
        }
    }

    #[test]
    fn total_bytes_sum_the_entries() {
        let builder = SdImageBuilder::new(CARD_8_GIB);
        let builder = match builder {
            Ok(b) => b,
            Err(_) => return,
        };
        let plan = builder.build(CameraFamily::Yi, "rel", &yi_bundle());
        let plan = match plan {
            Ok(p) => p,
            Err(_) => return,
        };
        let mut sum = 0u64;
        for entry in plan.entries() {
            sum = sum.saturating_add(entry.size_bytes());
        }
        assert_eq!(plan.total_bytes(), sum);
    }

    #[test]
    fn bad_capacity_is_rejected() {
        assert!(matches!(
            SdImageBuilder::new(MIN_SDCARD_BYTES - 1),
            Err(SdImageError::BadCapacity { .. })
        ));
        assert!(matches!(
            SdImageBuilder::new(MAX_SDCARD_BYTES + 1),
            Err(SdImageError::BadCapacity { .. })
        ));
        assert!(SdImageBuilder::new(CARD_8_GIB).is_ok());
    }

    #[test]
    fn empty_release_is_rejected() {
        let builder = SdImageBuilder::new(CARD_8_GIB);
        let builder = match builder {
            Ok(b) => b,
            Err(_) => return,
        };
        let result = builder.build(CameraFamily::Yi, "", &yi_bundle());
        assert!(matches!(result, Err(SdImageError::EmptyRelease)));
    }
}
