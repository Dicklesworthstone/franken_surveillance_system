#![forbid(unsafe_code)]
//! Deployment capacity limits, `LAYOUT` descriptor codec, atomic `LAYOUT` I/O, and root skeleton checks.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest, ContractError};
use fss_object::SpoolLimits;
use fss_publication::LocalPublicationLimits;

use super::constants::{
    DEPLOYMENT_LAYOUT_FILENAME, DEPLOYMENT_LAYOUT_FORMAT_VERSION, DEPLOYMENT_LAYOUT_SCHEMA,
    RELATIVE_PATH_EFFECTS, RELATIVE_PATH_LEDGER, RELATIVE_PATH_OBJECTS, validate_site_lineage,
};
use crate::error::ReferenceError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DeploymentOpenMode {
    InitializeAndReconcile,
    ExistingWithoutEffectReconciliation,
}

pub(super) fn is_skeleton_or_empty(root: &Path) -> Result<bool, ReferenceError> {
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error.into()),
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let s = name.to_string_lossy();
        let kind = entry.file_type()?;
        if (s == DEPLOYMENT_LAYOUT_FILENAME || s.starts_with("LAYOUT.tmp.")) && kind.is_file() {
            continue;
        }
        if s == "objects" {
            let path = entry.path();
            if kind.is_dir() {
                for sub in fs::read_dir(&path)? {
                    let sub = sub?;
                    let sub_name = sub.file_name();
                    let sub_s = sub_name.to_string_lossy();
                    let sub_kind = sub.file_type()?;
                    if (sub_s == "LOCK" || sub_s.starts_with("LOCK.tmp."))
                        && sub_kind.is_file()
                        && sub.metadata()?.len() == 0
                    {
                        continue;
                    }
                    if sub_s == "roots" || sub_s == "tombstones" {
                        let sub_path = sub.path();
                        if sub_kind.is_dir() {
                            if fs::read_dir(&sub_path)?.next().is_some() {
                                return Ok(false);
                            }
                            continue;
                        }
                        return Ok(false);
                    }
                    if sub_s == "spool" {
                        let sub_path = sub.path();
                        if sub_kind.is_dir() {
                            for inner in fs::read_dir(&sub_path)? {
                                let inner = inner?;
                                let inner_name = inner.file_name();
                                let inner_s = inner_name.to_string_lossy();
                                let inner_kind = inner.file_type()?;
                                if (inner_s == "LOCK" || inner_s.starts_with("LOCK.tmp."))
                                    && inner_kind.is_file()
                                    && inner.metadata()?.len() == 0
                                {
                                    continue;
                                }
                                if (inner_s == "objects"
                                    || inner_s == "staging"
                                    || inner_s == "verified"
                                    || inner_s == "verified.tmp"
                                    || inner_s == "holds"
                                    || inner_s == "staged"
                                    || inner_s == "corrupt")
                                    && inner_kind.is_dir()
                                {
                                    if fs::read_dir(inner.path())?.next().is_some() {
                                        return Ok(false);
                                    }
                                    continue;
                                }
                                return Ok(false);
                            }
                            continue;
                        }
                        return Ok(false);
                    }
                    return Ok(false);
                }
                continue;
            }
            return Ok(false);
        }
        if s == "ledger" || s == "effects" {
            if kind.is_dir() {
                for journal in fs::read_dir(entry.path())? {
                    let journal = journal?;
                    if journal.file_name() != "journal.fssj"
                        || !journal.file_type()?.is_file()
                        || journal.metadata()?.len() != 0
                    {
                        return Ok(false);
                    }
                }
                continue;
            }
            return Ok(false);
        }
        return Ok(false);
    }
    Ok(true)
}

/// Only an empty initialization skeleton may create a missing journal. LAYOUT is published
/// before the two journal files during initialization, so its presence alone cannot distinguish
/// a new root interrupted at that boundary from a deployment with lost history. Any surviving
/// journal records, retained objects, publication, session, or unknown entry makes that distinction
/// unsafe: refusing preserves the evidence needed for deliberate recovery.
pub(super) fn require_journals_or_empty_skeleton(root: &Path) -> Result<(), ReferenceError> {
    let mut missing = None;
    for relative in [RELATIVE_PATH_LEDGER, RELATIVE_PATH_EFFECTS] {
        let path = root.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return Err(ReferenceError::NotADeployment {
                    path: root.to_path_buf(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.get_or_insert(path);
            }
            Err(error) => return Err(error.into()),
        }
    }
    if let Some(path) = missing
        && !is_skeleton_or_empty(root)?
    {
        return Err(ReferenceError::MissingDeploymentJournal { path });
    }
    Ok(())
}

/// An evaluation may inspect an established deployment, but cannot complete initialization or
/// replace lost history. Check this before opening the publisher and again under its lock.
pub(super) fn require_existing_layout_and_journals(root: &Path) -> Result<(), ReferenceError> {
    match fs::symlink_metadata(root.join(DEPLOYMENT_LAYOUT_FILENAME)) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(ReferenceError::NotADeployment {
                path: root.to_path_buf(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ReferenceError::NotADeployment {
                path: root.to_path_buf(),
            });
        }
        Err(error) => return Err(error.into()),
    }
    for relative in [RELATIVE_PATH_LEDGER, RELATIVE_PATH_EFFECTS] {
        let path = root.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return Err(ReferenceError::NotADeployment {
                    path: root.to_path_buf(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ReferenceError::MissingDeploymentJournal { path });
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Explicit capacity limits bounding a reference deployment instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentLimits {
    /// Maximum size of a single spool object in bytes (default: 64 MiB).
    pub spool_object_max_bytes: u64,
    /// Maximum total spool storage across all staged objects in bytes (default: 512 MiB).
    pub spool_total_max_bytes: u64,
    /// Maximum number of children in a manifest (default: 16,384).
    pub manifest_children_max: usize,
    /// Maximum deltas or children per authority batch (default: 16,384).
    pub batch_entries_max: usize,
    /// Maximum size of a single journal record payload in bytes (default: 16 MiB).
    pub journal_record_max_bytes: u32,
    /// Maximum visible roots (default: 128).
    pub max_roots: usize,
    /// Maximum durable tombstones (default: 128).
    pub max_tombstones: usize,
    /// Maximum unique staged objects in the spool (default: 65,536).
    pub spool_max_objects: usize,
    /// Maximum entries listed from one directory on open (default: 131,072). The spool requires it
    /// to be at least `spool_max_objects`, and the publisher at least `max_roots` and
    /// `max_tombstones`; an inconsistent set is refused on open, never silently raised.
    pub scan_max_objects: usize,
}

impl Default for DeploymentLimits {
    fn default() -> Self {
        Self::standard()
    }
}

impl DeploymentLimits {
    /// Standard 64 MiB spool object maximum.
    pub const STANDARD_SPOOL_OBJECT_MAX_BYTES: u64 = 64 * 1024 * 1024;
    /// Standard 512 MiB spool total maximum.
    pub const STANDARD_SPOOL_TOTAL_MAX_BYTES: u64 = 512 * 1024 * 1024;
    /// Standard 16,384 manifest children maximum.
    pub const STANDARD_MANIFEST_CHILDREN_MAX: usize = 16_384;
    /// Standard 16,384 entries per batch maximum.
    pub const STANDARD_BATCH_ENTRIES_MAX: usize = 16_384;
    /// Standard 16 MiB journal record payload maximum.
    pub const STANDARD_JOURNAL_RECORD_MAX_BYTES: u32 = 16 * 1024 * 1024;
    /// Standard 128 visible roots maximum.
    pub const STANDARD_MAX_ROOTS: usize = 128;
    /// Standard 128 durable tombstones maximum.
    pub const STANDARD_MAX_TOMBSTONES: usize = 128;
    /// Standard 65,536 spool objects maximum.
    pub const STANDARD_SPOOL_MAX_OBJECTS: usize = 65_536;
    /// Standard 131,072 directory entries scan maximum (twice the standard spool object bound).
    ///
    /// Not a registered policy threshold: no row in `registries/*.md` or `architecture/*` names
    /// this bound or the spool object bound (checked against main 361f3fa, fss-2h5zq.9). It is a
    /// structural invariant of the owned staging spool, whose `SpoolLimits::validate` refuses
    /// a scan bound below `spool_max_objects` (`ScanBoundBelowObjectBound`); the publisher also
    /// requires it to be at least `max_roots` and `max_tombstones`. 131,072 matches
    /// `SpoolLimits::default()` for 65,536 objects. The earlier 4,096 made every standard open
    /// fail. `exported_constants_and_tables_integrity` validates the standard publication limits.
    pub const STANDARD_SCAN_MAX_OBJECTS: usize = 131_072;

    /// Standard deployment bounds.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            spool_object_max_bytes: Self::STANDARD_SPOOL_OBJECT_MAX_BYTES,
            spool_total_max_bytes: Self::STANDARD_SPOOL_TOTAL_MAX_BYTES,
            manifest_children_max: Self::STANDARD_MANIFEST_CHILDREN_MAX,
            batch_entries_max: Self::STANDARD_BATCH_ENTRIES_MAX,
            journal_record_max_bytes: Self::STANDARD_JOURNAL_RECORD_MAX_BYTES,
            max_roots: Self::STANDARD_MAX_ROOTS,
            max_tombstones: Self::STANDARD_MAX_TOMBSTONES,
            spool_max_objects: Self::STANDARD_SPOOL_MAX_OBJECTS,
            scan_max_objects: Self::STANDARD_SCAN_MAX_OBJECTS,
        }
    }

    /// Computes the canonical content digest of the deployment limits.
    pub fn canonical_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.reference_deployment.limits.v1");
        encoder.u64(self.spool_object_max_bytes);
        encoder.u64(self.spool_total_max_bytes);
        encoder.u64(self.manifest_children_max as u64);
        encoder.u64(self.batch_entries_max as u64);
        encoder.u32(self.journal_record_max_bytes);
        encoder.u64(self.max_roots as u64);
        encoder.u64(self.max_tombstones as u64);
        encoder.u64(self.spool_max_objects as u64);
        encoder.u64(self.scan_max_objects as u64);
        let bytes = encoder.finish_checked()?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Converts these limits to publication layer limits.
    #[must_use]
    pub fn to_publication_limits(&self) -> LocalPublicationLimits {
        let max_object_bytes = match usize::try_from(self.spool_object_max_bytes) {
            Ok(n) => n,
            Err(_) => usize::MAX,
        };
        let spool_scan = self.scan_max_objects;
        LocalPublicationLimits::new(
            self.max_roots,
            self.manifest_children_max,
            self.max_tombstones,
            self.scan_max_objects,
            SpoolLimits::new(
                self.spool_max_objects,
                self.spool_total_max_bytes,
                max_object_bytes,
                spool_scan,
            ),
        )
    }
}

/// Read-only deployment layout report and on-disk descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentLayout {
    /// Schema identity (`fss.reference_deployment.layout.v1`).
    pub schema: String,
    /// Layout format version.
    pub format_version: u32,
    /// Site lineage identifier.
    pub site_lineage: String,
    /// Relative path to authority ledger journal.
    pub ledger_relpath: String,
    /// Relative path to object storage directory.
    pub objects_relpath: String,
    /// Relative path to durable effect journal.
    pub effects_relpath: String,
    /// Canonical digest of the deployment capacity limits.
    pub limits_digest: ContentDigest,
}

impl DeploymentLayout {
    /// Constructs a standard layout specification with the given lineage and limits digest.
    #[must_use]
    pub fn new(site_lineage: &str, limits_digest: ContentDigest) -> Self {
        Self {
            schema: DEPLOYMENT_LAYOUT_SCHEMA.to_owned(),
            format_version: DEPLOYMENT_LAYOUT_FORMAT_VERSION,
            site_lineage: site_lineage.to_owned(),
            ledger_relpath: RELATIVE_PATH_LEDGER.to_owned(),
            objects_relpath: RELATIVE_PATH_OBJECTS.to_owned(),
            effects_relpath: RELATIVE_PATH_EFFECTS.to_owned(),
            limits_digest,
        }
    }

    /// Computes the canonical content digest of the layout.
    pub fn canonical_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DEPLOYMENT_LAYOUT_SCHEMA);
        encoder.u32(self.format_version);
        encoder.text(&self.site_lineage);
        encoder.text(&self.ledger_relpath);
        encoder.text(&self.objects_relpath);
        encoder.text(&self.effects_relpath);
        encoder.digest(self.limits_digest);
        let bytes = encoder.finish_checked()?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Serializes to canonical text for writing to the LAYOUT file.
    #[must_use]
    pub fn to_canonical_text(&self) -> String {
        format!(
            "schema={}\nversion={}\nsite_lineage={}\nledger={}\nobjects={}\neffects={}\nlimits_digest={}\n",
            self.schema,
            self.format_version,
            self.site_lineage,
            self.ledger_relpath,
            self.objects_relpath,
            self.effects_relpath,
            self.limits_digest.to_text()
        )
    }

    /// Parses canonical text from the LAYOUT file.
    pub fn parse_canonical_text(text: &str) -> Result<Self, ReferenceError> {
        let mut schema = None;
        let mut version = None;
        let mut site_lineage = None;
        let mut ledger = None;
        let mut objects = None;
        let mut effects = None;
        let mut limits_digest = None;

        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                return Err(ReferenceError::InvalidSpec(
                    "layout line must use '=' separator",
                ));
            };

            match key {
                "schema" => {
                    if schema.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: schema"));
                    }
                    schema = Some(value.to_owned());
                }
                "version" => {
                    if version.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: version"));
                    }
                    let v = value.parse::<u32>().map_err(|_| {
                        ReferenceError::InvalidSpec("invalid layout format version")
                    })?;
                    version = Some(v);
                }
                "site_lineage" => {
                    if site_lineage.is_some() {
                        return Err(ReferenceError::InvalidSpec(
                            "duplicate layout key: site_lineage",
                        ));
                    }
                    validate_site_lineage(value)?;
                    site_lineage = Some(value.to_owned());
                }
                "ledger" => {
                    if ledger.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: ledger"));
                    }
                    if value != RELATIVE_PATH_LEDGER {
                        return Err(ReferenceError::InvalidSpec("invalid layout ledger relpath"));
                    }
                    ledger = Some(value.to_owned());
                }
                "objects" => {
                    if objects.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: objects"));
                    }
                    if value != RELATIVE_PATH_OBJECTS {
                        return Err(ReferenceError::InvalidSpec(
                            "invalid layout objects relpath",
                        ));
                    }
                    objects = Some(value.to_owned());
                }
                "effects" => {
                    if effects.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: effects"));
                    }
                    if value != RELATIVE_PATH_EFFECTS {
                        return Err(ReferenceError::InvalidSpec(
                            "invalid layout effects relpath",
                        ));
                    }
                    effects = Some(value.to_owned());
                }
                "limits_digest" => {
                    if limits_digest.is_some() {
                        return Err(ReferenceError::InvalidSpec(
                            "duplicate layout key: limits_digest",
                        ));
                    }
                    let digest = ContentDigest::parse(value)
                        .map_err(|_| ReferenceError::InvalidSpec("invalid layout limits digest"))?;
                    limits_digest = Some(digest);
                }
                _ => return Err(ReferenceError::InvalidSpec("unknown layout key")),
            }
        }

        let schema = schema.ok_or(ReferenceError::InvalidSpec("missing layout schema"))?;
        let version = version.ok_or(ReferenceError::InvalidSpec("missing layout version"))?;
        let site_lineage =
            site_lineage.ok_or(ReferenceError::InvalidSpec("missing layout site lineage"))?;
        let ledger = ledger.ok_or(ReferenceError::InvalidSpec("missing layout ledger"))?;
        let objects = objects.ok_or(ReferenceError::InvalidSpec("missing layout objects"))?;
        let effects = effects.ok_or(ReferenceError::InvalidSpec("missing layout effects"))?;
        let limits_digest =
            limits_digest.ok_or(ReferenceError::InvalidSpec("missing layout limits digest"))?;

        if schema != DEPLOYMENT_LAYOUT_SCHEMA {
            return Err(ReferenceError::InvalidSpec("incompatible layout schema"));
        }
        if version != DEPLOYMENT_LAYOUT_FORMAT_VERSION {
            return Err(ReferenceError::InvalidSpec("incompatible layout version"));
        }

        let layout = Self {
            schema,
            format_version: version,
            site_lineage,
            ledger_relpath: ledger,
            objects_relpath: objects,
            effects_relpath: effects,
            limits_digest,
        };

        if layout.to_canonical_text() != text {
            return Err(ReferenceError::InvalidSpec("layout text is not canonical"));
        }

        Ok(layout)
    }
}

/// Filesystem boundary for the two commit steps of [`write_layout_atomic`].
///
/// The temporary descriptor is always written and fsynced through the host filesystem. The two
/// steps that decide visibility and durability, the rename onto `LAYOUT` and the fsync of the
/// deployment root directory, go through this trait, so a failure-path test injects an error at
/// either step through a value it owns and no process-wide state is involved.
pub trait LayoutIo {
    /// Atomically renames `from` onto `to`.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    /// Fsyncs the directory `dir` so a rename inside it is durable.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
}

/// The host filesystem implementation of [`LayoutIo`]; [`super::ReferenceDeployment::open`] uses it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostLayoutIo;

impl LayoutIo for HostLayoutIo {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        let dir = fs::File::open(dir)?;
        dir.sync_all()
    }
}

/// Writes `layout` as `<root>/LAYOUT` atomically.
///
/// The canonical text is written to `LAYOUT.tmp.<pid>` and fsynced, renamed onto `LAYOUT` through
/// `io`, and the root directory is then fsynced through `io`. Pass [`HostLayoutIo`] outside tests.
///
/// A failure before or at the rename leaves any previous `LAYOUT` byte-identical; the temporary
/// file stays behind and the next open removes it under the deployment lock. A failed directory
/// fsync after the rename is returned as an error: the new descriptor is visible, but its
/// durability is not proven, so the write is never reported as complete.
///
/// # Errors
///
/// [`ReferenceError::InvalidSpec`] if the site lineage is invalid (nothing is written), and
/// [`ReferenceError::Io`] for any filesystem failure, including one injected through `io`.
pub fn write_layout_atomic(
    root: &Path,
    layout: &DeploymentLayout,
    io: &dyn LayoutIo,
) -> Result<(), ReferenceError> {
    validate_site_lineage(&layout.site_lineage)?;
    let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);
    let temp_path = root.join(format!(
        "{}.tmp.{}",
        DEPLOYMENT_LAYOUT_FILENAME,
        std::process::id()
    ));
    let text = layout.to_canonical_text();
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    }
    io.rename(&temp_path, &layout_path)?;
    io.sync_dir(root)?;
    Ok(())
}
