#![forbid(unsafe_code)]
//! Exact historical ONVIF handoff bindings and protected input leases for site planning.
//!
//! The caller's read context owns every filesystem boundary. A handoff never proves its
//! HTTP origin, current liveness or capture authority. Independent RTSP scope, selected
//! profile and onboarding-plan expectations are explicit, pinned inputs to the plan.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;

use fss_core::json_input::{self, Value};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::site::{SiteManifest, SourceKind};

use crate::onvif_plan::{MAX_ONVIF_HANDOFF_BYTES, OnvifSourceSpec, ProtectedOnvifInput};
use crate::site_plan::{SiteOnvifInput, SitePlanError, SitePlanOptions};

#[allow(
    dead_code,
    unused_imports,
    reason = "The existing private-file owner also writes outputs"
)]
#[path = "bin/fss-onvif/private_file.rs"]
mod private_file;

/// Strict explicit operator bindings for existing private ONVIF handoff artifacts.
pub const SITE_ONVIF_BINDINGS_SCHEMA: &str = "fss.site_onvif_bindings.v1";
/// Maximum complete UTF-8 binding document.
pub const MAX_SITE_ONVIF_BINDINGS_BYTES: usize = 1024 * 1024;
/// Maximum retained handoff bytes: 64 complete native 8 KiB handoffs.
pub const MAX_SITE_ONVIF_HANDOFF_BYTES: usize = 64 * MAX_ONVIF_HANDOFF_BYTES;
/// Stable refusal identity without private paths, profile tokens or capability URLs.
pub const ERR_SITE_ONVIF_INPUT: &str = "ERR-SITE-ONVIF-INPUT-001";

pub(crate) struct Binding {
    pub(crate) source_index: usize,
    pub(crate) source_id: String,
    pub(crate) spec: OnvifSourceSpec,
    pub(crate) onboarding_plan: ContentDigest,
    pub(crate) profile_digest: ContentDigest,
    pub(crate) peer: SocketAddr,
    pub(crate) authority: String,
    pub(crate) control_root: String,
}

pub(crate) struct Bindings {
    pub(crate) digest: ContentDigest,
    sources: Vec<Binding>,
}

pub(crate) fn refused(source_index: Option<usize>, reason: &'static str) -> SitePlanError {
    SitePlanError {
        code: ERR_SITE_ONVIF_INPUT,
        source_index,
        reason,
    }
}

fn fields<'a>(
    value: &'a Value,
    expected: &[&str],
    index: Option<usize>,
) -> Result<&'a BTreeMap<String, Value>, SitePlanError> {
    let row = value
        .object()
        .ok_or_else(|| refused(index, "binding object required"))?;
    if row.len() != expected.len() || expected.iter().any(|key| !row.contains_key(*key)) {
        return Err(refused(index, "exact binding fields required"));
    }
    Ok(row)
}

fn text<'a>(
    fields: &'a BTreeMap<String, Value>,
    key: &str,
    index: Option<usize>,
) -> Result<&'a str, SitePlanError> {
    fields
        .get(key)
        .and_then(Value::text)
        .ok_or_else(|| refused(index, "binding text field required"))
}

fn digest(value: &str, index: Option<usize>) -> Result<ContentDigest, SitePlanError> {
    let parsed = ContentDigest::parse(value)
        .map_err(|_| refused(index, "canonical nonzero SHA-256 digest required"))?;
    if parsed.algorithm() != DigestAlgorithm::Sha256
        || parsed.bytes() == [0; 32]
        || parsed.to_text() != value
    {
        return Err(refused(index, "canonical nonzero SHA-256 digest required"));
    }
    Ok(parsed)
}

pub(crate) fn parse_bindings(
    manifest: &SiteManifest,
    bytes: &[u8],
) -> Result<Bindings, SitePlanError> {
    parse_bindings_scoped(manifest, bytes, None, false)
}

/// Exact selected inventory using validated original-manifest source ordinals.
pub(crate) fn parse_selected_bindings(
    manifest: &SiteManifest,
    bytes: &[u8],
    selected: &[usize],
) -> Result<Bindings, SitePlanError> {
    parse_bindings_scoped(manifest, bytes, Some(selected), false)
}

/// Select one source for probing from either its own or the complete site's
/// binding inventory. Every supplied row is validated, but unselected handoffs
/// are never opened and need not have a row in a single-source probe request.
pub(crate) fn probe_binding(
    manifest: &SiteManifest,
    bytes: &[u8],
    source_id: &str,
) -> Result<Binding, SitePlanError> {
    let index = manifest
        .sources
        .iter()
        .position(|source| source.source_id == source_id)
        .ok_or_else(|| refused(None, "selected probe source is unknown"))?;
    parse_bindings_scoped(manifest, bytes, Some(&[index]), true)?
        .sources
        .into_iter()
        .find(|binding| binding.source_index == index)
        .ok_or_else(|| {
            refused(
                Some(index),
                "selected source has no protected ONVIF binding",
            )
        })
}

fn parse_bindings_scoped(
    manifest: &SiteManifest,
    bytes: &[u8],
    selected: Option<&[usize]>,
    allow_unselected: bool,
) -> Result<Bindings, SitePlanError> {
    let manifest_digest = manifest
        .digest()
        .map_err(|_| refused(None, "valid canonical site manifest required"))?;
    if bytes.is_empty() || bytes.len() > MAX_SITE_ONVIF_BINDINGS_BYTES {
        return Err(refused(None, "binding document exceeds its byte bound"));
    }
    let value = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| json_input::parse(text).ok())
        .ok_or_else(|| refused(None, "strict complete binding JSON required"))?;
    let root = fields(&value, &["schema", "manifest_digest", "sources"], None)?;
    if text(root, "schema", None)? != SITE_ONVIF_BINDINGS_SCHEMA {
        return Err(refused(None, "unsupported binding schema"));
    }
    if digest(text(root, "manifest_digest", None)?, None)? != manifest_digest {
        return Err(refused(None, "binding manifest digest is stale"));
    }
    let rows = root
        .get("sources")
        .and_then(Value::array)
        .ok_or_else(|| refused(None, "binding source array required"))?;
    if rows.len() > 64 {
        return Err(refused(None, "binding source count exceeds its bound"));
    }
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(rows.len())
        .map_err(|_| refused(None, "binding allocation refused"))?;
    let mut seen = BTreeSet::new();
    for row in rows {
        let raw = row
            .object()
            .ok_or_else(|| refused(None, "binding object required"))?;
        let source_id = text(raw, "source_id", None)?;
        let source_index = manifest
            .sources
            .iter()
            .position(|source| source.source_id == source_id)
            .ok_or_else(|| refused(None, "binding names an unknown site source"))?;
        let index = Some(source_index);
        let source = &manifest.sources[source_index];
        if !allow_unselected && selected.is_some_and(|indices| !indices.contains(&source_index)) {
            return Err(refused(index, "binding names an unselected site source"));
        }
        if source.kind != SourceKind::Onvif || !seen.insert(source_index) {
            return Err(refused(
                index,
                "exactly one binding per ONVIF source required",
            ));
        }
        let row = fields(
            row,
            &[
                "source_id",
                "source_file",
                "source_digest",
                "onboarding_plan",
                "profile_digest",
                "rtsp_peer",
                "rtsp_authority",
                "control_root",
            ],
            index,
        )?;
        let peer = text(row, "rtsp_peer", index)?
            .parse::<SocketAddr>()
            .map_err(|_| refused(index, "independently pinned literal RTSP peer required"))?;
        let authority = text(row, "rtsp_authority", index)?;
        let control_root = text(row, "control_root", index)?;
        if authority.is_empty()
            || authority.len() > 256
            || control_root.is_empty()
            || control_root.len() > 2048
            || control_root.contains('?')
            || authority
                .chars()
                .chain(control_root.chars())
                .any(char::is_control)
        {
            return Err(refused(
                index,
                "bounded RTSP authority and query-free control subtree required",
            ));
        }
        sources.push(Binding {
            source_index,
            source_id: source.source_id.clone(),
            spec: OnvifSourceSpec {
                source: private_file::absolute_path(text(row, "source_file", index)?).map_err(
                    |_| refused(index, "bounded absolute private handoff path required"),
                )?,
                expected: digest(text(row, "source_digest", index)?, index)?,
            },
            onboarding_plan: digest(text(row, "onboarding_plan", index)?, index)?,
            profile_digest: digest(text(row, "profile_digest", index)?, index)?,
            peer,
            authority: authority.to_owned(),
            control_root: control_root.to_owned(),
        });
    }
    for (index, source) in manifest.sources.iter().enumerate() {
        if source.kind == SourceKind::Onvif
            && selected.is_none_or(|indices| indices.contains(&index))
            && !seen.contains(&index)
        {
            return Err(refused(
                Some(index),
                if selected.is_some() {
                    "every selected ONVIF source requires one protected binding"
                } else {
                    "every ONVIF source requires one protected binding"
                },
            ));
        }
    }
    sources.sort_by_key(|binding| binding.source_index);
    Ok(Bindings {
        digest: ContentDigest::sha256(bytes),
        sources,
    })
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

pub(crate) fn check_paths(
    manifest: &SiteManifest,
    bindings: &Bindings,
    options: &SitePlanOptions,
) -> Result<(), SitePlanError> {
    for root in [&options.archive_root, &options.pins_root] {
        private_file::absolute_path(
            root.to_str()
                .ok_or_else(|| refused(None, "absolute destination parent required"))?,
        )
        .map_err(|_| refused(None, "absolute destination parent required"))?;
    }
    for binding in &bindings.sources {
        if [&options.archive_root, &options.pins_root]
            .iter()
            .any(|root| overlaps(&binding.spec.source, root))
            || manifest
                .sources
                .iter()
                .filter_map(|source| source.authentication.as_ref())
                .any(|auth| overlaps(&binding.spec.source, &auth.credential_file))
        {
            return Err(refused(
                Some(binding.source_index),
                "private handoffs must be separate from output and credential namespaces",
            ));
        }
    }
    Ok(())
}

fn check_destinations(
    bindings: &Bindings,
    options: &SitePlanOptions,
    checkpoint: &impl Fn() -> Result<(), &'static str>,
) -> Result<(), SitePlanError> {
    if bindings.sources.is_empty() {
        return Ok(());
    }
    for root in [&options.archive_root, &options.pins_root] {
        checkpoint().map_err(|_| refused(None, "private input read authority expired"))?;
        let parent = std::fs::canonicalize(root)
            .map_err(|_| refused(None, "existing destination parent required"))?;
        checkpoint().map_err(|_| refused(None, "private input read authority expired"))?;
        for binding in &bindings.sources {
            if overlaps(&binding.spec.source, &parent) {
                return Err(refused(
                    Some(binding.source_index),
                    "private handoff overlaps a canonical destination namespace",
                ));
            }
        }
    }
    Ok(())
}

/// Leases remain held while the complete mixed-site plan and all private inputs are revalidated.
pub(crate) struct OwnedInputs<'a> {
    bindings: &'a Bindings,
    leases: Vec<(private_file::InputLease, [u8; 88])>,
}

impl<'a> OwnedInputs<'a> {
    pub(crate) fn open(
        bindings: &'a Bindings,
        options: &SitePlanOptions,
        checkpoint: &impl Fn() -> Result<(), &'static str>,
    ) -> Result<Self, SitePlanError> {
        check_destinations(bindings, options, checkpoint)?;
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(bindings.sources.len())
            .map_err(|_| refused(None, "private input allocation refused"))?;
        let mut total = 0usize;
        for binding in &bindings.sources {
            // The existing owner may temporarily read its bounded 256 KiB maximum.
            // Only an admitted 8 KiB handoff is retained; the enclosing scope reserves
            // this transient allowance in addition to all retained handoffs and exports.
            let lease =
                private_file::InputLease::open(&binding.spec.source, checkpoint).map_err(|_| {
                    refused(
                        Some(binding.source_index),
                        "protected ONVIF handoff read refused",
                    )
                })?;
            total = total
                .checked_add(lease.bytes().len())
                .ok_or_else(|| refused(None, "aggregate handoff byte bound exceeded"))?;
            if lease.bytes().len() > MAX_ONVIF_HANDOFF_BYTES
                || total > MAX_SITE_ONVIF_HANDOFF_BYTES
                || ContentDigest::sha256(lease.bytes()) != binding.spec.expected
            {
                return Err(refused(
                    Some(binding.source_index),
                    "protected handoff size or digest does not match its binding",
                ));
            }
            let fingerprint = lease.fingerprint();
            leases.push((lease, fingerprint));
        }
        Ok(Self { bindings, leases })
    }

    pub(crate) fn inputs(&self) -> Vec<SiteOnvifInput<'_>> {
        self.bindings
            .sources
            .iter()
            .zip(&self.leases)
            .map(|(binding, (lease, fingerprint))| SiteOnvifInput {
                source_id: &binding.source_id,
                spec: &binding.spec,
                onboarding_plan: binding.onboarding_plan,
                profile_digest: binding.profile_digest,
                peer: binding.peer,
                authority: &binding.authority,
                control_root: &binding.control_root,
                input: ProtectedOnvifInput {
                    bytes: lease.bytes(),
                    fingerprint,
                },
            })
            .collect()
    }

    pub(crate) fn revalidate(
        &self,
        options: &SitePlanOptions,
        checkpoint: &impl Fn() -> Result<(), &'static str>,
    ) -> Result<(), SitePlanError> {
        check_destinations(self.bindings, options, checkpoint)?;
        for (binding, (lease, _)) in self.bindings.sources.iter().zip(&self.leases) {
            lease.revalidate(checkpoint).map_err(|_| {
                refused(
                    Some(binding.source_index),
                    "protected handoff changed before plan release",
                )
            })?;
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "site_onvif/tests.rs"]
mod tests;
