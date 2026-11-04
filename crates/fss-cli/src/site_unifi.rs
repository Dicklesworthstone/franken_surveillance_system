#![forbid(unsafe_code)]
//! Protected operator exports for the pure site-to-UniFi capture compiler.
//!
//! A strict binding document names only private files and exact selections. The
//! existing private-file and request owners perform every read; only a complete
//! plan survives final file revalidation and runtime finalization. This adapter
//! never contacts a console, reads credentials, creates destinations or captures.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fss_core::json_input::{self, Value};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::site::{SiteManifest, SiteProbeReceipt, SourceKind};
use fss_reference::unifi::{ProtectQuality, TransportChoice};

use crate::site_plan::{self, SitePlan, SitePlanError, SitePlanOptions};
use crate::unifi_plan::{ProtectedUnifiInput, UnifiSourceSpec};

/// Pure borrowed observations live with the compiler, independently of this native reader.
pub use crate::site_plan::SiteUnifiInput;

#[allow(
    dead_code,
    unused_imports,
    reason = "The shared owner also supports private output"
)]
#[path = "bin/fss-onvif/private_file.rs"]
pub(crate) mod private_file;
#[allow(
    dead_code,
    reason = "The shared owner also supports network and durable output"
)]
#[path = "bin/fss-onvif/runtime.rs"]
mod runtime;

/// Strict operator binding document; no endpoint or credential can be supplied here.
pub const SITE_UNIFI_BINDINGS_SCHEMA: &str = "fss.site_unifi_bindings.v1";
/// Bound for the complete binding document, independently of protected export bytes.
pub const MAX_SITE_UNIFI_BINDINGS_BYTES: usize = 1024 * 1024;
/// Maximum complete protected exports in one site compilation.
pub const MAX_SITE_UNIFI_EXPORT_BYTES: usize = 8 * 1024 * 1024;
/// Exact existing private-file owner ceiling for each individual export.
pub const MAX_SITE_UNIFI_EXPORT_FILE_BYTES: usize = 262_144;
/// Stable, non-disclosing binding/read/finalization refusal.
pub const ERR_SITE_UNIFI_INPUT: &str = "ERR-SITE-UNIFI-INPUT-001";
const MAX_SOURCES: usize = 64;
const MAX_READ_OPERATIONS: u64 = 16_384;
const READ_TIMEOUT_NS: u64 = 5_000_000_000;
// Prepaid logical work allowance: 8 MiB of export buffers, 1 MiB of bindings,
// multiple coexisting 2 MiB source/report representations, and bounded parsed
// values/manifest clones. This is an authority reservation, not an RSS claim.
const READ_WORKING_BYTES: u64 = 32 * 1024 * 1024;
const _: () = assert!(private_file::MAX_FILE_BYTES == MAX_SITE_UNIFI_EXPORT_FILE_BYTES);

struct Binding {
    source_index: usize,
    source_id: String,
    spec: UnifiSourceSpec,
}

struct Bindings {
    digest: ContentDigest,
    sources: Vec<Binding>,
}

fn refused(source_index: Option<usize>, reason: &'static str) -> SitePlanError {
    SitePlanError {
        code: ERR_SITE_UNIFI_INPUT,
        source_index,
        reason,
    }
}

fn exact_fields<'a>(
    value: &'a Value,
    expected: &[&str],
    source_index: Option<usize>,
) -> Result<&'a BTreeMap<String, Value>, SitePlanError> {
    let fields = value
        .object()
        .ok_or_else(|| refused(source_index, "binding object required"))?;
    if fields.len() != expected.len() || expected.iter().any(|key| !fields.contains_key(*key)) {
        return Err(refused(source_index, "exact binding fields required"));
    }
    Ok(fields)
}

fn text<'a>(
    fields: &'a BTreeMap<String, Value>,
    key: &str,
    source_index: Option<usize>,
) -> Result<&'a str, SitePlanError> {
    fields
        .get(key)
        .and_then(Value::text)
        .ok_or_else(|| refused(source_index, "binding text field required"))
}

fn digest(text: &str, source_index: Option<usize>) -> Result<ContentDigest, SitePlanError> {
    let digest = ContentDigest::parse(text)
        .map_err(|_| refused(source_index, "canonical nonzero SHA-256 digest required"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256
        || digest.bytes() == [0; 32]
        || digest.to_text() != text
    {
        return Err(refused(
            source_index,
            "canonical nonzero SHA-256 digest required",
        ));
    }
    Ok(digest)
}

fn parse_bindings(manifest: &SiteManifest, bytes: &[u8]) -> Result<Bindings, SitePlanError> {
    let manifest_digest = manifest
        .digest()
        .map_err(|_| refused(None, "valid canonical site manifest required"))?;
    if bytes.is_empty() || bytes.len() > MAX_SITE_UNIFI_BINDINGS_BYTES {
        return Err(refused(None, "binding document exceeds its byte bound"));
    }
    let document = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| json_input::parse(text).ok())
        .ok_or_else(|| refused(None, "strict complete binding JSON required"))?;
    let fields = exact_fields(&document, &["schema", "manifest_digest", "sources"], None)?;
    if text(fields, "schema", None)? != SITE_UNIFI_BINDINGS_SCHEMA {
        return Err(refused(None, "unsupported binding schema"));
    }
    if digest(text(fields, "manifest_digest", None)?, None)? != manifest_digest {
        return Err(refused(None, "binding manifest digest is stale"));
    }
    let values = fields
        .get("sources")
        .and_then(Value::array)
        .ok_or_else(|| refused(None, "binding source array required"))?;
    if values.len() > MAX_SOURCES {
        return Err(refused(None, "binding source count exceeds its bound"));
    }
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(values.len())
        .map_err(|_| refused(None, "binding allocation refused"))?;
    let mut seen = BTreeSet::new();
    for value in values {
        let raw = value
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
        if source.kind != SourceKind::UnifiProtect {
            return Err(refused(index, "binding must name a UniFi Protect source"));
        }
        if !seen.insert(source_index) {
            return Err(refused(index, "duplicate UniFi source binding"));
        }
        let row = exact_fields(
            value,
            &[
                "source_id",
                "source_file",
                "source_digest",
                "quality",
                "stream_transport",
            ],
            index,
        )?;
        let path = private_file::absolute_path(text(row, "source_file", index)?)
            .map_err(|_| refused(index, "bounded absolute private export path required"))?;
        let quality = match text(row, "quality", index)? {
            "high" => ProtectQuality::High,
            "medium" => ProtectQuality::Medium,
            "low" => ProtectQuality::Low,
            "package" => ProtectQuality::Package,
            _ => return Err(refused(index, "exact supported UniFi quality required")),
        };
        let transport = match text(row, "stream_transport", index)? {
            "operator-rtsp" => TransportChoice::OperatorRtsp,
            "published" => TransportChoice::Published,
            _ => return Err(refused(index, "exact supported UniFi transport required")),
        };
        sources.push(Binding {
            source_index,
            source_id: source.source_id.clone(),
            spec: UnifiSourceSpec {
                source: path,
                expected: digest(text(row, "source_digest", index)?, index)?,
                quality,
                transport,
                peer: source.peer,
            },
        });
    }
    for (index, source) in manifest.sources.iter().enumerate() {
        if source.kind == SourceKind::UnifiProtect && !seen.contains(&index) {
            return Err(refused(
                Some(index),
                "every UniFi source requires one protected binding",
            ));
        }
    }
    sources.sort_by_key(|source| source.source_index);
    Ok(Bindings {
        digest: ContentDigest::sha256(bytes),
        sources,
    })
}

/// Select one source from the same strict site binding document used for capture.
/// This performs no export read and does not broaden the requested peer or rendition.
pub(crate) fn probe_source_spec(
    manifest: &SiteManifest,
    bytes: &[u8],
    source_id: &str,
) -> Result<UnifiSourceSpec, SitePlanError> {
    parse_bindings(manifest, bytes)?
        .sources
        .into_iter()
        .find(|binding| binding.source_id == source_id)
        .map(|binding| binding.spec)
        .ok_or_else(|| refused(None, "selected source has no protected UniFi binding"))
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn check_paths(
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
        let path = &binding.spec.source;
        if [&options.archive_root, &options.pins_root]
            .iter()
            .any(|root| overlaps(path, root))
        {
            return Err(refused(
                Some(binding.source_index),
                "private export overlaps a destination namespace",
            ));
        }
        if manifest
            .sources
            .iter()
            .filter_map(|source| source.authentication.as_ref())
            .any(|authentication| overlaps(path, &authentication.credential_file))
        {
            return Err(refused(
                Some(binding.source_index),
                "private export overlaps a credential reference",
            ));
        }
    }
    Ok(())
}

fn check_canonical_destinations(
    bindings: &Bindings,
    options: &SitePlanOptions,
    checkpoint: &impl Fn() -> Result<(), &'static str>,
) -> Result<(), SitePlanError> {
    // Native from-unifi previews check the actual destination parents without
    // creating them. Repeat that exact canonical overlap check for both namespaces.
    for root in [&options.archive_root, &options.pins_root] {
        checkpoint().map_err(|_| refused(None, "private input read authority expired"))?;
        let parent = std::fs::canonicalize(root)
            .map_err(|_| refused(None, "existing destination parent required"))?;
        checkpoint().map_err(|_| refused(None, "private input read authority expired"))?;
        for binding in &bindings.sources {
            if overlaps(&binding.spec.source, &parent) {
                return Err(refused(
                    Some(binding.source_index),
                    "private export overlaps a canonical destination namespace",
                ));
            }
        }
    }
    Ok(())
}

fn compile_owned(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    bindings: &Bindings,
    checkpoint: &impl Fn() -> Result<(), &'static str>,
) -> Result<SitePlan, SitePlanError> {
    check_canonical_destinations(bindings, options, checkpoint)?;
    let mut leases = Vec::new();
    leases
        .try_reserve_exact(bindings.sources.len())
        .map_err(|_| refused(None, "private input allocation refused"))?;
    let mut remaining = MAX_SITE_UNIFI_EXPORT_BYTES;
    for binding in &bindings.sources {
        // Reserve the native owner's maximum before opening a file, then refund
        // unused bytes. A raced file can never read past the aggregate allowance.
        if remaining < MAX_SITE_UNIFI_EXPORT_FILE_BYTES {
            return Err(refused(
                Some(binding.source_index),
                "aggregate private input reservation exhausted",
            ));
        }
        let input =
            private_file::InputLease::open(&binding.spec.source, checkpoint).map_err(|_| {
                refused(
                    Some(binding.source_index),
                    "protected UniFi export read refused",
                )
            })?;
        remaining -= input.bytes().len();
        if ContentDigest::sha256(input.bytes()) != binding.spec.expected {
            return Err(refused(
                Some(binding.source_index),
                "protected export digest does not match its binding",
            ));
        }
        let fingerprint = input.fingerprint();
        leases.push((input, fingerprint));
    }
    let inputs: Vec<_> = bindings
        .sources
        .iter()
        .zip(&leases)
        .map(|(binding, (lease, fingerprint))| SiteUnifiInput {
            source_id: &binding.source_id,
            spec: &binding.spec,
            input: ProtectedUnifiInput {
                bytes: lease.bytes(),
                fingerprint,
            },
        })
        .collect();
    let plan = site_plan::compile_with_unifi(manifest, receipts, options, &inputs)?;
    // Destination aliases can drift while several exports are read and parsed.
    // Recheck the same native isolation rule before releasing any source lease.
    check_canonical_destinations(bindings, options, checkpoint)?;
    for (binding, (lease, _)) in bindings.sources.iter().zip(&leases) {
        lease.revalidate(checkpoint).map_err(|_| {
            refused(
                Some(binding.source_index),
                "protected export changed before plan release",
            )
        })?;
    }
    Ok(plan)
}

/// Read exactly the bound private exports and return only a fully finalized site plan.
/// Existing direct-site planning remains pure when no UniFi binding is requested.
pub fn compile_from_bindings(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    bindings_json: &[u8],
) -> Result<SitePlan, SitePlanError> {
    let bindings = parse_bindings(manifest, bindings_json)?;
    check_paths(manifest, &bindings, options)?;
    if bindings.sources.is_empty() {
        return site_plan::compile_with_unifi(manifest, receipts, options, &[]);
    }
    let mut inner_error = None;
    runtime::run(
        runtime::Request {
            approval: bindings.digest,
            principal: options.principal.clone(),
            timeout_ns: READ_TIMEOUT_NS,
            bytes: READ_WORKING_BYTES,
            network_bytes: 0,
            storage_operations: MAX_READ_OPERATIONS,
            network: false,
            write: false,
            secrets: false,
        },
        |scope| {
            compile_owned(manifest, receipts, options, &bindings, &|| scope.input()).map_err(
                |error| {
                    let code = error.code;
                    inner_error = Some(error);
                    code
                },
            )
        },
    )
    .map_err(|_| {
        inner_error.unwrap_or_else(|| refused(None, "protected input runtime did not finalize"))
    })
}

#[cfg(test)]
#[path = "site_unifi/tests.rs"]
mod tests;
