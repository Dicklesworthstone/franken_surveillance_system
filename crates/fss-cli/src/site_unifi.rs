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
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
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

pub(crate) struct Bindings {
    pub(crate) digest: ContentDigest,
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

pub(crate) fn parse_bindings(
    manifest: &SiteManifest,
    bytes: &[u8],
) -> Result<Bindings, SitePlanError> {
    parse_bindings_scoped(manifest, bytes, None)
}

// Selected ordinals come only from the full-manifest selection validator. Keep
// the all-source parser unchanged for capture and probe callers.
fn parse_bindings_scoped(
    manifest: &SiteManifest,
    bytes: &[u8],
    selected: Option<&[usize]>,
) -> Result<Bindings, SitePlanError> {
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
        if selected.is_some_and(|indices| !indices.contains(&source_index)) {
            return Err(refused(index, "binding names an unselected site source"));
        }
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
        if source.kind == SourceKind::UnifiProtect
            && selected.is_none_or(|indices| indices.contains(&index))
            && !seen.contains(&index)
        {
            return Err(refused(
                Some(index),
                if selected.is_some() {
                    "every selected UniFi source requires one protected binding"
                } else {
                    "every UniFi source requires one protected binding"
                },
            ));
        }
    }
    sources.sort_by_key(|source| source.source_index);
    Ok(Bindings {
        digest: ContentDigest::sha256(bytes),
        sources,
    })
}

// Refuse a mismatched receipt inventory before opening any protected export.
// The pure compiler repeats complete validation after receiving the leased bytes.
fn check_selected_receipts(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    selected: &[usize],
) -> Result<(), SitePlanError> {
    if receipts.len() > selected.len() {
        return Err(refused(
            None,
            "probe inventory contains extra or duplicate source receipts",
        ));
    }
    let manifest_digest = manifest
        .digest()
        .map_err(|_| refused(None, "valid canonical site manifest required"))?;
    let mut seen = BTreeSet::new();
    for receipt in receipts {
        let index = manifest
            .sources
            .iter()
            .position(|source| source.source_id == receipt.source_id)
            .ok_or_else(|| refused(None, "probe inventory contains a foreign source"))?;
        if !selected.contains(&index) {
            return Err(refused(
                Some(index),
                "probe inventory contains an unselected source",
            ));
        }
        if !seen.insert(index) {
            return Err(refused(Some(index), "duplicate probe receipt for source"));
        }
        // ONVIF's management endpoint remains in the original manifest while
        // the handoff and its independent pins own the RTSP endpoint. Its full
        // route is verified by the protected compiler after reading the handoff.
        if receipt.validate().is_err()
            || receipt.site_id != manifest.site_id
            || receipt.manifest_digest != manifest_digest
            || receipt.source_generation != manifest.sources[index].generation
            || (manifest.sources[index].kind != SourceKind::Onvif
                && receipt.validate_for(manifest).is_err())
        {
            return Err(refused(
                Some(index),
                "probe evidence does not bind the exact current manifest source",
            ));
        }
    }
    for index in selected {
        if !seen.contains(index) {
            return Err(refused(
                Some(*index),
                "selected source has no exact probe receipt",
            ));
        }
    }
    Ok(())
}

// Shared selected admission boundary: complete scope and receipt checks finish
// before either the runtime wrapper or a bounded test owner can open an export.
fn prepare_selected_bindings(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    source_ids: &[String],
    bindings_json: &[u8],
) -> Result<Bindings, SitePlanError> {
    let selected = site_plan::validate_selected_sources(manifest, source_ids)?;
    if let Some(index) = selected
        .iter()
        .find(|index| manifest.sources[**index].kind == SourceKind::Onvif)
    {
        return Err(crate::site_onvif::refused(
            Some(*index),
            "selected ONVIF source requires a protected handoff binding document",
        ));
    }
    let bindings = parse_bindings_scoped(manifest, bindings_json, Some(&selected))?;
    check_selected_receipts(manifest, receipts, &selected)?;
    Ok(bindings)
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
    compile_owned_scoped(manifest, receipts, options, bindings, None, checkpoint)
}

fn compile_owned_scoped(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    bindings: &Bindings,
    source_ids: Option<&[String]>,
    checkpoint: &impl Fn() -> Result<(), &'static str>,
) -> Result<SitePlan, SitePlanError> {
    with_inputs(
        manifest,
        options,
        bindings,
        checkpoint,
        |inputs| match source_ids {
            Some(ids) => {
                site_plan::compile_selected_with_unifi(manifest, receipts, options, ids, inputs)
            }
            None => site_plan::compile_with_unifi(manifest, receipts, options, inputs),
        },
    )
}

/// Hold exact UniFi leases across a combined protected-source compilation and revalidation.
/// The caller's existing read scope owns every boundary; no nested runtime is started.
pub(crate) fn with_inputs(
    _manifest: &SiteManifest,
    options: &SitePlanOptions,
    bindings: &Bindings,
    checkpoint: &impl Fn() -> Result<(), &'static str>,
    compile: impl FnOnce(&[SiteUnifiInput<'_>]) -> Result<SitePlan, SitePlanError>,
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
    let plan = compile(&inputs)?;
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
    compile_bound_inputs(manifest, receipts, options, &bindings, None)
}

/// Read exactly the protected exports for an explicit source selection.
///
/// The complete original manifest remains authoritative: selections use its
/// original ordinals, receipts and bindings retain its digest, and all sources'
/// credential references remain protected. The binding document must contain
/// exactly the selected UniFi sources; unrelated, duplicate or missing bindings
/// are refused before any private file is opened. Receipt inventory and binding
/// validation also finish before reads. Unselected sources require no exports or
/// receipts and are never silently added to the returned plan.
///
/// Reads use the same bounded request authority, private-file fingerprints and
/// final revalidation as whole-site planning. No capture or credential authority
/// is acquired. A selection containing only direct sources remains pure when
/// paired with an empty, manifest-bound binding inventory.
pub fn compile_selected_from_bindings(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    source_ids: &[String],
    bindings_json: &[u8],
) -> Result<SitePlan, SitePlanError> {
    let bindings = prepare_selected_bindings(manifest, receipts, source_ids, bindings_json)?;
    compile_bound_inputs(manifest, receipts, options, &bindings, Some(source_ids))
}

fn compile_bound_inputs(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    bindings: &Bindings,
    source_ids: Option<&[String]>,
) -> Result<SitePlan, SitePlanError> {
    check_paths(manifest, bindings, options)?;
    if bindings.sources.is_empty() {
        return match source_ids {
            Some(ids) => {
                site_plan::compile_selected_with_unifi(manifest, receipts, options, ids, &[])
            }
            None => site_plan::compile_with_unifi(manifest, receipts, options, &[]),
        };
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
            let result = match source_ids {
                Some(_) => {
                    compile_owned_scoped(manifest, receipts, options, bindings, source_ids, &|| {
                        scope.input()
                    })
                }
                None => compile_owned(manifest, receipts, options, bindings, &|| scope.input()),
            };
            result.map_err(|error| {
                let code = error.code;
                inner_error = Some(error);
                code
            })
        },
    )
    .map_err(|_| {
        inner_error.unwrap_or_else(|| refused(None, "protected input runtime did not finalize"))
    })
}

/// Compile a mixed site with exact protected ONVIF handoffs and optional UniFi exports.
/// Both binding documents are parsed and checked before opening any protected input.
/// One finite read scope owns all leases; no credentials, network or writes are enabled.
pub fn compile_with_onvif_bindings(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    onvif_json: &[u8],
    unifi_json: Option<&[u8]>,
) -> Result<SitePlan, SitePlanError> {
    let onvif = crate::site_onvif::parse_bindings(manifest, onvif_json)?;
    crate::site_onvif::check_paths(manifest, &onvif, options)?;
    let unifi = unifi_json
        .map(|bytes| parse_bindings(manifest, bytes))
        .transpose()?;
    if let Some(bindings) = &unifi {
        check_paths(manifest, bindings, options)?;
    }
    let mut encoded = CanonicalEncoder::new();
    encoded.text("fss.site_protected_input_read.v1");
    encoded.digest(onvif.digest);
    if let Some(bindings) = &unifi {
        encoded.digest(bindings.digest);
    }
    let approval = ContentDigest::sha256(&encoded.finish_checked().map_err(|_| {
        crate::site_onvif::refused(None, "private input identity encoding refused")
    })?);
    compile_bound_onvif_inputs(
        manifest,
        receipts,
        options,
        &onvif,
        unifi.as_ref(),
        None,
        approval,
    )
}

/// Admit the exact selected inventories before either protected input owner opens a file.
/// Source ordinals and all policy/credential references remain in the original manifest.
pub(crate) fn prepare_selected_onvif_bindings(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    source_ids: &[String],
    onvif_json: &[u8],
    unifi_json: Option<&[u8]>,
) -> Result<(crate::site_onvif::Bindings, Option<Bindings>), SitePlanError> {
    let selected = site_plan::validate_selected_sources(manifest, source_ids)?;
    let onvif = crate::site_onvif::parse_selected_bindings(manifest, onvif_json, &selected)?;
    let unifi = unifi_json
        .map(|bytes| parse_bindings_scoped(manifest, bytes, Some(&selected)))
        .transpose()?;
    if unifi.is_none()
        && let Some(index) = selected
            .iter()
            .find(|index| manifest.sources[**index].kind == SourceKind::UnifiProtect)
    {
        return Err(refused(
            Some(*index),
            "selected UniFi source requires a protected export binding document",
        ));
    }
    check_selected_receipts(manifest, receipts, &selected)?;
    crate::site_onvif::check_paths(manifest, &onvif, options)?;
    if let Some(bindings) = &unifi {
        check_paths(manifest, bindings, options)?;
    }
    Ok((onvif, unifi))
}

/// Compile an explicit source selection using protected ONVIF and optional UniFi bindings.
///
/// Both documents must cover exactly the selected sources of their respective kinds.
/// Full-manifest validation, selection, binding and receipt inventory checks finish before
/// opening any protected input. A selected ONVIF receipt retains its independently pinned
/// RTSP endpoint; the manifest's original HTTP management endpoint is never rewritten.
///
/// One finite read scope holds both sets of private-file leases through complete compilation
/// and revalidation. The scope identity binds the normalized selection and both documents.
/// Credentials, network access, destination creation and capture remain disabled.
pub fn compile_selected_with_onvif_bindings(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    source_ids: &[String],
    onvif_json: &[u8],
    unifi_json: Option<&[u8]>,
) -> Result<SitePlan, SitePlanError> {
    let (onvif, unifi) = prepare_selected_onvif_bindings(
        manifest, receipts, options, source_ids, onvif_json, unifi_json,
    )?;
    let selected = site_plan::validate_selected_sources(manifest, source_ids)?;
    if selected.iter().all(|index| {
        !matches!(
            manifest.sources[*index].kind,
            SourceKind::Onvif | SourceKind::UnifiProtect
        )
    }) {
        return site_plan::compile_selected_with_sources(
            manifest,
            receipts,
            options,
            source_ids,
            &[],
            &[],
        );
    }
    let mut encoded = CanonicalEncoder::new();
    encoded.text("fss.site_protected_input_read.v2");
    encoded.digest(onvif.digest);
    encoded.bool(unifi.is_some());
    if let Some(bindings) = &unifi {
        encoded.digest(bindings.digest);
    }
    encoded.u64(selected.len() as u64);
    for index in selected {
        encoded.u64(index as u64);
        encoded.text(&manifest.sources[index].source_id);
    }
    let approval = ContentDigest::sha256(&encoded.finish_checked().map_err(|_| {
        crate::site_onvif::refused(None, "private input identity encoding refused")
    })?);
    compile_bound_onvif_inputs(
        manifest,
        receipts,
        options,
        &onvif,
        unifi.as_ref(),
        Some(source_ids),
        approval,
    )
}

fn compile_bound_onvif_inputs(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    onvif: &crate::site_onvif::Bindings,
    unifi: Option<&Bindings>,
    source_ids: Option<&[String]>,
    approval: ContentDigest,
) -> Result<SitePlan, SitePlanError> {
    let mut inner_error = None;
    runtime::run(
        runtime::Request {
            approval,
            principal: options.principal.clone(),
            timeout_ns: READ_TIMEOUT_NS,
            // Existing 32 MiB export/report allowance plus handoffs, second binding
            // document and bounded private parser representations; no RSS promise.
            bytes: READ_WORKING_BYTES + 8 * 1024 * 1024,
            network_bytes: 0,
            storage_operations: MAX_READ_OPERATIONS * 2,
            network: false,
            write: false,
            secrets: false,
        },
        |scope| {
            let result = match source_ids {
                Some(ids) => compile_owned_selected_with_onvif(
                    manifest,
                    receipts,
                    options,
                    ids,
                    onvif,
                    unifi,
                    &|| scope.input(),
                ),
                None => {
                    compile_owned_with_onvif(manifest, receipts, options, onvif, unifi, &|| {
                        scope.input()
                    })
                }
            };
            result.map_err(|error| {
                let code = error.code;
                inner_error = Some(error);
                code
            })
        },
    )
    .map_err(|_| {
        inner_error.unwrap_or_else(|| {
            crate::site_onvif::refused(None, "protected input runtime did not finalize")
        })
    })
}

pub(crate) fn compile_owned_with_onvif(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    onvif: &crate::site_onvif::Bindings,
    unifi: Option<&Bindings>,
    checkpoint: &impl Fn() -> Result<(), &'static str>,
) -> Result<SitePlan, SitePlanError> {
    compile_owned_with_onvif_scoped(manifest, receipts, options, onvif, unifi, None, checkpoint)
}

pub(crate) fn compile_owned_selected_with_onvif(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    source_ids: &[String],
    onvif: &crate::site_onvif::Bindings,
    unifi: Option<&Bindings>,
    checkpoint: &impl Fn() -> Result<(), &'static str>,
) -> Result<SitePlan, SitePlanError> {
    compile_owned_with_onvif_scoped(
        manifest,
        receipts,
        options,
        onvif,
        unifi,
        Some(source_ids),
        checkpoint,
    )
}

fn compile_owned_with_onvif_scoped(
    manifest: &SiteManifest,
    receipts: &[SiteProbeReceipt],
    options: &SitePlanOptions,
    onvif: &crate::site_onvif::Bindings,
    unifi: Option<&Bindings>,
    source_ids: Option<&[String]>,
    checkpoint: &impl Fn() -> Result<(), &'static str>,
) -> Result<SitePlan, SitePlanError> {
    let owned = crate::site_onvif::OwnedInputs::open(onvif, options, checkpoint)?;
    let inputs = owned.inputs();
    let compile = |unifi_inputs: &[SiteUnifiInput<'_>]| {
        let result = match source_ids {
            Some(ids) => site_plan::compile_selected_with_sources(
                manifest,
                receipts,
                options,
                ids,
                unifi_inputs,
                &inputs,
            )?,
            None => site_plan::compile_with_protected(
                manifest,
                receipts,
                options,
                unifi_inputs,
                &inputs,
            )?,
        };
        // Keep both lease sets alive through complete compilation and the first
        // handoff recheck; the UniFi owner then revalidates its own held exports.
        owned.revalidate(options, checkpoint)?;
        Ok(result)
    };
    let plan = match unifi {
        Some(bindings) => with_inputs(manifest, options, bindings, checkpoint, compile)?,
        None => compile(&[])?,
    };
    owned.revalidate(options, checkpoint)?;
    Ok(plan)
}

#[cfg(test)]
#[path = "site_unifi/tests.rs"]
mod tests;
