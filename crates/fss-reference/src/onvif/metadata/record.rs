#![forbid(unsafe_code)]
//! Canonical recipes and deterministic projections; never JSON authority or XML rewriting.

use fss_core::{
    CanonicalDecoder, CanonicalEncoder, CaptureInterval, ContentDigest, DigestAlgorithm, SensorId,
    TimestampNs,
};

use super::{
    MAX_PROJECTION_BYTES, MAX_RECIPE_BYTES, MAX_SOURCE_BYTES, MetadataError, PARSER_GENERATION,
    PROJECTION_DOMAIN, RECIPE_DOMAIN, SourceBinding,
};
use crate::onvif::wire::{
    EventDocument, EventDocumentFormat, EventItems, EventNotification, PropertyOperation,
};

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Recipe {
    pub(super) site: String,
    pub(super) binding: SourceBinding,
    pub(super) source: ContentDigest,
    pub(super) source_bytes: usize,
    pub(super) projection: ContentDigest,
}

pub(super) fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(super) fn encode(recipe: &Recipe) -> Result<Vec<u8>, MetadataError> {
    recipe.binding.validate()?;
    if !valid_label(&recipe.site)
        || recipe.source_bytes == 0
        || recipe.source_bytes > MAX_SOURCE_BYTES
        || recipe.source.algorithm() != DigestAlgorithm::Sha256
        || recipe.projection.algorithm() != DigestAlgorithm::Sha256
    {
        return Err(MetadataError::InvalidBinding);
    }
    let mut e = CanonicalEncoder::new();
    e.text(RECIPE_DOMAIN);
    e.text(PARSER_GENERATION);
    e.text("owner_supplied_file");
    e.text(&recipe.site);
    source_binding(&mut e, &recipe.binding);
    e.i128(recipe.binding.receive_interval.earliest.0);
    e.i128(recipe.binding.receive_interval.latest.0);
    e.digest(recipe.source);
    e.u64(recipe.source_bytes as u64);
    e.digest(recipe.projection);
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_RECIPE_BYTES {
        return Err(MetadataError::Limit);
    }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Recipe, MetadataError> {
    if bytes.len() > MAX_RECIPE_BYTES {
        return Err(MetadataError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != RECIPE_DOMAIN
        || d.text()? != PARSER_GENERATION
        || d.text()? != "owner_supplied_file"
    {
        return Err(MetadataError::Custody);
    }
    let site = d.text()?.to_owned();
    let sensor_id = SensorId::parse(d.text()?)?;
    let device_generation = d.digest()?;
    let profile_generation = d.digest()?;
    let profile_token = d.text()?.to_owned();
    let receive_interval = CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?;
    let source = d.digest()?;
    let source_bytes = usize::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?;
    let projection = d.digest()?;
    d.ensure_finished()?;
    let recipe = Recipe {
        site,
        binding: SourceBinding {
            sensor_id,
            device_generation,
            profile_generation,
            profile_token,
            receive_interval,
        },
        source,
        source_bytes,
        projection,
    };
    if encode(&recipe)? != bytes {
        return Err(MetadataError::Custody);
    }
    Ok(recipe)
}

fn source_binding(e: &mut CanonicalEncoder, binding: &SourceBinding) {
    e.text(binding.sensor_id.as_str());
    e.digest(binding.device_generation);
    e.digest(binding.profile_generation);
    e.text(&binding.profile_token);
}
fn optional_text(e: &mut CanonicalEncoder, value: Option<&str>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.text(value);
    }
}
fn items(e: &mut CanonicalEncoder, items: Option<&EventItems>) {
    e.bool(items.is_some());
    if let Some(items) = items {
        e.u64(items.simple_items.len() as u64);
        for item in &items.simple_items {
            e.text(&item.name);
            e.text(&item.value);
        }
        e.u64(items.element_items.len() as u64);
        for name in &items.element_items {
            e.text(name);
        }
        e.u64(items.unsupported_extensions as u64);
    }
}
fn notification(e: &mut CanonicalEncoder, value: &EventNotification) {
    e.text(&value.topic.namespace);
    e.u64(value.topic.path.len() as u64);
    for component in &value.topic.path {
        e.text(component);
    }
    e.text(&value.utc_time);
    e.u8(match value.property_operation {
        None => 0,
        Some(PropertyOperation::Initialized) => 1,
        Some(PropertyOperation::Changed) => 2,
        Some(PropertyOperation::Deleted) => 3,
    });
    items(e, value.source.as_ref());
    items(e, value.key.as_ref());
    items(e, value.data.as_ref());
    e.u64(value.unsupported_extensions as u64);
}

pub(super) fn projection(document: &EventDocument) -> Result<Vec<u8>, MetadataError> {
    let mut e = CanonicalEncoder::new();
    e.text(PROJECTION_DOMAIN);
    e.text(PARSER_GENERATION);
    e.text("cognition");
    e.text("vendor_claimed");
    e.text("vendor_clock_unverified");
    e.u8(match document.format {
        EventDocumentFormat::PullMessages => 1,
        EventDocumentFormat::MetadataStream => 2,
    });
    optional_text(&mut e, document.current_time.as_deref());
    optional_text(&mut e, document.termination_time.as_deref());
    e.u64(document.notifications.len() as u64);
    for value in &document.notifications {
        notification(&mut e, value);
    }
    e.u64(document.unsupported_sections as u64);
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_PROJECTION_BYTES {
        return Err(MetadataError::Limit);
    }
    Ok(bytes)
}

pub(super) fn notification_identity(
    recipe: &Recipe,
    value: &EventNotification,
    index: usize,
    document_has_opaque_content: bool,
) -> Result<ContentDigest, MetadataError> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.onvif_vendor_notification_identity.v1");
    e.text(PARSER_GENERATION);
    e.text(&recipe.site);
    source_binding(&mut e, &recipe.binding);
    notification(&mut e, value);
    let opaque = document_has_opaque_content
        || value.unsupported_extensions != 0
        || [
            value.source.as_ref(),
            value.key.as_ref(),
            value.data.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|items| !items.element_items.is_empty() || items.unsupported_extensions != 0);
    e.bool(opaque);
    if opaque {
        e.digest(recipe.source);
        e.u64(index as u64);
    }
    Ok(ContentDigest::sha256(&e.finish_checked()?))
}
