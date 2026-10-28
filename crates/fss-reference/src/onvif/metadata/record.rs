#![forbid(unsafe_code)]
//! Canonical recipes and deterministic projections; never JSON authority or XML rewriting.

use fss_core::{
    CanonicalDecoder, CanonicalEncoder, CaptureInterval, ContentDigest, DigestAlgorithm, SensorId,
    TimestampNs,
};

use super::{
    Interpretation, MAX_PROJECTION_BYTES, MAX_RECIPE_BYTES, MAX_SOURCE_BYTES, MetadataError,
    PULLPOINT_RECIPE_DOMAIN, PullPointAcquisition, RECIPE_DOMAIN, RECIPE_DOMAIN_V1, SourceBinding,
};
use crate::onvif::wire::{
    AnalyticsAppearance, AnalyticsClassFormat, AnalyticsFrame, AnalyticsTransformation,
    AnalyticsVector, EventDocument, EventDocumentFormat, EventItems, EventNotification,
    PropertyOperation,
};

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Recipe {
    pub(super) interpretation: Interpretation,
    pub(super) site: String,
    pub(super) binding: SourceBinding,
    pub(super) source: ContentDigest,
    pub(super) source_bytes: usize,
    pub(super) projection: ContentDigest,
    pub(super) acquisition: Option<PullPointAcquisition>,
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
    if let Some(acquisition) = &recipe.acquisition {
        acquisition.validate()?;
        let span =
            recipe.binding.receive_interval.latest.0 - recipe.binding.receive_interval.earliest.0;
        if recipe.interpretation != Interpretation::EventsV1
            || span != i128::from(acquisition.completed_ns - acquisition.started_ns)
        {
            return Err(MetadataError::InvalidBinding);
        }
    }
    let mut e = CanonicalEncoder::new();
    e.text(if recipe.acquisition.is_some() {
        PULLPOINT_RECIPE_DOMAIN
    } else {
        recipe.interpretation.recipe_domain()
    });
    e.text(recipe.interpretation.parser_generation());
    e.text(if recipe.acquisition.is_some() {
        "onvif_pullpoint"
    } else {
        "owner_supplied_file"
    });
    e.text(&recipe.site);
    source_binding(&mut e, &recipe.binding);
    e.i128(recipe.binding.receive_interval.earliest.0);
    e.i128(recipe.binding.receive_interval.latest.0);
    e.digest(recipe.source);
    e.u64(recipe.source_bytes as u64);
    e.digest(recipe.projection);
    if let Some(acquisition) = &recipe.acquisition {
        e.digest(acquisition.approval);
        e.digest(acquisition.event_route);
        e.digest(acquisition.subscription_route);
        e.u64(u64::from(acquisition.pull_index));
        e.u64(acquisition.started_ns);
        e.u64(acquisition.completed_ns);
        e.bool(acquisition.client_authenticated);
        e.digest(acquisition.subscription_source);
        e.u64(acquisition.subscription_source_bytes as u64);
        e.text(&acquisition.message_id);
        e.text(&acquisition.subscription_message_id);
        e.u64(acquisition.subscription_started_ns);
        e.u64(acquisition.subscription_completed_ns);
    }
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
    let (interpretation, live) = match d.text()? {
        RECIPE_DOMAIN_V1 => (Interpretation::EventsV1, false),
        RECIPE_DOMAIN => (Interpretation::AnalyticsV2, false),
        PULLPOINT_RECIPE_DOMAIN => (Interpretation::EventsV1, true),
        _ => return Err(MetadataError::Custody),
    };
    let mode = if live {
        "onvif_pullpoint"
    } else {
        "owner_supplied_file"
    };
    if d.text()? != interpretation.parser_generation() || d.text()? != mode {
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
    let acquisition = if live {
        Some(PullPointAcquisition {
            approval: d.digest()?,
            event_route: d.digest()?,
            subscription_route: d.digest()?,
            pull_index: u32::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?,
            started_ns: d.u64()?,
            completed_ns: d.u64()?,
            client_authenticated: d.bool()?,
            subscription_source: d.digest()?,
            subscription_source_bytes: usize::try_from(d.u64()?)
                .map_err(|_| MetadataError::Limit)?,
            message_id: d.text()?.to_owned(),
            subscription_message_id: d.text()?.to_owned(),
            subscription_started_ns: d.u64()?,
            subscription_completed_ns: d.u64()?,
        })
    } else {
        None
    };
    d.ensure_finished()?;
    let recipe = Recipe {
        interpretation,
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
        acquisition,
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

pub(super) fn projection(
    document: &EventDocument,
    interpretation: Interpretation,
) -> Result<Vec<u8>, MetadataError> {
    let mut e = CanonicalEncoder::new();
    e.text(interpretation.projection_domain());
    e.text(interpretation.parser_generation());
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
    if interpretation == Interpretation::AnalyticsV2 {
        e.u64(document.analytics_frames.len() as u64);
        for frame in &document.analytics_frames {
            analytics_frame(&mut e, frame);
        }
    } else if !document.analytics_frames.is_empty() {
        return Err(MetadataError::Custody);
    }
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
    e.text(match recipe.interpretation {
        Interpretation::EventsV1 => "fss.onvif_vendor_notification_identity.v1",
        Interpretation::AnalyticsV2 => "fss.onvif_vendor_notification_identity.v2",
    });
    e.text(recipe.interpretation.parser_generation());
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

fn vector(e: &mut CanonicalEncoder, value: &AnalyticsVector) {
    e.text(value.x.as_str());
    e.text(value.y.as_str());
    e.u64(value.unsupported_extensions as u64);
}

fn transformation(e: &mut CanonicalEncoder, value: Option<&AnalyticsTransformation>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        for component in [value.translate.as_ref(), value.scale.as_ref()] {
            e.bool(component.is_some());
            if let Some(component) = component {
                vector(e, component);
            }
        }
        e.u64(value.unsupported_extensions as u64);
    }
}

fn appearance(e: &mut CanonicalEncoder, value: Option<&AnalyticsAppearance>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        transformation(e, value.transformation.as_ref());
        e.bool(value.shape.is_some());
        if let Some(shape) = &value.shape {
            let bounds = &shape.bounding_box;
            e.text(bounds.left.as_str());
            e.text(bounds.top.as_str());
            e.text(bounds.right.as_str());
            e.text(bounds.bottom.as_str());
            e.u64(bounds.unsupported_extensions as u64);
            vector(e, &shape.center_of_gravity);
            e.u64(shape.unsupported_extensions as u64);
        }
        e.bool(value.class.is_some());
        if let Some(class) = &value.class {
            e.u64(class.candidates.len() as u64);
            for candidate in &class.candidates {
                e.u8(match candidate.format {
                    AnalyticsClassFormat::LegacyCandidate => 1,
                    AnalyticsClassFormat::Type => 2,
                });
                e.text(&candidate.label);
                optional_text(e, candidate.likelihood.as_ref().map(|value| value.as_str()));
                e.u64(candidate.unsupported_extensions as u64);
            }
            e.u64(class.unsupported_extensions as u64);
        }
        e.u64(value.unsupported_extensions as u64);
    }
}

fn analytics_frame(e: &mut CanonicalEncoder, frame: &AnalyticsFrame) {
    e.text(&frame.utc_time);
    optional_text(e, frame.source.as_deref());
    transformation(e, frame.transformation.as_ref());
    e.u64(frame.objects.len() as u64);
    for object in &frame.objects {
        e.text(&object.object_id);
        appearance(e, object.appearance.as_ref());
        e.u64(object.unsupported_extensions as u64);
    }
    e.u64(frame.unsupported_extensions as u64);
}

pub(super) fn analytics_frame_identity(
    recipe: &Recipe,
    frame: &AnalyticsFrame,
    index: usize,
) -> Result<ContentDigest, MetadataError> {
    if recipe.interpretation != Interpretation::AnalyticsV2 {
        return Err(MetadataError::Custody);
    }
    let mut e = CanonicalEncoder::new();
    e.text("fss.onvif_vendor_analytics_frame_identity.v2");
    e.text(recipe.interpretation.parser_generation());
    e.text(&recipe.site);
    source_binding(&mut e, &recipe.binding);
    e.digest(recipe.source);
    e.u64(index as u64);
    analytics_frame(&mut e, frame);
    Ok(ContentDigest::sha256(&e.finish_checked()?))
}
