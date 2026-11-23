#![forbid(unsafe_code)]
//! Strict control-document decoding. The canonical decision uses typed fields, not JSON bytes.

use std::collections::BTreeMap;

use crate::json_input::{self, Value};

use super::*;

type Fields = BTreeMap<String, Value>;

fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Fields, FamiliarityError> {
    let fields = value
        .object()
        .ok_or(FamiliarityError::Malformed("expected object"))?;
    if fields.len() != keys.len() || fields.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(FamiliarityError::Malformed("unknown or missing field"));
    }
    Ok(fields)
}
fn field<'a>(fields: &'a Fields, key: &str) -> Result<&'a Value, FamiliarityError> {
    fields
        .get(key)
        .ok_or(FamiliarityError::Malformed("missing field"))
}
fn text<'a>(fields: &'a Fields, key: &str) -> Result<&'a str, FamiliarityError> {
    field(fields, key)?
        .text()
        .ok_or(FamiliarityError::Malformed("expected text"))
}
fn digest(fields: &Fields, key: &str) -> Result<ContentDigest, FamiliarityError> {
    ContentDigest::parse(text(fields, key)?)
        .map_err(|_| FamiliarityError::Malformed("invalid digest"))
}
fn boolean(fields: &Fields, key: &str) -> Result<bool, FamiliarityError> {
    field(fields, key)?
        .boolean()
        .ok_or(FamiliarityError::Malformed("expected boolean"))
}
fn time(fields: &Fields, key: &str) -> Result<TimestampNs, FamiliarityError> {
    let value = field(fields, key)?;
    let number = value
        .integer()
        .ok_or(FamiliarityError::Malformed("expected exact nanoseconds"))?;
    if !matches!(value, Value::Number(text) | Value::Text(text) if *text == number.to_string()) {
        return Err(FamiliarityError::Malformed("noncanonical nanoseconds"));
    }
    Ok(TimestampNs(number))
}
fn risk(value: &str) -> Result<AssertedRisk, FamiliarityError> {
    match value {
        "clear_asserted" => Ok(AssertedRisk::Clear),
        "unknown" => Ok(AssertedRisk::Unknown),
        "present" => Ok(AssertedRisk::Present),
        _ => Err(FamiliarityError::Malformed("risk class")),
    }
}

impl FamiliarityContext {
    /// Decode a complete bounded control document, refusing unknown/duplicate fields,
    /// noncanonical integer values, unsupported schemas and over-bound signal inventories.
    pub fn from_json(text_input: &str) -> Result<Self, FamiliarityError> {
        if text_input.len() > MAX_CONTEXT_BYTES {
            return Err(FamiliarityError::Malformed("context byte limit"));
        }
        let value = json_input::parse(text_input)
            .map_err(|_| FamiliarityError::Malformed("invalid JSON"))?;
        let fields = object(
            &value,
            &[
                "schema",
                "site_lineage",
                "authority_root",
                "privacy_scope",
                "event_id",
                "event_revision_digest",
                "event_policy_generation",
                "coverage",
                "threat_actions",
                "sensor_integrity",
                "high_consequence",
                "signals",
            ],
        )?;
        if text(fields, "schema")? != CONTEXT_SCHEMA {
            return Err(FamiliarityError::Malformed("unsupported schema"));
        }
        let coverage = match text(fields, "coverage")? {
            "complete_asserted" => AssertedCoverage::Complete,
            "unknown" => AssertedCoverage::Unknown,
            "degraded" => AssertedCoverage::Degraded,
            _ => return Err(FamiliarityError::Malformed("coverage class")),
        };
        let entries = field(fields, "signals")?
            .array()
            .ok_or(FamiliarityError::Malformed("expected signals array"))?;
        if entries.len() > MAX_SIGNALS {
            return Err(FamiliarityError::Malformed("signal count"));
        }
        let mut signals = Vec::with_capacity(entries.len());
        for entry in entries {
            let row = object(
                entry,
                &[
                    "evidence_digest",
                    "source_generation",
                    "kind",
                    "supports",
                    "failure_domains",
                    "valid_from_ns",
                    "expires_at_ns",
                    "revoked",
                    "opted_in",
                    "model_receipt",
                ],
            )?;
            let kind = match text(row, "kind")? {
                "authorized_door" => SignalKind::AuthorizedDoor,
                "path_continuity" => SignalKind::PathContinuity,
                "trusted_device" => SignalKind::TrustedDevice,
                "appearance" => SignalKind::Appearance,
                "routine" => SignalKind::Routine,
                "operator_confirmation" => SignalKind::OperatorConfirmation,
                _ => return Err(FamiliarityError::Malformed("signal kind")),
            };
            let domains = field(row, "failure_domains")?
                .array()
                .ok_or(FamiliarityError::Malformed("expected failure domain array"))?;
            if domains.is_empty() || domains.len() > MAX_DOMAINS {
                return Err(FamiliarityError::Malformed("failure domain count"));
            }
            let failure_domains = domains
                .iter()
                .map(|value| {
                    let name = value
                        .text()
                        .ok_or(FamiliarityError::Malformed("expected failure domain text"))?;
                    if !valid_name(name) {
                        return Err(FamiliarityError::Malformed("failure domain identity"));
                    }
                    Ok(name.to_owned())
                })
                .collect::<Result<Vec<_>, FamiliarityError>>()?;
            let model_receipt = match field(row, "model_receipt")? {
                Value::Null => None,
                Value::Text(value) => Some(
                    ContentDigest::parse(value)
                        .map_err(|_| FamiliarityError::Malformed("model receipt digest"))?,
                ),
                _ => {
                    return Err(FamiliarityError::Malformed(
                        "model receipt must be digest or null",
                    ));
                }
            };
            signals.push(FamiliaritySignal {
                evidence_digest: digest(row, "evidence_digest")?,
                source_generation: digest(row, "source_generation")?,
                kind,
                supports: boolean(row, "supports")?,
                failure_domains,
                valid_from_ns: time(row, "valid_from_ns")?,
                expires_at_ns: time(row, "expires_at_ns")?,
                revoked: boolean(row, "revoked")?,
                opted_in: boolean(row, "opted_in")?,
                model_receipt,
            });
        }
        let context = Self {
            site_lineage: text(fields, "site_lineage")?.to_owned(),
            authority_root: digest(fields, "authority_root")?,
            privacy_scope: text(fields, "privacy_scope")?.to_owned(),
            event_id: EventId::parse(text(fields, "event_id")?)
                .map_err(|_| FamiliarityError::Malformed("event identity"))?,
            event_revision_digest: digest(fields, "event_revision_digest")?,
            event_policy_generation: digest(fields, "event_policy_generation")?,
            coverage,
            threat_actions: risk(text(fields, "threat_actions")?)?,
            sensor_integrity: risk(text(fields, "sensor_integrity")?)?,
            high_consequence: boolean(fields, "high_consequence")?,
            signals,
        };
        context.validate()?;
        Ok(context)
    }
}
