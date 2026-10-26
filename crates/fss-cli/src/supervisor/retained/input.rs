#![forbid(unsafe_code)]
//! Exact-byte-pinned operator request. Native detections can only be selected, never supplied.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, DigestAlgorithm, EventId};
use fss_fusion::{FusionPolicy, LlrInterval, Severity};

use crate::event_fusion::parse_score_calibration;
use crate::json_input::{Value, parse};

use super::{
    MAX_RETAINED_SUPERVISOR_PLAN_BYTES, RetainedCameraSpec, RetainedDiscoveryRequest,
    RetainedEventPin, RetainedObservationSelector, RetainedSupervisorError as Error,
    RetainedSupervisorLimits, RetainedSupervisorPlan, RetainedSupervisorSpec,
    RetainedSupervisorWindow,
};

type Result<T> = std::result::Result<T, Error>;
type Object = BTreeMap<String, Value>;

impl RetainedSupervisorPlan {
    /// Verify the exact input bytes before parsing or opening any deployment. This is an
    /// inert request, not a calibration activation, event publication or effect approval.
    /// Unknown fields and duplicate keys are refused, including nested calibration fields.
    pub fn from_json(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RETAINED_SUPERVISOR_PLAN_BYTES {
            return Err(Error::Limit("plan bytes"));
        }
        if expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(Error::Plan("plan byte digest"));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Plan("plan UTF-8"))?;
        let document = parse(text).map_err(|_| Error::Plan("plan JSON"))?;
        Self::from_value(&document)
    }

    // Discovery carries the same complete plan dialect, without serializing caller JSON
    // again or introducing another authority/calibration parser.
    pub(super) fn from_value(document: &Value) -> Result<Self> {
        let top = object(
            document,
            &[
                "schema",
                "site_lineage",
                "hypothesis_id",
                "expected_authority_root",
                "label",
                "start_ns",
                "cameras",
                "events",
                "windows",
                "prior",
                "policy",
                "severity",
                "limits",
            ],
        )?;
        if text_field(top, "schema")? != "fss.retained_supervisor_plan.v1" {
            return Err(Error::Plan("plan schema"));
        }
        let camera_values = array(field(top, "cameras")?, 8)?;
        let mut cameras = Vec::with_capacity(camera_values.len());
        for value in camera_values {
            let camera = object(
                value,
                &[
                    "camera_id",
                    "sensor_id",
                    "package_digest",
                    "model_digest",
                    "contract_digest",
                    "class_index",
                    "failure_domains",
                    "calibration",
                ],
            )?;
            let mut failure_domains = BTreeSet::new();
            for value in array(field(camera, "failure_domains")?, 8)? {
                let domain = value.text().ok_or(Error::Plan("failure domain"))?;
                if !failure_domains.insert(domain.to_owned()) {
                    return Err(Error::Plan("duplicate failure domain"));
                }
            }
            let calibration = match field(camera, "calibration")? {
                Value::Null => None,
                value => Some(parse_score_calibration(value).map_err(Error::Fusion)?),
            };
            cameras.push(RetainedCameraSpec {
                camera_id: text_field(camera, "camera_id")?.to_owned(),
                sensor_id: text_field(camera, "sensor_id")?.to_owned(),
                package_digest: sha(field(camera, "package_digest")?)?,
                model_digest: sha(field(camera, "model_digest")?)?,
                contract_digest: sha(field(camera, "contract_digest")?)?,
                class_index: number(field(camera, "class_index")?)?,
                failure_domains,
                calibration,
            });
        }
        let event_values = array(field(top, "events")?, 32)?;
        let mut events = Vec::with_capacity(event_values.len());
        for value in event_values {
            let event = object(value, &["camera_id", "event_id", "expected_event_root"])?;
            events.push(RetainedEventPin {
                camera_id: text_field(event, "camera_id")?.to_owned(),
                event_id: event_id(field(event, "event_id")?)?,
                expected_event_root: sha(field(event, "expected_event_root")?)?,
            });
        }
        let window_values = array(field(top, "windows")?, 32)?;
        let mut windows = Vec::with_capacity(window_values.len());
        let mut selections = 0_usize;
        for value in window_values {
            let window = object(value, &["window_index", "end_ns", "observations"])?;
            let rows = array(field(window, "observations")?, 128)?;
            selections = selections
                .checked_add(rows.len())
                .filter(|count| *count <= 512)
                .ok_or(Error::Limit("total selections"))?;
            let mut observations = Vec::with_capacity(rows.len());
            for value in rows {
                let selection = object(
                    value,
                    &["event_id", "capsule_digest", "segment", "detection_row"],
                )?;
                observations.push(RetainedObservationSelector {
                    event_id: event_id(field(selection, "event_id")?)?,
                    capsule_digest: sha(field(selection, "capsule_digest")?)?,
                    segment: number(field(selection, "segment")?)?,
                    detection_row: number(field(selection, "detection_row")?)?,
                });
            }
            windows.push(RetainedSupervisorWindow {
                window_index: number(field(window, "window_index")?)?,
                end_ns: number(field(window, "end_ns")?)?,
                observations,
            });
        }
        let policy = object(
            field(top, "policy")?,
            &[
                "generation",
                "alert_threshold",
                "retain_threshold",
                "reject_threshold",
                "min_independent_support",
                "urgent_single_domain_threshold",
                "max_wait_ns",
                "look_penalty_per_doubling",
                "operator_confirmation_available",
            ],
        )?;
        let severity = object(
            field(top, "severity")?,
            &[
                "expected_harm",
                "false_alert_cost",
                "delay_cost_per_second",
                "reversible",
            ],
        )?;
        let limits = object(
            field(top, "limits")?,
            &[
                "max_read_bytes",
                "max_read_attempts",
                "max_journal_bytes",
                "max_report_bytes",
            ],
        )?;
        Self::new(RetainedSupervisorSpec {
            site_lineage: text_field(top, "site_lineage")?.to_owned(),
            hypothesis_id: text_field(top, "hypothesis_id")?.to_owned(),
            expected_authority_root: sha(field(top, "expected_authority_root")?)?,
            label: text_field(top, "label")?.to_owned(),
            start_ns: number(field(top, "start_ns")?)?,
            cameras,
            events,
            windows,
            prior: interval(field(top, "prior")?)?,
            policy: FusionPolicy {
                generation: text_field(policy, "generation")?.to_owned(),
                alert_threshold: number(field(policy, "alert_threshold")?)?,
                retain_threshold: number(field(policy, "retain_threshold")?)?,
                reject_threshold: number(field(policy, "reject_threshold")?)?,
                min_independent_support: number(field(policy, "min_independent_support")?)?,
                urgent_single_domain_threshold: match field(
                    policy,
                    "urgent_single_domain_threshold",
                )? {
                    Value::Null => None,
                    value => Some(number(value)?),
                },
                max_wait_ns: number(field(policy, "max_wait_ns")?)?,
                look_penalty_per_doubling: number(field(policy, "look_penalty_per_doubling")?)?,
                operator_confirmation_available: boolean(field(
                    policy,
                    "operator_confirmation_available",
                )?)?,
            },
            severity: Severity {
                expected_harm: number(field(severity, "expected_harm")?)?,
                false_alert_cost: number(field(severity, "false_alert_cost")?)?,
                delay_cost_per_second: number(field(severity, "delay_cost_per_second")?)?,
                reversible: boolean(field(severity, "reversible")?)?,
            },
            limits: RetainedSupervisorLimits {
                max_read_bytes: number(field(limits, "max_read_bytes")?)?,
                max_read_attempts: number(field(limits, "max_read_attempts")?)?,
                max_journal_bytes: number(field(limits, "max_journal_bytes")?)?,
                max_report_bytes: number(field(limits, "max_report_bytes")?)?,
            },
        })
    }
}

impl RetainedDiscoveryRequest {
    /// Verify the exact wrapper bytes before parsing. The nested plan uses the ordinary
    /// retained schema and must contain no caller-selected event or detection row.
    pub fn from_json(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RETAINED_SUPERVISOR_PLAN_BYTES {
            return Err(Error::Limit("discovery request bytes"));
        }
        if expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(Error::Plan("discovery request byte digest"));
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| Error::Plan("discovery request UTF-8"))?;
        let document = parse(text).map_err(|_| Error::Plan("discovery request JSON"))?;
        let top = object(&document, &["schema", "maximum_catalog_events", "plan"])?;
        if text_field(top, "schema")? != "fss.retained_supervisor_discovery.v1" {
            return Err(Error::Plan("discovery request schema"));
        }
        let template = RetainedSupervisorPlan::from_value(field(top, "plan")?)?;
        Self::new(template, number(field(top, "maximum_catalog_events")?)?)
    }
}

fn object<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Object> {
    let object = value.object().ok_or(Error::Plan("JSON object"))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(Error::Plan("unknown JSON field"));
    }
    Ok(object)
}
fn field<'a>(object: &'a Object, key: &str) -> Result<&'a Value> {
    object.get(key).ok_or(Error::Plan("missing JSON field"))
}
fn text_field<'a>(object: &'a Object, key: &str) -> Result<&'a str> {
    field(object, key)?.text().ok_or(Error::Plan("JSON text"))
}
fn array(value: &Value, maximum: usize) -> Result<&[Value]> {
    let values = value.array().ok_or(Error::Plan("JSON array"))?;
    if values.len() > maximum {
        return Err(Error::Limit("array entries"));
    }
    Ok(values)
}
fn number<T: TryFrom<i128>>(value: &Value) -> Result<T> {
    value
        .integer()
        .and_then(|n| T::try_from(n).ok())
        .ok_or(Error::Plan("JSON integer"))
}
fn boolean(value: &Value) -> Result<bool> {
    value.boolean().ok_or(Error::Plan("JSON boolean"))
}
fn sha(value: &Value) -> Result<ContentDigest> {
    ContentDigest::parse(value.text().ok_or(Error::Plan("digest text"))?)
        .ok()
        .filter(|digest| digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32])
        .ok_or(Error::Plan("SHA-256 digest"))
}
fn event_id(value: &Value) -> Result<EventId> {
    EventId::parse(value.text().ok_or(Error::Plan("event ID text"))?)
        .map_err(|_| Error::Plan("event ID"))
}
fn interval(value: &Value) -> Result<LlrInterval> {
    let [lo, hi] = array(value, 2)? else {
        return Err(Error::Plan("prior interval"));
    };
    LlrInterval::new(number(lo)?, number(hi)?).map_err(Error::Engine)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> String {
        r#"{
          "schema":"fss.retained_supervisor_plan.v1",
          "site_lineage":"site:retained-input",
          "hypothesis_id":"hyp:class:tie",
          "expected_authority_root":"PIN",
          "label":"tie","start_ns":0,
          "cameras":[{"camera_id":"east","sensor_id":"sensor:east",
            "package_digest":"PIN","model_digest":"PIN","contract_digest":"PIN",
            "class_index":27,"failure_domains":[],"calibration":null}],
          "events":[{"camera_id":"east","event_id":"event:retained-input",
            "expected_event_root":"PIN"}],
          "windows":[{"window_index":0,"end_ns":1000,"observations":[{
            "event_id":"event:retained-input","capsule_digest":"PIN","segment":0,"detection_row":7}]}],
          "prior":[0,0],
          "policy":{"generation":"policy:retained-input:v1","alert_threshold":1800,
            "retain_threshold":0,"reject_threshold":-1000,"min_independent_support":2,
            "urgent_single_domain_threshold":null,"max_wait_ns":0,
            "look_penalty_per_doubling":0,"operator_confirmation_available":false},
          "severity":{"expected_harm":10000,"false_alert_cost":500,
            "delay_cost_per_second":100,"reversible":false},
          "limits":{"max_read_bytes":134217728,"max_read_attempts":8192,
            "max_journal_bytes":16777216,"max_report_bytes":2097152}
        }"#.replace("PIN", &ContentDigest::sha256(b"retained input fixture pin").to_text())
    }

    fn read(json: &str) -> Result<RetainedSupervisorPlan> {
        RetainedSupervisorPlan::from_json(json.as_bytes(), ContentDigest::sha256(json.as_bytes()))
    }

    #[test]
    fn exact_byte_pin_precedes_json_and_no_supplied_score_or_unknown_field_is_accepted() {
        let json = document();
        let plan = read(&json).expect("valid retained selection");
        assert_eq!(plan.spec().cameras.len(), 1);
        assert!(plan.spec().cameras[0].calibration.is_none());
        assert!(
            RetainedSupervisorPlan::from_json(json.as_bytes(), ContentDigest::sha256(b"other"))
                .is_err()
        );
        for altered in [
            json.replacen("\"schema\":", "\"schema\":\"duplicate\",\"schema\":", 1),
            json.replacen(
                "\"start_ns\":0",
                "\"start_ns\":0,\"effects_authorized\":true",
                1,
            ),
            json.replacen(
                "\"detection_row\":7",
                "\"detection_row\":7,\"score_ppm\":999999",
                1,
            ),
            json.replacen(
                "\"end_ns\":1000",
                "\"end_ns\":1000,\"coverage\":\"complete\"",
                1,
            ),
            json.replacen(
                "\"max_read_bytes\":134217728",
                "\"max_read_bytes\":134217728,\"skip_privacy\":true",
                1,
            ),
            json.replacen("\"segment\":0", "\"segment\":0.0", 1),
            json.replacen("\"segment\":0", "\"segment\":-1", 1),
        ] {
            assert!(
                read(&altered).is_err(),
                "accepted an ambiguous or unsupported request"
            );
        }
    }

    #[test]
    fn optional_calibration_uses_existing_count_reconstruction_and_derived_value_checks() {
        let calibration = fss_fusion::ScoreCalibration::from_counts(
            "cal:retained-input:v1",
            &[0, 500_000],
            &[(2, 98), (98, 2)],
        )
        .expect("fixture counts");
        let table = format!(
            r#"{{"schema":"fss.score_calibration.v1","generation":"{}","digest":"{}","bins":[{{"lo_ppm":0,"true_positives":2,"false_positives":98}},{{"lo_ppm":500000,"true_positives":98,"false_positives":2}}]}}"#,
            calibration.generation, calibration.digest,
        );
        let json = document().replace("\"calibration\":null", &format!("\"calibration\":{table}"));
        let plan = read(&json).expect("valid explicit calibration");
        assert_eq!(
            plan.spec().cameras[0]
                .calibration
                .as_ref()
                .expect("calibration")
                .digest,
            calibration.digest
        );
        for invalid in [
            json.replace(
                &calibration.digest.to_text(),
                &ContentDigest::sha256(b"wrong calibration").to_text(),
            ),
            json.replace(
                "\"false_positives\":2}",
                "\"false_positives\":2,\"llr_millibans\":[0,0]}",
            ),
            json.replace("\"bins\":[", "\"unverified_applicability\":true,\"bins\":["),
        ] {
            assert_ne!(invalid, json, "fixture must modify the calibration");
            assert!(read(&invalid).is_err());
        }
    }

    #[test]
    fn whole_plan_byte_ceiling_is_enforced_even_when_the_digest_matches() {
        let bytes = vec![b' '; MAX_RETAINED_SUPERVISOR_PLAN_BYTES + 1];
        assert!(RetainedSupervisorPlan::from_json(&bytes, ContentDigest::sha256(&bytes)).is_err());
    }

    fn discovery_document() -> String {
        let selected = document();
        let events = selected.find("\"events\":").expect("fixture events");
        let prior = selected.find("\"prior\":").expect("fixture prior");
        let template = format!(
            "{}\"events\":[],\"windows\":[{{\"window_index\":0,\"end_ns\":1000,\"observations\":[]}}],{}",
            &selected[..events],
            &selected[prior..],
        );
        format!(
            r#"{{"schema":"fss.retained_supervisor_discovery.v1","maximum_catalog_events":64,"plan":{template}}}"#
        )
    }

    fn discover(json: &str) -> Result<RetainedDiscoveryRequest> {
        RetainedDiscoveryRequest::from_json(json.as_bytes(), ContentDigest::sha256(json.as_bytes()))
    }

    #[test]
    fn discovery_byte_pin_and_complete_existing_plan_are_admitted_before_io() {
        let json = discovery_document();
        let request = discover(&json).expect("valid discovery request");
        assert_eq!(request.maximum_catalog_events(), 64);
        assert_eq!(request.template().spec().cameras.len(), 1);
        assert!(request.template().spec().events.is_empty());
        assert!(request.template().spec().windows[0].observations.is_empty());
        assert!(matches!(
            RetainedDiscoveryRequest::from_json(b"not JSON", ContentDigest::sha256(b"other")),
            Err(Error::Plan("discovery request byte digest"))
        ));
        for altered in [
            json.replacen(
                "\"maximum_catalog_events\":64",
                "\"maximum_catalog_events\":0",
                1,
            ),
            json.replacen(
                "\"maximum_catalog_events\":64",
                "\"maximum_catalog_events\":4097",
                1,
            ),
            json.replacen(
                "\"maximum_catalog_events\":64",
                "\"maximum_catalog_events\":1.0",
                1,
            ),
            json.replacen(
                "\"maximum_catalog_events\":64",
                "\"maximum_catalog_events\":64,\"maximum_catalog_events\":64",
                1,
            ),
            json.replacen(
                "\"maximum_catalog_events\":64",
                "\"maximum_catalog_events\":64,\"skip_privacy\":true",
                1,
            ),
            json.replacen(
                "\"class_index\":27",
                "\"class_index\":27,\"score_ppm\":999999",
                1,
            ),
            json.replacen(
                "\"min_independent_support\":2",
                "\"min_independent_support\":1",
                1,
            ),
            format!(
                r#"{{"schema":"fss.retained_supervisor_discovery.v1","maximum_catalog_events":64,"plan":{}}}"#,
                document(),
            ),
        ] {
            assert_ne!(altered, json);
            assert!(
                discover(&altered).is_err(),
                "discovery accepted a malformed or selected input"
            );
        }
        let bytes = vec![b' '; MAX_RETAINED_SUPERVISOR_PLAN_BYTES + 1];
        assert!(
            RetainedDiscoveryRequest::from_json(&bytes, ContentDigest::sha256(&bytes)).is_err()
        );
    }
}
