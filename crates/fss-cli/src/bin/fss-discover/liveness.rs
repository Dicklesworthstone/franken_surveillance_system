#![forbid(unsafe_code)]
//! Explicit owner binding and short-lived deployment custody for discovery sweeps.
use fss_cli::agent_json::{object, string};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
};
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::discovery::retained_liveness::{
    DeviceEnrollment, MAX_LIVENESS_SENSORS, parse_device_class, retain_discovery_window,
    validate_enrollments,
};
use fss_reference::discovery::watchdog::DeviceClass;
use fss_reference::discovery::{DiscoverConfig, DiscoverReport};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::path::{Component, PathBuf};

#[derive(Debug)]
pub(super) struct Options {
    root: PathBuf,
    site: String,
    enrollments: Vec<DeviceEnrollment>,
}
impl Options {
    pub(super) fn parse(
        root: Option<String>,
        site: Option<String>,
        bindings: Vec<String>,
    ) -> Result<Option<Self>, &'static str> {
        if root.is_none() && site.is_none() && bindings.is_empty() {
            return Ok(None);
        }
        let root = PathBuf::from(root.ok_or("liveness retention requires --root")?);
        let site = site.ok_or("liveness retention requires --site")?;
        if !root.is_absolute()
            || root.parent().is_none()
            || root
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err("--root must be an absolute existing deployment path");
        }
        fss_reference::reference_deployment::validate_site_lineage(&site)
            .map_err(|_| "invalid --site")?;
        if site.len() > 256 || bindings.is_empty() || bindings.len() > MAX_LIVENESS_SENSORS {
            return Err(
                "liveness retention requires 1..=64 explicit --bind IP=SENSOR[,CLASS] values",
            );
        }
        let mut enrollments = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let (endpoint, sensor_class) = binding
                .split_once('=')
                .ok_or("--bind requires IP=SENSOR[,CLASS]")?;
            let endpoint = endpoint
                .parse()
                .map_err(|_| "invalid --bind IPv4 endpoint")?;
            let (sensor, class) = match sensor_class.split_once(',') {
                Some((sensor, class)) => (sensor, parse_device_class(class).ok_or("invalid --bind class; use tutk, tuya, onvif, battery_event_driven, unknown or provisioned_agent")?),
                None => (sensor_class, DeviceClass::Unknown),
            };
            let sensor = SensorId::parse(sensor).map_err(|_| "invalid --bind sensor identity")?;
            enrollments.push(
                DeviceEnrollment::new(endpoint, sensor, class)
                    .map_err(|_| "invalid liveness enrollment")?,
            );
        }
        validate_enrollments(&enrollments, &[])
            .map_err(|_| "duplicate or invalid --bind enrollment")?;
        Ok(Some(Self {
            root,
            site,
            enrollments,
        }))
    }
    /// Pure scope validation and read-only binding checks precede network, context
    /// construction, lock acquisition and directory creation.
    pub(super) fn preflight(&self, config: &DiscoverConfig) -> Result<(), &'static str> {
        let plan = config
            .census
            .plan()
            .map_err(|_| "ERR-DISCOVER-LIVENESS-001: invalid census scope")?;
        if self.enrollments.iter().any(|binding| {
            plan.ping_targets
                .binary_search(&binding.endpoint())
                .is_err()
        }) {
            return Err(
                "ERR-DISCOVER-LIVENESS-001: every bound endpoint must be inside an authorized subnet",
            );
        }
        let snapshot = read_deployment(&self.root, &OrientLimits::default())
            .map_err(|_| "ERR-DISCOVER-LIVENESS-001: existing deployment cannot be read or retained liveness is invalid")?;
        if snapshot.site_lineage != self.site {
            return Err("ERR-DISCOVER-LIVENESS-001: deployment site differs from --site");
        }
        validate_enrollments(&self.enrollments, &snapshot.sensor_liveness)
            .map_err(|_| "ERR-DISCOVER-LIVENESS-001: explicit bindings conflict with retained sensor enrollment")?;
        Ok(())
    }
    /// The exclusive deployment lock covers publication only, never the network or sleep.
    pub(super) fn retain(
        &self,
        report: &DiscoverReport,
        sweep_started_ns: u64,
        at_ns: u64,
    ) -> Result<Vec<String>, &'static str> {
        const ERROR: &str = "ERR-DISCOVER-LIVENESS-001: cannot retain sweep; inspect deployment and preserve binding/time on retry";
        if !std::fs::symlink_metadata(&self.root).is_ok_and(|m| m.file_type().is_dir())
            || !std::fs::symlink_metadata(self.root.join("LAYOUT"))
                .is_ok_and(|m| m.file_type().is_file())
        {
            return Err(ERROR);
        }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:discovery-liveness".into(),
            operation_id: OperationId::parse("operation:discovery-liveness").map_err(|_| ERROR)?,
            principal: "principal:owner-network-operator".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(16 * 1024 * 1024)
                .storage_operations(8192)
                .build()
                .map_err(|_| ERROR)?,
            privacy_scope: "privacy:owner-network-metadata".into(),
            retention_scope: "retention:existing-deployment-policy".into(),
            anchor_universe: ContentDigest::sha256(self.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| ERROR)?;
        let cx =
            ReplayCx::from_context_authority(&authority, self.root.clone()).map_err(|_| ERROR)?;
        let result = (|| {
            let mut deployment =
                ReferenceDeployment::reopen(&self.root, &self.site, &cx).map_err(|_| ERROR)?;
            let retained = retain_discovery_window(
                &mut deployment,
                &self.enrollments,
                report,
                sweep_started_ns,
                at_ns,
                &cx,
            )
            .map_err(|_| ERROR)?;
            Ok(retained
                .iter()
                .map(|entry| {
                    let record = &entry.record;
                    let binding = record.enrollment();
                    let optional = |value: Option<u64>| {
                        value.map_or_else(|| "null".to_owned(), |value| value.to_string())
                    };
                    object(&[
                        ("schema", string("fss.sensor_liveness_cli.v1")),
                        ("type", string("sensor_liveness_retained")),
                        ("site", string(&self.site)),
                        ("sensor", string(binding.sensor().as_str())),
                        ("endpoint", string(&binding.endpoint().to_string())),
                        ("class", string(binding.class().as_str())),
                        ("network_state", string(record.state().as_str())),
                        ("generation", record.generation().to_string()),
                        ("sweep_started_ns", record.sweep_started_ns().to_string()),
                        ("sweep_completed_ns", record.observed_at_ns().to_string()),
                        ("last_response_earliest_ns", optional(record.last_seen_ns())),
                        (
                            "last_response_latest_ns",
                            optional(record.last_response_latest_ns()),
                        ),
                        (
                            "conservative_grace_until_ns",
                            optional(record.fresh_until_ns()),
                        ),
                        (
                            "response_time_basis",
                            string("bounded_by_sweep_window_age_from_earliest"),
                        ),
                        ("last_unobserved_ns", optional(record.last_unobserved_ns())),
                        ("record_digest", string(&record.digest().to_text())),
                        ("root", string(&entry.root.to_text())),
                        ("commit_sequence", entry.anchor.commit_sequence.to_string()),
                        ("claim_scope", string("historical_network_observation")),
                        ("media_continuity", string("unverified")),
                    ])
                })
                .collect())
        })();
        cx.drain_and_finalize();
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_or_ambiguous_bindings_refuse_before_any_io() {
        assert!(Options::parse(None, None, vec![]).unwrap().is_none());
        assert!(
            Options::parse(
                Some("/tmp/liveness-no-create".into()),
                Some("site:test".into()),
                vec![]
            )
            .is_err()
        );
        assert!(
            Options::parse(
                Some("/tmp/liveness-no-create".into()),
                Some("site:test".into()),
                vec!["10.0.0.1=sensor:a".into(), "10.0.0.1=sensor:b".into()]
            )
            .is_err()
        );
        assert!(
            Options::parse(
                Some("/tmp/liveness-no-create".into()),
                Some("site:test".into()),
                vec!["10.0.0.1=sensor:a,typo".into()]
            )
            .is_err()
        );
    }
    #[test]
    fn out_of_scope_binding_is_rejected_without_creating_the_deployment() {
        let root = std::env::temp_dir().join(format!(
            "fss-liveness-scope-no-create-{}",
            std::process::id()
        ));
        assert!(!root.exists());
        let options = Options::parse(
            Some(root.to_str().unwrap().to_owned()),
            Some("site:test".into()),
            vec!["10.0.0.5=sensor:a".into()],
        )
        .unwrap()
        .unwrap();
        let config = DiscoverConfig::for_subnets(
            vec!["192.168.4.0/24".into()],
            "192.168.4.1".parse().unwrap(),
        );
        assert!(
            options
                .preflight(&config)
                .unwrap_err()
                .contains("inside an authorized subnet")
        );
        assert!(!root.exists());
    }
}
