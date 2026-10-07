#![forbid(unsafe_code)]
//! Owner-declared common causes for recorded corroboration. Connected components contract
//! evidence into one support domain; disjoint declarations never certify real independence.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest};

use super::{CameraSummary, CorroborationError, CorroborationPlan, Result, hex, json_string};

/// Maximum explicit common-cause declarations per analysis.
pub const MAX_CORROBORATION_FAILURE_DOMAINS: usize = 32;
/// Maximum bytes of one qualified common-cause identifier, including its kind.
pub const MAX_CORROBORATION_DOMAIN_BYTES: usize = 128;
/// Maximum camera labels per declaration (the current corroboration plan has two cameras).
pub const MAX_CORROBORATION_DOMAIN_CAMERAS: usize = 8;
/// Maximum complete canonical declaration/assessment record.
pub const MAX_CORROBORATION_DEPENDENCY_BYTES: usize = 64 * 1024;

const DECLARATION_DOMAIN: &str = "fss.recorded_corroboration_dependencies.v1";
const ASSESSMENT_DOMAIN: &str = "fss.recorded_corroboration_dependency_assessment.v1";
const CLUSTER_DOMAIN: &str = "fss.recorded_corroboration_dependency_cluster.v1";
const EDGE_DOMAIN: &str = "fss.recorded_corroboration_dependency_edge.v1";

/// An owner assertion that all named cameras share one possible cause of correlated evidence.
/// Camera labels are local to the exact plan; they are resolved to retained sensor identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureDomainDeclaration {
    /// Qualified identifier: network, power, clock, host, model, calibration, or replay.
    pub domain: String,
    /// One or more plan camera labels. Duplicate labels are refused.
    pub cameras: Vec<String>,
}

/// Immutable, bounded and canonically ordered common-cause declarations. A declaration can only
/// contract support domains. It cannot establish independence, class probability or effect authority.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CorroborationDependencies {
    declarations: Vec<FailureDomainDeclaration>,
}

impl CorroborationDependencies {
    /// Validates all declarations before sorting; repeated domain names or camera labels are
    /// refused rather than silently combined. Input ordering does not change the generation.
    pub fn new(mut declarations: Vec<FailureDomainDeclaration>) -> Result<Self> {
        if declarations.len() > MAX_CORROBORATION_FAILURE_DOMAINS {
            return Err(CorroborationError::InvalidPlan("too many failure domains"));
        }
        let mut names = BTreeSet::new();
        for declaration in &mut declarations {
            if !valid_domain(&declaration.domain) {
                return Err(CorroborationError::InvalidPlan(
                    "invalid failure domain identifier",
                ));
            }
            if !names.insert(declaration.domain.clone()) {
                return Err(CorroborationError::InvalidPlan("duplicate failure domain"));
            }
            if declaration.cameras.is_empty()
                || declaration.cameras.len() > MAX_CORROBORATION_DOMAIN_CAMERAS
                || declaration
                    .cameras
                    .iter()
                    .any(|camera| !super::valid_name(camera, 32))
            {
                return Err(CorroborationError::InvalidPlan(
                    "invalid failure domain camera list",
                ));
            }
            declaration.cameras.sort();
            if declaration
                .cameras
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            {
                return Err(CorroborationError::InvalidPlan(
                    "duplicate failure domain camera",
                ));
            }
        }
        declarations.sort_by(|left, right| left.domain.cmp(&right.domain));
        Ok(Self { declarations })
    }

    /// Every member must name a camera in the supplied plan. Call this before deployment I/O.
    pub fn validate_for(&self, plan: &CorroborationPlan) -> Result<()> {
        self.validate_cameras(
            &plan
                .cameras
                .iter()
                .map(|camera| camera.name.clone())
                .collect::<Vec<_>>(),
        )
    }

    /// Checks a bounded unique camera-label set without opening a deployment.
    pub fn validate_cameras(&self, cameras: &[String]) -> Result<()> {
        if cameras.is_empty() || cameras.len() > MAX_CORROBORATION_DOMAIN_CAMERAS {
            return Err(CorroborationError::InvalidPlan(
                "invalid dependency camera count",
            ));
        }
        let known: BTreeSet<&str> = cameras.iter().map(String::as_str).collect();
        if known.len() != cameras.len() || cameras.iter().any(|name| !super::valid_name(name, 32)) {
            return Err(CorroborationError::InvalidPlan(
                "invalid dependency camera names",
            ));
        }
        if self
            .declarations
            .iter()
            .flat_map(|declaration| &declaration.cameras)
            .any(|camera| !known.contains(camera.as_str()))
        {
            return Err(CorroborationError::InvalidPlan(
                "failure domain names an unknown camera",
            ));
        }
        Ok(())
    }

    /// Canonically sorted declarations, including singleton declarations.
    #[must_use]
    pub fn declarations(&self) -> &[FailureDomainDeclaration] {
        &self.declarations
    }

    /// Whether this is the compatibility policy with intrinsic sensor domains only.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.declarations.is_empty()
    }

    /// Exact versioned declaration generation. A different topology assertion changes this digest.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Bounded canonical declaration bytes, retained in every dependency-enabled candidate graph.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DECLARATION_DOMAIN);
        encoder.u64(self.declarations.len() as u64);
        for declaration in &self.declarations {
            encoder.text(&declaration.domain);
            encode_strings(&mut encoder, &declaration.cameras);
        }
        // Construction bounds every value well below the canonical encoder's fixed ceilings.
        encoder.finish()
    }

    /// Reads a bounded exact generation. Noncanonical order, unknown kinds and trailing bytes fail.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CORROBORATION_DEPENDENCY_BYTES {
            return Err(CorroborationError::Limit);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != DECLARATION_DOMAIN {
            return Err(CorroborationError::InvalidPlan(
                "unknown dependency generation",
            ));
        }
        let count = bounded_count(decoder.u64()?, MAX_CORROBORATION_FAILURE_DOMAINS)?;
        let mut declarations = Vec::with_capacity(count);
        for _ in 0..count {
            let domain = decoder.text()?.to_owned();
            let count = bounded_count(decoder.u64()?, MAX_CORROBORATION_DOMAIN_CAMERAS)?;
            let mut cameras = Vec::with_capacity(count);
            for _ in 0..count {
                cameras.push(decoder.text()?.to_owned());
            }
            declarations.push(FailureDomainDeclaration { domain, cameras });
        }
        decoder.ensure_finished()?;
        let value = Self::new(declarations)?;
        if value.to_bytes() != bytes {
            return Err(CorroborationError::InvalidPlan(
                "noncanonical dependency generation",
            ));
        }
        Ok(value)
    }
}

fn valid_domain(domain: &str) -> bool {
    if domain.len() > MAX_CORROBORATION_DOMAIN_BYTES {
        return false;
    }
    let Some((kind, id)) = domain.split_once(':') else {
        return false;
    };
    matches!(
        kind,
        "network" | "power" | "clock" | "host" | "model" | "calibration" | "replay"
    ) && !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_:.-".contains(&byte))
}

fn bounded_count(value: u64, maximum: usize) -> Result<usize> {
    usize::try_from(value)
        .ok()
        .filter(|count| *count <= maximum)
        .ok_or(CorroborationError::Limit)
}

fn encode_strings(encoder: &mut CanonicalEncoder, values: &[String]) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn strings_json(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| json_string(value))
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Source-bound decomposition for one plan camera. `failure_domains` always includes its intrinsic
/// sensor identity; `support_domain` is the complete transitive component used by event policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraFailureDomains {
    /// Local plan camera label.
    pub camera: String,
    /// Retained sensor identity digest.
    pub sensor_digest: ContentDigest,
    /// Retained import identity.
    pub import_identity: ContentDigest,
    /// Retained source root.
    pub import_root: ContentDigest,
    /// Sorted intrinsic and declared causes.
    pub failure_domains: Vec<String>,
    /// One canonical domain for all observations in the connected component.
    pub support_domain: String,
}

/// A connected common-cause component. It is a conservative dependency group, not a measured
/// probability model or a certificate that other components are physically independent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorroborationDependencyCluster {
    /// Canonical support-domain identifier.
    pub support_domain: String,
    /// Sorted plan camera labels in this component.
    pub cameras: Vec<String>,
    /// Union of the component's intrinsic and declared causes.
    pub failure_domains: Vec<String>,
}

/// Rebuildable common-cause assessment over exact retained camera sources. Declaration and source
/// ordering do not affect its bytes. The report never upgrades an owner assertion to verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorroborationDependencyReport {
    declarations: CorroborationDependencies,
    cameras: Vec<CameraFailureDomains>,
    clusters: Vec<CorroborationDependencyCluster>,
    bytes: Vec<u8>,
}

impl CorroborationDependencyReport {
    pub(super) fn build(
        declarations: &CorroborationDependencies,
        cameras: &[CameraSummary],
    ) -> Result<Self> {
        Self::from_sources(
            declarations,
            cameras
                .iter()
                .map(|camera| CameraFailureDomains {
                    camera: camera.name.clone(),
                    sensor_digest: camera.sensor_digest,
                    import_identity: camera.import_identity,
                    import_root: camera.import_root,
                    failure_domains: Vec::new(),
                    support_domain: String::new(),
                })
                .collect(),
        )
    }

    fn from_sources(
        declarations: &CorroborationDependencies,
        mut cameras: Vec<CameraFailureDomains>,
    ) -> Result<Self> {
        declarations.validate_cameras(
            &cameras
                .iter()
                .map(|camera| camera.camera.clone())
                .collect::<Vec<_>>(),
        )?;
        cameras.sort_by(|left, right| left.camera.cmp(&right.camera));
        let mut roots: Vec<usize> = (0..cameras.len()).collect();
        for camera in &mut cameras {
            camera.failure_domains = vec![format!("recorded-sensor:{}", hex(camera.sensor_digest))];
            camera.failure_domains.extend(
                declarations
                    .declarations
                    .iter()
                    .filter(|declaration| declaration.cameras.binary_search(&camera.camera).is_ok())
                    .map(|declaration| declaration.domain.clone()),
            );
            camera.failure_domains.sort();
        }
        // At most eight cameras and 33 causes each. This bounded reference contracts overlap
        // transitively; a bridge camera cannot let either end self-corroborate as a fresh domain.
        for left in 0..cameras.len() {
            for right in left + 1..cameras.len() {
                if cameras[left]
                    .failure_domains
                    .iter()
                    .any(|domain| cameras[right].failure_domains.binary_search(domain).is_ok())
                {
                    let (a, b) = (roots[left], roots[right]);
                    let root = a.min(b);
                    for value in &mut roots {
                        if *value == a || *value == b {
                            *value = root;
                        }
                    }
                }
            }
        }
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (index, root) in roots.into_iter().enumerate() {
            groups.entry(root).or_default().push(index);
        }
        let mut clusters = Vec::with_capacity(groups.len());
        for members in groups.values() {
            let domains: Vec<String> = members
                .iter()
                .flat_map(|index| cameras[*index].failure_domains.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let support_domain = if declarations.is_empty() {
                // Exact pre-declaration event compatibility. Duplicate sensor identities still
                // share this intrinsic domain, regardless of their camera labels.
                domains[0].clone()
            } else {
                let mut encoder = CanonicalEncoder::new();
                encoder.text(CLUSTER_DOMAIN);
                encode_strings(&mut encoder, &domains);
                format!(
                    "recorded-cluster:{}",
                    hex(ContentDigest::sha256(&encoder.finish_checked()?))
                )
            };
            for index in members {
                cameras[*index].support_domain = support_domain.clone();
            }
            clusters.push(CorroborationDependencyCluster {
                support_domain,
                cameras: members
                    .iter()
                    .map(|index| cameras[*index].camera.clone())
                    .collect(),
                failure_domains: domains,
            });
        }
        clusters.sort_by(|left, right| left.support_domain.cmp(&right.support_domain));
        let mut encoder = CanonicalEncoder::new();
        encoder.text(ASSESSMENT_DOMAIN);
        encoder.bytes(&declarations.to_bytes());
        encoder.u64(cameras.len() as u64);
        for camera in &cameras {
            encoder.text(&camera.camera);
            encoder.digest(camera.sensor_digest);
            encoder.digest(camera.import_identity);
            encoder.digest(camera.import_root);
            encode_strings(&mut encoder, &camera.failure_domains);
            encoder.text(&camera.support_domain);
        }
        encoder.u64(clusters.len() as u64);
        for cluster in &clusters {
            encoder.text(&cluster.support_domain);
            encode_strings(&mut encoder, &cluster.cameras);
            encode_strings(&mut encoder, &cluster.failure_domains);
        }
        let bytes = encoder.finish_checked()?;
        if bytes.len() > MAX_CORROBORATION_DEPENDENCY_BYTES {
            return Err(CorroborationError::Limit);
        }
        Ok(Self {
            declarations: declarations.clone(),
            cameras,
            clusters,
            bytes,
        })
    }

    /// Exact owner declaration generation.
    #[must_use]
    pub fn declarations(&self) -> &CorroborationDependencies {
        &self.declarations
    }
    /// Source-bound per-camera domains, sorted by camera label.
    #[must_use]
    pub fn cameras(&self) -> &[CameraFailureDomains] {
        &self.cameras
    }
    /// Complete transitive dependency components.
    #[must_use]
    pub fn clusters(&self) -> &[CorroborationDependencyCluster] {
        &self.clusters
    }
    /// Exact source-bound assessment digest, distinct from the declaration-only generation.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.bytes)
    }
    /// Complete bounded canonical assessment, retained before publication when declarations exist.
    #[must_use]
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstructs all components and requires exact bytes; supplied domain/cluster claims are
    /// never accepted without recomputation. Custody/source authority remains the caller's check.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CORROBORATION_DEPENDENCY_BYTES {
            return Err(CorroborationError::Limit);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != ASSESSMENT_DOMAIN {
            return Err(CorroborationError::InvalidPlan(
                "unknown dependency assessment",
            ));
        }
        let declarations = CorroborationDependencies::from_bytes(decoder.bytes()?)?;
        let count = bounded_count(decoder.u64()?, MAX_CORROBORATION_DOMAIN_CAMERAS)?;
        let mut cameras = Vec::with_capacity(count);
        for _ in 0..count {
            let camera = decoder.text()?.to_owned();
            let sensor_digest = decoder.digest()?;
            let import_identity = decoder.digest()?;
            let import_root = decoder.digest()?;
            let count = bounded_count(decoder.u64()?, MAX_CORROBORATION_FAILURE_DOMAINS + 1)?;
            for _ in 0..count {
                decoder.text()?;
            }
            decoder.text()?;
            cameras.push(CameraFailureDomains {
                camera,
                sensor_digest,
                import_identity,
                import_root,
                failure_domains: Vec::new(),
                support_domain: String::new(),
            });
        }
        // The remaining component table is verified by exact reconstruction, never trusted or
        // allocated from its asserted counts. This also refuses trailing or truncated bytes.
        let value = Self::from_sources(&declarations, cameras)?;
        if value.to_bytes() != bytes {
            return Err(CorroborationError::InvalidPlan(
                "dependency assessment does not rederive",
            ));
        }
        Ok(value)
    }

    pub(super) fn support_domain(&self, camera: &str) -> Result<&str> {
        self.cameras
            .iter()
            .find(|value| value.camera == camera)
            .map(|value| value.support_domain.as_str())
            .ok_or(CorroborationError::Limit)
    }

    /// Canonical individual cause records for composition with cross-event sensor-integrity
    /// dependencies. Records stay in sorted domain order and confer no event authority.
    pub(super) fn cause_records(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let domains: BTreeSet<&String> = self
            .cameras
            .iter()
            .flat_map(|camera| &camera.failure_domains)
            .collect();
        let mut result = Vec::with_capacity(domains.len());
        for domain in domains {
            let mut encoder = CanonicalEncoder::new();
            encoder.text(EDGE_DOMAIN);
            encoder.digest(self.digest());
            encoder.text(domain);
            let bytes = encoder.finish_checked()?;
            result.push((domain.clone(), bytes));
        }
        Ok(result)
    }

    /// Bounded explanatory JSON. The component count is conditional on declared causes and never
    /// establishes calibrated independence, live health or effect authority.
    #[must_use]
    pub fn to_json(&self) -> String {
        let declarations = self
            .declarations
            .declarations
            .iter()
            .map(|value| {
                format!(
                    "{{\"domain\":{},\"cameras\":{}}}",
                    json_string(&value.domain),
                    strings_json(&value.cameras)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let cameras = self.cameras.iter().map(|value| format!(
            "{{\"camera\":{},\"sensor_digest\":\"{}\",\"import_identity\":\"{}\",\"import_root\":\"{}\",\"failure_domains\":{},\"support_domain\":{}}}",
            json_string(&value.camera), value.sensor_digest, value.import_identity, value.import_root,
            strings_json(&value.failure_domains), json_string(&value.support_domain)
        )).collect::<Vec<_>>().join(",");
        let clusters = self
            .clusters
            .iter()
            .map(|value| {
                format!(
                    "{{\"support_domain\":{},\"cameras\":{},\"failure_domains\":{}}}",
                    json_string(&value.support_domain),
                    strings_json(&value.cameras),
                    strings_json(&value.failure_domains)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{\"generation\":\"{}\",\"assessment_digest\":\"{}\",\"basis\":\"{}\",",
                "\"model\":\"transitive_shared_cause_components_v1\",\"declarations\":[{}],",
                "\"cameras\":[{}],\"clusters\":[{}],\"dependency_cluster_count\":{},",
                "\"independence\":\"unknown\",\"undeclared_dependencies\":\"unknown_not_absent\",",
                "\"independence_certified\":false}}"
            ),
            self.declarations.digest(),
            self.digest(),
            if self.declarations.is_empty() {
                "sensor_only_assumption"
            } else {
                "owner_assertion_not_verified_topology"
            },
            declarations,
            cameras,
            clusters,
            self.clusters.len()
        )
    }
}

#[cfg(test)]
mod tests;
