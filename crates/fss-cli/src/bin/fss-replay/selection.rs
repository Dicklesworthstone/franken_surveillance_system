#![forbid(unsafe_code)]
//! Explicit current privacy authority and independently retained original prefix selection.
//! Neither source scope nor sensor identity can be supplied to replace committed history.
use super::*;
use fss_reference::ingest::http_archive::HttpWirePin;

#[derive(Debug, Default)]
pub(super) struct Selection {
    privacy: Option<(PathBuf, String)>,
    wire: Option<(ContentDigest, u64, u64)>,
}
impl Selection {
    pub(super) fn parse(values: &BTreeMap<&str, &OsStr>) -> Result<Self, String> {
        let text = |key: &str| {
            values
                .get(key)
                .and_then(|v| v.to_str())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("missing UTF-8 {key}"))
        };
        let privacy = match (values.get("--privacy-root"), values.get("--privacy-site")) {
            (None, None) => None,
            (Some(path), Some(_)) => {
                let path = PathBuf::from(*path);
                let site = text("--privacy-site")?.to_owned();
                if !path.is_absolute() || site.len() > 256 {
                    return Err("privacy root must be absolute and site bounded".into());
                }
                fss_reference::reference_deployment::validate_site_lineage(&site)
                    .map_err(|_| "invalid privacy site")?;
                Some((path, site))
            }
            _ => return Err("--privacy-root and --privacy-site are required together".into()),
        };
        let keys = ["--wire-head", "--wire-reads", "--wire-bytes"];
        let present = keys.iter().filter(|key| values.contains_key(**key)).count();
        let wire = match present {
            0 => None,
            3 => {
                let head =
                    ContentDigest::parse(text("--wire-head")?).map_err(|_| "invalid wire head")?;
                if head.algorithm() != DigestAlgorithm::Sha256 || head.bytes() == [0; 32] {
                    return Err("nonzero SHA-256 wire head required".into());
                }
                let integer = |key: &str, maximum: u64| -> Result<u64, String> {
                    let s = text(key)?;
                    if !s.bytes().all(|b| b.is_ascii_digit()) {
                        return Err("unsigned wire count required".into());
                    }
                    let n: u64 = s.parse().map_err(|_| "wire count overflow")?;
                    if n == 0 || n > maximum {
                        return Err("wire count outside native bounds".into());
                    }
                    Ok(n)
                };
                Some((
                    head,
                    integer("--wire-reads", 4096)?,
                    integer("--wire-bytes", 256 * 1024 * 1024)?,
                ))
            }
            _ => {
                return Err(
                    "--wire-head, --wire-reads and --wire-bytes are required together".into(),
                );
            }
        };
        Ok(Self { privacy, wire })
    }

    /// The source scope is recovered from the committed configuration, never an operator flag.
    pub(super) fn wire_tip(&self, scope: ContentDigest) -> Option<HttpWirePin> {
        self.wire.map(|(head, reads, bytes)| HttpWirePin {
            scope,
            head,
            reads,
            bytes,
        })
    }

    pub(super) fn open_privacy(
        &self,
        history_root: &Path,
        original_root: Option<&Path>,
        principal: &str,
        clock: &Clock,
    ) -> Run<Option<PrivacyOwner>> {
        let Some((path, site)) = &self.privacy else {
            return Ok(None);
        };
        if !clock.alive() {
            return Err(ReplayError::Denied.into());
        }
        let root = existing_deployment(path)?;
        if overlap(&root, history_root) || original_root.is_some_and(|p| overlap(&root, p)) {
            return Err(failure(
                "external privacy, history and original stores must not overlap",
            ));
        }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:http-rgb-replay-privacy-cli".into(),
            operation_id: OperationId::parse("operation:http-rgb-replay-privacy-cli")?,
            principal: principal.to_owned(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(1024 * 1024 * 1024)
                .storage_operations(1_000_000)
                .build()?,
            privacy_scope: "privacy:owner-selected-current-policy".into(),
            retention_scope: "retention:read-existing-no-mutation".into(),
            anchor_universe: ContentDigest::sha256(site.as_bytes()),
            generation: 1,
        })?;
        authority.validate()?;
        let cx = ScopedContext(ReplayCx::from_context_authority(&authority, root.clone())?);
        if !clock.alive() {
            return Err(ReplayError::Denied.into());
        }
        let deployment = ReferenceDeployment::reopen(&root, site, &cx.0)?;
        if !clock.alive() {
            return Err(ReplayError::Denied.into());
        }
        Ok(Some(PrivacyOwner {
            deployment,
            _context: cx,
        }))
    }
}
fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
struct ScopedContext(ReplayCx);
impl Drop for ScopedContext {
    fn drop(&mut self) {
        self.0.drain_and_finalize();
    }
}
pub(super) struct PrivacyOwner {
    pub(super) deployment: ReferenceDeployment,
    _context: ScopedContext,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn values<'a>(pairs: &'a [(&'a str, &'a str)]) -> BTreeMap<&'a str, &'a OsStr> {
        pairs.iter().map(|(k, v)| (*k, OsStr::new(v))).collect()
    }
    #[test]
    fn default_neither_infers_external_policy_nor_follows_newer_source() -> Result<(), String> {
        let selection = Selection::parse(&BTreeMap::new())?;
        assert!(selection.privacy.is_none());
        assert!(
            selection
                .wire_tip(ContentDigest::sha256(b"scope"))
                .is_none()
        );
        Ok(())
    }
    #[test]
    fn external_privacy_selection_is_complete_and_bounded() -> Result<(), String> {
        for p in [
            vec![("--privacy-root", "/policy")],
            vec![("--privacy-site", "site:policy")],
            vec![
                ("--privacy-root", "relative"),
                ("--privacy-site", "site:policy"),
            ],
        ] {
            assert!(Selection::parse(&values(&p)).is_err());
        }
        let s = Selection::parse(&values(&[
            ("--privacy-root", "/policy"),
            ("--privacy-site", "site:policy"),
        ]))?;
        assert_eq!(
            s.privacy,
            Some((PathBuf::from("/policy"), "site:policy".into()))
        );
        Ok(())
    }
    #[test]
    fn original_tip_requires_all_fields_and_inherits_only_committed_scope() -> Result<(), String> {
        let head = ContentDigest::sha256(b"wire");
        let text = head.to_text();
        let all = [
            ("--wire-head", text.as_str()),
            ("--wire-reads", "2"),
            ("--wire-bytes", "800"),
        ];
        for omitted in 0..all.len() {
            let subset: Vec<_> = all
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != omitted)
                .map(|(_, p)| *p)
                .collect();
            assert!(Selection::parse(&values(&subset)).is_err());
        }
        let s = Selection::parse(&values(&all))?;
        let scope = ContentDigest::sha256(b"committed source scope");
        assert_eq!(
            s.wire_tip(scope),
            Some(HttpWirePin {
                scope,
                head,
                reads: 2,
                bytes: 800
            })
        );
        Ok(())
    }
    #[test]
    fn malformed_or_oversized_original_counts_never_become_a_pin() {
        let head = ContentDigest::sha256(b"wire").to_text();
        for (reads, bytes) in [
            ("0", "10"),
            ("4097", "10"),
            ("1", "268435457"),
            ("-1", "10"),
            ("1", "0"),
            ("1", "18446744073709551616"),
        ] {
            assert!(
                Selection::parse(&values(&[
                    ("--wire-head", &head),
                    ("--wire-reads", reads),
                    ("--wire-bytes", bytes)
                ]))
                .is_err()
            );
        }
    }
    #[test]
    fn overlap_is_component_based_and_symmetric() {
        for (a, b) in [
            ("/data", "/data"),
            ("/data", "/data/policy"),
            ("/data/policy", "/data"),
        ] {
            assert!(overlap(Path::new(a), Path::new(b)));
        }
        assert!(!overlap(Path::new("/data"), Path::new("/data-other")));
    }
    #[test]
    fn metadata_inspection_cannot_request_external_disclosure() {
        for (key, value) in [("--privacy-root", "/policy"), ("--wire-reads", "2")] {
            let d = ContentDigest::sha256(b"session").to_text();
            let args: Vec<_> = [
                "inspect-http-rgb",
                "--root",
                "/history",
                "--site",
                "site:test",
                "--session",
                &d,
                key,
                value,
            ]
            .into_iter()
            .map(OsString::from)
            .collect();
            assert!(super::super::parse(&args).is_err());
        }
    }
}
