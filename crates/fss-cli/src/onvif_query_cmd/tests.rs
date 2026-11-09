#![forbid(unsafe_code)]
//! Closed grammar, semantic policy identity and genuine retained-source query rendering.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    CaptureInterval, ContextAuthority, OperationId, RootAuthoritySpec, SensorId, TimestampNs,
};
use fss_reference::onvif::metadata::{SourceBinding, retain};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::*;
use crate::{FssCommand, parse_fss_args};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:canonical-onvif-query";
const PRIVATE_MODULE: &str = "private-query-module-canary";
const PRIVATE_ID: &str = "8675309";

fn selector(pins: &[TrackSourcePin]) -> String {
    format!(
        "[{}]",
        pins.iter()
            .map(|pin| format!(
                r#"{{"kind":"{}","identity":"{}","root":"{}"}}"#,
                pin.kind(),
                pin.identity(),
                pin.root()
            ))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn pins() -> Vec<TrackSourcePin> {
    vec![
        TrackSourcePin::Xml {
            identity: ContentDigest::sha256(b"source-xml"),
            root: ContentDigest::sha256(b"root-xml"),
        },
        TrackSourcePin::Rtp {
            identity: ContentDigest::sha256(b"source-rtp"),
            root: ContentDigest::sha256(b"root-rtp"),
        },
    ]
}

fn parse(
    root: &Path,
    analysis: &str,
    sources: &str,
    extra: &[(&str, &str)],
) -> Result<OnvifQueryArgs, CliError> {
    let mut args: Vec<OsString> = vec![
        "query".into(),
        "--json".into(),
        "--root".into(),
        root.into(),
        "--target=onvif".into(),
        format!("--analysis={analysis}").into(),
        format!("--sources={sources}").into(),
    ];
    args.extend(
        extra
            .iter()
            .map(|(name, value)| format!("{name}={value}").into()),
    );
    let command = parse_fss_args(args)?;
    if let FssCommand::OnvifQuery(args) = command {
        Ok(args)
    } else {
        Err(malformed("--target", "wrong test command", 0))
    }
}

fn policy() -> String {
    let pin = ContentDigest::sha256(b"coordinate-domain");
    format!(
        r#"{{"schema":"fss.onvif_vendor_zone_policy.v1","coordinates":"raw_vendor_object_millionths","zones":[{{"id":"entry","scope":"{pin}","module_digest":"{pin}","frame_transform_digest":"{pin}","object_transform_digest":"{pin}","min":[-1000000000000000,-1],"max":[1000000000000000,1],"margin":0}}]}}"#
    )
}

#[test]
fn canonical_onvif_parser_preserves_order_scope_and_semantic_policy() -> Test {
    let pins = pins();
    let text = selector(&pins);
    let root = Path::new("/owner/deployment");
    let args = parse(
        root,
        "tracks",
        &text,
        &[("--principal", "principal:onvif"), ("--max-entries", "7")],
    )?;
    assert_eq!(args.root, root);
    assert_eq!(args.request.sources, pins);
    assert_eq!(args.request.max_entries, 7);
    assert_eq!(args.request.principal.as_str(), "principal:onvif");
    assert_eq!(args.request.analysis, OnvifAnalysis::Tracks);
    let reversed = selector(&pins.iter().copied().rev().collect::<Vec<_>>());
    assert_ne!(
        parse(root, "tracks", &reversed, &[])?.request.sources,
        args.request.sources
    );
    assert_eq!(
        parse(root, "lifecycle", &text, &[])?.request.analysis,
        OnvifAnalysis::Lifecycle
    );
    let policy = policy();
    let pretty = policy.replace(',', ",\n ").replace('{', "{\n ");
    let compact = parse(root, "zones", &text, &[("--zone-policy", &policy)])?;
    let spaced = parse(root, "zones", &text, &[("--zone-policy", &pretty)])?;
    assert_eq!(compact, spaced);
    let OnvifAnalysis::Zones(policy) = compact.request.analysis else {
        return Err("zone analysis expected".into());
    };
    assert_eq!(policy.zones[0].min[0], -1_000_000_000_000_000);
    assert_eq!(policy.zones[0].max[0], 1_000_000_000_000_000);
    Ok(())
}

#[test]
fn canonical_onvif_parser_refuses_ambiguity_disclosure_and_file_indirection() {
    let root = Path::new("/owner/deployment");
    let sources = selector(&pins());
    for extra in [
        vec![("--event-id", "event:other")],
        vec![("--sensor", "sensor:other")],
        vec![("--archive-root", "/outside")],
        vec![("--at", "latest")],
        vec![("--continuation", "cursor:any")],
        vec![("--include-values", "yes")],
        vec![("--hydrate", "H3")],
        vec![("--approve", "yes")],
        vec![("--max-entries", "0")],
        vec![("--max-entries", "33")],
        vec![("--max-entries", "+1")],
        vec![("--max-entries", "01")],
        vec![("--max-entries", "1.0")],
        vec![("--anchor", "latest")],
        vec![("--analysis", "tracks")],
        vec![("--zone-policy", "{}")],
    ] {
        assert!(
            parse(root, "tracks", &sources, &extra).is_err(),
            "accepted {extra:?}"
        );
    }
    for invalid in [
        "[]",
        "{}",
        "null",
        "/private/sources.json",
        "-",
        "[{}]",
        "[{\"kind\":\"xml\",\"kind\":\"rtp\"}]",
    ] {
        assert!(parse(root, "tracks", invalid, &[]).is_err());
    }
    let duplicate = selector(&[pins()[0], pins()[0]]);
    assert!(parse(root, "tracks", &duplicate, &[]).is_err());
    assert!(parse(root, "zones", &sources, &[]).is_err());
    assert!(
        parse(
            root,
            "zones",
            &sources,
            &[("--zone-policy", "/private/policy.json")]
        )
        .is_err()
    );
    assert!(parse(root, "zones", &sources, &[("--zone-policy", "-")]).is_err());
    assert!(parse(root, "future", &sources, &[]).is_err());
    let invalid = format!(
        "[{{\"private-query-input-canary\":\"{}\"}}]",
        "x".repeat(512)
    );
    let error = parse(root, "tracks", &invalid, &[]).err();
    assert!(
        error.is_some_and(|error| !format!("{error:?}").contains("private-query-input-canary"))
    );
}

#[test]
fn other_query_targets_refuse_onvif_selectors() {
    for target in ["events", "footage", "recordings"] {
        assert!(
            parse_fss_args(
                [
                    "query",
                    "--json",
                    "--root",
                    "/owner/deployment",
                    "--target",
                    target,
                    "--analysis",
                    "tracks"
                ]
                .into_iter()
                .map(OsString::from)
            )
            .is_err()
        );
        assert!(
            parse_fss_args(
                [
                    "query",
                    "--json",
                    "--root",
                    "/owner/deployment",
                    "--target",
                    target,
                    "--sources",
                    "[]"
                ]
                .into_iter()
                .map(OsString::from)
            )
            .is_err()
        );
    }
}

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let root = std::env::temp_dir().join(format!(
                "fss-onvif-query-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture directory capacity".into())
    }
    fn source(&self) -> Test<TrackSourcePin> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:canonical-onvif-query".to_owned(),
            operation_id: OperationId::parse("operation:canonical-onvif-query")?,
            principal: "operator:canonical-onvif-query".to_owned(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(128 * 1024 * 1024)
                .storage_operations(16_384)
                .build()?,
            privacy_scope: "privacy:fixture".to_owned(),
            retention_scope: "retention:fixture".to_owned(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, &self.0)?;
        let mut deployment = ReferenceDeployment::open(&self.0, SITE, &cx)?;
        let source = retain(&mut deployment, SourceBinding {
            sensor_id: SensorId::parse("sensor:front")?, device_generation: ContentDigest::sha256(b"device"),
            profile_generation: ContentDigest::sha256(b"profile"), profile_token: "private-query-profile-canary".to_owned(),
            receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
        }, format!(r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics><t:Frame UtcTime="2026-10-28T00:00:01Z" Source="{PRIVATE_MODULE}"><t:Object ObjectId="{PRIVATE_ID}"><t:Appearance><t:Shape><t:BoundingBox left="0.1" right="0.2" top="0.2" bottom="0.1"/><t:CenterOfGravity x="0.15" y="0.15"/></t:Shape></t:Appearance></t:Object></t:Frame><t:Frame UtcTime="2026-10-28T00:00:02Z" Source="{PRIVATE_MODULE}"><t:Object ObjectId="{PRIVATE_ID}"><t:Appearance><t:Shape><t:BoundingBox left="0.3" right="0.4" top="0.4" bottom="0.3"/><t:CenterOfGravity x="0.35" y="0.35"/></t:Shape></t:Appearance></t:Object></t:Frame></t:VideoAnalytics></t:MetadataStream>"#).as_bytes(), &cx)?;
        Ok(TrackSourcePin::Xml {
            identity: source.identity(),
            root: source.publication_root(),
        })
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, here: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) -> Test {
        for entry in fs::read_dir(here)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                visit(root, &path, output)?;
            } else if entry.file_type()?.is_file() {
                output.insert(path.strip_prefix(root)?.to_owned(), fs::read(path)?);
            } else {
                return Err("unexpected fixture filesystem kind".into());
            }
        }
        Ok(())
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output)?;
    Ok(output)
}

#[test]
fn native_tracks_and_lifecycle_return_same_redacted_envelopes_without_writes() -> Test {
    let dir = Directory::new("native")?;
    let pin = dir.source()?;
    let sources = selector(&[pin]);
    let before = tree(&dir.0)?;
    for analysis in ["tracks", "lifecycle"] {
        let args = parse(&dir.0, analysis, &sources, &[])?;
        let (output, exit) = execute_onvif_query(&args);
        assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
        assert!(json_input::parse(&output).is_ok());
        assert!(output.contains("fss.agent_response_envelope.v1"));
        assert!(output.contains("fss.agent_cognitive_envelope.v1"));
        assert!(output.contains("AOP-005"));
        assert!(output.contains(&pin.root().to_text()));
        assert!(output.contains("physical-observability"));
        for private in [
            PRIVATE_MODULE,
            PRIVATE_ID,
            "2026-10-28T",
            "private-query-profile-canary",
            "<t:",
        ] {
            assert!(!output.contains(private), "vendor value leaked: {private}");
        }
        assert_eq!((output, exit), execute_onvif_query(&args));
    }
    assert_eq!(before, tree(&dir.0)?);
    Ok(())
}

#[test]
fn native_zones_keep_unknown_rows_and_whole_result_limits() -> Test {
    let dir = Directory::new("zones")?;
    let pin = dir.source()?;
    let sources = selector(&[pin]);
    // A deliberately mismatched coordinate-domain policy must expose every unavailable
    // matrix cell, rather than reporting outside or silently discarding the observations.
    let policy = policy();
    let args = parse(&dir.0, "zones", &sources, &[("--zone-policy", &policy)])?;
    let before = tree(&dir.0)?;
    let (output, exit) = execute_onvif_query(&args);
    assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
    assert!(output.contains("scope_mismatch"));
    assert!(output.contains("not_observable"));
    assert!(output.contains("raw_vendor_object_millionths"));
    assert!(output.contains("zone-cell:0") && output.contains("zone-cell:1"));
    assert!(!output.contains(PRIVATE_MODULE));
    let small = parse(
        &dir.0,
        "zones",
        &sources,
        &[("--zone-policy", &policy), ("--max-entries", "1")],
    )?;
    let (refused, exit) = execute_onvif_query(&small);
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert!(!refused.contains("zone-cell:"));
    assert_eq!(before, tree(&dir.0)?);
    Ok(())
}
