#![forbid(unsafe_code)]
//! Actual-process import -> source-pinned vendor-zone reports and complete refusal contracts.
//! These fixtures establish no calibrated geometry, physical identity or coverage.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fss_core::{
    ContentDigest,
    json_input::{Value, parse},
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const SITE: &str = "site:onvif-zones-cli";
const PRIVATE_MODULE: &str = "private\"zone-module\\canary";
const PRIVATE_OBJECT: &str = "910000011";
const OPERATOR_ZONE: &str = "operator_entrance";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-zones-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture-directory capacity".into())
    }

    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Test<PathBuf> {
    std::env::var_os("FSS_ONVIF_METADATA_BIN")
        .or_else(|| option_env!("CARGO_BIN_EXE_fss-onvif-metadata").map(OsString::from))
        .map(PathBuf::from)
        .ok_or_else(|| "missing metadata binary; set FSS_ONVIF_METADATA_BIN".into())
}

fn read_output(reader: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(io::Error::other("fixture output exceeded bound"));
    }
    Ok(bytes)
}

fn run(args: &[OsString]) -> Test<Output> {
    let mut child = Command::new(binary()?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("stdout pipe")?;
    let stderr = child.stderr.take().ok_or("stderr pipe")?;
    thread::scope(|scope| {
        let stdout = scope.spawn(move || read_output(stdout));
        let stderr = scope.spawn(move || read_output(stderr));
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("zone fixture command timed out".into());
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error.into());
                }
            }
        };
        Ok(Output {
            status,
            stdout: stdout.join().map_err(|_| "stdout thread")??,
            stderr: stderr.join().map_err(|_| "stderr thread")??,
        })
    })
}

fn success(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn refusal(output: Output) {
    assert!(!output.status.success(), "unexpected successful command");
    assert!(
        output.stdout.is_empty(),
        "refusal emitted partial JSON: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn line<'a>(output: &'a str, name: &str) -> Test<&'a str> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(field, value)| (field == name).then_some(value))
        .ok_or_else(|| format!("missing receipt field {name}").into())
}

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("missing JSON field {name}").into())
}

fn text<'a>(value: &'a Value, name: &str) -> Test<&'a str> {
    field(value, name)?
        .text()
        .ok_or_else(|| format!("not JSON text: {name}").into())
}

fn list<'a>(value: &'a Value, name: &str) -> Test<&'a [Value]> {
    field(value, name)?
        .array()
        .ok_or_else(|| format!("not a JSON array: {name}").into())
}

fn object(bounds: [&str; 4]) -> String {
    format!(
        r#"<t:Object ObjectId="{PRIVATE_OBJECT}"><t:Appearance><t:Shape><t:BoundingBox left="{}" right="{}" top="{}" bottom="{}"/><t:CenterOfGravity x="0.5" y="0.5"/></t:Shape></t:Appearance></t:Object>"#,
        bounds[0], bounds[1], bounds[2], bounds[3]
    )
}

fn frame(second: u8, object: &str) -> String {
    format!(
        r#"<t:Frame UtcTime="2026-11-09T00:00:{second:02}Z" Source="private&quot;zone-module\canary">{object}</t:Frame>"#
    )
}

fn xml() -> Vec<u8> {
    let frames = frame(0, &object(["2", "3", ".2", ".4"]))
        + &frame(1, &object([".2", ".4", ".2", ".4"]))
        + &frame(2, &object([".8", "1.2", ".2", ".4"]))
        + &frame(
            3,
            &format!(r#"<t:Object ObjectId="{PRIVATE_OBJECT}"><t:Appearance/></t:Object>"#),
        );
    format!(
        r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics>{frames}</t:VideoAnalytics></t:MetadataStream>"#
    )
    .into_bytes()
}

fn import_args(root: &Path, input: &Path) -> Vec<OsString> {
    vec![
        "import".into(),
        "--root".into(),
        root.into(),
        "--site".into(),
        SITE.into(),
        "--input".into(),
        input.into(),
        "--sensor".into(),
        "sensor:front".into(),
        "--device-generation".into(),
        ContentDigest::sha256(b"zone-device").to_text().into(),
        "--profile-generation".into(),
        ContentDigest::sha256(b"zone-profile").to_text().into(),
        "--profile".into(),
        "private-zone-profile-canary".into(),
        "--received-start-ns".into(),
        "100".into(),
        "--received-end-ns".into(),
        "110".into(),
    ]
}

fn tracks_args(root: &Path, receipt: &str) -> Test<Vec<OsString>> {
    Ok(vec![
        "tracks".into(),
        "--root".into(),
        root.into(),
        "--site".into(),
        SITE.into(),
        "--xml-source".into(),
        format!(
            "{}@{}",
            line(receipt, "import_identity")?,
            line(receipt, "publication_root")?
        )
        .into(),
    ])
}

#[derive(Clone)]
struct DomainPins {
    scope: String,
    module: String,
    frame_transform: String,
    object_transform: String,
}
impl DomainPins {
    fn from_tracks(tracks: &Value) -> Test<Self> {
        let frame = list(tracks, "frames")?.first().ok_or("fixture frame")?;
        let occurrence = list(tracks, "occurrences")?
            .first()
            .ok_or("fixture occurrence")?;
        Ok(Self {
            scope: text(frame, "scope")?.to_owned(),
            module: text(frame, "module_digest")?.to_owned(),
            frame_transform: text(frame, "transformation_digest")?.to_owned(),
            object_transform: text(occurrence, "transformation_digest")?.to_owned(),
        })
    }

    fn json(&self) -> String {
        format!(
            r#"{{"schema":"fss.onvif_vendor_zone_policy.v1","coordinates":"raw_vendor_object_millionths","zones":[{{"id":"{OPERATOR_ZONE}","scope":"{}","module_digest":"{}","frame_transform_digest":"{}","object_transform_digest":"{}","min":[0,0],"max":[1000000,1000000],"margin":0}}]}}"#,
            self.scope, self.module, self.frame_transform, self.object_transform
        )
    }
}

struct Fixture {
    directory: Directory,
    receipt: String,
    source_digest: ContentDigest,
    original: Value,
    pins: DomainPins,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let input = directory.0.join("source.xml");
        let source = xml();
        fs::write(&input, &source)?;
        let receipt = success(run(&import_args(&directory.root(), &input))?)?;
        fs::remove_file(input)?;
        let original = parse(&success(run(&tracks_args(&directory.root(), &receipt)?)?)?)?;
        let pins = DomainPins::from_tracks(&original)?;
        Ok(Self {
            directory,
            receipt,
            source_digest: ContentDigest::sha256(&source),
            original,
            pins,
        })
    }

    fn policy(&self, name: &str, content: &str) -> Test<PathBuf> {
        let path = self.directory.0.join(name);
        assert!(path.is_absolute());
        fs::write(&path, content)?;
        Ok(path)
    }

    fn args(&self, policy: &Path) -> Test<Vec<OsString>> {
        let mut args = tracks_args(&self.directory.root(), &self.receipt)?;
        args[0] = "zones".into();
        args.extend(["--policy".into(), policy.into()]);
        Ok(args)
    }
}

fn original_is_unchanged(report: &Value, original: &Value) -> Test {
    let tracks = field(report, "tracklets")?;
    for key in [
        "report_digest",
        "sources",
        "frames",
        "occurrences",
        "tracklets",
    ] {
        assert_eq!(field(tracks, key)?, field(original, key)?);
    }
    assert_eq!(
        field(field(report, "analysis")?, "tracklet_report_digest")?,
        field(original, "report_digest")?
    );
    Ok(())
}

#[test]
fn retained_xml_to_zones_preserves_originals_transitions_and_exact_policy_bytes() -> Test {
    let fixture = Fixture::new("source-and-policy")?;
    let policy_text = fixture.pins.json();
    let policy_path = fixture.policy("policy.json", &policy_text)?;
    let args = fixture.args(&policy_path)?;
    let output = success(run(&args)?)?;
    let report = parse(&output)?;
    assert_eq!(text(&report, "schema")?, "fss.onvif_vendor_zones_report.v1");
    original_is_unchanged(&report, &fixture.original)?;
    let tracks = field(&report, "tracklets")?;
    let runs = list(tracks, "tracklets")?;
    assert_eq!(runs.len(), 1);
    let source = &list(tracks, "sources")?[0];
    assert_eq!(
        text(source, "identity")?,
        line(&fixture.receipt, "import_identity")?
    );
    assert_eq!(
        text(source, "root")?,
        line(&fixture.receipt, "publication_root")?
    );
    assert_eq!(
        text(source, "source_digest")?,
        fixture.source_digest.to_text()
    );
    let analysis = field(&report, "analysis")?;
    assert_eq!(
        text(analysis, "coordinates")?,
        "raw_vendor_object_millionths"
    );
    assert_eq!(
        field(analysis, "coordinate_scale")?.integer(),
        Some(1_000_000)
    );
    let cells = list(analysis, "cells")?;
    assert_eq!(cells.len(), 4);
    for (index, expected) in ["outside", "inside", "boundary", "unavailable"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(text(&cells[index], "relation")?, expected);
        assert_eq!(
            field(&cells[index], "occurrence_index")?.integer(),
            Some(index as i128)
        );
        assert_eq!(
            field(&cells[index], "frame_ordinal")?.integer(),
            Some(index as i128)
        );
    }
    assert_eq!(text(&cells[3], "reason")?, "missing_shape");
    let transitions = list(analysis, "transitions")?;
    assert_eq!(transitions.len(), 2);
    for (index, kind, previous, occurrence) in [
        (0, "entered_between_observations", 0, 1),
        (1, "observation_interrupted", 1, 3),
    ] {
        assert_eq!(text(&transitions[index], "kind")?, kind);
        assert_eq!(
            field(&transitions[index], "previous_occurrence")?.integer(),
            Some(previous)
        );
        assert_eq!(
            field(&transitions[index], "occurrence")?.integer(),
            Some(occurrence)
        );
        assert_eq!(
            field(&transitions[index], "tracklet_identity")?,
            field(&runs[0], "identity")?
        );
    }
    let policy_input = field(&report, "policy_input")?;
    assert_eq!(
        text(policy_input, "digest")?,
        ContentDigest::sha256(policy_text.as_bytes()).to_text()
    );
    assert_eq!(
        field(policy_input, "bytes")?.integer(),
        Some(policy_text.len() as i128)
    );
    assert_eq!(field(policy_input, "max_bytes")?.integer(), Some(65_536));
    assert_eq!(
        field(policy_input, "byte_reservation")?.integer(),
        Some(65_537)
    );
    assert_eq!(success(run(&args)?)?, output);

    // The operator's semantic policy is unchanged, while the exact admitted file is distinct.
    let whitespace = format!(" \n{policy_text}\n\t");
    fs::write(&policy_path, &whitespace)?;
    let changed = parse(&success(run(&args)?)?)?;
    assert_eq!(field(&changed, "analysis")?, analysis);
    assert_eq!(
        field(&changed, "snapshot_digest")?,
        field(&report, "snapshot_digest")?
    );
    assert_ne!(
        field(&changed, "query_digest")?,
        field(&report, "query_digest")?
    );
    assert_eq!(
        text(field(&changed, "policy_input")?, "digest")?,
        ContentDigest::sha256(whitespace.as_bytes()).to_text()
    );
    original_is_unchanged(&changed, &fixture.original)?;
    Ok(())
}

#[test]
fn wrong_domains_and_missing_shapes_stay_unknown_while_vendor_values_need_opt_in() -> Test {
    let fixture = Fixture::new("domains-and-privacy")?;
    let policy_path = fixture.policy("policy.json", &fixture.pins.json())?;
    let args = fixture.args(&policy_path)?;
    let hidden_text = success(run(&args)?)?;
    for private in [
        PRIVATE_MODULE,
        "zone-module",
        PRIVATE_OBJECT,
        "private-zone-profile-canary",
        "2026-11-09T",
    ] {
        assert!(!hidden_text.contains(private));
    }
    let hidden = parse(&hidden_text)?;
    let analysis = field(&hidden, "analysis")?;
    let operator_policy = field(analysis, "policy")?;
    assert_eq!(
        text(&list(operator_policy, "zones")?[0], "id")?,
        OPERATOR_ZONE
    );
    for claim in [
        "calibrated",
        "absence_certified",
        "physical_identity",
        "effect_authority",
    ] {
        assert_eq!(field(analysis, claim)?.boolean(), Some(false));
    }
    let tracks = field(&hidden, "tracklets")?;
    for occurrence in list(tracks, "occurrences")? {
        assert_eq!(field(occurrence, "values")?, &Value::Null);
    }
    let samples = list(analysis, "frame_samples")?;
    assert_eq!(samples.len(), 4);
    assert_eq!(field(&samples[3], "inside")?.integer(), Some(0));
    assert_eq!(field(&samples[3], "outside")?.integer(), Some(0));
    assert_eq!(field(&samples[3], "unavailable")?.integer(), Some(1));

    let mut revealed_args = args.clone();
    revealed_args.extend(["--include-values".into(), "yes".into()]);
    let revealed = parse(&success(run(&revealed_args)?)?)?;
    let values = field(
        &list(field(&revealed, "tracklets")?, "occurrences")?[0],
        "values",
    )?;
    assert_eq!(text(values, "vendor_object_id")?, PRIVATE_OBJECT);
    assert_eq!(text(values, "module_source")?, PRIVATE_MODULE);
    assert_eq!(field(&revealed, "analysis")?, analysis);
    assert_eq!(
        field(&revealed, "query_digest")?,
        field(&hidden, "query_digest")?
    );

    for (index, expected) in [
        "scope_mismatch",
        "module_mismatch",
        "frame_transform_mismatch",
        "object_transform_mismatch",
    ]
    .into_iter()
    .enumerate()
    {
        let mut wrong = fixture.pins.clone();
        let digest =
            ContentDigest::sha256(b"different operator-declared coordinate domain").to_text();
        match index {
            0 => wrong.scope = digest,
            1 => wrong.module = digest,
            2 => wrong.frame_transform = digest,
            _ => wrong.object_transform = digest,
        }
        fs::write(&policy_path, wrong.json())?;
        let changed = parse(&success(run(&args)?)?)?;
        let changed_analysis = field(&changed, "analysis")?;
        let cells = list(changed_analysis, "cells")?;
        assert_eq!(text(&cells[0], "reason")?, expected);
        for cell in cells {
            assert_eq!(text(cell, "relation")?, "unavailable");
        }
        for sample in list(changed_analysis, "frame_samples")? {
            assert_eq!(field(sample, "inside")?.integer(), Some(0));
            assert_eq!(field(sample, "outside")?.integer(), Some(0));
            assert_eq!(field(sample, "unavailable")?.integer(), Some(1));
        }
        assert!(list(changed_analysis, "transitions")?.is_empty());
        assert_ne!(
            field(changed_analysis, "policy_digest")?,
            field(analysis, "policy_digest")?
        );
        original_is_unchanged(&changed, &fixture.original)?;
    }
    Ok(())
}

#[test]
fn policy_errors_resource_bounds_and_missing_store_refuse_without_json_or_initialization() -> Test {
    let fixture = Fixture::new("refusals")?;
    let valid = fixture.pins.json();
    let policy_path = fixture.policy("policy.json", &valid)?;
    let args = fixture.args(&policy_path)?;

    let mut missing_flag = tracks_args(&fixture.directory.root(), &fixture.receipt)?;
    missing_flag[0] = "zones".into();
    refusal(run(&missing_flag)?);
    refusal(run(
        &fixture.args(&fixture.directory.0.join("missing-policy.json"))?
    )?);
    for malformed in [
        "{".to_owned(),
        valid.replacen('{', "{\"unknown\":true,", 1),
        valid.replace("raw_vendor_object_millionths", "image_pixels"),
        valid.replace("\"max\":[1000000,1000000]", "\"max\":[0,0]"),
    ] {
        fs::write(&policy_path, malformed)?;
        refusal(run(&args)?);
    }
    let mut oversized = valid.as_bytes().to_vec();
    oversized.resize(65_537, b' ');
    fs::write(&policy_path, oversized)?;
    refusal(run(&args)?);
    fs::write(&policy_path, &valid)?;

    for (flag, value) in [
        ("--max-read-bytes", "1"),
        ("--max-analysis-work", "2000000"),
        ("--max-analysis-bytes", "1"),
        ("--max-work-units", "10000000"),
    ] {
        let mut bounded = args.clone();
        bounded.extend([flag.into(), value.into()]);
        refusal(run(&bounded)?);
    }
    let missing = fixture.directory.0.join("missing-deployment");
    let mut missing_args = args.clone();
    missing_args[2] = missing.as_os_str().to_owned();
    refusal(run(&missing_args)?);
    assert!(!missing.exists());
    // Refused runs neither relabel the retained source nor corrupt its subsequent query.
    let completed = parse(&success(run(&args)?)?)?;
    original_is_unchanged(&completed, &fixture.original)?;
    Ok(())
}
