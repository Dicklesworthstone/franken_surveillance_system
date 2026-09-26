#![forbid(unsafe_code)]
//! Graph-complete deletion closure of a retained import (FSS-037) through the real binaries.
//!
//! Deployments are built with `fss-file import`, `fss-event watch --approve` (a published
//! event), `fss-event watch --retain-coverage` (a coverage record), `fss-file decode` (decoded
//! frames and receipts) and `fss-infer package-detect --retain yes` (a package-detection record).
//! The independent oracle of the closure is the set of ledger batches and publication roots each
//! command on the deleted import created (root-reachability summaries excluded), recorded by
//! diffing the deployment before and after every command:
//!
//! 1. `delete plan` enumerates exactly that set, classifies the event revision as authority
//!    history and everything else as deletable content, names the unknown copies, writes nothing
//!    and is byte-for-byte deterministic;
//! 2. `delete commit` removes exactly the planned objects and root records, appends exactly the
//!    deletion record and the completion record, and leaves every other file byte-identical (the
//!    unrelated import and its derivatives are untouched); later decode, read, re-import and plan
//!    report `ERR-EVIDENCE-DELETED-001`, orient/explain name the deleted evidence, and the
//!    root/ledger reconciliation stays clean;
//! 3. a plan made stale by a new analysis is refused before any write;
//! 4. an interruption at every cut point followed by a rerun completes exactly once, with
//!    byte-identical results to an uninterrupted commit;
//! 5. an indeterminate alert effect referencing the evidence blocks the commit.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_reference::deletion::{DELETION_CUT_POINTS, DeletionError, commit_deletion};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

/// Tests in this binary run on parallel threads, and a CLI child forked by one thread holds a
/// duplicate of any lock descriptor another thread has open until it execs (close-on-exec
/// releases it). A command that meets that transient lock is refused before any write
/// ("reference deployment is locked"), so it is re-run, boundedly; a lock that persists
/// returns the refusal to the test.
trait OutputUnlocked {
    fn output_unlocked(&mut self) -> std::io::Result<std::process::Output>;
}
impl OutputUnlocked for std::process::Command {
    fn output_unlocked(&mut self) -> std::io::Result<std::process::Output> {
        for _ in 0..100 {
            let output = self.output()?;
            if output.status.success()
                || !String::from_utf8_lossy(&output.stderr)
                    .contains("reference deployment is locked")
            {
                return Ok(output);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        self.output()
    }
}

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;
const SITE: &str = "site:deletion-cli";
const PRINCIPAL: &str = "principal:local-operator";
const DOOR: &str = "door:64,0,32,32";
const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-deletion-cli-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }

    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum Scene {
    /// A static scene of one background level.
    Quiet(u8),
    /// A bright 16x16 square enters at the left edge from frame 3 and moves 8 px right per frame.
    Right,
    /// The mirror image: it enters at the right edge and moves left.
    Left,
}

/// Fourteen grayscale MJPEG frames.
fn scene(kind: Scene) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let background = match kind {
            Scene::Quiet(level) => level,
            Scene::Right | Scene::Left => 40,
        };
        let mut pixels = vec![background; (WIDTH * HEIGHT) as usize];
        let left = match kind {
            Scene::Quiet(_) => None,
            Scene::Right => (index >= 3).then(|| (index - 3) * 8),
            Scene::Left => (index >= 3).then(|| 80 - (index - 3) * 8),
        };
        if let Some(left) = left {
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * WIDTH as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?);
    }
    Ok(stream)
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn refusal(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

fn line(text: &[u8], key: &str) -> TestResult<String> {
    let prefix = format!("{key}=");
    Ok(String::from_utf8(text.to_vec())?
        .lines()
        .find_map(|l| l.strip_prefix(&prefix).map(str::to_owned))
        .ok_or_else(|| format!("{key} missing"))?)
}

fn import_output(root: &Path, input: &Path, sensor: &str) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(root)
        .args(["--site", SITE, "--input"])
        .arg(input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{sensor}")])
        .args([
            "--media-format",
            "mjpeg",
            "--receive-time-ns",
            "10000000000000",
            "--capture-start-ns",
            "1000000000",
            "--capture-uncertainty-ns",
            "1000000",
            "--assumed-fps",
            "10",
        ])
        .output_unlocked()?)
}

/// Imports `bytes` for `sensor` with an operator capture hint and returns the import identity.
/// The input file is kept (the deployment never owns it) so a re-import can be attempted.
fn import(directory: &OwnedDirectory, bytes: &[u8], sensor: &str) -> TestResult<String> {
    let input = input_path(directory, sensor);
    fs::write(&input, bytes)?;
    let output = import_output(&directory.root(), &input, sensor)?;
    success(&output);
    line(&output.stdout, "import_identity")
}

fn input_path(directory: &OwnedDirectory, sensor: &str) -> PathBuf {
    directory
        .0
        .join(format!("{}.mjpeg", sensor.replace(':', "-")))
}

fn event(root: &Path, command: &str, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg(command)
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(args)
        .output_unlocked()?)
}

fn file(root: &Path, command: &str, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg(command)
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(args)
        .output_unlocked()?)
}

fn watch(root: &Path, import_id: &str, extra: &[&str]) -> TestResult<Output> {
    let mut args = vec![
        "--import-id",
        import_id,
        "--interpretation",
        "gray",
        "--zone",
        DOOR,
    ];
    args.extend_from_slice(extra);
    event(root, "watch", &args)
}

fn decode(root: &Path, import_id: &str, segment: &str) -> TestResult<Output> {
    file(
        root,
        "decode",
        &[
            "--import-id",
            import_id,
            "--segment",
            segment,
            "--interpretation",
            "gray",
        ],
    )
}

fn package_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/yolox-nano/yolox_nano.fmpk")
}

fn package_detect(root: &Path, import_id: &str) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-infer"))
        .arg("package-detect")
        .arg("--root")
        .arg(root)
        .args([
            "--site",
            SITE,
            "--import-id",
            import_id,
            "--first-segment",
            "6",
            "--frames",
            "1",
            "--interpretation",
            "gray",
            "--package-digest",
            PACKAGE_SHA256,
            "--retain",
            "yes",
        ])
        .arg("--package")
        .arg(package_path())
        .output_unlocked()?)
}

fn delete_plan(root: &Path, import_id: &str) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "plan", "--root"])
        .arg(root)
        .args(["--site", SITE, "--import-id", import_id])
        .output_unlocked()?)
}

fn delete_commit(root: &Path, plan: &str, approval: &str) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"])
        .arg(root)
        .args(["--site", SITE, "--plan", plan, "--approve", approval])
        .output_unlocked()?)
}

// ---------------------------------------------------------------------------------------------
// Minimal JSON reader.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn parse(text: &str) -> TestResult<Self> {
        let bytes = text.as_bytes();
        let mut position = 0;
        let value = parse_value(bytes, &mut position)?;
        skip_whitespace(bytes, &mut position);
        if position != bytes.len() {
            return Err(format!("trailing bytes at {position}").into());
        }
        Ok(value)
    }

    fn get(&self, key: &str) -> TestResult<&Self> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value)
                .ok_or_else(|| format!("missing key {key}").into()),
            _ => Err(format!("not an object when reading {key}").into()),
        }
    }

    fn path(&self, keys: &[&str]) -> TestResult<&Self> {
        let mut current = self;
        for key in keys {
            current = current.get(key)?;
        }
        Ok(current)
    }

    fn text(&self) -> TestResult<&str> {
        match self {
            Self::Text(value) => Ok(value),
            other => Err(format!("not a string: {other:?}").into()),
        }
    }

    fn items(&self) -> TestResult<&[Self]> {
        match self {
            Self::Array(items) => Ok(items),
            other => Err(format!("not an array: {other:?}").into()),
        }
    }

    fn number(&self) -> TestResult<u64> {
        match self {
            Self::Number(value) => Ok(value.parse()?),
            other => Err(format!("not a number: {other:?}").into()),
        }
    }
}

fn skip_whitespace(bytes: &[u8], position: &mut usize) {
    while bytes
        .get(*position)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        *position += 1;
    }
}

fn expect(bytes: &[u8], position: &mut usize, literal: &str) -> TestResult {
    if bytes[*position..].starts_with(literal.as_bytes()) {
        *position += literal.len();
        Ok(())
    } else {
        Err(format!("expected {literal} at {position}").into())
    }
}

fn parse_string(bytes: &[u8], position: &mut usize) -> TestResult<String> {
    expect(bytes, position, "\"")?;
    let mut out = String::new();
    loop {
        let byte = *bytes.get(*position).ok_or("unterminated string")?;
        *position += 1;
        match byte {
            b'"' => return Ok(out),
            b'\\' => {
                let escaped = *bytes.get(*position).ok_or("dangling escape")?;
                *position += 1;
                match escaped {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'u' => {
                        let hex = std::str::from_utf8(
                            bytes.get(*position..*position + 4).ok_or("short escape")?,
                        )?;
                        *position += 4;
                        out.push(char::from_u32(u32::from_str_radix(hex, 16)?).ok_or("bad char")?);
                    }
                    _ => return Err("bad escape".into()),
                }
            }
            _ => {
                let start = *position - 1;
                let mut end = *position;
                while end < bytes.len() && bytes[end] != b'"' && bytes[end] != b'\\' {
                    end += 1;
                }
                out.push_str(std::str::from_utf8(&bytes[start..end])?);
                *position = end;
            }
        }
    }
}

fn parse_value(bytes: &[u8], position: &mut usize) -> TestResult<Json> {
    skip_whitespace(bytes, position);
    match bytes.get(*position) {
        Some(b'n') => {
            expect(bytes, position, "null")?;
            Ok(Json::Null)
        }
        Some(b't') => {
            expect(bytes, position, "true")?;
            Ok(Json::Bool(true))
        }
        Some(b'f') => {
            expect(bytes, position, "false")?;
            Ok(Json::Bool(false))
        }
        Some(b'"') => Ok(Json::Text(parse_string(bytes, position)?)),
        Some(b'[') => {
            *position += 1;
            let mut items = Vec::new();
            skip_whitespace(bytes, position);
            if bytes.get(*position) == Some(&b']') {
                *position += 1;
                return Ok(Json::Array(items));
            }
            loop {
                items.push(parse_value(bytes, position)?);
                skip_whitespace(bytes, position);
                match bytes.get(*position) {
                    Some(b',') => *position += 1,
                    Some(b']') => {
                        *position += 1;
                        return Ok(Json::Array(items));
                    }
                    _ => return Err("bad array".into()),
                }
            }
        }
        Some(b'{') => {
            *position += 1;
            let mut fields = Vec::new();
            skip_whitespace(bytes, position);
            if bytes.get(*position) == Some(&b'}') {
                *position += 1;
                return Ok(Json::Object(fields));
            }
            loop {
                skip_whitespace(bytes, position);
                let key = parse_string(bytes, position)?;
                skip_whitespace(bytes, position);
                expect(bytes, position, ":")?;
                fields.push((key, parse_value(bytes, position)?));
                skip_whitespace(bytes, position);
                match bytes.get(*position) {
                    Some(b',') => *position += 1,
                    Some(b'}') => {
                        *position += 1;
                        return Ok(Json::Object(fields));
                    }
                    _ => return Err("bad object".into()),
                }
            }
        }
        _ => {
            let start = *position;
            while bytes
                .get(*position)
                .is_some_and(|byte| byte.is_ascii_digit() || b"-+.eE".contains(byte))
            {
                *position += 1;
            }
            if start == *position {
                return Err(format!("unexpected byte at {start}").into());
            }
            Ok(Json::Number(
                std::str::from_utf8(&bytes[start..*position])?.to_owned(),
            ))
        }
    }
}

fn report(output: &Output) -> TestResult<Json> {
    success(output);
    Json::parse(String::from_utf8(output.stdout.clone())?.trim_end())
}

// ---------------------------------------------------------------------------------------------
// Independent oracles over the deployment on disk.
// ---------------------------------------------------------------------------------------------

/// Every regular file under `root` with its content digest (content only: this is the
/// byte-identity proof, independent of times and inodes).
fn files(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if meta.file_type().is_file() {
            out.insert(
                path.strip_prefix(root)?.to_path_buf(),
                ContentDigest::sha256(&fs::read(&path)?),
            );
        }
    }
    Ok(out)
}

fn copy_tree(from: &Path, to: &Path) -> TestResult {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:deletion-test".into(),
        operation_id: OperationId::parse("operation:deletion-test")?,
        principal: PRINCIPAL.to_owned(),
        capabilities: vec![
            "ADP-REPLAY-001".to_owned(),
            "CAP-DELETE-PREPARE-001".to_owned(),
            "CAP-DELETE-COMMIT-001".to_owned(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1 << 20).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

/// Opens the deployment in this test process. The deployment lock is an `flock` on an open file
/// description: while a concurrently running test thread forks a child binary, the child briefly
/// holds a duplicate of this thread's just-dropped lock descriptor until it execs (close-on-exec
/// releases it). Only that transient `DeploymentLocked` is retried, boundedly; every other error
/// and a lock that persists fail the test.
fn open(root: &Path, cx: &ReplayCx) -> TestResult<ReferenceDeployment> {
    for _ in 0..100 {
        match ReferenceDeployment::open(root, SITE, cx) {
            Err(error) if error.is_deployment_locked() => {
                std::thread::sleep(Duration::from_millis(20));
            }
            other => return Ok(other?),
        }
    }
    Err("deployment lock held for more than 2 s".into())
}

/// Units of the deployment: every ledger batch except root-reachability summaries and deletion
/// records, and every visible publication root (`slot:<name>`).
fn units(root: &Path) -> TestResult<BTreeSet<String>> {
    if !root.join("LAYOUT").exists() {
        return Ok(BTreeSet::new());
    }
    let cx = context(root)?;
    let deployment = open(root, &cx)?;
    let mut out: BTreeSet<String> = deployment
        .ledger()
        .batches()
        .iter()
        .map(|batch| batch.batch_id.as_str().to_owned())
        .filter(|id| !id.starts_with("batch:local-root:") && !id.starts_with("batch:deletion:"))
        .collect();
    out.extend(
        deployment
            .publisher()
            .visible_roots()
            .map(|visible| format!("slot:{}", visible.slot.as_str())),
    );
    Ok(out)
}

/// Batch identities of the ledger, in order.
fn batch_ids(root: &Path) -> TestResult<Vec<String>> {
    let cx = context(root)?;
    let deployment = open(root, &cx)?;
    Ok(deployment
        .ledger()
        .batches()
        .iter()
        .map(|batch| batch.batch_id.as_str().to_owned())
        .collect())
}

/// Runs `step` and returns what it created.
fn created(root: &Path, step: impl FnOnce() -> TestResult) -> TestResult<BTreeSet<String>> {
    let before = units(root)?;
    step()?;
    Ok(units(root)?.difference(&before).cloned().collect())
}

/// A deployment with two imports; every derivative of `a` recorded by the command that made it.
struct Fixture {
    directory: OwnedDirectory,
    a: String,
    b: String,
    a_units: BTreeSet<String>,
    b_units: BTreeSet<String>,
    event_id: String,
}

fn fixture(name: &str) -> TestResult<Fixture> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.root();
    let mut a = String::new();
    let mut a_units = created(&root, || {
        a = import(&directory, &scene(Scene::Right)?, "sensor:alpha")?;
        Ok(())
    })?;
    let mut b = String::new();
    let mut b_units = created(&root, || {
        b = import(&directory, &scene(Scene::Quiet(60))?, "sensor:beta")?;
        Ok(())
    })?;

    // A published event, then its coverage record.
    let preview = report(&watch(&root, &a, &[])?)?;
    assert_eq!(preview.get("candidate_count")?.number()?, 1);
    let candidate = &preview.get("candidates")?.items()?[0];
    let event_id = candidate.get("event_id")?.text()?.to_owned();
    let proposal = candidate.get("proposal_digest")?.text()?.to_owned();
    let mut approval = String::new();
    a_units.extend(created(&root, || {
        let published = report(&watch(&root, &a, &["--approve", &proposal])?)?;
        approval = published
            .path(&["coverage", "approval_digest"])?
            .text()?
            .to_owned();
        Ok(())
    })?);
    a_units.extend(created(&root, || {
        let retained = report(&watch(&root, &a, &["--retain-coverage", &approval])?)?;
        assert_eq!(
            retained.path(&["coverage", "coverage_status"])?.text()?,
            "retained"
        );
        Ok(())
    })?);
    // Decoded frames and receipts.
    a_units.extend(created(&root, || {
        success(&decode(&root, &a, "5")?);
        Ok(())
    })?);
    // A retained package-detection record.
    a_units.extend(created(&root, || {
        let detect = package_detect(&root, &a)?;
        success(&detect);
        assert_eq!(line(&detect.stderr, "status")?, "retained");
        Ok(())
    })?);
    // The unrelated import gets its own coverage and decode.
    let quiet = report(&watch(&root, &b, &[])?)?;
    let quiet_approval = quiet
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    b_units.extend(created(&root, || {
        success(&watch(&root, &b, &["--retain-coverage", &quiet_approval])?);
        Ok(())
    })?);
    b_units.extend(created(&root, || {
        success(&decode(&root, &b, "5")?);
        Ok(())
    })?);
    Ok(Fixture {
        directory,
        a,
        b,
        a_units,
        b_units,
        event_id,
    })
}

fn hex(digest: &str) -> TestResult<&str> {
    Ok(digest
        .strip_prefix("sha256:")
        .ok_or("not a sha256 digest")?)
}

fn expected_kind(id: &str) -> &'static str {
    for (prefix, kind) in [
        ("batch:file-import:", "import_custody"),
        ("slot:fi-", "import_custody"),
        ("batch:recorded-decode:", "decoded_frames"),
        ("slot:fd-", "decoded_frames"),
        ("batch:coverage:", "coverage_record"),
        ("batch:package-detection:", "package_detection_record"),
        ("slot:pd-", "package_detection_record"),
        ("batch:model-run:", "model_run"),
        ("slot:mi-", "model_run"),
        ("slot:rw-", "event_provenance"),
        ("batch:event:", "event_revision"),
    ] {
        if id.starts_with(prefix) {
            return kind;
        }
    }
    "unexpected"
}

fn plan_units(plan: &Json) -> TestResult<BTreeMap<String, (String, String)>> {
    plan.get("units")?
        .items()?
        .iter()
        .map(|unit| {
            Ok((
                unit.get("id")?.text()?.to_owned(),
                (
                    unit.get("kind")?.text()?.to_owned(),
                    unit.get("class")?.text()?.to_owned(),
                ),
            ))
        })
        .collect()
}

fn digests(plan: &Json, key: &str) -> TestResult<BTreeSet<String>> {
    plan.get(key)?
        .items()?
        .iter()
        .map(|item| Ok(item.get("digest")?.text()?.to_owned()))
        .collect()
}

/// Validates `instance` against `schemas/<schema>` with the repository's strict validator.
fn assert_conforms(schema: &str, instance: &str, scratch: &Path, label: &str) -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let file = scratch.join(format!(
        "instance-{}.json",
        ContentDigest::sha256(format!("{schema}\n{label}\n{instance}").as_bytes())
            .to_text()
            .replace(':', "-")
    ));
    fs::write(&file, instance)?;
    let output = Command::new("python3")
        .arg("-B")
        .arg(root.join("scripts/json_instance_validate.py"))
        .arg(root.join("schemas").join(schema))
        .arg(&file)
        .output_unlocked()?;
    fs::remove_file(&file)?;
    assert!(
        output.status.success(),
        "{label}: output does not conform to schemas/{schema}: {}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}

fn run_fss(args: &[OsString]) -> TestResult<(Option<i32>, String, String)> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output_unlocked()?;
    Ok((
        output.status.code(),
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?,
    ))
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

#[test]
fn plan_enumerates_exactly_the_closure_and_commit_deletes_exactly_it() -> TestResult {
    let fixture = fixture("closure")?;
    let root = fixture.directory.root();
    let (a, b) = (fixture.a.as_str(), fixture.b.as_str());
    assert!(
        fixture
            .a_units
            .iter()
            .any(|id| id.starts_with("batch:event:"))
    );
    assert!(
        fixture
            .a_units
            .iter()
            .any(|id| id.starts_with("batch:coverage:"))
    );
    assert!(fixture.a_units.iter().any(|id| id.starts_with("slot:fd-")));
    assert!(fixture.a_units.iter().any(|id| id.starts_with("slot:pd-")));
    assert!(
        fixture
            .b_units
            .iter()
            .any(|id| id.starts_with("batch:coverage:"))
    );

    // 1. The plan is read-only, deterministic and enumerates exactly the recorded closure.
    let before = files(&root)?;
    let first = delete_plan(&root, a)?;
    let plan = report(&first)?;
    assert_eq!(files(&root)?, before, "a plan writes nothing");
    let again = delete_plan(&root, a)?;
    assert_eq!(first.stdout, again.stdout, "plans are deterministic");
    assert_eq!(plan.get("status")?.text()?, "planned");
    assert_eq!(plan.get("writes")?.text()?, "none");
    assert_eq!(plan.get("mechanism")?.text()?, "filesystem_unlink");
    assert_eq!(plan.get("cryptographic_erasure")?, &Json::Bool(false));
    assert_eq!(plan.path(&["counts", "blockers"])?.number()?, 0);
    let units = plan_units(&plan)?;
    let ids: BTreeSet<String> = units.keys().cloned().collect();
    assert_eq!(
        ids, fixture.a_units,
        "the closure is exactly the import's derivatives"
    );
    assert!(ids.is_disjoint(&fixture.b_units));
    let b_hex = hex(b)?;
    assert!(ids.iter().all(|id| !id.contains(b_hex)));
    for (id, (kind, class)) in &units {
        assert_eq!(kind, expected_kind(id), "{id}");
        let expected_class = if kind == "event_revision" {
            "authority_history"
        } else {
            "deletable_content"
        };
        assert_eq!(class, expected_class, "{id}");
    }
    let events = plan.get("events")?.items()?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].get("object_id")?.text()?,
        format!("object:event:{}", fixture.event_id)
    );
    assert_eq!(events[0].get("history")?.text()?, "retained");
    let copies: BTreeSet<&str> = plan
        .get("unknown_copies")?
        .items()?
        .iter()
        .map(|copy| copy.get("kind")?.text())
        .collect::<TestResult<_>>()?;
    assert_eq!(
        copies,
        BTreeSet::from(["original_input_file", "unrecorded_operator_exports"])
    );
    let deletable = digests(&plan, "deletable")?;
    assert_eq!(
        deletable.len() as u64,
        plan.path(&["counts", "deletable_objects"])?.number()?
    );
    let retractions: BTreeSet<String> = plan
        .path(&["tombstone_batch", "retractions"])?
        .items()?
        .iter()
        .map(|r| Ok(r.get("slot")?.text()?.to_owned()))
        .collect::<TestResult<_>>()?;
    let slots: BTreeSet<String> = ids
        .iter()
        .filter_map(|id| id.strip_prefix("slot:").map(str::to_owned))
        .collect();
    assert_eq!(retractions, slots, "every closure root is retracted");
    let tombstoned: BTreeSet<String> = plan
        .path(&["tombstone_batch", "tombstones"])?
        .items()?
        .iter()
        .map(|t| Ok(t.get("object_id")?.text()?.to_owned()))
        .collect::<TestResult<_>>()?;
    assert!(tombstoned.contains(&format!("object:file-import:{}", hex(a)?)));
    assert!(
        tombstoned
            .iter()
            .all(|object| !object.starts_with("object:event:"))
    );

    // 2. Commit removes exactly the plan; every other file is byte-identical.
    let plan_digest = plan.get("plan_digest")?.text()?.to_owned();
    let approval = plan.get("approval_digest")?.text()?.to_owned();
    let refused = delete_commit(&root, &plan_digest, &ContentDigest::sha256(b"no").to_text())?;
    assert!(!refused.status.success());
    assert_eq!(refusal(&refused), "ERR-DELETION-APPROVAL-001");
    assert_eq!(files(&root)?, before, "a refused commit writes nothing");
    let committed = report(&delete_commit(&root, &plan_digest, &approval)?)?;
    assert_eq!(committed.get("outcome")?.text()?, "completed");
    assert_eq!(
        committed.get("objects_unlinked")?.number()?,
        deletable.len() as u64
    );
    assert_eq!(
        committed.get("bytes_unlinked")?.number()?,
        plan.path(&["counts", "deletable_bytes"])?.number()?
    );
    assert_eq!(committed.get("cryptographic_erasure")?, &Json::Bool(false));
    assert_eq!(committed.get("blocked")?.items()?.len(), 0);
    assert_eq!(committed.get("not_proven")?.items()?.len(), 2);
    let completion = committed.get("completion_digest")?.text()?.to_owned();
    let after = files(&root)?;
    let deleted_hex: BTreeSet<&str> = deletable
        .iter()
        .map(|d| hex(d))
        .collect::<TestResult<_>>()?;
    let mut removed_objects = BTreeSet::new();
    for (path, digest) in &before {
        match after.get(path) {
            Some(now) if now == digest => {}
            Some(_) => assert_eq!(
                path,
                Path::new("ledger/journal.fssj"),
                "only the ledger journal changes in place"
            ),
            None => {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or("file name")?;
                if let Some(slot) = name.strip_suffix(".root") {
                    assert!(slots.contains(slot), "{path:?} is not a planned root");
                } else {
                    assert!(
                        deleted_hex.contains(name),
                        "{path:?} is not a planned object"
                    );
                    if path.parent().and_then(Path::file_name) == Some("objects".as_ref()) {
                        removed_objects.insert(name.to_owned());
                    }
                }
            }
        }
    }
    let expected_removed: BTreeSet<String> = deleted_hex.iter().map(|h| (*h).to_owned()).collect();
    assert_eq!(
        removed_objects, expected_removed,
        "every planned object was unlinked"
    );
    for path in after.keys().filter(|path| !before.contains_key(*path)) {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("file name")?;
        assert!(
            name == hex(&plan_digest)? || name == hex(&completion)?,
            "{path:?} is not the plan or completion record"
        );
    }
    let batches = batch_ids(&root)?;
    for id in [
        format!("batch:deletion:{}", hex(&plan_digest)?),
        format!("batch:deletion:{}:complete", hex(&plan_digest)?),
    ] {
        assert_eq!(batches.iter().filter(|b| **b == id).count(), 1, "{id}");
    }
    {
        let cx = context(&root)?;
        let mut deployment = open(&root, &cx)?;
        assert!(
            deployment.reconcile()?.is_clean(),
            "retracted roots are not unbacked claims"
        );
    }
    let rerun = report(&delete_commit(&root, &plan_digest, &approval)?)?;
    assert_eq!(rerun.get("outcome")?.text()?, "already_complete");
    assert_eq!(rerun.get("completion_digest")?.text()?, completion);
    assert_eq!(files(&root)?, after, "a rerun writes nothing");

    // 3. Reads of deleted evidence are typed `deleted`, never ambiguous; the other import works.
    for output in [
        decode(&root, a, "5")?,
        file(
            &root,
            "read-decoded",
            &[
                "--import-id",
                a,
                "--segment",
                "5",
                "--interpretation",
                "gray",
            ],
        )?,
        file(&root, "inspect", &["--import-id", a])?,
        file(&root, "verify", &["--import-id", a])?,
        delete_plan(&root, a)?,
        import_output(
            &root,
            &input_path(&fixture.directory, "sensor:alpha"),
            "sensor:alpha",
        )?,
    ] {
        assert!(!output.status.success());
        assert_eq!(refusal(&output), "ERR-EVIDENCE-DELETED-001", "{output:?}");
    }
    success(&file(&root, "verify", &["--import-id", b])?);
    success(&file(
        &root,
        "read-decoded",
        &[
            "--import-id",
            b,
            "--segment",
            "5",
            "--interpretation",
            "gray",
        ],
    )?);
    assert_eq!(
        report(&delete_plan(&root, b)?)?.get("status")?.text()?,
        "planned"
    );

    // 4. Orient and explain show the deleted evidence as deleted.
    let (code, stdout, stderr) = run_fss(&[
        OsString::from("orient"),
        OsString::from("--json"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--view"),
        OsString::from("brief"),
    ])?;
    assert_eq!(code, Some(0), "{stderr}");
    assert_conforms(
        "agent_response_envelope.v1.json",
        stdout.trim_end(),
        &fixture.directory.0,
        "orient after deletion",
    )?;
    assert!(stdout.contains(&format!("was deleted under deletion plan {plan_digest}")));
    assert!(stdout.contains("resolve to `deleted`, not missing"));
    for view in ["pulse", "epistemic_map"] {
        let (code, stdout, stderr) = run_fss(&[
            OsString::from("orient"),
            OsString::from("--json"),
            OsString::from("--root"),
            root.as_os_str().to_owned(),
            OsString::from("--view"),
            OsString::from(view),
        ])?;
        assert_eq!(code, Some(0), "{view}: {stderr}");
        assert!(stdout.contains("deletion"), "{view}: {stdout}");
    }
    let (code, stdout, stderr) = run_fss(&[
        OsString::from("explain"),
        OsString::from("--json"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--event-id"),
        OsString::from(&fixture.event_id),
    ])?;
    assert_eq!(code, Some(0), "{stderr}");
    assert_conforms(
        "agent_response_envelope.v1.json",
        stdout.trim_end(),
        &fixture.directory.0,
        "explain after deletion",
    )?;
    assert!(stdout.contains("no new revision was minted"), "{stdout}");
    Ok(())
}

#[test]
fn a_plan_made_stale_by_a_new_analysis_is_refused_before_any_write() -> TestResult {
    let fixture = fixture("stale")?;
    let root = fixture.directory.root();
    let plan = report(&delete_plan(&root, &fixture.a)?)?;
    let plan_digest = plan.get("plan_digest")?.text()?.to_owned();
    let approval = plan.get("approval_digest")?.text()?.to_owned();
    success(&decode(&root, &fixture.a, "3")?);
    let before = files(&root)?;
    let refused = delete_commit(&root, &plan_digest, &approval)?;
    assert!(!refused.status.success());
    assert_eq!(refusal(&refused), "ERR-DELETION-PLAN-STALE-001");
    assert_eq!(files(&root)?, before, "a stale plan writes nothing");
    // Planning again includes the new analysis and commits.
    let fresh = report(&delete_plan(&root, &fixture.a)?)?;
    assert_ne!(fresh.get("plan_digest")?.text()?, plan_digest);
    let committed = report(&delete_commit(
        &root,
        fresh.get("plan_digest")?.text()?,
        fresh.get("approval_digest")?.text()?,
    )?)?;
    assert_eq!(committed.get("outcome")?.text()?, "completed");
    Ok(())
}

#[test]
fn a_source_file_shared_with_another_import_is_retained_for_it() -> TestResult {
    let directory = OwnedDirectory::new("shared")?;
    let root = directory.root();
    let bytes = scene(Scene::Right)?;
    let mut first = String::new();
    let first_units = created(&root, || {
        first = import(&directory, &bytes, "sensor:one")?;
        Ok(())
    })?;
    let mut second = String::new();
    let mut second_units = created(&root, || {
        second = import(&directory, &bytes, "sensor:two")?;
        Ok(())
    })?;
    second_units.extend(created(&root, || {
        success(&decode(&root, &second, "5")?);
        Ok(())
    })?);
    let plan = report(&delete_plan(&root, &first)?)?;
    let ids: BTreeSet<String> = plan_units(&plan)?.keys().cloned().collect();
    assert_eq!(
        ids, first_units,
        "the other import of the same bytes is not derived"
    );
    assert!(ids.is_disjoint(&second_units));
    let deletable = digests(&plan, "deletable")?;
    let shared: Vec<String> = plan
        .get("retained")?
        .items()?
        .iter()
        .filter(|object| {
            object
                .get("reason")
                .and_then(Json::text)
                .is_ok_and(|reason| reason == "shared_with_retained_authority")
        })
        .map(|object| Ok(object.get("digest")?.text()?.to_owned()))
        .collect::<TestResult<_>>()?;
    assert!(
        !shared.is_empty(),
        "the shared chunks and custody manifest stay"
    );
    assert!(shared.iter().all(|digest| !deletable.contains(digest)));
    let committed = report(&delete_commit(
        &root,
        plan.get("plan_digest")?.text()?,
        plan.get("approval_digest")?.text()?,
    )?)?;
    assert_eq!(committed.get("outcome")?.text()?, "completed");
    // The other import still verifies byte for byte and serves its decode.
    success(&file(&root, "verify", &["--import-id", &second])?);
    success(&file(
        &root,
        "read-decoded",
        &[
            "--import-id",
            &second,
            "--segment",
            "5",
            "--interpretation",
            "gray",
        ],
    )?);
    let deleted = file(&root, "verify", &["--import-id", &first])?;
    assert!(!deleted.status.success());
    assert_eq!(refusal(&deleted), "ERR-EVIDENCE-DELETED-001");
    Ok(())
}

#[test]
fn an_interruption_at_every_cut_point_resumes_and_completes_exactly_once() -> TestResult {
    let fixture = fixture("cuts")?;
    let base = fixture.directory.root();
    let plan = report(&delete_plan(&base, &fixture.a)?)?;
    let plan_digest = plan.get("plan_digest")?.text()?.to_owned();
    let approval = plan.get("approval_digest")?.text()?.to_owned();

    let reference = fixture.directory.0.join("reference");
    copy_tree(&base, &reference)?;
    let uninterrupted = report(&delete_commit(&reference, &plan_digest, &approval)?)?;
    let completion = uninterrupted.get("completion_digest")?.text()?.to_owned();
    let expected = files(&reference)?;

    for (index, stage) in DELETION_CUT_POINTS.iter().enumerate() {
        let copy = fixture.directory.0.join(format!("cut-{index}"));
        copy_tree(&base, &copy)?;
        {
            let cx = context(&copy)?;
            cx.set_cancel_at_checkpoint(stage);
            let mut deployment = open(&copy, &cx)?;
            let result = commit_deletion(
                &mut deployment,
                ContentDigest::parse(&plan_digest)?,
                ContentDigest::parse(&approval)?,
                PRINCIPAL,
                &cx,
            );
            match result {
                Err(DeletionError::Cancelled { stage: reached }) => assert_eq!(reached, *stage),
                other => {
                    return Err(format!("{stage}: expected an interruption, got {other:?}").into());
                }
            }
        }
        let resumed = report(&delete_commit(&copy, &plan_digest, &approval)?)?;
        let outcome = resumed.get("outcome")?.text()?;
        if index < 2 {
            assert_eq!(outcome, "completed", "{stage}: nothing durable yet");
        } else {
            assert_eq!(outcome, "resumed", "{stage}");
        }
        assert_eq!(
            resumed.get("completion_digest")?.text()?,
            completion,
            "{stage}"
        );
        let batches = batch_ids(&copy)?;
        for id in [
            format!("batch:deletion:{}", hex(&plan_digest)?),
            format!("batch:deletion:{}:complete", hex(&plan_digest)?),
        ] {
            assert_eq!(
                batches.iter().filter(|b| **b == id).count(),
                1,
                "{stage} {id}"
            );
        }
        assert_eq!(
            files(&copy)?,
            expected,
            "{stage}: identical to an uninterrupted commit"
        );
        let again = report(&delete_commit(&copy, &plan_digest, &approval)?)?;
        assert_eq!(again.get("outcome")?.text()?, "already_complete", "{stage}");
        assert_eq!(files(&copy)?, expected, "{stage}: a rerun writes nothing");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Blocker: an indeterminate alert effect referencing the evidence.
// ---------------------------------------------------------------------------------------------

/// Whether `request` holds complete headers and the whole `Content-Length` body.
fn complete(request: &[u8]) -> bool {
    let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let length = String::from_utf8_lossy(&request[..end])
        .split("\r\n")
        .find_map(|line| line.strip_prefix("Content-Length: ").map(str::to_owned))
        .and_then(|value| value.parse::<usize>().ok());
    length.is_some_and(|length| request.len() >= end + 4 + length)
}

/// Loopback relay that reads one complete request and closes without any response, so the
/// acknowledgement is lost and the alert stays indeterminate.
struct SilentRelay {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SilentRelay {
    fn spawn() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let halt = stop.clone();
        let handle = std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                if stream.set_nonblocking(false).is_err()
                    || stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .is_err()
                {
                    continue;
                }
                let mut buffer = [0_u8; 4096];
                let mut request = Vec::new();
                while !complete(&request) && request.len() < 65_536 {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                let _ = stream.flush();
            }
        });
        Ok(Self {
            address,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for SilentRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn field(output: &Output, key: &str) -> TestResult<String> {
    let text = String::from_utf8(output.stdout.clone())?;
    let pattern = format!("\"{key}\":");
    let start = text
        .find(&pattern)
        .ok_or_else(|| format!("missing {key} in {text}"))?
        + pattern.len();
    let rest = &text[start..];
    Ok(match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default().to_owned(),
        None => rest
            .split([',', '}', ']'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    })
}

#[test]
fn an_indeterminate_alert_referencing_the_evidence_blocks_the_commit() -> TestResult {
    let directory = OwnedDirectory::new("blocked")?;
    let root = directory.root();
    let east = import(&directory, &scene(Scene::Right)?, "sensor:east")?;
    let west = import(&directory, &scene(Scene::Left)?, "sensor:west")?;
    let cameras = [format!("east:{east}"), format!("west:{west}")];
    let corroborate = |extra: &[&str]| -> TestResult<Output> {
        let mut args = vec![
            "--camera",
            &cameras[0],
            "--camera",
            &cameras[1],
            "--ground",
            "east:1,0,0,0,1,0,0,0,1",
            "--ground",
            "west:-1,0,96,0,1,0,0,0,1",
            "--zone",
            "door:56,0,40,48",
            "--interpretation",
            "gray",
            "--time-gate-ns",
            "250000000",
            "--distance-gate",
            "16",
        ];
        args.extend_from_slice(extra);
        event(&root, "corroborate", &args)
    };
    let prepared = corroborate(&[])?;
    success(&prepared);
    let proposal = field(&prepared, "proposal_digest")?;
    let published = corroborate(&["--approve", &proposal])?;
    success(&published);
    let event_id = field(&published, "event_id")?;

    let relay = SilentRelay::spawn()?;
    let address = relay.address.to_string();
    let plaintext = ContentDigest::sha256(b"owner approves the plaintext loopback relay").to_text();
    let alert = |extra: &[&str]| -> TestResult<Output> {
        let mut args = vec![
            "--event-id",
            &event_id,
            "--relay",
            &address,
            "--path",
            "/fss/alert",
            "--plaintext-approval",
            &plaintext,
            "--deadline-ms",
            "2000",
        ];
        args.extend_from_slice(extra);
        event(&root, "alert", &args)
    };
    let proposed = alert(&[])?;
    success(&proposed);
    let plan = field(&proposed, "plan_digest")?;
    let prepared = alert(&["--approve", &plan])?;
    success(&prepared);
    let dispatch = field(&prepared, "dispatch_digest")?;
    let lost = alert(&["--approve", &plan, "--dispatch", &dispatch])?;
    assert_eq!(refusal(&lost), "ERR-EFFECT-INDETERMINATE-001");
    assert_eq!(field(&lost, "effect_state")?, "indeterminate");
    drop(relay);

    let before = files(&root)?;
    let planned = report(&delete_plan(&root, &east)?)?;
    assert_eq!(planned.get("status")?.text()?, "blocked");
    assert_eq!(planned.get("approve_command")?, &Json::Null);
    let blockers = planned.get("blockers")?.items()?;
    assert!(
        blockers.iter().any(|blocker| {
            blocker
                .get("kind")
                .and_then(Json::text)
                .is_ok_and(|k| k == "open_effect")
                && blocker
                    .get("detail")
                    .and_then(Json::text)
                    .is_ok_and(|d| d.contains("indeterminate"))
        }),
        "{blockers:?}"
    );
    assert!(
        planned
            .get("unknown_copies")?
            .items()?
            .iter()
            .any(|copy| copy
                .get("kind")
                .and_then(Json::text)
                .is_ok_and(|k| k == "alert_dispatch")),
        "a transmitted alert is a named unknown copy"
    );
    let refused = delete_commit(
        &root,
        planned.get("plan_digest")?.text()?,
        planned.get("approval_digest")?.text()?,
    )?;
    assert!(!refused.status.success());
    assert_eq!(refusal(&refused), "ERR-DELETION-BLOCKED-001");
    assert_eq!(files(&root)?, before, "a blocked commit writes nothing");
    // The other camera's import is equally blocked: the corroborated event cites both.
    assert_eq!(
        report(&delete_plan(&root, &west)?)?.get("status")?.text()?,
        "blocked"
    );
    Ok(())
}
