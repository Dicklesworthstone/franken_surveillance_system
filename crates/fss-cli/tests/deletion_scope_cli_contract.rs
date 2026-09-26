#![forbid(unsafe_code)]
//! Sensor- and event-scoped deletion closure (fss-x4a.30.86.20 / .21) through the real binaries.
//!
//! `fss-event delete plan --sensor-id ID | --event-id ID` seals ONE plan over the union closure
//! of the scope's retained member imports, and `delete commit` executes it with the same
//! approval, stale-plan, tombstone-first and exactly-once guarantees as an import plan. The
//! independent oracle is again the set of ledger batches and roots each command created
//! (recorded by diffing the deployment around every command) plus the file bytes on disk:
//!
//! 1. a sensor scope over two imports plans exactly the union of their closures, deletes exactly
//!    it, and leaves the other sensor's objects byte-identical;
//! 2. an event scope deletes the evidence imports of a corroborated event, keeps the event's
//!    revision history, and leaves an unrelated import intact;
//! 3. an object another retained import still holds is retained and listed;
//! 4. an owner evidence hold (`fss-hold`) on one member import blocks the whole scoped commit;
//! 5. a plan whose scope identity was tampered with is refused;
//! 6. an interruption at every cut point resumes and completes exactly once;
//! 7. the plan scope is exactly one of `--import-id`, `--sensor-id`, `--event-id`.
//!
//! Removal is `filesystem_unlink` from the local deployment: not cryptographic erasure, and no
//! replica, backup or archive copy is covered.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId};
use fss_reference::deletion::{
    DELETION_CUT_POINTS, DeletionError, DeletionPlan, DeletionScope, commit_deletion,
    plan_deletion, plan_scope_deletion,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;
const SITE: &str = "site:deletion-scope-cli";
const PRINCIPAL: &str = "principal:local-operator";
const DOOR: &str = "door:64,0,32,32";

// ---------------------------------------------------------------------------------------------
// Fixtures (shared shape with deletion_cli_contract.rs).
// ---------------------------------------------------------------------------------------------

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-deletion-scope-cli-{name}-{}-{attempt}",
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
        .output()?)
}

fn event(root: &Path, command: &str, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg(command)
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(args)
        .output()?)
}

fn file(root: &Path, command: &str, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg(command)
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(args)
        .output()?)
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

fn run_fss(args: &[OsString]) -> TestResult<(Option<i32>, String, String)> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    Ok((
        output.status.code(),
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?,
    ))
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

// ---------------------------------------------------------------------------------------------
// Scope-specific helpers.
// ---------------------------------------------------------------------------------------------

fn delete_plan(root: &Path, scope: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "plan", "--root"])
        .arg(root)
        .args(["--site", SITE])
        .args(scope)
        .output()?)
}

fn delete_commit(root: &Path, plan: &str, approval: &str) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"])
        .arg(root)
        .args(["--site", SITE, "--plan", plan, "--approve", approval])
        .output()?)
}

fn hex(digest: &str) -> TestResult<&str> {
    Ok(digest
        .strip_prefix("sha256:")
        .ok_or("not a sha256 digest")?)
}

fn texts(value: &Json) -> TestResult<Vec<String>> {
    value
        .items()?
        .iter()
        .map(|item| Ok(item.text()?.to_owned()))
        .collect()
}

/// Imports `bytes` for `sensor` from an input file named `name`, returning the import identity
/// and the units the import created.
fn import_named(
    directory: &OwnedDirectory,
    bytes: &[u8],
    sensor: &str,
    name: &str,
) -> TestResult<(String, BTreeSet<String>)> {
    let root = directory.root();
    let input = directory.0.join(format!("{name}.mjpeg"));
    fs::write(&input, bytes)?;
    let mut identity = String::new();
    let units = created(&root, || {
        let output = import_output(&root, &input, sensor)?;
        success(&output);
        identity = line(&output.stdout, "import_identity")?;
        Ok(())
    })?;
    Ok((identity, units))
}

/// Decodes segment 5 of `import`, returning what it created.
fn decoded(root: &Path, import: &str) -> TestResult<BTreeSet<String>> {
    created(root, || {
        success(&decode(root, import, "5")?);
        Ok(())
    })
}

/// Publishes the moving-square event of `import` and retains its coverage; returns the event
/// identity and what the two commands created.
fn published_event(root: &Path, import: &str) -> TestResult<(String, BTreeSet<String>)> {
    let preview = report(&watch(root, import, &[])?)?;
    assert_eq!(preview.get("candidate_count")?.number()?, 1);
    let candidate = &preview.get("candidates")?.items()?[0];
    let event_id = candidate.get("event_id")?.text()?.to_owned();
    let proposal = candidate.get("proposal_digest")?.text()?.to_owned();
    let mut approval = String::new();
    let mut units = created(root, || {
        let published = report(&watch(root, import, &["--approve", &proposal])?)?;
        approval = published
            .path(&["coverage", "approval_digest"])?
            .text()?
            .to_owned();
        Ok(())
    })?;
    units.extend(created(root, || {
        success(&watch(root, import, &["--retain-coverage", &approval])?);
        Ok(())
    })?);
    Ok((event_id, units))
}

/// Every file of the deployment that is not in `removed` (object hex names and root slots) is
/// byte-identical after the commit, except the append-only ledger journal; every new file is
/// the plan or the completion record; every planned object was unlinked.
fn assert_exactly_removed(
    before: &BTreeMap<PathBuf, ContentDigest>,
    after: &BTreeMap<PathBuf, ContentDigest>,
    deletable: &BTreeSet<String>,
    slots: &BTreeSet<String>,
    records: &[&str],
) -> TestResult {
    let deleted_hex: BTreeSet<&str> = deletable
        .iter()
        .map(|d| hex(d))
        .collect::<TestResult<_>>()?;
    let mut removed_objects = BTreeSet::new();
    for (path, digest) in before {
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
    let expected: BTreeSet<String> = deleted_hex.iter().map(|h| (*h).to_owned()).collect();
    assert_eq!(
        removed_objects, expected,
        "every planned object was unlinked"
    );
    for path in after.keys().filter(|path| !before.contains_key(*path)) {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("file name")?;
        assert!(
            records
                .iter()
                .any(|record| hex(record).is_ok_and(|h| h == name)),
            "{path:?} is not the plan or completion record"
        );
    }
    Ok(())
}

fn slots_of(plan: &Json) -> TestResult<BTreeSet<String>> {
    plan.path(&["tombstone_batch", "retractions"])?
        .items()?
        .iter()
        .map(|r| Ok(r.get("slot")?.text()?.to_owned()))
        .collect()
}

/// The object files (spool `objects/` entries) of the deployment with their content digests.
fn objects(root: &Path) -> TestResult<BTreeMap<String, ContentDigest>> {
    Ok(files(root)?
        .into_iter()
        .filter(|(path, _)| path.parent().and_then(Path::file_name) == Some("objects".as_ref()))
        .filter_map(|(path, digest)| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| (name.to_owned(), digest))
        })
        .collect())
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_sensor_scope_deletes_exactly_the_union_of_its_imports_and_leaves_other_sensors_intact()
-> TestResult {
    let directory = OwnedDirectory::new("sensor")?;
    let root = directory.root();
    let (first, mut first_units) =
        import_named(&directory, &scene(Scene::Right)?, "sensor:alpha", "alpha-1")?;
    let (second, mut second_units) = import_named(
        &directory,
        &scene(Scene::Quiet(80))?,
        "sensor:alpha",
        "alpha-2",
    )?;
    let (other, mut other_units) =
        import_named(&directory, &scene(Scene::Quiet(60))?, "sensor:beta", "beta")?;
    let (event_id, event_units) = published_event(&root, &first)?;
    first_units.extend(event_units);
    first_units.extend(decoded(&root, &first)?);
    second_units.extend(decoded(&root, &second)?);
    other_units.extend(decoded(&root, &other)?);

    // The unrelated sensor's own closure, before anything is deleted: its objects are the
    // byte-level oracle that it stays intact.
    let other_plan = report(&delete_plan(&root, &["--import-id", &other])?)?;
    let other_objects = digests(&other_plan, "deletable")?;
    assert!(!other_objects.is_empty());
    let first_plan = report(&delete_plan(&root, &["--import-id", &first])?)?;
    let second_plan = report(&delete_plan(&root, &["--import-id", &second])?)?;

    // 1. One read-only, deterministic plan over the union of both alpha imports.
    let before = files(&root)?;
    let output = delete_plan(&root, &["--sensor-id", "sensor:alpha"])?;
    let plan = report(&output)?;
    assert_eq!(files(&root)?, before, "a plan writes nothing");
    assert_eq!(
        delete_plan(&root, &["--sensor-id", "sensor:alpha"])?.stdout,
        output.stdout,
        "plans are deterministic"
    );
    assert_eq!(plan.get("status")?.text()?, "planned");
    assert_eq!(plan.get("format")?.text()?, "fss.deletion_plan.v2");
    assert_eq!(plan.path(&["scope", "kind"])?.text()?, "sensor");
    assert_eq!(plan.path(&["scope", "id"])?.text()?, "sensor:alpha");
    assert_eq!(plan.get("import_identity")?, &Json::Null);
    let mut members = vec![first.clone(), second.clone()];
    members.sort();
    assert_eq!(
        texts(plan.get("imports")?)?,
        members,
        "sorted member imports"
    );
    let ids: BTreeSet<String> = plan_units(&plan)?.keys().cloned().collect();
    let union: BTreeSet<String> = first_units.union(&second_units).cloned().collect();
    assert_eq!(
        ids, union,
        "the closure is exactly the union of the members"
    );
    assert!(ids.is_disjoint(&other_units));
    let deletable = digests(&plan, "deletable")?;
    let member_deletable: BTreeSet<String> = digests(&first_plan, "deletable")?
        .union(&digests(&second_plan, "deletable")?)
        .cloned()
        .collect();
    assert_eq!(
        deletable, member_deletable,
        "the union plan deletes exactly what the member plans delete"
    );
    assert!(deletable.is_disjoint(&other_objects));
    let events = plan.get("events")?.items()?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].get("object_id")?.text()?,
        format!("object:event:{event_id}")
    );
    let copies = plan.get("unknown_copies")?.items()?;
    assert_eq!(copies.len(), 4, "input file and exports of each member");
    let tombstoned: BTreeSet<String> = plan
        .path(&["tombstone_batch", "tombstones"])?
        .items()?
        .iter()
        .map(|t| Ok(t.get("object_id")?.text()?.to_owned()))
        .collect::<TestResult<_>>()?;
    for member in &members {
        assert!(tombstoned.contains(&format!("object:file-import:{}", hex(member)?)));
    }
    let slots = slots_of(&plan)?;
    // The scope is inside the digest: no member's import plan has this digest.
    let plan_digest = plan.get("plan_digest")?.text()?.to_owned();
    let approval = plan.get("approval_digest")?.text()?.to_owned();
    for member_plan in [&first_plan, &second_plan] {
        assert_ne!(member_plan.get("plan_digest")?.text()?, plan_digest);
    }

    // 2. One commit removes exactly the union; every other file is byte-identical.
    let other_bytes_before = objects(&root)?;
    let committed = report(&delete_commit(&root, &plan_digest, &approval)?)?;
    assert_eq!(committed.get("outcome")?.text()?, "completed");
    assert_eq!(
        committed.get("format")?.text()?,
        "fss.deletion_completion.v2"
    );
    assert_eq!(
        committed.path(&["scope", "text"])?.text()?,
        "sensor:sensor:alpha"
    );
    assert_eq!(texts(committed.get("imports")?)?, members);
    assert_eq!(
        committed.get("objects_unlinked")?.number()?,
        deletable.len() as u64
    );
    assert_eq!(committed.get("cryptographic_erasure")?, &Json::Bool(false));
    let completion = committed.get("completion_digest")?.text()?.to_owned();
    let after = files(&root)?;
    assert_exactly_removed(
        &before,
        &after,
        &deletable,
        &slots,
        &[&plan_digest, &completion],
    )?;
    let batches = batch_ids(&root)?;
    for id in [
        format!("batch:deletion:{}", hex(&plan_digest)?),
        format!("batch:deletion:{}:complete", hex(&plan_digest)?),
    ] {
        assert_eq!(batches.iter().filter(|b| **b == id).count(), 1, "{id}");
    }
    // The other sensor's objects are present with identical bytes.
    let other_bytes_after = objects(&root)?;
    for digest in &other_objects {
        let name = hex(digest)?;
        assert_eq!(
            other_bytes_after.get(name),
            other_bytes_before.get(name),
            "{digest} of sensor:beta is byte-identical"
        );
        assert!(
            other_bytes_before.contains_key(name),
            "{digest} is a spool object file of the deployment"
        );
    }
    success(&file(&root, "verify", &["--import-id", &other])?);
    success(&file(
        &root,
        "read-decoded",
        &[
            "--import-id",
            &other,
            "--segment",
            "5",
            "--interpretation",
            "gray",
        ],
    )?);
    {
        let cx = context(&root)?;
        let mut deployment = open(&root, &cx)?;
        assert!(deployment.reconcile()?.is_clean());
    }

    // 3. Every member reads `deleted`; the scope is now empty; a rerun writes nothing.
    for member in &members {
        let output = file(&root, "verify", &["--import-id", member])?;
        assert!(!output.status.success());
        assert_eq!(refusal(&output), "ERR-EVIDENCE-DELETED-001");
        let output = delete_plan(&root, &["--import-id", member])?;
        assert_eq!(refusal(&output), "ERR-EVIDENCE-DELETED-001");
    }
    let empty = delete_plan(&root, &["--sensor-id", "sensor:alpha"])?;
    assert!(!empty.status.success());
    assert_eq!(refusal(&empty), "ERR-DELETION-SCOPE-EMPTY-001");
    let rerun = report(&delete_commit(&root, &plan_digest, &approval)?)?;
    assert_eq!(rerun.get("outcome")?.text()?, "already_complete");
    assert_eq!(rerun.get("completion_digest")?.text()?, completion);
    assert_eq!(files(&root)?, after, "a rerun writes nothing");
    assert_eq!(
        report(&delete_plan(&root, &["--sensor-id", "sensor:beta"])?)?
            .get("status")?
            .text()?,
        "planned"
    );

    // 4. Orient names the scoped deletion.
    let (code, stdout, stderr) = run_fss(&[
        OsString::from("orient"),
        OsString::from("--json"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--view"),
        OsString::from("brief"),
    ])?;
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stdout.contains(&format!(
            "The scope sensor:sensor:alpha (import(s) {}) was deleted under deletion plan \
             {plan_digest}",
            members.join(", ")
        )),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn an_event_scope_deletes_the_event_evidence_but_not_unrelated_imports() -> TestResult {
    let directory = OwnedDirectory::new("event")?;
    let root = directory.root();
    let (east, mut east_units) =
        import_named(&directory, &scene(Scene::Right)?, "sensor:east", "east")?;
    let (west, mut west_units) =
        import_named(&directory, &scene(Scene::Left)?, "sensor:west", "west")?;
    let (north, mut north_units) = import_named(
        &directory,
        &scene(Scene::Quiet(60))?,
        "sensor:north",
        "north",
    )?;
    north_units.extend(decoded(&root, &north)?);
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
    let mut event_id = String::new();
    let event_units = created(&root, || {
        let published = corroborate(&["--approve", &proposal])?;
        success(&published);
        event_id = field(&published, "event_id")?;
        Ok(())
    })?;
    // The corroborated event's own units belong to both cameras' closures.
    east_units.extend(event_units.iter().cloned());
    west_units.extend(event_units.iter().cloned());
    east_units.extend(decoded(&root, &east)?);

    let north_before = report(&delete_plan(&root, &["--import-id", &north])?)?;
    let north_objects = digests(&north_before, "deletable")?;
    let before = files(&root)?;
    let plan = report(&delete_plan(&root, &["--event-id", &event_id])?)?;
    assert_eq!(files(&root)?, before, "a plan writes nothing");
    assert_eq!(plan.get("status")?.text()?, "planned", "{plan:?}");
    assert_eq!(plan.get("format")?.text()?, "fss.deletion_plan.v2");
    assert_eq!(plan.path(&["scope", "kind"])?.text()?, "event");
    assert_eq!(plan.path(&["scope", "id"])?.text()?, event_id);
    let mut members = vec![east.clone(), west.clone()];
    members.sort();
    assert_eq!(
        texts(plan.get("imports")?)?,
        members,
        "the event's evidence imports"
    );
    let ids: BTreeSet<String> = plan_units(&plan)?.keys().cloned().collect();
    let union: BTreeSet<String> = east_units.union(&west_units).cloned().collect();
    assert_eq!(ids, union);
    assert!(
        ids.is_disjoint(&north_units),
        "unrelated imports are not in scope"
    );
    for (id, (kind, class)) in plan_units(&plan)? {
        if id.starts_with("batch:event:") {
            assert_eq!(
                (kind.as_str(), class.as_str()),
                ("event_revision", "authority_history"),
                "{id}"
            );
        }
    }
    let events = plan.get("events")?.items()?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].get("history")?.text()?, "retained");
    let deletable = digests(&plan, "deletable")?;
    assert!(deletable.is_disjoint(&north_objects));

    let north_bytes = objects(&root)?;
    let plan_digest = plan.get("plan_digest")?.text()?.to_owned();
    let committed = report(&delete_commit(
        &root,
        &plan_digest,
        plan.get("approval_digest")?.text()?,
    )?)?;
    assert_eq!(committed.get("outcome")?.text()?, "completed");
    let completion = committed.get("completion_digest")?.text()?.to_owned();
    assert_exactly_removed(
        &before,
        &files(&root)?,
        &deletable,
        &slots_of(&plan)?,
        &[&plan_digest, &completion],
    )?;
    let after = objects(&root)?;
    for digest in &north_objects {
        let name = hex(digest)?;
        assert!(north_bytes.contains_key(name), "{digest} is a spool object");
        assert_eq!(after.get(name), north_bytes.get(name), "{digest} intact");
    }
    success(&file(&root, "verify", &["--import-id", &north])?);
    for member in &members {
        assert_eq!(
            refusal(&file(&root, "verify", &["--import-id", member])?),
            "ERR-EVIDENCE-DELETED-001"
        );
    }
    // The event keeps its history; its evidence is `deleted`.
    let (code, stdout, stderr) = run_fss(&[
        OsString::from("explain"),
        OsString::from("--json"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--event-id"),
        OsString::from(&event_id),
    ])?;
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.contains("no new revision was minted"), "{stdout}");
    assert!(
        stdout.contains(&format!("the scope event:{event_id}")),
        "{stdout}"
    );
    // An event whose evidence is gone has an empty scope; an unknown event is refused alike.
    for id in [event_id.as_str(), "event:never-committed"] {
        let refused = delete_plan(&root, &["--event-id", id])?;
        assert!(!refused.status.success());
        assert_eq!(refusal(&refused), "ERR-DELETION-SCOPE-EMPTY-001", "{id}");
    }
    Ok(())
}

#[test]
fn a_shared_object_outside_the_scope_is_retained_and_listed() -> TestResult {
    let directory = OwnedDirectory::new("shared")?;
    let root = directory.root();
    let bytes = scene(Scene::Right)?;
    let (mine, mine_units) = import_named(&directory, &bytes, "sensor:one", "one")?;
    let (theirs, mut their_units) = import_named(&directory, &bytes, "sensor:two", "two")?;
    their_units.extend(decoded(&root, &theirs)?);
    let plan = report(&delete_plan(&root, &["--sensor-id", "sensor:one"])?)?;
    assert_eq!(texts(plan.get("imports")?)?, vec![mine.clone()]);
    let ids: BTreeSet<String> = plan_units(&plan)?.keys().cloned().collect();
    assert_eq!(ids, mine_units);
    assert!(ids.is_disjoint(&their_units));
    let deletable = digests(&plan, "deletable")?;
    let shared: BTreeSet<String> = plan
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
        "the shared chunks and custody manifest are listed"
    );
    assert!(shared.is_disjoint(&deletable));
    assert_eq!(
        plan.path(&["counts", "retained_objects"])?.number()?,
        plan.get("retained")?.items()?.len() as u64
    );
    let before = objects(&root)?;
    let committed = report(&delete_commit(
        &root,
        plan.get("plan_digest")?.text()?,
        plan.get("approval_digest")?.text()?,
    )?)?;
    assert_eq!(committed.get("outcome")?.text()?, "completed");
    let after = objects(&root)?;
    for digest in &shared {
        let name = hex(digest)?;
        assert!(before.contains_key(name), "{digest} was a spool object");
        assert_eq!(
            after.get(name),
            before.get(name),
            "{digest} is retained intact"
        );
    }
    success(&file(&root, "verify", &["--import-id", &theirs])?);
    Ok(())
}

#[test]
fn a_hold_on_one_member_import_blocks_the_whole_scoped_commit() -> TestResult {
    let directory = OwnedDirectory::new("hold")?;
    let root = directory.root();
    let (first, _) = import_named(&directory, &scene(Scene::Right)?, "sensor:alpha", "a1")?;
    let (second, _) = import_named(&directory, &scene(Scene::Quiet(80))?, "sensor:alpha", "a2")?;
    let (other, _) = import_named(&directory, &scene(Scene::Quiet(60))?, "sensor:beta", "b")?;
    let open_plan = report(&delete_plan(&root, &["--sensor-id", "sensor:alpha"])?)?;
    assert_eq!(open_plan.get("status")?.text()?, "planned");

    // The owner's approval-gated evidence hold (fss-hold) on one import.
    let hold =
        |action: &str, id: &str, import: &str, approve: Option<&str>| -> TestResult<Output> {
            let mut command = Command::new(env!("CARGO_BIN_EXE_fss-hold"));
            command.arg(action).arg("--root").arg(&root).args([
                "--site",
                SITE,
                "--hold-id",
                id,
                "--import-id",
                import,
                "--reason",
                "Owner incident review",
            ]);
            if let Some(digest) = approve {
                command.args(["--approve", digest]);
            }
            Ok(command.output()?)
        };
    let approve = |action: &str, id: &str, import: &str| -> TestResult {
        let preview = report(&hold(action, id, import, None)?)?;
        let digest = preview
            .path(&["result", "approval_digest"])?
            .text()?
            .to_owned();
        success(&hold(action, id, import, Some(&digest))?);
        Ok(())
    };
    // A hold on an import outside the scope does not block it.
    approve("place", "unrelated", &other)?;
    let unblocked = report(&delete_plan(&root, &["--sensor-id", "sensor:alpha"])?)?;
    assert_eq!(unblocked.get("status")?.text()?, "planned");
    approve("place", "incident", &second)?;

    // The plan computed before the hold is stale; the new plan is blocked by the member hold.
    let before = files(&root)?;
    for old in [&open_plan, &unblocked] {
        let stale = delete_commit(
            &root,
            old.get("plan_digest")?.text()?,
            old.get("approval_digest")?.text()?,
        )?;
        assert_eq!(refusal(&stale), "ERR-DELETION-PLAN-STALE-001");
    }
    let plan = report(&delete_plan(&root, &["--sensor-id", "sensor:alpha"])?)?;
    assert_eq!(plan.get("status")?.text()?, "blocked");
    assert_eq!(plan.get("approve_command")?, &Json::Null);
    assert_eq!(
        plan.get("hold_registry")?.text()?,
        "enforced_import_closure_v1"
    );
    let blockers: Vec<(String, String)> = plan
        .get("blockers")?
        .items()?
        .iter()
        .map(|b| {
            Ok((
                b.get("kind")?.text()?.to_owned(),
                b.get("subject")?.text()?.to_owned(),
            ))
        })
        .collect::<TestResult<_>>()?;
    assert_eq!(
        blockers,
        vec![("evidence_hold".to_owned(), "incident".to_owned())]
    );
    let refused = delete_commit(
        &root,
        plan.get("plan_digest")?.text()?,
        plan.get("approval_digest")?.text()?,
    )?;
    assert!(!refused.status.success());
    assert_eq!(refusal(&refused), "ERR-DELETION-BLOCKED-001");
    assert!(String::from_utf8_lossy(&refused.stderr).contains("incident"));
    assert_eq!(
        files(&root)?,
        before,
        "a blocked scoped commit writes nothing"
    );
    // The unheld member is not deleted through the scope either; both still verify.
    for member in [&first, &second] {
        success(&file(&root, "verify", &["--import-id", member])?);
    }

    // Releasing the member hold unblocks the scope, which then commits.
    approve("release", "incident", &second)?;
    let plan = report(&delete_plan(&root, &["--sensor-id", "sensor:alpha"])?)?;
    assert_eq!(plan.get("status")?.text()?, "planned");
    let committed = report(&delete_commit(
        &root,
        plan.get("plan_digest")?.text()?,
        plan.get("approval_digest")?.text()?,
    )?)?;
    assert_eq!(committed.get("outcome")?.text()?, "completed");
    success(&file(&root, "verify", &["--import-id", &other])?);
    Ok(())
}

#[test]
fn a_plan_whose_scope_was_tampered_with_is_refused() -> TestResult {
    let directory = OwnedDirectory::new("tamper")?;
    let root = directory.root();
    let (alpha, _) = import_named(&directory, &scene(Scene::Right)?, "sensor:alpha", "alpha")?;
    let (_gamma, _) = import_named(&directory, &scene(Scene::Left)?, "sensor:gamma", "gamma")?;
    let cx = context(&root)?;
    let (plan, import_plan) = {
        let deployment = open(&root, &cx)?;
        (
            plan_scope_deletion(
                &deployment,
                &DeletionScope::Sensor(SensorId::parse("sensor:alpha")?),
                &cx,
            )?,
            plan_deletion(&deployment, ContentDigest::parse(&alpha)?, &cx)?,
        )
    };
    assert_eq!(
        plan.imports, import_plan.imports,
        "one member, the same import"
    );
    assert_eq!(plan.deletable, import_plan.deletable, "the same closure");
    let digest = plan.digest()?;
    assert_ne!(
        digest,
        import_plan.digest()?,
        "a sensor plan is never the digest of an import plan"
    );
    assert_ne!(
        plan.record_object_id_of(digest),
        import_plan.record_object_id_of(import_plan.digest()?)
    );
    // Byte-level tamper: the same-length scope id of another sensor.
    let bytes = plan.canonical_bytes()?;
    let needle = b"sensor:alpha";
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .ok_or("scope id not in the plan bytes")?;
    let mut tampered = bytes.clone();
    tampered[at..at + needle.len()].copy_from_slice(b"sensor:gamma");
    assert!(
        DeletionPlan::decode(&tampered, digest).is_err(),
        "tampered bytes do not verify against the sealed digest"
    );
    let forged = DeletionPlan::decode(&tampered, ContentDigest::sha256(&tampered))?;
    assert_eq!(forged.scope.text(), "sensor:sensor:gamma");
    let mut rescoped = plan.clone();
    rescoped.scope = DeletionScope::Import(ContentDigest::parse(&alpha)?);
    assert!(
        rescoped.canonical_bytes().is_ok_and(|b| b != bytes),
        "the import kind has its own encoding"
    );
    let before = files(&root)?;
    for candidate in [forged, rescoped.clone()] {
        let candidate_digest = candidate.digest()?;
        if candidate_digest == import_plan.digest()? {
            // Re-scoping the sensor plan to its sole import is exactly the import plan: a
            // different, separately approved plan, never the sensor plan's approval.
            let mut deployment = open(&root, &cx)?;
            let wrong = commit_deletion(
                &mut deployment,
                candidate_digest,
                plan.approval_digest(PRINCIPAL)?,
                PRINCIPAL,
                &cx,
            );
            assert!(
                matches!(wrong, Err(DeletionError::ApprovalMismatch(_))),
                "{wrong:?}"
            );
            continue;
        }
        let mut deployment = open(&root, &cx)?;
        let result = commit_deletion(
            &mut deployment,
            candidate_digest,
            candidate.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &cx,
        );
        assert!(
            matches!(result, Err(DeletionError::StalePlan(_))),
            "a forged scope has no current plan: {result:?}"
        );
    }
    // The sensor plan's approval does not approve anything else, through the binary either.
    let wrong = delete_commit(
        &root,
        &import_plan.digest()?.to_text(),
        &plan.approval_digest(PRINCIPAL)?.to_text(),
    )?;
    assert_eq!(refusal(&wrong), "ERR-DELETION-APPROVAL-001");
    assert_eq!(files(&root)?, before, "refused commits write nothing");
    // The untampered plan commits.
    let committed = report(&delete_commit(
        &root,
        &digest.to_text(),
        &plan.approval_digest(PRINCIPAL)?.to_text(),
    )?)?;
    assert_eq!(committed.get("outcome")?.text()?, "completed");
    Ok(())
}

#[test]
fn an_interrupted_scoped_commit_resumes_and_completes_exactly_once() -> TestResult {
    let directory = OwnedDirectory::new("cuts")?;
    let base = directory.root();
    let (first, _) = import_named(&directory, &scene(Scene::Right)?, "sensor:alpha", "a1")?;
    let (second, _) = import_named(&directory, &scene(Scene::Quiet(80))?, "sensor:alpha", "a2")?;
    let (_other, _) = import_named(&directory, &scene(Scene::Quiet(60))?, "sensor:beta", "b")?;
    decoded(&base, &first)?;
    decoded(&base, &second)?;
    let plan = report(&delete_plan(&base, &["--sensor-id", "sensor:alpha"])?)?;
    let plan_digest = plan.get("plan_digest")?.text()?.to_owned();
    let approval = plan.get("approval_digest")?.text()?.to_owned();
    assert!(
        plan.path(&["tombstone_batch", "retractions"])?
            .items()?
            .len()
            >= 2
    );

    let reference = directory.0.join("reference");
    copy_tree(&base, &reference)?;
    let uninterrupted = report(&delete_commit(&reference, &plan_digest, &approval)?)?;
    let completion = uninterrupted.get("completion_digest")?.text()?.to_owned();
    let expected = files(&reference)?;

    for (index, stage) in DELETION_CUT_POINTS.iter().enumerate() {
        let copy = directory.0.join(format!("cut-{index}"));
        copy_tree(&base, &copy)?;
        {
            let cx = context(&copy)?;
            cx.set_cancel_at_checkpoint(stage);
            let mut deployment = open(&copy, &cx)?;
            match commit_deletion(
                &mut deployment,
                ContentDigest::parse(&plan_digest)?,
                ContentDigest::parse(&approval)?,
                PRINCIPAL,
                &cx,
            ) {
                Err(DeletionError::Cancelled { stage: reached }) => assert_eq!(reached, *stage),
                other => {
                    return Err(format!("{stage}: expected an interruption, got {other:?}").into());
                }
            }
        }
        if index >= 2 {
            // The record is durable: both members already read `deleted`.
            for member in [&first, &second] {
                assert_eq!(
                    refusal(&file(&copy, "verify", &["--import-id", member])?),
                    "ERR-EVIDENCE-DELETED-001",
                    "{stage}"
                );
            }
        }
        let resumed = report(&delete_commit(&copy, &plan_digest, &approval)?)?;
        let outcome = resumed.get("outcome")?.text()?;
        assert_eq!(
            outcome,
            if index < 2 { "completed" } else { "resumed" },
            "{stage}"
        );
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

#[test]
fn the_plan_scope_is_exactly_one_of_import_sensor_or_event() -> TestResult {
    let directory = OwnedDirectory::new("arguments")?;
    let root = directory.root();
    let (alpha, _) = import_named(&directory, &scene(Scene::Right)?, "sensor:alpha", "alpha")?;
    let before = files(&root)?;
    for (args, reason) in [
        (
            vec!["--import-id", alpha.as_str(), "--sensor-id", "sensor:alpha"],
            "mutually exclusive",
        ),
        (
            vec!["--sensor-id", "sensor:alpha", "--event-id", "event:x"],
            "mutually exclusive",
        ),
        (
            vec![],
            "required option --import-id, --sensor-id or --event-id",
        ),
        (vec!["--sensor-id", "not a sensor"], "invalid sensor ID"),
        (vec!["--event-id", "bad event!"], "invalid event ID"),
    ] {
        let output = delete_plan(&root, &args)?;
        assert!(!output.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("ERR-CLI-MALFORMED-VALUE-001"),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains(reason), "{args:?}: {stderr}");
    }
    // Scope options belong to plan, never to commit.
    let commit = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"])
        .arg(&root)
        .args([
            "--site",
            SITE,
            "--sensor-id",
            "sensor:alpha",
            "--plan",
            &ContentDigest::sha256(b"p").to_text(),
            "--approve",
            &ContentDigest::sha256(b"a").to_text(),
        ])
        .output()?;
    assert!(!commit.status.success());
    assert!(String::from_utf8_lossy(&commit.stderr).contains("unknown or inapplicable option"));
    // A sensor without retained imports is a typed empty scope.
    let empty = delete_plan(&root, &["--sensor-id", "sensor:nobody"])?;
    assert_eq!(refusal(&empty), "ERR-DELETION-SCOPE-EMPTY-001");
    // The import scope keeps its v1 plan and adds the scope fields.
    let plan = report(&delete_plan(&root, &["--import-id", &alpha])?)?;
    assert_eq!(plan.get("format")?.text()?, "fss.deletion_plan.v1");
    assert_eq!(plan.path(&["scope", "kind"])?.text()?, "import");
    assert_eq!(plan.get("import_identity")?.text()?, alpha);
    assert_eq!(texts(plan.get("imports")?)?, vec![alpha.clone()]);
    assert_eq!(files(&root)?, before, "nothing was written");
    Ok(())
}
