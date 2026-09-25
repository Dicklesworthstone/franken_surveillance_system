#![forbid(unsafe_code)]
//! Deletion holds (fss-nswce, PRIVACY.md 8.1) through the real binaries.
//!
//! 1. placement is approval-gated: a preview writes nothing, a wrong or stale approval is
//!    refused before any write, the exact approval retains one hold and a rerun writes nothing;
//! 2. an active hold on the import blocks `delete plan` and `delete commit`
//!    (`ERR-DELETION-BLOCKED-001` naming the hold id); its release is recorded (never erased) and
//!    unblocks; the released hold survives the deletion;
//! 3. an expired hold (on the deployment's evidence clock, advanced only by committed evidence)
//!    no longer blocks;
//! 4. a hold placed after planning makes the plan stale at commit;
//! 5. sensor and event scopes cover exactly the imports of the sensor and the imports whose
//!    closure reaches the event;
//! 6. every preview, plan and list is byte-for-byte deterministic, and identical deployments
//!    give identical hold identities.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;
const SITE: &str = "site:deletion-hold-cli";
const DOOR: &str = "door:64,0,32,32";
/// Operator capture-hint start of an import (ns); the evidence clock follows capture time.
const CAPTURE_NS: &str = "1000000000";

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-deletion-hold-cli-{name}-{}-{attempt}",
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

/// Fourteen grayscale MJPEG frames; with `moving`, a bright square crosses the door zone.
fn scene(moving: bool, level: u8) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![level; (WIDTH * HEIGHT) as usize];
        if moving && index >= 3 {
            let left = (index - 3) * 8;
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
    assert!(!output.status.success(), "expected a refusal");
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

/// Imports `bytes` for `sensor` with an operator capture hint starting at `capture_ns`
/// (14 frames at 10 fps), received at 10^13 ns.
fn import(
    directory: &OwnedDirectory,
    bytes: &[u8],
    sensor: &str,
    capture_ns: &str,
) -> TestResult<String> {
    let input = directory
        .0
        .join(format!("{}-{capture_ns}.mjpeg", sensor.replace(':', "-")));
    fs::write(&input, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{sensor}")])
        .args([
            "--media-format",
            "mjpeg",
            "--receive-time-ns",
            "10000000000000",
        ])
        .args(["--capture-start-ns", capture_ns])
        .args(["--capture-uncertainty-ns", "1000000"])
        .args(["--assumed-fps", "10"])
        .output()?;
    success(&output);
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?)
}

fn event(root: &Path, args: &[&str]) -> TestResult<Output> {
    let (first, rest) = args.split_first().ok_or("empty command")?;
    let (command, rest) = if matches!(*first, "hold" | "delete") {
        let (second, rest) = rest.split_first().ok_or("missing operation")?;
        (vec![*first, *second], rest)
    } else {
        (vec![*first], rest)
    };
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(command)
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(rest)
        .output()?)
}

fn place(root: &Path, scope: &str, extra: &[&str]) -> TestResult<Output> {
    let mut args = vec![
        "hold",
        "place",
        "--scope",
        scope,
        "--reason",
        "litigation hold: case 7",
    ];
    args.extend_from_slice(extra);
    event(root, &args)
}

/// Previews and places a hold on `scope`, returning its identity.
fn placed(root: &Path, scope: &str, extra: &[&str]) -> TestResult<String> {
    let preview = report(&place(root, scope, extra)?)?;
    assert_eq!(preview.get("status")?.text()?, "proposed");
    let approval = preview.get("approval_digest")?.text()?.to_owned();
    let mut approved = extra.to_vec();
    approved.extend_from_slice(&["--approve", &approval]);
    let retained = report(&place(root, scope, &approved)?)?;
    assert_eq!(retained.get("status")?.text()?, "retained");
    assert_eq!(
        retained.get("hold_id")?.text()?,
        preview.get("hold_id")?.text()?
    );
    Ok(retained.get("hold_id")?.text()?.to_owned())
}

fn release(root: &Path, hold_id: &str, approve: Option<&str>) -> TestResult<Output> {
    let mut args = vec!["hold", "release", "--hold-id", hold_id];
    if let Some(approval) = approve {
        args.extend_from_slice(&["--approve", approval]);
    }
    event(root, &args)
}

fn list(root: &Path) -> TestResult<Output> {
    event(root, &["hold", "list"])
}

fn plan(root: &Path, import_id: &str) -> TestResult<Output> {
    event(root, &["delete", "plan", "--import-id", import_id])
}

fn commit(root: &Path, plan: &str, approval: &str) -> TestResult<Output> {
    event(
        root,
        &["delete", "commit", "--plan", plan, "--approve", approval],
    )
}

/// Every regular file under `root` with its content digest.
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

/// The `kind`/`subject` pairs of a plan's blockers.
fn blockers(plan: &Json) -> TestResult<Vec<(String, String)>> {
    plan.get("blockers")?
        .items()?
        .iter()
        .map(|b| {
            Ok((
                b.get("kind")?.text()?.to_owned(),
                b.get("subject")?.text()?.to_owned(),
            ))
        })
        .collect()
}

/// The covering holds of a plan: (hold id, covered via, state, blocks).
fn covering(plan: &Json) -> TestResult<Vec<(String, String, String, bool)>> {
    plan.path(&["holds", "covering"])?
        .items()?
        .iter()
        .map(|h| {
            Ok((
                h.get("hold_id")?.text()?.to_owned(),
                h.get("covers_via")?.text()?.to_owned(),
                h.get("state")?.text()?.to_owned(),
                h.get("blocks")? == &Json::Bool(true),
            ))
        })
        .collect()
}

/// State of `hold_id` in `hold list`.
fn listed_state(root: &Path, hold_id: &str) -> TestResult<String> {
    let listed = report(&list(root)?)?;
    for hold in listed.get("holds")?.items()? {
        if hold.get("hold_id")?.text()? == hold_id {
            return Ok(hold.get("state")?.text()?.to_owned());
        }
    }
    Err(format!("{hold_id} not listed").into())
}

fn evidence_clock(root: &Path) -> TestResult<u64> {
    report(&list(root)?)?.get("evidence_clock_ns")?.number()
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_import_hold_is_approval_gated_blocks_until_released_and_survives_deletion() -> TestResult {
    let directory = OwnedDirectory::new("import")?;
    let root = directory.root();
    let a = import(&directory, &scene(false, 60)?, "sensor:alpha", CAPTURE_NS)?;
    let scope = format!("import:{a}");

    // 1. The preview writes nothing and is deterministic.
    let before = files(&root)?;
    let preview = place(&root, &scope, &[])?;
    success(&preview);
    assert_eq!(files(&root)?, before, "a preview writes nothing");
    assert_eq!(place(&root, &scope, &[])?.stdout, preview.stdout);
    let preview = report(&preview)?;
    assert_eq!(preview.get("status")?.text()?, "proposed");
    assert_eq!(preview.get("writes")?.text()?, "none");
    assert_eq!(preview.get("scope_kind")?.text()?, "import");
    assert_eq!(
        preview.get("clock")?.text()?,
        "deployment_evidence_clock_not_wall_time"
    );
    let approval = preview.get("approval_digest")?.text()?.to_owned();
    let hold_id = preview.get("hold_id")?.text()?.to_owned();
    assert!(preview.get("approve_command")?.text()?.contains(&approval));

    // A wrong approval is refused before any write.
    let wrong = ContentDigest::sha256(b"not the approval").to_text();
    let refused = place(&root, &scope, &["--approve", &wrong])?;
    assert_eq!(refusal(&refused), "ERR-DELETION-HOLD-APPROVAL-STALE-001");
    assert_eq!(files(&root)?, before, "a refused placement writes nothing");
    // Invalid requests are refused before any write.
    for (bad_scope, reason) in [
        (
            "import:sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "x",
        ),
        ("event:event:no-such-event", "x"),
        ("camera:alpha", "x"),
        (scope.as_str(), ""),
    ] {
        let refused = event(
            &root,
            &["hold", "place", "--scope", bad_scope, "--reason", reason],
        )?;
        assert!(!refused.status.success(), "{bad_scope}");
    }
    assert_eq!(files(&root)?, before);

    // The exact approval retains one hold; the rerun writes nothing.
    let retained = report(&place(&root, &scope, &["--approve", &approval])?)?;
    assert_eq!(retained.get("status")?.text()?, "retained");
    assert_eq!(retained.get("hold_id")?.text()?, hold_id);
    let held = files(&root)?;
    let rerun = report(&place(&root, &scope, &["--approve", &approval])?)?;
    assert_eq!(rerun.get("status")?.text()?, "already_retained");
    assert_eq!(files(&root)?, held, "a rerun writes nothing");
    assert_eq!(listed_state(&root, &hold_id)?, "active");

    // 2. The active hold blocks the plan and the commit, naming the hold.
    let blocked = report(&plan(&root, &a)?)?;
    assert_eq!(blocked.get("status")?.text()?, "blocked");
    assert_eq!(blocked.get("hold_registry")?.text()?, "ledger");
    assert_eq!(
        blockers(&blocked)?,
        vec![("active_hold".to_owned(), hold_id.clone())]
    );
    assert_eq!(
        covering(&blocked)?,
        vec![(
            hold_id.clone(),
            "import".to_owned(),
            "active".to_owned(),
            true
        )]
    );
    assert_eq!(blocked.get("approve_command")?, &Json::Null);
    let plan_digest = blocked.get("plan_digest")?.text()?.to_owned();
    let plan_approval = blocked.get("approval_digest")?.text()?.to_owned();
    let refused = commit(&root, &plan_digest, &plan_approval)?;
    assert_eq!(refusal(&refused), "ERR-DELETION-BLOCKED-001");
    assert!(String::from_utf8_lossy(&refused.stderr).contains(&hold_id));
    assert_eq!(files(&root)?, held, "a blocked commit writes nothing");

    // The release is approval-gated and recorded as a new generation.
    let preview = report(&release(&root, &hold_id, None)?)?;
    assert_eq!(preview.get("status")?.text()?, "proposed");
    assert_eq!(files(&root)?, held);
    let release_approval = preview.get("approval_digest")?.text()?.to_owned();
    assert_eq!(
        refusal(&release(&root, &hold_id, Some(&wrong))?),
        "ERR-DELETION-HOLD-APPROVAL-STALE-001"
    );
    assert_eq!(files(&root)?, held);
    let released = report(&release(&root, &hold_id, Some(&release_approval))?)?;
    assert_eq!(released.get("status")?.text()?, "retained");
    assert_eq!(released.get("placement_record")?.text()?, "retained");
    assert_eq!(released.path(&["hold", "state"])?.text()?, "released");
    let after_release = files(&root)?;
    let again = report(&release(&root, &hold_id, Some(&release_approval))?)?;
    assert_eq!(again.get("status")?.text()?, "already_retained");
    assert_eq!(
        report(&release(&root, &hold_id, None)?)?
            .get("status")?
            .text()?,
        "already_released"
    );
    assert_eq!(files(&root)?, after_release);
    assert_eq!(
        refusal(&release(
            &root,
            &ContentDigest::sha256(b"unknown hold").to_text(),
            None
        )?),
        "ERR-DELETION-HOLD-001"
    );

    // Released: the plan is unblocked and still names the (non-blocking) hold.
    let planned = report(&plan(&root, &a)?)?;
    assert_eq!(planned.get("status")?.text()?, "planned");
    assert!(blockers(&planned)?.is_empty());
    assert_eq!(
        covering(&planned)?,
        vec![(
            hold_id.clone(),
            "import".to_owned(),
            "released".to_owned(),
            false
        )]
    );
    // The hold records are authority history of the import, kept by the deletion.
    let units = planned.get("units")?.items()?;
    let hold_units: Vec<(&str, &str)> = units
        .iter()
        .filter(|u| {
            u.get("kind")
                .and_then(Json::text)
                .is_ok_and(|k| k == "deletion_hold")
        })
        .map(|u| Ok((u.get("id")?.text()?, u.get("class")?.text()?)))
        .collect::<TestResult<_>>()?;
    assert!(!hold_units.is_empty());
    assert!(
        hold_units
            .iter()
            .all(|(_, class)| *class == "authority_history")
    );
    let committed = report(&commit(
        &root,
        planned.get("plan_digest")?.text()?,
        planned.get("approval_digest")?.text()?,
    )?)?;
    assert_eq!(committed.get("outcome")?.text()?, "completed");
    // Release is recorded, never erased: both records survive the deletion.
    let listed = report(&list(&root)?)?;
    let holds = listed.get("holds")?.items()?;
    assert_eq!(holds.len(), 1);
    assert_eq!(holds[0].get("state")?.text()?, "released");
    assert!(
        holds[0]
            .get("release_record")?
            .text()?
            .starts_with("sha256:")
    );
    assert!(listed.get("unreadable")?.items()?.is_empty());
    // A deleted import cannot be held.
    assert_eq!(
        refusal(&place(&root, &scope, &[])?),
        "ERR-EVIDENCE-DELETED-001"
    );
    Ok(())
}

#[test]
fn an_expired_hold_stops_blocking_when_the_evidence_clock_passes_it() -> TestResult {
    let directory = OwnedDirectory::new("expiry")?;
    let root = directory.root();
    let a = import(&directory, &scene(false, 60)?, "sensor:alpha", CAPTURE_NS)?;
    let clock = evidence_clock(&root)?;
    assert!(
        clock > 0,
        "the evidence clock is the latest committed evidence time"
    );
    // An expiry at or before the evidence clock would never block: refused.
    let stale = clock.to_string();
    assert_eq!(
        refusal(&place(
            &root,
            &format!("import:{a}"),
            &["--expires-at-ns", &stale]
        )?),
        "ERR-DELETION-HOLD-001"
    );
    let expiry = (clock + 1_000_000).to_string();
    let hold_id = placed(&root, &format!("import:{a}"), &["--expires-at-ns", &expiry])?;
    let blocked = report(&plan(&root, &a)?)?;
    assert_eq!(blocked.get("status")?.text()?, "blocked");
    assert_eq!(blockers(&blocked)?[0].1, hold_id);
    // Placing a hold and planning commit no evidence: the clock has not moved.
    assert_eq!(evidence_clock(&root)?, clock);
    assert_eq!(listed_state(&root, &hold_id)?, "active");

    // Later evidence (an import captured 50 s later) moves the clock past the expiry.
    import(&directory, &scene(false, 90)?, "sensor:beta", "50000000000")?;
    let later = evidence_clock(&root)?;
    assert!(later >= clock + 1_000_000, "{later} vs {clock}");
    assert_eq!(listed_state(&root, &hold_id)?, "expired");
    let planned = report(&plan(&root, &a)?)?;
    assert_eq!(planned.get("status")?.text()?, "planned");
    assert!(blockers(&planned)?.is_empty());
    assert_eq!(
        covering(&planned)?,
        vec![(hold_id, "import".to_owned(), "expired".to_owned(), false)]
    );
    Ok(())
}

#[test]
fn a_hold_placed_after_planning_makes_the_commit_stale() -> TestResult {
    let directory = OwnedDirectory::new("stale")?;
    let root = directory.root();
    let a = import(&directory, &scene(false, 60)?, "sensor:alpha", CAPTURE_NS)?;
    let b = import(&directory, &scene(false, 90)?, "sensor:beta", CAPTURE_NS)?;
    let planned = report(&plan(&root, &a)?)?;
    assert_eq!(planned.get("status")?.text()?, "planned");
    let plan_digest = planned.get("plan_digest")?.text()?.to_owned();
    let approval = planned.get("approval_digest")?.text()?.to_owned();

    // A sensor hold on the import's sensor, placed after planning.
    let hold_id = placed(&root, "sensor:sensor:alpha", &[])?;
    let before = files(&root)?;
    assert_eq!(
        refusal(&commit(&root, &plan_digest, &approval)?),
        "ERR-DELETION-PLAN-STALE-001"
    );
    assert_eq!(files(&root)?, before, "a stale commit writes nothing");
    // Planning again reports the hold as the blocker.
    let blocked = report(&plan(&root, &a)?)?;
    assert_eq!(blocked.get("status")?.text()?, "blocked");
    assert_eq!(
        covering(&blocked)?,
        vec![(
            hold_id.clone(),
            "sensor".to_owned(),
            "active".to_owned(),
            true
        )]
    );
    // It does not cover another sensor's import.
    let other = report(&plan(&root, &b)?)?;
    assert_eq!(other.get("status")?.text()?, "planned");
    assert!(covering(&other)?.is_empty());

    // A preview approved after the head moved is stale too.
    let preview = report(&place(&root, "sensor:sensor:beta", &[])?)?;
    let old = preview.get("approval_digest")?.text()?.to_owned();
    import(&directory, &scene(false, 120)?, "sensor:gamma", CAPTURE_NS)?;
    let moved = files(&root)?;
    assert_eq!(
        refusal(&place(&root, "sensor:sensor:beta", &["--approve", &old])?),
        "ERR-DELETION-HOLD-APPROVAL-STALE-001"
    );
    assert_eq!(files(&root)?, moved);
    Ok(())
}

#[test]
fn an_event_hold_covers_every_import_whose_closure_reaches_the_event() -> TestResult {
    let directory = OwnedDirectory::new("event")?;
    let root = directory.root();
    let a = import(&directory, &scene(true, 40)?, "sensor:alpha", CAPTURE_NS)?;
    let b = import(&directory, &scene(false, 60)?, "sensor:beta", CAPTURE_NS)?;
    let watch = |extra: &[&str]| -> TestResult<Json> {
        let mut args = vec![
            "watch",
            "--import-id",
            a.as_str(),
            "--interpretation",
            "gray",
            "--zone",
            DOOR,
        ];
        args.extend_from_slice(extra);
        report(&event(&root, &args)?)
    };
    let preview = watch(&[])?;
    let candidate = &preview.get("candidates")?.items()?[0];
    let event_id = candidate.get("event_id")?.text()?.to_owned();
    let proposal = candidate.get("proposal_digest")?.text()?.to_owned();
    watch(&["--approve", &proposal])?;

    let hold_id = placed(&root, &format!("event:{event_id}"), &[])?;
    let blocked = report(&plan(&root, &a)?)?;
    assert_eq!(blocked.get("status")?.text()?, "blocked");
    assert_eq!(
        blockers(&blocked)?,
        vec![("active_hold".to_owned(), hold_id.clone())]
    );
    assert_eq!(
        covering(&blocked)?,
        vec![(
            hold_id.clone(),
            "event".to_owned(),
            "active".to_owned(),
            true
        )]
    );
    let unrelated = report(&plan(&root, &b)?)?;
    assert_eq!(unrelated.get("status")?.text()?, "planned");
    assert!(covering(&unrelated)?.is_empty());
    let listed = report(&list(&root)?)?;
    assert_eq!(
        listed.get("holds")?.items()?[0].get("scope_kind")?.text()?,
        "event"
    );
    Ok(())
}

#[test]
fn holds_plans_and_lists_are_deterministic() -> TestResult {
    let mut outputs = Vec::new();
    for name in ["determinism-1", "determinism-2"] {
        let directory = OwnedDirectory::new(name)?;
        let root = directory.root();
        let a = import(&directory, &scene(false, 60)?, "sensor:alpha", CAPTURE_NS)?;
        let hold_id = placed(
            &root,
            &format!("import:{a}"),
            &["--expires-at-ns", "99000000000000"],
        )?;
        let sensor_hold = placed(&root, "sensor:sensor:alpha", &[])?;
        let first = plan(&root, &a)?;
        success(&first);
        assert_eq!(
            plan(&root, &a)?.stdout,
            first.stdout,
            "plan is deterministic"
        );
        let listed = list(&root)?;
        success(&listed);
        assert_eq!(list(&root)?.stdout, listed.stdout, "list is deterministic");
        let preview = place(&root, "sensor:sensor:beta", &[])?;
        success(&preview);
        assert_eq!(
            place(&root, "sensor:sensor:beta", &[])?.stdout,
            preview.stdout
        );
        let planned = report(&first)?;
        outputs.push((
            a,
            hold_id,
            sensor_hold,
            planned.get("plan_digest")?.text()?.to_owned(),
            listed.stdout,
        ));
    }
    assert_eq!(
        outputs[0], outputs[1],
        "identical deployments, identical holds"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Minimal JSON reader.
// ---------------------------------------------------------------------------------------------

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
