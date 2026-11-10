#![forbid(unsafe_code)]
//! Real cold CLI publication and private disclosure over a retained native movie fixture.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_container::demux::{AvcMp4, DemuxLimits};
use fss_core::json_input::{self, Value};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
    StreamId, TimestampNs,
};
use fss_reference::ingest::privacy_mask::{
    PrivacyMaskPolicy, current_mask, declare_mask, preview_mask,
};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_reference::{ReferenceDeployment, ReplayCx};

#[path = "delivery_tests.rs"]
mod durable_delivery;

type Test<T = ()> = Result<T, Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
const SITE: &str = "site:review-cli";
const SENSOR: &str = "sensor:review-cli";
const SOURCE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-container/tests/fixtures/indexed_avc.mp4"
));

struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        let path = std::env::temp_dir().join(format!(
            "fss-review-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn json_field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| io::Error::other("missing CLI JSON field").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    json_field(value, key)?
        .text()
        .ok_or_else(|| io::Error::other("CLI JSON field is not text").into())
}
fn run(args: &[OsString]) -> Test<Value> {
    let options = super::options::parse(args).map_err(io::Error::other)?;
    Ok(json_input::parse(&super::execute::run(&options)?)?)
}
fn args(root: &Path, action: &str, extra: &[&str]) -> Vec<OsString> {
    let mut args = vec![
        action.into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
    ];
    args.extend(extra.iter().map(OsString::from));
    args
}
fn approved(mut args: Vec<OsString>, preview: &Value) -> Test<Vec<OsString>> {
    args.extend(["--approve".into(), text(preview, "approval_digest")?.into()]);
    Ok(args)
}

fn imported(directory: &Directory) -> Test<(PathBuf, Vec<OsString>)> {
    let root = directory.0.join("deployment");
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:review-cli-import".into(),
        operation_id: OperationId::parse("operation:review-cli-import")?,
        principal: "principal:local-operator".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "ADP-FILE-001".into(),
            "adp:file:001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(131_072)
            .build()?,
        privacy_scope: "privacy:screened-review-media-v1".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let input = directory.0.join("source.mp4");
    fs::write(&input, SOURCE)?;
    let source = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &input,
            SensorId::parse(SENSOR)?,
            StreamId::parse("stream:review-cli")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000)),
        &cx,
        &mut deployment,
    )?;
    fs::remove_file(&input)?;
    let [width, height] = AvcMp4::parse(SOURCE, None, DemuxLimits::default())?.dimensions();
    let dimensions = [u32::from(width), u32::from(height)];
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse(SENSOR)?,
        dimensions,
        &[[0, 0, dimensions[0] / 2, dimensions[1]]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    let privacy = current_mask(&deployment, &SensorId::parse(SENSOR)?)?.digest();
    let request = args(
        &root,
        "review",
        &[
            "--import-identity",
            &source.import_identity.to_text(),
            "--expected-import-root",
            &source.import_root.to_text(),
            "--sensor",
            SENSOR,
            "--movie-start-tick",
            "400",
            "--movie-end-tick",
            "800",
            "--privacy-digest",
            &privacy.to_text(),
            "--recipient",
            "principal:reviewer",
            "--purpose",
            "Screened incident review",
            "--issued-at-ns",
            "10",
            "--expires-at-ns",
            "100",
            "--max-media-bytes",
            "1048576",
        ],
    );
    drop(deployment);
    cx.drain_and_finalize();
    Ok((root, request))
}

fn delivery(root: &Path, review: &str, output: &Path, principal: &str, now: &str) -> Vec<OsString> {
    let mut values = args(
        root,
        "review-read",
        &[
            "--review-root",
            review,
            "--principal",
            principal,
            "--attested-now-ns",
            now,
        ],
    );
    values.extend(["--out".into(), output.as_os_str().to_owned()]);
    values
}

#[test]
fn cold_review_cli_publishes_delivers_exact_private_bytes_and_revokes_future_reads() -> Test {
    let directory = Directory::new()?;
    let (root, request) = imported(&directory)?;
    let preview = run(&request)?;
    assert_eq!(text(&preview, "status")?, "awaiting_publication_approval");
    let review_root = text(&preview, "review_root")?.to_owned();
    let publish = approved(request, &preview)?;
    assert_eq!(text(&run(&publish)?, "status")?, "published");
    assert_eq!(text(&run(&publish)?, "status")?, "already_published");
    let show = args(&root, "review-show", &["--review-root", &review_root]);
    assert_eq!(
        json_field(&run(&show)?, "grant_revoked")?.boolean(),
        Some(false)
    );

    let output = directory.0.join("screened.mkv");
    let read = delivery(&root, &review_root, &output, "principal:reviewer", "20:30");
    let read_preview = run(&read)?;
    assert!(!output.exists(), "preview disclosed media");
    let approved_read = approved(read, &read_preview)?;
    let completed = run(&approved_read)?;
    assert_eq!(text(&completed, "status")?, "private_file_written");
    let bytes = fs::read(&output)?;
    assert!(bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]));
    assert_eq!(
        ContentDigest::sha256(&bytes).to_text(),
        text(&completed, "media_digest")?
    );
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        json_field(&completed, "delivery_receipt_in_deployment")?.boolean(),
        Some(true)
    );
    let verified_again = run(&approved_read)?;
    assert_eq!(text(&verified_again, "status")?, "private_file_verified");
    assert_eq!(
        json_field(&verified_again, "file_written")?.boolean(),
        Some(false)
    );
    assert_eq!(
        text(&verified_again, "delivery_record_digest")?,
        text(&completed, "delivery_record_digest")?
    );
    let delivery_show = args(
        &root,
        "review-delivery-show",
        &[
            "--delivery-id",
            text(&completed, "delivery_id")?,
            "--principal",
            "principal:reviewer",
        ],
    );
    assert_eq!(
        text(&run(&delivery_show)?, "delivery_state")?,
        "verified_local_file"
    );

    let revoke = args(&root, "review-revoke", &["--review-root", &review_root]);
    let revoke_preview = run(&revoke)?;
    let revoke = approved(revoke, &revoke_preview)?;
    assert_eq!(text(&run(&revoke)?, "status")?, "revoked");
    assert_eq!(text(&run(&revoke)?, "status")?, "already_revoked");
    assert_eq!(
        json_field(&run(&show)?, "grant_revoked")?.boolean(),
        Some(true)
    );
    let blocked = directory.0.join("after-revocation.mkv");
    assert!(
        run(&delivery(
            &root,
            &review_root,
            &blocked,
            "principal:reviewer",
            "20:30"
        ))
        .is_err()
    );
    assert!(!blocked.exists());
    assert_eq!(
        text(&run(&delivery_show)?, "delivery_state")?,
        "verified_local_file"
    );
    assert_eq!(
        fs::read(&output)?,
        bytes,
        "revocation cannot recall a prior copy"
    );
    Ok(())
}

#[test]
fn wrong_recipient_expiry_changed_destination_and_unsafe_paths_never_create_output() -> Test {
    let directory = Directory::new()?;
    let (root, request) = imported(&directory)?;
    let preview = run(&request)?;
    let review_root = text(&preview, "review_root")?.to_owned();
    run(&approved(request, &preview)?)?;
    let output = directory.0.join("refused.mkv");
    for (principal, now) in [
        ("principal:other", "20:30"),
        ("principal:reviewer", "9:20"),
        ("principal:reviewer", "90:100"),
    ] {
        assert!(run(&delivery(&root, &review_root, &output, principal, now)).is_err());
        assert!(!output.exists());
    }
    let prepare = delivery(&root, &review_root, &output, "principal:reviewer", "20:30");
    let preview = run(&prepare)?;
    assert!(
        run(&approved(
            delivery(&root, &review_root, &output, "principal:reviewer", "21:31"),
            &preview
        )?)
        .is_err(),
        "approval was reused for a different clock attestation"
    );
    let moved = directory.0.join("changed.mkv");
    assert!(
        run(&approved(
            delivery(&root, &review_root, &moved, "principal:reviewer", "20:30"),
            &preview
        )?)
        .is_err()
    );
    assert!(!moved.exists());
    assert!(!output.exists());
    let parent = directory.0.join("held-parent");
    fs::create_dir(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    let rebound_output = parent.join("screened.mkv");
    let rebound_request = delivery(
        &root,
        &review_root,
        &rebound_output,
        "principal:reviewer",
        "20:30",
    );
    let before_rebind = run(&rebound_request)?;
    fs::rename(&parent, directory.0.join("previous-parent"))?;
    fs::create_dir(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    assert!(run(&approved(rebound_request, &before_rebind)?).is_err());
    assert!(
        !rebound_output.exists(),
        "approval crossed a parent-directory identity change"
    );
    assert!(
        run(&delivery(
            &root,
            &review_root,
            &root.join("leaked.mkv"),
            "principal:reviewer",
            "20:30"
        ))
        .is_err()
    );
    assert!(!root.join("leaked.mkv").exists());
    let public = directory.0.join("public");
    fs::create_dir(&public)?;
    fs::set_permissions(&public, fs::Permissions::from_mode(0o777))?;
    assert!(
        run(&delivery(
            &root,
            &review_root,
            &public.join("leaked.mkv"),
            "principal:reviewer",
            "20:30"
        ))
        .is_err()
    );
    assert!(!public.join("leaked.mkv").exists());
    symlink(directory.0.join("uncreated-target"), &output)?;
    assert!(run(&prepare).is_err());
    assert!(!directory.0.join("uncreated-target").exists());
    Ok(())
}

#[test]
fn read_only_commands_never_bootstrap_a_missing_deployment() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("missing-deployment");
    let show = args(
        &root,
        "review-show",
        &[
            "--review-root",
            &ContentDigest::sha256(b"missing").to_text(),
        ],
    );
    assert!(run(&show).is_err());
    assert!(!root.exists());
    Ok(())
}
