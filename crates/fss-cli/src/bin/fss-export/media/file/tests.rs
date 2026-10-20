#![forbid(unsafe_code)]
//! Faults at the actual filesystem publication boundary, without a simulated writer.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    deployment: PathBuf,
    output: PathBuf,
}
impl Fixture {
    fn new() -> RunResult<Self> {
        let directory = std::env::temp_dir().join(format!(
            "fss-original-media-file-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let deployment = directory.join("deployment");
        fs::create_dir(&deployment)?;
        let output = directory.join("export");
        Ok(Self {
            directory,
            deployment,
            output,
        })
    }
    fn target(&self) -> Result<Target, FileError> {
        Target::new(&self.output, &self.deployment)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn files<'a>(media: &'a [u8]) -> [(&'static str, &'a [u8]); 4] {
    [
        ("source.mp4", media),
        ("record.canonical", b"record"),
        ("manifest.canonical", b"manifest"),
        ("record.json", b"{\"record\":true}"),
    ]
}

#[test]
fn completed_output_has_exact_bytes_private_modes_and_idempotent_retry() -> RunResult<()> {
    if !supported() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let target = fixture.target()?;
    let binding = target.binding()?;
    assert!(!fixture.output.exists());
    let payload = vec![0x5a; IO_CHUNK * 2 + 3];
    let receipt = publish(&target, &files(&payload), b"complete", |_| Ok(()))?;
    assert!(!receipt.already_present);
    assert_eq!(binding, target.binding()?);
    let input = Input::open(&fixture.output)?;
    assert_eq!(input.read("source.mp4", payload.len())?, payload);
    assert_eq!(
        input.media(payload.len())?,
        ("source.mp4".into(), payload.clone())
    );
    assert_eq!(input.read("COMPLETE.json", 64)?, b"complete");
    assert!(publish(&target, &files(&payload), b"complete", |_| Ok(()))?.already_present);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&fixture.output)?.permissions().mode() & 0o777,
            0o700
        );
        for name in [
            "source.mp4",
            "record.canonical",
            "manifest.canonical",
            "record.json",
            "COMPLETE.json",
        ] {
            assert_eq!(
                fs::metadata(fixture.output.join(name))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    Ok(())
}

#[test]
fn final_authority_refusal_never_publishes_completion_or_adopts_partial_directory() -> RunResult<()>
{
    if !supported() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let target = fixture.target()?;
    let result = publish(&target, &files(b"exact source"), b"complete", |stage| {
        if stage == "original_media:file_publish" {
            return Err(io::Error::other("authority changed").into());
        }
        Ok(())
    });
    assert!(result.is_err());
    assert!(fixture.output.join("source.mp4").exists());
    assert!(!fixture.output.join("COMPLETE.json").exists());
    assert!(publish(&target, &files(b"exact source"), b"complete", |_| Ok(())).is_err());
    assert!(!fixture.output.join("COMPLETE.json").exists());
    Ok(())
}

#[test]
fn cancellation_before_mkdir_has_no_output_and_during_write_has_no_completion() -> RunResult<()> {
    if !supported() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let target = fixture.target()?;
    assert!(
        publish(&target, &files(b"source"), b"complete", |_| Err(
            io::Error::other("cancelled").into()
        ))
        .is_err()
    );
    assert!(!fixture.output.exists());
    let mut writes = 0;
    let payload = vec![0x7c; 2 * IO_CHUNK + 1];
    assert!(
        publish(&target, &files(&payload), b"complete", |stage| {
            if stage == "original_media:file_write" {
                writes += 1;
                if writes == 2 {
                    return Err(io::Error::other("cancelled").into());
                }
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(
        fs::metadata(fixture.output.join("source.mp4"))?.len(),
        IO_CHUNK as u64
    );
    assert!(!fixture.output.join("COMPLETE.json").exists());
    Ok(())
}

#[test]
fn altered_complete_payload_is_never_overwritten_on_retry() -> RunResult<()> {
    if !supported() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let target = fixture.target()?;
    publish(&target, &files(b"source"), b"complete", |_| Ok(()))?;
    fs::write(fixture.output.join("source.mp4"), b"forged")?;
    assert!(publish(&target, &files(b"source"), b"complete", |_| Ok(())).is_err());
    assert_eq!(fs::read(fixture.output.join("source.mp4"))?, b"forged");
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinks_and_second_media_file_are_refused() -> RunResult<()> {
    if !supported() {
        return Ok(());
    }
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new()?;
    let target = fixture.target()?;
    symlink(&fixture.deployment, &fixture.output)?;
    assert!(publish(&target, &files(b"source"), b"complete", |_| Ok(())).is_err());
    fs::remove_file(&fixture.output)?;
    publish(&target, &files(b"source"), b"complete", |_| Ok(()))?;
    fs::write(fixture.output.join("source.mjpeg"), b"another source")?;
    let input = Input::open(&fixture.output)?;
    assert!(input.media(1024).is_err());
    assert!(publish(&target, &files(b"source"), b"complete", |_| Ok(())).is_err());
    Ok(())
}

#[test]
fn destination_inode_replacement_invalidates_exact_approval_binding() -> RunResult<()> {
    if !supported() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let parent = fixture.directory.join("handoff");
    fs::create_dir(&parent)?;
    let path = parent.join("export");
    let target = Target::new(&path, &fixture.deployment)?;
    let binding = target.binding()?;
    fs::rename(&parent, fixture.directory.join("old-handoff"))?;
    fs::create_dir(&parent)?;
    assert!(target.binding().is_err());
    assert_ne!(Target::new(&path, &fixture.deployment)?.binding()?, binding);
    assert!(publish(&target, &files(b"source"), b"complete", |_| Ok(())).is_err());
    assert!(!path.exists());
    Ok(())
}

#[test]
fn parent_replacement_after_mkdir_cannot_redirect_original_bytes() -> RunResult<()> {
    if !supported() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let parent = fixture.directory.join("handoff");
    fs::create_dir(&parent)?;
    let output = parent.join("export");
    let target = Target::new(&output, &fixture.deployment)?;
    let moved = fixture.directory.join("old-handoff");
    let result = publish(
        &target,
        &files(b"private original source"),
        b"complete",
        |stage| {
            if stage == "original_media:directory_created" {
                fs::rename(&parent, &moved)?;
                fs::create_dir(&parent)?;
                fs::create_dir(&output)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
                }
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(fs::read_dir(output)?.count(), 0);
    assert_eq!(fs::read_dir(moved.join("export"))?.count(), 0);
    Ok(())
}

#[test]
fn destination_inside_deployment_and_metadata_over_budget_fail_before_output() -> RunResult<()> {
    if !supported() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    assert!(Target::new(&fixture.deployment.join("export"), &fixture.deployment).is_err());
    let target = fixture.target()?;
    let oversized = vec![0; MAX_METADATA_BYTES + 1];
    assert!(publish(&target, &files(b"source"), &oversized, |_| Ok(())).is_err());
    assert!(!fixture.output.exists());
    Ok(())
}
