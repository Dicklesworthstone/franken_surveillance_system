#![forbid(unsafe_code)]
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-package-file-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    fs::create_dir(path.join("deployment"))?;
                    fs::create_dir(path.join("handoff"))?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
    fn output(&self) -> PathBuf {
        self.0.join("handoff/case.fssp")
    }
    fn target(&self) -> Test<Target> {
        Ok(Target::new(&self.output(), &self.root())?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn publication_is_complete_private_create_only_and_exactly_idempotent() -> Test {
    let directory = Directory::new("complete")?;
    let target = directory.target()?;
    let bytes = b"complete deterministic package fixture";
    let first = publish(&target, bytes, |_| Ok(()))?;
    assert!(!first.already_present);
    assert!(!first.temporary_cleanup_pending);
    assert_eq!(fs::read(directory.output())?, bytes);
    let metadata = fs::metadata(directory.output())?;
    assert_eq!(metadata.mode() & 0o777, 0o600);
    let second = publish(&target, bytes, |_| Ok(()))?;
    assert!(second.already_present);
    assert_eq!(fs::metadata(directory.output())?.ino(), metadata.ino());
    assert_eq!(fs::read_dir(directory.0.join("handoff"))?.count(), 1);
    assert!(matches!(
        publish(&target, b"replacement", |_| Ok(())),
        Err(FileError::Conflict)
    ));
    assert_eq!(fs::read(directory.output())?, bytes);
    Ok(())
}

#[test]
fn cancellation_at_every_prepublication_boundary_never_exposes_a_partial_final_file() -> Test {
    for (index, stop) in [
        "export_package:file_begin",
        "export_package:file_staged",
        "export_package:file_written",
        "export_package:file_publish",
    ]
    .iter()
    .enumerate()
    {
        let directory = Directory::new(&format!("cancel-{index}"))?;
        let target = directory.target()?;
        let result = publish(&target, b"complete package", |stage| {
            if stage == *stop {
                Err(FileError::Cancelled)
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(FileError::Cancelled)));
        assert!(!directory.output().exists());
        assert_eq!(fs::read_dir(directory.0.join("handoff"))?.count(), 0);
        assert!(!publish(&target, b"complete package", |_| Ok(()))?.already_present);
        assert_eq!(fs::read(directory.output())?, b"complete package");
    }
    Ok(())
}

#[test]
fn files_directories_and_dangling_symlinks_are_never_replaced() -> Test {
    for (index, kind) in ["file", "directory", "symlink"].iter().enumerate() {
        let directory = Directory::new(&format!("conflict-{index}"))?;
        let target = directory.target()?;
        match *kind {
            "file" => fs::write(directory.output(), b"do not overwrite")?,
            "directory" => fs::create_dir(directory.output())?,
            _ => symlink("missing-target", directory.output())?,
        }
        let before = fs::symlink_metadata(directory.output())?;
        assert!(matches!(
            publish(&target, b"new package", |_| Ok(())),
            Err(FileError::Conflict)
        ));
        let after = fs::symlink_metadata(directory.output())?;
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.file_type(), before.file_type());
        if *kind == "file" {
            assert_eq!(fs::read(directory.output())?, b"do not overwrite");
        }
    }
    Ok(())
}

#[test]
fn a_competing_final_name_between_preflight_and_publication_is_not_overwritten() -> Test {
    let directory = Directory::new("raced-file")?;
    let target = directory.target()?;
    let result = publish(&target, b"package", |stage| {
        if stage == "export_package:file_publish" {
            fs::write(directory.output(), b"competing file")?;
        }
        Ok(())
    });
    assert!(matches!(result, Err(FileError::Conflict)));
    assert_eq!(fs::read(directory.output())?, b"competing file");
    assert_eq!(fs::read_dir(directory.0.join("handoff"))?.count(), 1);
    Ok(())
}

#[test]
fn exact_competing_publication_is_an_idempotent_existing_file() -> Test {
    let directory = Directory::new("raced-identical")?;
    let target = directory.target()?;
    let receipt = publish(&target, b"package", |stage| {
        if stage == "export_package:file_publish" {
            fs::write(directory.output(), b"package")?;
        }
        Ok(())
    })?;
    assert!(receipt.already_present);
    assert!(!receipt.temporary_cleanup_pending);
    assert_eq!(fs::read_dir(directory.0.join("handoff"))?.count(), 1);
    Ok(())
}

#[test]
fn replaced_output_directory_is_refused_before_any_final_write() -> Test {
    let directory = Directory::new("replaced")?;
    let target = directory.target()?;
    fs::rename(directory.0.join("handoff"), directory.0.join("old-handoff"))?;
    fs::create_dir(directory.0.join("handoff"))?;
    assert!(publish(&target, b"package", |_| Ok(())).is_err());
    assert!(!directory.output().exists());
    assert!(!directory.0.join("old-handoff/case.fssp").exists());
    Ok(())
}

#[test]
fn rename_at_visibility_never_redirects_bytes_to_a_replacement_directory() -> Test {
    let directory = Directory::new("renamed-at-link")?;
    let target = directory.target()?;
    let result = publish(&target, b"complete package", |stage| {
        if stage == "export_package:file_publish" {
            fs::rename(
                directory.0.join("handoff"),
                directory.0.join("approved-directory"),
            )?;
            fs::create_dir(directory.0.join("handoff"))?;
        }
        Ok(())
    });
    assert!(matches!(result, Err(FileError::PublicationIndeterminate)));
    assert!(
        !directory.output().exists(),
        "replacement directory received no bytes"
    );
    assert_eq!(
        fs::read(directory.0.join("approved-directory/case.fssp"))?,
        b"complete package"
    );
    Ok(())
}

#[test]
fn output_inside_deployment_or_in_a_writable_shared_directory_is_refused() -> Test {
    let directory = Directory::new("placement")?;
    assert!(matches!(
        Target::new(&directory.root().join("case.fssp"), &directory.root()),
        Err(FileError::InvalidOutput)
    ));
    symlink(directory.root(), directory.0.join("alias"))?;
    assert!(matches!(
        Target::new(&directory.0.join("alias/case.fssp"), &directory.root()),
        Err(FileError::InvalidOutput)
    ));
    fs::set_permissions(
        directory.0.join("handoff"),
        fs::Permissions::from_mode(0o777),
    )?;
    assert!(matches!(directory.target(), Err(_)));
    assert!(!directory.output().exists());
    Ok(())
}

#[test]
fn bounded_reader_refuses_oversize_special_and_symlink_inputs() -> Test {
    let directory = Directory::new("reader")?;
    fs::write(directory.output(), b"12345")?;
    assert_eq!(read_bounded(&directory.output(), 5)?, b"12345");
    assert!(read_bounded(&directory.output(), 4).is_err());
    assert!(read_bounded(&directory.root(), 100).is_err());
    let alias = directory.0.join("alias.fssp");
    symlink(directory.output(), &alias)?;
    assert!(read_bounded(&alias, 100).is_err());
    Ok(())
}
