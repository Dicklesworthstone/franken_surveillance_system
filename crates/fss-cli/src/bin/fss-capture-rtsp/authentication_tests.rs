#![forbid(unsafe_code)]

use super::*;

#[test]
fn credential_record_is_exact_bounded_and_never_decodes_extra_lines() {
    assert_eq!(
        credential_ranges(b"camera\npassword:with:colons\n"),
        Ok((6, 27))
    );
    assert_eq!(credential_ranges(b"camera\n\n"), Ok((6, 7)));
    let maximum = format!("{}\n{}\n", "u".repeat(256), "p".repeat(1024));
    assert!(credential_ranges(maximum.as_bytes()).is_ok());
    for bytes in [
        b"".as_slice(),
        b"user\n",
        b"\npassword\n",
        b"user\npassword",
        b"user\npassword\nextra\n",
        b"user:role\npassword\n",
        b"user\r\npassword\r\n",
        b"user\npassword\0\n",
        b"user\n\xff\n",
    ] {
        assert_eq!(credential_ranges(bytes), Err(SecretError::Credentials));
    }
    for bytes in [
        format!("{}\np\n", "u".repeat(257)),
        format!("u\n{}\n", "p".repeat(1025)),
    ] {
        assert_eq!(
            credential_ranges(bytes.as_bytes()),
            Err(SecretError::Credentials)
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct Fixture {
        directory: PathBuf,
        path: PathBuf,
    }
    impl Fixture {
        fn new() -> Test<Self> {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let directory = std::env::temp_dir().join(format!(
                "fss-rtsp-credential-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
            let path = directory.join("credential");
            fs::write(&path, b"unit-user\nunit-password\n")?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            Ok(Self { directory, path })
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn private_file_resolves_and_credentials_debug_is_redacted() -> Test {
        let fixture = Fixture::new()?;
        let lease = CredentialLease::load(&fixture.path, &|| Ok(()))?;
        lease.revalidate(&|| Ok(()))?;
        assert_eq!(
            format!("{:?}", lease.credentials()?),
            "DigestCredentials([REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn credential_source_refuses_symlink_hardlink_public_mode_and_oversize() -> Test {
        let fixture = Fixture::new()?;
        let link = fixture.directory.join("link");
        symlink(&fixture.path, &link)?;
        assert!(CredentialLease::load(&link, &|| Ok(())).is_err());
        fs::remove_file(&link)?;
        fs::hard_link(&fixture.path, &link)?;
        assert!(CredentialLease::load(&fixture.path, &|| Ok(())).is_err());
        fs::remove_file(&link)?;
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o640))?;
        assert!(CredentialLease::load(&fixture.path, &|| Ok(())).is_err());
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600))?;
        fs::write(&fixture.path, vec![b'x'; MAX_CREDENTIAL_BYTES + 1])?;
        assert!(CredentialLease::load(&fixture.path, &|| Ok(())).is_err());
        assert!(CredentialLease::load(&fixture.directory, &|| Ok(())).is_err());
        Ok(())
    }

    #[test]
    fn modification_replacement_removal_and_permission_drift_revoke_a_lease() -> Test {
        for change in 0..4 {
            let fixture = Fixture::new()?;
            let lease = CredentialLease::load(&fixture.path, &|| Ok(()))?;
            match change {
                0 => fs::write(&fixture.path, b"another-user\nanother-password\n")?,
                1 => {
                    let replacement = fixture.directory.join("replacement");
                    fs::write(&replacement, b"unit-user\nunit-password\n")?;
                    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))?;
                    fs::rename(&replacement, &fixture.path)?;
                }
                2 => fs::remove_file(&fixture.path)?,
                _ => fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o644))?,
            }
            assert_eq!(lease.revalidate(&|| Ok(())), Err(SecretError::Revoked));
        }
        Ok(())
    }

    #[test]
    fn authority_and_deadline_are_checked_before_secret_and_entropy_io() -> Test {
        for error in [SecretError::Authority, SecretError::Deadline] {
            assert!(
                matches!(CredentialLease::load(Path::new("/must/not/be/opened"), &|| Err(error)), Err(actual) if actual == error)
            );
            assert!(matches!(Entropy::open(&|| Err(error)), Err(actual) if actual == error));
            let fixture = Fixture::new()?;
            let lease = CredentialLease::load(&fixture.path, &|| Ok(()))?;
            assert_eq!(lease.revalidate(&|| Err(error)), Err(error));
            let mut entropy = Entropy::open(&|| Ok(()))?;
            assert_eq!(entropy.next(&|| Err(error)), Err(error));
        }
        Ok(())
    }

    #[test]
    fn entropy_is_read_for_each_request_without_a_reused_cnonce() -> Test {
        let mut entropy = Entropy::open(&|| Ok(()))?;
        let first = entropy.next(&|| Ok(()))?;
        let second = entropy.next(&|| Ok(()))?;
        assert_ne!(first, second);
        Ok(())
    }
}
