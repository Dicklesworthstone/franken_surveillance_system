#![forbid(unsafe_code)]
//! Linux private-file key custody. The caller must supply a trusted, private
//! directory and trusted ancestors; same-owner or privileged interference and
//! whole-directory replacement are outside this boundary. This module does
//! not use Keychain, back up the key, or retain checkpoint scopes or journal
//! pins. File creation and synchronization are synchronous blocking I/O.

use super::{Action, Authority, Error, Key, Scope, admit};
use asupersync::Cx;
use std::{
    fmt,
    fs::{File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

const OPEN_FLAGS: i32 = 0o4000 | 0o400000; // Linux O_NONBLOCK | O_NOFOLLOW
const KEY_BYTES: usize = 32;
const IO_ATTEMPTS: usize = KEY_BYTES + 2;

struct Secret([u8; KEY_BYTES]);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Fingerprint {
    fn file(m: Metadata) -> Result<Self, Error> {
        if !m.is_file()
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() != KEY_BYTES as u64
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            len: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unifi_direct::{
        AudioCodec, StreamStart, VideoChannel, VideoCodec,
        handoff::Framing,
        http_stream::{
            Plan,
            checkpoint::{Sealed, Stored},
            tests::{conditions, snapshot},
        },
    };
    use asupersync::runtime::RuntimeBuilder;
    use fss_core::ContentDigest;
    use fss_object::{SpoolLimits, StagingSpool};
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    };

    struct Policy(bool);
    impl Authority for Policy {
        fn permits(&self, _: &Cx, _: &Scope, _: Action) -> bool {
            self.0
        }
    }
    struct Deny(Action);
    impl Authority for Deny {
        fn permits(&self, _: &Cx, _: &Scope, action: Action) -> bool {
            self.0 != action
        }
    }

    #[test]
    fn private_file_survives_reopen_and_refuses_links_and_denied_use()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir =
            std::env::temp_dir().join(format!("fss-checkpoint-keyfile-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let peer = Ipv4Addr::new(192, 168, 44, 20);
        let listener = SocketAddrV4::new(Ipv4Addr::new(192, 168, 44, 10), 17777);
        let baseline = snapshot(
            peer,
            1,
            br#"{"av":{"video":{"video1":{"avSerializer":null}}}}"#,
        );
        let start = StreamStart::new(
            VideoChannel::Video1,
            listener,
            VideoCodec::H264,
            AudioCodec::Aac,
            "0123456789abcdef",
        )?;
        let plan = Plan::new(
            peer,
            &start,
            conditions(&baseline, listener),
            &baseline,
            Framing::ContentLength,
        )?;
        let scope = Scope::from_plan(&plan, ContentDigest::sha256(b"fixture certificate"))?;
        let other_scope = Scope::from_plan(&plan, ContentDigest::sha256(b"different certificate"))?;
        let key_path = dir.join("private-key");
        let mut spool = StagingSpool::open(
            dir.join("spool"),
            SpoolLimits::new(4, 1_000_000, 100_000, 8),
        )?;
        let runtime = RuntimeBuilder::current_thread().build()?;
        runtime.block_on(async {
            let cx = Cx::current().ok_or("missing runtime")?;
            let denied = dir.join("denied");
            assert!(KeyLease::create(&cx, &Policy(false), scope, &denied).is_err());
            assert!(!denied.exists());
            let lease = KeyLease::create(&cx, &Policy(true), scope, &key_path)?;
            assert_eq!(format!("{lease:?}"), "CheckpointKeyLease(<redacted>)");
            assert!(KeyLease::create(&cx, &Policy(true), scope, &key_path).is_err());
            assert!(lease.with_key(&cx, &Deny(Action::KeyUse), |_| ()).is_err());
            let stored = Stored::capture_with_keyfile(
                &cx,
                &Policy(true),
                scope,
                &lease,
                &plan,
                &baseline,
                &mut spool,
            )?;
            assert!(
                Stored::capture_with_keyfile(
                    &cx,
                    &Policy(true),
                    other_scope,
                    &lease,
                    &plan,
                    &baseline,
                    &mut spool
                )
                .is_err()
            );
            let encrypted = spool.read_bounded(stored.digest(), 100_000)?;
            drop(lease);
            let reopened = KeyLease::load(&cx, &Policy(true), scope, &key_path)?;
            reopened.with_key(&cx, &Policy(true), |key| {
                Sealed::from_bytes(&encrypted)?.open(&cx, &Policy(true), scope, key)
            })??;
            let alias = dir.join("symlink");
            symlink(&key_path, &alias)?;
            assert!(KeyLease::load(&cx, &Policy(true), scope, &alias).is_err());
            let public = dir.join("public-key");
            let mut public_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&public)?;
            public_file.write_all(&[1; KEY_BYTES])?;
            std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644))?;
            assert!(KeyLease::load(&cx, &Policy(true), scope, &public).is_err());
            let short = dir.join("short-key");
            let mut short_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&short)?;
            short_file.write_all(&[1; KEY_BYTES - 1])?;
            assert!(KeyLease::load(&cx, &Policy(true), scope, &short).is_err());
            std::fs::hard_link(&key_path, dir.join("hardlink"))?;
            assert!(reopened.revalidate(&cx, &Policy(true)).is_err());
            assert!(KeyLease::load(&cx, &Policy(true), scope, &key_path).is_err());
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        Ok(())
    }
}

fn parent(path: &Path) -> Result<(&Path, Metadata), Error> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(Error::Invalid);
    }
    let parent = path.parent().ok_or(Error::Invalid)?;
    let meta = std::fs::symlink_metadata(parent).map_err(|_| Error::Storage)?;
    if !meta.is_dir() || meta.mode() & 0o077 != 0 {
        return Err(Error::Invalid);
    }
    Ok((parent, meta))
}

fn same_parent(a: &Metadata, b: &Metadata) -> bool {
    a.is_dir()
        && b.is_dir()
        && a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.uid() == b.uid()
        && a.mode() == b.mode()
}

fn fill_exact(
    file: &mut File,
    output: &mut [u8],
    mut check: impl FnMut() -> Result<(), Error>,
) -> Result<(), Error> {
    let mut done = 0;
    for _ in 0..IO_ATTEMPTS {
        check()?;
        let read = file.read(&mut output[done..]);
        check()?;
        match read {
            Ok(0) => return Err(Error::Storage),
            Ok(n) => {
                done += n;
                if done == output.len() {
                    return Ok(());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::Storage),
        }
    }
    Err(Error::Storage)
}

/// An open private-file identity and zeroizing key. The trusted parent and
/// ancestors must remain controlled by the caller. Rotation or metadata drift
/// revokes the lease; no automatic refresh or replacement occurs.
pub struct KeyLease {
    scope: Scope,
    path: PathBuf,
    file: File,
    identity: Fingerprint,
    key: Key,
}
impl fmt::Debug for KeyLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckpointKeyLease(<redacted>)")
    }
}
impl KeyLease {
    /// Create one owner-only file with fresh Linux OS entropy, sync file and
    /// directory, and reopen it as a lease. Failure after creation may leave a
    /// partial file: inspect it rather than overwriting or silently retrying.
    pub fn create(
        cx: &Cx,
        authority: &dyn Authority,
        scope: Scope,
        path: &Path,
    ) -> Result<Self, Error> {
        admit(cx, &scope, authority, Action::KeyCreate)?;
        let (directory, before) = parent(path)?;
        admit(cx, &scope, authority, Action::Entropy)?;
        let mut entropy = OpenOptions::new()
            .read(true)
            .custom_flags(OPEN_FLAGS)
            .open("/dev/urandom")
            .map_err(|_| Error::Storage)?;
        admit(cx, &scope, authority, Action::Entropy)?;
        let meta = entropy.metadata().map_err(|_| Error::Storage)?;
        if !meta.file_type().is_char_device() || meta.rdev() != 0x109 {
            return Err(Error::Invalid);
        }
        let mut secret = Secret([0; KEY_BYTES]);
        fill_exact(&mut entropy, &mut secret.0, || {
            admit(cx, &scope, authority, Action::Entropy)
        })?;
        admit(cx, &scope, authority, Action::Entropy)?;
        if secret.0.iter().all(|b| *b == 0) {
            return Err(Error::Invalid);
        }
        admit(cx, &scope, authority, Action::KeyCreate)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(OPEN_FLAGS)
            .open(path)
            .map_err(|_| Error::Storage)?;
        admit(cx, &scope, authority, Action::KeyCreate)?;
        let mut done = 0;
        for _ in 0..IO_ATTEMPTS {
            admit(cx, &scope, authority, Action::KeyCreate)?;
            let written = file.write(&secret.0[done..]);
            admit(cx, &scope, authority, Action::KeyCreate)?;
            match written {
                Ok(0) => return Err(Error::Storage),
                Ok(n) => {
                    done += n;
                    if done == KEY_BYTES {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Error::Storage),
            }
        }
        if done != KEY_BYTES {
            return Err(Error::Storage);
        }
        admit(cx, &scope, authority, Action::KeyCreate)?;
        file.sync_all().map_err(|_| Error::Storage)?;
        admit(cx, &scope, authority, Action::KeyCreate)?;
        let after = std::fs::symlink_metadata(directory).map_err(|_| Error::Storage)?;
        if !same_parent(&before, &after) {
            return Err(Error::Invalid);
        }
        let dir = File::open(directory).map_err(|_| Error::Storage)?;
        if !same_parent(&before, &dir.metadata().map_err(|_| Error::Storage)?) {
            return Err(Error::Invalid);
        }
        admit(cx, &scope, authority, Action::KeyCreate)?;
        dir.sync_all().map_err(|_| Error::Storage)?;
        admit(cx, &scope, authority, Action::KeyCreate)?;
        drop(file);
        Self::load(cx, authority, scope, path)
    }

    /// Load exactly one existing private key file without following a final
    /// symlink. The file must have mode 0600, one link and the parent's owner.
    pub fn load(
        cx: &Cx,
        authority: &dyn Authority,
        scope: Scope,
        path: &Path,
    ) -> Result<Self, Error> {
        admit(cx, &scope, authority, Action::KeyRead)?;
        let (_, parent_meta) = parent(path)?;
        let identity =
            Fingerprint::file(std::fs::symlink_metadata(path).map_err(|_| Error::Storage)?)?;
        if identity.uid != parent_meta.uid() {
            return Err(Error::Invalid);
        }
        admit(cx, &scope, authority, Action::KeyRead)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(OPEN_FLAGS)
            .open(path)
            .map_err(|_| Error::Storage)?;
        admit(cx, &scope, authority, Action::KeyRead)?;
        if Fingerprint::file(file.metadata().map_err(|_| Error::Storage)?)? != identity {
            return Err(Error::Invalid);
        }
        let mut secret = Secret([0; KEY_BYTES]);
        fill_exact(&mut file, &mut secret.0, || {
            admit(cx, &scope, authority, Action::KeyRead)
        })?;
        admit(cx, &scope, authority, Action::KeyRead)?;
        let key = Key::new(secret.0)?;
        let lease = Self {
            scope,
            path: path.to_owned(),
            file,
            identity,
            key,
        };
        lease.revalidate(cx, authority)?;
        Ok(lease)
    }

    /// Recheck file and path identity; caller authority is consulted around I/O.
    pub fn revalidate(&self, cx: &Cx, authority: &dyn Authority) -> Result<(), Error> {
        admit(cx, &self.scope, authority, Action::KeyRead)?;
        let (_, parent_meta) = parent(&self.path)?;
        let path =
            Fingerprint::file(std::fs::symlink_metadata(&self.path).map_err(|_| Error::Storage)?)?;
        admit(cx, &self.scope, authority, Action::KeyRead)?;
        let held = Fingerprint::file(self.file.metadata().map_err(|_| Error::Storage)?)?;
        if path != self.identity || held != self.identity || parent_meta.uid() != self.identity.uid
        {
            return Err(Error::Invalid);
        }
        admit(cx, &self.scope, authority, Action::KeyRead)
    }

    /// Borrow the key only while the lease and current disclosure policy agree.
    pub fn with_key<R>(
        &self,
        cx: &Cx,
        authority: &dyn Authority,
        use_key: impl FnOnce(&Key) -> R,
    ) -> Result<R, Error> {
        self.revalidate(cx, authority)?;
        admit(cx, &self.scope, authority, Action::KeyUse)?;
        let result = use_key(&self.key);
        admit(cx, &self.scope, authority, Action::KeyUse)?;
        self.revalidate(cx, authority)?;
        Ok(result)
    }

    pub(super) fn matches_scope(&self, scope: Scope) -> bool {
        self.scope == scope
    }
}
