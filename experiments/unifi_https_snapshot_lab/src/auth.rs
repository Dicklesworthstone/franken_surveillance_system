#![forbid(unsafe_code)]
//! Private-file credential and cookie handling for the isolated Linux lab.
use fss_core::json_input::{self, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_SECRET: u64 = 4096;
const OPEN_FLAGS: i32 = 0o4000 | 0o400000; // Linux O_NONBLOCK | O_NOFOLLOW

/// Best-effort clearing; upstream TLS and parsers may make other copies.
pub struct Secret(pub Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
fn identity(m: fs::Metadata) -> Result<Identity, &'static str> {
    if !m.is_file()
        || m.mode() & 0o077 != 0
        || m.mode() & 0o400 == 0
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > MAX_SECRET
    {
        return Err("private credential unavailable");
    }
    Ok(Identity {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        size: m.len(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}

pub struct Lease {
    path: PathBuf,
    file: File,
    id: Identity,
    pub secret: Secret,
}
impl Lease {
    pub fn load(
        path: &Path,
        check: &impl Fn() -> Result<(), &'static str>,
    ) -> Result<Self, &'static str> {
        check()?;
        let id =
            identity(fs::symlink_metadata(path).map_err(|_| "private credential unavailable")?)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(OPEN_FLAGS)
            .open(path)
            .map_err(|_| "private credential unavailable")?;
        if identity(
            file.metadata()
                .map_err(|_| "private credential unavailable")?,
        )? != id
        {
            return Err("private credential changed");
        }
        check()?;
        let mut secret = Secret(Vec::new());
        file.by_ref()
            .take(MAX_SECRET + 1)
            .read_to_end(&mut secret.0)
            .map_err(|_| "private credential unavailable")?;
        if secret.0.len() as u64 != id.size {
            return Err("private credential changed");
        }
        let text = std::str::from_utf8(&secret.0).map_err(|_| "invalid credential format")?;
        let mut doc = json_input::parse(text).map_err(|_| "invalid credential format")?;
        let valid = doc.object().is_some_and(|obj| {
            obj.len() == 2
                && ["username", "password"].iter().all(|key| {
                    obj.get(*key)
                        .and_then(Value::text)
                        .is_some_and(|s| !s.is_empty() && s.len() <= 1024)
                })
        });
        clear_value(&mut doc);
        if !valid {
            return Err("invalid credential format");
        }
        let lease = Self {
            path: path.to_owned(),
            file,
            id,
            secret,
        };
        lease.revalidate(check)?;
        Ok(lease)
    }
    pub fn revalidate(
        &self,
        check: &impl Fn() -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        check()?;
        if identity(fs::symlink_metadata(&self.path).map_err(|_| "private credential changed")?)?
            != self.id
            || identity(
                self.file
                    .metadata()
                    .map_err(|_| "private credential changed")?,
            )? != self.id
        {
            return Err("private credential changed");
        }
        check()
    }
}

fn clear_value(value: &mut Value) {
    match value {
        Value::Text(s) | Value::Number(s) => {
            let mut bytes = std::mem::take(s).into_bytes();
            bytes.fill(0);
        }
        Value::Array(a) => {
            for v in a {
                clear_value(v);
            }
        }
        Value::Object(o) => {
            for v in o.values_mut() {
                clear_value(v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_file_lease_refuses_rotation_and_weak_permissions()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let path =
            std::env::temp_dir().join(format!("fss-unifi-auth-lease-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        std::io::Write::write_all(
            &mut file,
            br#"{"username":"fixture","password":"synthetic"}"#,
        )?;
        drop(file);
        let allowed = || Ok(());
        let lease = Lease::load(&path, &allowed)?;
        lease.revalidate(&allowed)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(lease.revalidate(&allowed).is_err());
        assert!(Lease::load(&path, &allowed).is_err());
        fs::remove_file(path)?;
        Ok(())
    }
}
