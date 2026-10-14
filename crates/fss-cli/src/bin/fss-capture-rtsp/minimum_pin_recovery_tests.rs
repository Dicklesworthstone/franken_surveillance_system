#![forbid(unsafe_code)]
//! Cold native journal floors and unchanged single-capture authority.

use super::*;
use crate::single::SinglePlan;
use std::ffi::OsString;
use std::sync::atomic::{AtomicU64, Ordering};

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const TIMEOUT: u64 = 30_000_000_000;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-minimum-pin-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(fs::canonicalize(path)?)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory reservation exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn args(directory: &Directory, codec: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        ("--peer", "127.0.0.1:8554"), ("--authority", "camera.test:8554"),
        ("--presentation", "/camera/main"), ("--control-root", "/camera"),
        ("--sensor-id", "sensor:camera"), ("--stream-id", "stream:main"),
        ("--generation", "1"), ("--ingress", "1"), ("--ssrc", "7"),
        ("--frame-duration-ticks", "18000"), ("--stop-after-pictures", "2"),
        ("--owner-authorized", "yes"), ("--plaintext", "yes"),
        ("--retain-originals", "yes"), ("--codec", codec),
    ].into_iter().flat_map(|(k, v)| [OsString::from(k), OsString::from(v)]).collect();
    for key in ["--anchor", "--receive-clock", "--timing-evidence", "--journal-id"] {
        args.extend([key.into(), ContentDigest::sha256(key.as_bytes()).to_text().into()]);
    }
    args.extend([
        "--root".into(), directory.0.join("archive").into_os_string(),
        "--pins".into(), directory.0.join("pins").into_os_string(),
    ]);
    args
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = args.iter().position(|arg| arg == key) {
        args[index + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

fn anchor_text(attempt: usize, anchor: ArchivePinAnchor) -> String {
    format!("{attempt}:{}:{}", anchor.sequence, anchor.root.to_text())
}

fn approval(preview: &str) -> Test<ContentDigest> {
    Ok(ContentDigest::parse(preview.split("\"approval\":\"").nth(1)
        .and_then(|tail| tail.split('"').next()).ok_or("missing approval")?)?)
}

fn genesis<C: ArchiveCodec>(options: &Options) -> Test<ArchivePinAnchor> {
    let _publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    let journal = CodecArchivePinJournal::<C>::create(
        &options.pins, options.pin_scope(), options.pin_limits(), &NeverCancel,
    )?;
    Ok(journal.anchor())
}

#[test]
fn single_minimum_is_recovery_only_and_preserves_the_complete_capture_basis() -> Test {
    let directory = Directory::new()?;
    for codec in ["avc", "hevc"] {
        for supervised in [false, true] {
            let mut input = args(&directory, codec);
            if supervised { set(&mut input, "--progress-timeout-ms", "10"); }
            let original = SinglePlan::parse(&input)?;
            let anchor = ArchivePinAnchor { sequence: 1, root: ContentDigest::sha256(b"independent") };
            set(&mut input, "--minimum-pin-anchors", &anchor_text(1, anchor));
            assert!(SinglePlan::parse(&input).is_err());
            for mode in ["yes", "index"] {
                set(&mut input, "--recover", mode);
                let guarded = SinglePlan::parse(&input)?;
                assert_eq!(guarded.capture_digest()?, original.capture_digest()?);
                assert_eq!(guarded.attempts()[0].digest()?, original.attempts()[0].digest()?);
                assert_eq!(guarded.attempts()[0].root, original.attempts()[0].root);
                assert_eq!(guarded.attempts()[0].pins, original.attempts()[0].pins);
                assert_eq!(guarded.minimum_pins().and_then(|pins| pins.get(0)), Some(anchor));
            }
            set(&mut input, "--minimum-pin-anchors", &anchor_text(2, anchor));
            assert!(SinglePlan::parse(&input).is_err());
            set(&mut input, "--minimum-pin-anchors", &anchor_text(1, ArchivePinAnchor {
                sequence: original.attempts()[0].pin_limits().max_records as u64 + 1, ..anchor
            }));
            assert!(SinglePlan::parse(&input).is_err());
            set(&mut input, "--minimum-pin-anchors", &anchor_text(1, anchor));
            input.extend(["--minimum-pin-anchors".into(), anchor_text(1, anchor).into()]);
            assert!(SinglePlan::parse(&input).is_err());
        }
    }
    assert!(!directory.0.join("archive").exists());
    assert!(!directory.0.join("pins").exists());
    Ok(())
}

fn cold_genesis<C: ArchiveCodec>(codec: &str) -> Test {
    let directory = Directory::new()?;
    let mut input = args(&directory, codec);
    set(&mut input, "--recover", "yes");
    let original = SinglePlan::parse(&input)?;
    let saved = genesis::<C>(&original.attempts()[0])?;
    let path = original.attempts()[0].pins.join("pins.journal");
    let before = fs::read(&path)?;
    let unpinned = original.preview()?;
    assert!(!unpinned.contains("minimum_prefixes_verified"));
    set(&mut input, "--minimum-pin-anchors", &anchor_text(1, saved));
    let guarded = SinglePlan::parse(&input)?;
    let pinned = guarded.preview()?;
    assert_ne!(approval(&unpinned)?, approval(&pinned)?);
    assert!(pinned.contains("\"minimum_prefixes_verified\":true"));
    // A correct approval without the independent floor cannot authorize the guarded request.
    set(&mut input, "--approve", &approval(&unpinned)?.to_text());
    let refused = SinglePlan::parse(&input)?;
    let mut emitted = 0;
    assert_eq!(execute_codec::<C>(&refused, TIMEOUT, |_| { emitted += 1; Ok(()) }, &NeverCancel), Err(APPROVAL));
    assert_eq!(emitted, 0);
    for wrong in [
        ArchivePinAnchor { sequence: 2, ..saved },
        ArchivePinAnchor { root: ContentDigest::sha256(b"foreign-prefix"), ..saved },
    ] {
        set(&mut input, "--minimum-pin-anchors", &anchor_text(1, wrong));
        for mode in ["yes", "index"] {
            set(&mut input, "--recover", mode);
            let refused = SinglePlan::parse(&input)?;
            assert!(refused.preview().is_err());
            assert!(execute(&refused, TIMEOUT).is_err());
            assert_eq!(fs::read(&path)?, before);
        }
    }
    Ok(())
}

#[test]
fn avc_and_hevc_verify_the_independent_prefix_before_work_or_index_admission() -> Test {
    cold_genesis::<AvcArchiveCodec>("avc")?;
    cold_genesis::<HevcArchiveCodec>("hevc")
}

#[test]
fn independently_known_missing_stores_never_become_an_unobserved_success() -> Test {
    let directory = Directory::new()?;
    let mut input = args(&directory, "hevc");
    set(&mut input, "--recover", "yes");
    assert!(SinglePlan::parse(&input)?.preview()?.contains("both_stores_unobserved"));
    let saved = ArchivePinAnchor { sequence: 2, root: ContentDigest::sha256(b"saved") };
    set(&mut input, "--minimum-pin-anchors", &anchor_text(1, saved));
    for mode in ["yes", "index"] {
        set(&mut input, "--recover", mode);
        let mut plan = SinglePlan::parse(&input)?;
        assert!(plan.preview().is_err());
        assert!(plan.execute().is_err());
        assert!(!directory.0.join("archive").exists());
        assert!(!directory.0.join("pins").exists());
    }
    Ok(())
}

#[path = "minimum_pin_media_tests.rs"]
mod media;
