#![forbid(unsafe_code)]
//! Native JPEG/real trained coefficients; procedural content is NOT people-quality evidence.
use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
const JPEG: &[u8] = include_bytes!("../../tests/fixtures/jpeg_people_shadow/texture.jpg");
const WORK: u64 = 1_000_000_000;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "fss-jpeg-people-shadow-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let fixture = Self {
            root: root.canonicalize()?,
        };
        fs::write(fixture.root.join("frame.jpg"), JPEG)?;
        fs::write(fixture.root.join("allow.mask"), vec![1; 80 * 144])?;
        fs::write(fixture.root.join("deny.mask"), vec![0; 80 * 144])?;
        Ok(fixture)
    }
    fn manifest(&self, inference: u64, count: u8, private: bool, output: usize) -> String {
        let id = "01".repeat(32);
        let jpeg = output::hex(ContentDigest::sha256(JPEG).bytes());
        let allow = output::hex(ContentDigest::sha256(&vec![1; 80 * 144]).bytes());
        let deny = output::hex(ContentDigest::sha256(&vec![0; 80 * 144]).bytes());
        let mut text = format!(
            "FSS_JPEG_PEOPLE_SHADOW_1\nsensor 1 2 1 0 {id} {id} {id}\nimage 80 144 160 160 40 72 1 grayscale\nbackground {id} 0 1000 0\nforeground 20 1 128 1000\nhealth 16 0 255 1000 0 3 1 1000 0 1 0 100 0\ntracking 32 32 128 1 8 1000 200 8 1000 0\nbudgets {WORK} {WORK} {WORK} {WORK} {inference} {WORK} 16384 {output}\nscan 8 8 -100 500000 64 64 80x144\nzone_policy {id} 100\nmodel opencv-people-shadow-1\nzone 1 0 20 1,1 79,1 79,143 1,143\n"
        );
        for n in 1..=3 {
            text.push_str(&format!(
                "reference {} {n} {n} - - frame.jpg {jpeg} allow.mask {allow}\n",
                output::hex([n; 32])
            ));
        }
        for n in 1..=count {
            let t = 30 + u64::from(n) * 10;
            let (mask, hash) = if private {
                ("deny.mask", &deny)
            } else {
                ("allow.mask", &allow)
            };
            text.push_str(&format!(
                "query {} {t} {t} {n} {t} frame.jpg {jpeg} {mask} {hash}\n",
                output::hex([10 + n; 32])
            ));
        }
        text
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn native_jpeg_real_model_replay_emits_every_window_and_current_tracking_zones() -> Result<()> {
    let fixture = Fixture::new()?;
    let text = fixture.manifest(WORK, 2, false, 1_000_000);
    let mut bytes = Vec::new();
    execute(&text, &fixture.root, &mut bytes)?;
    let json = String::from_utf8(bytes)?;
    assert_eq!(json.matches("\"kind\":\"window\"").count(), 18);
    assert_eq!(json.matches("\"kind\":\"frame_complete\"").count(), 2);
    assert_eq!(json.matches("\"kind\":\"tracking\"").count(), 2);
    assert_eq!(json.matches("\"kind\":\"zones\"").count(), 2);
    assert!(json.contains("\"margin\":-"));
    assert!(json.contains("cb2198952eaa5bc7e43d950b9f2aa1966528063c7295c7262133e7fa0d3d564c"));
    assert!(
        json.lines()
            .last()
            .ok_or("missing completion")?
            .contains("\"kind\":\"complete\",\"frames\":2")
    );
    // Background is identical: no motion requirement may prevent learned scanning.
    assert!(json.contains("\"changed_pixels\":0"));
    assert!(!json.contains("\"qualified_detector\":true"));
    Ok(())
}
#[test]
fn inference_refusal_retains_source_output_without_false_completion() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut work = WorkBudget::new(WORK);
    load_opencv_people_candidate(&mut work)?;
    let text = fixture.manifest(work.used(), 1, false, 1_000_000);
    let mut bytes = Vec::new();
    assert!(execute(&text, &fixture.root, &mut bytes).is_err());
    let json = String::from_utf8(bytes)?;
    assert!(json.contains("\"kind\":\"source_screen\""));
    assert!(json.contains("\"kind\":\"pending\""));
    assert!(json.contains("\"stage\":\"Inference\""));
    assert!(!json.contains("\"kind\":\"scan\""));
    assert!(!json.contains("\"kind\":\"complete\""));
    Ok(())
}
#[test]
fn private_jpeg_windows_are_unknown_not_negative_detections() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut bytes = Vec::new();
    execute(
        &fixture.manifest(WORK, 1, true, 1_000_000),
        &fixture.root,
        &mut bytes,
    )?;
    let json = String::from_utf8(bytes)?;
    let windows: Vec<_> = json
        .lines()
        .filter(|l| l.contains("\"kind\":\"window\""))
        .collect();
    assert_eq!(windows.len(), 9);
    assert!(
        windows
            .iter()
            .all(|l| l.contains("\"state\":\"unobservable\",\"margin\":null"))
    );
    assert!(json.contains("\"health\":\"NotObservable\""));
    Ok(())
}
#[test]
fn frozen_source_remains_degraded_despite_trained_model_scores() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut bytes = Vec::new();
    execute(
        &fixture.manifest(WORK, 3, false, 1_000_000),
        &fixture.root,
        &mut bytes,
    )?;
    let json = String::from_utf8(bytes)?;
    let screen = json
        .lines()
        .filter(|l| l.contains("\"kind\":\"source_screen\""))
        .last()
        .ok_or("screen missing")?;
    let tracking = json
        .lines()
        .filter(|l| l.contains("\"kind\":\"tracking\""))
        .last()
        .ok_or("tracking missing")?;
    assert!(screen.contains("\"health\":\"Degraded\""));
    assert!(tracking.contains("\"availability\":\"Disturbed\""));
    Ok(())
}
#[test]
fn output_quota_failure_never_emits_a_session_completion() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut bytes = Vec::new();
    assert!(
        execute(
            &fixture.manifest(WORK, 1, false, 1000),
            &fixture.root,
            &mut bytes
        )
        .is_err()
    );
    assert!(bytes.len() <= 1000);
    assert!(!String::from_utf8(bytes)?.contains("\"kind\":\"complete\""));
    let mut tiny = Vec::new();
    {
        let mut bounded = output::Limited::new(&mut tiny, 3);
        assert!(bounded.write_all(b"1234").is_err());
        bounded.write_all(b"123")?;
        assert!(bounded.write_all(b"4").is_err());
    }
    assert_eq!(tiny, b"123");
    Ok(())
}
#[test]
fn malformed_profiles_sequences_and_paths_are_refused_before_output() -> Result<()> {
    let fixture = Fixture::new()?;
    let good = fixture.manifest(WORK, 2, false, 1_000_000);
    for bad in [
        good.replace("model opencv-people-shadow-1", "model latest"),
        good.replace("80x144\n", "80x144,80x144\n"),
        good.replace("scan 8 8 -100", "scan 1 8 NaN"),
        good.replace("50 50 2 50", "50 50 1 50"),
        good.replace("frame.jpg", "../frame.jpg"),
        format!("{good}model opencv-people-shadow-1\n"),
    ] {
        let mut bytes = Vec::new();
        assert!(execute(&bad, &fixture.root, &mut bytes).is_err());
        assert!(bytes.is_empty());
    }
    Ok(())
}
#[test]
fn exact_source_hash_mismatch_is_not_silently_rebound() -> Result<()> {
    let fixture = Fixture::new()?;
    let good = fixture.manifest(WORK, 1, false, 1_000_000);
    let jpeg_hash = output::hex(ContentDigest::sha256(JPEG).bytes());
    let bad = good.replace(&jpeg_hash, &"ff".repeat(32));
    let mut bytes = Vec::new();
    assert!(execute(&bad, &fixture.root, &mut bytes).is_err());
    assert!(bytes.is_empty());
    Ok(())
}
