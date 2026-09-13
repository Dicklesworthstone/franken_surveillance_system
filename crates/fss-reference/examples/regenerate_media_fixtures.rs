#![forbid(unsafe_code)]
//! Deterministic regeneration tool for synthetic H.264 and rtpdump media fixtures.
//!
//! Run with:
//! ```sh
//! cargo run -p fss-reference --example regenerate_media_fixtures
//! ```

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_reference::media_fixture::{
    H264FixtureParams, RtpdumpParams, build_h264_manifest_json, build_rtp_manifest_json,
    generate_h264_annexb, generate_rtpdump_clean, generate_rtpdump_duplicate,
    generate_rtpdump_large_gap, generate_rtpdump_loss, generate_rtpdump_reorder,
    generate_rtpdump_ssrc_reset, generate_rtpdump_truncated_last_record,
};

fn main() -> Result<(), Box<dyn Error>> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .ok_or("cannot find repo root from CARGO_MANIFEST_DIR")?;

    let h264_dir = repo_root.join("tests/fixtures/media/h264");
    let rtp_dir = repo_root.join("tests/fixtures/media/rtp");
    fs::create_dir_all(&h264_dir)?;
    fs::create_dir_all(&rtp_dir)?;

    let h264_params = H264FixtureParams::default();
    let annexb = generate_h264_annexb(&h264_params)?;
    let clean_264_path = h264_dir.join("clean.264");
    fs::write(&clean_264_path, &annexb.bytes)?;
    println!("Wrote clean.264 (sha256: {})", annexb.sha256);

    let h264_manifest = build_h264_manifest_json(&annexb, &h264_params, "clean.264");
    fs::write(h264_dir.join("fixture_manifest.json"), h264_manifest)?;
    println!("Wrote tests/fixtures/media/h264/fixture_manifest.json");

    let rtp_params = RtpdumpParams::default();
    let clean = generate_rtpdump_clean(&annexb, &rtp_params)?;
    let loss = generate_rtpdump_loss(&annexb, &rtp_params)?;
    let reorder = generate_rtpdump_reorder(&annexb, &rtp_params)?;
    let duplicate = generate_rtpdump_duplicate(&annexb, &rtp_params)?;
    let ssrc_reset = generate_rtpdump_ssrc_reset(&annexb, &rtp_params)?;
    let truncated = generate_rtpdump_truncated_last_record(&annexb, &rtp_params)?;
    let large_gap = generate_rtpdump_large_gap(&annexb, &rtp_params)?;

    let rtp_fixtures = [
        ("clean.rtp", &clean),
        ("loss.rtp", &loss),
        ("reorder.rtp", &reorder),
        ("duplicate.rtp", &duplicate),
        ("ssrc_reset.rtp", &ssrc_reset),
        ("truncated_last_record.rtp", &truncated),
        ("large_gap.rtp", &large_gap),
    ];

    for (fname, fix) in rtp_fixtures {
        fs::write(rtp_dir.join(fname), &fix.bytes)?;
        println!("Wrote tests/fixtures/media/rtp/{} (sha256: {})", fname, fix.sha256);
    }

    let all_fixtures = [
        clean, loss, reorder, duplicate, ssrc_reset, truncated, large_gap,
    ];
    let rtp_manifest = build_rtp_manifest_json(&all_fixtures, &rtp_params);
    fs::write(rtp_dir.join("fixture_manifest.json"), rtp_manifest)?;
    println!("Wrote tests/fixtures/media/rtp/fixture_manifest.json");

    println!("All media fixtures and manifests successfully regenerated.");
    Ok(())
}
