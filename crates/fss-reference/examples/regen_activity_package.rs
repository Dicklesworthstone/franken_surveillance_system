#![forbid(unsafe_code)]
//! Regenerates `models/fss-activity/fss_activity_v1.fmpk` from the current
//! first-party builder (`build_activity_package`) and prints the new pinned
//! whole-archive SHA-256. Run from the workspace root whenever an activity
//! package constant changes, then update `ACTIVITY_PACKAGE_V1_SHA256` to the
//! printed digest:
//!
//! ```text
//! cargo run -p fss-reference --example regen_activity_package
//! ```

fn main() {
    let bytes =
        fss_reference::executor_activity_package::build_activity_package().expect("build");
    let path = "models/fss-activity/fss_activity_v1.fmpk";
    std::fs::write(path, &bytes).expect("write fmpk");
    println!("wrote {path} ({} bytes)", bytes.len());
    println!(
        "new ACTIVITY_PACKAGE_V1_SHA256 pin: sha256:{}",
        fss_core::ContentDigest::sha256(&bytes)
            .to_string()
            .trim_start_matches("sha256:")
    );
}
