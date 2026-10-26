#![forbid(unsafe_code)]
//! One approved camera capture becomes native, source-closed trained-detector evidence.

#[path = "../fss-watch-rtsp-campaign/archive_open.rs"]
mod archive_open;
#[path = "sentinel/continuation.rs"]
mod continuation;
#[path = "sentinel/driver.rs"]
mod driver;
#[path = "../fss-import-rtsp/plan.rs"]
mod import_plan;
#[path = "../fss-sentinel-rtsp-campaign/model.rs"]
mod model;
#[path = "sentinel/plan.rs"]
mod plan;
#[path = "sentinel/preflight.rs"]
mod preflight;

pub(super) use plan::{HELP, MAX_ARGUMENTS, Options};

pub(super) fn execute(options: &mut Options) -> Result<(), &'static str> {
    driver::execute(options)
}

const AUTHORITY: &str = "ERR-CAPTURE-SENTINEL-AUTHORITY-001";
const DEADLINE: &str = "ERR-CAPTURE-SENTINEL-DEADLINE-001";
const LIMIT: &str = "ERR-CAPTURE-SENTINEL-LIMIT-001";
const PATH: &str = "ERR-CAPTURE-SENTINEL-PATH-001";
const SOURCE: &str = "ERR-CAPTURE-SENTINEL-SOURCE-001";

fn emit(options: &Options, kind: &str, detail: String) -> Result<(), &'static str> {
    use fss_cli::agent_json::{object, string};
    let row = object(&[
        ("schema", string(plan::FORMAT)),
        ("kind", string(kind)),
        ("approval", string(&options.approval()?.to_text())),
        ("detail", detail),
    ]);
    if row.len() >= plan::MAX_OUTPUT_BYTES {
        return Err(LIMIT);
    }
    super::write_bounded((row + "\n").as_bytes())
}
