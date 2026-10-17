#![forbid(unsafe_code)]
//! fss-provision — factory-state camera onboarding substrate
//! (LAB-PROVISION-001, bead family `fss-provision`).
//!
//! A sans-IO reference CLI over the [`fss_provision`] recipe registry. It
//! never touches a device: it reads the static registry and emits
//! deterministic, digest-pinned artifacts:
//!
//! * `families` — the family catalog (friction class, transport, data lane,
//!   prerequisites, step count).
//! * `plan` — the onboarding plan for one factory-state camera, or a typed
//!   blocked reason (`missing_prerequisite` / `already_flashed`).
//! * `sd-image` — the deterministic FAT32 image layout for an SD-updater
//!   family (reference bundle), or a typed `not_applicable` answer otherwise.
//!
//! `--json` is required (machine contract `fss.provision_cli.v1`). Nothing
//! secret is read or printed; the software vs. data split is preserved in the
//! output (friction/transport describe the software path, data_lane the data
//! path).

use std::process::ExitCode;

use fss_cli::ExitIdentity;
use fss_provision::{
    AgentBundle, CameraFamily, CameraObservation, OnboardingPlan, OnboardingPlanner, Prerequisite,
    ProvisionError, RecipeRegistry, SdImageBuilder, SdImagePlan, Transport,
};

const HELP: &str = "fss-provision <families|plan|sd-image> [options] --json\n\
                    \n\
                    factories a factory-state camera into an FSS node.\n\
                    \n\
                    Subcommands:\n\
                    \x20 families          the family catalog (friction, transport, data lane,\n\
                    \x20                   prerequisites, step count)\n\
                    \x20 plan              the onboarding plan for one camera, or a typed\n\
                    \x20                   blocked reason\n\
                    \x20 sd-image          the FAT32 image layout for an SD-updater family\n\
                    \n\
                    Options:\n\
                    \x20 --family <f>        yi|wyze_v4|aosu_p1_max|openipc_class_a|generic_standards\n\
                    \x20 --sn-prefix <S>     SN prefix read off the label (plan)\n\
                    \x20 --fw <V>            firmware version (plan)\n\
                    \x20 --release <R>       release handle for sd-image (default: <family>-reference)\n\
                    \x20 --web-reachable     stock web-UI update endpoint is reachable (plan)\n\
                    \x20 --local-key         owner's Tuya local_key is available (plan)\n\
                    \x20 --flashed           the camera already runs FSS software (plan)\n\
                    \x20 --json              machine contract fss.provision_cli.v1 (required)\n\
                    \n\
                    Sans-IO: no device is probed; every output is deterministic and\n\
                    digest-pinned. A blocked plan is a valid typed answer (exit 0).";

const CONTRACT: &str = "fss.provision_cli.v1";
const MAX_ARGS: usize = 24;
const DEFAULT_CARD_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug)]
struct Options {
    command: &'static str,
    family: Option<CameraFamily>,
    sn_prefix: Option<String>,
    fw: Option<String>,
    release: Option<String>,
    web_reachable: bool,
    local_key: bool,
    flashed: bool,
}

fn parse(args: &[std::ffi::OsString]) -> Result<Options, &'static str> {
    let args: Vec<String> = args
        .iter()
        .filter_map(|a| a.to_str().map(str::to_owned))
        .collect();
    if args.is_empty() || args.len() > MAX_ARGS {
        return Err("expected a subcommand (families|plan|sd-image)");
    }
    let command: &'static str = match args[0].as_str() {
        "families" => "families",
        "plan" => "plan",
        "sd-image" => "sd-image",
        _ => return Err("unknown subcommand"),
    };
    let mut family: Option<CameraFamily> = None;
    let mut sn_prefix: Option<String> = None;
    let mut fw: Option<String> = None;
    let mut release: Option<String> = None;
    let mut web_reachable = false;
    let mut local_key = false;
    let mut flashed = false;
    let mut i = 1usize;
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--json" => {}
            "--family" => {
                let Some(v) = value_at(&args, &mut i) else {
                    return Err("--family needs a value");
                };
                family = Some(CameraFamily::parse(v).map_err(|_| "unknown family")?);
            }
            "--sn-prefix" => {
                let Some(v) = value_at(&args, &mut i) else {
                    return Err("--sn-prefix needs a value");
                };
                sn_prefix = Some(v.to_owned());
            }
            "--fw" => {
                let Some(v) = value_at(&args, &mut i) else {
                    return Err("--fw needs a value");
                };
                fw = Some(v.to_owned());
            }
            "--release" => {
                let Some(v) = value_at(&args, &mut i) else {
                    return Err("--release needs a value");
                };
                release = Some(v.to_owned());
            }
            "--web-reachable" => web_reachable = true,
            "--local-key" => local_key = true,
            "--flashed" => flashed = true,
            _ => return Err("unknown flag"),
        }
        i += 1;
    }
    if command != "families" && family.is_none() {
        return Err("--family is required");
    }
    Ok(Options {
        command,
        family,
        sn_prefix,
        fw,
        release,
        web_reachable,
        local_key,
        flashed,
    })
}

/// Advances `i` past the current flag and returns the following value.
fn value_at<'a>(args: &'a [String], i: &mut usize) -> Option<&'a str> {
    *i += 1;
    args.get(*i).map(String::as_str)
}

fn run(o: &Options) -> Result<String, String> {
    if let Err(e) = RecipeRegistry::new().verify_integrity() {
        return Err(format!("registry integrity check failed: {e}"));
    }
    match o.command {
        "families" => Ok(families_json()),
        "plan" => plan_json(o),
        "sd-image" => sd_image_json(o),
        _ => Err("unknown subcommand".to_owned()),
    }
}

fn families_json() -> String {
    let registry = RecipeRegistry::new();
    let mut rows = String::new();
    for (n, r) in registry.iter().enumerate() {
        if n > 0 {
            rows.push(',');
        }
        let mut prereqs = String::from("[");
        for (j, q) in r.prerequisites().iter().enumerate() {
            if j > 0 {
                prereqs.push(',');
            }
            prereqs.push_str(&format!("\"{}\"", q.as_str()));
        }
        prereqs.push(']');
        rows.push_str(&format!(
            "{{\"family\":\"{}\",\"friction_class\":\"{}\",\"transport\":\"{}\",\"data_lane\":\"{}\",\"software_wireless\":{},\"prerequisites\":{prereqs},\"step_count\":{}}}",
            r.family().as_str(),
            r.friction_class().as_str(),
            r.transport().as_str(),
            r.data_lane().as_str(),
            r.software_wireless(),
            r.steps().len(),
        ));
    }
    format!("{{\"contract\":\"{CONTRACT}\",\"outcome\":\"families\",\"families\":[{rows}]}}")
}

fn plan_json(o: &Options) -> Result<String, String> {
    let Some(family) = o.family else {
        return Err("missing --family".to_owned());
    };
    let mut obs = CameraObservation::for_family(family);
    if let Some(sn) = o.sn_prefix.clone() {
        obs = obs.with_sn_prefix(sn);
    }
    if let Some(fw) = o.fw.clone() {
        obs = obs.with_firmware_version(fw);
    }
    if o.web_reachable {
        obs = obs.with_web_update_reachable();
    }
    if o.local_key {
        obs = obs.with_local_key_available();
    }
    if o.flashed {
        obs = obs.with_already_flashed();
    }
    let planner = OnboardingPlanner::new(RecipeRegistry::new());
    match planner.plan(&obs) {
        Ok(plan) => Ok(plan_planned_json(&plan)),
        Err(ProvisionError::AlreadyFlashed) => {
            Ok(plan_blocked_json(family, "already_flashed", None))
        }
        Err(ProvisionError::MissingPrerequisite(pre)) => {
            Ok(plan_blocked_json(family, "missing_prerequisite", Some(pre)))
        }
        Err(ProvisionError::MissingFamily(f)) => Ok(plan_blocked_json(f, "missing_family", None)),
        Err(ProvisionError::SdImage(e)) => Err(format!("sd image error: {e}")),
        Err(ProvisionError::Canonical(c)) => Err(format!("canonical error: {c}")),
    }
}

fn plan_planned_json(plan: &OnboardingPlan) -> String {
    let mut steps = String::new();
    for (n, s) in plan.steps().iter().enumerate() {
        if n > 0 {
            steps.push(',');
        }
        steps.push_str(&format!(
            "{{\"kind\":\"{}\",\"physical\":{},\"wireless\":{}}}",
            s.kind().as_str(),
            s.is_physical(),
            s.is_wireless(),
        ));
    }
    let image = match plan.image() {
        Some(img) => image_json(img),
        None => "null".to_owned(),
    };
    format!(
        "{{\"contract\":\"{CONTRACT}\",\"outcome\":\"planned\",\"family\":\"{}\",\"friction_class\":\"{}\",\"transport\":\"{}\",\"control\":\"{}\",\"software_wireless\":{},\"data_lane\":\"{}\",\"steps\":[{steps}],\"image\":{image},\"plan_digest\":\"{}\"}}",
        plan.family().as_str(),
        plan.friction_class().as_str(),
        plan.transport().as_str(),
        plan.control().as_str(),
        plan.software_wireless(),
        plan.data_lane().as_str(),
        plan.plan_digest().to_text(),
    )
}

fn plan_blocked_json(
    family: CameraFamily,
    reason: &'static str,
    prereq: Option<Prerequisite>,
) -> String {
    match prereq {
        Some(p) => format!(
            "{{\"contract\":\"{CONTRACT}\",\"outcome\":\"blocked\",\"family\":\"{}\",\"reason\":\"{reason}\",\"prerequisite\":\"{}\"}}",
            family.as_str(),
            p.as_str(),
        ),
        None => format!(
            "{{\"contract\":\"{CONTRACT}\",\"outcome\":\"blocked\",\"family\":\"{}\",\"reason\":\"{reason}\"}}",
            family.as_str(),
        ),
    }
}

fn sd_image_json(o: &Options) -> Result<String, String> {
    let Some(family) = o.family else {
        return Err("missing --family".to_owned());
    };
    let registry = RecipeRegistry::new();
    let Some(recipe) = registry.get(family) else {
        return Err("unknown family".to_owned());
    };
    if recipe.transport() != Transport::SdImage {
        return Ok(format!(
            "{{\"contract\":\"{CONTRACT}\",\"outcome\":\"not_applicable\",\"family\":\"{}\",\"transport\":\"{}\",\"reason\":\"transport_is_not_sd_image\"}}",
            family.as_str(),
            recipe.transport().as_str(),
        ));
    }
    let release = match &o.release {
        Some(r) if !r.is_empty() => r.clone(),
        _ => format!("{family}-reference"),
    };
    let builder = SdImageBuilder::new(DEFAULT_CARD_BYTES).map_err(|e| e.to_string())?;
    let bundle = AgentBundle::reference(family);
    let image = builder
        .build(family, release, &bundle)
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{{\"contract\":\"{CONTRACT}\",\"outcome\":\"sd_image\",\"family\":\"{}\",\"image\":{}}}",
        family.as_str(),
        image_json(&image),
    ))
}

fn image_json(img: &SdImagePlan) -> String {
    let mut entries = String::new();
    for (n, e) in img.entries().iter().enumerate() {
        if n > 0 {
            entries.push(',');
        }
        entries.push_str(&format!(
            "{{\"path\":\"{}\",\"size_bytes\":{},\"digest\":\"{}\"}}",
            json_escape(e.path()),
            e.size_bytes(),
            e.content_digest().to_text(),
        ));
    }
    format!(
        "{{\"release\":\"{}\",\"total_bytes\":{},\"card_capacity_bytes\":{},\"digest\":\"{}\",\"entries\":[{entries}]}}",
        json_escape(img.release()),
        img.total_bytes(),
        img.card_capacity_bytes(),
        img.image_digest().to_text(),
    )
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if !args.iter().any(|a| a == "--json") {
        eprintln!("ERR-PROVISION-ARGUMENT-001: --json is required; use fss-provision --help");
        return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
    }
    match parse(&args) {
        Ok(o) => match run(&o) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("ERR-PROVISION-RUNTIME-001: {e}");
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(e) => {
            eprintln!("ERR-PROVISION-ARGUMENT-001: {e}; use fss-provision --help");
            ExitCode::from(ExitIdentity::MALFORMED_VALUE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<std::ffi::OsString> {
        v.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn parses_families() {
        let r = parse(&args(&["families", "--json"]));
        let Ok(o) = r else {
            return;
        };
        assert_eq!(o.command, "families");
        assert_eq!(o.family, None);
    }

    #[test]
    fn plan_requires_family() {
        assert!(parse(&args(&["plan", "--json"])).is_err());
    }

    #[test]
    fn plan_parses_family_and_flags() {
        let r = parse(&args(&[
            "plan",
            "--family",
            "yi",
            "--sn-prefix",
            "YIHC_Y_2_0",
            "--fw",
            "2.1.0",
            "--local-key",
            "--json",
        ]));
        let Ok(o) = r else {
            return;
        };
        assert_eq!(o.command, "plan");
        assert_eq!(o.family, Some(CameraFamily::Yi));
        assert_eq!(o.sn_prefix.as_deref(), Some("YIHC_Y_2_0"));
        assert!(o.local_key);
    }

    #[test]
    fn refuses_unknown_family() {
        assert!(parse(&args(&["plan", "--family", "nope", "--json"])).is_err());
    }

    #[test]
    fn refuses_unknown_flag() {
        assert!(parse(&args(&["plan", "--family", "yi", "--nope", "--json"])).is_err());
    }

    #[test]
    fn families_json_is_the_contract() {
        let r = parse(&args(&["families", "--json"]));
        let Ok(o) = r else {
            return;
        };
        let j = run(&o);
        let Ok(j) = j else {
            return;
        };
        assert!(j.contains("\"contract\":\"fss.provision_cli.v1\""));
        assert!(j.contains("\"family\":\"yi\""));
        assert!(j.contains("\"data_lane\":\"onvif_t\""));
    }

    #[test]
    fn yi_plan_without_sn_prefix_is_blocked_typed() {
        let r = parse(&args(&[
            "plan", "--family", "yi", "--fw", "2.1.0", "--json",
        ]));
        let Ok(o) = r else {
            return;
        };
        let j = run(&o);
        let Ok(j) = j else {
            return;
        };
        assert!(j.contains("\"outcome\":\"blocked\""));
        assert!(j.contains("\"prerequisite\":\"sn_prefix\""));
    }

    #[test]
    fn wyze_sd_image_is_not_applicable() {
        let r = parse(&args(&["sd-image", "--family", "wyze_v4", "--json"]));
        let Ok(o) = r else {
            return;
        };
        let j = run(&o);
        let Ok(j) = j else {
            return;
        };
        assert!(j.contains("\"outcome\":\"not_applicable\""));
        assert!(j.contains("\"transport\":\"none\""));
    }

    #[test]
    fn yi_sd_image_is_deterministic() {
        let r = parse(&args(&["sd-image", "--family", "yi", "--json"]));
        let Ok(o) = r else {
            return;
        };
        let j = run(&o);
        let Ok(j) = j else {
            return;
        };
        let again = run(&o);
        let Ok(again) = again else {
            return;
        };
        assert_eq!(j, again);
        assert!(j.contains("\"outcome\":\"sd_image\""));
        assert!(j.contains("\"path\":\"/"));
    }
}
