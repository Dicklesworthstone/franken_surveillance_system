#![forbid(unsafe_code)]
//! Ordered, exact-approval import of independent source epochs through the native owners.
//! This is an operator request, not a new durable media format or an atomic transaction.

use std::ffi::OsString;
use std::process::ExitCode;

use fss_cli::ExitIdentity;
use fss_cli::agent_json::{array, object, string};
use fss_cli::json_input::{Value, parse};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};

use super::plan::Options;

const FORMAT: &str = "fss.rtsp_import_batch_operator.v1";
const POLICY: &str = "ordered-native-imports:one-destination:independent-epochs:no-network:\
exact-child-approvals:stop-on-unconfirmed:replay-exact-batch-to-reconcile:v1";
const MAX_IMPORTS: usize = 16;
const MAX_REQUEST_BYTES: usize = 48 * 1024;
const MAX_ROW_BYTES: usize = 64 * 1024;
const REQUEST: &str = "ERR-RTSP-IMPORT-BATCH-REQUEST-001";
const APPROVAL: &str = "ERR-RTSP-IMPORT-BATCH-APPROVAL-001";
const OUTPUT: &str = "ERR-RTSP-IMPORT-BATCH-OUTPUT-001";
const RECEIPT: &str = "ERR-RTSP-IMPORT-BATCH-RECEIPT-001";

const HELP: &str = "fss-import-rtsp batch --requests JSON [--approve sha256:HEX]\n\
JSON is an array of 1..16 arrays of ordinary fss-import-rtsp option/value strings.\n\
Every child must explicitly authorize original reading/retention, omit --approve,\n\
and select one native window, catalog or ordered page list. All children must\n\
name the same destination root, site and principal; sources and epochs may differ.\n\
Preview validates EVERY child and prices aggregate ceilings without filesystem,\n\
clock or network access. Approve the exact outer digest, not a child approval.\n\
Execution emits bounded JSONL with each original native receipt. It is incremental,\n\
not atomic: a failed or unreported import may already be durable. No later child\n\
runs after a failure. Preserve all stores and repeat the exact approved batch\n\
to reconcile; completed native imports retain their identities. No source epochs\n\
are merged, no capture times are inferred, and no continuity/absence is certified.\n\
Input is at most 49152 UTF-8 bytes; preview and each output row at most 65536 bytes.\n";

type Result<T> = std::result::Result<T, &'static str>;

struct BatchPlan {
    children: Vec<Options>,
    pins: Vec<ContentDigest>,
    approve: Option<ContentDigest>,
}

impl BatchPlan {
    fn parse(args: &[OsString]) -> Result<Self> {
        if !matches!(args.len(), 2 | 4) {
            return Err(REQUEST);
        }
        let mut requests = None;
        let mut approve = None;
        for pair in args.as_chunks::<2>().0 {
            match pair[0].to_str() {
                Some("--requests") if requests.is_none() => {
                    let text = pair[1].to_str().ok_or(REQUEST)?;
                    if text.is_empty() || text.len() > MAX_REQUEST_BYTES {
                        return Err(REQUEST);
                    }
                    requests = Some(text);
                }
                Some("--approve") if approve.is_none() => {
                    let text = pair[1].to_str().ok_or(REQUEST)?;
                    if text.len() != 71 {
                        return Err(REQUEST);
                    }
                    let digest = ContentDigest::parse(text).map_err(|_| REQUEST)?;
                    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
                        return Err(REQUEST);
                    }
                    approve = Some(digest);
                }
                _ => return Err(REQUEST),
            }
        }
        let document = parse(requests.ok_or(REQUEST)?).map_err(|_| REQUEST)?;
        let requests = document.array().ok_or(REQUEST)?;
        if !(1..=MAX_IMPORTS).contains(&requests.len()) {
            return Err(REQUEST);
        }
        let mut children: Vec<Options> = Vec::with_capacity(requests.len());
        let mut pins = Vec::with_capacity(requests.len());
        for request in requests {
            let values = request.array().ok_or(REQUEST)?;
            if values.is_empty() || values.len() > super::plan::MAX_ARGUMENTS {
                return Err(REQUEST);
            }
            let input = values
                .iter()
                .map(|value| value.text().map(OsString::from).ok_or(REQUEST))
                .collect::<Result<Vec<_>>>()?;
            let child = Options::parse(&input).map_err(|_| REQUEST)?;
            let pin = child.approval()?;
            if child.approve.is_some() || pins.contains(&pin) {
                return Err(REQUEST);
            }
            if let Some(first) = children.first()
                && (child.root != first.root
                    || child.site != first.site
                    || child.principal != first.principal)
            {
                return Err(REQUEST);
            }
            children.push(child);
            pins.push(pin);
        }
        let plan = Self {
            children,
            pins,
            approve,
        };
        // Even approved execution must admit the complete pure preview before any child I/O.
        plan.preview()?;
        Ok(plan)
    }

    fn approval(&self) -> Result<ContentDigest> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(FORMAT);
        encoder.text(POLICY);
        encoder.u64(MAX_IMPORTS as u64);
        encoder.u64(MAX_REQUEST_BYTES as u64);
        encoder.u64(MAX_ROW_BYTES as u64);
        encoder.u64(self.pins.len() as u64);
        for pin in &self.pins {
            encoder.digest(*pin);
        }
        let bytes = encoder.finish_checked().map_err(|_| REQUEST)?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn sum(&self, price: impl Fn(&Options) -> u64) -> Result<u64> {
        self.children.iter().try_fold(0_u64, |total, child| {
            total.checked_add(price(child)).ok_or(REQUEST)
        })
    }

    fn preview(&self) -> Result<String> {
        let children = self
            .children
            .iter()
            .map(Options::preview)
            .collect::<Result<Vec<_>>>()?;
        bounded(object(&[
            ("format", string(FORMAT)),
            ("kind", string("plan")),
            ("approval_digest", string(&self.approval()?.to_text())),
            ("policy", string(POLICY)),
            ("imports", self.children.len().to_string()),
            (
                "maximum_frames",
                self.sum(|c| c.request.max_frames as u64)?.to_string(),
            ),
            (
                "maximum_original_bytes",
                self.sum(|c| c.request.max_original_bytes)?.to_string(),
            ),
            (
                "maximum_media_bytes",
                self.sum(|c| c.request.max_media_bytes)?.to_string(),
            ),
            ("maximum_work", self.sum(|c| c.work)?.to_string()),
            (
                "sum_child_timeout_ms",
                self.sum(|c| c.timeout_ms)?.to_string(),
            ),
            (
                "timeout_scope",
                string("per-child-cooperative-not-preemptive"),
            ),
            (
                "maximum_report_bytes",
                ((2 * self.children.len() + 2) * (MAX_ROW_BYTES + 1)).to_string(),
            ),
            ("atomic", "false".into()),
            ("continuity_between_imports", "false".into()),
            ("absence_certifiable", "false".into()),
            ("network", string("none")),
            ("writes", string("none-until-exact-outer-approval")),
            ("children", array(&children)),
        ]))
    }
}

fn bounded(text: String) -> Result<String> {
    if text.len() > MAX_ROW_BYTES {
        Err(OUTPUT)
    } else {
        Ok(text)
    }
}

trait Effects {
    fn emit(&mut self, row: &str) -> Result<()>;
    fn import(&mut self, child: &Options) -> Result<String>;
}

fn row(
    effects: &mut impl Effects,
    approval: ContentDigest,
    sequence: &mut usize,
    kind: &str,
    detail: String,
) -> Result<()> {
    let row = bounded(object(&[
        ("format", string(FORMAT)),
        ("approval_digest", string(&approval.to_text())),
        ("sequence", sequence.to_string()),
        ("kind", string(kind)),
        ("detail", detail),
    ]))?;
    effects.emit(&row)?;
    *sequence += 1;
    Ok(())
}

fn verify_receipt(receipt: &str, approval: ContentDigest) -> Result<()> {
    if receipt.len() > MAX_ROW_BYTES {
        return Err(OUTPUT);
    }
    let value = parse(receipt).map_err(|_| RECEIPT)?;
    let fields = value.object().ok_or(RECEIPT)?;
    if fields.get("kind").and_then(Value::text) != Some("imported")
        || fields.get("approval_digest").and_then(Value::text) != Some(approval.to_text().as_str())
    {
        return Err(RECEIPT);
    }
    Ok(())
}

fn execute(plan: &mut BatchPlan, effects: &mut impl Effects) -> Result<()> {
    let approval = plan.approval()?;
    if plan.approve != Some(approval) {
        return Err(APPROVAL);
    }
    // Revalidate the canonical plans, not just a cached pin, before emitting or delegating.
    for (child, pin) in plan.children.iter().zip(&plan.pins) {
        if child.approval()? != *pin {
            return Err(APPROVAL);
        }
    }
    plan.preview()?;
    let count = plan.children.len();
    let mut sequence = 0;
    row(
        effects,
        approval,
        &mut sequence,
        "batch_started",
        object(&[
            ("imports", count.to_string()),
            ("atomic", "false".into()),
            ("network", string("none")),
            ("continuity_between_imports", "false".into()),
        ]),
    )?;
    for (index, (child, pin)) in plan.children.iter_mut().zip(&plan.pins).enumerate() {
        row(
            effects,
            approval,
            &mut sequence,
            "import_started",
            object(&[
                ("ordinal", (index + 1).to_string()),
                ("child_approval", string(&pin.to_text())),
            ]),
        )?;
        // Only the exact outer approval delegates these original, independently checked plans.
        // The original importer owns all filesystem, lock, clock, cancellation and custody I/O.
        child.approve = Some(*pin);
        let result = effects.import(child).and_then(|receipt| {
            verify_receipt(&receipt, *pin)?;
            Ok(receipt)
        });
        match result {
            Ok(receipt) => row(
                effects,
                approval,
                &mut sequence,
                "import_completed",
                object(&[("ordinal", (index + 1).to_string()), ("receipt", receipt)]),
            )?,
            Err(error) => {
                row(
                    effects,
                    approval,
                    &mut sequence,
                    "batch_terminal",
                    object(&[
                        ("complete", "false".into()),
                        ("completed_imports", index.to_string()),
                        ("failed_import", (index + 1).to_string()),
                        ("unattempted_imports", (count - index - 1).to_string()),
                        ("error_id", string(error)),
                        ("failed_import_state", string("unconfirmed_may_be_durable")),
                        (
                            "reconciliation",
                            string("repeat_exact_approved_batch_with_original_archives"),
                        ),
                        ("atomic", "false".into()),
                        ("continuity_between_imports", "false".into()),
                        ("absence_certifiable", "false".into()),
                    ]),
                )?;
                return Err(error);
            }
        }
    }
    row(
        effects,
        approval,
        &mut sequence,
        "batch_terminal",
        object(&[
            ("complete", "true".into()),
            ("completed_imports", count.to_string()),
            ("failed_import", "null".into()),
            ("unattempted_imports", "0".into()),
            ("error_id", "null".into()),
            ("atomic", "false".into()),
            ("continuity_between_imports", "false".into()),
            ("absence_certifiable", "false".into()),
        ]),
    )
}

struct Native;
impl Effects for Native {
    fn emit(&mut self, row: &str) -> Result<()> {
        super::emit(row).map_err(|_| OUTPUT)
    }
    fn import(&mut self, child: &Options) -> Result<String> {
        super::driver::execute(child)
    }
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    let result = if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help")) {
        super::emit(HELP).map_err(|_| OUTPUT)
    } else {
        let mut plan = match BatchPlan::parse(args) {
            Ok(plan) => plan,
            Err(code) => {
                eprintln!("{code}: invalid bounded batch request; use fss-import-rtsp batch --help");
                return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
            }
        };
        if plan.approve.is_none() {
            plan.preview()
                .and_then(|preview| super::emit(&preview).map_err(|_| OUTPUT))
        } else {
            execute(&mut plan, &mut Native)
        }
    };
    match result {
        Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
        Err(code) => {
            eprintln!("{code}: batch not confirmed; preserve every store and complete receipt. Replay the exact approved batch to reconcile; do not infer rollback or retry from truncated output.");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
#[path = "batch_tests.rs"]
mod tests;
