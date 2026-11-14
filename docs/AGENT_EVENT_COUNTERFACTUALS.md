# Explain a current event under declared source loss

The canonical AOP-011 `explain` operation now accepts a bounded `what_if`
question: **what would the numerical assessment be if selected declared failure
domains were unavailable?** It returns the complete current event declaration,
an explicit hypothetical baseline, the changed query, both recomputed outcomes
and their derivation receipts. The CLI and MCP use the same owner.

This closes the gap between the pure fusion ablation API and an agent working
with an actual retained event. The retained event supplies exact evidence and
failure-domain identities. It does **not** supply measured detector scores,
verified physical sensor identities or a current physical coverage witness.
The caller must therefore supply the numerical assumptions explicitly.

## Prepare an exact request

Select the event and its current revision using the existing event query or
explanation:

```sh
fss query --json --root /absolute/deployment --target events
fss explain --json --root /absolute/deployment \
  --event-id event:selected --view forensic --budget-tokens 16000
```

Use the selected event's exact revision digest and declared evidence domains,
not camera names inferred from a label or an edge's position. Every domain on a
`Supports` or `Contradicts` evidence edge must have one explicit raw score.
The map must also include domains selected for removal: the complete baseline
is computed before the loss scenario.

The request is a closed JSON object with schema
`fss.event_counterfactual_request.v1`. Machine-readable contracts are available
in [the request schema](../schemas/event_counterfactual_request.v1.json) and
[the complete artifact schema](../schemas/event_counterfactual.v1.json):

| Field | Meaning |
|---|---|
| `event_revision_digest` | Exact, nonzero SHA-256 digest of the current retained event revision. |
| `without_domains` | Between one and 16 unique, exact contributing failure-domain identities. They form one simultaneous scenario. |
| `score_calibration` | Complete `fss.score_calibration.v1` object, with generation, digest and count-derived bins. |
| `domain_scores_ppm` | Exact map of contributing failure domains to JSON integer scores from 0 through 1,000,000. |
| `fusion_policy` | Optional canonical `alert,retain,reject` milliban threshold string. Default: `"1000,0,-1000"`. |

A calibration bin declares `lo_ppm`, `true_positives` and `false_positives`.
The derived `hi_ppm` and `llr_millibans` fields are verified when supplied. The native calibration report emitted by
`fss-evaluate --calibration-bins` can supply the `score_calibration` object.
The owner rebuilds the calibration from its counts, checks the digest and
verifies any supplied derived totals, intervals, prior and bin likelihood
summaries. The caller remains responsible for whether that calibration applies
to the hypothetical raw scores.

For example, create `source-loss-request.json` with the following shape,
replacing the revision, domain identities and calibration with actual selected
inputs. The angle-bracket values below are placeholders, not valid digests or a
runnable calibration:

```json
{
  "schema": "fss.event_counterfactual_request.v1",
  "event_revision_digest": "sha256:<exact-current-event-revision>",
  "without_domains": ["camera:east"],
  "score_calibration": {
    "schema": "fss.score_calibration.v1",
    "generation": "<applicable-calibration-generation>",
    "digest": "sha256:<verified-calibration-digest>",
    "bins": [
      {
        "lo_ppm": 0,
        "hi_ppm": 299999,
        "true_positives": 5,
        "false_positives": 95
      },
      {
        "lo_ppm": 300000,
        "hi_ppm": 699999,
        "true_positives": 50,
        "false_positives": 50
      },
      {
        "lo_ppm": 700000,
        "hi_ppm": 1000000,
        "true_positives": 95,
        "false_positives": 5
      }
    ]
  },
  "domain_scores_ppm": {
    "camera:east": 900000,
    "camera:west": 850000
  },
  "fusion_policy": "1000,0,-1000"
}
```

The example counts and scores are synthetic. They demonstrate the input shape;
they are not deployment measurements.

Unknown keys, duplicate JSON keys, score aliases, numeric strings, out-of-range
scores, missing or extra score mappings, and unknown or duplicate exclusions
are refused. The complete request, including its canonical expansion, is
bounded to 32 KiB. A declared domain is at most 256 UTF-8 bytes. Reserved
synthetic common-cause identities cannot masquerade as source domains.

## CLI and MCP

Pass the complete request as literal JSON:

```sh
fss explain --json --root /absolute/deployment \
  --event-id event:selected --question what_if \
  --counterfactual "$(cat source-loss-request.json)" \
  --view forensic --budget-tokens 16000
```

Here the shell reads the caller's chosen file. The `--counterfactual` argument
itself accepts an inline JSON value; it is not a server-side path or an
`@file` reference. The operation requires an event ID and cannot be combined
with historical `--at`, event-change `--from`/`--to`, learning or custody
questions, or the legacy `--score-calibration`/`--fusion-policy` file mode.

Launch the existing stdio server with its deployment and audit principal fixed
by the operator:

```sh
fss-mcp --root /absolute/deployment --principal principal:operator
```

After normal MCP initialization, call `explain` with
`question: "what_if"`, `event_id`, the request object as `counterfactual`,
`view: "forensic"` and `budget_tokens: 16000`. Send `counterfactual` as a
JSON object, not a serialized JSON string or path. Root, principal, capability
and privacy overrides remain outside this request. The local principal is an
audit label, not remote authentication.

The default `decision_diff` view has a 1,800-token ceiling. `forensic` has
an 8,000-token default and a 16,000-token maximum. Complete artifacts can exceed
compact defaults, so the examples explicitly request the larger admitted
allowance. The implementation never enlarges the caller's allowance.

## What the result means

The numerical baseline uses the supplied calibration's prior and explicitly
mapped scores. It keeps the original relation metadata in `source_event`;
support and contradiction labels never manufacture numerical scores. All
projected evidence shares the supplied `calibration:<digest>` dependency and
one synthetic `event-evidence-projection` sensor grouping. Distinct domain
labels therefore do not create physical independence.

The scenario marks matched evidence rows as `not_observable`, retaining their
original identities, scores, calibration and declared domains. The ordinary
fusion owner then recomputes the remaining usable clusters and their
uncertainty. It does not subtract a precomputed cluster from the posterior.
Both the baseline and changed query retain a coverage gap because this path
has no current physical coverage witness. Low scores or loss of every source
cannot become a physical absence claim.

The consequence profile is explicit in the artifact: expected harm 1,000,
false-alert cost 100, delay cost 10, irreversible consequence, one look and
virtual time zero. No future observations or probes are added. These are fixed
hypothetical assumptions; they do not replay the event's historical policy,
change its probability or lifecycle, publish another revision, or authorize an
alert or other effect.

The canonical response remains `AgentResponseEnvelope` with its existing
cognitive payload. Additional propositions have IDs
`claim:event-counterfactual:row:<n>` and statements of this form:

```text
Hypothetical source-loss artifact at /request/without_domains: ["camera:east"]
```

Each JSON pointer names a complete JSON value. Small subtrees stay together;
large containers are split recursively, retaining scalar values and empty
arrays or objects. Reassemble every row at its pointer to recover the full
`fss.event_counterfactual.v1` artifact. Do not treat one row as the whole
result. Pointer segments use JSON Pointer escaping for `~` and `/`.

The complete artifact contains:

- The original canonical `source_event`, its revision digest and publication root.
- The normalized request and its digest, including every exact raw score.
- The native ablation's complete baseline and changed queries, both outcomes,
  affected evidence inventories, work counts and digest.
- The typed `WhatIf` explain receipt and enclosing counterfactual digest.
- Explicit assumptions and false values for `source_custody_verified`,
  `historical_decision_replayed`, `physical_coverage_certified`,
  `event_policy_changed`, `published` and `effect_authority`.

Those flags describe the numerical artifact's scope. The adapter verifies
retained event metadata for admission; it does not reopen original media or
certify all source references. The ordinary protected event knowledge,
uncertainty, possible worlds and counterevidence stay attached to the answer.

Map insertion order and selector order do not change semantic identity. An
exact raw-score change does change the request and enclosing receipt, even when
both scores calibrate to the same bin and the numerical ablation is identical.
Derived receipts are recomputable read products, not newly persisted evidence
objects or new hydration handles.

## Current metadata and complete-output boundaries

One immutable retained-metadata owner covers the initial history and event
publication-lineage reads plus final revalidation. The default shared limits
are 256 MiB of metadata payload and 65,536 read attempts. Final checking uses
the same remaining allowance; it does not open a fresh independent budget.

The adapter uses a cooperative 60-second deadline. Payload bytes and read
attempts are measured; semantic UTF-8 bytes divided by four estimate additional
context tokens. CPU time, full model tokenization, allocator peak and elapsed
latency are not claimed as measured resources. Blocking I/O is not guaranteed
to stop exactly at that deadline.

Revalidation is a final sequential observation of current authority and
metadata custody, not an atomic filesystem snapshot or a lease against future
change. These checks cannot exclude a change followed by an undetected revert.

The request, native artifact, proposition rows and final response each have
finite bounds. Subtree rows target 2,048 encoded bytes; an indivisible scalar
statement has a 16,384-byte ceiling. The complete response is bounded to
256 KiB and must fit the requested context allowance. No source, assumption,
counterevidence, dependency, protected world or alternative is silently
truncated to make a successful result fit.

| Refusal | Meaning and next step |
|---|---|
| `ERR-FUSION-INPUT-INVALID-001` | The admitted scenario does not match the event's contributing domains, or its numerical input is invalid. Correct the assumptions. Malformed control JSON can also refuse during CLI/MCP admission before a deployment read. |
| `ERR-AGENT-RESNAPSHOT-001` | The explicitly requested event revision differs from the current selected revision. Re-read the event and intentionally prepare a request for its new digest. |
| `ERR-AGENT-CONTEXT-INCOMPLETE-001` | Complete computation/output, shared source allowances, final custody/authority checks or the cooperative deadline could not be satisfied. The answer contains no partial hypothetical artifact. |

A failed final metadata recheck uses `ERR-AGENT-CONTEXT-INCOMPLETE-001`; it is
not necessarily a stale requested event revision.

## Existing calibrated explanations now require explicit assumptions

The older `fss explain --score-calibration calibration.json` path remains
available for its existing question. Its input must now include a complete
`domain_scores_ppm` map alongside the calibration, with one explicit score
for every contributing declared event domain and no extra keys.

Calibration-only files, invented numeric edge-index mappings and fallback
scores inferred from support/contradiction labels are refused. The legacy
`camera_scores_ppm` spelling remains an alias for domain keys only; duplicated
keys across both maps refuse even when their values agree. The new inline
`what_if` request accepts only `domain_scores_ppm`.

Legacy calibrated results now declare caller assumptions in a dedicated
`caller-assumptions` proposition, keep coverage unknown through an explicit
gap, preserve the shared calibration dependency, and bind exact raw scores
into the receipt. They no longer label low hypothetical scores as
`NoActivity` or treat different event labels as independent physical sensors.

## Implementation and focused contracts

The pure owner is `fss_cli::event_counterfactual`. The canonical adapter is
`orient_cmd::what_if`; the numerical source-loss owner remains
`fss_fusion::ablate`. The broader pure sensor/domain API and historical
native-report adapter are described in [fusion ablation](fusion_ablation.md).

Run the focused contracts with:

```sh
cargo test -p fss-cli --lib event_counterfactual::tests
cargo test -p fss-cli --test event_counterfactual_cli_contract
cargo test -p fss-cli --test explain_fusion_cli_contract
```

The contracts cover explicit complete inputs, exact revision pins, shared
calibration dependence, missingness without physical absence, calibration
tampering, same-bin raw-score identity, normalized request order, bounded
complete output, full canonical CLI/MCP parity and unchanged deployment bytes
and directory membership. Native execution was unavailable in the authoring
environment; source review does not replace compilation, Rust tests, rustfmt
or Clippy.
