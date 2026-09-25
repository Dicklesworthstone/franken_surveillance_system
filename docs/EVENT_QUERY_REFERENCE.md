# Bounded event queries through CLI and MCP

`fss query` exposes the existing `fss_reference::agent_query::query_deployment`
engine. It searches the latest verified, committed revision of each event. It
neither searches raw footage nor certifies that physical activity did or did not
occur. The same typed command serves the MCP `query` tool, without a subprocess
or a second query implementation.

## CLI

```sh
cargo build --locked -p fss-cli --bin fss --bin fss-mcp
./target/debug/fss query --json --root /absolute/deployment \
  --zone door --kind unclassified --max-entries 8
```

Optional predicates are conjunctive: `--event-id`, `--kind`, `--state`, `--zone`,
`--from-ns`, and `--through-ns`. Event IDs, kinds, lifecycle states and zone labels
are exact, case-sensitive metadata matches. Time endpoints are independently
optional signed 128-bit nanoseconds, in canonical decimal spelling. Matching uses
possible overlap of closed recorded intervals, including endpoints, not receipt
time, interval midpoints or inferred UTC. Reversed intervals fail closed.

`--max-entries` is 1..32 (default 16). The complete verified catalogue is separately
bounded at 128 events. Reducing page size or excluding events does not bypass a
catalogue read/integrity failure.

`--anchor` optionally requires an exact current authority/effect-history token.
Every answer exposes the token in `claim:query:anchor`. Continue with the returned
`continuation`, keeping all predicates, principal and page size unchanged. The
native engine binds the full index, contract basis and authority/effect-history
head. Any such change refuses the cursor; no automatic rebase or raw offset is
accepted. This is latest-revision querying, not historical/as-of search.

## MCP

Start the existing owner-launched stdio adapter:

```sh
./target/debug/fss-mcp --root /absolute/deployment
```

After initialization, call `query` with optional `event_id`, `kind`, `state`, `zone`,
`from_ns`, `through_ns`, `max_entries`, `anchor` and `continuation`. The launcher
fixes the root and principal audit label; tool arguments cannot replace them.
Nanosecond endpoints are JSON **strings**, not numbers, to preserve the full
signed 128-bit range across clients:

```json
{"name":"query","arguments":{"zone":"door","from_ns":"1000000000","through_ns":"2000000000","max_entries":8}}
```

No notification executes a query. Unknown fields, scope overrides, effects,
malformed integers and invalid enums are rejected. The result contains the exact
CLI library `AgentResponseEnvelope` bytes as text; a nonzero exit becomes
`isError: true` without rewriting the refusal or its uncertainty.

## Answers and boundaries

AOP-005 returns the registered cognitive envelope in the case view. Its
record-level propositions and completeness come from the native query engine.
Protected deployment context comes from the existing bounded orientation, read
from the same verified snapshot: coverage, contradictions, tamper and unresolved
effects are not removed just because a query filter excludes an event. Existing
read-side refresh and per-hit explanation affordances are listed, never executed.

An empty matching set retains `claim:query:physical-absence` as `unknown`.
`committed_index_exhausted` describes the index, not physical surveillance
coverage. The outer completeness remains `bounded`, even on the last page.
Remaining matched records are named by exact continuations. Oversized complete
responses (256 KiB, including JSON escaping) are refused rather than clipped.

The projection adapts to the newer engine already present on main; it does not
replace that engine with the older implementation bundle. Consequently it uses
`from_ns`/`through_ns`, supports the native `kind` and `anchor` fields, and does not
add the old bundle's `after_commit` predicate.

This remains a synchronous local reference interface. Principals are audit labels,
not authentication. It does not implement universal `AgentRequestEnvelope`
ingress, arbitrary session/workspace authority, natural-language interpretation,
remote authentication, physical-absence certification, or effect execution. Query
CPU, output tokens and elapsed time are not metered; the native admission latency
allowance is neither elapsed time nor an enforced deadline. No production or
release qualification is claimed.

## Verification

```sh
cargo test --locked -p fss-cli --lib query_cmd
cargo test --locked -p fss-cli --bin fss-mcp query_
cargo test --locked -p fss-cli --test query_surface_contract
```

The added regressions cover canonical predicates and i128 bounds, real deployment
reads, unchanged response bytes across CLI/library/MCP, native cursor refusals,
non-mutation, schema validation and forbidden transport inputs. Rust compilation,
Rustfmt and these tests were not executed in the authoring environment because
`cargo`, `rustc` and `rustfmt` were unavailable. Static syntax checks are not
compilation or qualification receipts. Run the repository's normal manifest and
qualification lanes against the final formatted tree before qualification.
