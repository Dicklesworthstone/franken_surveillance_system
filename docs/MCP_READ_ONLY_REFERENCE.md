# Read-only MCP reference adapter

`fss-mcp` connects a local MCP client to existing deployment reads. It is an
owner-launched stdio process, not a network service. Its registered tool names
come from the same crosswalk as the CLI. It calls the CLI library in-process;
there is no shell, subprocess dispatch, model runtime or new dependency.

## Run

```sh
cargo build --locked -p fss-cli --bin fss-mcp
./target/debug/fss-mcp --root /absolute/path/to/deployment
```

`--root` is required and must already exist. The launcher may additionally supply
`--principal principal:local-operator`. This is the same **audit label, not an
authentication mechanism**, used by the existing CLI reads. The root is resolved
at startup; tool arguments cannot override either root or principal. Trust the
MCP client and launching OS account with the read access of the CLI. This is not
a filesystem sandbox against a malicious local operator or a remote-auth service.

Typical client configuration, with paths replaced for the deployment:

```json
{
  "mcpServers": {
    "fss": {
      "command": "/absolute/path/to/fss-mcp",
      "args": ["--root", "/absolute/path/to/deployment"]
    }
  }
}
```

## Implemented reads

| Registered tool | Existing semantic implementation | Arguments |
| --- | --- | --- |
| `session_orient` (AOP-003) | `fss session orient` / `execute_orient` | Optional `view`: `pulse`, `brief`, `epistemic_map`; optional `budget_tokens`: 1..4096, additionally subject to the view's own limit |
| `session_follow` (AOP-004) | `fss session follow` / `execute_follow` | Required `since` anchor token; optional `view`: `pulse`, `brief`; `max_entries`: 1..4096; exact `continuation` token |
| `explain` (AOP-011) | `fss explain` / `execute_explain` | Required `event_id` |
| `doctor` (AOP-014) | `fss doctor --root` | No arguments; fixed deployment only |

The first three return the **unchanged serialized `AgentResponseEnvelope`** as
the MCP result's text content. Doctor returns its existing `fss.doctor.v1`
diagnostic report; it is not relabeled as an agent envelope. No semantic response
is shortened, reclassified, or synthesized by the transport. A nonzero CLI exit
sets MCP `isError: true` while preserving the original response and its error ID,
partial results, recovery guidance and uncertainty.

Follow is one bounded read. Obtain `since` from an orientation. To continue a page,
keep `since`, principal, view and page size unchanged and pass the exact continuation
returned by the previous page. The existing engine checks lineage, anchor binding,
head freshness, stream identity and cursor validity. The adapter never treats a
missing or stale anchor as "latest", never auto-rebases a rejected continuation,
and never converts an unwitnessed coverage gap into a silence certificate.

No mutation tool is advertised or accepted: session open/resume/handoff, commit,
alerts, repair, retention changes and other effects remain unavailable. The
read-only annotations are discovery hints; actual enforcement is an explicit
argument allowlist followed by a typed `FssCommand` dispatch clamp.

## Wire behavior and limits

The negotiated protocol is **MCP 2025-06-18**, not a claim to implement every later
protocol revision. The server accepts `initialize`, then
`notifications/initialized`, `ping`, `tools/list` and `tools/call`. The complete
four-tool list is returned in one response. There are no resources, subscriptions,
sampling, elicitation or asynchronous tasks.

Messages are UTF-8 JSON-RPC objects delimited by newlines; batches are refused.
Stdout contains only protocol messages, and each response is flushed. Notifications
never invoke reads and never receive replies. Diagnostics go to stderr. EOF ends
the process; a partial final line is rejected rather than executed.

Input is bounded before allocation grows beyond the admitted frame: 64 KiB
including the newline, 32 nesting levels, 4096 values, and 16 KiB per decoded
string. Duplicate keys, including escaped aliases of a key, malformed Unicode and
invalid JSON numbers are refused. Integer request IDs retain their spelling and
are never rounded through floating point. IDs must fit a signed 64-bit integer or
be a string of at most 128 bytes.

Semantic output is limited to 4 MiB before JSON string escaping. Above that ceiling
the server returns an explicit error asking for a smaller view/page, not a
truncated or falsely complete envelope. The existing semantic reader's limits
remain in force; this transport ceiling does not raise them.

## Scope and qualification boundary

This is a dependency-free, synchronous **reference projection of the implemented
CLI read arguments**. It does not implement the full universal
`AgentRequestEnvelope` ingress, arbitrary sessions/missions, capability negotiation,
privacy projections, remote authentication, in-flight cancellation, live follow or
FastMCP/Asupersync orchestration. It does not qualify the underlying surveillance
pipeline or any release gate. Full request-envelope admission and request-owned
production transport remain open under comprehensive-plan sections 20.6.1,
20.15 and 20.17. No unsupported request field is silently accepted.

`fss-mcp` initialization and tool discovery describe this narrow transport. Older
aggregate `fss capabilities`/implementation-status entries that say MCP is absent
predate this adapter; they must not be read as claiming the full MCP architecture
is now complete.

## Tests

```sh
cargo test --locked -p fss-cli --bin fss-mcp
cargo test --locked -p fss-cli --test mcp_cli_contract
```

Unit tests cover parsing budgets, duplicate keys, Unicode, exact IDs, lifecycle,
notification nonexecution, scope clamps, read-only dispatch, token passthrough,
byte ceilings and framing. The integration tests start the actual executable over
a real `ReferenceDeployment`, compare its semantic response bytes with the CLI,
check wrong-stream refusal parity, and compare every deployment file and directory
before and after reads and rejected writes.

These Rust tests were **not executed in the authoring environment**, which lacked
`cargo` and `rustc`. Included tests and a successful Git commit are not test-pass or
qualification receipts.

Protocol reference: `modelcontextprotocol/modelcontextprotocol`, specification
`2025-06-18`, `basic/lifecycle`, `basic/transports`, and `server/tools`.
