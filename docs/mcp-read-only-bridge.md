# Read-only MCP bridge (reference, opt-in)

`scripts/fss_mcp_bridge.py` exposes the existing FSS read-only agent commands over
newline-delimited MCP stdio. It is an optional Python 3.11+ / POSIX reference
adapter with no third-party packages. It is **not** the planned native Rust /
Asupersync service, a production qualification, an authorization system, or a
replacement for the canonical agent contracts.

## Start

Build `fss` using the repository's normal Rust toolchain. Launch the bridge with
absolute paths to the exact operator-trusted executable and authorized deployment:

```sh
python3 /absolute/path/to/repo/scripts/fss_mcp_bridge.py \
  --fss-binary /absolute/path/to/repo/target/debug/fss \
  --root /absolute/path/to/deployment \
  --principal principal:local-mcp
```

Configure an MCP client's stdio server with `python3` as its command and those
arguments as separate strings. No shell wrapper is required. stdout is reserved
for MCP messages; startup errors use a fixed identity on stderr. Close stdin to
shut down. SIGTERM and SIGINT also cancel and reap active CLI subprocesses.

The transport supports modern MCP `2026-07-28` and legacy `2025-11-25` /
`2025-06-18`. Modern requests carry `io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities` in `params._meta` on **every request**;
`server/discover` reports the supported versions and capabilities. No initialization
is needed in modern mode. Result wrappers include `resultType: "complete"` and
server identity metadata without modifying the enclosed FSS envelope.

Legacy clients use initialize followed by notifications/initialized. Both modes
support ping, tools/list, tools/call and notifications/cancelled. Both can share a
process, but one request's version, client identity or capabilities are never used
as authority for a later modern request. Unsupported modern versions receive the
specified `-32022` error. The adapter does not advertise subscriptions, prompts,
resources, model sampling, tasks, or effects.

For example, a modern discovery request is one line:

```json
{"jsonrpc":"2.0","id":"discover-1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
```

## Registered tool surface

| MCP tool | Existing CLI command | Contract |
|---|---|---|
| `session_orient` | `fss session orient --json` | AOP-003 |
| `session_follow` | `fss session follow --json` | AOP-004 |
| `query` | `fss query --json` | AOP-005 |
| `explain` | `fss explain --json` | AOP-011 |

Names match `architecture/operation_crosswalk.json`. Tool schemas expose only
these commands' read arguments. Root, executable, principal and process limits
are operator configuration, never tool arguments. Session open/resume/handoff,
alert preparation/commit, export, retention, deletion, capture and arbitrary
commands are deliberately absent.

A successful call returns the entire parsed CLI JSON object as
`structuredContent`, and the original JSON text (outer whitespace stripped) as a
text content item. A nonzero CLI exit with a valid JSON object remains an MCP tool
error with that object preserved. `_meta["fss/bridge"]` records operation identity,
exit code and hashes of the exact stdout/stderr bytes. Raw stderr is never sent to
clients. A timeout, corrupt response, output limit, or execution failure returns a
bridge error **without** a fabricated FSS envelope or authority receipt.

For follow/query, carry every anchor and continuation token unchanged. The bridge
neither stores a hidden cursor nor substitutes the latest anchor. `session_follow`
is one bounded read, not a live subscription. An empty query is not negative
physical evidence; uncovered, stale, indeterminate, redacted and incomplete states
are not promoted to complete. Affordances are data, not instructions to execute.

Query `from_ns` and `through_ns` are canonical decimal **strings** covering signed
i128, so JavaScript clients need not round nanoseconds through IEEE-754 numbers.
Underlying CLI validation remains authoritative for semantic values and view
budgets; transport validation is an additional bound, not an alternative policy.

## Limits and security boundary

Default CLI execution timeout is 15 seconds (operator range 0.05–60). stdout is
bounded to 2 MiB (operator range 1 KiB–16 MiB); stderr is bounded to 16 KiB. The
bridge drains both concurrently and kills/reaps the child process group on
cancellation, timeout or excess output. No automatic retry occurs. Each client
line is at most 64 KiB with JSON nesting at most 64, replies at most 16 MiB, and
there are at most two concurrent reads (operator range 1–4). Additional calls get
`ERR-MCP-BUSY-001`; there is no hidden queue. An unread output pipe is retired after
five seconds of backpressure. Cancellation before a worker's first poll retires
its slot; reply publication releases modern request IDs before local drain while
keeping the outstanding writer in the concurrency budget. Once a complete frame
has been admitted for transmission it cannot be retracted; later cancellation is
too late for that response. A process accepts at most 4,096 admitted requests before
requiring a restart (modern IDs may be reused after a reply, never in flight); oversized frames close the stream rather than interpreting
the suffix as a new command.

The subprocess receives no stdin, no shell, and only a minimal PATH/locale
environment. Startup resolves absolute paths; it does **not** sandbox the binary,
pin its bytes against replacement, prevent a privileged operator from changing a
symlink target, or police arbitrary filesystem/network syscalls. Trust the
operator-owned executable and deployment hierarchy, and use an OS-level
read-only sandbox where required. The audit principal is not authentication.
Every process has one fixed deployment/principal, so use separately authorized
processes for different deployment scopes. Clients receive the evidence the
selected CLI commands expose; do not share this bridge with an unauthorized
client. No listening socket, TLS, HTTP transport or OAuth is implemented.

## Tests and qualification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tests -p test_fss_mcp_bridge.py -v
```

The offline suite exercises actual subprocess and stdio transport boundaries,
strict parsing, argument confinement, exact cursor pass-through, envelope/error
preservation, secret stderr isolation, limits, cancellation, concurrent pressure
and shutdown. Its child executables are **fixtures**, not a built FSS binary or
real deployment. It does not establish model accuracy, camera interoperability,
privacy qualification, native service readiness or complete cross-surface
conformance. Run a real-deployment comparison and the repository qualification
lanes before adoption. No bead is closed by this bridge alone.

Protocol references:
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools

Modern protocol references:
- https://modelcontextprotocol.io/specification/2026-07-28/basic/index
- https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio
- https://modelcontextprotocol.io/specification/2026-07-28/server/discover
