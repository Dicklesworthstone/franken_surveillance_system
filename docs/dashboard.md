# FSS Observatory

A local browser workspace for retained evidence. The `fss-dashboard` Rust binary
embeds its HTML, CSS, JavaScript, icons and explicit demonstration fixture. There
is no frontend build, npm installation, CDN, hosted account or production Python
server. It is an operator-local, read-only view, not an agent protocol or control
surface.

## Launch

From the repository with the pinned toolchain installed:

```sh
cargo +nightly-2026-08-31 run --locked --offline -p fss-cli --bin fss-dashboard -- --demo
```

Open the `http://127.0.0.1:7474` address printed by the binary. The demonstration
banner stays visible in every view. Demonstration records are illustrative UI
fixtures, not validated native events, actual capture results or custody proofs.
No deployment is read in this mode.

For an existing deployment, name its absolute root and exact site lineage:

```sh
cargo +nightly-2026-08-31 run --locked --offline -p fss-cli --bin fss-dashboard -- \
  --root /absolute/path/to/deployment \
  --site site:your-site \
  --allow-local-metadata yes
```

Use an analysis deployment containing `LAYOUT`, its authority/effect journals,
and retained event metadata, not a standalone capture archive or pin journal.
The site must match `LAYOUT`; the dashboard never initializes a missing root.
The acknowledgement permits disclosure of operator-local metadata, including
identifiers, zone names, uncertainty text and evidence references, **without a
privacy/redaction transform**. This is not an approved evidence export.

`--port 0` chooses a free loopback port. `--serve-seconds N` sets a finite lease
from 1 to 86400 seconds; the default is eight hours. Ctrl-C stops the process.
The binary prints the address rather than spawning an external browser process.
`--snapshot` emits the same bounded metadata projection to stdout and opens no
listener. It cannot be combined with listener options.

## Explore

**Overview:** retained-event and import counts, open obligations, indeterminate
effects, an interactive event-interval timeline, recent events and an exact
record inspector. Select an interval or an event to follow its provenance.
The timeline uses relative capture coordinates, not inferred UTC. Empty space
is not coverage and does not establish absence. Beyond five named zones, the
overview explicitly groups additional zones; the explorer retains every zone.

**Event explorer:** search by event identifier, semantic kind, lifecycle state,
zone or declared failure domain. Combine state and zone filters, reset them, and
page through every admitted latest revision. A count always distinguishes the
filtered inventory from the retained inventory.

**Evidence graph:** select an event, filter relationship kinds, inspect exact
references, zoom, pan and fit the graph. All declared edges remain reachable in
pages of twelve. Supporting, contradictory and sensor-integrity relationships
remain distinct. References are not source availability proofs; matching digests
are not independent observations. The graph is not a physical camera map.

**Operations:** native read-only doctor verdict, uncommitted journal-tail flags,
effect-journal presence, source-read accounting, effect and obligation state
counts, retained import roots and committed evidence-family counts. No button
can prepare an effect, acknowledge an obligation, change a policy, repair a
journal, connect to a camera, or mutate the deployment.

The inspector shows recorded probability **intervals**, calibration presence,
full-width capture coordinates, revision identities and original canonical JSON.
A model score is not promoted to corroboration. The native event state is shown
literally; this viewer does not adjudicate it.

Keyboard: `1`–`4` switch views, `/` searches events, and `Ctrl-K` / `Cmd-K` opens
the command palette. Arrow keys choose a command, Enter opens it, and Escape
closes the dialog. Interactive graph/timeline nodes also support Enter and Space.
Dark and light themes use local system fonts; only the theme preference is stored
in browser local storage. Layouts adapt to narrow screens and reduced motion.

## Read lifecycle and boundaries

`agent_orient::read_deployment` remains the native source of truth. It inspects
retained committed metadata and verifies event object/revision bindings. The
dashboard does not use shell commands, parse CLI prose, hydrate media, inspect
secret files, or create a second persistence system.

Every response contains the selected site, ledger root, retained position,
counts, journal status, scope and original event records. Native event JSON is
carried as original strings. Before parsing those strings, the presentation model
preserves integer tokens outside JavaScript's safe integer range as decimal
strings; timeline arithmetic uses signed-128-bit-checked `BigInt`. The inspector
never reconstructs the canonical JSON from rounded JavaScript numbers.

Reads have explicit bounds: 256 events, 64 revisions per event, 16 MiB per
journal, 2 MiB per event object, 4096 completed-import references and 4 MiB per
rendered report. The five-second read deadline is cooperative before and after
the existing bounded native reader, not preemption of a filesystem call. An
over-limit or damaged deployment refuses instead of silently truncating its
important facts. No page is presented as the full inventory after a bound fails.

The browser requests a new snapshot fifteen seconds after a successful read.
Only one request is in flight; hidden tabs and explicit pause stop polling. Reads
are bounded to ten seconds and 4 MiB in the browser. A failure clears prior event,
import, graph and inspector contents, displays an error, and waits for explicit
retry. A real read never falls back to synthetic data. A paused view explicitly
warns that retained metadata may no longer reflect current custody or privacy.

## Local threat model

The listener binds only IPv4 loopback. It is **not** an authenticated multi-user
web service: other processes and trusted browser extensions on the same machine
can read the authorized metadata. Do not reverse-proxy it, forward its port or
expose it through a tunnel. Use the exact printed numeric-loopback address, not
`localhost` or another Host alias.

Requests require an exact Host; metadata requests additionally need the custom
same-origin read header. Cross-origin Origin/Fetch-Metadata values, duplicate
headers, request bodies, transfer encoding and non-GET methods are refused.
Assets are an embedded allowlist, never arbitrary filesystem paths. There is no
CORS grant, iframe embedding, external script/font/image fetch or write endpoint.
The response CSP permits only the embedded same-origin script/style resources;
metadata is rendered with text nodes, not HTML. Responses are `no-store`.

The server owns one connection at a time, limits headers to 8 KiB and 64 fields,
and applies absolute two-second read/write deadlines. It has no detached
producer or unbounded worker queue. These defenses reduce browser-origin and
resource risks; they do not make a hostile local process trustworthy.

## Verification

```sh
bash scripts/bootstrap_toolchain.sh
bash scripts/check_dashboard.sh
```

The shared check runs the dependency-free JavaScript model tests, native command
and deployment readback tests, and real HTTP tests against the built Rust binary.
The HTTP check covers the embedded assets, exact lengths, Host/origin/read-header
requirements, traversal refusal, write refusal, slow-request timeout and lease
expiry. The deployment tests compare complete small native fixture inventories
before/after reads and refusal paths.

For offline presentation/interaction tests and screenshots, with Playwright and
Chromium installed as **test tools only**:

```sh
python3 tests/test_dashboard_browser.py \
  --chromium /usr/bin/chromium --artifacts /tmp/fss-dashboard-previews
```

This harness injects the shipped DOM, styles and scripts into a headless browser
with the explicit synthetic fixture. It tests rendering, filtering, graph
selection/zoom, keyboard navigation, themes, narrow layouts, exact timestamps,
failed-read clearing, recovery and text injection. It does not test native HTTP,
CSP enforcement, real capture, field-camera behavior or production qualification.

Current scope is retained evidence metadata. Live camera tiles, native frame
preview, spatial calibration overlays, historical revision playback and writable
operator controls require their own source/authority/privacy integration and are
not claimed by this dashboard.
