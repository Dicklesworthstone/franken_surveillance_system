// Panels that print what the project's own binaries returned when run on this
// take's film files. Nothing here is scripted, with one exception that every
// panel names: whether a match landed on a staged person is worked out by
// comparing the tool's ground point with the scripted positions.

const pct = (n) => Math.round(n * 100) + "%";
// Integer parts per million need at most four decimal places as a percentage.
const chance = (ppm) => ppm / 10000;
const tallyOf = (calls) => {
  const t = calls.reduce((sum, c) => ({ ...sum, [c.outcome]: (sum[c.outcome] ?? 0) + 1 }), {});
  return [
    `${t.ok ?? 0} answered`,
    `${t.partial ?? 0} partial`,
    `${t.refused ?? 0} refused`,
    t.error ? `${t.error} failed` : null,
  ]
    .filter(Boolean)
    .join(", ");
};
const span = (pair, digits = 2) =>
  pair[0] === pair[1] ? pair[0].toFixed(digits) : `${pair[0].toFixed(digits)} to ${pair[1].toFixed(digits)}`;
const count = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
// An upper bound printed to two places must not round below the value it bounds.
const upTo = (value) => {
  const nearest = value.toFixed(2);
  return Number(nearest) < value ? (Number(nearest) + 0.01).toFixed(2) : nearest;
};
const listed = (items) =>
  items.length < 3 ? items.join(" and ") : items.slice(0, -1).join(", ") + " and " + items.at(-1);
const sum = (list, pick) => list.reduce((n, item) => n + (pick(item) ?? 0), 0);
const short = (text) =>
  text
    .replace(/^affordance:/, "")
    .replace(/[0-9a-f]{16,}/g, (hash) => hash.slice(0, 8))
    .replace(/:event:long-/, " ");

/** A machine value, allowed to wrap after each underscore. */
function Code({ children }) {
  const parts = String(children).split("_");
  return (
    <span className="data">
      {parts.map((part, i) => (
        <span key={i}>
          {part}
          {i < parts.length - 1 && (
            <>
              _<wbr />
            </>
          )}
        </span>
      ))}
    </span>
  );
}

function Panel({ title = "Measured on these films", children, className = "" }) {
  return (
    <aside className={"measured " + className}>
      <p className="source source--measured">{title}</p>
      {children}
    </aside>
  );
}

/** Every distinct state and action a set of matches was given, across pairs. */
function kindsOf(pairs, side) {
  const kinds = new Map();
  for (const p of pairs)
    for (const o of p[side].outcomes) {
      const key = o.state + "|" + o.action;
      kinds.set(key, { ...o, count: (kinds.get(key)?.count ?? 0) + o.count });
    }
  return [...kinds.values()];
}

function Kinds({ kinds }) {
  return kinds.map((kind, i) => (
    <span key={kind.state + kind.action}>
      {i > 0 && "; "}
      <Code>{kind.state}</Code>, <Code>{kind.action}</Code>
      {kinds.length > 1 && ` (${kind.count})`}
    </span>
  ));
}

function RetainedDistance({ match }) {
  if (!Number.isFinite(match.retainedDistance))
    return <>The retained report has no scripted-person comparison for this match.</>;
  const first = Math.min(...match.times);
  return <>{match.retainedDistance.toFixed(2)} m from the nearest staged person at {first} s from the start of the film.</>;
}

/** Cross-camera matches, and how the declared independence of the sources changes the result. */
export function Matches({ native, names, staged = [] }) {
  const pairName = (p) => `${names[p.cameras[0]].toLowerCase()} and ${names[p.cameras[1]].toLowerCase()}`;
  const hits = native.pairs.filter((p) => p.separate.count > 0);
  const all = hits.flatMap((p) => p.separate.list);
  const lit = all.filter((m) => m.afterLights);
  const skipped = native.pairs.filter((p) => !p.ran);
  const failed = native.pairs.filter((p) => p.ran && p.separate.outcome !== "ok");
  const quiet = native.pairs.filter((p) => p.ran && p.separate.outcome === "ok" && p.separate.count === 0);
  const fisheye = native.cameras.filter((c) => c.rectilinear === false).map((c) => names[c.id].toLowerCase());
  // The staged story has two cameras agreeing first. The tools may not have been able to compare that pair at all.
  const stagedSkipped = staged.length > 1 && skipped.find((p) => staged.slice(0, 2).every((id) => p.cameras.includes(id)));
  // The driver (scripts/watch-evidence.py, zones_for) widens the ground cells until a pair's shared ground fits in 16.
  const cellSizes = [...new Set(native.pairs.filter((p) => p.ran && p.cell).map((p) => p.cell))];
  const finest = native.settings?.zone_cell_m ?? Math.min(...cellSizes);
  const tried = (
    <p className={stagedSkipped ? "measured__flag" : "measured__aside"}>
      The tools were given {count(native.pairs.length, "pair")} of cameras.
      {skipped.length > 0 &&
        ` ${count(skipped.length, "pair shares", "pairs share")} no ground within range and could not be compared: ${skipped.map(pairName).join("; ")}.`}
      {stagedSkipped && ` The staged story has the ${pairName(stagedSkipped)} cameras agreeing first. The tools could not compare that pair.`}
      {quiet.length > 0 && ` ${count(quiet.length, "pair")} shared ground and matched nothing: ${quiet.map(pairName).join("; ")}.`}
      {cellSizes.length > 1 &&
        ` Cell sizes differ between pairs because the driver starts at ${finest} m and widens the cells a metre at a time until the ground a pair shares fits in 16 of them.`}
      {failed.length > 0 &&
        ` ${count(failed.length, "pair")} did not complete: ${failed.map((p) => `${pairName(p)} (${p.separate.outcome ?? "no outcome"}${p.separate.reason ? ", " + p.separate.reason : ""})`).join("; ")}.`}
      {fisheye.length > 0 &&
        ` The ${listed(fisheye)} ${fisheye.length === 1 ? "camera has a fisheye lens" : "cameras have fisheye lenses"}, which the matching tool cannot place on the ground, so ${fisheye.length === 1 ? "it takes" : "they take"} no part.`}
    </p>
  );
  if (!hits.length)
    return (
      <Panel>
        <p>No pair of cameras produced a match on these films.</p>
        {tried}
      </Panel>
    );
  // Pairs the driver also matched on a coarser grid, as a preview.
  const coarse = native.pairs.filter((p) => p.coarser && p.coarser.outcome === "ok" && p.coarser.cell);
  const separate = kindsOf(hits, "separate");
  const shared = kindsOf(hits, "shared");
  const held = shared.length > 0 && shared.every((kind) => kind.action === "hold");
  return (
    <Panel>
      {hits.map((p) => {
        const people = p.separate.list.filter((m) => m.onPerson);
        const empty = p.separate.list.filter((m) => m.near && !m.onPerson);
        const far = empty.map((m) => m.near.distance);
        const unplaced = p.separate.list.length - people.length - empty.length;
        const nobody =
          empty.length < p.separate.count
            ? `${empty.length} had nobody there`
            : empty.length === 1
              ? "Nobody was there"
              : empty.length === 2
                ? "Nobody was at either spot"
                : "Nobody was at any of those spots";
        return (
          <p key={p.cameras.join()} data-camera-pair={p.cameras.join("+")}>
            <strong>
              {names[p.cameras[0]]} and {names[p.cameras[1]]}:
            </strong>{" "}
            {count(p.separate.count, "match", "matches")}
            {p.cell ? ` on ${p.cell} m ground cells` : ""},{" "}
            {p.separate.residual ? `${span(p.separate.residual)} m apart on the ground` : "distance on the ground not stated"} and{" "}
            {!p.separate.lag
              ? "time apart not stated"
              : p.separate.lag[1] < 0.005
                ? "in the same frame"
                : `at most ${upTo(p.separate.lag[1])} s apart in time`}
            .{" "}
            {people.length > 0 &&
              `${people.length === p.separate.count ? (people.length === 1 ? "It is" : "Each is") : `${people.length} ${people.length === 1 ? "is" : "are"}`} on a staged person, never more than ${upTo(Math.max(...people.map((m) => m.near.distance)))} m from the scripted position in the sampled frames spanning the two observations (${people.map((m) => m.clock).join(", ")}). `}
            {empty.length > 0 &&
              `${nobody}. The nearest staged person was about ${Math.min(...far).toFixed(1)} m away.`}
            {unplaced > 0 && ` The scripted position was unavailable for ${count(unplaced, "match", "matches")}.`}
          </p>
        );
      })}
      <details className="measured__calls">
        <summary>Retained comparisons at the earlier camera frame</summary>
        <ul>
          {hits.flatMap((p) => p.separate.list.map((m) => (
            <li key={m.eventId} data-match-event={m.eventId}>
              {names[p.cameras[0]]} and {names[p.cameras[1]]}. <RetainedDistance match={m} />
            </li>
          )))}
        </ul>
      </details>
      {lit.length > 0 && (
        <p className="measured__flag">
          {count(lit.length, "match", "matches")} outside the staged positions {lit.length === 1 ? "has its" : "have their"} midpoint within
          1.5 s after the floodlights switched on at {native.lightsClock}. The timing is consistent with a shared
          lighting change. The matching report does not identify a cause.
        </p>
      )}
      {coarse.map((p) => {
        const on = p.coarser.list.filter((m) => m.onPerson).length;
        const lights = p.coarser.list.filter((m) => m.afterLights).length;
        const away = p.coarser.list.filter((m) => m.near && !m.onPerson && !m.afterLights).length;
        const unplaced = p.coarser.list.length - on - lights - away;
        const fine = p.separate.list.filter((m) => m.onPerson).length;
        return (
          <p key={p.cameras.join()} className="measured__flag">
            The grid matters. On {p.coarser.cell} m cells the {pairName(p)} films gave{" "}
            {count(p.coarser.count, "match", "matches")}: {on || "none"} on a staged person and {lights || "none"} away
            from the staged people shortly after the floodlights switched on
            {away > 0 && `, ${away} away from staged people at other times`}.
            {unplaced > 0 && ` The scripted position was unavailable for ${count(unplaced, "match", "matches")}.`}
            {on === 0 && fine > 0 && ` The ${fine === 1 ? "match" : "matches"} on a person above ${fine === 1 ? "appears" : "appear"} only on the ${p.cell} m grid.`}
          </p>
        );
      })}
      <p className="measured__aside">
        Whether a match is on a person is not something the tools know. This page works it out: it takes each matched
        point, finds how far the scripted person gets from it in the sampled frames spanning the two observations, and applies the tools'
        own {native.gate} m distance gate. Those distances are this page's arithmetic. They are not tool output.
      </p>
      {tried}
      <table className="measured__table">
        <thead>
          <tr>
            <th scope="col">Sources declared as</th>
            <th scope="col">Each match becomes</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Separate devices, as in the story</td>
            <td>
              <Kinds kinds={separate} />
            </td>
          </tr>
          {shared.length > 0 && (
            <tr>
              <td>Views from one renderer, which is what they are</td>
              <td>
                <Kinds kinds={shared} />
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <p className="measured__aside">
        Sources that share a cause cannot corroborate each other.
        {held && " Told the truth about these films, the software holds the alert."}
        {lit.length > 0 &&
          " A lighting change visible in two pictures is one possible shared cause."}
      </p>
    </Panel>
  );
}

/** How the detector did against the staged positions, per camera. */
export function Detector({ native, names }) {
  const extra = sum(native.cameras, (c) => c.extra);
  const stuck = native.cameras.filter((c) => c.fixed.length > 0);
  const stuckBoxes = sum(stuck, (c) => sum(c.fixed, (spot) => spot.boxes));
  return (
    <Panel title="Measured: the detector on these frames">
      <table className="measured__table">
        <thead>
          <tr>
            <th scope="col">Camera</th>
            <th scope="col">Frames run</th>
            <th scope="col">Staged person found</th>
            <th scope="col">Box overlap</th>
            <th scope="col">Extra boxes</th>
          </tr>
        </thead>
        <tbody>
          {native.cameras.map((c) => (
            <tr key={c.id}>
              <th scope="row">{names[c.id]}</th>
              <td className="num">{c.inferred ?? "not run"}</td>
              <td className="num">
                {c.compared == null
                  ? "n/a"
                  : c.compared
                    ? `${c.matched} of ${c.compared} (${pct(c.matched / c.compared)})`
                    : "none in view"}
              </td>
              <td className="num">{c.overlap != null && c.compared ? c.overlap.toFixed(2) : "n/a"}</td>
              <td className="num">{c.extra ?? "n/a"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="measured__aside">
        {native.rule ??
          "Found counts each staged person in each frame. A person is in view when at least a quarter of them is unobstructed and they stand at least 5% of the frame tall. A detector box finds them when the two boxes overlap by 0.3 or more, as intersection over union."}
      </p>
      {native.sizes.length > 0 && (
        <table className="measured__table">
          <thead>
            <tr>
              <th scope="col">Person's height in the frame</th>
              <th scope="col">Found</th>
            </tr>
          </thead>
          <tbody>
            {native.sizes.map((band) => (
              <tr key={band.key}>
                <td>{band.label}</td>
                <td className="num">
                  {band.matched} of {band.compared} ({pct(band.matched / band.compared)})
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {stuckBoxes > 0 && (
        <p className="measured__aside">
          {stuckBoxes} of the {extra} extra boxes are the detector calling something that does not move a person:{" "}
          {listed(
            stuck.map(
              (c) =>
                `${count(c.fixed.length, "spot")} on the ${names[c.id].toLowerCase()} camera (${listed(c.fixed.map((spot) => String(spot.boxes)))} boxes)`,
            ),
          )}
          . They are the solid boxes with nobody in them in the films above.
        </p>
      )}
      <p className="measured__aside">
        {native.model.name}, the one detector the project ships. Its scores are not calibrated, and rendered frames say
        nothing about its accuracy on real footage.
      </p>
    </Panel>
  );
}

/** Coverage witnesses the watch kept for each film, and whether absence is certified inside them. */
export function CoverageRuns({ native, names }) {
  const rows = native.cameras.filter((c) => c.coverage);
  if (!rows.length) return null;
  const certified = rows.some((c) => c.coverage.certified);
  const broken = rows.filter((c) => c.coverage.failed.length > 0);
  return (
    <Panel title="Measured: coverage witnesses for these films">
      <table className="measured__table">
        <thead>
          <tr>
            <th scope="col">Camera</th>
            <th scope="col">Witnesses kept</th>
            <th scope="col">Seconds covered</th>
            <th scope="col">No confirmed zone entry inside witnesses</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.id}>
              <th scope="row">{names[c.id]}</th>
              {c.coverage.refusal ? (
                <td colSpan={3}>
                  <span className="data">refused</span>
                  <small>{c.coverage.refusal}</small>
                </td>
              ) : (
                <>
                  <td className="num">{c.coverage.records ?? "n/a"}</td>
                  <td className="num">
                    {c.coverage.seconds != null ? c.coverage.seconds.toFixed(1) : "n/a"}
                    {c.coverage.seconds != null && c.seconds != null && ` of ${c.seconds.toFixed(0)}`}
                  </td>
                  <td>
                    {c.coverage.certified == null ? "not stated" : c.coverage.certified ? "yes" : "no"}
                    {c.coverage.report && <small><a href={c.coverage.report} aria-label={`First retained coverage report for ${names[c.id]}`}>First report</a></small>}
                  </td>
                </>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      {broken.map((c) => (
        <p key={c.id}>
          <strong>{names[c.id]}:</strong> the watch refused {c.coverage.failed.length} of its{" "}
          {count(c.coverage.windows ?? c.coverage.failed.length, "window")}, {sum(c.coverage.failed, (w) => w.frames)}{" "}
          frames in all, because {listed([...new Set(c.coverage.failed.map((w) => w.reason))])}. Those frames have no
          witness.
        </p>
      ))}
      <p className="measured__aside">
        A witness says one camera decoded its zone without a gap over one stretch of time.{" "}
        {certified
          ? "A “yes” means this watch recorded no confirmed foreground-track entry into that zone during the witnessed interval. Outside it, the watch makes no such claim."
          : "No report in this run certifies an interval free of confirmed foreground-track entries."}
      </p>
    </Panel>
  );
}

const VARIANT = {
  measured_scores_uncalibrated: "Scores declared uncalibrated, which they are",
  illustrative_separate_devices: "Assume each camera that saw a person is worth 600 to 800 mB. Separate devices",
  illustrative_shared_render: "Same assumption. One shared renderer",
};

/** What the fusion tool returned under each declaration. */
export function FusionRuns({ native, children }) {
  const fusion = native.fusion;
  if (!fusion.variants.length) {
    return (
      <Panel title="Fusion on these films">
        {children}
        <p>{fusion.outcome === "not_run" ? "Fusion did not run." : "No fusion result was recorded."}
          {fusion.reason && ` Reason: ${fusion.reason}.`}</p>
      </Panel>
    );
  }
  return (
    <Panel title="Measured: the fusion tool on these films">
      {children}
      <p>
        Hypothesis: <q>{fusion.hypothesis}</q>
      </p>
      <table className="measured__table">
        <thead>
          <tr>
            <th scope="col">Told that</th>
            <th scope="col">Probability</th>
            <th scope="col">Decision</th>
          </tr>
        </thead>
        <tbody>
          {fusion.variants.map((v) => (
            <tr key={v.id}>
              <td>{VARIANT[v.id] ?? v.id}</td>
              <td className="num">
                {v.outcome === "ok" && v.ppm
                  ? `${chance(v.ppm[0])} to ${chance(v.ppm[1])}%` : "Unavailable"}
              </td>
              <td>
                <Code>{v.outcome === "ok" ? v.decision : v.outcome}</Code>
                {v.reason && <small>{v.reason}</small>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="measured__aside">
        The measured scores have no calibration for this site. The illustrative runs assign each camera an assumed evidence weight.
      </p>
    </Panel>
  );
}

/** The situation the agent session actually received, in plain words. */
export function Briefing({ native }) {
  const b = native.briefing;
  if (!b) return null;
  const refusedPulse = native.calls.find((c) => c.view === "pulse" && c.outcome === "refused");
  // The driver asks for the briefing again once coverage witnesses are stored.
  const later = native.calls.filter((c) => /after coverage/.test(c.call));
  const laterFailed = later.filter((c) => c.outcome === "error");
  const saysNone = [...b.attention.map((a) => a.reason), ...b.notObservable, ...b.unknowns].some((line) =>
    /No CoverageWitness is retained/.test(line),
  );
  const lists = [
    ["Warnings", b.warnings],
    ["Stands out", b.salient.map((s) => s.summary)],
    ["Unknown", b.unknowns],
    ["Not observable", b.notObservable],
    ["Needs attention", b.attention.map((a) => a.reason)],
  ];
  const control = [
    ["Safe in every reading", b.control.robust],
    ["Allowed under conditions", b.control.conditional],
    ["Would find something out", b.control.information_gathering],
    ["Wait and watch", b.control.wait],
    ["Blocked", b.control.blocked],
  ].filter(([, list]) => list?.length);
  return (
    <Panel title="Measured: what the agent session was told" className="measured--briefing">
      <p>
        <strong>
          The {b.view} view, {b.tokens.toLocaleString("en")} of {b.target.toLocaleString("en")} tokens.
        </strong>{" "}
        {refusedPulse && `The smaller pulse view was refused: ${refusedPulse.reason ?? refusedPulse.error}.`}
      </p>
      {laterFailed.length > 0 && (
        <p className="measured__flag">
          This briefing was taken before the coverage witnesses were stored
          {saysNone && ", which is why it says none is retained"}. Asked again afterwards, {laterFailed.length === later.length ? (later.length === 1 ? "the call" : later.length === 2 ? "both briefing calls" : `all ${later.length} briefing calls`) : `${laterFailed.length} of ${later.length} briefing calls`}{" "}
          failed with a runtime error and gave no reason. {later.length === 1 ? "The same call" : "The same calls"} had
          succeeded before.
        </p>
      )}
      <dl className="measured__brief">
        {lists.map(
          ([label, rows]) =>
            rows.length > 0 && (
              <div key={label}>
                <dt>{label}</dt>
                <dd>
                  <ul>
                    {rows.map((row) => (
                      <li key={row}>{row}</li>
                    ))}
                  </ul>
                </dd>
              </div>
            ),
        )}
        <div>
          <dt>What it may do next</dt>
          <dd>
            <ul>
              {control.map(([label, list]) => (
                <li key={label}>
                  {label}: <span className="data">{list.map(short).join(", ")}</span>
                </li>
              ))}
            </ul>
          </dd>
        </div>
        {b.compression && (
          <div>
            <dt>Left out</dt>
            <dd>
              {b.compression.omitted_classes.map((c) => c.replaceAll("_", " ")).join(", ")}. Critical items omitted:{" "}
              {b.compression.critical.omittedCriticalItems} of {b.compression.critical.knownCriticalItems}.
            </dd>
          </div>
        )}
      </dl>
      <details className="measured__calls">
        <summary>
          All {native.calls.length} calls in the session: {tallyOf(native.calls)}
        </summary>
        <table className="measured__table">
          <thead className="visually-hidden">
            <tr>
              <th scope="col">Call</th>
              <th scope="col">Outcome</th>
              <th scope="col">Tokens returned</th>
            </tr>
          </thead>
          <tbody>
            {native.calls.map((c, i) => (
              <tr key={i}>
                <td>{callLabels[c.call] ?? c.call}</td>
                <td>
                  <span className="data">{c.outcome}</span>
                  {(c.reason ?? c.error) && <small>{c.reason ?? c.error}</small>}
                </td>
                <td className="num">{c.tokens ? c.tokens.toLocaleString("en") : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </Panel>
  );
}

// The historical call log used role names for approvals supplied by the evidence script.
const callLabels = {
  "plan alert (owner approves the plan)": "plan alert (script approves the plan)",
  "commit (owner approves dispatch)": "commit (script approves dispatch)",
  "commit reconcile (owner attests)": "commit reconcile (script attests to loopback receipt)",
  "commit again (must not resend)": "commit again",
};

const knownCount = (n) => Number.isSafeInteger(n) && n >= 0;
const outcomeText = (action, outcome, reason) => outcome
  ? `${action} returned ${outcome}${reason ? ` (${reason})` : ""}.`
  : `${action} has no recorded outcome.`;

function relayText(alert, retried) {
  const total = alert.requests_received;
  const first = alert.dispatch_requests_received;
  const retry = alert.retry_requests_received;
  const lines = [];
  if (knownCount(first)) lines.push(`On the first dispatch attempt the loopback relay received ${count(first, "request")}.`);
  else if (knownCount(total)) lines.push(`The loopback relay recorded ${count(total, "request")} in total.`);
  else lines.push("The relay request count is unknown.");
  // Older runs retained the total and a flag derived from total > 1. The flag cannot
  // distinguish two first-attempt requests from a first request that arrived on retry.
  if (knownCount(retry)) lines.push(`During the retry the relay received ${count(retry, "request")}.`);
  else if (retried || typeof alert.resend_on_retry === "boolean")
    lines.push("The recording has no separate request count for the retry.");
  return lines.join(" ");
}

function alertDetails(native) {
  const a = native.alert;
  const call = (prefix) => native.calls?.find((c) => c.call.startsWith(prefix));
  const preview = call("plan alert (preview)");
  const prepare = call("plan alert (owner") ?? call("plan alert (script");
  const dispatch = call("commit (");
  const retry = call("commit again");
  const stageCall = dispatch ?? prepare ?? preview;
  const stage = dispatch ? "dispatch" : prepare ? "preparation" : "preview";
  const status = stageCall ? outcomeText(`Agent alert ${stage}`, stageCall.outcome, stageCall.error)
    : a.stage === "proposed" ? outcomeText("Agent alert preview", a.outcome, a.error)
    : a.stage ? `The recorded agent alert stage was ${a.stage.replaceAll("_", " ")}.`
    : outcomeText("The agent alert", a.outcome, a.error);
  const operator = a.operator_fallback;
  const receipt = relayText(a, retry);
  const effect = a.effect_state && `The native effect state was ${a.effect_state.replaceAll("_", " ")}.`;
  const reconciliation = call("commit reconcile (script") ?? call("commit reconcile (owner");
  let reconciled;
  if (a.reconciled_state && (!reconciliation || reconciliation.outcome === "ok")) {
    const scripted = a.attestation_source === "evidence_script_loopback_receipt" ||
      (a.relay === "loopback, owned by this script" && reconciliation?.outcome === "ok");
    reconciled = scripted ? `The script attested to its own relay receipt. Reconciliation recorded ${a.reconciled_state}.`
                          : `The recorded reconciliation state was ${a.reconciled_state}.`;
  } else if (reconciliation) {
    reconciled = outcomeText("Reconciliation", reconciliation.outcome, reconciliation.error);
  }
  const operatorLines = [];
  if (operator) {
    const phase = ["dispatch", "prepare", "preview"].find((p) => operator[p + "_outcome"]);
    operatorLines.push(phase
      ? outcomeText(`Operator alert ${phase}`, operator[phase + "_outcome"], operator[phase + "_reason"])
      : operator.stage ? `The operator command reported the stage ${operator.stage}.`
                       : outcomeText("The operator command", operator.outcome, operator.reason));
    operatorLines.push(relayText(operator, operator.retry_stage || operator.retry_outcome));
    if (operator.delivery_claim) operatorLines.push(`The operator command recorded ${operator.delivery_claim.replaceAll("_", " ")}.`);
    if (operator.retry_outcome) operatorLines.push(outcomeText("The operator retry", operator.retry_outcome));
  }
  const lines = [status, receipt, effect, reconciled, ...operatorLines].filter(Boolean);
  const waited = call("wait");
  const closedEarly = call("plan close (before");
  const bodyBytes = a.request_headers?.["Content-Length"];
  const retainedBody = a.request && /^\d+$/.test(bodyBytes) &&
    `The retained request had a ${bodyBytes}-byte body${a.request_headers["Idempotency-Key"] ? " and an idempotency key" : ""}.`;
  const steps = [
    preview && prepare && outcomeText("The two-camera alert preview", preview.outcome),
    prepare && dispatch && outcomeText("The script’s plan approval", prepare.outcome),
    status, effect,
    retry && outcomeText("The agent retry", retry.outcome, retry.error),
    receipt, retainedBody,
    waited && outcomeText("Waiting for the operation", waited.outcome, waited.reason ?? waited.error),
    closedEarly && outcomeText("Closing the plan before reconciliation", closedEarly.outcome, closedEarly.reason ?? closedEarly.error),
    reconciled,
    a.episode_recorded === true && "The session recorded an execution episode.",
    ...operatorLines,
  ].filter(Boolean);
  return { lines, steps };
}

/** The native results and the evidence script's local relay observations. */
function RelayComparison({ replay }) {
  if (!replay) return <p className="measured__aside">No separate retry and acknowledgement comparison was published for this take.</p>;
  const step = (branch, phase) => branch?.steps?.find((entry) => entry.phase === phase);
  const branch = (id) => replay.branches.find((entry) => entry.id === id);
  const accepted = branch("accepted");
  const lost = branch("lost-ack");
  const held = branch("held");
  const frames = [...new Set(replay.source.cameras.map((camera) => camera.source_frame))];
  const attempts = [
    { key: "accepted", label: "Approved dispatch", branch: accepted, call: step(accepted, "dispatch") },
    { key: "repeat", label: "Same approval again", branch: accepted, call: step(accepted, "repeat") },
    { key: "lost-ack", label: "Acknowledgement lost", branch: lost, call: step(lost, "dispatch") },
    { key: "held", label: "Shared camera source", branch: held, call: step(held, "plan") },
  ];
  return (
    <section className="measured__excerpt" aria-labelledby="relay-receipts">
      <h4 id="relay-receipts">Follow a notification to its receiver</h4>
      <p>The camera views{frames.length === 1 && ` at frame ${frames[0]}`} share one renderer. To exercise
        dispatch, the lab declared them independent and ran two separate copies of the eligible event against an approved local HTTP receiver.{" "}
        {knownCount(accepted?.receivedBytes) && accepted.receivedBody?.sha256 === lost?.receivedBody?.sha256 &&
          `Both send tests used the same ${accepted.receivedBytes}-byte POST. `}
        No person was notified.{" "}
        <a href="/watch/intrusion/relay-replay.json">Replay inputs and results</a>.</p>
      <dl className="relay-outcomes">
        {attempts.map(({ key, label, branch, call }) => (
          <div key={key} data-relay-case={key}>
            <dt>{label}</dt>
            <dd>
              {knownCount(call?.requests_received)
                ? <><strong>{count(call.requests_received, "POST")}</strong> received during this call.</>
                : "The request count is unavailable."}{" "}
              {key === "accepted" && (Number.isInteger(branch?.relay?.response_status)
                ? `The receiver replied HTTP ${branch.relay.response_status}. ` : "The receiver’s HTTP status is unavailable. ")}
              {key === "lost-ack" && (branch?.relay?.response_disposition === "connection_closed_without_response"
                ? "The receiver closed the connection without replying. " : "The receiver’s response is unrecorded. ")}
              {key === "held" && branch?.event?.policy_action === "hold" && "The event policy held the alert. "}
              {call?.effect_state
                ? <>FSS recorded <Code>{call.effect_state}</Code>. </>
                : call?.outcome ? <>FSS returned <Code>{call.outcome}</Code>. </> : "The native outcome is unavailable. "}
              {key === "lost-ack" && knownCount(step(branch, "repeat")?.requests_received) &&
                `The repeat produced ${count(step(branch, "repeat").requests_received, "additional POST")}. `}
              {key === "lost-ack" && step(branch, "inspect")?.effect_state && <>A{" "}
                <a href={`/watch/intrusion/${step(branch, "inspect").native.path}`}>fresh process</a> read back{" "}
                <Code>{step(branch, "inspect").effect_state}</Code>. </>}
              <span className="relay-outcomes__links">
                {call?.native && <a aria-label={`${label} native result`} href={`/watch/intrusion/${call.native.path}`}>Native result</a>}
                {branch?.listener && <a aria-label={`${label} receiver log`} href={`/watch/intrusion/${branch.listener.path}`}>Receiver log</a>}
                {call?.phase === "dispatch" && branch?.receivedBody &&
                  <a aria-label={`${label} POST body`} href={`/watch/intrusion/${branch.receivedBody.path}`}>POST body</a>}
              </span>
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

export function AlertRun({ native }) {
  const a = native.alert;
  if (!a && !native.single && !native.relayReplay) return null;
  const cause = a?.event_id && native.events.find((e) => e.id === a.event_id);
  const steps = [
    native.single && outcomeText("The single-camera alert preview", native.single.outcome, native.single.error),
    ...(a ? alertDetails(native).steps : []),
  ].filter(Boolean);
  return (
    <Panel title="Measured alert delivery">
      <RelayComparison replay={native.relayReplay} />
      {steps.length > 0 && (
        <details className="measured__calls">
          <summary>Alert calls in the original five-camera run</summary>
          <ol className="measured__steps">
            {steps.map((step, index) => (
              <li key={index}>{step}</li>
            ))}
          </ol>
        </details>
      )}
      {cause && cause.onPerson && (
        <p className="measured__aside">
          The alert plan concerned the two-camera match at {cause.clock}. By this page's arithmetic it is never
          more than {upTo(cause.near.distance)} m from the scripted position of {cause.near.track} in the sampled
          frames spanning the two observations.
        </p>
      )}
      {cause && cause.near && !cause.onPerson && (
        <p className="measured__flag">
          The alert plan concerned {cause.afterLights ? "a match shortly after the floodlights switched on" : "a match with nobody at that spot"}, about {cause.near.distance.toFixed(1)} m from the nearest staged person.
        </p>
      )}
      {cause?.ground && (
        <p className="measured__aside" data-alert-event={cause.id}>
          The retained comparison uses the earlier camera frame. <RetainedDistance match={cause} />
        </p>
      )}
      <p className="measured__aside">
        The evidence script targeted a relay on the same machine. No person was notified.
      </p>
    </Panel>
  );
}

/** Source custody and the ledger after the run. */
export function Custody({ native, names }) {
  const published = (native.ledger.entries ?? []).map((entry) => entry.seq).filter((seq) => seq != null);
  const final = native.ledger.final;
  return (
    <Panel title="Measured: custody and ledger for these films">
      <table className="measured__table">
        <thead>
          <tr>
            <th scope="col">Film</th>
            <th scope="col">Frames</th>
            <th scope="col">SHA-256 of the file</th>
          </tr>
        </thead>
        <tbody>
          {native.cameras.map((c) => (
            <tr key={c.id}>
              <th scope="row">{names[c.id]}</th>
              <td className="num">{c.frames ?? "—"}</td>
              <td>{c.custody === "ok" ? <span className="data" title={c.sha256}>{c.sha256.slice(0, 24)}</span>
                : <>Import {c.custody}{c.custodyReason && <small>{c.custodyReason}</small>}</>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>
        {count(native.events.length, "event")} published
        {published.length > 0 && `, at ledger ${published.length === 1 ? "sequence" : "sequences"} ${listed(published)}`}
        {native.events.length > 0 && native.events.every((e) => e.verified)
          ? ", every object behind them verified against its digest."
          : "."}{" "}
        {final ? (
          <>
            The run ended with the ledger at sequence {final.sequence}
            {final.root && (
              <>
                , root <span className="data">{final.root.replace("sha256:", "").slice(0, 24)}</span>
              </>
            )}
            .
          </>
        ) : (
          native.ledger.root && (
            <>
              At the last custody audit the ledger root was{" "}
              <span className="data">{native.ledger.root.replace("sha256:", "").slice(0, 24)}</span>, sequence{" "}
              {native.ledger.sequence}.
            </>
          )
        )}
      </p>
    </Panel>
  );
}

/** One list of everything measured, for the status section. */
export function MeasuredSummary({ native, names }) {
  const imported = native.cameras.filter((c) => c.custody === "ok");
  const frames = sum(imported, (c) => c.frames);
  const inferred = sum(native.cameras, (c) => c.inferred);
  const compared = sum(native.cameras, (c) => c.compared);
  const matched = sum(native.cameras, (c) => c.matched);
  const hits = native.pairs.filter((p) => p.separate.count > 0);
  const matches = hits.flatMap((p) => p.separate.list);
  const stray = matches.filter((m) => m.near && !m.onPerson && !m.afterLights).length;
  const unplaced = matches.filter((m) => !m.near).length;
  // Seconds inside coverage witnesses, for each film that has any.
  const covered = native.cameras.filter((c) => c.coverage?.records && c.coverage.seconds != null).map((c) => c.coverage.seconds);
  const certified = native.cameras.some((c) => c.coverage?.certified);
  return (
    <ul>
      <li>
        {imported.length
          ? `${count(imported.length, "film")}, ${frames.toLocaleString("en")} frames, imported under SHA-256 custody.`
          : "No film entered SHA-256 custody."}
        {imported.length < native.cameras.length && ` See the custody table for ${count(native.cameras.length - imported.length, "unsuccessful import")}.`}
      </li>
      <li>
        {native.cameras.some((c) => c.inferred != null)
          ? `Person detector run on ${inferred.toLocaleString("en")} frames.` : "No detector run was recorded."}
        {native.cameras.some((c) => c.compared != null) &&
          ` Counting each person in each compared frame, a staged person was in view ${compared.toLocaleString("en")} times and the detector found them ${matched.toLocaleString("en")} times${compared ? ` (${pct(matched / compared)})` : ""}.`}
      </li>
      <li>
        {matches.length
          ? `${count(matches.length, "cross-camera match", "cross-camera matches")} from ${count(hits.length, "pair")} of cameras. ${matches.filter((m) => m.onPerson).length} on a staged person, ${matches.filter((m) => m.afterLights).length} away from the staged people shortly after the floodlights switched on${stray ? `, ${stray} on nothing the script put there` : ""}.`
          : native.pairs.some((p) => p.ran) ? "No cross-camera match in the pairs tested." : "No pair was tested."}
        {unplaced > 0 && ` The scripted position was unavailable for ${count(unplaced, "match", "matches")}.`}
      </li>
      <li>
        {count(native.events.length, "event")} published to the ledger
        {native.ledger.final ? `, which ended the run at sequence ${native.ledger.final.sequence}` : ""}.
      </li>
      {(native.alert || native.single) && (
        <li>
          {native.alert ? alertDetails(native).lines.join(" ") : outcomeText("The single-camera alert preview", native.single.outcome, native.single.error)} No person was notified.
        </li>
      )}
      <li>
        Agent session of {native.calls.length} calls: {tallyOf(native.calls)}.
      </li>
      <li>
        Not established: detector scores are uncalibrated;{" "}
        {covered.length
          ? `${certified ? "the watch certifies intervals without a confirmed zone entry only within its witnesses, which hold" : "no interval is certified free of confirmed zone entries, and the witnesses hold"} ${span([Math.min(...covered), Math.max(...covered)], 0)} s per covered film;`
          : "no coverage witness was kept, so absence is never certified;"}{" "}
        tracks are not joined across cameras.
      </li>
      <li>
        {native.commands} commands, {Math.round(native.seconds / 60) || 1} min, run with the repository at commit{" "}
        <span className="data">{native.commit.slice(0, 10)}</span> by{" "}
        <span className="data">website/scripts/watch-evidence.py</span>.
      </li>
    </ul>
  );
}
