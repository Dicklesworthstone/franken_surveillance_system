"use client";
import { useEffect, useState } from "react";
import { ArrowUpRight, Check, Fingerprint, FileJson } from "lucide-react";
import { displayCamera } from "../../lib/night/catalog";

function ProofLinks({ items }) {
  return (
    <ul className="proof-links">
      {items
        .filter(([, url]) => url)
        .map(([label, url]) => (
          <li key={label}>
            <a href={url}>
              <FileJson size={15} />
              {label}
              <ArrowUpRight size={14} />
            </a>
          </li>
        ))}
    </ul>
  );
}

function VerifyBytes({ url, digest, label, source }) {
  const [attempt, setAttempt] = useState(0),
    [state, setState] = useState("idle");
  useEffect(() => {
    if (!attempt) return;
    const abort = new AbortController();
    async function verify() {
      try {
        const response = await fetch(url, { signal: abort.signal });
        if (!response.ok) throw Error();
        const hash = await crypto.subtle.digest(
          "SHA-256",
          await response.arrayBuffer(),
        );
        const actual = Array.from(new Uint8Array(hash), (n) =>
          n.toString(16).padStart(2, "0"),
        ).join("");
        if (!abort.signal.aborted)
          setState("sha256:" + actual === digest ? "verified" : "mismatch");
      } catch {
        if (!abort.signal.aborted) setState("unavailable");
      }
    }
    verify();
    return () => abort.abort();
  }, [attempt, url, digest]);
  const messages = {
    idle: "Recompute the SHA-256 digest in this browser.",
    reading: "Reading the source bytes…",
    verified: "The downloaded bytes match the retained digest.",
    mismatch: "The downloaded bytes differ from the retained digest.",
    unavailable: "These bytes could not be verified.",
  };
  return (
    <div className="film-proof">
      <div>
        <Fingerprint size={22} />
        <span className="ticker">{source}</span>
      </div>
      <code>{digest}</code>
      <button
        onClick={() => {
          setState("reading");
          setAttempt(attempt + 1);
        }}
        disabled={state === "reading"}
      >
        {state === "verified" ? <Check size={15} /> : <Fingerprint size={15} />}{" "}
        {state === "verified" ? "Verify again" : label}
      </button>
      <p role="status">{messages[state]}</p>
    </div>
  );
}

function Ledger({ ledger }) {
  const [object, select] = useState(0);
  if (ledger.status !== "verified")
    return (
      <div className="reading">
        <h3>No event published</h3>
        <p>
          The native run produced no eligible event candidate for this case. Its
          source films and camera reports are available below.
        </p>
      </div>
    );
  const item = ledger.objects[object];
  return (
    <div className="reading">
      <span className="ticker">Published event</span>
      <h3>Publication and custody</h3>
      <p>
        This case has its own ledger. Its cameras share one sequence. The first
        approval published the event, and a repeat returned the same sequence
        number. The custody audit checked the referenced objects.
      </p>
      <dl className="case-facts">
        <div>
          <dt>Sequence</dt>
          <dd>{ledger.sequence}</dd>
        </div>
        <div>
          <dt>Event identity</dt>
          <dd>
            <code>{ledger.eventId}</code>
          </dd>
        </div>
        <div>
          <dt>Ledger root</dt>
          <dd>
            <code>{ledger.root}</code>
          </dd>
        </div>
      </dl>
      <ProofLinks
        items={[
          ["Publication receipt", ledger.publication],
          ["Idempotent retry", ledger.repeat],
          ["Custody audit", ledger.custody],
          ["Forensic explanation", ledger.explain],
        ]}
      />
      {item && (
        <>
          <label className="object-choice">
            Retained object{" "}
            <select
              value={object}
              onChange={(e) => select(Number(e.target.value))}
            >
              {ledger.objects.map((o, i) => (
                <option key={o.digest} value={i}>
                  {i + 1} · {o.digest.slice(7, 19)}
                </option>
              ))}
            </select>
          </label>
          <VerifyBytes
            key={item.digest}
            url={item.file}
            digest={item.digest}
            source="Immutable payload"
            label="Verify object"
          />
        </>
      )}
    </div>
  );
}
function AgentReadout({ agent, mode }) {
  const links =
    mode === "response"
      ? [
          ["Notification plan", agent.notification],
          ["Event orientation", agent.orient],
        ]
      : [
          ["Orientation", agent.orient],
          ["Workspace handoff", agent.handoff],
          ["Resumed session", agent.resume],
          ["Session opening", agent.open],
        ];
  const options = links.filter(([, url]) => url);
  const [active, choose] = useState(0),
    [result, load] = useState(null);
  const url = options[active][1];
  useEffect(() => {
    const ctrl = new AbortController();
    load(null);
    async function open() {
      try {
        const response = await fetch(url, { signal: ctrl.signal });
        if (!response.ok) throw Error();
        const record = await response.json();
        if (!ctrl.signal.aborted) load({ record });
      } catch {
        if (!ctrl.signal.aborted) load({ error: true });
      }
    }
    open();
    return () => ctrl.abort();
  }, [url]);
  return (
    <div className="reading">
      <span className="ticker">Native agent record</span>
      <h3>
        {mode === "response"
          ? agent.notification
            ? "Owner notification held"
            : "Notification disposition"
          : "Follow the workspace"}
      </h3>
      {mode === "response" && (
        <p>
          {agent.notification
            ? "FSS declined the alert plan for this offline event. Open the native response to inspect its error identity."
            : "This case has no published event eligible for a notification plan."}
        </p>
      )}
      <div className="record-choices">
        {options.map(([name, link], i) => (
          <button
            key={link}
            aria-pressed={i === active}
            onClick={() => choose(i)}
          >
            {name}
          </button>
        ))}
      </div>
      {result?.record ? (
        <>
          <div className="native-fields">
            {Object.entries(result.record)
              .filter(
                ([k, v]) =>
                  [
                    "outcome",
                    "errorId",
                    "error_id",
                    "code",
                    "sessionId",
                    "workspaceId",
                    "operation",
                    "operationId",
                  ].includes(k) && typeof v === "string",
              )
              .map(([k, v]) => (
                <div key={k}>
                  <small>{k}</small>
                  <code>{v}</code>
                </div>
              ))}
          </div>
          <details className="envelope">
            <summary>Inspect complete JSON</summary>
            <pre>{JSON.stringify(result.record, null, 2)}</pre>
          </details>
        </>
      ) : (
        <p role="status">
          {result?.error
            ? "Could not open the agent record."
            : "Opening the agent record…"}
        </p>
      )}
      <ProofLinks items={[["Download native record", url]]} />
    </div>
  );
}
function Association({ association }) {
  return (
    <div className="reading">
      <span className="ticker">Native cross-camera comparison</span>
      <h3>Which observations align?</h3>
      <p>
        FSS projects the observations onto the ground and tests their position
        and timing. These cameras share a synthetic scene and clock.
      </p>
      <ul className="proof-links">
        {Object.values(association.pairs).map((pair) => (
          <li key={pair.report}>
            <a href={pair.report}>
              <span>{pair.cameras.map(displayCamera).join(" + ")}</span>
              <strong>
                {pair.count} {pair.count === 1 ? "candidate" : "candidates"}
              </strong>
              <ArrowUpRight size={14} />
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}
function BeliefReview({ belief }) {
  const [active, choose] = useState(0);
  if (!belief || belief.status === "no_person_label")
    return (
      <div className="reading">
        <h3>Evidence for a person</h3>
        <p>
          The inspected camera frames returned no person label. The
          person-visibility experiment requires a measured observation.
        </p>
      </div>
    );
  const v = belief.variants[active];
  const [low, high] = v.probabilityPpm.map((n) => n / 10000);
  return (
    <div className="reading">
      <span className="ticker">Source dependence experiment</span>
      <h3>{belief.hypothesis}</h3>
      <p>
        The experiment uses real camera observations with an illustrative prior
        and likelihood bounds. The interval describes the visibility hypothesis
        under those assumptions.
      </p>
      <div className="record-choices">
        {belief.variants.map((v, i) => (
          <button
            key={v.id}
            aria-pressed={active === i}
            onClick={() => choose(i)}
          >
            {v.label}
          </button>
        ))}
      </div>
      <strong className="probability-readout">
        {low.toFixed(1)}–{high.toFixed(1)}%
      </strong>
      <div className="probability-track" aria-hidden="true">
        <i style={{ left: low + "%", width: high - low + "%" }} />
      </div>
      <p>
        {v.supportingClusters} supporting{" "}
        {v.supportingClusters === 1 ? "cluster" : "clusters"} ·{" "}
        {String(v.decision?.kind ?? v.decision).replaceAll("_", " ")}
      </p>
      {v.id === "independent" && (
        <p>
          Independence is hypothetical. All recordings in this case share a
          scene and clock.
        </p>
      )}
      <ProofLinks
        items={[
          ["Fusion inputs and assumptions", v.input],
          ["Native fusion result", v.report],
          ...belief.observations.map((o) => [
            displayCamera(o.camera) + " person observation",
            o.report,
          ]),
        ]}
      />
    </div>
  );
}
export default function CaseDesk({ incident, mode = "evidence", modelDigest }) {
  const ids = Object.keys(incident.views),
    [camera, select] = useState(incident.primary),
    view = incident.views[camera];
  const agentMode = ["agent", "response", "hypotheses"].includes(mode),
    ledger = incident.ledger;
  const links = [
    ["Original camera film", view.film],
    ["Imported camera bytes", view.input],
    ["Native import receipt", view.importReceipt],
    ["Native watch report", view.watch],
    ["Case evidence index", "/night-evidence/index.json"],
  ];
  return (
    <section className="case-desk" id="evidence">
      <div className="section-head">
        <div>
          <span className="ticker">
            {agentMode ? "Agent and operator review" : "Evidence desk"}
          </span>
          <h2>
            {agentMode ? (
              <>
                What can an agent <em>conclude?</em>
              </>
            ) : (
              <>
                Open the <em>evidence.</em>
              </>
            )}
          </h2>
        </div>
        <p>
          {agentMode
            ? "Inspect the report, the camera observations and the recorded decision as separate sources."
            : "Follow the film into its native import, inspect the watch result and verify the source bytes."}
        </p>
      </div>
      <div className="desk-grid">
        <div className="desk-paper">
          <span className="ticker">Case file / {incident.label}</span>
          <h3>{incident.title}</h3>
          <dl className="case-facts">
            <div>
              <dt>Scenario report</dt>
              <dd>{incident.report}</dd>
            </div>
            <div>
              <dt>Camera observations</dt>
              <dd>
                {ids.map((c) => (
                  <span className="camera-stat" key={c}>
                    {displayCamera(c)} <b>{incident.views[c].candidateCount}</b>{" "}
                    event candidates
                  </span>
                ))}
              </dd>
            </div>
            <div>
              <dt>Native disposition</dt>
              <dd>{incident.decision.summary}</dd>
            </div>
            <div>
              <dt>Authority</dt>
              <dd>{incident.decision.authority}</dd>
            </div>
          </dl>
          {mode === "compare" && (
            <Association association={incident.associations} />
          )}
          {mode === "inputs" && (
            <div className="reading">
              <h3>Bring your own cameras</h3>
              <p>
                A doorbell and a driveway camera can come from different
                manufacturers. FSS gives each stream an identity and can plan a
                capture from an authorized RTSP endpoint, an ONVIF profile or a
                bound UniFi Protect camera. This exhibit uses rendered inputs so
                you can inspect every source frame.
              </p>
              <a href="https://github.com/Dicklesworthstone/franken_surveillance_system/blob/main/docs/SITE_PLANNING.md">
                Read the site and camera setup guide ↗
              </a>
            </div>
          )}
          {["agent", "response"].includes(mode) && (
            <AgentReadout agent={incident.agent} mode={mode} />
          )}
          {["ledger", "incident"].includes(mode) && <Ledger ledger={ledger} />}
          {mode === "hypotheses" && <BeliefReview belief={incident.belief} />}
          {mode === "hypotheses" && (
            <div className="reading">
              <h3>Limits of the observations</h3>
              <p>
                The camera frames can support a visible class or movement. The
                recorded views share one source. Independent confirmation and
                certified absence are both unresolved.
              </p>
              <ProofLinks
                items={ids.map((c) => [
                  displayCamera(c) + " frame inspection",
                  incident.views[c].samples[0]?.report,
                ])}
              />
            </div>
          )}
        </div>
        <div className="desk-source">
          <div className="source-title">
            <h3>Source record</h3>
            <label>
              <span className="sr-only">Source camera</span>
              <select value={camera} onChange={(e) => select(e.target.value)}>
                {ids.map((c) => (
                  <option key={c} value={c}>
                    {displayCamera(c)}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <VerifyBytes
            key={view.film}
            url={view.film}
            digest={view.filmDigest}
            source={displayCamera(camera) + " / source custody"}
            label="Verify recording"
          />
          <ProofLinks items={links} />
          <details className="identity-details">
            <summary>Import and model identities</summary>
            <b>Native import</b>
            <code>{view.importId}</code>
            <b>Model package</b>
            <code>{modelDigest}</code>
          </details>
        </div>
      </div>
    </section>
  );
}
