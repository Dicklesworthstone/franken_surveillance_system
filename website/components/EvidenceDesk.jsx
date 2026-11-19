"use client";
import SectionLink from "./SectionLink";
import { exhibitPath } from "../lib/exhibits";

import { useState } from "react";
import {
  ArrowUpRight,
  Binary,
  Fingerprint,
  GitMerge,
  Layers3,
  Play,
  X,
  Check,
  ShieldCheck,
} from "lucide-react";
import { recording, stamp } from "../lib/scenarios";

const tabRoutes = {
  association: "camera-fusion",
  belief: "belief-lab",
  ledger: "event-ledger",
};

function Receipt({ name, children = "Native report" }) {
  return (
    <a className="receipt" href={name}>
      {children} <ArrowUpRight size={14} />
    </a>
  );
}

function Association({ data, onSurvey }) {
  const [gate, setGate] = useState(1),
    [film, setFilm] = useState(false);
  const matched = gate === 1;
  return (
    <div className="case-panel">
      <div className="case-copy">
        <span className="section-kicker">CROSS-CAMERA ASSOCIATION</span>
        <h3>Is it the same entry?</h3>
        <p>
          The porch and driveway each measured a track entering the porch zone.
          FSS projects the foot of each track into metres on the property. The
          two observations land{" "}
          <b>{(data.distance * 100).toFixed(0)} cm apart.</b>
        </p>
        <label className="control-label">Compare recorded time windows</label>
        <div className="segmented">
          {data.gates.map((g, i) => (
            <button
              key={g}
              aria-pressed={i === gate}
              onClick={() => setGate(i)}
            >
              {g} ms
            </button>
          ))}
        </div>
        <p className="finding" aria-live="polite">
          <b>{matched ? "One witnessed entry." : "No qualifying pair."}</b>{" "}
          {matched
            ? "The 500 ms window admits both entries. Their shared replay and clock leave the alert on hold."
            : "Including clock uncertainty, the entries can be 252 ms apart. That exceeds the 250 ms window."}
        </p>
        <Receipt
          name={
            matched
              ? "/field/association.json"
              : "/evidence/delivery-drive-porch.json"
          }
        />
      </div>
      <div className="fusion-visual">
        <div className="visual-title">
          <span>JUNIPER HOUSE / PORCH ZONE</span>
          <GitMerge size={16} />
        </div>
        {film ? (
          <div className="feature-film">
            <video
              controls
              autoPlay
              muted
              playsInline
              aria-label="Synchronized doorstep film"
              src="/field/doorstep-review.mp4"
            />
            <button onClick={() => setFilm(false)}>
              <X size={14} /> Back to frames
            </button>
          </div>
        ) : (
          <div className="matches">
            {data.marks
              .toSorted((a, b) => a.segment - b.segment)
              .map((m) => {
                const [x, y, w, h] = m.box;
                return (
                  <figure key={m.camera} className={m.camera}>
                    <div className="match-frame">
                      <img
                        loading="lazy"
                        src={"/field/" + m.camera + ".jpg"}
                        alt={
                          m.camera +
                          " recording at " +
                          stamp(m.segment / recording.nativeFps, true)
                        }
                      />
                      <i
                        aria-hidden="true"
                        style={{
                          left:
                            ((x - w / 2) / recording.nativeWidth) * 100 + "%",
                          top:
                            ((y - h / 2) / recording.nativeHeight) * 100 + "%",
                          width: (w / recording.nativeWidth) * 100 + "%",
                          height: (h / recording.nativeHeight) * 100 + "%",
                        }}
                      />
                    </div>
                    <figcaption>
                      <strong>
                        <i />
                        {m.camera === "drive" ? "Driveway" : "Porch"}
                      </strong>
                      <time>
                        {stamp(m.segment / recording.nativeFps, true)}
                      </time>
                    </figcaption>
                  </figure>
                );
              })}
          </div>
        )}
        <dl className="triplet">
          <div>
            <dt>Ground separation</dt>
            <dd>
              {data.distance.toFixed(2)} <small>m</small>
            </dd>
          </div>
          <div>
            <dt>Time bound</dt>
            <dd>
              {data.delta} <small>ms</small>
            </dd>
          </div>
          <div>
            <dt>Support domains</dt>
            <dd>{data.shared}</dd>
          </div>
        </dl>
        <div className="visual-actions">
          <button onClick={onSurvey}>
            <Layers3 size={15} /> Locate on twin
          </button>
          {!film && (
            <button onClick={() => setFilm(true)}>
              <Play size={15} /> Play both feeds
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function Belief({ data }) {
  const [mode, setMode] = useState("shared"),
    r = data[mode];
  const [lo, hi] = r.interval.map((v) => v / 10000);
  const modes = [
    ["single", "One camera"],
    ["shared", "Shared source"],
    ["independent", "Independent sources"],
  ];
  return (
    <div className="case-panel">
      <div className="case-copy">
        <span className="section-kicker">PROBABILISTIC FUSION</span>
        <h3>How much does a second view add?</h3>
        <p>
          Give the native fusion engine the same illustrative evidence strength
          twice. Change whether the cameras share a failure cause and watch the
          range for an unknown presence change.
        </p>
        <div className="segmented">
          {modes.map(([id, label]) => (
            <button
              key={id}
              aria-pressed={mode === id}
              onClick={() => setMode(id)}
            >
              {label}
            </button>
          ))}
        </div>
        <p className="finding">
          This exercise assumes a roughly 20% prior and example likelihoods. The
          doorstep recordings have no field-calibrated threat probability.
        </p>
        <div className="visual-actions">
          <Receipt name={"/field/input-" + mode + ".json"}>Assumptions</Receipt>
          <Receipt name={"/field/belief-" + mode + ".json"} />
        </div>
      </div>
      <div className="belief-visual">
        <div className="visual-title">
          <span>HYPOTHETICAL PRESENCE / NATIVE FUSION</span>
          <Binary size={16} />
        </div>
        <div className="prob-result" aria-live="polite">
          <span>Posterior probability interval</span>
          <strong>
            {lo.toFixed(1)}–{hi.toFixed(1)}
            <small>%</small>
          </strong>
        </div>
        <div className="range-plot" aria-hidden="true">
          <i style={{ left: lo + "%", width: hi - lo + "%" }} />
        </div>
        <div className="axis">
          <span>0%</span>
          <span>50%</span>
          <span>100%</span>
        </div>
        <dl className="result-facts">
          <div>
            <dt>Independent support groups</dt>
            <dd>{r.clusters}</dd>
          </div>
          <div>
            <dt>Native decision</dt>
            <dd>{r.decision.replaceAll("_", " ")}</dd>
          </div>
        </dl>
      </div>
    </div>
  );
}

function Ledger({ data }) {
  const [variant, setVariant] = useState("original"),
    [state, setState] = useState("idle");
  async function verify() {
    setState("checking");
    try {
      const results = await Promise.all(
        data.objects.map(async (obj) => {
          const response = await fetch(
            "/field/" + obj.digest.slice(7) + ".bin",
          );
          if (!response.ok) throw Error("Object unavailable");
          const bytes = new Uint8Array(await response.arrayBuffer());
          if (variant === "changed" && !obj.manifest) bytes[0] ^= 1;
          const hash = await crypto.subtle.digest("SHA-256", bytes);
          return (
            "sha256:" +
              Array.from(new Uint8Array(hash), (b) =>
                b.toString(16).padStart(2, "0"),
              ).join("") ===
            obj.digest
          );
        }),
      );
      setState(results.every(Boolean) ? "verified" : "mismatch");
    } catch {
      setState("unavailable");
    }
  }
  const messages = {
    idle: "Ready to verify the published manifest and its witness.",
    checking: "Reading and hashing both objects…",
    verified: "Verified. Both objects match the custody report.",
    mismatch:
      "Mismatch. The changed witness no longer matches its recorded digest.",
    unavailable:
      "Verification unavailable. The objects and their expected digests are in the custody report.",
  };
  return (
    <div className="case-panel">
      <div className="case-copy">
        <span className="section-kicker">IMMUTABLE EVENT HISTORY</span>
        <h3>Can you verify the record?</h3>
        <p>
          The native publisher recorded the witnessed entry at commit{" "}
          {data.after}. Replaying the same approval left the ledger at commit{" "}
          {data.repeat}. The audit retained the event manifest and its witness
          by content hash.
        </p>
        <div className="segmented">
          {[
            ["original", "Original bytes"],
            ["changed", "Change one byte"],
          ].map(([id, label]) => (
            <button
              key={id}
              disabled={state === "checking"}
              aria-pressed={variant === id}
              onClick={() => {
                setVariant(id);
                setState("idle");
              }}
            >
              {label}
            </button>
          ))}
        </div>
        <p className="finding">
          Hash the archived bytes locally, or change one byte in a temporary
          browser copy and run the same check.
        </p>
        <div className="visual-actions">
          <Receipt name="/field/custody.json">Custody audit</Receipt>
          <Receipt name="/field/repeat.json">Replay receipt</Receipt>
        </div>
      </div>
      <div className="ledger-visual">
        <div className="visual-title">
          <span>CONTENT-ADDRESSED EVENT</span>
          <Fingerprint size={17} />
        </div>
        <ol className="ledger-chain">
          {[
            ["Camera imports", data.before],
            ["Event published", data.after],
            ["Approval replayed", data.repeat],
          ].map(([l, n]) => (
            <li key={l}>
              <i />
              <strong>{l}</strong>
              <code>#{n}</code>
            </li>
          ))}
        </ol>
        <div className="root-digest">
          <span>EVENT ROOT · SHA-256</span>
          <code>{data.root.slice(7)}</code>
          <div className="object-links">
            {data.objects.map((o) => (
              <a
                key={o.digest}
                href={"/field/" + o.digest.slice(7) + ".bin"}
                download
              >
                {o.manifest ? "Manifest" : "Witness"} ·{" "}
                {o.bytes.toLocaleString("en-US")} B <ArrowUpRight size={12} />
              </a>
            ))}
          </div>
        </div>
        <button
          className="verify"
          disabled={state === "checking"}
          onClick={verify}
        >
          {state === "verified" ? (
            <Check size={15} />
          ) : (
            <ShieldCheck size={15} />
          )}{" "}
          Verify bytes
        </button>
        <p className="verify-result" data-verdict={state} role="status">
          {messages[state]}
        </p>
      </div>
    </div>
  );
}

export default function EvidenceDesk({
  field,
  onSurvey,
  initialTab = "association",
  standalone = false,
}) {
  const [tab, setTab] = useState(initialTab);
  return (
    <section id="casebook" className="exhibit">
      <div className="chapter-heading">
        <div>
          <span className="section-kicker">THE EVIDENCE DESK</span>
          <h2>Follow one doorstep event.</h2>
          <SectionLink slug={tabRoutes[tab]} />
        </div>
        <p>
          Two camera views, one proposed match, and a published record you can
          check yourself.
        </p>
      </div>
      <div className="workbench">
        <div className="workbench-tabs" aria-label="Evidence exhibit">
          {[
            [GitMerge, "association", "Camera fusion"],
            [Binary, "belief", "Belief lab"],
            [Fingerprint, "ledger", "Event ledger"],
          ].map(([Icon, id, label]) => (
            <button
              key={id}
              aria-pressed={id === tab}
              onClick={() => {
                if (standalone && id !== tab)
                  window.location.assign(exhibitPath(tabRoutes[id]));
                else setTab(id);
              }}
            >
              <Icon size={16} />
              {label}
            </button>
          ))}
        </div>
        {tab === "association" ? (
          <Association data={field.association} onSurvey={onSurvey} />
        ) : tab === "belief" ? (
          <Belief data={field.belief} />
        ) : (
          <Ledger data={field.ledger} />
        )}
      </div>
    </section>
  );
}
