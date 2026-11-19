"use client";
import { useState } from "react";
import {
  ArrowUpRight,
  TerminalSquare,
  Radio,
  Bell,
  Lightbulb,
  Fence,
  Siren,
  Camera,
  FileVideo,
} from "lucide-react";
const operations = [
  [
    "orient",
    "Read situation",
    "What does the reviewing agent know?",
    "The situation capsule pins the session to a ledger revision and includes open questions, proof pointers and permissible next operations.",
  ],
  [
    "explain",
    "Explain event",
    "Why was this event held?",
    "The forensic explanation ties the committed event to its evidence. The replay source and clock are shared, so the two views cannot establish independent support.",
  ],
  [
    "alert",
    "Plan notification",
    "Would the system notify the owner?",
    "The agent asked to plan an alert for this event. The native planner refused it before preparing or dispatching a notification.",
  ],
  [
    "handoff",
    "Hand off case",
    "What survives a handoff?",
    "The agent saved its objective, situation root, unresolved questions, budgets and recommended next steps in a handoff capsule.",
  ],
  [
    "resume",
    "Resume session",
    "Can another review pick up here?",
    "The native resume operation accepted the saved handoff and reopened the same session. The receiving reviewer inherits its recorded scope and obligations.",
  ],
];
export default function AgentDesk({ data }) {
  const [op, setOp] = useState("orient"),
    r = data[op];
  const [, label, title, body] = operations.find((v) => v[0] === op);
  return (
    <section id="agent-console" className="exhibit agent-area">
      <div className="chapter-heading">
        <div>
          <span className="section-kicker">AGENT CONSOLE</span>
          <h2>Give the next agent the case.</h2>
        </div>
        <p>
          Inspect the actual responses from the local Rust agent interface. Each
          operation has a capability, an evidence anchor and an explicit
          outcome.
        </p>
      </div>
      <div className="agent-shell">
        <div className="agent-menu">
          <span className="micro">
            <TerminalSquare size={15} /> FSS/1 SESSION
          </span>
          {operations.map(([id, name]) => (
            <button key={id} aria-pressed={id === op} onClick={() => setOp(id)}>
              <i />
              {name}
              <span>{data[id].operation}</span>
            </button>
          ))}
        </div>
        <div className="agent-response">
          <div className="response-heading">
            <span>
              {r.operation} / {label}
            </span>
            <b className={r.outcome === "refused" ? "held" : ""}>{r.outcome}</b>
          </div>
          <h3>{title}</h3>
          <p>{body}</p>
          <dl className="agent-fields">
            <div>
              <dt>Response payload</dt>
              <dd>{r.payload}</dd>
            </div>
            <div>
              <dt>Capability</dt>
              <dd>{r.capabilities.join(", ")}</dd>
            </div>
            <div>
              <dt>{r.error ? "Refusal identity" : "Proof pointers"}</dt>
              <dd>{r.error ?? r.proofs}</dd>
            </div>
            {op === "orient" && (
              <div>
                <dt>Open question</dt>
                <dd>{r.unknowns.at(-1)}</dd>
              </div>
            )}
            {op === "handoff" && (
              <div>
                <dt>Handoff ID</dt>
                <dd>{r.handoff}</dd>
              </div>
            )}
            {op === "resume" && (
              <div>
                <dt>Resumed session</dt>
                <dd>{r.session}</dd>
              </div>
            )}
          </dl>
          <a className="receipt" href={"/field/" + op + ".json"}>
            Inspect response JSON <ArrowUpRight size={14} />
          </a>
        </div>
      </div>
      <div className="response-horizon">
        <div>
          <span className="section-kicker">OWNER-CONTROLLED RESPONSE</span>
          <h3>From review to action.</h3>
          <p>
            FSS separates what an agent believes from what it can do. Its
            reference notification path requires a witnessed plan, approval,
            dispatch and a verifiable outcome. Lights, gates and sirens
            illustrate the wider design for capability-scoped device adapters.
          </p>
        </div>
        <div className="actuators">
          {[
            [Bell, "Owner notification", "Reference relay"],
            [Lightbulb, "Porch lighting", "Design target"],
            [Fence, "Gate control", "Design target"],
            [Siren, "Audible alarm", "Design target"],
          ].map(([Icon, name, state]) => (
            <div key={name}>
              <Icon size={17} />
              <strong>{name}</strong>
              <span>{state}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export function Sources() {
  const references =
    "https://github.com/Dicklesworthstone/franken_surveillance_system/blob/main/";
  return (
    <section className="exhibit sources">
      <div className="chapter-heading">
        <div>
          <span className="section-kicker">CAMERA INPUTS</span>
          <h2>Start with the cameras you own.</h2>
        </div>
        <p>
          The ambition is one site view across makes and price points. Available
          inputs depend on the model, firmware and local interfaces the owner
          can access.
        </p>
      </div>
      <div className="source-grid">
        {[
          [
            Radio,
            "Local network cameras",
            "RTSP / ONVIF",
            "A compatible IP camera or recorder can expose local video or recording metadata. Native reference paths preserve source identity, packet gaps and timing uncertainty.",
            "docs/ONVIF_RECORDING_DISCOVERY.md",
          ],
          [
            Camera,
            "Manufacturer adapters",
            "EXACT DEVICE + FIRMWARE",
            "Wyze, AOSU and UniFi represent different integration surfaces. The adapter matrix records the scope and maturity of each path.",
            "DEVICE_ADAPTER_MATRIX.md",
          ],
          [
            FileVideo,
            "Recordings and exports",
            "FILE IMPORT / REPLAY",
            "Juniper House uses this path. Nine synthetic camera films become hashed imports that the tracker, fusion engine and agent interface can inspect.",
            "website/README.md",
          ],
        ].map(([Icon, name, state, body, path]) => (
          <article key={name}>
            <Icon size={22} />
            <span>{state}</span>
            <h3>{name}</h3>
            <p>{body}</p>
            <a className="receipt" href={references + path}>
              Implementation notes <ArrowUpRight size={13} />
            </a>
          </article>
        ))}
      </div>
    </section>
  );
}
