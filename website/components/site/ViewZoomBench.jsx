"use client";
import { useRef, useState } from "react";

// Registered views from architecture/agent_views.json (design target budgets).
const VIEWS = [
  {
    id: "AVIEW-001",
    name: "pulse",
    target: 120,
    max: 300,
    owner: "fss-context-pack",
    purpose: "Tiny high-severity meaningful delta, sensor-health, coverage-loss, effect-uncertainty and obligation heartbeat.",
    sections: ["changed", "criticalChanges", "coverageChanges", "urgentObligations", "effectUncertainty"],
  },
  {
    id: "AVIEW-002",
    name: "brief",
    target: 800,
    max: 1600,
    owner: "fss-situation",
    purpose: "Primary mission SituationCapsule answering what is established, which alternative worlds remain possible, what changed and what is robustly safe next.",
    sections: ["situation", "certifiedCore", "materialAlternatives", "adversarialResiduals", "controlEnvelope", "next"],
  },
  {
    id: "AVIEW-005",
    name: "operation",
    target: 600,
    max: 1200,
    owner: "fss-obligation",
    purpose: "One durable plan, effect or task with progress, expected terminal proof, open obligations and reconciliation status.",
    sections: ["plans", "obligations", "progress", "proofExpected", "reconciliation", "effectUncertainty"],
  },
  {
    id: "AVIEW-007",
    name: "decision_diff",
    target: 900,
    max: 1800,
    owner: "fss-explain",
    purpose: "Explains why a conclusion, priority, hypothesis, plan or preferred affordance changed between two anchors.",
    sections: ["basisBefore", "basisAfter", "changedEvidence", "decisionImpact", "whatWouldReverse"],
  },
  {
    id: "AVIEW-008",
    name: "epistemic_map",
    target: 1500,
    max: 3000,
    owner: "fss-knowledge",
    purpose: "Full domain map of known, estimated, unknown, conflicted, stale, not_observable, redacted and indeterminate cells plus protected possible worlds.",
    sections: ["states", "certified", "certifiedAbsences", "unknown", "contradictions", "coverage", "redactions"],
  },
  {
    id: "AVIEW-006",
    name: "handoff",
    target: 1800,
    max: 3200,
    owner: "fss-handoff",
    purpose: "Minimum sufficient root-last state for a fresh agent to resume without rediscovery or hidden conversational assumptions.",
    sections: ["mission", "authority", "cases", "plans", "obligations", "invalidatedAssumptions", "budgets"],
  },
  {
    id: "AVIEW-003",
    name: "case",
    target: 3000,
    max: 5000,
    owner: "fss-investigation",
    purpose: "Durable investigation view carrying competing hypotheses, support, contradictions, predicted observations, falsifiers and stop rules.",
    sections: ["question", "hypotheses", "evidence", "contradictions", "discriminators", "stopRule"],
  },
  {
    id: "AVIEW-004",
    name: "forensic",
    target: 8000,
    max: 16000,
    owner: "fss-context-pack",
    purpose: "Broad exact evidence graph, source byte spans, receipts, alternative derivations and replay handles.",
    sections: ["evidenceGraph", "sourceHandles", "receipts", "derivations", "replay"],
  },
];

const HYDRATION = [
  ["H0", "Identity", "Handle, kind, anchor and cost quote only"],
  ["H1", "Synopsis", "Typed summary, knowledge state and provenance"],
  ["H2", "Artifact", "Decision receipt, witness or bounded geometry"],
  ["H3", "Source", "Authorized privacy-screened media bytes"],
];

export default function ViewZoomBench({ native }) {
  const [selectedId, setSelectedId] = useState("AVIEW-002");
  const tabRefs = useRef([]);
  const view = VIEWS.find((v) => v.id === selectedId) ?? VIEWS[1];
  const maxBudget = 16000;

  const brief = native?.briefing ?? null;
  const refusedPulse = native?.calls?.find((c) => c.view === "pulse" && c.outcome === "refused") ?? null;

  let takeNote = null;
  let isMeasuredNote = false;
  if (view.name === "pulse" && refusedPulse) {
    takeNote = `Refused on this take: ${refusedPulse.reason ?? refusedPulse.error ?? "critical facts exceeded the 300-token ceiling"} (fail-closed, never silently truncated).`;
  } else if (view.name === "brief" && brief) {
    const crit = brief.compression?.critical;
    const critText = crit
      ? ` with ${crit.omittedCriticalItems} of ${crit.knownCriticalItems} critical items omitted`
      : "";
    takeNote = `Measured on this take: ${brief.tokens.toLocaleString("en")} of ${brief.target.toLocaleString("en")} tokens returned${critText}.`;
    isMeasuredNote = true;
  }

  const onTabKeyDown = (event, index) => {
    let next = null;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (index + 1) % VIEWS.length;
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (index - 1 + VIEWS.length) % VIEWS.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = VIEWS.length - 1;
    if (next == null) return;
    event.preventDefault();
    setSelectedId(VIEWS[next].id);
    tabRefs.current[next]?.focus();
  };

  return (
    <div className="views" aria-labelledby="views-heading">
      <div className="views__head">
        <h4 id="views-heading" className="beat__label">
          Eight registered views, sized by token ceiling
        </h4>
        <span className="views__budget data">
          target {view.target.toLocaleString("en")} / max {view.max.toLocaleString("en")} tok
        </span>
      </div>

      <div className="views__pills" role="tablist" aria-label="Registered fss/1 agent views">
        {VIEWS.map((item, i) => {
          const active = item.id === view.id;
          return (
            <button
              key={item.id}
              ref={(el) => { tabRefs.current[i] = el; }}
              id={`view-tab-${item.id}`}
              type="button"
              role="tab"
              tabIndex={active ? 0 : -1}
              aria-selected={active}
              aria-controls={`view-panel-${item.id}`}
              className={"views__pill data" + (active ? " is-active" : "")}
              onKeyDown={(e) => onTabKeyDown(e, i)}
              onClick={() => setSelectedId(item.id)}
            >
              {item.name}
            </button>
          );
        })}
      </div>

      <div
        className="views__card"
        role="tabpanel"
        id={`view-panel-${view.id}`}
        aria-labelledby={`view-tab-${view.id}`}
      >
        <div className="views__meta">
          <span className="data views__id">{view.id}</span>
          <span className="data views__owner">{view.owner}</span>
        </div>
        <p className="views__purpose">{view.purpose}</p>

        <div className="views__meter" aria-hidden="true">
          <span className="views__meter-max" style={{ width: `${Math.max((view.max / maxBudget) * 100, 3)}%` }}>
            <i className="views__meter-target" style={{ width: `${(view.target / view.max) * 100}%` }} />
          </span>
        </div>
        <p className="views__scale data">
          <span>Target: {view.target.toLocaleString("en")} tok</span>
          <span>Ceiling: {view.max.toLocaleString("en")} tok</span>
        </p>

        <div className="views__sections">
          {view.sections.map((sec) => (
            <span key={sec} className="chip data">
              {sec}
            </span>
          ))}
        </div>

        {takeNote && (
          <p className={"views__note" + (isMeasuredNote ? " is-measured" : "")}>{takeNote}</p>
        )}

        <dl className="views__ladder" aria-label="Progressive evidence hydration ladder">
          {HYDRATION.map(([lvl, label, desc]) => (
            <div key={lvl}>
              <dt className="data">
                {lvl} <span>{label}</span>
              </dt>
              <dd>{desc}</dd>
            </div>
          ))}
        </dl>
      </div>

      <p className="source source--staged">
        Design token budgets from architecture/agent_views.json.
        {brief && ` Brief measured at ${brief.tokens.toLocaleString("en")} tokens on this take.`}
      </p>
    </div>
  );
}
