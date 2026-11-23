"use client";
import { useRef, useState } from "react";
import { AGENT_VIEWS, HYDRATION_LEVELS } from "../../lib/watch/agent-views.mjs";
import { Badge, Figure } from "./ui";

// The registered views, smallest ceiling first.
const VIEWS = [...AGENT_VIEWS].sort((a, b) => a.max - b.max);
const MAX_BUDGET = Math.max(...VIEWS.map((v) => v.max));
// The registry's purposes are phrases; the page prints them as sentences, word for word.
const sentence = (text) => text[0].toUpperCase() + text.slice(1) + ".";
// Words joined by slashes are one unbreakable run to the browser, wider than a phone; allow a break after each slash.
const breakable = (text) => text.split(/(?<=\/)/).flatMap((part, i) => (i ? [<wbr key={i} />, part] : [part]));

export default function ViewZoomBench({ native }) {
  const [selectedId, setSelectedId] = useState("AVIEW-002");
  const tabRefs = useRef([]);
  const view = VIEWS.find((v) => v.id === selectedId) ?? VIEWS[0];

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
    <Figure
      className="views reveal"
      eyebrow="Semantic zoom"
      title="Eight registered views, sized by token ceiling."
      titleId="views-heading"
      badge={<Badge kind="design">Design budgets</Badge>}
      note={
        <p>
          Purposes, sections and token budgets from architecture/agent_views.json, drawn on a square-root scale so the
          smallest views stay visible.
          {brief && ` Brief measured at ${brief.tokens.toLocaleString("en")} tokens on this take.`}
        </p>
      }
    >
      <div className="views__bars" role="tablist" aria-label="Registered fss/1 agent views" aria-orientation="vertical">
        {VIEWS.map((item, i) => {
          const active = item.id === view.id;
          return (
            <button
              key={item.id}
              ref={(el) => {
                tabRefs.current[i] = el;
              }}
              id={`view-tab-${item.id}`}
              type="button"
              role="tab"
              tabIndex={active ? 0 : -1}
              aria-selected={active}
              aria-controls="view-panel"
              className={"views__bar" + (active ? " is-active" : "")}
              onKeyDown={(e) => onTabKeyDown(e, i)}
              onClick={() => setSelectedId(item.id)}
            >
              <span className="views__name data">{item.name}</span>
              <span className="views__track" aria-hidden="true">
                <i style={{ width: `${Math.sqrt(item.max / MAX_BUDGET) * 100}%` }} />
                <i style={{ width: `${Math.sqrt(item.target / MAX_BUDGET) * 100}%` }} />
              </span>
              <span className="views__tok data">
                {item.target.toLocaleString("en")} of {item.max.toLocaleString("en")}
              </span>
            </button>
          );
        })}
      </div>

      <div className="views__card" role="tabpanel" id="view-panel" aria-labelledby={`view-tab-${view.id}`}>
        <div>
          <p className="views__meta data">
            <span>{view.id}</span>
            <span>{view.owner}</span>
          </p>
          <p className="views__purpose">{breakable(sentence(view.purpose))}</p>
          <div className="views__sections">
            {view.sections.map((sec) => (
              <span key={sec} className="chip data">
                {sec}
              </span>
            ))}
          </div>
          {takeNote && <p className={"views__note" + (isMeasuredNote ? " is-measured" : "")}>{takeNote}</p>}
        </div>
        <dl className="views__ladder" aria-label="Progressive evidence hydration ladder">
          {HYDRATION_LEVELS.map(({ id, label, meaning, raw }) => (
            <div key={id}>
              <dt className="data">
                {id} <span>{label}</span>
              </dt>
              <dd>
                {sentence(meaning)}
                {raw && " Raw private media."}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </Figure>
  );
}
