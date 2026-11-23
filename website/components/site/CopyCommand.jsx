"use client";
import { useEffect, useRef, useState } from "react";
import { REPO } from "./TopBar";

const SNIPPETS = [
  {
    id: "inspect",
    label: "Inspect build",
    code: `git clone ${REPO}
cd franken_surveillance_system
cargo run -p fss-cli -- capabilities --json
cargo run -p fss-cli -- doctor --json`,
    note: "capabilities lists what this build can do. doctor checks the installation and its stores. A passing build does not qualify any camera, codec or model.",
  },
  {
    id: "mcp",
    label: "Local MCP",
    code: `cargo run -p fss-cli --bin fss-mcp -- \\
  --root /path/to/deployment \\
  --principal agent:night-watch`,
    note: "Starts the synchronous local stdio MCP server exposing all 14 fss/1 operations and 10 query targets under fixed launcher authority.",
  },
  {
    id: "store",
    label: "Inspect store",
    code: `cargo run -p fss-cli -- status --json --root /path/to/deployment
cargo run -p fss-cli -- doctor --json --root /path/to/deployment
cargo run -p fss-cli -- query --json --root /path/to/deployment --target events`,
    note: "Read-only deployment inspection: status reports retained inventory, doctor checks journal/root health without writing or locking, and query reads committed events.",
  },
  {
    id: "qualify",
    label: "Local qualify",
    code: `bash scripts/qualify.sh --lane policy
bash scripts/qualify.sh --lane rust`,
    note: "Repository-local qualification entrypoint. GitHub workflows call these scripts and hold no independent release authority.",
  },
];

function fallbackCopy(text) {
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(area);
  return ok;
}

export default function CopyCommand() {
  const [tab, setTab] = useState("inspect");
  const [status, setStatus] = useState("idle");
  const timer = useRef(null);
  const tabRefs = useRef([]);
  const currentIndex = Math.max(0, SNIPPETS.findIndex((s) => s.id === tab));
  const current = SNIPPETS[currentIndex] ?? SNIPPETS[0];

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  const flashStatus = (next) => {
    if (timer.current) clearTimeout(timer.current);
    setStatus(next);
    timer.current = setTimeout(() => setStatus("idle"), 1800);
  };

  const copy = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(current.code);
        flashStatus("copied");
        return;
      }
      flashStatus(fallbackCopy(current.code) ? "copied" : "failed");
    } catch {
      flashStatus(fallbackCopy(current.code) ? "copied" : "failed");
    }
  };

  const onTabKeyDown = (event, index) => {
    let next = null;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (index + 1) % SNIPPETS.length;
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (index - 1 + SNIPPETS.length) % SNIPPETS.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = SNIPPETS.length - 1;
    if (next == null) return;
    event.preventDefault();
    setTab(SNIPPETS[next].id);
    setStatus("idle");
    tabRefs.current[next]?.focus();
  };

  return (
    <div className="cmdbox">
      <div className="cmdbox__bar">
        <div className="cmdbox__tabs" role="tablist" aria-label="Example commands">
          {SNIPPETS.map((s, i) => {
            const active = s.id === current.id;
            return (
              <button
                key={s.id}
                ref={(el) => { tabRefs.current[i] = el; }}
                id={`cmd-tab-${s.id}`}
                type="button"
                role="tab"
                tabIndex={active ? 0 : -1}
                aria-selected={active}
                aria-controls={active ? `cmd-panel-${s.id}` : undefined}
                className={active ? "is-active" : ""}
                onKeyDown={(e) => onTabKeyDown(e, i)}
                onClick={() => {
                  setTab(s.id);
                  setStatus("idle");
                }}
              >
                {s.label}
              </button>
            );
          })}
        </div>
        <button type="button" className="cmdbox__copy data" onClick={copy} aria-live="polite">
          {status === "copied" ? "Copied" : status === "failed" ? "Copy failed" : "Copy"}
        </button>
      </div>
      <div role="tabpanel" id={`cmd-panel-${current.id}`} aria-labelledby={`cmd-tab-${current.id}`}>
        <pre className="status__run data" tabIndex={0} role="group" aria-label="The commands, scrolls sideways">
          <code>{current.code}</code>
        </pre>
        <p className="soft">{current.note}</p>
      </div>
    </div>
  );
}
