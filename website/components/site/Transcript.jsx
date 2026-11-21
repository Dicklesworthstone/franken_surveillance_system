"use client";
import { useEffect, useRef } from "react";

/**
 * A list that follows the clock: entries already reached are solid, the rest
 * are dimmed, and pressing one moves the clock to it.
 */
function Follow({ rows, t, clock, children, label }) {
  const list = useRef(null);
  const index = rows.reduce((last, row, i) => (row.t <= t + 0.01 ? i : last), -1);
  useEffect(() => {
    const el = list.current?.children[Math.max(index, 0)];
    if (!el) return;
    const box = list.current;
    const top = el.offsetTop - box.clientHeight / 2 + el.clientHeight / 2;
    box.scrollTo({ top, behavior: clock.playing() ? "smooth" : "auto" });
  }, [index, clock]);
  return (
    <ol className="follow" ref={list} aria-label={label}>
      {rows.map((row, i) => (
        <li key={row.id} className={i === index ? "is-now" : i < index ? "is-past" : "is-ahead"}>
          <button type="button" onClick={() => clock.seek(row.t)}>
            {children(row)}
          </button>
        </li>
      ))}
    </ol>
  );
}

export function AgentLog({ rows, t, clock }) {
  return (
    <Follow rows={rows} t={t} clock={clock} label="What the agent called, in order">
      {(row) => (
        <>
          <span className="follow__when data">{row.clock}</span>
          <span className="follow__what">
            <span className="follow__op data">{row.opName}</span>
            <span className="follow__line">{row.line}</span>
          </span>
        </>
      )}
    </Follow>
  );
}

export function LedgerLog({ rows, t, clock }) {
  return (
    <Follow rows={rows} t={t} clock={clock} label="Ledger rows, in order">
      {(row) => (
        <>
          <span className="follow__when data">{row.clock}</span>
          <span className="follow__what">
            <span className="follow__op data">{row.kind}</span>
            <span className="follow__line">{row.subject}</span>
            <span className="follow__hash data">sha256 {row.digest.slice(0, 16)}</span>
          </span>
        </>
      )}
    </Follow>
  );
}
