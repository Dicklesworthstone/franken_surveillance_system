"use client";
import { useEffect, useState } from "react";

const NAV_ITEMS = [
  ["minute", "The minute", "Minute"],
  ["how", "How it works", "How"],
  ["architecture", "Architecture", "Stack"],
  ["status", "What runs today", "Status"],
];

export default function TopBarNav({ repo, home = "#top", mark }) {
  const [current, setCurrent] = useState("");

  useEffect(() => {
    const sections = NAV_ITEMS.map(([id]) => document.getElementById(id)).filter(Boolean);
    if (!sections.length) return;
    let raf = 0;
    const pick = () => {
      raf = 0;
      const probe = 120;
      let active = "";
      for (const sec of sections) {
        if (sec.getBoundingClientRect().top <= probe) active = sec.id;
      }
      setCurrent((prev) => (prev === active ? prev : active));
    };
    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(pick);
    };
    pick();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      if (raf) cancelAnimationFrame(raf);
      window.removeEventListener("scroll", onScroll);
    };
  }, []);

  return (
    <>
      <div className="wrap topbar__row">
        <a className="wordmark" href={home}>
          {mark}
          <span>Franken Surveillance</span>
        </a>
        <nav aria-label="Sections">
          <ul>
            {NAV_ITEMS.map(([id, label]) => (
              <li key={id}>
                <a
                  href={`#${id}`}
                  className={current === id ? "is-current" : undefined}
                  aria-current={current === id ? "location" : undefined}
                >
                  {label}
                </a>
              </li>
            ))}
            <li className="topbar__keep">
              <a className="topbar__source" href={repo}>
                Source
              </a>
            </li>
          </ul>
        </nav>
      </div>
      <nav className="topbar__mobile" aria-label="Quick section jump">
        <div className="wrap topbar__mobile-row">
          {NAV_ITEMS.map(([id, , shortLabel]) => (
            <a
              key={id}
              href={`#${id}`}
              className={current === id ? "is-current" : undefined}
              aria-current={current === id ? "location" : undefined}
            >
              {shortLabel}
            </a>
          ))}
        </div>
      </nav>
    </>
  );
}
