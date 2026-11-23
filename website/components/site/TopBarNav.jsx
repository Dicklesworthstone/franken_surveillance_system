"use client";
import { ArrowUpRight, Bot, ClipboardList, Layers, Play, Scale } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { CHAPTERS } from "./chapters";

const ICONS = { minute: Play, how: Layers, evidence: Scale, watch: Bot, machine: ClipboardList };

/**
 * The page's chrome. Wide screens: a floating pill with the five chapters, the
 * one in view marked, and a hairline that fills as the page is read. Phones:
 * the name and the source at the top, and the chapters in a dock at the bottom.
 */
export default function TopBarNav({ repo, home = "#top", mark }) {
  const [scrolled, setScrolled] = useState(false);
  const [current, setCurrent] = useState(null);
  const bar = useRef(null);

  // The progress bar is written directly, never through a React render.
  useEffect(() => {
    let raf = 0;
    const update = () => {
      raf = 0;
      const doc = document.documentElement;
      const room = doc.scrollHeight - window.innerHeight;
      const done = room > 0 ? Math.min(1, Math.max(0, window.scrollY / room)) : 0;
      if (bar.current) bar.current.style.transform = `scaleX(${done})`;
      setScrolled(window.scrollY > 24);
    };
    const schedule = () => {
      if (!raf) raf = requestAnimationFrame(update);
    };
    update();
    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule, { passive: true });
    return () => {
      if (raf) cancelAnimationFrame(raf);
      window.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
    };
  }, []);

  // The chapter crossing the middle of the window is the one in view. The hero and the footer are in none.
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries)
          if (entry.isIntersecting) setCurrent(entry.target.getAttribute("data-chapter"));
      },
      { rootMargin: "-46% 0px -53% 0px" },
    );
    for (const el of document.querySelectorAll("[data-chapter], [data-outside]")) observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const link = (chapter) => ({
    href: "#" + chapter.id,
    className: current === chapter.id ? "is-current" : undefined,
    "aria-current": current === chapter.id ? "location" : undefined,
    style: { "--sphere": `var(--${chapter.light})` },
  });
  return (
    <>
      <header className={"topbar" + (scrolled ? " is-scrolled" : "")}>
        <div className="topbar__pill">
          <a className="wordmark" href={home}>
            {mark}
            <span>Franken Surveillance</span>
          </a>
          <nav className="topbar__nav" aria-label="Chapters">
            <ul>
              {CHAPTERS.map((chapter) => (
                <li key={chapter.id}>
                  <a {...link(chapter)}>
                    <span className="sphere" aria-hidden="true" />
                    <span className="data" aria-hidden="true">
                      {chapter.number}
                    </span>
                    {chapter.label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
          <a className="topbar__source" href={repo}>
            GitHub <ArrowUpRight aria-hidden="true" />
          </a>
          <span className="topbar__progress" aria-hidden="true">
            <i ref={bar} />
          </span>
        </div>
      </header>
      <nav className="dock" aria-label="Chapters, quick jump">
        <ul className="glass">
          {CHAPTERS.map((chapter) => {
            const Icon = ICONS[chapter.id];
            return (
              <li key={chapter.id}>
                <a {...link(chapter)}>
                  <Icon aria-hidden="true" />
                  {chapter.short}
                </a>
              </li>
            );
          })}
        </ul>
      </nav>
    </>
  );
}
