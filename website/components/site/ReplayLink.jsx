"use client";

/**
 * A link up to the console that also sets its clock back to the start of the minute, so a visitor
 * who watched to the end does not arrive on the last frame. Without JavaScript it is a plain link.
 */
export default function ReplayLink({ className, children }) {
  return (
    <a className={className} href="#console" onClick={() => window.dispatchEvent(new CustomEvent("fss:seek", { detail: 0 }))}>
      {children}
    </a>
  );
}
