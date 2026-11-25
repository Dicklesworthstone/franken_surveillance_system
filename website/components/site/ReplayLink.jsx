"use client";

/**
 * A link up to the console that also sets its clock back to the start of the minute, so a visitor
 * who watched to the end does not arrive on the last frame. Without JavaScript it is a plain link.
 * A click that opens a new tab or window leaves this page's film where it is.
 */
export default function ReplayLink({ className, children }) {
  const rewind = (event) => {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    window.dispatchEvent(new CustomEvent("fss:seek", { detail: 0 }));
  };
  return (
    <a className={className} href="#console" onClick={rewind}>
      {children}
    </a>
  );
}
