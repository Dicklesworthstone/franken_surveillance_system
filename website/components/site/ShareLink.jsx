"use client";
import { Check, Link2 } from "lucide-react";
import { useRef, useState } from "react";

/**
 * A link to a chapter's own page, whose preview carries the chapter's picture. On a phone it opens
 * the system share sheet; elsewhere it copies the address and says so. Without scripts, or if both
 * are refused, it is an ordinary link to that page.
 */
export default function ShareLink({ path, title }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef(0);
  const share = async (event) => {
    const url = new URL(path, window.location.href).href;
    if (navigator.share && window.matchMedia("(pointer: coarse)").matches) {
      event.preventDefault();
      // Closing the share sheet rejects; that is the visitor's choice, not an error.
      await navigator.share({ title, url }).catch(() => {});
      return;
    }
    if (!navigator.clipboard) return;
    event.preventDefault();
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 2400);
    } catch {
      window.location.assign(path);
    }
  };
  return (
    <>
      <a className={"share-link" + (copied ? " is-copied" : "")} href={path} onClick={share}>
        {copied ? <Check aria-hidden="true" /> : <Link2 aria-hidden="true" />}
        <span>{copied ? "Link copied" : "Share this chapter"}</span>
      </a>
      <span className="visually-hidden" aria-live="polite">
        {copied ? "The link to this chapter is on your clipboard." : ""}
      </span>
    </>
  );
}
