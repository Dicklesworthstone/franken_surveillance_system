"use client";
import { useEffect } from "react";

/**
 * Arms every `.reveal` block once. A block already on screen, or above it,
 * stays as it is; each one further down waits until it scrolls into view. The
 * HTML shows everything, so a page whose script never runs is still whole, and
 * a visitor who asks for less motion gets no entrances.
 */
export default function RevealController() {
  // Anything that moves on its own does so only while it is on screen.
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) entry.target.toggleAttribute("data-live", entry.isIntersecting);
    });
    for (const el of document.querySelectorAll(".chain")) observer.observe(el);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const show = (el) => el.classList.add("is-shown");
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          // A block the reader has jumped past is shown too, so scrolling back never meets a blank.
          if (!entry.isIntersecting && entry.boundingClientRect.top > 0) continue;
          show(entry.target);
          observer.unobserve(entry.target);
        }
      },
      { rootMargin: "0px 0px -8% 0px" },
    );
    for (const el of document.querySelectorAll(".reveal")) {
      if (el.getBoundingClientRect().top < window.innerHeight) show(el);
      else observer.observe(el);
    }
    document.documentElement.classList.add("reveal-armed");
    return () => {
      observer.disconnect();
      document.documentElement.classList.remove("reveal-armed");
    };
  }, []);
  return null;
}
