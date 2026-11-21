"use client";
import { useEffect, useRef, useState } from "react";

/**
 * The picture behind the headline. The still is always there. When a loop
 * exists and the visitor has not asked for reduced motion, the loop fades in
 * over it once it can play.
 */
export default function HeroMedia({ video, still, alt }) {
  const ref = useRef(null);
  const [moving, setMoving] = useState(false);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    if (!video) return;
    const calm = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setMoving(!calm.matches);
    update();
    calm.addEventListener("change", update);
    return () => calm.removeEventListener("change", update);
  }, [video]);
  useEffect(() => {
    if (!moving) setReady(false);
    else ref.current?.play().catch(() => setMoving(false));
  }, [moving]);
  return (
    <div className="hero__plate">
      {still && <img src={still} alt={alt} />}
      {moving && (
        <video
          ref={ref}
          src={video}
          className={ready ? "is-ready" : ""}
          onPlaying={() => setReady(true)}
          muted
          loop
          playsInline
          preload="auto"
          aria-hidden="true"
        />
      )}
    </div>
  );
}
