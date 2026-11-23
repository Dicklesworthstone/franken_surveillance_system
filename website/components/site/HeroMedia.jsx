"use client";
import { Pause, Play } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { stamp } from "../../lib/watch/take";
import { Badge, Reticle } from "./ui";

/**
 * The picture behind the headline, with what the script says about the man in
 * it. The still is always there. When a loop exists and the visitor has not
 * asked for reduced motion, the loop covers the still once it plays, and the
 * outline, the clock and the camera lamps follow the frame on screen. Nothing
 * here fades: a readout over a blend of two moments would match neither.
 *
 * Those change with every frame, so they are written to the page directly.
 * React only ever renders the still's own moment.
 */
export default function HeroMedia({ video, still, stillFrame, alt, truth, take }) {
  const ref = useRef(null);
  const [calm, setCalm] = useState(true);
  const [playing, setPlaying] = useState(false);
  // What the visitor wants. Scrolling away pauses the film without changing it.
  const wanted = useRef(true);
  const shown = useRef(-1);
  const el = useRef({});
  const set = (name) => (node) => {
    el.current[name] = node;
  };

  useEffect(() => {
    if (!video) return;
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setCalm(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, [video]);
  const moving = Boolean(video) && !calm;

  const show = useCallback(
    (frame) => {
      if (!truth) return;
      const index = Math.max(0, Math.min(truth.frames.length - 1, frame));
      if (index === shown.current) return;
      shown.current = index;
      const row = truth.frames[index];
      const t = truth.start + index / truth.fps;
      const { box, clock, lights, action, count, lamps, wall } = el.current;
      if (box) {
        box.style.opacity = row.box ? "1" : "0";
        if (row.box) {
          const [left, top, width, height] = row.box;
          box.style.left = left * 100 + "%";
          box.style.top = top * 100 + "%";
          box.style.width = width * 100 + "%";
          box.style.height = height * 100 + "%";
        }
      }
      const text = (node, value) => {
        if (node && node.textContent !== value) node.textContent = value;
      };
      text(clock, stamp(take, t, 0, true));
      text(lights, t >= truth.lights ? "On" : "Off");
      lights?.toggleAttribute("data-on", t >= truth.lights);
      text(action, row.action ?? "Out of the scene");
      text(count, String(row.seen.length));
      [...(lamps?.children ?? [])].forEach((lamp, i) => lamp.toggleAttribute("data-on", row.seen.includes(i)));
      [...(wall?.children ?? [])].forEach((tile, i) => tile.toggleAttribute("data-on", row.seen.includes(i)));
    },
    [truth, take],
  );

  // Without the film the still is on screen, so the readout is the still's.
  useEffect(() => {
    if (moving) return;
    setPlaying(false);
    show(stillFrame);
  }, [moving, show, stillFrame]);

  const frameAt = useCallback((seconds) => Math.floor(seconds * (truth?.fps ?? 0) + 0.001), [truth]);
  useEffect(() => {
    const v = ref.current;
    if (!moving || !v || !truth) return;
    let request;
    // Frames decoded before the film covers the still are not on screen.
    const present = (seconds) => v.hasAttribute("data-shown") && show(frameAt(seconds));
    if (v.requestVideoFrameCallback) {
      const next = (_, meta) => {
        present(meta.mediaTime);
        request = v.requestVideoFrameCallback(next);
      };
      request = v.requestVideoFrameCallback(next);
      return () => v.cancelVideoFrameCallback(request);
    }
    const tick = () => {
      present(v.currentTime);
      request = requestAnimationFrame(tick);
    };
    request = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(request);
  }, [moving, truth, show, frameAt]);

  // It plays while it is on screen; a loop nobody can see does not need to decode.
  useEffect(() => {
    const v = ref.current;
    if (!moving || !v) return;
    const observer = new IntersectionObserver((entries) => {
      if (!entries.at(-1).isIntersecting) v.pause();
      else if (wanted.current) v.play().catch(() => {});
    });
    observer.observe(v);
    return () => observer.disconnect();
  }, [moving]);

  const first = truth?.frames[stillFrame];
  const at = truth ? truth.start + stillFrame / truth.fps : 0;
  return (
    <div className="hero__media">
      <div className="hero__plate">
        <div className="hero__frame">
          {still && <img src={still} alt={alt} fetchPriority="high" />}
          {moving && (
            <video
              ref={ref}
              src={video}
              onPlaying={(event) => {
                const v = event.currentTarget;
                // After this the readout only follows frames that were presented; a stall ends here too, and shows nothing new.
                if (!v.hasAttribute("data-shown")) {
                  v.setAttribute("data-shown", "");
                  show(frameAt(v.currentTime));
                }
                setPlaying(true);
              }}
              onPause={() => setPlaying(false)}
              muted
              loop
              playsInline
              preload="auto"
              aria-hidden="true"
              tabIndex={-1}
            />
          )}
          {first && (
            <span
              className="hero__box"
              ref={set("box")}
              aria-hidden="true"
              style={
                first.box
                  ? { left: first.box[0] * 100 + "%", top: first.box[1] * 100 + "%", width: first.box[2] * 100 + "%", height: first.box[3] * 100 + "%" }
                  : { opacity: 0 }
              }
            >
              <b>{truth.track}</b>
            </span>
          )}
        </div>
        <Reticle className="hero__reticle" />
      </div>
      {/* The security room's other screens: each camera, lit while the script has the man in its view. */}
      {first && (
        <ol className="hero__wall" ref={set("wall")} aria-hidden="true">
          {take.cameras.map((cam, i) => (
            <li key={cam.id} data-on={first.seen.includes(i) ? "" : undefined}>
              <img src={`/watch/plates/cam-${cam.id}.webp`} width="640" height="360" alt="" loading="lazy" decoding="async" />
              <span>{cam.name}</span>
            </li>
          ))}
        </ol>
      )}
      {(first || moving) && (
        <div className="hero__hud">
          {first && (
            <dl>
              <div>
                <dt className="micro">Scene clock</dt>
                <dd className="data" ref={set("clock")}>
                  {stamp(take, at, 0, true)}
                </dd>
              </div>
              <div>
                <dt className="micro">Floodlights</dt>
                <dd className="data hero__lights" ref={set("lights")} data-on={at >= truth.lights ? "" : undefined}>
                  {at >= truth.lights ? "On" : "Off"}
                </dd>
              </div>
              <div>
                <dt className="micro">{truth.track}</dt>
                <dd className="data hero__action" ref={set("action")}>
                  {first.action ?? "Out of the scene"}
                </dd>
              </div>
              <div className="hero__seen">
                <dt className="micro">
                  Held by <span ref={set("count")}>{first.seen.length}</span> of {take.cameras.length} cameras
                </dt>
                <dd>
                  <ol ref={set("lamps")}>
                    {take.cameras.map((cam, i) => (
                      <li key={cam.id} data-on={first.seen.includes(i) ? "" : undefined}>
                        {cam.name}
                      </li>
                    ))}
                  </ol>
                </dd>
              </div>
            </dl>
          )}
          {moving && (
            <button
              type="button"
              className="hero__pause"
              onClick={() => {
                const v = ref.current;
                if (!v) return;
                wanted.current = v.paused;
                if (v.paused) v.play().catch(() => {});
                else v.pause();
              }}
              aria-label={playing ? "Pause the film behind the headline" : "Play the film behind the headline"}
            >
              {playing ? <Pause aria-hidden="true" /> : <Play aria-hidden="true" />}
            </button>
          )}
        </div>
      )}
      <p className="hero__credit">
        <Badge kind="staged">Rendered scene, fictional house, staged positions</Badge>
      </p>
    </div>
  );
}
