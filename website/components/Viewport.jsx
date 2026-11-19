"use client";
import { useEffect, useRef, useState } from "react";
import CameraFilm from "./CameraFilm";
import { createProperty } from "../lib/property";

import { cameraAsset, recording, stamp } from "../lib/scenarios";

export default function Viewport({
  scenario,
  time,
  view,
  cones,
  reset,
  vantage,
  entries,
}) {
  const surface = useRef(null),
    stage = useRef(null),
    current = useRef(null),
    frame = useRef(null);
  const [ready, setReady] = useState(false),
    [failed, setFailed] = useState(false);
  useEffect(() => {
    current.current = { scenario, time, view, cones, entries };
    frame.current?.();
  }, [scenario, time, view, cones, entries]);
  useEffect(() => {
    const canvas = surface.current,
      parent = canvas.parentElement;
    let model;
    const lost = (e) => {
      e.preventDefault();
      setFailed(true);
      setReady(false);
    };
    canvas.addEventListener("webglcontextlost", lost);
    try {
      model = createProperty(canvas);
    } catch {
      setFailed(true);
      return () => canvas.removeEventListener("webglcontextlost", lost);
    }
    stage.current = model;
    const draw = () => {
      const v = current.current;
      if (!v) return;
      const o = model.draw(v.scenario, v.time, v.view, v.cones, v.entries);
      for (const marker of parent.querySelectorAll(".survey-point")) {
        const e = o.entryLabels[marker.dataset.camera];
        marker.hidden = !e || e.x < 0 || e.x > 100 || e.y < 0 || e.y > 100;
        if (e && !marker.hidden) {
          marker.style.left = e.x + "%";
          marker.style.top = e.y + "%";
          marker.querySelector("time").textContent = stamp(
            e.segment / recording.nativeFps,
            true,
          );
        }
      }
      const marks = parent.querySelector(".trackbox");
      const height = Math.abs(o.foot[1] - o.head[1]);
      marks.hidden = v.view === "overview" || !o.visible;
      marks.style.left = o.foot[0] + "%";
      marks.style.top = Math.min(o.head[1], o.foot[1]) + "%";
      marks.style.height = height + "%";
      marks.style.width =
        Math.max(
          2,
          (height *
            (v.scenario.id === "wildlife" ? 0.98 : 0.35) *
            parent.clientHeight) /
            parent.clientWidth,
        ) + "%";
    };
    frame.current = draw;
    model.onOrbit(draw);
    const size = () => {
      model.resize(parent.clientWidth, parent.clientHeight);
      draw();
    };
    const ro = new ResizeObserver(size);
    ro.observe(parent);
    size();
    setReady(true);
    return () => {
      ro.disconnect();
      frame.current = null;
      stage.current = null;
      canvas.removeEventListener("webglcontextlost", lost);
      model.dispose();
    };
  }, []);
  useEffect(() => {
    if (vantage === "overhead") stage.current?.overhead();
    else stage.current?.reset();
    frame.current?.();
  }, [reset, vantage]);
  const inSurvey = entries != null;
  useEffect(() => {
    if (inSurvey) stage.current?.focusSurvey();
    frame.current?.();
  }, [inSurvey]);
  const camera = view === "overview" ? scenario.camera : view;
  const asset = cameraAsset(scenario, camera);
  return (
    <div
      className={
        "viewport-surface" + (view === "overview" ? "" : " fixed-view")
      }
      style={{
        backgroundImage:
          "url(/films/" + (view === "overview" ? "property" : asset) + ".jpg)",
      }}
    >
      <canvas
        ref={surface}
        aria-label={
          view === "overview"
            ? "Interactive 3D model of Juniper House. Drag to orbit or choose a fixed camera below."
            : "Virtual camera image of Juniper House"
        }
        style={{ opacity: ready ? 1 : 0 }}
      />
      {failed && (
        <>
          <CameraFilm key={asset} asset={asset} target={time} />
          <span className="fallback">
            WebGL unavailable · recorded {camera} view
          </span>
        </>
      )}
      {entries &&
        !failed &&
        ["porch", "drive"].map((id) => (
          <div
            hidden
            className={"survey-point " + id}
            data-camera={id}
            key={id}
          >
            <span>
              {id === "porch" ? "Porch" : "Driveway"} <time />
            </span>
          </div>
        ))}
      <div
        className="trackbox"
        style={failed ? { display: "none" } : undefined}
        hidden
      >
        <span>{scenario.kind} · simulated</span>
      </div>
    </div>
  );
}
