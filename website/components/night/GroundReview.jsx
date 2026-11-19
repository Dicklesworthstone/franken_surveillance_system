"use client";
import { useEffect, useRef, useState } from "react";
import { displayCamera } from "../../lib/night/catalog";

function Plan({ estate, pair, report, selected }) {
  const canvas = useRef(null);
  useEffect(() => {
    const surface = canvas.current,
      ctx = surface.getContext("2d");
    if (!ctx) return;
    function paint() {
      const w = surface.clientWidth,
        h = surface.clientHeight,
        scale = window.devicePixelRatio || 1;
      if (!w || !h) return;
      surface.width = Math.round(w * scale);
      surface.height = Math.round(h * scale);
      ctx.scale(scale, scale);
      const cameras = pair.map((id) => estate.cameras.find((c) => c.id === id));
      const box = report.zones[0],
        padding = 5;
      const xs = [
        box.x,
        box.x + box.width,
        ...cameras.map((c) => c.position[0]),
      ];
      const zs = [
        box.y,
        box.y + box.height,
        ...cameras.map((c) => c.position[2]),
      ];
      const minX = Math.min(...xs) - padding,
        maxX = Math.max(...xs) + padding,
        minZ = Math.min(...zs) - padding,
        maxZ = Math.max(...zs) + padding;
      const step = Math.min(w / (maxX - minX), h / (maxZ - minZ)),
        cx = (minX + maxX) / 2,
        cz = (minZ + maxZ) / 2;
      const X = (x) => (x - cx) * step + w / 2,
        Z = (z) => (z - cz) * step + h / 2;
      const rect = (x, z, dx, dz, fill, stroke) => {
        ctx.fillStyle = fill;
        ctx.strokeStyle = stroke;
        ctx.lineWidth = 1;
        ctx.fillRect(X(x), Z(z), dx * step, dz * step);
        ctx.strokeRect(X(x), Z(z), dx * step, dz * step);
      };
      ctx.fillStyle = "#152321";
      ctx.fillRect(0, 0, w, h);
      ctx.strokeStyle = "#243431";
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let x = Math.floor((cx - w / step / 2) / 2) * 2; X(x) < w; x += 2) {
        ctx.moveTo(X(x), 0);
        ctx.lineTo(X(x), h);
      }
      for (let z = Math.floor((cz - h / step / 2) / 2) * 2; Z(z) < h; z += 2) {
        ctx.moveTo(0, Z(z));
        ctx.lineTo(w, Z(z));
      }
      ctx.stroke();
      for (const b of Object.values(estate.buildings))
        rect(
          b.x[0],
          b.z[0],
          b.x[1] - b.x[0],
          b.z[1] - b.z[0],
          "#32433c",
          "#697365",
        );
      for (const lane of estate.walks) {
        ctx.strokeStyle = "#4b5144";
        ctx.lineWidth = lane.width * step;
        ctx.lineJoin = "round";
        ctx.beginPath();
        lane.centre_line.forEach(([x, z], i) =>
          i ? ctx.lineTo(X(x), Z(z)) : ctx.moveTo(X(x), Z(z)),
        );
        ctx.stroke();
      }
      ctx.setLineDash([5, 4]);
      rect(box.x, box.y, box.width, box.height, "#e0c18420", "#d8af6a");
      ctx.setLineDash([]);
      const ink = ["#eec487", "#a3cdc1"];
      cameras.forEach((c, i) => {
        const x = X(c.position[0]),
          z = Z(c.position[2]);
        ctx.fillStyle = ink[i];
        ctx.beginPath();
        ctx.arc(x, z, 5, 0, 2 * Math.PI);
        ctx.fill();
        ctx.font = "12px sans-serif";
        ctx.fillText(
          displayCamera(c.id),
          Math.max(4, Math.min(x + 8, w - 56)),
          z - 7,
        );
      });
      report.entries.forEach((entry, i) => {
        const [x, z] = entry.ground;
        ctx.strokeStyle = ink[pair.indexOf(entry.camera)];
        ctx.lineWidth = i === selected ? 3 : 1.5;
        ctx.beginPath();
        ctx.arc(X(x), Z(z), i === selected ? 7 : 4, 0, 2 * Math.PI);
        ctx.stroke();
      });
      ctx.fillStyle = "#e4e3d2";
      ctx.font = "10px monospace";
      ctx.fillText("N ↑", 12, 17);
      const length = step * 2;
      ctx.fillRect(12, h - 15, length, 2);
      ctx.fillText("2 m", 12, h - 21);
    }
    const obs = new ResizeObserver(paint);
    obs.observe(surface);
    paint();
    return () => obs.disconnect();
  }, [estate, pair, report, selected]);
  return (
    <canvas
      ref={canvas}
      className="ground-plan"
      aria-label="Ground plan showing the two selected mounted cameras, comparison zone and measured event entries"
    />
  );
}

export default function GroundReview({ estate, incident, cameras, onSeek }) {
  const pair = Object.values(incident.associations.pairs).find((p) =>
    p.cameras.every((c) => cameras.includes(c)),
  );
  const [result, setResult] = useState(null),
    [selected, select] = useState(null);
  useEffect(() => {
    if (!pair) return;
    const abort = new AbortController();
    async function load() {
      try {
        const r = await fetch(pair.report, { signal: abort.signal });
        if (!r.ok) throw Error();
        const value = await r.json();
        if (!abort.signal.aborted) setResult({ src: pair.report, value });
      } catch {
        if (!abort.signal.aborted) setResult({ src: pair.report, error: true });
      }
    }
    select(null);
    load();
    return () => abort.abort();
  }, [pair]);
  if (!pair) return null;
  const report = result?.src === pair.report ? result.value : null;
  return (
    <section className="ground-review">
      <div className="ground-heading">
        <div>
          <span className="ticker">Ground projection</span>
          <h3>Two views of one place.</h3>
        </div>
        <a href={pair.report}>Pair report ↗</a>
      </div>
      {report ? (
        <div className="ground-grid">
          <Plan
            estate={estate}
            pair={pair.cameras}
            report={report}
            selected={selected}
          />
          <div className="ground-findings">
            <b>
              {report.candidate_count} paired{" "}
              {report.candidate_count === 1 ? "candidate" : "candidates"}
            </b>
            <p>
              The outlined area is the comparison zone. FSS compares measured
              entries within {report.distance_gate} m and{" "}
              {report.time_gate_ns / 1000000} ms.
            </p>
            {report.entries.length ? (
              <>
                <label>
                  Projected track entry
                  <select
                    value={selected ?? ""}
                    onChange={(e) => {
                      const n = Number(e.target.value);
                      select(n);
                      const entry = report.entries[n];
                      onSeek(
                        entry.camera,
                        entry.segment / incident.views[entry.camera].nativeFps,
                      );
                    }}
                  >
                    <option value="" disabled>
                      Choose an observation
                    </option>
                    {report.entries.map((e, i) => (
                      <option key={i} value={i}>
                        {displayCamera(e.camera)} ·{" "}
                        {(
                          e.segment / incident.views[e.camera].nativeFps
                        ).toFixed(2)}{" "}
                        s · Track {e.track_id}
                      </option>
                    ))}
                  </select>
                </label>
                {selected !== null && (
                  <p>
                    Measured ground position{" "}
                    <code>
                      {report.entries[selected].ground
                        .map((v) => v.toFixed(2) + " m")
                        .join(" / ")}
                    </code>
                  </p>
                )}
              </>
            ) : (
              <p>
                Neither camera recorded a qualifying zone entry for this pair.
              </p>
            )}
          </div>
        </div>
      ) : (
        <p role="status">
          {result?.src === pair.report && result.error
            ? "The pair report could not be loaded."
            : "Loading the native camera comparison…"}
        </p>
      )}
    </section>
  );
}
