"use client";
import { useEffect, useMemo, useState } from "react";
export function useNativeWatch(view) {
  const [response, store] = useState(null),
    url = view?.watch;
  useEffect(() => {
    if (!url) return;
    const controller = new AbortController();
    async function read() {
      try {
        const r = await fetch(url, { signal: controller.signal });
        if (!r.ok) throw Error();
        const data = await r.json();
        if (!controller.signal.aborted) store({ url, data });
      } catch {
        if (!controller.signal.aborted) store({ url, error: true });
      }
    }
    read();
    return () => controller.abort();
  }, [url]);
  return response?.url === url ? response : null;
}
function boxesFor(report) {
  const result = new Map();
  function add(frame, box) {
    const boxes = result.get(frame) || [];
    boxes.push(box);
    result.set(frame, boxes);
  }
  for (const c of report?.candidates || []) {
    for (const e of c.evidence) {
      const [x, y, w, h] = e.track_box_cxcywh;
      add(e.segment, {
        kind: "track",
        label: "T" + c.track_id,
        x: x - w / 2,
        y: y - h / 2,
        w,
        h,
        key: e.observation_digest,
      });
    }
    for (const e of c.class_evidence || []) {
      if (e.outcome !== "associated") continue;
      const [x, y, r, b] = e.bounds_subpixel.map((n) => n / 256);
      add(e.segment, {
        kind: "class",
        label: e.label,
        x,
        y,
        w: r - x,
        h: b - y,
        key: e.evidence_digest,
      });
    }
  }
  return result;
}
export function TrackOverlay({ videoRef, view, watch }) {
  const [presented, setPresented] = useState(null);
  const report = watch?.data,
    boxes = useMemo(() => boxesFor(report), [report]);
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    let job;
    const update = (time) =>
      setPresented(Math.floor(time * view.filmFps + 0.001));
    if (!video.seeking && video.currentTime > 0 && video.readyState >= 2)
      update(video.currentTime);
    if (typeof video.requestVideoFrameCallback === "function") {
      const frame = (_now, metadata) => {
        update(metadata.mediaTime);
        job = video.requestVideoFrameCallback(frame);
      };
      job = video.requestVideoFrameCallback(frame);
      return () => video.cancelVideoFrameCallback(job);
    }
    const seek = () => update(video.currentTime);
    video.addEventListener("seeked", seek);
    video.addEventListener("timeupdate", seek);
    return () => {
      video.removeEventListener("seeked", seek);
      video.removeEventListener("timeupdate", seek);
    };
  }, [videoRef, view]);
  if (!report || presented === null) return null;
  const native = (presented * view.nativeFps) / view.filmFps;
  if (!Number.isInteger(native)) return null;
  return (
    <div className="track-overlay" aria-hidden="true">
      {(boxes.get(native) || []).map((b, i) => (
        <i
          key={b.key + "-" + i}
          className={b.kind}
          style={{
            left: (b.x / report.width) * 100 + "%",
            top: (b.y / report.height) * 100 + "%",
            width: (b.w / report.width) * 100 + "%",
            height: (b.h / report.height) * 100 + "%",
          }}
        >
          <span>{b.label}</span>
        </i>
      ))}
    </div>
  );
}
export function TrackEvents({ view, watch, seek }) {
  const [picked, pick] = useState("");
  if (watch?.error)
    return (
      <p className="track-events" role="status">
        The native track report could not be opened.{" "}
        <a href={view.watch}>Read source ↗</a>
      </p>
    );
  if (!watch?.data) return null;
  const report = watch.data,
    rows = report.candidates
      .flatMap((c) => [
        {
          time: c.entry_segment / view.nativeFps,
          label: "Track " + c.track_id + " enters the image zone",
        },
        ...(c.class_evidence || [])
          .filter((e) => e.outcome === "associated")
          .map((e) => ({
            time: e.segment / view.nativeFps,
            label:
              "Track " +
              c.track_id +
              " · " +
              e.label +
              " (" +
              e.score.toFixed(2) +
              ")",
          })),
      ])
      .sort((a, b) => a.time - b.time);
  return (
    <div className="track-events">
      <div>
        <span className="ticker">Native motion timeline</span>
        <p>
          {rows.length
            ? "Select an entry to inspect the measured frame. Boxes appear on the sampled frames that supplied them."
            : "FSS returned no image-zone track entry for this recording."}
        </p>
      </div>
      {rows.length > 0 && (
        <label>
          <span className="sr-only">Measured track event</span>
          <select
            value={picked}
            onChange={(e) => {
              pick(e.target.value);
              seek(rows[Number(e.target.value)].time);
            }}
          >
            <option value="" disabled>
              Choose a measured event
            </option>
            {rows.map((e, i) => (
              <option key={i} value={i}>
                {e.time.toFixed(2)} s · {e.label}
              </option>
            ))}
          </select>
        </label>
      )}
      <a href={view.watch}>Watch report ↗</a>
      {view.dwell && <div className="dwell-result"><span className="ticker">Time in view</span>
        <p>{view.dwell.count
          ? "The longest qualifying track spans at least "+view.dwell.longestSeconds.toFixed(2)+" s in the sampled image zone. The subject can move within the zone."
          : "No track met the five-observation, one-second dwell threshold."}</p>
        <a href={view.dwell.report}>Native dwell evidence ↗</a>
      </div>}
    </div>
  );
}
