"use client";
import { useState } from "react";
import CameraFilm from "./CameraFilm";
import { DURATION, recording } from "../lib/scenarios";

export default function EvidenceReplay({
  asset,
  time,
  report,
  entries,
  label,
}) {
  const [displayed, setDisplayed] = useState(null);
  const segment = Math.min(
    DURATION * recording.nativeFps - 1,
    Math.floor(time * recording.nativeFps),
  );
  // The importer takes frame 0, 3, 6, ... . Seek inside that film frame,
  // avoiding browser-dependent rounding at an exact presentation boundary.
  const target = segment / recording.nativeFps + 0.5 / recording.fps;
  const boxes = [];
  if (displayed === target) {
    const trackBox = (track, sample) => {
      const [cx, cy, w, h] = sample.track_box_cxcywh;
      boxes.push({
        key: "track-" + track,
        label: entries ? "Zone entry" : "T" + track,
        x: cx - w / 2,
        y: cy - h / 2,
        w,
        h,
      });
    };
    if (entries) {
      for (const entry of entries.filter((e) => e.segment === segment))
        trackBox(entry.track_id, entry);
    } else {
      for (const track of report?.candidates ?? []) {
        for (const sample of track.evidence.filter(
          (e) => e.segment === segment,
        ))
          trackBox(track.track_id, sample);
        for (const e of track.class_evidence.filter(
          (e) => e.segment === segment && e.outcome === "associated",
        )) {
          // FSS BOX_SUBPIXELS is 256. The detector reports the four edges.
          const [x, y, right, bottom] = e.bounds_subpixel.map((q) => q / 256);
          boxes.push({
            key: e.evidence_digest,
            label: e.label,
            model: true,
            x,
            y,
            w: right - x,
            h: bottom - y,
          });
        }
      }
    }
  }
  const width = report?.width ?? recording.nativeWidth,
    height = report?.height ?? recording.nativeHeight;
  return (
    <div
      className="replay-root"
      data-feed={asset}
      data-segment={displayed === target ? segment : undefined}
    >
      <div className="film-frame">
        <CameraFilm
          key={asset}
          asset={asset}
          target={target}
          onDisplayed={setDisplayed}
          aria-label={label + " camera recording"}
        />
        {boxes.map(({ key, label, model, x, y, w, h }) => (
          <div
            key={key}
            className={"native-box" + (model ? " model-box" : "")}
            style={{
              left: (x / width) * 100 + "%",
              top: (y / height) * 100 + "%",
              width: (w / width) * 100 + "%",
              height: (h / height) * 100 + "%",
            }}
          >
            <span>{label}</span>
          </div>
        ))}
      </div>
      <span className="scene-label">
        <span />
        {label} · {entries ? "Ground zone" : "FSS replay"}
      </span>
    </div>
  );
}
