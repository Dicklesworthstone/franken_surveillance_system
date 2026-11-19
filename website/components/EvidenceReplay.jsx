"use client";
import { useEffect, useRef } from "react";

export default function EvidenceReplay({ scenario, time, report }) {
  const clip = useRef(null);
  useEffect(() => {
    const video = clip.current;
    const sync = () => {
      if (video.readyState >= 1 && Math.abs(video.currentTime - time) > 0.055)
        video.currentTime = time;
    };
    sync();
    video.addEventListener("loadedmetadata", sync);
    return () => video.removeEventListener("loadedmetadata", sync);
  }, [time, scenario]);
  const segment = Math.min(47, Math.floor(time * 4));
  const boxes = (report?.candidates || []).flatMap((c) =>
    c.evidence
      .filter((e) => e.segment === segment)
      .map((e) => ({ track: c.track_id, box: e.track_box_cxcywh })),
  );
  return (
    <div className="replay-root">
      <div className="film-frame">
        <video
          ref={clip}
          key={scenario.id}
          muted
          playsInline
          preload="auto"
          src={"/films/" + scenario.id + ".mp4"}
          poster={"/films/" + scenario.id + ".jpg"}
        />
        {boxes.map(({ track, box: [x, y, w, h] }) => (
          <div
            key={track}
            className="native-box"
            style={{
              left: ((x - w / 2) / 160) * 100 + "%",
              top: ((y - h / 2) / 90) * 100 + "%",
              width: (w / 160) * 100 + "%",
              height: (h / 90) * 100 + "%",
            }}
          >
            <span>T{track}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
