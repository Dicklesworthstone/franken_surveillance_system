"use client";
import { useEffect, useRef, useState } from "react";
import { FilmFailure, useFilm } from "./Feed";

/**
 * One frame of a camera's film at a chosen moment, shown as a still. It plays
 * nothing; it reuses the film the console has already fetched.
 */
export default function FilmFrame({ camera, t, caption }) {
  const box = useRef(null);
  const video = useRef(null);
  const [near, setNear] = useState(false);
  useEffect(() => {
    const watcher = new IntersectionObserver(
      (entries) => entries.some((entry) => entry.isIntersecting) && setNear(true),
      { rootMargin: "500px" },
    );
    watcher.observe(box.current);
    return () => watcher.disconnect();
  }, []);
  const { source, failure, retry } = useFilm(camera, near);
  // The picture stays dark until this film has reached the moment named in the caption.
  const [displayed, setDisplayed] = useState(null);
  const [decodeFailure, setDecodeFailure] = useState(null);
  const decodingFailed = Boolean(source && decodeFailure === source);
  const shown = source && !decodingFailed && displayed?.source === source && displayed.t === t;
  useEffect(() => {
    const v = video.current;
    if (!v || !source) return;
    const arrived = () => {
      // Half a frame of tolerance: some browsers report the frame's own time after a seek.
      if (!v.error && !v.seeking && v.currentSrc === source && v.readyState >= 2 && Math.abs(v.currentTime - t) < 0.04)
        setDisplayed({ source, t });
    };
    const seek = () => {
      if (v.readyState >= 1 && Math.abs(v.currentTime - t) >= 0.001) v.currentTime = t;
      arrived();
    };
    seek();
    v.addEventListener("loadedmetadata", seek);
    v.addEventListener("loadeddata", arrived);
    v.addEventListener("seeked", arrived);
    return () => {
      v.removeEventListener("loadedmetadata", seek);
      v.removeEventListener("loadeddata", arrived);
      v.removeEventListener("seeked", arrived);
    };
  }, [source, t]);
  return (
    <figure className="frame" ref={box}>
      <span className="frame__picture" style={{ "--shape": `${camera.width} / ${camera.height}` }}>
        {camera.video ? (
          <video
            key={source ?? "waiting"}
            ref={video}
            src={source ?? undefined}
            className={shown ? "is-shown" : ""}
            onEmptied={() => setDisplayed(null)}
            onSeeking={() => setDisplayed(null)}
            onError={() => { if (source) setDecodeFailure(source); }}
            muted
            playsInline
            preload="auto"
            tabIndex={-1}
          />
        ) : (
          <FilmFailure message="No recording is available for this moment." />
        )}
        <FilmFailure message={failure || (decodingFailed && "This browser could not decode the camera recording.")} retry={retry} />
      </span>
      <figcaption>{caption}</figcaption>
    </figure>
  );
}
