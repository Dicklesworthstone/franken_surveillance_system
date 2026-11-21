"use client";
import { useEffect, useEffectEvent, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { matchesDigest } from "../../lib/night/digest";
import { boxAt } from "../../lib/watch/take";

// Each film is fetched whole, once, and played from memory. A static host that
// ignores byte ranges cannot seek a streamed MP4, and the console seeks constantly.
//
// The outlines drawn over a film come from the scene file, so the film has to be
// the one that scene file was written for. Its bytes are checked against the
// SHA-256 the scene file records. A film that fails the check, or does not
// arrive, is not shown; the visitor gets a message and a button to fetch it again.
const films = new Map();
function film(url, digest, again) {
  const key = url + " " + digest;
  if (!films.has(key)) {
    const load = async () => {
      if (!/^[a-f0-9]{64}$/.test(digest)) throw Error("This film has no recorded fingerprint.");
      if (!globalThis.crypto?.subtle) throw Error("This browser cannot check the film here. Open the site over HTTPS.");
      const response = await fetch(url, { cache: again ? "reload" : "default" });
      if (!response.ok) throw Error("This film did not load.");
      const blob = await response.blob();
      if (!(await matchesDigest(blob, "sha256:" + digest))) throw Error("This film is not the one the outlines were made for.");
      return blob;
    };
    const request = load();
    films.set(key, request);
    request.catch(() => {
      if (films.get(key) === request) films.delete(key);
    });
  }
  return films.get(key);
}

/** The film for one camera as an object URL, or why it could not be shown, with a way to try again. */
export function useFilm(camera, wanted) {
  const { video: url, videoDigest: digest } = camera;
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState(null);
  const binding = useMemo(() => ({ url, digest, wanted, attempt }), [url, digest, wanted, attempt]);
  useEffect(() => {
    if (!binding.url || !binding.wanted) return;
    let active = true;
    let object;
    film(binding.url, binding.digest, binding.attempt > 0).then(
      (blob) => {
        if (!active) return;
        object = URL.createObjectURL(blob);
        setResult({ binding, source: object });
      },
      (error) => {
        if (active) setResult({ binding, failure: error.message || "This film did not load." });
      },
    );
    return () => {
      active = false;
      if (object) URL.revokeObjectURL(object);
    };
  }, [binding]);
  return {
    ...(result?.binding === binding ? result : {}),
    retry: () => setAttempt((n) => n + 1),
  };
}

export function FilmFailure({ message, retry }) {
  if (!message) return null;
  return (
    <span className="film-error" role="status">
      <span>{message}</span>
      {retry && <button type="button" onClick={retry}>
        Load this film again
      </button>}
    </span>
  );
}

/**
 * One camera's film, kept on the console clock, with the people it sees
 * outlined. Outlines are dashed because they are staged positions projected
 * through the lens. Detector boxes from the FSS binaries are drawn solid.
 *
 * The console keeps one element per camera and moves the selected one into the
 * large slot, so a cut between cameras never reloads a film.
 */
export default function Feed({ camera, take, summary, clock, detections, large, wanted = true, style, setPresentation }) {
  const video = useRef(null);
  const { source, failure, retry } = useFilm(camera, wanted);
  // mediaTime is the PTS of the picture sent to the compositor. currentTime can already be
  // at a seek destination and the console clock keeps moving if the browser stalls this film.
  const lastPicture = useRef(null);
  const [displayed, setDisplayed] = useState(null);
  const [decodeFailure, setDecodeFailure] = useState(null);
  const decodingFailed = Boolean(source && decodeFailure === source);
  const picture = source && !decodingFailed && displayed?.source === source ? displayed.frame : null;
  const reportPicture = useEffectEvent((frame) => {
    const timingAvailable = Boolean(video.current?.requestVideoFrameCallback);
    setPresentation?.((previous) =>
      previous?.camera === camera && previous.frame === frame && previous.timingAvailable === timingAvailable
        ? previous : { camera, frame, timingAvailable },
    );
  });
  useEffect(() => {
    const v = video.current;
    if (!source || !v?.requestVideoFrameCallback) return;
    let callback;
    const present = (_, metadata) => {
      const frame = Math.round(metadata.mediaTime * summary.fps);
      const sample = Number.isFinite(frame) && frame >= 0 && frame < summary.frames ? { source, frame } : null;
      lastPicture.current = sample;
      if (!v.seeking && !v.error && v.currentSrc === source) {
        // Commit the SVG during the compositor callback. A deferred React update can
        // otherwise leave the previous frame's outline in the next browser paint.
        flushSync(() => {
          setDisplayed(sample);
          reportPicture(sample?.frame ?? null);
        });
      }
      callback = v.requestVideoFrameCallback(present);
    };
    callback = v.requestVideoFrameCallback(present);
    return () => v.cancelVideoFrameCallback(callback);
  }, [source, summary.fps, summary.frames]);
  const finishSeek = (event) => {
    const v = event.currentTarget;
    // The presentation callback may have run during this seek. Reuse only a picture
    // observed at its destination. Otherwise wait for the compositor's next callback.
    const sample = lastPicture.current;
    const target = Math.floor(v.currentTime * summary.fps + 0.0001);
    if (!v.seeking && !v.error && v.currentSrc === source && sample?.source === source && sample.frame === target) setDisplayed(sample);
  };
  useEffect(() => {
    reportPicture(picture);
  }, [camera, picture, setPresentation]);
  useEffect(() => {
    const v = video.current;
    const sync = () => {
      if (!v || v.readyState < 1) return;
      const t = Math.min(clock.time(), (v.duration || clock.duration) - 0.05);
      if (clock.playing()) {
        if (v.paused) v.play().catch(() => {});
        // Let the decoder finish its current seek before requesting another.
        if (!v.seeking && Math.abs(v.currentTime - t) > 0.3) v.currentTime = t;
      } else {
        if (!v.paused) v.pause();
        if (Math.abs(v.currentTime - t) > 0.03) v.currentTime = t;
      }
    };
    sync();
    v?.addEventListener("loadeddata", sync);
    const stop = clock.subscribe(sync);
    return () => {
      stop();
      v?.removeEventListener("loadeddata", sync);
    };
  }, [clock, source]);

  const people = take && picture != null
    ? summary.actors
        .map((a) => ({ actor: a, box: boxAt(take, camera.id, a.id, picture) }))
        .filter((p) => p.box)
    : [];
  const live = detections?.[picture] ?? [];
  return (
    <div className={"feed" + (large ? " feed--large" : "") + (picture == null ? " is-finding" : "")} style={style}>
      <span className="feed__picture" style={{ aspectRatio: `${camera.width} / ${camera.height}` }}>
        {camera.video ? (
          <video
            key={source ?? "waiting"}
            ref={video}
            onSeeked={finishSeek}
            onSeeking={() => setDisplayed(null)}
            onEmptied={() => { lastPicture.current = null; setDisplayed(null); }}
            onError={() => { if (source) setDecodeFailure(source); }}
            src={source ?? undefined}
            muted
            playsInline
            preload="auto"
            tabIndex={-1}
            aria-hidden="true"
          />
        ) : (
          <FilmFailure message="No recording is available for this camera." />
        )}
        <FilmFailure message={failure || (decodingFailed && "This browser could not decode the camera recording.")} retry={retry} />
        {picture != null && <svg className="feed__marks" viewBox="0 0 1 1" preserveAspectRatio="none" aria-hidden="true">
          {people.map(({ actor, box }) => (
            <rect
              key={actor.id}
              className="feed__staged"
              x={box[0]}
              y={box[1]}
              width={box[2] - box[0]}
              height={box[3] - box[1]}
              style={{ stroke: actor.colour }}
            />
          ))}
          {live.map((d, i) => (
            <rect key={i} className="feed__measured" x={d[0]} y={d[1]} width={d[2] - d[0]} height={d[3] - d[1]} />
          ))}
        </svg>}
        {picture != null && large &&
          people.map(({ actor, box }) => (
            <span
              key={actor.id}
              className="feed__label"
              style={{ left: `${box[0] * 100}%`, top: `${box[1] * 100}%`, background: actor.colour }}
            >
              {actor.track}
            </span>
          ))}
      </span>
    </div>
  );
}
