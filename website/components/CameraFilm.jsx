"use client";
import { useEffect, useImperativeHandle, useRef, useState } from "react";
import { matchesDigest } from "../lib/night/digest";

// These small, same-origin fixtures must be seekable even on a static host
// that ignores byte ranges. Release the clip whenever the view changes.
export default function CameraFilm({
  asset,
  filmUrl,
  filmDigest,
  directory = "films",
  active = true,
  videoRef,
  target,
  onDisplayed,
  onError,
  ...props
}) {
  const ref = useRef(null);
  useImperativeHandle(videoRef, () => ref.current, []);
  const [loaded, setLoaded] = useState(null);
  const [failure, setFailure] = useState("");
  const [attempt, retry] = useState(0);
  const path = filmUrl ?? "/" + directory + "/" + asset + ".mp4";
  const source = active && loaded?.path === path && loaded.digest === filmDigest
    ? loaded.url : undefined;
  useEffect(() => {
    setLoaded(null);
    setFailure("");
    if (!active) return;
    const request = new AbortController();
    let url;
    async function load() {
      let message = "Camera film unavailable.";
      try {
        const response = await fetch(path, { signal: request.signal });
        if (!response.ok) throw Error("Film unavailable");
        const blob = await response.blob();
        if (filmDigest !== undefined) {
          message = "The camera film could not be verified.";
          if (!(await matchesDigest(blob, filmDigest))) {
            message = "The recording differs from its retained digest.";
            throw Error(message);
          }
        }
        if (request.signal.aborted) return;
        url = URL.createObjectURL(blob);
        setLoaded({ path, digest: filmDigest, url });
      } catch {
        if (!request.signal.aborted) {
          ref.current?.dispatchEvent(new CustomEvent("error", { detail: message }));
        }
      }
    }
    load();
    return () => {
      request.abort();
      if (url) URL.revokeObjectURL(url);
    };
  }, [path, filmDigest, active, attempt]);
  useEffect(() => {
    const video = ref.current;
    if (!source || target === undefined || !video) return;
    const confirm = () => {
      if (
        !video.seeking &&
        video.readyState >= 2 &&
        Math.abs(video.currentTime - target) < 0.001
      )
        onDisplayed?.(target);
    };
    const seek = () => {
      if (
        video.readyState >= 1 &&
        Math.abs(video.currentTime - target) >= 0.001
      )
        video.currentTime = target;
      confirm();
    };
    seek();
    video.addEventListener("loadedmetadata", seek);
    video.addEventListener("loadeddata", confirm);
    video.addEventListener("seeked", confirm);
    return () => {
      video.removeEventListener("loadedmetadata", seek);
      video.removeEventListener("loadeddata", confirm);
      video.removeEventListener("seeked", confirm);
    };
  }, [source, target, onDisplayed]);
  return (
    <>
      <video
        ref={ref}
        src={source ?? undefined}
        data-recording={path}
        poster={path.replace(/\.mp4$/, ".jpg")}
        muted
        playsInline
        preload="auto"
        onError={(event) => {
          setFailure(event.nativeEvent.detail || "Camera film unavailable.");
          onError?.(event);
        }}
        {...props}
      />
      {failure && (
        <span className="fallback" role="status">
          {failure}{" "}
          <button type="button" onClick={() => retry((n) => n + 1)}>Retry recording</button>
        </span>
      )}
    </>
  );
}
