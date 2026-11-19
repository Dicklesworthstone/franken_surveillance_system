"use client";
import { useEffect, useImperativeHandle, useRef, useState } from "react";

// These small, same-origin fixtures must be seekable even on a static host
// that ignores byte ranges. Release the clip whenever the view changes.
export default function CameraFilm({
  asset,
  directory = "films",
  active = true,
  videoRef,
  target,
  onDisplayed,
  ...props
}) {
  const ref = useRef(null);
  useImperativeHandle(videoRef, () => ref.current, []);
  const [source, setSource] = useState(null);
  const [failed, setFailed] = useState(false);
  const path = "/" + directory + "/" + asset + ".mp4";
  useEffect(() => {
    if (!active) return;
    const request = new AbortController();
    let url;
    fetch(path, { signal: request.signal })
      .then((response) => {
        if (!response.ok) throw Error("Film unavailable");
        return response.blob();
      })
      .then((blob) => {
        if (request.signal.aborted) return;
        url = URL.createObjectURL(blob);
        setSource(url);
      })
      .catch(() => {
        if (!request.signal.aborted) setFailed(true);
      });
    return () => {
      request.abort();
      if (url) URL.revokeObjectURL(url);
    };
  }, [path, active]);
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
        poster={"/" + directory + "/" + asset + ".jpg"}
        muted
        playsInline
        preload="auto"
        onError={() => setFailed(true)}
        {...props}
      />
      {failed && (
        <span className="fallback" role="status">
          Camera film unavailable
        </span>
      )}
    </>
  );
}
