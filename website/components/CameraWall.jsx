"use client";
import { useEffect, useRef, useState } from "react";
import { StepBack, StepForward } from "lucide-react";
import {
  cases,
  cameras,
  recording,
  cameraAsset,
  DURATION,
} from "../lib/scenarios";
import SectionLink from "./SectionLink";
import CameraFilm from "./CameraFilm";

export default function CameraWall({ samples }) {
  const [s, setCase] = useState(cases[0]);
  useEffect(() => {
    const requested = new URLSearchParams(window.location.search).get("case");
    const match = cases.find((c) => c.id === requested);
    if (match) setCase(match);
  }, []);
  return (
    <section className="exhibit camera-wall" id="camera-wall">
      <div className="chapter-heading">
        <div>
          <span className="section-kicker">SYNCHRONIZED CAMERA WALL</span>
          <h2>Four views. One instant.</h2>
        </div>
        <div>
          <p>
            Watch the house from above as three cameras record the same
            encounter. Pause anywhere to compare a single moment across the
            property.
          </p>
          <SectionLink slug="camera-wall" />
        </div>
      </div>
      <div className="wall-case" aria-label="Camera wall encounter">
        {cases.map((c) => (
          <button
            key={c.id}
            aria-pressed={s.id === c.id}
            onClick={() => setCase(c)}
          >
            {c.title}
          </button>
        ))}
      </div>
      <WallFilm key={s.id} scenario={s} samples={samples[s.id]} />
    </section>
  );
}

function WallFilm({ scenario, samples }) {
  const video = useRef(null);
  const [active, setActive] = useState(false);
  const [frame, setFrame] = useState(null),
    [failed, setFailed] = useState(false);
  const total = recording.fps * DURATION;
  const source = "/wall/" + scenario.id;
  const displayTime = (time) =>
    setFrame(Math.min(total - 1, Math.floor(time * recording.fps + 1e-5)));
  const update = () => displayTime(video.current.currentTime);
  useEffect(() => {
    const v = video.current;
    if (!v.requestVideoFrameCallback) return;
    let handle;
    const presented = (_, metadata) => {
      displayTime(metadata.mediaTime);
      handle = v.requestVideoFrameCallback(presented);
    };
    handle = v.requestVideoFrameCallback(presented);
    return () => v.cancelVideoFrameCallback(handle);
  }, []);

  const step = (direction) => {
    const v = video.current;
    v.pause();
    const target = Math.max(
      0,
      Math.min(
        total - 1,
        Math.floor(v.currentTime * recording.fps + 1e-5) + direction,
      ),
    );
    v.currentTime = (target + 0.5) / recording.fps;
  };
  const stride = recording.fps / recording.nativeFps;
  const firstSample = Object.values(samples).flatMap((rows) =>
    Object.entries(rows)
      .filter(([, r]) => r.status === "inferred")
      .map(([segment]) => Number(segment)),
  );
  const jump = () => {
    const v = video.current;
    v.pause();
    v.currentTime = (Math.min(...firstSample) * stride + 0.5) / recording.fps;
  };
  return (
    <div className="wall-player">
      <div className="wall-screen">
        <CameraFilm
          videoRef={video}
          directory="wall"
          asset={scenario.id}
          active={active}
          controls={active}
          autoPlay={active}
          aria-label={scenario.title + " synchronized camera wall"}
          onLoadedData={update}
          onTimeUpdate={() => {
            if (!video.current.requestVideoFrameCallback) update();
          }}
          onSeeked={update}
          onError={() => setFailed(true)}
        />
        {!active && (
          <button className="wall-launch" onClick={() => setActive(true)}>
            Play synchronized reel
          </button>
        )}
      </div>
      {failed && (
        <p role="status">
          The camera wall film is unavailable. The individual views are linked
          below.
        </p>
      )}
      <div className="wall-tools">
        <div>
          <span className="micro">SHARED FILM CLOCK</span>
          <strong>
            {frame == null
              ? "Ready to play"
              : "Frame " + (frame + 1) + " / " + total}
          </strong>
        </div>
        <div>
          <button
            aria-label="Previous wall frame"
            onClick={() => step(-1)}
            disabled={failed || frame == null || frame === 0}
          >
            <StepBack size={16} />
          </button>
          <button
            aria-label="Next wall frame"
            onClick={() => step(1)}
            disabled={failed || frame == null || frame === total - 1}
          >
            <StepForward size={16} />
          </button>
          <a href={source + ".mp4"} download>
            Download reel
          </a>
        </div>
      </div>
      <div className="wall-readings">
        <div className="wall-reading-head">
          <strong>Detector at this frame</strong>
          {firstSample.length > 0 && (
            <button disabled={failed || frame == null} onClick={jump}>
              First inference
            </button>
          )}
        </div>
        <div className="wall-readout">
          {cameras.map((c) => {
            const sample =
              frame != null && frame % stride === 0
                ? samples[c.id][frame / stride]
                : null;
            let text = "Frame not sampled";
            if (frame == null) text = "Awaiting playback";
            else if (frame % stride === 0) {
              if (!sample) text = "Detector skipped";
              else if (sample.status === "inferred")
                text = sample.classes.join(", ") || "No model boxes";
              else text = sample.status.replaceAll("_", " ");
            }
            return (
              <div key={c.id}>
                <a
                  href={"/evidence/" + cameraAsset(scenario, c.id) + ".json"}
                  title={c.label + " native detector report"}
                >
                  {c.label}
                </a>
                <strong>{text}</strong>
              </div>
            );
          })}
        </div>
        <p>
          FSS samples the films at {recording.nativeFps} fps and runs YOLOX on
          selected samples. Each label belongs to the displayed frame.
        </p>
      </div>
      <div className="wall-sources">
        <span>Original camera films</span>
        {cameras.map((c) => (
          <a href={"/films/" + cameraAsset(scenario, c.id) + ".mp4"} key={c.id}>
            {c.label}
          </a>
        ))}
      </div>
    </div>
  );
}
