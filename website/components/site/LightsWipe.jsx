"use client";
import { useState } from "react";
import FilmFrame from "./FilmFrame";

/** One camera at two moments, with a divider to drag between them. */
export default function LightsWipe({ camera, before, after, labels }) {
  const [at, setAt] = useState(46);
  return (
    <div className="wipe" style={{ "--at": at + "%" }}>
      <div className="wipe__before">
        <FilmFrame camera={camera} t={before} caption={labels[0]} />
      </div>
      <div className="wipe__after">
        <FilmFrame camera={camera} t={after} caption={labels[1]} />
      </div>
      <span className="wipe__line" aria-hidden="true">
        <i />
      </span>
      <input
        className="wipe__range"
        type="range"
        min="0"
        max="100"
        value={at}
        onChange={(event) => setAt(+event.target.value)}
        aria-label="Divider between before and after the lights"
        aria-valuetext={`${at}% of the picture shows the moment before the lights`}
      />
    </div>
  );
}
