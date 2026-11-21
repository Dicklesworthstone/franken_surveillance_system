"use client";
import { Pause, Play } from "lucide-react";
import { stamp } from "../../lib/watch/take";
import { usePlaying } from "./clock";

/** Named moments, alternating above and below the lanes so the labels have room. */
function Marks({ markers, t, clock, pct, row }) {
  return (
    <ol className={"timeline__marks" + (row ? " timeline__marks--below" : "")}>
      {markers.map(
        (m, i) =>
          i % 2 === row && (
            <li key={m.id} style={{ left: pct(m.t) }}>
              <button type="button" onClick={() => clock.seek(m.t)} className={m.t <= t + 0.01 ? "is-past" : ""}>
                {m.label}
              </button>
            </li>
          ),
      )}
    </ol>
  );
}

/**
 * Who saw whom, and when. One lane per camera; a bar wherever that camera had
 * a person in view. The gaps between bars are the stretches where coverage
 * handed over, or where nobody could see.
 */
export default function Timeline({ summary, spans, markers, belief, clock, frame }) {
  const playing = usePlaying(clock);
  const t = frame / summary.fps;
  const pct = (s) => (s / summary.duration) * 100 + "%";
  const current = markers.filter((m) => m.t <= t + 0.01).at(-1);
  const held = belief.filter((step) => step.from <= t + 0.01).at(-1);
  return (
    <div className="timeline">
      <div className="timeline__controls">
        <button
          type="button"
          className="timeline__play"
          onClick={() => (playing ? clock.pause() : clock.play())}
          aria-label={playing ? "Pause" : "Play"}
        >
          {playing ? <Pause size={20} aria-hidden="true" /> : <Play size={20} aria-hidden="true" />}
        </button>
        <p className="timeline__now">
          <span className="data">{stamp(summary, t)}</span>
          <span className="timeline__beat">{current ? current.label : "Quiet"}</span>
        </p>
        <p className="timeline__case">
          {!held ? (
            <span>No assessment at this time.</span>
          ) : held === belief[0] ? (
            <span>No track confirmed yet.</span>
          ) : (
            <>
              <strong className="num">{(held.chance * 100).toFixed(held.chance > 0.995 ? 1 : 0)}%</strong>
              <span>that a stranger is on the property</span>
            </>
          )}
        </p>
      </div>
      <div className="timeline__chart" style={{ "--at": t / summary.duration }}>
        <Marks markers={markers} t={t} clock={clock} pct={pct} row={0} />
        <div className="timeline__lanes">
          <div className="timeline__lane timeline__lane--case">
            <span className="timeline__name">Assessment</span>
            <span className="timeline__track">
              {belief.map((step) => (
                <i
                  key={step.from}
                  className="timeline__level"
                  title={step.latest}
                  style={{ left: pct(step.from), width: pct(step.to - step.from), height: `${Math.max(step.chance * 100, 4)}%` }}
                />
              ))}
            </span>
          </div>
          {summary.cameras.map((cam) => (
            <div className="timeline__lane" key={cam.id}>
              <span className="timeline__name">{cam.name}</span>
              <span className="timeline__track">
                {spans
                  .filter((s) => s.camera === cam.id)
                  .map((s, i) => (
                    <i
                      key={i}
                      className={"timeline__bar timeline__bar--" + s.actor}
                      style={{ left: pct(s.from), width: pct(s.to - s.from) }}
                    />
                  ))}
              </span>
            </div>
          ))}
          <span className="timeline__head" aria-hidden="true" />
          <input
            className="timeline__slider"
            type="range"
            min="0"
            max={summary.duration}
            step="0.25"
            value={t}
            onChange={(e) => {
              clock.pause();
              clock.seek(+e.target.value);
            }}
            aria-label="Time in the recording"
            aria-valuetext={stamp(summary, t)}
          />
        </div>
        <Marks markers={markers} t={t} clock={clock} pct={pct} row={1} />
        <div className="timeline__scale data" aria-hidden="true">
          <span>{stamp(summary, 0)}</span>
          <span>{stamp(summary, summary.duration / 2)}</span>
          <span>{stamp(summary, summary.duration)}</span>
        </div>
      </div>
    </div>
  );
}
