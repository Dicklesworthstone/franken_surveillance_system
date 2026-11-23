"use client";
import { ChevronLeft, ChevronRight, Pause, Play } from "lucide-react";
import { stamp } from "../../lib/watch/take";
import { usePlaying } from "./clock";

/** Named moments, alternating above and below the lanes so the labels have room. */
function Marks({ markers, t, clock, pct, duration, row }) {
  return (
    <ol className={"timeline__marks" + (row ? " timeline__marks--below" : "")}>
      {markers.map(
        (m, i) =>
          i % 2 === row && (
            <li
              key={m.id}
              className={m.t / duration > 0.8 ? "is-end" : ""}
              style={{ left: pct(m.t) }}
            >
              <button
                type="button"
                onClick={() => clock.seek(m.t)}
                className={m.t <= t + 0.01 ? "is-past" : ""}
                title={`${m.label} (${m.clock})`}
              >
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
  const prevMarker = markers.filter((m) => m.t < t - 0.15).at(-1);
  const nextMarker = markers.find((m) => m.t > t + 0.15);
  const held = belief.filter((step) => step.from <= t + 0.01).at(-1);
  return (
    <div className="timeline">
      <div className="timeline__controls">
        <div className="timeline__transport">
          <button
            type="button"
            className="timeline__play"
            onClick={() => (playing ? clock.pause() : clock.play())}
            aria-label={playing ? "Pause" : "Play"}
          >
            {playing ? <Pause size={20} aria-hidden="true" /> : <Play size={20} aria-hidden="true" />}
          </button>
          <div className="timeline__steppers">
            <button
              type="button"
              className="timeline__step"
              aria-label="Previous moment"
              disabled={!prevMarker}
              onClick={() => {
                clock.pause();
                if (prevMarker) clock.seek(prevMarker.t);
              }}
              title={prevMarker ? `Jump back to ${prevMarker.label}` : "At start"}
            >
              <ChevronLeft size={16} aria-hidden="true" />
            </button>
            <button
              type="button"
              className="timeline__step"
              aria-label="Next moment"
              disabled={!nextMarker}
              onClick={() => {
                clock.pause();
                if (nextMarker) clock.seek(nextMarker.t);
              }}
              title={nextMarker ? `Jump forward to ${nextMarker.label}` : "At end"}
            >
              <ChevronRight size={16} aria-hidden="true" />
            </button>
          </div>
        </div>
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
        <Marks markers={markers} t={t} clock={clock} pct={pct} duration={summary.duration} row={0} />
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
        <Marks markers={markers} t={t} clock={clock} pct={pct} duration={summary.duration} row={1} />
        <div className="timeline__scale data" aria-hidden="true">
          <span>{stamp(summary, 0)}</span>
          <span>{stamp(summary, summary.duration / 2)}</span>
          <span>{stamp(summary, summary.duration)}</span>
        </div>
      </div>
    </div>
  );
}
