"use client";
import dynamic from "next/dynamic";
import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDown,
  ArrowUpRight,
  Box,
  Camera,
  DraftingCompass,
  Film,
  Layers3,
  Maximize2,
  Orbit,
  Package,
  Pause,
  PawPrint,
  Play,
  RotateCcw,
  ScanEye,
  ScanLine,
  Shield,
  X,
} from "lucide-react";
import CameraFilm from "./CameraFilm";
import EvidenceReplay from "./EvidenceReplay";
import PairInspector from "./PairInspector";
import FieldHero from "./FieldHero";
import EvidenceDesk from "./EvidenceDesk";
import AgentDesk, { Sources } from "./AgentDesk";
import {
  cameras,
  cameraAsset,
  cases,
  DURATION,
  recording,
  stamp,
  subjectAt,
} from "../lib/scenarios";
const Viewport = dynamic(() => import("./Viewport"), {
  ssr: false,
  loading: () => (
    <div
      className="viewport-surface"
      style={{ backgroundImage: "url(/films/property.jpg)" }}
    />
  ),
});
const SOURCE =
  "https://github.com/Dicklesworthstone/franken_surveillance_system";
const icons = [Package, PawPrint, Shield];
function Logo() {
  return (
    <a className="logo" href="#top">
      <span className="logo-mark">
        <ScanEye size={26} />
      </span>
      <span>
        Franken<span className="logo-light">Surveillance</span>
      </span>
    </a>
  );
}
function FilmCard({ s, open }) {
  return (
    <button className="film-card" onClick={() => open(s)}>
      <div className="thumb">
        <img
          src={"/films/" + s.id + ".jpg"}
          alt={s.subject + " in the simulated " + s.camera + " camera"}
        />
        <span className="film-play">
          <Play size={17} fill="currentColor" />
        </span>
        <span className="duration">00:12</span>
      </div>
      <div className="film-label">
        <span>
          CAM 0{cameras.findIndex((c) => c.id === s.camera) + 1} /{" "}
          {s.camera.toUpperCase()}
        </span>
        <ArrowUpRight size={16} />
      </div>
      <h3>{s.title}</h3>
    </button>
  );
}
function FilmDialog({ film, close }) {
  const ref = useRef(null);
  const [camera, setCamera] = useState(film.camera);
  const asset = cameraAsset(film, camera);
  useEffect(() => {
    const d = ref.current;
    d.showModal();
    return () => d.close();
  }, []);
  return (
    <dialog
      ref={ref}
      onCancel={close}
      onClick={(e) => {
        if (e.target === ref.current) close();
      }}
      aria-label={film.title}
    >
      <div className="dialog-top">
        <div>
          <span className="eyebrow">VIRTUAL CAMERA FILM</span>
          <h2>{film.title}</h2>
        </div>
        <button className="icon" aria-label="Close film" onClick={close}>
          <X />
        </button>
      </div>
      <div className="archive-camera">
        <label htmlFor="archive-camera">Camera</label>
        <select
          id="archive-camera"
          value={camera}
          onChange={(e) => setCamera(e.target.value)}
        >
          {cameras.map((c) => (
            <option key={c.id} value={c.id}>
              {c.label}
            </option>
          ))}
        </select>
      </div>
      <CameraFilm
        key={asset}
        asset={asset}
        controls
        autoPlay
        aria-label={camera + " camera film"}
      />
      <p>
        {film.detail} This film uses the same camera and motion as the
        interactive scene.
      </p>
      <div className="dialog-links">
        <a href={"/films/" + asset + ".mp4"} download>
          Download MP4 <ArrowDown size={14} />
        </a>
        <a href={"/evidence/" + asset + ".json"}>
          Native FSS report <ArrowUpRight size={14} />
        </a>
      </div>
    </dialog>
  );
}
function useEvidence(file) {
  const [result, setResult] = useState(null);
  useEffect(() => {
    if (!file) return;
    const request = new AbortController();
    fetch("/evidence/" + file, { signal: request.signal })
      .then((response) => {
        if (!response.ok) throw Error("Evidence request failed");
        return response.json();
      })
      .then((data) => {
        if (!request.signal.aborted) setResult({ file, data, status: "ready" });
      })
      .catch(() => {
        if (!request.signal.aborted) setResult({ file, status: "error" });
      });
    return () => request.abort();
  }, [file]);
  return result && result.file === file ? result : { status: "loading" };
}
export default function Observatory({ field }) {
  const [mode, setMode] = useState("scene"),
    [peerId, setPeer] = useState(null);
  const [selected, select] = useState(0),
    [time, seek] = useState(3.2),
    [playing, play] = useState(false),
    [view, setView] = useState("overview"),
    [cones, setCones] = useState(true),
    [survey, setSurvey] = useState(false),
    [reset, setReset] = useState(0),
    [film, openFilm] = useState(null),
    [expanded, expand] = useState(false);
  const s = cases[selected],
    actor = subjectAt(s, time),
    clock = useRef(time);
  const goto = (t) => {
    clock.current = t;
    seek(t);
  };
  const change = (i) => {
    select(i);
    setView("overview");
    setPeer(null);
    goto(0);
    play(false);
  };
  useEffect(() => {
    if (!playing) return;
    let last = null,
      id;
    const tick = (now) => {
      if (last !== null && !document.hidden)
        clock.current = Math.min(
          DURATION,
          clock.current + Math.min(0.15, (now - last) / 1000),
        );
      last = now;
      seek(clock.current);
      if (clock.current >= DURATION) {
        play(false);
        return;
      }
      id = requestAnimationFrame(tick);
    };
    id = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(id);
  }, [playing]);
  useEffect(() => {
    const key = (e) => {
      if (e.key === "Escape") expand(false);
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, []);
  const toggle = () => {
    if (clock.current >= DURATION) goto(0);
    play(!playing);
  };
  const camera = cameras.find(
    (c) => c.id === (view === "overview" ? s.camera : view),
  );
  const peer =
    cameras.find((c) => c.id === peerId && c.id !== camera.id) ??
    cameras.find((c) => c.id === (camera.id === "porch" ? "drive" : "porch"));
  const asset = cameraAsset(s, camera.id),
    peerAsset = cameraAsset(s, peer.id);
  const evidenceMode = mode !== "scene",
    comparing = mode === "compare";
  const proof = useEvidence("index.json");
  const native = proof.data?.[s.id]?.views[camera.id];
  const primaryReport = useEvidence(mode === "native" ? asset + ".json" : null);
  const pairFile = s.id + "-" + [camera.id, peer.id].sort().join("-") + ".json";
  const pairReport = useEvidence(comparing ? pairFile : null);
  const measured = primaryReport.data,
    cascade = measured?.detector_cascade;
  const matched =
    measured?.candidates.flatMap((c) =>
      c.class_evidence
        .filter((e) => e.outcome === "associated")
        .map((e) => ({ ...e, track: c.track_id })),
    ) || [];
  const timeline = [
    ...(measured?.candidates ?? []).map((c) => ({
      key: c.candidate_id,
      segment: c.entry_segment,
      label: "Track " + c.track_id + " enters image zone",
      kind: "track",
    })),
    ...matched.map((e) => ({
      key: e.evidence_digest,
      segment: e.segment,
      label: "YOLOX · " + e.label + " on T" + e.track,
      kind: "model",
    })),
  ].sort((a, b) => a.segment - b.segment);
  const openView = (v) => {
    if (v === "overview") setMode("scene");
    if (v === peer.id) setPeer(camera.id);
    setView(v);
  };
  const phaseTimes = native?.visibility || [];
  const sight = phaseTimes.filter((item) => item.time <= time).at(-1);
  const at = (val) => {
    play(false);
    goto(val);
  };
  const firstSight = phaseTimes.find((p) => p.visible)?.time,
    entry = phaseTimes.find((p) => p.inZone)?.time;
  return (
    <>
      <header>
        <div className="wrap nav">
          <Logo />
          <nav>
            <a className="active" href="#simulator">
              Simulator
            </a>
            <a href="#casebook">Evidence desk</a>
            <a className="desktop-link" href="#agent-console">
              Agent console
            </a>
            <a
              className="source"
              href={SOURCE}
              target="_blank"
              rel="noreferrer"
            >
              Source <ArrowUpRight size={15} />
            </a>
          </nav>
        </div>
      </header>
      <main className="wrap" id="top">
        <FieldHero />
        <section
          id="simulator"
          className="simulator"
          aria-label="Property simulator"
        >
          <div className="chapter-heading">
            <div>
              <span className="section-kicker">INTERACTIVE DIGITAL TWIN</span>
              <h2>Inside Juniper House.</h2>
            </div>
            <p>
              Orbit the house, choose a camera, or switch to survey mode to see
              measured ground entries appear as the encounter unfolds.
            </p>
          </div>
          <div className="scenario-bar">
            <span className="micro">SCENARIO</span>
            <div className="scenario-tabs">
              {cases.map((c, i) => {
                const Icon = icons[i];
                return (
                  <button
                    key={c.id}
                    aria-pressed={selected === i}
                    onClick={() => change(i)}
                  >
                    <Icon size={16} />
                    {c.short}
                  </button>
                );
              })}
            </div>
          </div>
          <div className="console-grid">
            <article className={"viewer" + (expanded ? " expanded" : "")}>
              <div className="viewer-top">
                <span>
                  <span className="signal" />{" "}
                  {evidenceMode
                    ? comparing
                      ? "SYNCHRONIZED CAMERA REPLAY"
                      : camera.label.toUpperCase() + " · FSS REPLAY"
                    : view === "overview"
                      ? "PROPERTY VIEW"
                      : camera.label.toUpperCase() + " CAMERA"}
                </span>
                <div>
                  <button
                    className={
                      "survey-button" +
                      (survey && view === "overview" && !evidenceMode
                        ? " lit"
                        : "")
                    }
                    aria-pressed={
                      survey && view === "overview" && !evidenceMode
                    }
                    onClick={() => {
                      const active =
                        survey && view === "overview" && !evidenceMode;
                      openView("overview");
                      setSurvey(!active);
                    }}
                  >
                    <DraftingCompass size={15} /> Survey mode
                  </button>
                  <button
                    className={"icon" + (cones ? " lit" : "")}
                    disabled={evidenceMode || view !== "overview"}
                    aria-label="Toggle camera fields of view"
                    aria-pressed={cones}
                    title="Camera fields of view"
                    onClick={() => setCones(!cones)}
                  >
                    <Layers3 size={16} />
                  </button>
                  <button
                    className="icon"
                    aria-label="Reset orbit"
                    title="Reset orbit"
                    onClick={() => {
                      openView("overview");
                      setReset((x) => x + 1);
                    }}
                  >
                    <RotateCcw size={15} />
                  </button>
                  <button
                    className="icon"
                    title="Expand viewport"
                    aria-label={
                      expanded ? "Close expanded viewport" : "Expand viewport"
                    }
                    aria-pressed={expanded}
                    onClick={() => expand(!expanded)}
                  >
                    {expanded ? <X size={16} /> : <Maximize2 size={15} />}
                  </button>
                </div>
              </div>
              <div className="stage">
                {evidenceMode ? (
                  <div className={comparing ? "compare-feeds" : "single-feed"}>
                    <div>
                      <EvidenceReplay
                        key={asset}
                        asset={asset}
                        label={camera.label}
                        time={time}
                        report={measured}
                        entries={
                          comparing
                            ? (pairReport.data?.entries.filter(
                                (e) => e.camera === camera.id,
                              ) ?? [])
                            : undefined
                        }
                      />
                    </div>
                    {comparing && (
                      <div>
                        <EvidenceReplay
                          key={peerAsset}
                          asset={peerAsset}
                          label={peer.label}
                          time={time}
                          entries={
                            pairReport.data?.entries.filter(
                              (e) => e.camera === peer.id,
                            ) ?? []
                          }
                        />
                      </div>
                    )}
                  </div>
                ) : (
                  <Viewport
                    scenario={s}
                    time={time}
                    view={view}
                    cones={cones}
                    reset={reset}
                    entries={
                      survey && view === "overview" ? field.survey[s.id] : null
                    }
                  />
                )}
                {!evidenceMode && (
                  <span className="scene-label">
                    <span />{" "}
                    {view === "overview"
                      ? survey
                        ? "GROUND SURVEY"
                        : "SPATIAL MODEL"
                      : "OPTICAL FEED"}
                  </span>
                )}
                {!evidenceMode && view === "overview" && survey && (
                  <span className="survey-key">
                    <i /> Porch <i /> Driveway ·{" "}
                    {
                      field.survey[s.id].filter(
                        (e) => e.segment / recording.nativeFps <= time,
                      ).length
                    }{" "}
                    measured entries
                  </span>
                )}
                {!evidenceMode && view === "overview" && (
                  <span className="orbit-hint">
                    <Orbit size={13} /> Drag to orbit
                  </span>
                )}
              </div>
              <div className="views" aria-label="Viewpoint">
                {[{ id: "overview", label: "3D overview" }, ...cameras].map(
                  (c) => (
                    <button
                      key={c.id}
                      aria-pressed={
                        evidenceMode ? camera.id === c.id : view === c.id
                      }
                      onClick={() => openView(c.id)}
                    >
                      {c.id === "overview" ? (
                        <Box size={14} />
                      ) : (
                        <Camera size={14} />
                      )}{" "}
                      {c.label}
                    </button>
                  ),
                )}
                <button
                  aria-pressed={mode === "native"}
                  onClick={() => {
                    setView(camera.id);
                    setMode(mode === "native" ? "scene" : "native");
                  }}
                >
                  <ScanLine size={14} /> FSS replay
                </button>
                <button
                  aria-pressed={comparing}
                  onClick={() => {
                    setView(camera.id);
                    setMode(comparing ? "native" : "compare");
                  }}
                >
                  <Layers3 size={14} /> Compare cameras
                </button>
              </div>
              <div className="transport">
                <button
                  onClick={toggle}
                  aria-label={playing ? "Pause simulation" : "Play simulation"}
                >
                  {playing ? (
                    <Pause size={15} fill="currentColor" />
                  ) : (
                    <Play size={15} fill="currentColor" />
                  )}
                </button>
                <span>{stamp(time, true)}</span>
                <input
                  type="range"
                  aria-label="Simulation time"
                  min="0"
                  max={DURATION}
                  step=".05"
                  value={time}
                  style={{ "--progress": (time / DURATION) * 100 + "%" }}
                  onChange={(e) => at(Number(e.target.value))}
                />
                <span className="muted">{stamp(DURATION)}</span>
              </div>
            </article>
            <aside className="inspector">
              <div className="inspector-top">
                <span className="micro">
                  <Activity size={15} /> EVENT INSPECTOR
                </span>
                <span className="case-id">0{selected + 1} / 03</span>
              </div>
              <h2>
                {s.title}
                <span>.</span>
              </h2>
              <p>{s.detail}</p>
              {comparing ? (
                <>
                  <PairInspector
                    camera={camera}
                    peer={peer}
                    setPeer={setPeer}
                    report={pairReport.data}
                    status={pairReport.status}
                    at={at}
                    time={time}
                  />
                </>
              ) : evidenceMode ? (
                <>
                  <div className="facts">
                    <div>
                      <span>Decoded frames</span>
                      <strong>{measured?.frames_decoded ?? "…"}</strong>
                    </div>
                    <div>
                      <span>YOLOX-Nano inferences</span>
                      <strong>{cascade?.inference_count ?? "…"}</strong>
                    </div>
                    <div>
                      <span>Model class by {stamp(time, true)}</span>
                      <strong>
                        {matched
                          .filter(
                            (m) => m.segment / recording.nativeFps <= time,
                          )
                          .map((m) => m.label)
                          .filter((v, i, a) => a.indexOf(v) === i)
                          .join(", ") || (measured ? "None" : "…")}
                      </strong>
                    </div>
                  </div>
                  <div className="trace native-trace">
                    <div className="micro">MEASURED EVENTS</div>
                    {!measured ? (
                      <p role="status">
                        {primaryReport.status === "error"
                          ? "Camera report unavailable."
                          : "Loading camera report…"}
                      </p>
                    ) : measured.candidates.length === 0 ? (
                      <p>
                        No confirmed track entered this image zone. The subject
                        may still be present.
                      </p>
                    ) : (
                      timeline.map((entry) => {
                        const t = entry.segment / recording.nativeFps;
                        return (
                          <button
                            key={entry.key}
                            data-observation={entry.kind}
                            data-segment={entry.segment}
                            className={t <= time ? "reached" : ""}
                            onClick={() => at(t)}
                          >
                            <span className="trace-dot" />
                            <span>{entry.label}</span>
                            <time>{stamp(t, true)}</time>
                          </button>
                        );
                      })
                    )}
                  </div>
                </>
              ) : survey && view === "overview" ? (
                <>
                  <div className="facts">
                    <div>
                      <span>Surveyed zone</span>
                      <strong>{s.zone}</strong>
                    </div>
                    <div>
                      <span>Coordinates</span>
                      <strong>Local ground plane · metres</strong>
                    </div>
                  </div>
                  <div className="trace native-trace">
                    <div className="micro">MEASURED GROUND ENTRIES</div>
                    {field.survey[s.id].length === 0 ? (
                      <p>
                        Neither camera produced a measured ground entry. The
                        fixture subject can still be present.
                      </p>
                    ) : (
                      field.survey[s.id]
                        .toSorted((a, b) => a.segment - b.segment)
                        .map((e) => (
                          <button
                            key={
                              e.camera +
                              "-" +
                              e.segment +
                              "-" +
                              e.ground.join(",")
                            }
                            onClick={() => at(e.segment / recording.nativeFps)}
                            className={
                              e.segment / recording.nativeFps <= time
                                ? "reached"
                                : ""
                            }
                          >
                            <span className="trace-dot" />
                            <span>
                              {e.camera === "drive" ? "Driveway" : "Porch"} ·{" "}
                              {e.ground.map((n) => n.toFixed(2)).join(", ")} m
                            </span>
                            <time>
                              {stamp(e.segment / recording.nativeFps, true)}
                            </time>
                          </button>
                        ))
                    )}
                  </div>
                </>
              ) : (
                <>
                  <div className="facts">
                    <div>
                      <span>Fixture subject</span>
                      <strong>{s.subject}</strong>
                    </div>
                    <div>
                      <span>Selected camera</span>
                      <button onClick={() => openView(camera.id)}>
                        {camera.label} <ArrowUpRight size={13} />
                      </button>
                    </div>
                    <div>
                      <span>Subject center in this view</span>
                      <strong>
                        {sight
                          ? sight.visible
                            ? "Visible"
                            : "Out of sight"
                          : proof.status === "error"
                            ? "Unavailable"
                            : "…"}
                      </strong>
                    </div>
                    <div>
                      <span>Zone membership</span>
                      <strong>
                        <i className={actor.inZone ? "on" : ""} />
                        {actor.inZone ? "Inside" : "Outside"}
                      </strong>
                    </div>
                  </div>
                  <div className="trace">
                    <div className="micro">SIMULATED TIMELINE</div>
                    {[
                      [0, "Scene begins"],
                      [firstSight, "Center first visible"],
                      [entry, s.action],
                    ].map(([t, label], i) => (
                      <button
                        key={label}
                        disabled={t == null}
                        onClick={() => at(t)}
                        className={t != null && time >= t ? "reached" : ""}
                      >
                        <span className="trace-dot" />
                        <span>{label}</span>
                        <time>{t == null ? "—" : stamp(t)}</time>
                      </button>
                    ))}
                  </div>
                </>
              )}
              <a
                className="proof-link"
                href={
                  "/evidence/" +
                  (comparing
                    ? pairFile
                    : !evidenceMode && survey && view === "overview"
                      ? s.id + "-drive-porch.json"
                      : asset + ".json")
                }
              >
                <ScanLine size={16} />
                {comparing || (!evidenceMode && survey && view === "overview")
                  ? "Open native pair report"
                  : native
                    ? native.candidates +
                      " native event candidate" +
                      (native.candidates === 1 ? "" : "s")
                    : "Native FSS report"}
                <ArrowUpRight size={14} />
              </a>
            </aside>
          </div>
        </section>
        <EvidenceDesk
          field={field}
          onSurvey={() => {
            change(0);
            openView("overview");
            setSurvey(true);
            at(
              Math.max(...field.association.marks.map((m) => m.segment)) /
                recording.nativeFps,
            );
            document.querySelector("#simulator").scrollIntoView();
          }}
        />
        <AgentDesk data={field.agent} />
        <Sources />
        <section id="films" className="films-section">
          <div className="section-head">
            <div>
              <div className="eyebrow">
                <Film size={14} /> CAMERA RECORDINGS
              </div>
              <h2>
                Film archive<span>.</span>
              </h2>
            </div>
            <span className="archive-count">
              09 FILMS <span>/</span> MP4
            </span>
          </div>
          <div className="films-grid">
            {cases.map((c, i) => (
              <FilmCard
                key={c.id}
                s={c}
                i={i}
                open={(f) => {
                  play(false);
                  openFilm(f);
                }}
              />
            ))}
          </div>
        </section>
        <section className="method">
          <div className="micro">
            <ScanEye size={16} /> HOW TO READ THE DEMO
          </div>
          <div>
            <h2>Scene labels and measured evidence</h2>
            <p>
              The simulator supplies each actor’s identity and path. Its overlay
              tests camera visibility and zone membership. The linked Rust
              reports come from importing the rendered camera frames into FSS
              and running its foreground tracker and digest-pinned YOLOX-Nano
              detector on selected frames. FSS replay draws the measured track
              and model boxes at their source frame times. Compare cameras runs
              the same recordings through the native ground-zone association and
              shows the disposition of each entry. A motion candidate alone
              cannot identify a courier, a raccoon, or someone’s intent.
            </p>
            <a
              href={SOURCE + "/tree/main/website"}
              target="_blank"
              rel="noreferrer"
            >
              Explore the implementation <ArrowUpRight size={15} />
            </a>
          </div>
        </section>
      </main>
      <footer>
        <div className="wrap">
          <Logo />
          <a href="#top">Back to top ↑</a>
        </div>
      </footer>
      {film && <FilmDialog film={film} close={() => openFilm(null)} />}
    </>
  );
}
