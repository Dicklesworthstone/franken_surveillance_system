"use client";
import dynamic from "next/dynamic";
import { useEffect, useRef, useState } from "react";
import {
  Aperture,
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  ChevronDown,
  Download,
  Menu,
  Play,
  X,
} from "lucide-react";
import {
  cases,
  exhibits,
  pathFor,
  displayCamera,
} from "../../lib/night/catalog";
import CameraReview from "./CameraReview";
import CaseDesk from "./CaseDesk";
import CameraFilm from "../CameraFilm";
const EstateViewer = dynamic(() => import("./EstateViewer"), {
  ssr: false,
  loading: () => (
    <div className="twin-loading">Opening the property viewer…</div>
  ),
});
const href = (id, c) =>
  pathFor(id) + (c ? "?case=" + encodeURIComponent(c) : "");
const plate = (id, v) => "/night-media/" + id + "-" + v + ".jpg";
const navigation = [
  ["Case files", "/#case-files"],
  ["Property twin", pathFor("digital-twin")],
  ["Evidence", pathFor("event-ledger")],
  ["Agent desk", pathFor("agent-console")],
];
const archiveLinks = [
  "camera-wall",
  "camera-fusion",
  "camera-inputs",
  "field-method",
  "event-ledger",
  "belief-lab",
  "owner-response",
  "agent-console",
  "film-archive",
  "poster-room",
];
function Brand() {
  return (
    <a className="estate-brand" href="/" aria-label="Franken Surveillance home">
      <Aperture size={26} strokeWidth={1.4} />
      <span>
        Franken <span>Surveillance</span>
      </span>
    </a>
  );
}
function Masthead() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);
  return (
    <header className="estate-mast">
      <div className="frame">
        <Brand />
        <nav aria-label="Main navigation">
          {navigation.map(([name, url]) => (
            <a key={url} href={url}>
              {name}
            </a>
          ))}
          <a
            className="source-link"
            href="https://github.com/Dicklesworthstone/franken_surveillance_system"
          >
            Source <ArrowUpRight size={13} />
          </a>
        </nav>
        <button
          className="menu-toggle"
          aria-label={open ? "Close navigation" : "Open navigation"}
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          {open ? <X /> : <Menu />}
        </button>
      </div>
      {open && (
        <div className="mobile-nav">
          {navigation.map(([name, url]) => (
            <a key={url} href={url} onClick={() => setOpen(false)}>
              {name}
              <ArrowRight size={15} />
            </a>
          ))}
        </div>
      )}
    </header>
  );
}
function CaseFiles({ records }) {
  const [preview, setPreview] = useState(null);
  return (
    <section className="case-files frame" id="case-files">
      <div className="section-head">
        <div>
          <span className="ticker">Incident archive</span>
          <h2>
            Review the <em>case files.</em>
          </h2>
        </div>
        <p>
          Play a camera recording, then open its case to see what the detector
          picked up.
        </p>
      </div>
      <div className="case-cards">
        {cases.map((id) => {
          const c = records[id];
          return (
            <article key={id} className="case-card">
              <figure>
                {preview === id ? (
                  <CameraFilm
                    controls
                    autoPlay
                    muted
                    playsInline
                    autoFocus
                    aria-label={c.title + ", " + displayCamera(c.primary) + " camera recording"}
                    poster={plate(id, c.primary)}
                    filmUrl={c.views[c.primary].film}
                  />
                ) : (
                  <button
                    className="case-preview"
                    aria-label={"Play " + c.title + " camera recording"}
                    onClick={() => setPreview(id)}
                  >
                    <img
                      src={plate(id, c.primary)}
                      alt=""
                      width="720"
                      height="405"
                      loading="lazy"
                    />
                    <span className="preview-source">
                      {c.localTime} · {displayCamera(c.primary)} camera
                    </span>
                    <span className="preview-play">
                      <Play size={15} fill="currentColor" aria-hidden="true" />
                    </span>
                  </button>
                )}
              </figure>
              <h3>
                <a href={pathFor(id)}>
                  {c.title}<ArrowUpRight size={20} aria-hidden="true" />
                </a>
              </h3>
              <p>{c.description}</p>
            </article>
          );
        })}
      </div>
    </section>
  );
}
function Hero({ hero }) {
  return (
    <section className="estate-hero" aria-labelledby="estate-title">
      <img
        className="hero-photo"
        src={hero}
        alt="A lit front porch and a curved stone walk seen from across the lawn at night"
        fetchPriority="high"
        width="1920"
        height="1080"
      />
      <div className="hero-inner frame">
        <div>
          <span className="ticker hero-overline">
            <i /> Residential security demo
          </span>
          <h1 id="estate-title">
            Who’s outside
            <br />
            <em>at 02:14?</em>
          </h1>
          <p>
            A resident reports a possible intruder. The entry and porch cameras
            recorded the approach. Replay both angles and see what an agent can
            establish from the evidence.
          </p>
          <div className="hero-actions">
            <a className="gold-button" href={pathFor("after-hours")}>
              Review the incident <ArrowRight size={17} />
            </a>
            <a className="quiet-button" href={pathFor("digital-twin")}>
              Explore the 3D property <ArrowUpRight size={15} />
            </a>
          </div>
        </div>
      </div>
      <span className="hero-credit">Simulated property</span>
    </section>
  );
}
function NightBriefing({ data }) {
  const ref = useRef(null),
    [opened, open] = useState(false);
  const briefing = data.briefing;
  const films = Object.values(data.records).reduce(
    (n, c) => n + Object.keys(c.views).length,
    0,
  );
  useEffect(() => {
    const dialog = ref.current;
    if (!opened || !dialog) return;
    dialog.showModal();
    return () => {
      if (dialog.open) dialog.close();
    };
  }, [opened]);
  return (
    <section className="briefing frame" aria-label="Property camera network">
      <div className="briefing-stats">
        <a href={pathFor("digital-twin")}>
          <b>{data.estate.cameras.length}</b> mounted cameras
        </a>
        <a href={pathFor("film-archive")}>
          <b>{films}</b> camera recordings
        </a>
      </div>
      <button className="open-briefing" onClick={() => open(true)}>
        <span aria-hidden="true">▶</span> Watch the site film ·{" "}
        {briefing.seconds}s
      </button>
      {opened && (
        <dialog
          className="briefing-film"
          ref={ref}
          onClose={() => open(false)}
          aria-label="Residential security demo film"
          onClick={(e) => {
            if (e.target === ref.current) ref.current.close();
          }}
        >
          <div className="briefing-panel">
            <header>
              <span className="ticker">Three encounters on camera</span>
              <button
                autoFocus
                aria-label="Close film"
                onClick={() => ref.current.close()}
              >
                <X size={21} />
              </button>
            </header>
            <CameraFilm
              autoPlay
              controls
              playsInline
              muted
              preload="metadata"
              filmUrl={briefing.film}
              poster={data.estate.hero}
            >
              <track
                kind="captions"
                srcLang="en"
                label="English"
                src={briefing.captions}
                default
              />
            </CameraFilm>
            <footer>
              <span>Property render and original camera recordings</span>
              <a href={briefing.film} download>
                Download film ↗
              </a>
            </footer>
          </div>
        </dialog>
      )}
    </section>
  );
}
function StudyIndex({ record }) {
  const cards = [
    [
      "digital-twin",
      "The property twin",
      "Inspect the approach from each mounted camera.",
    ],
    [
      "camera-fusion",
      "Compare the cameras",
      "Compare measured observations on a common ground plan.",
    ],
    [
      "event-ledger",
      "Verify the recording",
      "Rehash a source film and inspect its native record.",
    ],
    [
      "agent-console",
      "Open the agent desk",
      "Read the case context, authority and handoff.",
    ],
  ];
  return (
    <section className="index-section frame">
      <div className="section-head">
        <div>
          <span className="ticker">System exhibits</span>
          <h2>
            From camera to <em>case file.</em>
          </h2>
        </div>
        <p>
          Follow a camera observation onto the site plan. Check the original
          recording against its ledger entry, then open the agent’s handoff to
          see which questions still need a homeowner’s attention.
        </p>
      </div>
      <div className="index-grid">
        {cards.map(([id, title, desc]) => (
          <a href={href(id, record)} key={id}>
            <ArrowUpRight />
            <h3>{title}</h3>
            <p>{desc}</p>
          </a>
        ))}
      </div>
    </section>
  );
}
function Archive({ records }) {
  return (
    <div className="archive-list">
      {cases.map((id) => (
        <section key={id}>
          <h3>{records[id].title}</h3>
          {Object.entries(records[id].views).map(([camera, v]) => (
            <a key={camera} href={v.film}>
              <img
                alt=""
                width="140"
                height="79"
                src={plate(id, camera)}
                loading="lazy"
              />
              <span>
                {displayCamera(camera)}
                <small>Original film</small>
              </span>
              <Download size={16} />
            </a>
          ))}
        </section>
      ))}
    </div>
  );
}
function EstatePhotographs({ photographs }) {
  const [album, setAlbum] = useState(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open || album) return;
    const controller = new AbortController();
    fetch("/estate/stills.json", { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw Error("Render index unavailable");
        return r.json();
      })
      .then(({ stills }) => setAlbum(stills))
      .catch(() => { if (!controller.signal.aborted) setAlbum([]); });
    return () => controller.abort();
  }, [open, album]);
  if (!photographs.length) return null;
  return (
    <section className="estate-photographs" aria-label="Architectural stills">
      <h2>House and grounds</h2>
      <div>
        {photographs.map(({ url, label }) => (
          <a
            href={url}
            key={url}
            aria-label={"Open full-size view of " + label.toLowerCase()}
          >
            <img
              src={url}
              alt={label}
              loading="lazy"
              width="1280"
              height="720"
            />
            <span>
              {label}
              <ArrowUpRight size={17} aria-hidden="true" />
            </span>
          </a>
        ))}
      </div>
      <details onToggle={(e) => setOpen(e.currentTarget.open)}>
        <summary>All architectural and camera views</summary>
        {open && !album && <p role="status">Opening the render index…</p>}
        {open && album && (
          <ul>
            {album.map(({ path, camera, width, height }) => {
              const name = camera.replace(/^(cam_|view_)/, "").replaceAll("_", " ");
              return <li key={path}><a href={path}>{name}{camera.startsWith("cam_") ? " camera" : " view"} <small>{width} × {height}</small></a></li>;
            })}
            <li><a href="/estate/stills.json">Download render index ↗</a></li>
          </ul>
        )}
      </details>
    </section>
  );
}
function Prints({ items }) {
  const [format, setFormat] = useState("og");
  return (
    <section className="print-gallery">
      <div className="format-choices">
        {[
          ["og", "Open Graph · 1200 × 630"],
          ["x", "X · 1200 × 600"],
        ].map(([id, label]) => (
          <button
            key={id}
            aria-pressed={id === format}
            onClick={() => setFormat(id)}
          >
            {label}
          </button>
        ))}
      </div>
      <div>
        {items.map((p) => (
          <figure key={p.id}>
            <img
              src={p[format]}
              width="1200"
              height={format === "og" ? 630 : 600}
              loading="lazy"
              alt={p.title + " exhibit cover"}
            />
            <figcaption>
              <a href={pathFor(p.id)}>{p.title}</a>
              <a
                download={p.id + "-" + format + ".png"}
                href={p[format]}
                aria-label={"Download " + p.title + " cover"}
              >
                <Download size={17} />
              </a>
            </figcaption>
          </figure>
        ))}
      </div>
    </section>
  );
}
function Footer() {
  return (
    <footer className="estate-footer">
      <div className="frame">
        <Brand />
        <details>
          <summary>
            Exhibit index <ChevronDown size={14} />
          </summary>
          <nav>
            {archiveLinks.map((id) => (
              <a key={id} href={pathFor(id)}>
                {exhibits[id].label}
              </a>
            ))}
          </nav>
        </details>
        <a href="/night-media/actors/CREDITS.txt">Scene credits</a>
        <a href="https://github.com/Dicklesworthstone/franken_surveillance_system">
          Source repository ↗
        </a>
      </div>
    </footer>
  );
}
export default function NightObservatory({ page, data, prints = [] }) {
  const [caseId, setCase] = useState(
    cases.includes(page) ? page : "after-hours",
  );
  const [loadedTwin, loadTwin] = useState(false),
    mode = exhibits[page].section;
  useEffect(() => {
    if (cases.includes(page)) return;
    const candidate = new URLSearchParams(location.search).get("case");
    if (cases.includes(candidate)) setCase(candidate);
  }, [page]);
  const incident = data.records[caseId],
    home = page === "home",
    hero = data.estate.hero || "/estate/hero.jpg";
  function pick(id) {
    setCase(id);
    const url = new URL(location.href);
    url.searchParams.set("case", id);
    history.replaceState(null, "", url);
  }
  const showPlayer = [
    "incident",
    "compare",
    "replay",
    "evidence",
    "inputs",
    "twin",
  ].includes(mode);
  const showDesk = [
    "incident",
    "hypotheses",
    "ledger",
    "response",
    "agent",
    "inputs",
    "evidence",
    "compare",
  ].includes(mode);
  return (
    <>
      <a className="skip-link" href="#content">
        Skip to content
      </a>
      <Masthead />
      <main id="content">
        {home ? (
          <>
            <Hero hero={hero} />
            <NightBriefing data={data} />
            <CaseFiles records={data.records} />
            <StudyIndex record="after-hours" />
          </>
        ) : (
          <div className="frame report-page">
            <nav className="breadcrumbs" aria-label="Breadcrumb">
              <a href="/">Home</a>
              <span>/</span>
              {mode === "incident" ? "Incident archive" : "Field guide"}
            </nav>
            <div className="report-heading">
              <div>
                {mode === "incident" && (
                  <span className="ticker"><i />{incident.label}</span>
                )}
                <h1>
                  {exhibits[page].title}
                  <em>.</em>
                </h1>
              </div>
              <p>{exhibits[page].description}</p>
            </div>
            {mode !== "incident" && !["archive", "prints"].includes(mode) && (
              <fieldset className="case-switch">
                <legend>Case file</legend>
                {cases.map((i) => (
                  <button
                    key={i}
                    aria-pressed={caseId === i}
                    onClick={() => pick(i)}
                  >
                    {data.records[i].title}
                  </button>
                ))}
              </fieldset>
            )}
            {mode === "twin" && (
              <>
                <EstateViewer
                  lenses={data.estate.cameras}
                  key={caseId}
                  id={caseId}
                  incident={incident}
                  seconds={incident.seconds}
                  hero={hero}
                />
                <EstatePhotographs photographs={data.estate.photographs} />
              </>
            )}
            {showPlayer && (
              <CameraReview
                estate={data.estate}
                key={caseId}
                id={caseId}
                incident={incident}
                compare={mode === "compare"}
                seconds={incident.seconds}
                fps={incident.fps}
              />
            )}
            {showDesk && (
              <CaseDesk
                key={caseId}
                incident={incident}
                id={caseId}
                mode={mode}
                modelDigest={data.modelDigest}
              />
            )}
            {mode === "archive" && <Archive records={data.records} />}
            {mode === "prints" && <Prints items={prints} />}
            {mode === "incident" && (
              <div className="context-twin">
                {loadedTwin ? (
                  <EstateViewer
                    lenses={data.estate.cameras}
                    id={caseId}
                    incident={incident}
                    seconds={incident.seconds}
                    hero={hero}
                  />
                ) : (
                  <button onClick={() => loadTwin(true)}>
                    <img src={hero} alt="" loading="lazy" />
                    <span>
                      <small>Site reconstruction</small>
                      <strong>Locate this incident in 3D</strong>
                    </span>
                    <ArrowUpRight />
                  </button>
                )}
              </div>
            )}
            <nav className="related" aria-label="Related exhibits">
              <a href={href("digital-twin", caseId)}>Property twin ↗</a>
              <a href={href("camera-fusion", caseId)}>Compare views ↗</a>
              <a href={href("event-ledger", caseId)}>Evidence ledger ↗</a>
              <a href={href("agent-console", caseId)}>Agent desk ↗</a>
            </nav>
          </div>
        )}
      </main>
      <Footer />
    </>
  );
}
