"use client";
import { useState } from "react";
import { ArrowDownRight, ArrowUpRight, Play, RotateCcw } from "lucide-react";
const films = [
  {
    name: "The bounce pass",
    section: "Courtyard study",
    image: "/court/cover.jpg",
    thumbnail: "/court/wide.jpg",
    film: "/court/wide.mp4",
    url: "/exhibits/courtyard/",
    cta: "Open the courtyard",
    description:
      "Two neighbors, one ball, and two cameras. Change the pass and compare the evidence.",
    seconds: 4,
  },
  {
    name:"Two rays. One ball.", section:"Stereo bench", image:"/stereo/sightlines.jpg", thumbnail:"/stereo/sightlines.jpg",
    film:"/stereo/sightlines.mp4",url:"/exhibits/stereo-bench/",cta:"Open the stereo bench",
    description:"Mark the basketball in both frames and see where the lines of sight meet.",seconds:4,
  },
  {
    name: "The parcel drop",
    section: "Motion lab",
    image: "/motion/pose.jpg",
    thumbnail: "/motion/pose.jpg",
    film: "/motion/studio.mp4",
    url: "/exhibits/motion-study/",
    cta: "Enter the motion lab",
    description:
      "Set the courier’s stride, release height and parcel bounce. Trace one delivery into its original frames.",
    seconds: 9,
  },
  {
    name: "The night garden",
    section: "Camera wall",
    image: "/wall/wildlife.jpg",
    thumbnail: "/films/wildlife.jpg",
    film: "/wall/wildlife.mp4",
    url: "/exhibits/camera-wall/?case=wildlife",
    cta: "Open the camera wall",
    description:
      "Follow a raccoon through three fixed views and a flyover. Inspect the tracker’s record of its visit.",
    seconds: 12,
  },
];
export default function FieldHero() {
  const [index, setIndex] = useState(0),
    [show, setShow] = useState(false),
    [failed, setFailed] = useState(false);
  const film = films[index];
  function choose(i) {
    setIndex(i);
    setShow(false);
    setFailed(false);
  }
  return (
    <section className="field-cover" aria-labelledby="field-title">
      <div className="cover-spread">
        <div className="cover-intro">
          <span className="cover-kicker">Juniper House / Field guide</span>
          <h1 id="field-title">
            One home.
            <br />
            <em>Many views.</em>
          </h1>
          <p>
            Follow a person across a property, compare what each camera saw, and
            open the evidence behind an agent’s decision.
          </p>
          <a className="cover-enter" href={film.url}>
            {film.cta}
            <ArrowUpRight size={18} />
          </a>
          <a className="cover-record" href="#casebook">
            Trace a recorded event <ArrowDownRight size={15} />
          </a>
        </div>
        <figure className="cover-figure">
          <div className="cover-screen">
            {show && !failed ? (
              <video
                key={film.film}
                autoPlay
                playsInline
                muted
                controls
                aria-label={film.name + " reference film"}
                src={film.film}
                onError={() => setFailed(true)}
              />
            ) : (
              <>
                <img
                  src={film.image}
                  className="hero-art"
                  width="1536"
                  height="960"
                  alt={film.name + " rendered reference scene"}
                  fetchPriority="high"
                />
                <button
                  className="cover-play"
                  onClick={() => {
                    setFailed(false);
                    setShow(true);
                  }}
                  aria-label={"Play " + film.name}
                >
                  <Play size={18} fill="currentColor" />
                  Play film
                </button>
              </>
            )}
            <span className="cover-film-id">
              {film.section} / {film.seconds} s
            </span>
          </div>
          <figcaption>
            <div>
              <h2>{film.name}</h2>
              <p>{film.description}</p>
            </div>
            {show && (
              <button
                onClick={() => {
                  setShow(false);
                  setFailed(false);
                }}
                aria-label="Return to film still"
              >
                <RotateCcw size={17} />
              </button>
            )}
          </figcaption>
          {failed && <a href={film.film}>Download the reference film</a>}
        </figure>
      </div>
      <div
        className="cover-index"
        role="group"
        aria-label="Choose a field film"
      >
        {films.map((f, i) => (
          <button
            key={f.name}
            onClick={() => choose(i)}
            aria-pressed={i === index}
          >
            <img src={f.thumbnail} width="85" height="57" alt="" />
            <span>
              <small>{f.section}</small>
              <b>{f.name}</b>
            </span>
            <Play size={15} />
          </button>
        ))}
      </div>
      <nav className="cover-contents" aria-label="Explore the field guide">
        <a href="#simulator">Digital twin ↘</a>
        <a href="/exhibits/poster-room/">Exhibit posters ↗</a>
        <a href="#camera-wall">Camera wall ↘</a>
        <a href="#casebook">Evidence ledger ↘</a>
        <a href="#agent-console">Agent console ↘</a>
      </nav>
    </section>
  );
}
