"use client";
import { useState } from "react";
export default function PosterRoom({ prints }) {
  const [format, setFormat] = useState("og");
  return (
    <article className="poster-room">
      <div className="stereo-heading">
        <div>
          <span className="court-kicker">Juniper House / Poster room</span>
          <h2>
            Exhibit <em>posters.</em>
          </h2>
        </div>
        <p>Download the cover for any exhibit, or open the scene behind it.</p>
      </div>
      <div className="stereo-moments" role="group" aria-label="Poster format">
        {[
          ["og", "Open Graph", "1200 × 630"],
          ["x", "X", "1200 × 600"],
        ].map(([k, label, size]) => (
          <button
            key={k}
            aria-pressed={format === k}
            onClick={() => setFormat(k)}
          >
            {label} <small>{size}</small>
          </button>
        ))}
      </div>
      <div className="poster-grid">
        {prints.map((p, i) => (
          <figure key={p.path}>
            <a href={p[format]} aria-label={"View " + p.title + " poster"}>
              <img
                src={p[format]}
                width="1200"
                height={format === "og" ? 630 : 600}
                alt={p.alt}
                loading={i > 2 ? "lazy" : "eager"}
              />
            </a>
            <figcaption>
              <a href={p.path}>{p.title} ↗</a>
              <a
                href={p[format]}
                download={p.slug + "-" + format + ".png"}
                aria-label={"Download " + p.title + " PNG"}
              >
                Download PNG
              </a>
            </figcaption>
          </figure>
        ))}
      </div>
    </article>
  );
}
