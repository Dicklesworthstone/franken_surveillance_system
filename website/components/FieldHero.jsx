import {
  ArrowDownRight,
  ArrowRight,
  Scan,
  Layers3,
  TerminalSquare,
  Database,
} from "lucide-react";
export default function FieldHero() {
  return (
    <>
      <section className="field-hero" aria-labelledby="field-title">
        <img
          src="/juniper-at-dusk.webp"
          alt=""
          fetchPriority="high"
          width="1672"
          height="941"
          className="hero-art"
        />
        <div className="hero-content">
          <div className="eyebrow">
            <span className="live-dot" /> JUNIPER HOUSE FIELD LAB
          </div>
          <h1 id="field-title">
            The home
            <br />
            <em>control room.</em>
          </h1>
          <p>
            A staffed security room follows an event across a wall of screens.
            Our goal is to give households that same context with $35 Wi-Fi
            cameras and AI agents. Follow one visitor from first sight to a
            decision.
          </p>
          <div className="hero-actions">
            <a className="solid-action" href="#simulator">
              Explore the twin <ArrowDownRight size={18} />
            </a>
            <a className="ghost-action" href="#casebook">
              Trace an event <ArrowRight size={16} />
            </a>
          </div>
        </div>
        <span className="art-caption">
          <Scan size={14} /> Residential site concept
        </span>
      </section>
      <nav className="chapter-nav" aria-label="Explore the field lab">
        <a href="#simulator">
          <Layers3 /> Digital twin <ArrowDownRight />
        </a>
        <a href="#camera-wall">
          <Scan /> Camera wall <ArrowDownRight />
        </a>
        <a href="#casebook">
          <Database /> Evidence desk <ArrowDownRight />
        </a>
        <a href="#agent-console">
          <TerminalSquare /> Agent console <ArrowDownRight />
        </a>
      </nav>
    </>
  );
}
