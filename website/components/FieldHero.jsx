import { ArrowDownRight, ArrowUpRight, Play } from "lucide-react";
const chapters = [
  ["#simulator", "/motion/site.jpg", "Site survey", "Explore the digital twin"],
  ["#camera-wall", "/wall/delivery.jpg", "Camera wall", "Follow three cameras"],
  ["#casebook", "/field/porch.jpg", "Evidence desk", "Inspect the record"],
];
export default function FieldHero() {
  return (
    <>
      <section className="field-hero" aria-labelledby="field-title">
        <img
          src="/motion/arrival.webp"
          alt=""
          fetchPriority="high"
          width="1672"
          height="941"
          className="hero-art"
        />
        <div className="hero-content">
          <div className="eyebrow">
            JUNIPER HOUSE <span className="hero-rule" /> FIELD LAB
          </div>
          <h1 id="field-title">
            The home
            <br />
            <em>control room.</em>
          </h1>
          <p>
            A parcel arrives. Two cameras catch it. Follow the encounter from a
            3D home to an evidence ledger an AI agent can read. The ambition is
            a household control room built from $35 Wi-Fi cameras.
          </p>
          <div className="hero-actions">
            <a className="solid-action" href="/exhibits/motion-study/">
              <Play size={15} fill="currentColor" /> Enter the motion lab
            </a>
            <a className="ghost-action" href="#casebook">
              Trace an event <ArrowDownRight size={16} />
            </a>
          </div>
        </div>
        <span className="art-caption">
          Juniper House · concept illustration
        </span>
      </section>
      <nav className="chapter-nav" aria-label="Explore the field lab">
        {chapters.map(([href, src, label, title]) => (
          <a key={href} href={href}>
            <img src={src} alt="" width="88" height="62" />
            <span>
              <small>{label}</small>
              <b>{title}</b>
            </span>
            <ArrowUpRight size={15} />
          </a>
        ))}
      </nav>
    </>
  );
}
