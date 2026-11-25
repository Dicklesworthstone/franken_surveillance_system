import { ArrowUp, ArrowUpRight } from "lucide-react";
import CopyCommand from "./CopyCommand";
import ReplayLink from "./ReplayLink";
import { REPO } from "./TopBar";
import { Figure, Lit } from "./ui";

const file = (width) => `/watch/plates/house-${width}.webp`;
const WIDTHS = [960, 1600, 2400];

/**
 * The page's last scene. The minute is over and the house is lit. What a visitor can do next is
 * read the code, build it, and ask the build what it can do.
 */
export default function Finale({ last }) {
  return (
    <section className="finale" id="finale" aria-labelledby="finale-title">
      <div className="finale__plate" aria-hidden="true">
        <img
          src={file(1600)}
          srcSet={WIDTHS.map((width) => `${file(width)} ${width}w`).join(", ")}
          sizes="100vw"
          width="1600"
          height="900"
          loading="lazy"
          decoding="async"
          alt=""
        />
      </div>
      <div className="wrap finale__grid">
        <div className="finale__words reveal">
          <p className="finale__eyebrow">
            <span className="sphere" aria-hidden="true" />
            <span className="micro micro--chapter">
              {last.clock} · {last.label}
              <span className="finale__end"> · End of the minute</span>
            </span>
          </p>
          <h2 className="display-2" id="finale-title">
            <Lit text="The security room is [open source]." />
          </h2>
          <p className="lede">
            It is unfinished, and <a href="#status">the unfinished parts are listed</a>: what runs, what is built but not yet
            proven, and what is planned. Clone it and ask the build what it can do.
          </p>
          <div className="finale__actions">
            <a className="button button--lamp" href={REPO}>
              Read the source on GitHub <ArrowUpRight aria-hidden="true" />
            </a>
            <ReplayLink className="button button--line">
              Watch the minute again <ArrowUp aria-hidden="true" />
            </ReplayLink>
          </div>
        </div>
        <Figure
          className="inside finale__inside reveal"
          eyebrow="Look inside"
          title="Read it, build it, ask it what it can do."
          titleId="inside-title"
          level={3}
          style={{ "--delay": "0.08s" }}
        >
          <CopyCommand />
        </Figure>
      </div>
    </section>
  );
}
