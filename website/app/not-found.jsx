import { ArrowRight, ArrowUpRight } from "lucide-react";
import { CHAPTERS } from "../components/site/chapters";
import { Mark, REPO } from "../components/site/TopBar";
import { Badge, Lit } from "../components/site/ui";

export const metadata = {
  title: "Page not found · Franken Surveillance",
};

const plain = (title) => title.replace(/[[\]]/g, "");

/**
 * Any address the site does not have. Without this file the export's 404 is Next's own page, whose
 * white background and the site's light text left it blank. Server-rendered and script-free: Next
 * sends this page's tree with every route.
 */
export default function NotFound() {
  return (
    <main className="missing">
      <a className="share__brand" href="/">
        <Mark />
        <span>Franken Surveillance</span>
      </a>
      <div className="missing__grid">
        <div className="missing__words">
          <p className="opener__eyebrow">
            <span className="sphere" aria-hidden="true" />
            <span className="micro micro--chapter">404 · Page not found</span>
          </p>
          <h1 className="display-2">
            <Lit text="Nobody at this [address]." />
          </h1>
          <p className="lede">
            The link may be old or mistyped. Everything on the site is on one page: start at the top, or go straight to a
            chapter.
          </p>
          <p className="share__actions">
            <a className="button button--lamp" href="/">
              Start at the top <ArrowRight aria-hidden="true" />
            </a>
            <a className="button button--line" href={REPO}>
              Source on GitHub <ArrowUpRight aria-hidden="true" />
            </a>
          </p>
        </div>
        <figure className="missing__monitor">
          <div className="missing__screen">
            {/* The gate camera's still, from the same render as the home page's thumbnail; the 1280 px source on sharp screens.
                No reticle: on this site it is the frame a detector draws round what it found, and this picture has nobody. */}
            <img
              src="/watch/plates/cam-gate.webp"
              srcSet="/watch/plates/cam-gate.webp 640w, /watch/intrusion/gate.jpg 1280w"
              sizes="(min-width: 900px) 640px, calc(100vw - 32px)"
              width="640"
              height="360"
              alt=""
            />
            <span className="missing__credit">
              <Badge kind="staged">Rendered scene, fictional house</Badge>
            </span>
          </div>
          <figcaption className="micro">Gate camera</figcaption>
        </figure>
      </div>
      <nav className="missing__chapters" aria-label="Chapters">
        <ol>
          {CHAPTERS.map((chapter) => (
            <li key={chapter.id} style={{ "--chapter": `var(--${chapter.light})` }}>
              <a href={"/#" + chapter.id}>
                <span className="micro micro--chapter">
                  {chapter.number} · {chapter.label}
                </span>
                <span className="missing__title">{plain(chapter.title)}</span>
              </a>
            </li>
          ))}
        </ol>
      </nav>
    </main>
  );
}
