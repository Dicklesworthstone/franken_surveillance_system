// The page's shared parts: headings with one lit phrase, the reticle, chapters,
// sections, and the framed figure with its provenance badge.
import { sectionIndex } from "./chapters";
import { sharePath } from "./share";
import ShareLink from "./ShareLink";

/** A heading whose [bracketed] words are the lit phrase. */
export function Lit({ text, glow = false }) {
  return text.split(/(\[[^\]]+\])/).map((part, i) =>
    part.startsWith("[") ? (
      <span key={i} className={glow ? "lit lit--glow" : "lit"}>
        {part.slice(1, -1)}
      </span>
    ) : (
      part
    ),
  );
}

/** Four corner ticks, the frame every detector draws round what it has found. */
export function Reticle({ className = "" }) {
  return (
    <span className={"reticle " + className} aria-hidden="true">
      <i />
      <i />
      <i />
      <i />
    </span>
  );
}

const KIND = {
  staged: "Staged",
  measured: "Measured",
  browser: "Computed in your browser",
  design: "From the design registry",
};

/** Where a figure's numbers or pictures come from. */
export function Badge({ kind, children }) {
  return <span className={"badge badge--" + kind}>{children ?? KIND[kind]}</span>;
}

/**
 * A framed figure: what it is, where its numbers come from, the figure itself,
 * and the source note at its foot.
 */
export function Figure({ as: Tag = "section", id, eyebrow, title, titleId, badge, note, level = 4, className = "", children, ...rest }) {
  const Title = `h${level}`;
  return (
    <Tag id={id} className={"fig " + className} aria-labelledby={title ? titleId : undefined} {...rest}>
      <Reticle />
      {(eyebrow || title || badge) && (
        <div className="fig__head">
          <div>
            {eyebrow && <p className="micro micro--chapter">{eyebrow}</p>}
            {title && (
              <Title className="fig__title" id={titleId}>
                {title}
              </Title>
            )}
          </div>
          {badge}
        </div>
      )}
      <div className="fig__body">{children}</div>
      {note && <div className="fig__note">{note}</div>}
    </Tag>
  );
}

const DRAWER = { measured: "Measured on these films", design: "From the design registry" };

/**
 * The figures that back a section up, folded under one line so the section reads in a screen or
 * two. The line says where the figures come from, by the same mark as the badges, and what they show.
 */
export function Drawer({ kind = "measured", detail, count = 1, children }) {
  return (
    <details className={"drawer drawer--" + kind}>
      <summary>
        <span className="drawer__mark" aria-hidden="true" />
        <span className="drawer__text">
          <strong>{DRAWER[kind]}</strong>
          <span>{detail}</span>
        </span>
        <span className="drawer__cue" aria-hidden="true">
          <span className="drawer__show">{count > 1 ? `Show ${count} figures` : "Show"}</span>
          <span className="drawer__hide">Hide</span>
          <svg viewBox="0 0 16 16">
            <path d="M4 6l4 4 4-4" />
          </svg>
        </span>
      </summary>
      <div className="drawer__body">{children}</div>
    </details>
  );
}

const STANDING = { runs: "Runs in tests", built: "Built, not yet proven", planned: "Planned", demo: "This demo only" };

/** What exists behind a section, by how far it has got. */
export function Standing({ rows }) {
  return (
    <div className="standing reveal">
      <p className="standing__label micro" aria-hidden="true">
        Where this stands
      </p>
      <ul aria-label="Where this stands" style={{ "--n": rows.length }}>
        {rows.map(([kind, text]) => (
          <li key={kind + text} className={"standing__row standing__row--" + kind}>
            <strong>{STANDING[kind]}</strong>
            <span>{text}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
export const standingLabel = (kind) => STANDING[kind];

/** A chapter: its opener over a render of the scene, then its sections. */
export function Chapter({ chapter, children }) {
  const heading = `ch-${chapter.id}`;
  const file = (width) => `/watch/plates/${chapter.plate}-${width}.webp`;
  const widths = chapter.plateWidths ?? [960, 1600, 2400];
  return (
    <div className="chapter" data-chapter={chapter.id} style={{ "--chapter": `var(--${chapter.light})` }}>
      <section className="opener" id={chapter.id} aria-labelledby={heading}>
        <div className="opener__plate" aria-hidden="true">
          <img
            src={file(1600)}
            srcSet={widths.map((width) => `${file(width)} ${width}w`).join(", ")}
            sizes="100vw"
            width="1600"
            height="900"
            loading="lazy"
            decoding="async"
            alt=""
          />
        </div>
        <div className="wrap opener__grid">
          <div className="reveal opener__words">
            <p className="opener__eyebrow">
              <span className="sphere" aria-hidden="true" />
              <span className="micro micro--chapter">
                Chapter {chapter.number} · {chapter.label}
              </span>
            </p>
            <h2 className="display-2" id={heading}>
              <Lit text={chapter.title} />
            </h2>
            <p className="lede">{chapter.thesis}</p>
            <p className="opener__share">
              <ShareLink path={sharePath(chapter.id)} title={`${chapter.title.replace(/[[\]]/g, "")} Franken Surveillance`} />
            </p>
          </div>
          <div className="opener__side reveal" style={{ "--delay": "0.08s" }}>
            <span className="opener__numeral" aria-hidden="true">
              {chapter.number}
            </span>
            {chapter.sections.length > 1 && (
              <ol className="opener__index">
                {chapter.sections.map(([id, label], i) => (
                  <li key={id}>
                    <a href={"#" + id}>
                      <span className="data">
                        {chapter.number}.{i + 1}
                      </span>
                      {label}
                    </a>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
        <p className="opener__credit micro">Rendered scene, fictional house</p>
      </section>
      {children}
    </div>
  );
}

/** A section: a numbered heading with its words beside it, then full-width figures. */
export function Section({ id, eyebrow, title, when, words, children, standing }) {
  return (
    <section className="section" id={id} aria-labelledby={id + "-title"}>
      <div className="wrap">
        <div className="section__head reveal">
          <div>
            <p className="section__eyebrow">
              <span className="data">{sectionIndex(id)}</span>
              <i aria-hidden="true" />
              <span className="micro">{eyebrow}</span>
            </p>
            <h3 className="display-3" id={id + "-title"}>
              <Lit text={title} />
            </h3>
            {when}
          </div>
          <div className="section__words">{words}</div>
        </div>
        <div className="section__figures">{children}</div>
        {standing && <Standing rows={standing} />}
      </div>
    </section>
  );
}
