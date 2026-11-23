import { ArrowRight } from "lucide-react";
import { CHAPTERS } from "./chapters";
import { SHARE_LINE, sharePath } from "./share";
import { Mark } from "./TopBar";
import { Lit } from "./ui";

const plain = (title) => title.replace(/[[\]]/g, "");
const find = (id) => CHAPTERS.find((chapter) => chapter.id === id);

/**
 * What a site showing a preview of a chapter's link reads. The picture is the folder's own
 * opengraph-image.jpg and twitter-image.jpg, which Next adds because nothing here names an image.
 */
export function shareMetadata(id) {
  const chapter = find(id);
  const title = `${plain(chapter.title)} Chapter ${chapter.number} of Franken Surveillance`;
  const description = `${SHARE_LINE[id]} Open-source, local-first software in pure Rust for cheap Wi-Fi cameras.`;
  return {
    title,
    description,
    // The chapter lives on the home page; this page only carries its preview.
    alternates: { canonical: "/" },
    openGraph: { type: "website", url: sharePath(id), siteName: "Franken Surveillance", title, description },
    twitter: { card: "summary_large_image", title, description },
  };
}

/**
 * A chapter's own page. A browser is sent straight on to the chapter on the home page; without
 * scripts, or for the moment before, it shows the chapter's opener and a link to it.
 */
export default function ChapterShare({ id }) {
  const chapter = find(id);
  const target = "/#" + id;
  return (
    <main className="share" style={{ "--chapter": `var(--${chapter.light})` }}>
      <script dangerouslySetInnerHTML={{ __html: `location.replace(${JSON.stringify(target)})` }} />
      <img
        className="share__plate"
        src={`/watch/plates/${chapter.plate}-1600.webp`}
        width="1600"
        height="900"
        alt=""
        aria-hidden="true"
      />
      <div className="share__body">
        <a className="share__brand" href="/">
          <Mark />
          <span>Franken Surveillance</span>
        </a>
        <p className="opener__eyebrow">
          <span className="sphere" aria-hidden="true" />
          <span className="micro micro--chapter">
            Chapter {chapter.number} · {chapter.label}
          </span>
        </p>
        <h1 className="display-2">
          <Lit text={chapter.title} />
        </h1>
        <p className="lede">{SHARE_LINE[id]}</p>
        <p className="share__actions">
          <a className="button button--lamp" href={target}>
            Read chapter {chapter.number} <ArrowRight aria-hidden="true" />
          </a>
          <a className="button button--line" href="/">
            Start at the top
          </a>
        </p>
      </div>
    </main>
  );
}
