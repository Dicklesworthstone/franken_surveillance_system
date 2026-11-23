// The observatory routes carry their own fonts and stylesheet so that pages
// outside this wrapper are not styled by them.
import "@fontsource-variable/space-grotesk/index.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/instrument-serif/latin-400.css";
import "@fontsource/instrument-serif/latin-400-italic.css";
import "../app/estate.css";
import NightObservatory from "../components/night/NightObservatory";
import { nightData } from "./night/data";
import { exhibits, pathFor } from "./night/catalog";
async function prints() {
  const { imageMeta } = await import("./share-card");
  return Promise.all(
    Object.entries(exhibits).map(async ([id, e]) => ({
      id,
      title: e.title,
      og: pathFor(id) + "opengraph-image/" + (await imageMeta(id, 630))[0].id,
      x: pathFor(id) + "twitter-image/" + (await imageMeta(id, 600))[0].id,
    })),
  );
}
export function exhibitPage(id) {
  return async function NightPage() {
    return (
      <NightObservatory
        page={id}
        data={nightData()}
        prints={id === "poster-room" ? await prints() : []}
      />
    );
  };
}
export function exhibitMetadata(id) {
  const { title, description } = exhibits[id],
    url = pathFor(id);
  return {
    title: title + " · Franken Surveillance",
    description,
    alternates: { canonical: url },
    openGraph: { url, title, description, type: "website" },
  };
}
