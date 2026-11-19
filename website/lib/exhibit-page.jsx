import Observatory from "../components/Observatory";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fieldData } from "./field-data";
import { exhibits, exhibitPath } from "./exhibits";

export function exhibitPage(slug) {
  return () => (
    <Observatory
      field={fieldData()}
      exhibit={slug}
      motion={
        slug === "motion-study"
          ? JSON.parse(
              readFileSync(
                join(process.cwd(), "public/motion/analysis.json"),
                "utf8",
              ),
            )
          : undefined
      }
    />
  );
}
export function exhibitMetadata(slug) {
  const entry = exhibits[slug],
    title = entry.title + " · Franken Surveillance",
    url = exhibitPath(slug);
  return {
    title,
    description: entry.description,
    alternates: { canonical: url },
    openGraph: { type: "website", url, title, description: entry.description },
  };
}
