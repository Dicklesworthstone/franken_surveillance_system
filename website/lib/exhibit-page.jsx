import {moments} from "./stereo.js";
import Observatory from "../components/Observatory";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fieldData } from "./field-data";
import { exhibits, exhibitPath } from "./exhibits";

function courtData() {
  const read = (name) =>
    JSON.parse(
      readFileSync(join(process.cwd(), "public/court", name + ".json"), "utf8"),
    );
  const { segment } = read("earlier/source");
  const views = Object.fromEntries(
    Object.entries(read("analysis").views).map(([id, view]) => [
      id,
      {
        samples: view.samples,
        frameDigests: view.frameDigests,
        inspection: read(id + "-inspection").frames[0],
      },
    ]),
  );
  return {
    ...views,
    earlier: read("earlier/garden").detector_cascade.frames.find(
      (frame) => frame.segment === segment,
    ),
  };
}

export function exhibitPage(slug) {
  return () => (
    <Observatory
      field={fieldData()}
      exhibit={slug}
      stereo={slug==="stereo-bench" ? Object.fromEntries(moments.map(({frame})=>{
        const data=JSON.parse(readFileSync(join(process.cwd(),"public/stereo","report-"+frame+".json"),"utf8"));
        return [frame,{height:data.report.hypotheses[0].estimate.position[2]}];
      })):undefined}
      court={slug === "courtyard" ? courtData() : undefined}
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
