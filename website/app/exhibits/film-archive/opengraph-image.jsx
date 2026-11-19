import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("film-archive", 630);
export default function Image() {
  return imageBody("film-archive", 630);
}
