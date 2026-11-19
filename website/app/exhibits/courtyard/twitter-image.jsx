import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("courtyard", 600);
export default function Image() {
  return imageBody("courtyard", 600);
}
