import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("belief-lab", 600);
export default function Image() {
  return imageBody("belief-lab", 600);
}
